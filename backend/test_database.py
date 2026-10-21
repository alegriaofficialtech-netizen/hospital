#!/usr/bin/env python3
"""
test_database.py - Pruebas Unitarias de Persistencia Relacional y Cadena de Auditoría
SGSI-ZTA Hospital Lab — ISO/IEC 27001:2022 Control A.8.15 & NIST SP 800-207
"""

import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time
import unittest

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from database import (
    AuditChainCorruptedError,
    ClinicalDatabaseManager,
    DatabaseBackedAuditLogs,
    DatabaseBackedOrdersDict,
    DatabaseError,
)


class TestClinicalDatabaseManager(unittest.TestCase):
    """Suite de pruebas rigurosas para ClinicalDatabaseManager."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_lis_db_")
        self.db_path = os.path.join(self.test_dir, "test_lis.db")
        self.db = ClinicalDatabaseManager(db_path=self.db_path)

    def tearDown(self):
        self.db.close()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_initialization_and_pragmas(self):
        """Verifica que la base de datos se inicializa con WAL, foreign keys y esquemas."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode;")
        mode = cur.fetchone()[0]
        self.assertEqual(mode.lower(), "wal")

        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [r[0] for r in cur.fetchall()]
        self.assertIn("clinical_orders", tables)
        self.assertIn("audit_events", tables)
        self.assertIn("audit_checkpoints", tables)
        self.assertIn("schema_migrations", tables)
        conn.close()

    def test_02_order_crud_operations(self):
        """Verifica operaciones CRUD de órdenes clínicas."""
        order_data = {
            "order_id": "ORD-TEST-001",
            "patient_dni": "DNI-1001",
            "test_type": "HEMOGRAMA COMPLETO",
            "status": "SAMPLE_COLLECTED",
            "created_by": "recepcionista.demo",
            "measurements": {},
            "validated_by": None,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        # Guardar orden
        self.db.save_order(order_data)

        # Recuperar orden
        saved = self.db.get_order("ORD-TEST-001")
        self.assertIsNotNone(saved)
        self.assertEqual(saved["patient_dni"], "DNI-1001")
        self.assertEqual(saved["status"], "SAMPLE_COLLECTED")

        # Filtrar por DNI
        orders = self.db.get_orders(patient_dni="DNI-1001")
        self.assertEqual(len(orders), 1)
        self.assertEqual(orders[0]["order_id"], "ORD-TEST-001")

        # Actualizar orden con resultados IoMT
        saved["measurements"] = {"hemoglobina_g_dl": 14.5}
        saved["status"] = "ANALYZED"
        saved["device_id"] = "IOMT-001"
        self.db.save_order(saved)

        updated = self.db.get_order("ORD-TEST-001")
        self.assertEqual(updated["status"], "ANALYZED")
        self.assertEqual(updated["measurements"]["hemoglobina_g_dl"], 14.5)

    def test_03_audit_chain_continuous_hashing(self):
        """Verifica el cálculo encadenado de hashes SHA-256."""
        ev1 = self.db.record_audit_event("CREATE_ORDER", "recepcion", "ROLE_RECEPTION", "SUCCESS", "Orden 1", "127.0.0.1")
        self.assertEqual(ev1["prev_hash"], "0" * 64)
        hash1 = ev1["hash"]
        self.assertEqual(len(hash1), 64)
        self.assertEqual(self.db.get_last_audit_hash(), hash1)

        ev2 = self.db.record_audit_event("VALIDATE_ORDER", "medico", "ROLE_PATHOLOGIST", "SUCCESS", "Orden 1 validada", "127.0.0.1", mfa_verified=True)
        self.assertEqual(ev2["prev_hash"], hash1)
        hash2 = ev2["hash"]
        self.assertNotEqual(hash1, hash2)
        self.assertEqual(self.db.get_last_audit_hash(), hash2)

        # Verificar integridad
        valid, err = self.db.verify_chain_integrity()
        self.assertTrue(valid, f"Cadena inválida: {err}")
        self.assertIsNone(err)

    def test_04_tamper_detection_direct_db_manipulation(self):
        """Verifica que alteraciones directas en SQLite rompen la verificación."""
        self.db.record_audit_event("EVENT_1", "actor1", "ROLE_A", "SUCCESS", "Detalle 1")
        self.db.record_audit_event("EVENT_2", "actor2", "ROLE_B", "SUCCESS", "Detalle 2")
        self.db.record_audit_event("EVENT_3", "actor3", "ROLE_C", "SUCCESS", "Detalle 3")

        # Manipulación maliciosa de un registro en la base de datos
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT raw_json FROM audit_events WHERE id = 2;")
        raw = cur.fetchone()[0]
        data = json.loads(raw)
        data["action"] = "TAMPERED_ACTION"
        cur.execute("UPDATE audit_events SET raw_json = ? WHERE id = 2;", (json.dumps(data),))
        conn.commit()
        conn.close()

        # Debe detectar la alteración
        valid, err = self.db.verify_chain_integrity()
        self.assertFalse(valid)
        self.assertIn("Manipulación detectada en evento ID 2", str(err))

    def test_05_persistence_across_restart(self):
        """Demuestra que órdenes y auditoría sobreviven al cierre e inicio de un nuevo proceso."""
        # 1. Poblar datos
        self.db.save_order({
            "order_id": "ORD-SURVIVE-01",
            "patient_dni": "DNI-SURVIVE",
            "status": "VALIDATED_AND_RELEASED",
            "measurements": {"glucosa": 95},
        })
        self.db.record_audit_event("TEST_EVENT", "system", "SYSTEM", "SUCCESS", "Pre-restart event")
        last_hash_before = self.db.get_last_audit_hash()

        # 2. Cerrar proceso / base de datos
        self.db.close()

        # 3. Iniciar nuevo gestor sobre el mismo archivo
        new_db = ClinicalDatabaseManager(db_path=self.db_path)
        try:
            order = new_db.get_order("ORD-SURVIVE-01")
            self.assertIsNotNone(order, "La orden desapareció tras el reinicio!")
            self.assertEqual(order["status"], "VALIDATED_AND_RELEASED")
            self.assertEqual(order["measurements"]["glucosa"], 95)

            events = new_db.get_audit_events()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["action"], "TEST_EVENT")
            self.assertEqual(new_db.get_last_audit_hash(), last_hash_before)

            # Agregar un evento más y verificar que la cadena continúa sin ruptura
            ev2 = new_db.record_audit_event("POST_RESTART", "system", "SYSTEM", "SUCCESS", "Post-restart event")
            self.assertEqual(ev2["prev_hash"], last_hash_before)

            valid, err = new_db.verify_chain_integrity()
            self.assertTrue(valid, f"Cadena rota tras reinicio: {err}")
        finally:
            new_db.close()

    def test_06_orders_dict_proxy_compatibility(self):
        """Verifica compatibilidad de DatabaseBackedOrdersDict con la sintaxis dict nativa."""
        orders_proxy = DatabaseBackedOrdersDict(self.db)
        orders_proxy["ORD-PROXY-01"] = {
            "order_id": "ORD-PROXY-01",
            "patient_dni": "DNI-PROXY",
            "status": "SAMPLE_COLLECTED"
        }

        self.assertIn("ORD-PROXY-01", orders_proxy)
        self.assertEqual(orders_proxy["ORD-PROXY-01"]["status"], "SAMPLE_COLLECTED")
        self.assertEqual(len(orders_proxy), 1)
        self.assertEqual(len(list(orders_proxy.values())), 1)

        orders_proxy.clear()
        self.assertEqual(len(orders_proxy), 0)
        self.assertNotIn("ORD-PROXY-01", orders_proxy)

    def test_07_audit_logs_proxy_compatibility(self):
        """Verifica compatibilidad de DatabaseBackedAuditLogs con la sintaxis list nativa."""
        audit_proxy = DatabaseBackedAuditLogs(self.db)
        self.assertEqual(len(audit_proxy), 0)

        self.db.record_audit_event("PROXY_EV", "actor", "ROLE", "OK", "Proxy detail")
        self.assertEqual(len(audit_proxy), 1)
        self.assertEqual(audit_proxy[0]["action"], "PROXY_EV")

        audit_proxy.clear()
        self.assertEqual(len(audit_proxy), 0)
        self.assertEqual(self.db.get_last_audit_hash(), "0" * 64)

    def test_08_online_backup_and_restore(self):
        """Verifica el respaldo atómico en línea y la restauración."""
        self.db.save_order({"order_id": "ORD-BK", "patient_dni": "DNI-BK", "status": "CREATED"})
        self.db.record_audit_event("BK_EVENT", "admin", "ADMIN", "SUCCESS", "Detalle de backup")

        backup_file = os.path.join(self.test_dir, "backup_test.db")
        self.db.backup_database(backup_file)

        # Comprobar permisos del backup 0600
        st = os.stat(backup_file)
        self.assertEqual(st.st_mode & 0o777, 0o600)

        # Instanciar DB sobre el backup y comprobar datos
        bk_db = ClinicalDatabaseManager(db_path=backup_file)
        try:
            self.assertIsNotNone(bk_db.get_order("ORD-BK"))
            self.assertEqual(len(bk_db.get_audit_events()), 1)
            valid, err = bk_db.verify_chain_integrity()
            self.assertTrue(valid)
        finally:
            bk_db.close()


def main():
    unittest.main(verbosity=2)


if __name__ == "__main__":
    main()
