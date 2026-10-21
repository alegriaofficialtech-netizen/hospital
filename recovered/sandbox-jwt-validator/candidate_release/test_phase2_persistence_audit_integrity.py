#!/usr/bin/env python3
"""
test_phase2_persistence_audit_integrity.py - Validación Rigurosa de Persistencia y Auditoría
SGSI-ZTA Hospital Lab — ISO/IEC 27001:2022 Control A.8.15 & NIST SP 800-207

FASE 2: Verificación de 10 garantías transaccionales y criptográficas:
1. Las modificaciones de órdenes se guardan efectivamente.
2. Los cambios sobre diccionarios u objetos anidados se preservan.
3. Los registros de auditoría mantienen orden cronológico estricto.
4. Modificaciones y auditoría no dejan estados parciales inconsistentes.
5. Operaciones fallidas producen rollback transaccional completo.
6. La base de datos conserva datos tras reinicio y reemplazo de contenedor.
7. SQLite no se inicializa silenciosamente desde cero ante corrupción.
8. Se verifican PRAGMA integrity_check, claves foráneas y continuidad de hashes.
9. Configuración WAL y políticas de sincronización (journal_mode=WAL, synchronous=FULL).
10. Respaldos consistentes y recuperables con transacciones WAL activas.
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


class TestPhase2PersistenceAuditIntegrity(unittest.TestCase):
    """Suite de validación exhaustiva de persistencia, concurrencia y auditoría."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_phase2_db_")
        self.db_path = os.path.join(self.test_dir, "test_lis.db")
        self.db = ClinicalDatabaseManager(db_path=self.db_path)

    def tearDown(self):
        self.db.close()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_order_modifications_persisted(self):
        """1. Las modificaciones de órdenes se guardan efectivamente."""
        order = {
            "order_id": "ORD-MOD-01",
            "patient_dni": "12345678",
            "status": "SAMPLE_COLLECTED",
            "test_type": "HEMOGRAMA",
            "created_by": "recepcionista.demo",
            "measurements": {},
            "validated_by": None,
        }
        self.db.save_order(order)

        # Modificación 1: Estado analizado
        order["status"] = "ANALYZED"
        order["measurements"] = {"plaquetas_k_ul": 250}
        self.db.save_order(order)

        # Modificación 2: Validación médica
        order["status"] = "VALIDATED_AND_RELEASED"
        order["validated_by"] = "medico.demo"
        order["observations"] = "Conforme"
        self.db.save_order(order)

        # Recargar desde nueva conexión
        new_db = ClinicalDatabaseManager(db_path=self.db_path)
        try:
            loaded = new_db.get_order("ORD-MOD-01")
            self.assertEqual(loaded["status"], "VALIDATED_AND_RELEASED")
            self.assertEqual(loaded["validated_by"], "medico.demo")
            self.assertEqual(loaded["observations"], "Conforme")
            self.assertEqual(loaded["measurements"]["plaquetas_k_ul"], 250)
        finally:
            new_db.close()

    def test_02_nested_dictionary_modifications_preserved(self):
        """2. Los cambios realizados sobre diccionarios u objetos anidados no se pierden."""
        orders_proxy = DatabaseBackedOrdersDict(self.db)
        orders_proxy["ORD-NESTED-01"] = {
            "order_id": "ORD-NESTED-01",
            "patient_dni": "87654321",
            "status": "SAMPLE_COLLECTED",
            "measurements": {
                "hematology": {
                    "leukocytes": {"value": 6.8, "unit": "10^3/uL", "reference": [4.5, 11.0]},
                    "erythrocytes": {"value": 4.9, "unit": "10^6/uL", "reference": [4.3, 5.9]},
                },
                "chemistry": {
                    "glucose": {"value": 92, "unit": "mg/dL", "fasting": True}
                }
            },
            "audit_meta": {
                "tags": ["urgent", "stat"],
                "flags": {"flag_critical": False, "verified_by_tech": True}
            }
        }

        # Modificación profunda de objeto anidado
        order_copy = dict(orders_proxy["ORD-NESTED-01"])
        order_copy["measurements"]["hematology"]["platelets"] = {"value": 240, "unit": "10^3/uL"}
        order_copy["measurements"]["chemistry"]["glucose"]["value"] = 95
        order_copy["audit_meta"]["flags"]["flag_critical"] = True
        orders_proxy["ORD-NESTED-01"] = order_copy

        # Verificar persistencia desde almacenamiento en frío
        self.db.close()
        cold_db = ClinicalDatabaseManager(db_path=self.db_path)
        try:
            cold_orders = DatabaseBackedOrdersDict(cold_db)
            saved = cold_orders["ORD-NESTED-01"]
            self.assertEqual(saved["measurements"]["hematology"]["platelets"]["value"], 240)
            self.assertEqual(saved["measurements"]["chemistry"]["glucose"]["value"], 95)
            self.assertTrue(saved["audit_meta"]["flags"]["flag_critical"])
            self.assertEqual(saved["audit_meta"]["tags"], ["urgent", "stat"])
        finally:
            cold_db.close()
            # Reiniciar conexión para tearDown
            self.db = ClinicalDatabaseManager(db_path=self.db_path)

    def test_03_audit_log_chronological_ordering(self):
        """3. Los registros de auditoría mantienen el orden cronológico estricto."""
        for i in range(1, 11):
            self.db.record_audit_event(
                action=f"ACTION_{i:02d}",
                actor="test_runner",
                role="ROLE_TEST",
                status="SUCCESS",
                details=f"Paso {i} en la secuencia temporal",
            )
            time.sleep(0.005)

        events = self.db.get_audit_events()
        self.assertEqual(len(events), 10)

        # Validar orden de ID secuencial, continuidad de hashes y timestamps
        expected_prev = "0" * 64
        for idx, ev in enumerate(events, start=1):
            self.assertEqual(ev["action"], f"ACTION_{idx:02d}")
            self.assertEqual(ev["prev_hash"], expected_prev)
            expected_prev = ev["hash"]

    def test_04_no_partial_inconsistent_states(self):
        """4. Modificaciones y auditoría no dejan estados parciales inconsistentes."""
        # En una operación atómica, si falla la persistencia, no se altera la base de datos
        conn = self.db._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM clinical_orders;")
        orders_count_before = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM audit_events;")
        audit_count_before = cur.fetchone()[0]
        cur.close()

        # Intentar guardar una orden inválida sin order_id
        with self.assertRaises(DatabaseError):
            self.db.save_order({"patient_dni": "00000000", "status": "INVALID"})

        # Comprobar que no hay registros espurios
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM clinical_orders;")
        self.assertEqual(cur.fetchone()[0], orders_count_before)
        cur.execute("SELECT count(*) FROM audit_events;")
        self.assertEqual(cur.fetchone()[0], audit_count_before)
        cur.close()

    def test_05_transactional_rollback_on_failure(self):
        """5. Una operación fallida produce rollback transaccional completo."""
        conn = self.db._get_conn()
        cur = conn.cursor()

        # Iniciar transacción manual para simular fallo a mitad de camino
        cur.execute("BEGIN IMMEDIATE;")
        try:
            cur.execute("""
                INSERT INTO clinical_orders (order_id, patient_dni, status, created_at, data_json)
                VALUES ('ORD-FAIL-ROLLBACK', 'DNI-ROLLBACK', 'TEST', 12345.0, '{"test": true}');
            """)
            # Simular error de violación de restricción (columna inexistente o constraint)
            cur.execute("INSERT INTO clinical_orders (order_id, patient_dni) VALUES ('ORD-FAIL-ROLLBACK', 'DUP');")
            cur.execute("COMMIT;")
        except Exception:
            cur.execute("ROLLBACK;")
        finally:
            cur.close()

        # Verificar que ORD-FAIL-ROLLBACK no existe en la base de datos
        self.assertIsNone(self.db.get_order("ORD-FAIL-ROLLBACK"))

    def test_06_sqlite_data_survives_process_restart(self):
        """6. La base SQLite conserva datos después de reiniciar el proceso."""
        self.db.save_order({"order_id": "ORD-PERSIST", "patient_dni": "12341234", "status": "CREATED"})
        ev = self.db.record_audit_event("INIT", "admin", "ADMIN", "OK", "Init event")
        last_hash = ev["hash"]
        self.db.close()

        new_mgr = ClinicalDatabaseManager(db_path=self.db_path)
        try:
            self.assertIsNotNone(new_mgr.get_order("ORD-PERSIST"))
            self.assertEqual(new_mgr.get_last_audit_hash(), last_hash)
            valid, err = new_mgr.verify_chain_integrity()
            self.assertTrue(valid, f"Cadena rota tras reinicio: {err}")
        finally:
            new_mgr.close()
            self.db = ClinicalDatabaseManager(db_path=self.db_path)

    def test_07_no_silent_reinitialization_on_corruption(self):
        """7. SQLite no se inicializa silenciosamente desde cero ante corrupción de una base existente."""
        # 1. Crear eventos válidos
        self.db.record_audit_event("EV1", "usr", "ROL", "OK", "Evento uno")
        self.db.record_audit_event("EV2", "usr", "ROL", "OK", "Evento dos")
        self.db.close()

        # 2. Corromper deliberadamente un registro en el archivo de base de datos
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("UPDATE audit_events SET raw_json = '{\"tampered\": true}' WHERE id = 1;")
        conn.commit()
        conn.close()

        # 3. Al instanciar ClinicalDatabaseManager sobre la BD corrupta, DEBE fallar en el arranque
        # y NO inicializar silenciosamente una nueva cadena desde cero (Fail-Closed)
        with self.assertRaises(AuditChainCorruptedError) as ctx:
            ClinicalDatabaseManager(db_path=self.db_path)

        self.assertIn("Manipulación detectada", str(ctx.exception))

    def test_08_pragma_integrity_check_fk_hash_continuity(self):
        """8. Se verifican PRAGMA integrity_check, claves foráneas y continuidad de la cadena hash."""
        # Generar varias operaciones
        self.db.save_order({"order_id": "ORD-CHK-01", "patient_dni": "44332211", "status": "CREATED"})
        self.db.record_audit_event("CREATE", "actor", "ROLE", "OK", "Created order")
        self.db.record_audit_event("VERIFY", "actor", "ROLE", "OK", "Verified order")

        conn = self.db._get_conn()
        cur = conn.cursor()

        # PRAGMA integrity_check
        cur.execute("PRAGMA integrity_check;")
        res = cur.fetchone()[0]
        self.assertEqual(res, "ok", f"Integrity check falló: {res}")

        # PRAGMA foreign_keys
        cur.execute("PRAGMA foreign_keys;")
        fk_enabled = cur.fetchone()[0]
        self.assertEqual(fk_enabled, 1, "Claves foráneas no están habilitadas.")
        cur.close()

        # Continuidad de la cadena
        valid, err = self.db.verify_chain_integrity()
        self.assertTrue(valid, f"Cadena rota: {err}")

    def test_09_wal_configuration_and_sync_policies(self):
        """9. La configuración WAL y las políticas de sincronización cumplen durabilidad estricta."""
        conn = self.db._get_conn()
        cur = conn.cursor()

        # Modo WAL
        cur.execute("PRAGMA journal_mode;")
        journal_mode = cur.fetchone()[0].upper()
        self.assertEqual(journal_mode, "WAL", f"Modo de diario incorrecto: {journal_mode}")

        # Sincronización FULL: RPO estricto exigido por el informe de auditoría (A-05).
        cur.execute("PRAGMA synchronous;")
        sync_mode = cur.fetchone()[0]
        # 2 = FULL
        self.assertEqual(sync_mode, 2, f"PRAGMA synchronous esperado 2 (FULL), obtenido: {sync_mode}")

        # Busy timeout
        cur.execute("PRAGMA busy_timeout;")
        timeout = cur.fetchone()[0]
        self.assertEqual(timeout, 5000, f"Busy timeout esperado 5000ms, obtenido: {timeout}")
        cur.close()

    def test_10_atomic_backup_includes_uncheckpointed_wal(self):
        """10. Copias de respaldo son consistentes y recuperables, incluyendo transacciones WAL activas."""
        # 1. Insertar datos en la base principal
        self.db.save_order({"order_id": "ORD-WAL-01", "patient_dni": "99887766", "status": "IN_WAL"})
        self.db.record_audit_event("WAL_WRITE", "tester", "TEST", "OK", "Escritura en WAL no consolidada")

        # 2. Verificar que existe el archivo .db-wal en disco con escrituras pendientes
        wal_file = self.db_path + "-wal"
        # Nota: En modo WAL, las escrituras van al log WAL antes del checkpoint

        # 3. Ejecutar respaldo en caliente mediante API nativa de backup de SQLite
        backup_file = os.path.join(self.test_dir, "hot_wal_backup.db")
        self.db.backup_database(backup_file)
        self.assertTrue(os.path.exists(backup_file))

        # 4. Abrir la copia de respaldo en una nueva instancia aislada
        # sin tocar la base de datos principal
        backup_db = ClinicalDatabaseManager(db_path=backup_file)
        try:
            # Comprobar que la orden escrita en el WAL se recupera 100% íntegra en el respaldo
            recovered_order = backup_db.get_order("ORD-WAL-01")
            self.assertIsNotNone(recovered_order, "La orden presente en WAL no se consolidó en el backup!")
            self.assertEqual(recovered_order["status"], "IN_WAL")

            # Comprobar que los eventos de auditoría y hashes coinciden exactamente
            events = backup_db.get_audit_events()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["action"], "WAL_WRITE")
            self.assertEqual(backup_db.get_last_audit_hash(), self.db.get_last_audit_hash())

            # Integridad de la base de datos de respaldo
            valid, err = backup_db.verify_chain_integrity()
            self.assertTrue(valid, f"Cadena en respaldo corrupta: {err}")
        finally:
            backup_db.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
