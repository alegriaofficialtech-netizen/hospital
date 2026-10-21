#!/usr/bin/env python3
"""
test_persistence_durability.py - Pruebas Reales de Persistencia y Recuperación ante Desastres
SGSI-ZTA Hospital Lab — ISO/IEC 27001:2022 Control A.8.15 & NIST SP 800-207

FASE 4: Verificación exhaustiva de durabilidad ACID y continuidad criptográfica:
1. Reinicio del proceso LIS (HTTP server restart) manteniendo persistencia de órdenes y hash.
2. Recreación de contenedor Docker con volumen persistente (read_only: true, user 65534:65534).
3. Rollback de código simulado preservando el almacenamiento relacional.
4. Fallo de almacenamiento simulado (fail-closed HTTP 500 / PERSISTENCE_TRANSACTION_FAILED).
5. Respaldo atómico en línea y recuperación ante desastres (Disaster Recovery).
"""

import hashlib
import hmac
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
import uuid
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

import sys

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import server
from database import (
    AuditChainCorruptedError,
    ClinicalDatabaseManager,
    DatabaseError,
)
from jwt_validator import JWKSCacheManager, ZeroTrustJWTValidator


def b64url(data: bytes) -> str:
    return __import__("base64").urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class DurabilityMockCache(JWKSCacheManager):
    """Cache en memoria precargada con clave publica RSA para pruebas deterministas."""

    def __init__(self, public_key: rsa.RSAPublicKey, kid: str, issuer: str):
        self.discovery_url = f"{issuer}/.well-known/openid-configuration"
        self.cache_ttl_seconds = 3600
        self.min_refresh_interval_seconds = 60
        self._jwks_uri = f"{issuer}/protocol/openid-connect/certs"
        self._expected_issuer = issuer
        self._keys_by_kid = {kid: public_key}
        self._last_fetch_timestamp = time.time()

    @property
    def expected_issuer(self) -> str:
        return self._expected_issuer

    def _fetch_jwks(self) -> None:
        pass

    def _fetch_discovery(self) -> None:
        pass


class TestPersistenceDurability(unittest.TestCase):
    """Suite integral de pruebas de durabilidad y persistencia ACID."""

    @classmethod
    def setUpClass(cls):
        # 1. Claves RSA sintéticas para simular tokens JWT de Keycloak
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public_key = cls.private_key.public_key()
        cls.kid = "test-durability-kid"
        cls.issuer = "http://127.0.0.1:8085/realms/hospital-lab"
        cls.audience = "clinical-poc-api"

        cls.cache = DurabilityMockCache(cls.public_key, cls.kid, cls.issuer)
        cls.validator = ZeroTrustJWTValidator(
            discovery_url=f"{cls.issuer}/.well-known/openid-configuration",
            expected_audience=cls.audience,
            cache_manager=cls.cache,
            expected_authorized_party="clinical-poc",
            require_bearer_type=False,
        )

    def _generate_jwt(
        self,
        username: str,
        roles: List[str],
        mfa: bool = False,
        exp_offset: int = 300
    ) -> str:
        """Genera token JWT firmado sintéticamente idéntico a test_candidate_lis."""
        now = int(time.time())
        header = {"alg": "RS256", "typ": "JWT", "kid": self.kid}
        payload = {
            "iss": self.issuer,
            "sub": f"user-{username}-durability",
            "preferred_username": username,
            "aud": [self.audience],
            "azp": "clinical-poc",
            "iat": now,
            "nbf": now - 5,
            "exp": now + exp_offset,
            "jti": f"jwt-{username}-{now}",
            "realm_access": {"roles": roles},
            "resource_access": {"clinical-poc-api": {"roles": roles}},
            "amr": ["pwd", "totp"] if mfa else ["pwd"],
            "typ": "Bearer",
        }
        raw_header = b64url(json.dumps(header).encode("utf-8"))
        raw_payload = b64url(json.dumps(payload).encode("utf-8"))
        signing_input = f"{raw_header}.{raw_payload}".encode("ascii")
        sig = self.private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        raw_signature = b64url(sig)
        return f"{raw_header}.{raw_payload}.{raw_signature}"

    def _http_request(
        self,
        port: int,
        path: str,
        method: str = "GET",
        token: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Tuple[int, Dict[str, Any]]:
        url = f"http://127.0.0.1:{port}{path}"
        req_headers = {"Content-Type": "application/json"}
        if token:
            req_headers["Authorization"] = f"Bearer {token}"
        if headers:
            req_headers.update(headers)

        body_bytes = json.dumps(data).encode("utf-8") if data else None
        req = urllib.request.Request(url, data=body_bytes, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                status = resp.status
                body = json.loads(resp.read().decode("utf-8"))
                return status, body
        except urllib.error.HTTPError as e:
            err_body = json.loads(e.read().decode("utf-8")) if e.fp else {}
            return e.code, err_body

    def test_01_lis_process_restart_http_durability(self):
        """
        PRUEBA 1: Reinicio de proceso HTTP del LIS.
        Verifica que órdenes, mediciones y cadena de auditoría sobreviven al reinicio
        sin reset de hashes y con continuidad criptográfica perfecta.
        """
        test_dir = tempfile.mkdtemp(prefix="durability_test_01_")
        db_path = os.path.join(test_dir, "lis_restart.db")
        token_rec = self._generate_jwt("recepcion", ["ROLE_RECEPTION"], mfa=False)
        token_med = self._generate_jwt("medico", ["ROLE_PATHOLOGIST"], mfa=True)
        token_aud = self._generate_jwt("auditor", ["ROLE_SECURITY_AUDITOR"], mfa=False)

        try:
            # --- FASE A: Iniciar Servidor 1 sobre db_path ---
            server.db_manager = ClinicalDatabaseManager(db_path=db_path)
            server.ORDERS_DB = server.DatabaseBackedOrdersDict(server.db_manager)
            server.AUDIT_LOGS = server.DatabaseBackedAuditLogs(server.db_manager)
            server.LAST_AUDIT_HASH = server.db_manager.get_last_audit_hash()
            server.ZeroTrustRequestHandler.validator = self.validator

            httpd1 = server.HTTPServer(("127.0.0.1", 0), server.ZeroTrustRequestHandler)
            httpd1.validator = self.validator
            port1 = httpd1.server_address[1]
            th1 = threading.Thread(target=httpd1.serve_forever, daemon=True)
            th1.start()
            time.sleep(0.2)

            # 1. Crear Orden 1
            code, res = self._http_request(
                port1, "/api/v1/orders", "POST", token=token_rec,
                data={"order_id": "ORD-RESTART-01", "patient_dni": "11223344", "test_type": "HEMOGRAMA"}
            )
            self.assertEqual(code, 201, f"Fallo al crear orden en Servidor 1: code={code}, res={res}")

            # 2. Ingestar IoMT (canal M2M con clave por dispositivo y antirreplay)
            device_id = "IOMT-LAB-01"
            device_key = b"durability-iomt-device-key-0001"
            server.IOMT_DEVICE_KEYS = {device_id: device_key}
            iomt_payload = {"order_id": "ORD-RESTART-01", "measurements": {"leucocitos_mm3": 7200.0}}
            iomt_body = json.dumps(iomt_payload)
            stamp = str(time.time())
            nonce = uuid.uuid4().hex
            signing_input = f"{device_id}\n{stamp}\n{nonce}\n{iomt_body}"
            dev_sig = hmac.new(device_key, signing_input.encode(), hashlib.sha256).hexdigest()
            code, res = self._http_request(
                port1, "/api/v1/iomt/results", "POST",
                data=iomt_payload,
                headers={
                    "X-Device-Id": device_id,
                    "X-Device-Signature": dev_sig,
                    "X-Device-Timestamp": stamp,
                    "X-Device-Nonce": nonce,
                }
            )
            self.assertEqual(code, 200)

            # 3. Validar Médicamente con MFA
            code, res = self._http_request(
                port1, "/api/v1/orders/validate", "POST", token=token_med,
                data={"order_id": "ORD-RESTART-01", "observations": "Analítica conforme"}
            )
            self.assertEqual(code, 200)

            # 4. Obtener estado antes del apagado
            code, audit_resp = self._http_request(port1, "/api/v1/audit/events", "GET", token=token_aud)
            self.assertEqual(code, 200)
            events_before = audit_resp["events"]
            total_before = len(events_before)
            last_hash_before = events_before[-1]["hash"]
            self.assertTrue(audit_resp["audit_chain_valid"])

            # --- FASE B: Detener Servidor 1 (Simulación de reinicio/caída de proceso) ---
            httpd1.shutdown()
            httpd1.server_close()
            server.db_manager.close()
            time.sleep(0.2)

            # --- FASE C: Iniciar Servidor 2 sobre el MISMO archivo de base de datos ---
            new_db_manager = ClinicalDatabaseManager(db_path=db_path)
            server.db_manager = new_db_manager
            server.ORDERS_DB = server.DatabaseBackedOrdersDict(new_db_manager)
            server.AUDIT_LOGS = server.DatabaseBackedAuditLogs(new_db_manager)
            server.LAST_AUDIT_HASH = new_db_manager.get_last_audit_hash()

            httpd2 = server.HTTPServer(("127.0.0.1", 0), server.ZeroTrustRequestHandler)
            httpd2.validator = self.validator
            port2 = httpd2.server_address[1]
            th2 = threading.Thread(target=httpd2.serve_forever, daemon=True)
            th2.start()
            time.sleep(0.2)

            # 1. Consultar órdenes en Servidor 2
            code, orders_resp = self._http_request(port2, "/api/v1/orders", "GET", token=token_rec)
            self.assertEqual(code, 200)
            orders = orders_resp["orders"]
            self.assertEqual(len(orders), 1)
            order = orders[0]
            self.assertEqual(order["order_id"], "ORD-RESTART-01")
            self.assertEqual(order["status"], "VALIDATED_AND_RELEASED")
            self.assertEqual(order["measurements"]["leucocitos_mm3"], 7200.0)
            self.assertEqual(order["validated_by"], "medico")
            # El sello de integridad reemplaza a la firma ad hoc anterior.
            self.assertIn("integrity_seal", order)
            self.assertNotIn("digital_signature", order)

            # 2. Consultar eventos de auditoría en Servidor 2
            code, audit_resp2 = self._http_request(port2, "/api/v1/audit/events", "GET", token=token_aud)
            self.assertEqual(code, 200)
            self.assertTrue(audit_resp2["audit_chain_valid"])
            # Se sumaron los eventos de consulta del nuevo servidor
            self.assertGreaterEqual(len(audit_resp2["events"]), total_before)

            # 3. Registrar nueva orden en Servidor 2 y verificar continuidad criptográfica
            code, res = self._http_request(
                port2, "/api/v1/orders", "POST", token=token_rec,
                data={"order_id": "ORD-RESTART-02", "patient_dni": "88776655", "test_type": "GLUCOSA"}
            )
            self.assertEqual(code, 201)

            # Verificar que la cadena sigue 100% válida y el hash histórico nunca se reinició a 0
            valid, err = new_db_manager.verify_chain_integrity()
            self.assertTrue(valid, f"Cadena rota tras reinicio: {err}")
            self.assertNotEqual(new_db_manager.get_last_audit_hash(), "0" * 64)

            httpd2.shutdown()
            httpd2.server_close()
            new_db_manager.close()
        finally:
            shutil.rmtree(test_dir, ignore_errors=True)

    def test_02_docker_container_recreation_with_persistent_volume(self):
        """
        PRUEBA 2: Recreación de Contenedor Docker con Volumen Persistente.
        Verifica que bajo 'read_only: true', 'user: 65534:65534', cap_drop ALL y
        recreación destructiva ('docker rm -f'), los datos persisten intactos en el volumen.
        """
        vol_name = f"test-lis-durability-vol-{int(time.time())}"
        container_1 = f"test-lis-c1-{int(time.time())}"
        container_2 = f"test-lis-c2-{int(time.time())}"

        # 1. Crear volumen Docker persistente
        subprocess.run(["docker", "volume", "create", vol_name], check=True, capture_output=True)

        try:
            # 2. Configurar permisos del volumen para el usuario '65534:65534' (nobody)
            # Requisito crítico descubierto en análisis arquitectónico
            subprocess.run([
                "docker", "run", "--rm",
                "-v", f"{vol_name}:/data:rw",
                "python:3.12-slim-bookworm",
                "sh", "-c", "chown -R 65534:65534 /data && chmod 770 /data"
            ], check=True, capture_output=True)

            # 3. Lanzar Contenedor 1 con políticas estrictas de endurecimiento
            # e insertar orden clínica sintética ORD-DOCKER-01
            insert_script = (
                "import os, sys, time; sys.path.insert(0, '/app'); "
                "from database import ClinicalDatabaseManager; "
                "db = ClinicalDatabaseManager(db_path='/data/lis.db'); "
                "db.save_order({'order_id': 'ORD-DOCKER-01', 'patient_dni': '99001122', 'status': 'SAMPLE_COLLECTED'}); "
                "ev = db.record_audit_event('CREATE_ORDER', 'recepcion.c1', 'ROLE_RECEPTION', 'SUCCESS', 'Order 1 created'); "
                "print(f'C1_SAVED:{ev[\"hash\"]}'); db.close()"
            )

            res1 = subprocess.run([
                "docker", "run", "--name", container_1,
                "-v", f"{vol_name}:/data:rw",
                "-v", f"{CURRENT_DIR}:/app:ro",
                "--user", "65534:65534",
                "--read-only",
                "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges:true",
                "python:3.12-slim-bookworm",
                "python", "-c", insert_script
            ], check=True, capture_output=True, text=True)

            self.assertIn("C1_SAVED:", res1.stdout)
            c1_hash = [line for line in res1.stdout.splitlines() if line.startswith("C1_SAVED:")][0].split(":")[1]

            # 4. DESTRUIR CONTENEDOR 1 DE MANERA FORZOSA (docker rm -f)
            subprocess.run(["docker", "rm", "-f", container_1], check=True, capture_output=True)

            # 5. Lanzar Contenedor 2 montando el MISMO volumen Docker persistente
            # Verificar que ORD-DOCKER-01 existe e insertar ORD-DOCKER-02
            verify_script = (
                "import os, sys; sys.path.insert(0, '/app'); "
                "from database import ClinicalDatabaseManager; "
                "db = ClinicalDatabaseManager(db_path='/data/lis.db'); "
                "ord1 = db.get_order('ORD-DOCKER-01'); "
                "assert ord1 is not None and ord1['patient_dni'] == '99001122', 'Orden 1 no encontrada'; "
                "db.save_order({'order_id': 'ORD-DOCKER-02', 'patient_dni': '77889900', 'status': 'ANALYZED'}); "
                "ev2 = db.record_audit_event('CREATE_ORDER', 'recepcion.c2', 'ROLE_RECEPTION', 'SUCCESS', 'Order 2 created'); "
                "valid, err = db.verify_chain_integrity(); "
                "assert valid, f'Cadena invalida: {err}'; "
                "orders = db.get_orders(); "
                "print(f'C2_VERIFIED:TOTAL_ORDERS={len(orders)}:LAST_HASH={db.get_last_audit_hash()}'); "
                "db.close()"
            )

            res2 = subprocess.run([
                "docker", "run", "--name", container_2,
                "-v", f"{vol_name}:/data:rw",
                "-v", f"{CURRENT_DIR}:/app:ro",
                "--user", "65534:65534",
                "--read-only",
                "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges:true",
                "python:3.12-slim-bookworm",
                "python", "-c", verify_script
            ], check=True, capture_output=True, text=True)

            self.assertIn("C2_VERIFIED:TOTAL_ORDERS=2", res2.stdout)

            # Destruir Contenedor 2
            subprocess.run(["docker", "rm", "-f", container_2], check=True, capture_output=True)

        finally:
            subprocess.run(["docker", "rm", "-f", container_1], capture_output=True)
            subprocess.run(["docker", "rm", "-f", container_2], capture_output=True)
            subprocess.run(["docker", "volume", "rm", vol_name], capture_output=True)

    def test_03_code_rollback_with_storage_preservation(self):
        """
        PRUEBA 3: Rollback de Código con Preservación de Almacenamiento.
        Verifica que ante un despliegue y posterior rollback de binarios/scripts,
        el almacenamiento relacional no sufre corrupción ni pérdida de registros.
        """
        test_dir = tempfile.mkdtemp(prefix="durability_test_03_")
        db_path = os.path.join(test_dir, "lis_rollback.db")

        try:
            # 1. Versión N escribe datos
            db_v1 = ClinicalDatabaseManager(db_path=db_path)
            db_v1.save_order({"order_id": "ORD-V1", "patient_dni": "12345678", "status": "SAMPLE_COLLECTED"})
            db_v1.record_audit_event("DEPLOY_V1", "devops", "ROLE_ADMIN", "SUCCESS", "Despliegue version v1")
            v1_hash = db_v1.get_last_audit_hash()
            db_v1.close()

            # 2. Simulación de actualización de código y escritura
            db_v2 = ClinicalDatabaseManager(db_path=db_path)
            db_v2.save_order({"order_id": "ORD-V2", "patient_dni": "87654321", "status": "ANALYZED"})
            db_v2.record_audit_event("DEPLOY_V2", "devops", "ROLE_ADMIN", "SUCCESS", "Despliegue version v2")
            db_v2.close()

            # 3. Rollback a versión V1 apuntando a la misma base de datos
            db_rollback = ClinicalDatabaseManager(db_path=db_path)
            orders = db_rollback.get_orders()
            self.assertEqual(len(orders), 2)
            self.assertIsNotNone(db_rollback.get_order("ORD-V1"))
            self.assertIsNotNone(db_rollback.get_order("ORD-V2"))

            valid, err = db_rollback.verify_chain_integrity()
            self.assertTrue(valid, f"Cadena rota tras rollback: {err}")
            db_rollback.close()
        finally:
            shutil.rmtree(test_dir, ignore_errors=True)

    def test_04_storage_failure_fail_closed_handling(self):
        """
        PRUEBA 4: Fallo de Almacenamiento y Comportamiento Fail-Closed.
        Simula almacenamiento inaccesible o de solo lectura no autorizado.
        Verifica que el LIS responde HTTP 500 PERSISTENCE_TRANSACTION_FAILED de forma segura
        y nunca enmascara el fallo pretendiendo haber guardado la orden.
        """
        test_dir = tempfile.mkdtemp(prefix="durability_test_04_")
        db_path = os.path.join(test_dir, "lis_fail_closed.db")
        token_rec = self._generate_jwt("recepcion", ["ROLE_RECEPTION"], mfa=False)

        try:
            # Iniciar servidor sobre db_path
            db = ClinicalDatabaseManager(db_path=db_path)
            server.db_manager = db
            server.ORDERS_DB = server.DatabaseBackedOrdersDict(db)
            server.AUDIT_LOGS = server.DatabaseBackedAuditLogs(db)
            server.LAST_AUDIT_HASH = db.get_last_audit_hash()
            server.ZeroTrustRequestHandler.validator = self.validator

            httpd = server.HTTPServer(("127.0.0.1", 0), server.ZeroTrustRequestHandler)
            httpd.validator = self.validator
            port = httpd.server_address[1]
            th = threading.Thread(target=httpd.serve_forever, daemon=True)
            th.start()
            time.sleep(0.2)

            # 1. Petición normal funciona
            code, res = self._http_request(
                port, "/api/v1/orders", "POST", token=token_rec,
                data={"order_id": "ORD-NORMAL-01", "patient_dni": "10203040"}
            )
            self.assertEqual(code, 201, f"Fallo al crear orden normal: code={code}, res={res}")

            # 2. Provocar fallo de almacenamiento: cerrar conexión subyacente y simular bloqueo
            db.close()

            # 3. Intentar crear orden con almacenamiento roto
            code, err_res = self._http_request(
                port, "/api/v1/orders", "POST", token=token_rec,
                data={"order_id": "ORD-FAIL-01", "patient_dni": "99999999"}
            )
            # Debe fallar cerrado (HTTP 500)
            self.assertEqual(code, 500)
            self.assertEqual(err_res.get("code"), "PERSISTENCE_TRANSACTION_FAILED")
            self.assertIn("Fallo critico de persistencia duradera", err_res.get("message", ""))

            httpd.shutdown()
            httpd.server_close()
        finally:
            shutil.rmtree(test_dir, ignore_errors=True)

    def test_05_cold_hot_backup_and_disaster_recovery(self):
        """
        PRUEBA 5: Respaldo en Caliente y Recuperación ante Desastres (DR).
        Verifica respaldo atómico en línea (sqlite3.backup), simula destrucción total
        del almacenamiento primario y valida recuperación íntegra de órdenes y hashes.
        """
        test_dir = tempfile.mkdtemp(prefix="durability_test_05_")
        primary_db = os.path.join(test_dir, "primary.db")
        backup_file = os.path.join(test_dir, "backup", "lis_dr_backup.db")
        restored_db = os.path.join(test_dir, "restored.db")

        try:
            # 1. Poblar base de datos primaria
            db = ClinicalDatabaseManager(db_path=primary_db)
            db.save_order({"order_id": "ORD-DR-01", "patient_dni": "11112222", "status": "VALIDATED_AND_RELEASED"})
            db.save_order({"order_id": "ORD-DR-02", "patient_dni": "33334444", "status": "SAMPLE_COLLECTED"})
            db.record_audit_event("CREATE_ORDER", "recepcion", "ROLE_RECEPTION", "SUCCESS", "Order 1")
            db.record_audit_event("VALIDATE_ORDER", "medico", "ROLE_PATHOLOGIST", "SUCCESS", "Order 1 validated", mfa_verified=True)
            db.record_audit_event("CREATE_ORDER", "recepcion", "ROLE_RECEPTION", "SUCCESS", "Order 2")
            primary_hash = db.get_last_audit_hash()

            # 2. Ejecutar Respaldo Atómico en Línea
            db.backup_database(backup_file)
            self.assertTrue(os.path.exists(backup_file))
            self.assertEqual(os.stat(backup_file).st_mode & 0o777, 0o600)

            # 3. SIMULAR DESTRUCCIÓN TOTAL DEL ALMACENAMIENTO PRIMARIO
            db.close()
            os.remove(primary_db)
            if os.path.exists(primary_db + "-wal"):
                os.remove(primary_db + "-wal")
            if os.path.exists(primary_db + "-shm"):
                os.remove(primary_db + "-shm")
            self.assertFalse(os.path.exists(primary_db))

            # 4. RESTAURAR EN ENTORNO AISLADO A PARTIR DEL RESPALDO
            # El material de anclaje viaja con el respaldo: sin él la cadena no
            # puede verificarse y el arranque falla cerrado (sin claves por defecto).
            shutil.copy2(backup_file, restored_db)
            shutil.copy2(backup_file + ".anchor-key", restored_db + ".anchor-key")
            os.chmod(restored_db, 0o600)
            os.chmod(restored_db + ".anchor-key", 0o600)

            # 5. Instanciar LIS sobre base de datos restaurada y verificar integridad
            dr_db = ClinicalDatabaseManager(db_path=restored_db)
            orders = dr_db.get_orders()
            self.assertEqual(len(orders), 2)
            self.assertEqual(dr_db.get_order("ORD-DR-01")["status"], "VALIDATED_AND_RELEASED")
            self.assertEqual(dr_db.get_order("ORD-DR-02")["status"], "SAMPLE_COLLECTED")

            events = dr_db.get_audit_events()
            self.assertEqual(len(events), 3)
            self.assertEqual(dr_db.get_last_audit_hash(), primary_hash)

            valid, err = dr_db.verify_chain_integrity()
            self.assertTrue(valid, f"Cadena restaurada inválida: {err}")
            dr_db.close()

        finally:
            shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
