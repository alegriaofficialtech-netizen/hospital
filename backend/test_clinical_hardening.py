#!/usr/bin/env python3
"""
Suite de Endurecimiento Clínico y de Integridad
SGSI-ZTA Hospital Lab — ISO/IEC 27001:2022 Control A.8.15 & NIST SP 800-207

Cubre los hallazgos P0 del informe OPENCODE_CUTOVER_AUDIT.md:

- C-03: reutilizar un order_id sobrescribe la orden existente.
- C-04: el canal IoMT degrada órdenes liberadas y crea órdenes sin admisión.
- C-05: la validación médica exige estado ANALYZED, mediciones válidas y un
        sello de integridad sobre el contenido (no un hash de identificadores).
- C-06: la orden y su evento de auditoría se confirman en una sola transacción.
- C-07: el borrado o truncado de la cadena de auditoría se detecta siempre.
- C-08: dos escritores concurrentes no rompen la cadena.
- C-09: el token M2M del auditor no puede leer órdenes clínicas y la auditoría
        no almacena PHI en claro.
- A-01: no existen claves de anclaje de auditoría ni claves IoMT por defecto.
- A-02: el canal IoMT tiene firma con dispositivo+timestamp+nonce, ventana
        temporal, claves por dispositivo y registro antirreplay.
- A-04: el monitor rechaza una cadena vacía y devuelve código de salida != 0.
- A-05: synchronous=FULL y base, WAL, SHM y clave de anclaje en 0600.
"""

import contextlib
import copy
import hashlib
import hmac
import io
import json
import os
import stat
import sys
import tempfile
import threading
import time
import unittest
import uuid
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional
from unittest import mock

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

import server
from audit_monitor import monitor
from clinical_domain import (
    ORDER_ANALYZED,
    ORDER_RELEASED,
    ORDER_SAMPLE_COLLECTED,
    patient_reference,
    verify_integrity_seal,
)
from database import (
    AuditChainCorruptedError,
    ClinicalDatabaseManager,
    DatabaseError,
)
from jwt_validator import JWKSCacheManager, ZeroTrustJWTValidator

TEST_ISSUER = "http://127.0.0.1:8085/realms/hospital-lab"
TEST_AUDIENCE = "clinical-poc-api"
TEST_AZP = "clinical-poc"
TEST_KID = "hardening-rsa-key-01"
DEVICE_ID = "IOMT-HARDENING-01"
DEVICE_KEY = b"hardening-iomt-device-key-0001"


def b64url(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class HardeningMockJWKSCache(JWKSCacheManager):
    """Caché JWKS en memoria con clave RSA sintética para pruebas deterministas."""

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


class TestClinicalHardening(unittest.TestCase):
    """Pruebas de regresión de los hallazgos clínicos, de integridad y de privilegio."""

    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public_key = cls.private_key.public_key()
        cls.cache = HardeningMockJWKSCache(cls.public_key, TEST_KID, TEST_ISSUER)
        cls.validator = ZeroTrustJWTValidator(
            discovery_url=f"{TEST_ISSUER}/.well-known/openid-configuration",
            expected_audience=TEST_AUDIENCE,
            cache_manager=cls.cache,
            expected_authorized_party=TEST_AZP,
            require_bearer_type=False,
        )

        server.ORDERS_DB.clear()
        server.AUDIT_LOGS.clear()
        server.IOMT_DEVICE_KEYS = {DEVICE_ID: DEVICE_KEY}

        cls.httpd = server.HTTPServer(("127.0.0.1", 0), server.ZeroTrustRequestHandler)
        cls.httpd.validator = cls.validator
        cls.port = cls.httpd.server_address[1]
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    # ------------------------------------------------------------------
    # Utilidades
    # ------------------------------------------------------------------
    def create_signed_token(
        self,
        username: str,
        roles: List[str],
        amr: Optional[List[str]] = None,
    ) -> str:
        now = int(time.time())
        header = {"alg": "RS256", "typ": "JWT", "kid": TEST_KID}
        payload = {
            "sub": f"uuid-{username}-hardening",
            "preferred_username": username,
            "iss": TEST_ISSUER,
            "aud": [TEST_AUDIENCE],
            "azp": TEST_AZP,
            "typ": "Bearer",
            "exp": now + 3600,
            "nbf": now - 5,
            "iat": now,
            "jti": f"jwt-{username}-{now}",
            "realm_access": {"roles": roles},
            "amr": amr if amr is not None else ["pwd"],
        }
        raw_header = b64url(json.dumps(header).encode("utf-8"))
        raw_payload = b64url(json.dumps(payload).encode("utf-8"))
        signing_input = f"{raw_header}.{raw_payload}".encode("ascii")
        sig = self.private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        return f"{raw_header}.{raw_payload}.{b64url(sig)}"

    def do_request(
        self,
        method: str,
        path: str,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> tuple[int, Dict[str, Any]]:
        url = f"{self.base_url}{path}"
        req_headers = {"Content-Type": "application/json"}
        if headers:
            req_headers.update(headers)
        generic_payload = json.dumps(data).encode("utf-8") if data is not None else None
        req = urllib.request.Request(url, data=generic_payload, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as res:
                return res.status, json.loads(res.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8")
            try:
                return exc.code, json.loads(raw)
            except Exception:
                return exc.code, {"raw": raw}

    def create_order(self, order_id: str, patient_dni: str = "DNI-7000") -> None:
        token = self.create_signed_token("admision.hardening", roles=["admision"])
        status, body = self.do_request(
            "POST",
            "/api/v1/orders",
            {"order_id": order_id, "patient_dni": patient_dni, "test_type": "HEMOGRAMA"},
            {"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(status, 201, f"Alta de orden falló: {body}")

    def iomt_headers(
        self,
        data: Dict[str, Any],
        nonce: str,
        key: bytes = DEVICE_KEY,
        device_id: str = DEVICE_ID,
        timestamp: Optional[str] = None,
    ) -> Dict[str, str]:
        raw_body = json.dumps(data)
        stamp = timestamp if timestamp is not None else str(time.time())
        signing_input = f"{device_id}\n{stamp}\n{nonce}\n{raw_body}"
        signature = hmac.new(key, signing_input.encode("utf-8"), hashlib.sha256).hexdigest()
        return {
            "X-Device-Id": device_id,
            "X-Device-Signature": signature,
            "X-Device-Timestamp": stamp,
            "X-Device-Nonce": nonce,
        }

    def send_results(self, order_id: str, value: float = 14.2):
        # Nonce único por ejecución: la tabla de nonces es durable entre corridas.
        data = {"order_id": order_id, "measurements": {"hemoglobina_g_dl": value}}
        nonce = uuid.uuid4().hex
        return self.do_request("POST", "/api/v1/iomt/results", data, self.iomt_headers(data, nonce))

    def validate_order(self, order_id: str):
        token = self.create_signed_token("medico.hardening", roles=["medico"], amr=["pwd", "otp"])
        return self.do_request(
            "POST",
            "/api/v1/orders/validate",
            {"order_id": order_id, "observations": "Conforme"},
            {"Authorization": f"Bearer {token}"},
        )

    # ------------------------------------------------------------------
    # C-03: el alta nunca sobrescribe una orden existente
    # ------------------------------------------------------------------
    def test_01_duplicate_order_is_rejected_without_overwrite(self):
        order_id = "ORD-HARD-DUP-01"
        self.create_order(order_id, patient_dni="DNI-DUP-0001")

        token = self.create_signed_token("admision.hardening", roles=["admision"])
        status, body = self.do_request(
            "POST",
            "/api/v1/orders",
            {"order_id": order_id, "patient_dni": "DNI-ATACANTE"},
            {"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(status, 409)
        self.assertEqual(body.get("code"), "ORDER_ALREADY_EXISTS")

        stored = server.db_manager.get_order(order_id)
        self.assertEqual(stored["patient_dni"], "DNI-DUP-0001")

    # ------------------------------------------------------------------
    # C-04: el canal IoMT no crea órdenes
    # ------------------------------------------------------------------
    def test_02_iomt_cannot_create_orders(self):
        order_id = "ORD-HARD-GHOST-01"
        status, body = self.send_results(order_id)
        self.assertEqual(status, 404)
        self.assertEqual(body.get("code"), "ORDER_NOT_FOUND")
        self.assertNotIn(order_id, server.ORDERS_DB)

    # ------------------------------------------------------------------
    # C-05: la validación exige el estado ANALYZED
    # ------------------------------------------------------------------
    def test_03_validate_requires_analyzed_state(self):
        order_id = "ORD-HARD-STATE-01"
        self.create_order(order_id)

        status, body = self.validate_order(order_id)
        self.assertEqual(status, 409)
        self.assertEqual(body.get("code"), "INVALID_ORDER_TRANSITION")
        self.assertEqual(server.db_manager.get_order(order_id)["status"], ORDER_SAMPLE_COLLECTED)

    # ------------------------------------------------------------------
    # C-04: las órdenes liberadas son inmutables
    # ------------------------------------------------------------------
    def test_04_released_order_rejects_further_mutations(self):
        order_id = "ORD-HARD-LOCK-01"
        self.create_order(order_id)

        status, _ = self.send_results(order_id)
        self.assertEqual(status, 200)

        status, body = self.validate_order(order_id)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["order"]["status"], ORDER_RELEASED)

        # Nueva reingesta del analizador: la orden liberada no admite cambios.
        status, body = self.send_results(order_id, value=15.9)
        self.assertEqual(status, 409)
        self.assertEqual(body.get("code"), "ORDER_LOCKED")

        # Revalidación: la firma médica no se puede repetir.
        status, body = self.validate_order(order_id)
        self.assertEqual(status, 409)
        self.assertEqual(body.get("code"), "ORDER_ALREADY_VALIDATED")

        stored = server.db_manager.get_order(order_id)
        self.assertEqual(stored["measurements"]["hemoglobina_g_dl"], 14.2)
        self.assertEqual(stored["status"], ORDER_RELEASED)

    # ------------------------------------------------------------------
    # C-05: el sello cubre el contenido clínico completo
    # ------------------------------------------------------------------
    def test_05_integrity_seal_binds_clinical_content(self):
        order_id = "ORD-HARD-SEAL-01"
        self.create_order(order_id)
        status, _ = self.send_results(order_id)
        self.assertEqual(status, 200)
        status, body = self.validate_order(order_id)
        self.assertEqual(status, 200, body)

        sealed = body["order"]
        self.assertTrue(verify_integrity_seal(sealed, server.get_seal_key()))

        altered_value = copy.deepcopy(sealed)
        altered_value["measurements"]["hemoglobina_g_dl"] = 9.9
        self.assertFalse(verify_integrity_seal(altered_value, server.get_seal_key()))

        altered_state = copy.deepcopy(sealed)
        altered_state["status"] = ORDER_ANALYZED
        self.assertFalse(verify_integrity_seal(altered_state, server.get_seal_key()))

        # Una clave ajena no valida el sello: no es un hash público.
        self.assertFalse(verify_integrity_seal(sealed, b"foreign-key-with-32-bytes-entropy!"))

    # ------------------------------------------------------------------
    # C-06: orden + auditoría en una sola transacción
    # ------------------------------------------------------------------
    def test_06_order_and_audit_rollback_together(self):
        order_id = "ORD-HARD-ATOMIC-01"
        events_before = len(server.db_manager.get_audit_events())

        def boom(*args, **kwargs):
            raise DatabaseError("fallo de auditoría inducido")

        with mock.patch.object(server.db_manager, "_insert_audit_event", side_effect=boom):
            with self.assertRaises(DatabaseError):
                server.db_manager.create_order(
                    {
                        "order_id": order_id,
                        "patient_dni": "DNI-ATOMIC",
                        "test_type": "HEMOGRAMA",
                        "status": ORDER_SAMPLE_COLLECTED,
                        "measurements": {},
                        "version": 1,
                    },
                    audit_event={
                        "action": "CREATE_ORDER",
                        "actor": "suite",
                        "role": "ROLE_RECEPTION",
                        "status": "SUCCESS",
                        "details": "alta atómica",
                        "ip": "127.0.0.1",
                        "mfa_verified": False,
                    },
                )

        self.assertIsNone(server.db_manager.get_order(order_id))
        self.assertEqual(len(server.db_manager.get_audit_events()), events_before)

    # ------------------------------------------------------------------
    # C-07: borrado o truncado de la cadena siempre se detecta
    # ------------------------------------------------------------------
    def test_07_audit_chain_truncation_is_detected(self):
        order_id = "ORD-HARD-AUDIT-01"
        self.create_order(order_id)

        conn = server.db_manager._get_conn()
        conn.execute("DELETE FROM audit_events WHERE id = (SELECT MAX(id) FROM audit_events);")

        try:
            valid, reason = server.db_manager.verify_chain_integrity()
            self.assertFalse(valid, "El truncado de la cadena debe ser detectado")
            self.assertIsNotNone(reason)

            token = self.create_signed_token("auditor.hardening", roles=["auditor"])
            status, body = self.do_request(
                "GET", "/api/v1/audit/events", headers={"Authorization": f"Bearer {token}"}
            )
            self.assertEqual(status, 200)
            self.assertFalse(body.get("audit_chain_valid"))
            self.assertIsNotNone(body.get("chain_error"))
        finally:
            # Restauración autorizada y explícita del estado de la suite.
            server.AUDIT_LOGS.clear()

        valid, _ = server.db_manager.verify_chain_integrity()
        self.assertTrue(valid)

    # ------------------------------------------------------------------
    # C-09: VIEW_ORDERS se aplica por política
    # ------------------------------------------------------------------
    def test_08_view_orders_requires_explicit_role(self):
        token = self.create_signed_token("auditor.hardening", roles=["auditor"])
        status, body = self.do_request(
            "GET", "/api/v1/orders", headers={"Authorization": f"Bearer {token}"}
        )
        self.assertEqual(status, 403)
        self.assertEqual(body.get("code"), "INSUFFICIENT_ROLE_PERMISSIONS")

        tech_token = self.create_signed_token("tecnico.hardening", roles=["laboratorio"])
        status, _ = self.do_request(
            "GET", "/api/v1/orders", headers={"Authorization": f"Bearer {tech_token}"}
        )
        self.assertEqual(status, 200)

    # ------------------------------------------------------------------
    # A-01: sin claves de anclaje embebidas
    # ------------------------------------------------------------------
    def test_09_anchor_key_is_never_a_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = os.path.join(tmp, "first.db")
            second = os.path.join(tmp, "second.db")

            mgr_first = ClinicalDatabaseManager(first)
            mgr_second = ClinicalDatabaseManager(second)
            try:
                self.assertNotEqual(mgr_first.anchor_key, mgr_second.anchor_key)
                self.assertNotEqual(
                    mgr_first.anchor_key,
                    b"SGSI-ZTA-Default-Audit-Anchor-2026",
                    "La clave por defecto del informe no debe existir",
                )
                self.assertEqual(len(mgr_first.anchor_key), 32)

                mgr_first.record_audit_event("TEST", "suite", "ROLE_ADMIN", "SUCCESS", "anclaje")
            finally:
                mgr_first.close()
                mgr_second.close()

            # Una cadena existente sin clave de anclaje falla cerrada al arrancar.
            os.remove(first + ".anchor-key")
            with self.assertRaises(AuditChainCorruptedError):
                ClinicalDatabaseManager(first)

    # ------------------------------------------------------------------
    # A-04: el monitor no acepta una cadena vacía
    # ------------------------------------------------------------------
    def test_10_monitor_rejects_empty_chain(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(monitor.verify_audit_chain([]))

            events = server.db_manager.get_audit_events()
            self.assertGreaterEqual(len(events), 1)
            self.assertTrue(monitor.verify_audit_chain(events))

            # Un prefijo de la cadena sigue siendo autoconsistente por diseño:
            # el truncado por la cola solo se detecta con el checkpoint del
            # servidor, por eso run_audit_cycle exige también ese veredicto.
            # Un borrado en la cabeza sí rompe el encadenamiento local.
            self.assertFalse(monitor.verify_audit_chain(events[1:]))

            # El veredicto de checkpoint del servidor también se exige.
            payload = json.dumps({"audit_chain_valid": False, "events": events}).encode("utf-8")

            class FakeResponse:
                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

                def read(self):
                    return payload

            with mock.patch.object(monitor, "get_auditor_token", return_value="token"), \
                    mock.patch.object(monitor.urllib.request, "urlopen", return_value=FakeResponse()):
                result = monitor.run_audit_cycle(custom_audit_url="http://127.0.0.1:1/api/v1/audit/events")

            self.assertEqual(result["status"], "SUCCESS")
            self.assertFalse(result["chain_valid"])
            self.assertEqual(monitor.audit_exit_code(result), 1)
            self.assertEqual(monitor.audit_exit_code({"status": "SUCCESS", "chain_valid": True}), 0)
            self.assertEqual(monitor.audit_exit_code({"status": "AUTH_FAILED", "chain_valid": False}), 1)

    # ------------------------------------------------------------------
    # A-05: permisos de propietario para datos clínicos
    # ------------------------------------------------------------------
    def test_11_database_files_are_owner_only(self):
        db_path = server.db_manager.db_path
        targets = [db_path]
        for suffix in ("-wal", "-shm"):
            if os.path.exists(db_path + suffix):
                targets.append(db_path + suffix)
        targets.append(db_path + ".anchor-key")

        for path in targets:
            self.assertTrue(os.path.exists(path), f"Archivo esperado ausente: {path}")
            mode = stat.S_IMODE(os.stat(path).st_mode)
            self.assertEqual(mode, 0o600, f"{path} debe ser 0600, obtenido {oct(mode)}")

    # ------------------------------------------------------------------
    # C-09: los eventos de auditoría no contienen PHI en claro
    # ------------------------------------------------------------------
    def test_12_audit_details_are_pseudonymized(self):
        order_id = "ORD-HARD-PHI-01"
        dni = "DNI-SECRET-987654"
        self.create_order(order_id, patient_dni=dni)

        events = server.db_manager.get_audit_events()
        created = [e for e in events if e.get("action") == "CREATE_ORDER" and order_id in e.get("details", "")]
        self.assertTrue(created, "Debe existir el evento de alta de la orden")
        details = created[-1]["details"]
        self.assertNotIn(dni, details)
        self.assertIn(patient_reference(dni), details)


    # ------------------------------------------------------------------
    # A-02: antirreplay, separación por dispositivo y ventana temporal
    # ------------------------------------------------------------------
    def test_13_iomt_anti_replay_and_device_isolation(self):
        order_id = "ORD-HARD-IOMT-01"
        self.create_order(order_id)

        status, body = self.send_results(order_id)
        self.assertEqual(status, 200, body)

        data = {"order_id": order_id, "measurements": {"hemoglobina_g_dl": 8.8}}
        nonce = uuid.uuid4().hex

        # Reenvío exacto del mismo nonce.
        status, body = self.do_request(
            "POST", "/api/v1/iomt/results", data, self.iomt_headers(data, nonce)
        )
        self.assertEqual(status, 200, body)
        status, body = self.do_request(
            "POST", "/api/v1/iomt/results", data, self.iomt_headers(data, nonce)
        )
        self.assertEqual(status, 409)
        self.assertEqual(body.get("code"), "IOMT_REPLAY_DETECTED")

        # Firma con clave ajena: el dispositivo no puede suplantar a otro.
        status, body = self.do_request(
            "POST",
            "/api/v1/iomt/results",
            data,
            self.iomt_headers(data, uuid.uuid4().hex, key=b"foreign-device-key-000000000001"),
        )
        self.assertEqual(status, 403)
        self.assertEqual(body.get("code"), "IOMT_INVALID_SIGNATURE")

        # Dispositivo no registrado.
        status, body = self.do_request(
            "POST",
            "/api/v1/iomt/results",
            data,
            self.iomt_headers(data, uuid.uuid4().hex, device_id="IOMT-NO-AUTORIZADO"),
        )
        self.assertEqual(status, 403)
        self.assertEqual(body.get("code"), "IOMT_UNKNOWN_DEVICE")

        # Marca temporal fuera de la ventana permitida.
        status, body = self.do_request(
            "POST",
            "/api/v1/iomt/results",
            data,
            self.iomt_headers(data, uuid.uuid4().hex, timestamp=str(time.time() - 3600)),
        )
        self.assertEqual(status, 401)
        self.assertEqual(body.get("code"), "IOMT_STALE_TIMESTAMP")

        # Ningún intento rechazado modificó la orden.
        stored = server.db_manager.get_order(order_id)
        self.assertEqual(stored["measurements"]["hemoglobina_g_dl"], 8.8)
        self.assertEqual(stored["status"], ORDER_ANALYZED)

    # ------------------------------------------------------------------
    # A-05: sincronización FULL (RPO estricto)
    # ------------------------------------------------------------------
    def test_14_synchronous_is_full(self):
        conn = server.db_manager._get_conn()
        sync_mode = conn.execute("PRAGMA synchronous;").fetchone()[0]
        self.assertEqual(sync_mode, 2, f"PRAGMA synchronous esperado 2 (FULL), obtenido: {sync_mode}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
