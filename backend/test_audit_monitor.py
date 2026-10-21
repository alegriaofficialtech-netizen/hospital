#!/usr/bin/env python3
"""
Suite de Pruebas de Integracion y Transicion de Audit-Monitor (Endurecida Zero Trust)
SGSI-ZTA Hospital Lab — ISO/IEC 27001:2022 Control A.8.15 & NIST SP 800-207

Verifica:
1. Autenticacion M2M via OAuth 2.0 Client Credentials (RFC 6749 §4.4)
2. Principio de Menor Privilegio (denegacion de operaciones clinicas con token de servicio)
3. Prohibicion estricta de fallback automatico cuando falla OAuth
4. Falla cerrada (Fail-Closed) en ausencia de secretos externos obligatorios
5. Restriccion absoluta de login legacy (prohibido para usuarios clinicos y medicos)
6. Aislamiento continuo del canal IoMT
"""

import base64
import hashlib
import hmac
import json
import os
import sys
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import HTTPServer

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

import server
from audit_monitor import monitor

TEST_CREDS_FILE = "/home/elcra/sandbox-jwt-validator/.env.audit_monitor_credentials"
DISCOVERY_URL = "http://127.0.0.1:8085/realms/hospital-lab-oidc-test/.well-known/openid-configuration"
TEST_TRANSITION_HMAC = b"secure-external-transition-key-with-high-entropy-64bytes-min-len!"
TEST_AUDITOR_PASS = "AuditorCISO2026!"
TEST_AUDITOR_HASH = hashlib.sha256(TEST_AUDITOR_PASS.encode("utf-8")).hexdigest()


class TestAuditMonitorIntegration(unittest.TestCase):
    httpd = None
    server_thread = None
    port = 8991
    base_url = f"http://127.0.0.1:{port}"

    @classmethod
    def setUpClass(cls):
        server.DEFAULT_DISCOVERY_URL = DISCOVERY_URL
        server.DEFAULT_AUDIENCE = "clinical-poc-api"
        server.ZeroTrustRequestHandler._default_validator = None
        server.ORDERS_DB.clear()
        server.AUDIT_LOGS.clear()
        server.LAST_AUDIT_HASH = "0" * 64

        server.record_audit_event("INIT_TEST", "SYSTEM", "ROLE_ADMIN", "ALLOWED", "Inicio suite audit-monitor")

        server_address = ("127.0.0.1", cls.port)
        cls.httpd = HTTPServer(server_address, server.ZeroTrustRequestHandler)
        cls.server_thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        if cls.httpd:
            cls.httpd.shutdown()
            cls.httpd.server_close()

    def setUp(self):
        server.ENABLE_LEGACY_AUTH = False
        server.LEGACY_HMAC_SECRET = None
        server.LEGACY_AUDITOR_HASH = ""
        monitor.USE_LEGACY_AUTH = False
        monitor.AUDITOR_USER = ""
        monitor.AUDITOR_PASS = ""
        monitor._CACHED_TOKEN = None
        monitor._TOKEN_EXPIRES_AT = 0.0

    def get_service_token(self) -> str:
        """Obtiene un token real de servicio via Keycloak Client Credentials."""
        creds = {}
        with open(TEST_CREDS_FILE, "r") as f:
            for line in f:
                if "=" in line and not line.startswith("#"):
                    k, v = line.strip().split("=", 1)
                    creds[k] = v

        data = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": creds["AUDIT_MONITOR_CLIENT_ID"],
            "client_secret": creds["AUDIT_MONITOR_CLIENT_SECRET"]
        }).encode("utf-8")

        req = urllib.request.Request(creds["AUDIT_MONITOR_TOKEN_URL"], data=data, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            return body["access_token"]

    def do_request(self, method: str, path: str, data=None, headers=None) -> tuple[int, dict, dict]:
        url = f"{self.base_url}{path}"
        req_headers = {"Content-Type": "application/json"}
        if headers:
            req_headers.update(headers)
        payload = json.dumps(data).encode("utf-8") if data is not None else None
        req = urllib.request.Request(url, data=payload, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as res:
                res_headers = dict(res.headers)
                return res.status, json.loads(res.read().decode("utf-8")), res_headers
        except urllib.error.HTTPError as e:
            res_headers = dict(e.headers)
            body = e.read().decode("utf-8")
            try:
                parsed = json.loads(body)
            except Exception:
                parsed = {"raw": body}
            return e.code, parsed, res_headers

    # 1. Obtencion de token OAuth 2.0 Client Credentials y verificacion de claims
    def test_01_client_credentials_token_retrieval(self):
        token = self.get_service_token()
        self.assertIsNotNone(token)
        parts = token.split(".")
        self.assertEqual(len(parts), 3, "El token debe ser un JWT OIDC RS256 de 3 partes")
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "==").decode("utf-8"))
        self.assertIn("auditor", payload.get("realm_access", {}).get("roles", []))
        self.assertIn("clinical-poc-api", payload.get("aud", []))
        self.assertEqual(payload.get("typ"), "Bearer")

    # 2. Modernizado monitor.py consulta eventos de auditoria exitosamente con Client Credentials
    def test_02_audit_monitor_queries_audit_events_successfully(self):
        server.ENABLE_LEGACY_AUTH = False
        audit_url = f"{self.base_url}/api/v1/audit/events"
        res = monitor.run_audit_cycle(custom_audit_url=audit_url)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertTrue(res["chain_valid"], "La cadena de auditoria debe ser criptograficamente valida")
        self.assertGreaterEqual(res["events_count"], 1)

    # 3. Menor privilegio: Token de servicio no puede crear ordenes clinicas (CREATE_ORDER)
    def test_03_service_token_cannot_create_orders(self):
        token = self.get_service_token()
        status, body, _ = self.do_request(
            "POST",
            "/api/v1/orders",
            {"order_id": "ORD-AUDIT-FAIL", "patient_dni": "DNI-999"},
            {"Authorization": f"Bearer {token}"}
        )
        self.assertEqual(status, 403)
        self.assertEqual(body.get("code"), "RECEPTION_ROLE_REQUIRED")

    # 4. Menor privilegio: Token de servicio no puede validar ordenes clinicas (VALIDATE_ORDER)
    def test_04_service_token_cannot_validate_orders(self):
        token = self.get_service_token()
        status, body, _ = self.do_request(
            "POST",
            "/api/v1/orders/validate",
            {"order_id": "ORD-AUDIT-FAIL"},
            {"Authorization": f"Bearer {token}"}
        )
        self.assertEqual(status, 403)
        self.assertIn(body.get("code"), ("MFA_AUTHENTICATION_REQUIRED", "AUDITOR_ROLE_REQUIRED", "INSUFFICIENT_ROLE_PERMISSIONS", "PATHOLOGIST_ROLE_REQUIRED"))

    # 5. Por defecto (sin bandera), el login legacy responde 410 Gone para todos
    def test_05_legacy_login_disabled_by_default(self):
        server.ENABLE_LEGACY_AUTH = False
        status, body, _ = self.do_request(
            "POST",
            "/api/v1/auth/login",
            {"username": "auditor", "password": TEST_AUDITOR_PASS}
        )
        self.assertEqual(status, 410)
        self.assertEqual(body.get("code"), "AUTH_DELEGATED_TO_KEYCLOAK")

    # 6. Con bandera activa y secretos externos configurados, auditor obtiene sesion temporal
    def test_06_legacy_audit_login_enabled_with_flag(self):
        server.ENABLE_LEGACY_AUTH = True
        server.LEGACY_HMAC_SECRET = TEST_TRANSITION_HMAC
        server.LEGACY_AUDITOR_HASH = TEST_AUDITOR_HASH

        status, body, headers = self.do_request(
            "POST",
            "/api/v1/auth/login",
            {"username": "auditor", "password": TEST_AUDITOR_PASS}
        )
        self.assertEqual(status, 200)
        self.assertEqual(body.get("status"), "LEGACY_SESSION_ACTIVE")
        self.assertEqual(body.get("scope"), "audit_only")
        self.assertIn("token", body)
        self.assertIn("Warning", headers)
        self.assertIn("Sunset", headers)
        self.assertIn("Deprecation", headers)

    # 7. Token legacy temporal de auditor permite consultar eventos de auditoria
    def test_07_legacy_audit_token_authorizes_audit_read(self):
        server.ENABLE_LEGACY_AUTH = True
        server.LEGACY_HMAC_SECRET = TEST_TRANSITION_HMAC
        server.LEGACY_AUDITOR_HASH = TEST_AUDITOR_HASH

        status, body, _ = self.do_request(
            "POST",
            "/api/v1/auth/login",
            {"username": "auditor", "password": TEST_AUDITOR_PASS}
        )
        legacy_token = body["token"]

        status, audit_body, _ = self.do_request(
            "GET",
            "/api/v1/audit/events",
            headers={"Authorization": f"Bearer {legacy_token}"}
        )
        self.assertEqual(status, 200)
        self.assertTrue(audit_body.get("audit_chain_valid"))
        self.assertGreaterEqual(audit_body.get("total_events", 0), 1)

    # 8. Regla de Oro Zero Trust: Medicos y recepcionistas son bloqueados (HTTP 403) incluso con bandera activa
    def test_08_legacy_clinical_login_prohibited_even_with_flag(self):
        server.ENABLE_LEGACY_AUTH = True
        server.LEGACY_HMAC_SECRET = TEST_TRANSITION_HMAC
        server.LEGACY_AUDITOR_HASH = TEST_AUDITOR_HASH

        for clinical_user in ("medico", "recepcionista", "admin"):
            status, body, _ = self.do_request(
                "POST",
                "/api/v1/auth/login",
                {"username": clinical_user, "password": "AnyPassword123!"}
            )
            self.assertEqual(status, 403, f"Usuario {clinical_user} debio ser bloqueado con 403 Forbidden")
            self.assertEqual(body.get("code"), "LEGACY_CLINICAL_LOGIN_PROHIBITED")

    # 9. Token legacy de auditor es rechazado en endpoints clinicos (/orders)
    def test_09_legacy_audit_token_rejected_on_orders(self):
        server.ENABLE_LEGACY_AUTH = True
        server.LEGACY_HMAC_SECRET = TEST_TRANSITION_HMAC
        server.LEGACY_AUDITOR_HASH = TEST_AUDITOR_HASH

        status, body, _ = self.do_request(
            "POST",
            "/api/v1/auth/login",
            {"username": "auditor", "password": TEST_AUDITOR_PASS}
        )
        legacy_token = body["token"]

        status, get_body, _ = self.do_request("GET", "/api/v1/orders", headers={"Authorization": f"Bearer {legacy_token}"})
        self.assertEqual(status, 401)
        self.assertEqual(get_body.get("code"), "INVALID_TOKEN_SIGNATURE")

        status, post_body, _ = self.do_request("POST", "/api/v1/orders", {"order_id": "ORD-TEST"}, {"Authorization": f"Bearer {legacy_token}"})
        self.assertEqual(status, 401)
        self.assertEqual(post_body.get("code"), "INVALID_TOKEN_SIGNATURE")

    # 10. Aislamiento del canal IoMT: Ingesta biomedica con HMAC de dispositivo independiente
    def test_10_iomt_hmac_channel_independent(self):
        device_id = "IOMT-ANALYZER-DEMO"
        device_key = b"audit-monitor-iomt-key-0001"
        server.IOMT_DEVICE_KEYS = {device_id: device_key}

        order_id = "ORD-IOMT-AUDIT-01"
        nonce_base = uuid.uuid4().hex
        server.db_manager.create_order({
            "order_id": order_id,
            "patient_dni": "DNI-5555",
            "test_type": "GLUCOSA",
            "status": "SAMPLE_COLLECTED",
            "created_by": "suite",
            "measurements": {},
            "version": 1,
        })

        def signed_headers(data, nonce, key=device_key, dev=device_id, ts=None):
            raw_body = json.dumps(data)
            stamp = ts if ts is not None else str(time.time())
            signing_input = f"{dev}\n{stamp}\n{nonce}\n{raw_body}"
            sig = hmac.new(key, signing_input.encode("utf-8"), hashlib.sha256).hexdigest()
            return {
                "X-Device-Id": dev,
                "X-Device-Signature": sig,
                "X-Device-Timestamp": stamp,
                "X-Device-Nonce": nonce,
            }

        data = {"order_id": order_id, "measurements": {"glucosa_mg_dl": 95.0}}
        status, body, _ = self.do_request(
            "POST", "/api/v1/iomt/results", data, signed_headers(data, nonce_base + "-01")
        )
        self.assertEqual(status, 200)
        self.assertEqual(body.get("status"), "ACCEPTED")
        self.assertEqual(server.ORDERS_DB[order_id]["status"], "ANALYZED")

        # Reenvio del mismo nonce: rechazo explicito (anti-replay).
        status, body, _ = self.do_request(
            "POST", "/api/v1/iomt/results", data, signed_headers(data, nonce_base + "-01")
        )
        self.assertEqual(status, 409)
        self.assertEqual(body.get("code"), "IOMT_REPLAY_DETECTED")

        # Firma con clave ajena: rechazo criptografico.
        status, body, _ = self.do_request(
            "POST",
            "/api/v1/iomt/results",
            data,
            signed_headers(data, nonce_base + "-02", key=b"wrong-audit-monitor-key-0001"),
        )
        self.assertEqual(status, 403)
        self.assertEqual(body.get("code"), "IOMT_INVALID_SIGNATURE")

        # Marca temporal fuera de ventana: rechazo.
        status, body, _ = self.do_request(
            "POST",
            "/api/v1/iomt/results",
            data,
            signed_headers(data, nonce_base + "-03", ts=str(time.time() - 3600)),
        )
        self.assertEqual(status, 401)
        self.assertEqual(body.get("code"), "IOMT_STALE_TIMESTAMP")

    # 11. Prohibicion estricta de fallback legacy cuando OAuth falla (Fail-Closed)
    def test_11_unauthorized_legacy_fallback_prohibited(self):
        monitor.USE_LEGACY_AUTH = False
        orig_secret = monitor.CLIENT_SECRET
        monitor.CLIENT_SECRET = "wrong-secret-causing-oauth-failure"
        monitor._CACHED_TOKEN = None

        monitor.AUDITOR_USER = "auditor"
        monitor.AUDITOR_PASS = TEST_AUDITOR_PASS

        token = monitor.get_auditor_token()
        self.assertIsNone(token, "monitor.get_auditor_token() no debe realizar fallback automatico a login legacy")
        monitor.CLIENT_SECRET = orig_secret

    # 12. Falla cerrada (503) cuando ENABLE_LEGACY_AUTH=1 pero faltan secretos externos obligatorios
    def test_12_missing_transition_secrets_denies_legacy_login(self):
        server.ENABLE_LEGACY_AUTH = True
        server.LEGACY_HMAC_SECRET = None  # Secreto ausente
        server.LEGACY_AUDITOR_HASH = ""

        status, body, _ = self.do_request(
            "POST",
            "/api/v1/auth/login",
            {"username": "auditor", "password": TEST_AUDITOR_PASS}
        )
        self.assertEqual(status, 503)
        self.assertEqual(body.get("code"), "LEGACY_TRANSITION_SECRETS_MISSING")

    # 13. Rechazo de credenciales legacy conocidas si los secretos no fueron configurados
    def test_13_known_default_credentials_rejected_without_external_config(self):
        server.ENABLE_LEGACY_AUTH = False
        status, body, _ = self.do_request(
            "POST",
            "/api/v1/auth/login",
            {"username": "auditor", "password": "AuditorCISO2026!"}
        )
        self.assertEqual(status, 410)
        self.assertEqual(body.get("code"), "AUTH_DELEGATED_TO_KEYCLOAK")

    # 14. Ejecucion del ciclo OAuth completo del monitor sin secretos hardcodeados
    def test_14_monitor_oauth_real_flow(self):
        self.assertEqual(monitor.AUDITOR_PASS, "")
        audit_url = f"{self.base_url}/api/v1/audit/events"
        res = monitor.run_audit_cycle(custom_audit_url=audit_url)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertTrue(res["chain_valid"])

    # 15. Service Account no puede realizar operaciones administrativas ni acceder a recursos ajenos
    def test_15_service_account_cannot_perform_admin_or_clinical_operations(self):
        token = self.get_service_token()
        status, _, _ = self.do_request("GET", "/admin", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(status, 404)

        status, body, _ = self.do_request("POST", "/api/v1/orders", {"order_id": "ORD-TEST"}, {"Authorization": f"Bearer {token}"})
        self.assertEqual(status, 403)


if __name__ == "__main__":
    unittest.main(verbosity=2)