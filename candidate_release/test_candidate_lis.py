#!/usr/bin/env python3
"""
Pruebas de Compatibilidad y Regresion: Version Candidata LIS con Keycloak JWT
SGSI-ZTA Hospital Lab
ISO/IEC 27001:2022 & NIST SP 800-207

Valida que candidate_release/server.py satisface 100% de las politicas Zero Trust,
mantiene la compatibilidad con el LIS original y asegura la integridad de la cadena de auditoria.
"""

import base64
import copy
import hashlib
import hmac
import json
import os
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

import server
from jwt_validator import JWKSCacheManager, ZeroTrustJWTValidator

TEST_ISSUER = "http://127.0.0.1:8085/realms/hospital-lab"
TEST_AUDIENCE = "clinical-poc-api"
TEST_AZP = "clinical-poc"
TEST_KID = "candidate-rsa-key-01"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class CandidateMockJWKSCache(JWKSCacheManager):
    """Cache en memoria precargada con clave publica RSA para pruebas deterministas del release candidato."""

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


class TestCandidateLISRelease(unittest.TestCase):
    """Suite de validacion para la version candidata de produccion del LIS."""

    @classmethod
    def setUpClass(cls):
        # 1. Par de claves RSA para pruebas sinteticas
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public_key = cls.private_key.public_key()

        # 2. Configurar cache y validador
        cls.cache = CandidateMockJWKSCache(cls.public_key, TEST_KID, TEST_ISSUER)
        cls.validator = ZeroTrustJWTValidator(
            discovery_url=f"{TEST_ISSUER}/.well-known/openid-configuration",
            expected_audience=TEST_AUDIENCE,
            cache_manager=cls.cache,
            expected_authorized_party=TEST_AZP,
            require_bearer_type=False,
        )

        # 3. Limpiar estado e iniciar HTTPServer
        server.ORDERS_DB.clear()
        server.AUDIT_LOGS.clear()
        server.LAST_AUDIT_HASH = "0" * 64

        server_address = ("127.0.0.1", 0)
        cls.httpd = server.HTTPServer(server_address, server.ZeroTrustRequestHandler)
        cls.httpd.validator = cls.validator
        cls.server_port = cls.httpd.server_address[1]
        cls.base_url = f"http://127.0.0.1:{cls.server_port}"

        cls.server_thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def create_signed_token(
        self,
        username: str,
        roles: List[str],
        amr: Optional[List[str]] = None,
        aud: Optional[List[str]] = None,
        azp: Optional[str] = TEST_AZP,
        iss: Optional[str] = TEST_ISSUER,
        typ: str = "Bearer",
        exp_delta: int = 3600,
        corrupt_sig: bool = False,
    ) -> str:
        now = int(time.time())
        header = {"alg": "RS256", "typ": "JWT", "kid": TEST_KID}
        payload = {
            "sub": f"uuid-{username}-candidate",
            "preferred_username": username,
            "iss": iss,
            "aud": aud if aud is not None else [TEST_AUDIENCE],
            "azp": azp,
            "typ": typ,
            "exp": now + exp_delta,
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
        if corrupt_sig:
            sig = sig[:-2] + b"\x00\xFF"
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
        payload = json.dumps(data).encode("utf-8") if data is not None else None
        req = urllib.request.Request(url, data=payload, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as res:
                return res.status, json.loads(res.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8")
            try:
                parsed = json.loads(body)
            except Exception:
                parsed = {"raw": body}
            return e.code, parsed

    # 1. Salud del servicio
    def test_01_health_endpoint(self):
        status, body = self.do_request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(body.get("status"), "HEALTHY")
        self.assertIn("timestamp", body)

    # 2. Control de admision preanalitica
    def test_02_create_order_reception_authorized(self):
        token = self.create_signed_token("admision.cand", roles=["admision"])
        status, body = self.do_request(
            "POST",
            "/api/v1/orders",
            {"order_id": "ORD-CAND-001", "patient_dni": "DNI-1001", "test_type": "HEMOGRAMA COMPLETO"},
            {"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(status, 201)
        self.assertEqual(body.get("status"), "CREATED")
        self.assertEqual(body["order"]["order_id"], "ORD-CAND-001")
        self.assertEqual(body["order"]["status"], "SAMPLE_COLLECTED")

    # 3. Denegacion por menor privilegio en creacion
    def test_03_create_order_unauthorized_role(self):
        token = self.create_signed_token("tecnico.cand", roles=["laboratorio"])
        status, body = self.do_request(
            "POST",
            "/api/v1/orders",
            {"order_id": "ORD-CAND-FAIL", "patient_dni": "DNI-1002"},
            {"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(body.get("code"), "RECEPTION_ROLE_REQUIRED")

    # 4. Ingesta biomédica IoMT independiente
    def test_04_iomt_biomedical_results_ingestion(self):
        data = {
            "order_id": "ORD-CAND-001",
            "patient_dni": "DNI-1001",
            "measurements": {"hemoglobina_g_dl": 14.5, "leucocitos_mm3": 6500},
        }
        raw_body = json.dumps(data)
        sig = hmac.new(server.DEVICE_KEY, raw_body.encode("utf-8"), hashlib.sha256).hexdigest()
        headers = {
            "X-Device-Id": "IOMT-ANALYZER-01",
            "X-Device-Signature": sig,
        }
        status, body = self.do_request("POST", "/api/v1/iomt/results", data, headers)
        self.assertEqual(status, 200)
        self.assertEqual(body.get("status"), "ACCEPTED")
        # Verificar estado actualizado en memoria
        self.assertEqual(server.ORDERS_DB["ORD-CAND-001"]["status"], "ANALYZED")
        self.assertEqual(server.ORDERS_DB["ORD-CAND-001"]["measurements"]["hemoglobina_g_dl"], 14.5)

    # 5. Firma y validacion medica facultativa con MFA
    def test_05_validate_order_physician_with_mfa(self):
        token = self.create_signed_token("medico.cand", roles=["medico"], amr=["pwd", "otp"])
        status, body = self.do_request(
            "POST",
            "/api/v1/orders/validate",
            {"order_id": "ORD-CAND-001", "observations": "Fórmula roja conforme."},
            {"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(body.get("status"), "SUCCESS")
        self.assertEqual(body["order"]["status"], "VALIDATED_AND_RELEASED")
        self.assertEqual(body["order"]["validated_by"], "medico.cand")
        self.assertIsNotNone(body["order"].get("digital_signature"))

    # 6. Rechazo de validacion facultativa sin MFA
    def test_06_validate_order_physician_without_mfa_denied(self):
        # Crear segunda orden
        token_adm = self.create_signed_token("admision.cand", roles=["admision"])
        self.do_request("POST", "/api/v1/orders", {"order_id": "ORD-CAND-002", "patient_dni": "DNI-1002"}, {"Authorization": f"Bearer {token_adm}"})

        # Medico sin segundo factor (amr pwd)
        token_no_mfa = self.create_signed_token("medico.cand", roles=["medico"], amr=["pwd"])
        status, body = self.do_request(
            "POST",
            "/api/v1/orders/validate",
            {"order_id": "ORD-CAND-002"},
            {"Authorization": f"Bearer {token_no_mfa}"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(body.get("code"), "MFA_AUTHENTICATION_REQUIRED")

    # 7. Consulta de auditoria y verificacion de cadena inmutable
    def test_07_audit_events_and_hash_chain_integrity(self):
        token = self.create_signed_token("auditor.cand", roles=["auditor"])
        status, body = self.do_request("GET", "/api/v1/audit/events", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(status, 200)
        self.assertTrue(body.get("audit_chain_valid"))
        self.assertGreaterEqual(body.get("total_events", 0), 5)
        # Verificar verificador local de cadena
        self.assertTrue(server.verify_audit_chain(body["events"]))

    # 8. Intento de adulteracion de auditoria detectado
    def test_08_audit_tamper_detection(self):
        token = self.create_signed_token("auditor.cand", roles=["auditor"])
        status, body = self.do_request("GET", "/api/v1/audit/events", headers={"Authorization": f"Bearer {token}"})
        events = copy.deepcopy(body["events"])
        events[0]["details"] = "DETALLE_ADULTERADO"
        self.assertFalse(server.verify_audit_chain(events))

    # 9. Rechazo de tokens HMAC legacy en rutas humanas
    def test_09_legacy_hmac_token_rejected_on_api(self):
        legacy_token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pc2lvbiJ9::fake_hmac_sig"
        status, body = self.do_request("GET", "/api/v1/orders", headers={"Authorization": f"Bearer {legacy_token}"})
        self.assertEqual(status, 401)
        self.assertEqual(body.get("code"), "INVALID_TOKEN_SIGNATURE")

    # 10. Deprecacion formal del login local
    def test_10_local_login_deprecated_410(self):
        status, body = self.do_request("POST", "/api/v1/auth/login", {"username": "medico", "password": "any"})
        self.assertEqual(status, 410)
        self.assertEqual(body.get("code"), "AUTH_DELEGATED_TO_KEYCLOAK")


if __name__ == "__main__":
    unittest.main(verbosity=2)
