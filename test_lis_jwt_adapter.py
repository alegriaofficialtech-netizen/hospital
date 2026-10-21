#!/usr/bin/env python3
"""
Pruebas de Integracion HTTP: Adaptador LIS Backend con Keycloak Zero Trust JWT
SGSI-ZTA Hospital Lab
ISO/IEC 27001:2022 & NIST SP 800-207

Verificacion exhaustiva de politicas ZTA, RBAC, autenticacion MFA,
aislamiento de canal IoMT y respuestas HTTP sanitizadas sobre HTTPServer real.
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

# Importar modulos del sandbox
SANDBOX_DIR = os.path.dirname(os.path.abspath(__file__))
if SANDBOX_DIR not in sys.path:
    sys.path.insert(0, SANDBOX_DIR)

import lis_server_adapter as lis_server
from jwt_validator import (
    JWKSCacheManager,
    ZeroTrustJWTValidator,
)

TEST_ISSUER = "https://127.0.0.1:8444/realms/hospital-lab-oidc-test"
TEST_AUDIENCE = "clinical-poc-api"
TEST_AZP = "clinical-poc-frontend-test"
TEST_KID = "test-rsa-key-stage3"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class MockJWKSCache(JWKSCacheManager):
    """Caché JWKS en memoria precargada con clave RSA de prueba para pruebas deterministas."""

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


class TestLISZeroTrustAdapter(unittest.TestCase):
    """Suite de pruebas funcionales HTTP sobre el adaptador LIS con ZeroTrustJWTValidator."""

    @classmethod
    def setUpClass(cls):
        # 1. Generar par de claves RSA (2048 bits) para la suite de pruebas
        cls.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        cls.public_key = cls.private_key.public_key()

        # 2. Configurar cache JWKS mock y validador
        cls.cache = MockJWKSCache(cls.public_key, TEST_KID, TEST_ISSUER)
        cls.validator = ZeroTrustJWTValidator(
            discovery_url=f"{TEST_ISSUER}/.well-known/openid-configuration",
            expected_audience=TEST_AUDIENCE,
            cache_manager=cls.cache,
            expected_authorized_party=TEST_AZP,
            require_bearer_type=False,
        )

        # 3. Limpiar estado en memoria e iniciar servidor HTTP en puerto efímero
        lis_server.ORDERS_DB.clear()
        lis_server.AUDIT_LOGS.clear()
        lis_server.LAST_AUDIT_HASH = "0" * 64

        cls.httpd = lis_server.create_lis_server("127.0.0.1", 0, validator=cls.validator)
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
        acr: Optional[str] = None,
        aud: Optional[List[str]] = None,
        azp: Optional[str] = TEST_AZP,
        iss: Optional[str] = TEST_ISSUER,
        typ: str = "Bearer",
        token_use: Optional[str] = None,
        exp_delta: int = 3600,
        corrupt_sig: bool = False,
    ) -> str:
        """Helper para generar tokens RS256 con claims estructurados idénticos a Keycloak."""
        now = int(time.time())
        header = {
            "alg": "RS256",
            "typ": "JWT",
            "kid": TEST_KID,
        }
        payload = {
            "sub": f"uuid-{username}-synthetic",
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
        if acr is not None:
            payload["acr"] = acr
        if token_use is not None:
            payload["token_use"] = token_use

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
        """Realiza peticion HTTP al servidor de prueba y deserializa respuesta JSON."""
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

    # =========================================================================
    # CASO 1: Admisión con token válido puede crear una orden
    # =========================================================================
    def test_01_admission_creates_order_success(self):
        """1. Personal de admision con rol ROLE_RECEPTION crea orden exitosamente (HTTP 201)."""
        token = self.create_signed_token("admision.test", roles=["admision"], amr=["pwd"])
        headers = {"Authorization": f"Bearer {token}"}
        order_payload = {
            "order_id": "ORD-ZTA-001",
            "patient_dni": "PAC-12345678",
            "test_type": "PERFIL BIOQUIMICO COMPLETO",
        }
        status, body = self.do_request("POST", "/api/v1/orders", order_payload, headers)
        self.assertEqual(status, 201)
        self.assertEqual(body.get("status"), "CREATED")
        self.assertIn("order", body)
        self.assertEqual(body["order"]["order_id"], "ORD-ZTA-001")
        self.assertEqual(body["order"]["created_by"], "admision.test")
        self.assertEqual(body["order"]["status"], "SAMPLE_COLLECTED")

    # =========================================================================
    # CASO 2: Personal sin permisos no puede crear órdenes
    # =========================================================================
    def test_02_unauthorized_staff_cannot_create_order(self):
        """2. Personal sin rol de admision (tecnologo, medico, anonimo) es bloqueado al crear orden (HTTP 403/401)."""
        # A) Tecnologo de laboratorio (ROLE_LAB_TECH) intenta crear orden
        tech_token = self.create_signed_token("tecnico.test", roles=["laboratorio"], amr=["pwd"])
        headers = {"Authorization": f"Bearer {tech_token}"}
        order_payload = {"order_id": "ORD-ZTA-ILLEGAL", "patient_dni": "PAC-9999"}
        status, body = self.do_request("POST", "/api/v1/orders", order_payload, headers)
        self.assertEqual(status, 403)
        self.assertEqual(body.get("code"), "RECEPTION_ROLE_REQUIRED")

        # B) Solicitud anonima (sin cabecera Authorization)
        status_anon, body_anon = self.do_request("POST", "/api/v1/orders", order_payload, {})
        self.assertEqual(status_anon, 401)
        self.assertEqual(body_anon.get("code"), "MISSING_AUTHORIZATION_HEADER")

    # =========================================================================
    # CASO 3: Médico con token real y MFA acreditado puede validar una orden
    # =========================================================================
    def test_03_physician_with_mfa_validates_order_success(self):
        """3. Medico patologo con MFA activo (amr: ['pwd', 'otp']) valida y firma orden (HTTP 200)."""
        # Asegurar orden existente
        token_adm = self.create_signed_token("admision.test", roles=["admision"])
        self.do_request("POST", "/api/v1/orders", {"order_id": "ORD-ZTA-002", "patient_dni": "PAC-87654321"}, {"Authorization": f"Bearer {token_adm}"})

        # Medico con evidencia MFA completa
        doc_token = self.create_signed_token("medico.test", roles=["medico"], amr=["pwd", "otp"])
        headers = {"Authorization": f"Bearer {doc_token}"}
        val_payload = {
            "order_id": "ORD-ZTA-002",
            "observations": "Parametros celulares dentro de rangos normales.",
        }
        status, body = self.do_request("POST", "/api/v1/orders/validate", val_payload, headers)
        self.assertEqual(status, 200)
        self.assertEqual(body.get("status"), "SUCCESS")
        self.assertEqual(body["order"]["status"], "VALIDATED_AND_RELEASED")
        self.assertEqual(body["order"]["validated_by"], "medico.test")
        self.assertIsNotNone(body["order"].get("digital_signature"))

    # =========================================================================
    # CASO 4: Médico sin evidencia MFA no puede validar una orden
    # =========================================================================
    def test_04_physician_without_mfa_cannot_validate_order(self):
        """4. Medico patologo autenticado solo con password (sin OTP) es denegado por politica Zero Trust (HTTP 403)."""
        token_adm = self.create_signed_token("admision.test", roles=["admision"])
        self.do_request("POST", "/api/v1/orders", {"order_id": "ORD-ZTA-003", "patient_dni": "PAC-11223344"}, {"Authorization": f"Bearer {token_adm}"})

        # Medico sin segundo factor (amr solo pwd)
        doc_no_mfa = self.create_signed_token("medico.test", roles=["medico"], amr=["pwd"])
        headers = {"Authorization": f"Bearer {doc_no_mfa}"}
        status, body = self.do_request("POST", "/api/v1/orders/validate", {"order_id": "ORD-ZTA-003"}, headers)
        self.assertEqual(status, 403)
        self.assertEqual(body.get("code"), "MFA_AUTHENTICATION_REQUIRED")
        self.assertIn("requiere autenticacion multifactor", body.get("message", ""))

    # =========================================================================
    # CASO 5: Token con audiencia incorrecta es rechazado
    # =========================================================================
    def test_05_invalid_audience_rejected(self):
        """5. Access Token con claim 'aud' no autorizado es rechazado de inmediato (HTTP 401)."""
        wrong_aud_token = self.create_signed_token("admision.test", roles=["admision"], aud=["rogue-client-api"])
        headers = {"Authorization": f"Bearer {wrong_aud_token}"}
        status, body = self.do_request("GET", "/api/v1/orders", headers=headers)
        self.assertEqual(status, 401)
        self.assertEqual(body.get("code"), "INVALID_AUDIENCE")

    # =========================================================================
    # CASO 6: ID Token no puede sustituir al Access Token
    # =========================================================================
    def test_06_id_token_rejected_as_access_token(self):
        """6. Presentacion de ID Token (typ='ID' o token_use='id') en endpoint API es bloqueada (HTTP 401)."""
        # A) Token con typ="ID"
        id_token = self.create_signed_token("admision.test", roles=["admision"], typ="ID")
        headers = {"Authorization": f"Bearer {id_token}"}
        status, body = self.do_request("GET", "/api/v1/orders", headers=headers)
        self.assertEqual(status, 401)
        self.assertEqual(body.get("code"), "INVALID_TOKEN_TYPE")

        # B) Token con token_use="id"
        id_token_use = self.create_signed_token("admision.test", roles=["admision"], token_use="id")
        status_b, body_b = self.do_request("GET", "/api/v1/orders", headers={"Authorization": f"Bearer {id_token_use}"})
        self.assertEqual(status_b, 401)
        self.assertEqual(body_b.get("code"), "INVALID_TOKEN_TYPE")

    # =========================================================================
    # CASO 7: Token expirado o firma manipulada es rechazado
    # =========================================================================
    def test_07_expired_token_and_corrupt_signature_rejected(self):
        """7. Tokens expirados, con firma criptografica RS256 corrupta o formato legacy HMAC son rechazados (HTTP 401)."""
        # A) Token expirado hace 5 minutos
        expired_token = self.create_signed_token("admision.test", roles=["admision"], exp_delta=-300)
        status_exp, body_exp = self.do_request("GET", "/api/v1/orders", headers={"Authorization": f"Bearer {expired_token}"})
        self.assertEqual(status_exp, 401)
        self.assertEqual(body_exp.get("code"), "TOKEN_EXPIRED")

        # B) Token con firma RS256 alterada/corrupta
        tampered_token = self.create_signed_token("admision.test", roles=["admision"], corrupt_sig=True)
        status_tamp, body_tamp = self.do_request("GET", "/api/v1/orders", headers={"Authorization": f"Bearer {tampered_token}"})
        self.assertEqual(status_tamp, 401)
        self.assertEqual(body_tamp.get("code"), "INVALID_TOKEN_SIGNATURE")

        # C) Token HMAC heredado (formato payload::sig) intentando eludir JWT
        legacy_hmac_token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJyZWNlcGNpb24ifQ::fake_hmac_signature"
        status_leg, body_leg = self.do_request("GET", "/api/v1/orders", headers={"Authorization": f"Bearer {legacy_hmac_token}"})
        self.assertEqual(status_leg, 401)
        self.assertEqual(body_leg.get("code"), "INVALID_TOKEN_SIGNATURE")

    # =========================================================================
    # CASO 8: Auditor solo accede a funciones autorizadas
    # =========================================================================
    def test_08_auditor_access_and_least_privilege(self):
        """8. Auditor CISO consulta registros y cadena de auditoria (HTTP 200), pero no puede crear/validar ordenes (HTTP 403)."""
        auditor_token = self.create_signed_token("auditor.test", roles=["auditor"], amr=["pwd"])
        headers = {"Authorization": f"Bearer {auditor_token}"}

        # A) Acceso autorizado a /api/v1/audit/events
        status_audit, body_audit = self.do_request("GET", "/api/v1/audit/events", headers=headers)
        self.assertEqual(status_audit, 200)
        self.assertTrue(body_audit.get("audit_chain_valid"))
        self.assertGreaterEqual(body_audit.get("total_events", 0), 1)

        # B) Menor Privilegio: Auditor no puede crear ordenes
        status_create, body_create = self.do_request("POST", "/api/v1/orders", {"order_id": "ORD-AUDITOR-FAIL", "patient_dni": "PAC-X"}, headers)
        self.assertEqual(status_create, 403)
        self.assertEqual(body_create.get("code"), "RECEPTION_ROLE_REQUIRED")

        # C) Menor Privilegio: Auditor no puede validar ordenes
        status_val, body_val = self.do_request("POST", "/api/v1/orders/validate", {"order_id": "ORD-ZTA-001"}, headers)
        self.assertEqual(status_val, 403)
        self.assertEqual(body_val.get("code"), "PATHOLOGIST_ROLE_REQUIRED")

    # =========================================================================
    # CASO 9: Canal IoMT mantiene su autenticación independiente
    # =========================================================================
    def test_09_iomt_biomedical_isolation_and_hmac(self):
        """9. Ingesta biomedica IoMT autentica via HMAC aislado y no interfiere ni permite eludir rutas humanas."""
        iomt_payload = {
            "order_id": "ORD-ZTA-001",
            "patient_dni": "PAC-12345678",
            "measurements": {
                "hemoglobina_g_dl": 14.2,
                "plaquetas_mm3": 240000,
            },
        }
        raw_body = json.dumps(iomt_payload)
        valid_sig = hmac.new(lis_server.IOMT_DEVICE_KEY, raw_body.encode("utf-8"), hashlib.sha256).hexdigest()

        # A) Ingesta correcta con cabeceras de firma
        iomt_headers = {
            "X-Device-Id": "IOMT-ANALYZER-HEM-01",
            "X-Device-Signature": valid_sig,
        }
        status_iomt, body_iomt = self.do_request("POST", "/api/v1/iomt/results", iomt_payload, iomt_headers)
        self.assertEqual(status_iomt, 200)
        self.assertEqual(body_iomt.get("status"), "ACCEPTED")

        # B) Firma de dispositivo corrupta o adulterada
        bad_sig_headers = {
            "X-Device-Id": "IOMT-ANALYZER-HEM-01",
            "X-Device-Signature": "firma_adulterada_man_in_the_middle",
        }
        status_bad, body_bad = self.do_request("POST", "/api/v1/iomt/results", iomt_payload, bad_sig_headers)
        self.assertEqual(status_bad, 403)
        self.assertEqual(body_bad.get("code"), "IOMT_INVALID_SIGNATURE")

        # C) Dispositivo sin cabeceras de firma
        status_nosig, body_nosig = self.do_request("POST", "/api/v1/iomt/results", iomt_payload, {})
        self.assertEqual(status_nosig, 401)
        self.assertEqual(body_nosig.get("code"), "IOMT_MISSING_CREDENTIALS")

        # D) Cabeceras de dispositivo intentando acceder a ruta humana sin Bearer token
        status_bypass, body_bypass = self.do_request("GET", "/api/v1/orders", headers=iomt_headers)
        self.assertEqual(status_bypass, 401)
        self.assertEqual(body_bypass.get("code"), "MISSING_AUTHORIZATION_HEADER")

    # =========================================================================
    # CASO 10: Errores devuelven respuestas coherentes sin filtrar información sensible
    # =========================================================================
    def test_10_sanitized_error_responses_no_leaks(self):
        """10. Errores de autenticacion devuelven JSON estructurado sin revelar stack traces, claves ni secretos."""
        test_probes = [
            ("Bearer invalid.notenoughparts", 401),
            ("Bearer " + "A" * 8000, 401),  # Oversized
            ("Bearer eyJhbGciOiJSUzI1NiJ9.corruptjson.sig", 401),
            ("Bearer not_a_jwt_at_all", 401),
            ("Basic dXNlcjpwYXNz", 401),
        ]
        sensitive_patterns = ["Traceback", "Exception", "private_key", "secret", "password", "File \""]

        for auth_val, expected_code in test_probes:
            status, body = self.do_request("GET", "/api/v1/orders", headers={"Authorization": auth_val})
            self.assertEqual(status, expected_code)
            self.assertIn("error", body)
            self.assertIn("code", body)
            body_text = json.dumps(body)
            for pat in sensitive_patterns:
                self.assertNotIn(pat, body_text)

    # =========================================================================
    # CASO 11: Normalización de roles RBAC (ROLE_RECEPTION vs ROLE_RECEPTIONIST)
    # =========================================================================
    def test_11_role_receptionist_normalization(self):
        """11. Token con claim de rol 'ROLE_RECEPTIONIST' se normaliza limpiamente a ROLE_RECEPTION."""
        rec_token = self.create_signed_token("receptionist.user", roles=["ROLE_RECEPTIONIST"], amr=["pwd"])
        headers = {"Authorization": f"Bearer {rec_token}"}
        status, body = self.do_request("POST", "/api/v1/orders", {"order_id": "ORD-ZTA-011", "patient_dni": "PAC-NORM"}, headers)
        self.assertEqual(status, 201)
        self.assertEqual(body.get("status"), "CREATED")

    # =========================================================================
    # CASO 12: Deprecación formal de endpoint local de login
    # =========================================================================
    def test_12_legacy_login_route_deprecated(self):
        """12. Ruta /api/v1/auth/login responde HTTP 410 Gone indicando delegacion formal a Keycloak OIDC."""
        status, body = self.do_request("POST", "/api/v1/auth/login", {"username": "patologo", "password": "any"})
        self.assertEqual(status, 410)
        self.assertEqual(body.get("code"), "AUTH_DELEGATED_TO_KEYCLOAK")


if __name__ == "__main__":
    unittest.main(verbosity=2)
