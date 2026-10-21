import base64
import dataclasses
import hashlib
import hmac
import http.cookiejar
import json
import os
import re
import secrets
import ssl
import struct
import sys
import time
import unittest
import urllib.parse
import urllib.request

sys.path.insert(0, "/home/elcra/sandbox-jwt-validator")

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from stage2_credentials import get_user_password
from jwt_validator import (
    ClinicalAuthContext,
    InsufficientPermissionsError,
    InvalidAudienceError,
    InvalidSignatureError,
    InvalidTokenTypeError,
    JWKSCacheManager,
    JWKSFetchError,
    MFARequiredError,
    TokenExpiredError,
    ZeroTrustJWTValidator,
    enforce_clinical_action,
)

REALM_NAME = "hospital-lab-oidc-test"
DEFAULT_BASE_URL = f"http://127.0.0.1:8085/realms/{REALM_NAME}"
BASE_URL = os.environ.get("KEYCLOAK_BASE_URL", DEFAULT_BASE_URL)
DISCOVERY_URL = f"{BASE_URL}/.well-known/openid-configuration"
CLIENT_ID = "clinical-poc-frontend-test"
REDIRECT_URI = "http://127.0.0.1:8080/callback"
AUDIENCE = "clinical-poc-api"

TLS_ENABLED = BASE_URL.startswith("https://")
CA_CERT_PATH = os.environ.get("SSL_CERT_FILE", "/home/elcra/sandbox-jwt-validator/tls/ca.crt")
MEDICO_SEED_FILE = "/home/elcra/sandbox-jwt-validator/.env.medico_totp_seed"

# Configurar SSL_CERT_FILE para validacion estricta contra la CA local
if TLS_ENABLED and os.path.exists(CA_CERT_PATH):
    os.environ["SSL_CERT_FILE"] = CA_CERT_PATH


def is_keycloak_reachable() -> bool:
    """Verifica si el servicio Keycloak esta disponible localmente."""
    try:
        ctx = ssl.create_default_context(cafile=CA_CERT_PATH) if TLS_ENABLED else None
        req = urllib.request.Request(DISCOVERY_URL)
        with urllib.request.urlopen(req, context=ctx, timeout=1):
            return True
    except Exception:
        return False


KEYCLOAK_REACHABLE = is_keycloak_reachable()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def generate_totp(secret_base32: str) -> str:
    """Implementacion estricta RFC 6238 de TOTP basada en hashlib/hmac."""
    secret = secret_base32.strip().replace(" ", "").upper()
    padding_len = (8 - len(secret) % 8) % 8
    key = base64.b32decode(secret + ("=" * padding_len), casefold=True)
    counter = int(time.time()) // 30
    counter_bytes = struct.pack(">Q", counter)
    h = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    binary = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
    code = binary % 1000000
    return f"{code:06d}"


def get_or_create_medico_totp_seed() -> str:
    """Obtiene la semilla TOTP del almacenamiento restringido (0600) si existe."""
    if os.path.exists(MEDICO_SEED_FILE):
        with open(MEDICO_SEED_FILE, "r") as f:
            seed = f.read().strip()
            if seed:
                return seed
    return ""


def save_medico_totp_seed(seed: str) -> None:
    """Almacena la semilla TOTP con permisos exclusivos de lectura/escritura (0600)."""
    with open(MEDICO_SEED_FILE, "w") as f:
        f.write(seed.strip().replace(" ", "").upper())
    os.chmod(MEDICO_SEED_FILE, 0o600)


class MockJWKSCacheForStage2(JWKSCacheManager):
    """Gestor de claves en memoria que simula el JWKS del realm para pruebas PEP sinteticas."""

    def __init__(self, key_pair: rsa.RSAPrivateKey, kid: str, issuer: str):
        self._key = key_pair.public_key()
        self._kid = kid
        self._issuer = issuer
        self._keys_by_kid = {kid: self._key}
        self._last_fetch_timestamp = time.time()
        self.cache_ttl_seconds = 3600
        self.min_refresh_interval_seconds = 60

    @property
    def expected_issuer(self) -> str:
        return self._issuer

    def _fetch_jwks(self) -> None:
        pass


class PKCEAuthClient:
    """Cliente estricto para Authorization Code Flow con PKCE S256 y soporte MFA TOTP."""

    def __init__(self):
        self.cj = http.cookiejar.CookieJar()

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        handlers_normal = [urllib.request.HTTPCookieProcessor(self.cj)]
        handlers_post = [urllib.request.HTTPCookieProcessor(self.cj), NoRedirect()]

        if TLS_ENABLED and os.path.exists(CA_CERT_PATH):
            ssl_ctx = ssl.create_default_context(cafile=CA_CERT_PATH)
            ssl_ctx.check_hostname = True
            ssl_ctx.verify_mode = ssl.CERT_REQUIRED
            handlers_normal.append(urllib.request.HTTPSHandler(context=ssl_ctx))
            handlers_post.append(urllib.request.HTTPSHandler(context=ssl_ctx))

        self.normal_opener = urllib.request.build_opener(*handlers_normal)
        self.post_opener = urllib.request.build_opener(*handlers_post)

    def generate_pkce(self):
        verifier = secrets.token_urlsafe(64)[:64]
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        return verifier, challenge

    def execute_login(self, username, password, totp_seed: str = None):
        """Ejecuta el flujo OIDC PKCE. Si se proporciona totp_seed, completa el segundo factor."""
        verifier, challenge = self.generate_pkce()
        state = secrets.token_hex(16)

        auth_params = urllib.parse.urlencode({
            "client_id": CLIENT_ID,
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
            "scope": "openid roles",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
        })
        auth_url = f"{BASE_URL}/protocol/openid-connect/auth?{auth_params}"

        resp = self.normal_opener.open(urllib.request.Request(auth_url))
        html = resp.read().decode("utf-8")
        m_action = re.search(r'<form[^>]+action="([^"]+)"[^>]*>', html)
        if not m_action:
            raise RuntimeError("Formulario de login no encontrado en Keycloak.")
        action = m_action.group(1).replace("&amp;", "&")

        login_data = urllib.parse.urlencode({
            "username": username,
            "password": password,
            "credentialId": "",
        }).encode("utf-8")

        req_login = urllib.request.Request(action, data=login_data, method="POST")
        req_login.add_header("Content-Type", "application/x-www-form-urlencoded")

        try:
            resp_login = self.post_opener.open(req_login)
            loc = resp_login.headers.get("Location")
            body = resp_login.read().decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as e:
            loc = e.headers.get("Location")
            body = e.read().decode("utf-8", errors="ignore")
            if e.code == 400 and ("cookie not found" in body.lower() or "restart login" in body.lower()):
                return {
                    "status": "COOKIE_REJECTED_BY_TRANSPORT",
                    "detail": "Keycloak rechazo la sesion porque las cookies Secure no fueron transmitidas sobre TLS.",
                }

        # Deteccion de desafio MFA (enrolamiento CONFIGURE_TOTP o formulario OTP)
        is_mfa_challenge = (
            (loc and ("CONFIGURE_TOTP" in loc or "totp" in loc.lower()))
            or (body and "otp" in body.lower())
        )

        if is_mfa_challenge:
            # Si NO se proporciona semilla TOTP, reportar el desafio sin resolverlo
            if not totp_seed:
                return {
                    "status": "MFA_CHALLENGE_TRIGGERED",
                    "location": loc,
                    "has_access_token": False,
                    "verifier": verifier,
                }

            # Si SE proporciona semilla TOTP, resolver interactivamente el desafio
            # Caso A: Pantalla de enrolamiento CONFIGURE_TOTP
            if loc and "CONFIGURE_TOTP" in loc:
                resp_totp_page = self.normal_opener.open(urllib.request.Request(loc))
                totp_html = resp_totp_page.read().decode("utf-8")

                m_manual = re.search(r'<a[^>]+href="([^"]+)"[^>]+id="mode-manual"', totp_html)
                if not m_manual:
                    m_manual = re.search(r'<a[^>]+id="mode-manual"[^>]+href="([^"]+)"', totp_html)

                manual_url = m_manual.group(1).replace("&amp;", "&")
                resp_man = self.normal_opener.open(urllib.request.Request(manual_url))
                man_html = resp_man.read().decode("utf-8")

                m_key = re.search(r'id="kc-totp-secret-key">([^<]+)<', man_html)
                if m_key:
                    seed_from_keycloak = m_key.group(1).replace(" ", "").strip().upper()
                    save_medico_totp_seed(seed_from_keycloak)
                    totp_seed = seed_from_keycloak

                m_form_act = re.search(r'<form[^>]+action="([^"]+)"[^>]*>', man_html)
                totp_action = m_form_act.group(1).replace("&amp;", "&")

                m_hidden = re.search(r'<input[^>]+name="totpSecret"[^>]+value="([^"]+)"', man_html)
                hidden_secret = m_hidden.group(1) if m_hidden else ""

                otp_code = generate_totp(totp_seed)
                post_fields = {
                    "totp": otp_code,
                    "totpSecret": hidden_secret,
                    "userLabel": "Medico TOTP Authenticator",
                }
                data_post = urllib.parse.urlencode(post_fields).encode("utf-8")
                req_totp = urllib.request.Request(totp_action, data=data_post, method="POST")
                req_totp.add_header("Content-Type", "application/x-www-form-urlencoded")

                try:
                    resp_post_totp = self.post_opener.open(req_totp)
                    loc = resp_post_totp.headers.get("Location")
                except urllib.error.HTTPError as e:
                    loc = e.headers.get("Location")

            # Caso B: Formulario directo de autenticacion OTP (auth-otp-form)
            elif body and "otp" in body.lower():
                m_otp_act = re.search(r'<form[^>]+action="([^"]+)"[^>]*>', body)
                otp_action = m_otp_act.group(1).replace("&amp;", "&")
                otp_code = generate_totp(totp_seed)
                otp_data = urllib.parse.urlencode({"otp": otp_code, "login": "Sign In"}).encode("utf-8")
                req_otp = urllib.request.Request(otp_action, data=otp_data, method="POST")
                req_otp.add_header("Content-Type", "application/x-www-form-urlencoded")
                try:
                    resp_otp = self.post_opener.open(req_otp)
                    loc = resp_otp.headers.get("Location")
                except urllib.error.HTTPError as e:
                    loc = e.headers.get("Location")

        if not loc or "code=" not in loc:
            raise RuntimeError(f"Login no devolvio redirect con code. Status/Loc: {loc}")

        parsed = urllib.parse.urlparse(loc)
        qs = urllib.parse.parse_qs(parsed.query)

        # Validacion estricta contra CSRF mediante state
        returned_state = qs.get("state", [None])[0]
        if returned_state != state:
            raise PermissionError("Validacion CSRF fallida: el parametro state recibido no coincide con el enviado.")

        code = qs["code"][0]

        token_data = urllib.parse.urlencode({
            "client_id": CLIENT_ID,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        }).encode("utf-8")

        req_token = urllib.request.Request(
            f"{BASE_URL}/protocol/openid-connect/token", data=token_data, method="POST"
        )
        req_token.add_header("Content-Type", "application/x-www-form-urlencoded")

        with self.normal_opener.open(req_token) as resp_tok:
            tokens = json.loads(resp_tok.read().decode("utf-8"))

        return {
            "status": "SUCCESS",
            "access_token": tokens["access_token"],
            "has_access_token": bool(tokens.get("access_token")),
            "has_id_token": bool(tokens.get("id_token")),
            "token_type": tokens.get("token_type"),
            "expires_in": tokens.get("expires_in"),
            "verifier": verifier,
        }


class TestStage2RealKeycloakIntegration(unittest.TestCase):
    """
    Suite de 16 pruebas de integracion adaptadas a la arquitectura Zero Trust y Keycloak 26.8.
    Verifica criptografia, flujos PKCE interactivos, segundo factor TOTP y enforcement PEP.
    """

    @classmethod
    def setUpClass(cls):
        cls.signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.kid = "test-stage2-key-01"
        cls.mock_cache = MockJWKSCacheForStage2(cls.signing_key, cls.kid, BASE_URL)

        cls.validator = ZeroTrustJWTValidator(
            discovery_url=DISCOVERY_URL,
            expected_audience=AUDIENCE,
            clock_skew_seconds=10,
            cache_manager=cls.mock_cache,
            expected_authorized_party=CLIENT_ID,
            require_bearer_type=True,
        )

        # Validador contra el JWKS real de Keycloak
        cls.real_validator = ZeroTrustJWTValidator(
            discovery_url=DISCOVERY_URL,
            expected_audience=AUDIENCE,
            clock_skew_seconds=10,
            expected_authorized_party=CLIENT_ID,
            require_bearer_type=True,
        )

    def setUp(self):
        self.client = PKCEAuthClient()

    def _forge_signed_token(
        self,
        payload_overrides: dict = None,
        header_overrides: dict = None,
        corrupt_signature: bool = False,
    ) -> str:
        header = {"alg": "RS256", "typ": "JWT", "kid": self.kid}
        if header_overrides:
            header.update(header_overrides)

        now = int(time.time())
        payload = {
            "sub": "user-uuid-synthetic-001",
            "preferred_username": "admision.test",
            "iss": BASE_URL,
            "aud": [AUDIENCE],
            "azp": CLIENT_ID,
            "typ": "Bearer",
            "exp": now + 600,
            "nbf": now - 10,
            "iat": now,
            "realm_access": {"roles": ["admision"]},
            "amr": ["pwd"],
        }
        if payload_overrides:
            for k, v in payload_overrides.items():
                if v is None:
                    payload.pop(k, None)
                else:
                    payload[k] = v

        raw_header = b64url(json.dumps(header).encode("utf-8"))
        raw_payload = b64url(json.dumps(payload).encode("utf-8"))
        signing_input = f"{raw_header}.{raw_payload}".encode("ascii")
        sig = self.signing_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())

        if corrupt_signature:
            sig = sig[:-1] + (b"\x00" if sig[-1:] != b"\x00" else b"\xFF")

        return f"{raw_header}.{raw_payload}.{b64url(sig)}"

    @unittest.skipUnless(KEYCLOAK_REACHABLE, "Servicio Keycloak local (127.0.0.1:8085) no disponible temporalmente en el entorno.")
    def test_01_oidc_discovery_real_keycloak_reachable(self):
        """1. Verifica que el endpoint OIDC Discovery de Keycloak real responde con metadatos validos."""
        req = urllib.request.Request(DISCOVERY_URL)
        ctx = ssl.create_default_context(cafile=CA_CERT_PATH) if TLS_ENABLED else None
        with urllib.request.urlopen(req, context=ctx) as resp:
            self.assertEqual(resp.status, 200)
            meta = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(meta.get("issuer"), BASE_URL)
            self.assertTrue(meta.get("jwks_uri").endswith("/protocol/openid-connect/certs"))

    @unittest.skipUnless(KEYCLOAK_REACHABLE, "Servicio Keycloak local (127.0.0.1:8085) no disponible temporalmente en el entorno.")
    def test_02_jwks_certs_real_keycloak_keys(self):
        """2. Verifica que el JWKS real publicado por Keycloak contiene claves RSA RS256 utilizables."""
        jwks_url = f"{BASE_URL}/protocol/openid-connect/certs"
        req = urllib.request.Request(jwks_url)
        ctx = ssl.create_default_context(cafile=CA_CERT_PATH) if TLS_ENABLED else None
        with urllib.request.urlopen(req, context=ctx) as resp:
            self.assertEqual(resp.status, 200)
            jwks = json.loads(resp.read().decode("utf-8"))
            keys = jwks.get("keys", [])
            self.assertTrue(len(keys) >= 1)
            sig_keys = [k for k in keys if k.get("use") == "sig" and k.get("kty") == "RSA"]
            self.assertTrue(len(sig_keys) >= 1)

    @unittest.skipUnless(TLS_ENABLED, "FASE 3 Zero Trust: Requiere endpoint HTTPS/TLS local para transmitir cookies 'Secure' sin eludir RFC 6265.")
    def test_03_real_token_pkce_admission_success(self):
        """3. Obtencion de Access Token real para admision.test via Authorization Code + PKCE S256."""
        pwd = get_user_password("admision.test")
        res = self.client.execute_login("admision.test", pwd)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertTrue(res.get("has_access_token"), "Keycloak debio emitir un Access Token valido")

    @unittest.skipUnless(TLS_ENABLED, "FASE 3 Zero Trust: Requiere endpoint HTTPS/TLS local para transmitir cookies 'Secure' sin eludir RFC 6265.")
    def test_04_real_mfa_challenge_triggered_for_medico(self):
        """4. Medico con rol mfa-required recibe desafio MFA obligatorio en Keycloak sin emision de codigo."""
        pwd = get_user_password("medico.test")
        res = self.client.execute_login("medico.test", pwd)
        self.assertEqual(res["status"], "MFA_CHALLENGE_TRIGGERED")
        self.assertFalse(res.get("has_access_token", False))

    def test_05_id_token_rejection_by_type_end_to_end(self):
        """5. ID Token debidamente firmado con audiencia valida es rechazado en PEP via validate_token()."""
        id_token = self._forge_signed_token(
            header_overrides={"typ": "JWT"},
            payload_overrides={"typ": "ID", "aud": [AUDIENCE], "token_use": None},
        )
        with self.assertRaises(InvalidTokenTypeError):
            self.validator.validate_token(id_token)

    def test_06_unauthorized_party_azp_rejection_end_to_end(self):
        """6. Token firmado con cliente azp no autorizado es rechazado en PEP via validate_token()."""
        token_bad_azp = self._forge_signed_token(
            payload_overrides={"azp": "malicious-third-party-client"}
        )
        with self.assertRaises(InvalidAudienceError):
            self.validator.validate_token(token_bad_azp)

    def test_07_keycloak_failure_handling_fail_closed(self):
        """7. Manejo de fallos de red en Keycloak: exige estrictamente JWKSFetchError (sin excepciones genericas)."""
        failing_validator = ZeroTrustJWTValidator(
            discovery_url="http://127.0.0.1:9999/unreachable/.well-known/openid-configuration",
            expected_audience=AUDIENCE,
        )
        token = self._forge_signed_token(header_overrides={"kid": "phantom-kid-999"})
        with self.assertRaises(JWKSFetchError):
            failing_validator.validate_token(token)

    @unittest.skipUnless(KEYCLOAK_REACHABLE, "Servicio Keycloak local (127.0.0.1:8085) no disponible temporalmente en el entorno.")
    def test_08_real_keycloak_jwks_key_parsing(self):
        """8. Comprueba que JWKSCacheManager puede parsear y cargar claves reales publicadas por Keycloak."""
        cache_real = JWKSCacheManager(discovery_url=DISCOVERY_URL)
        issuer = cache_real.expected_issuer
        self.assertEqual(issuer, BASE_URL)
        cache_real._fetch_jwks()
        self.assertTrue(len(cache_real._keys_by_kid) >= 1)
        for kid, pkey in cache_real._keys_by_kid.items():
            self.assertIsInstance(pkey, rsa.RSAPublicKey)

    def test_09_tampered_signature_rejection_end_to_end(self):
        """9. Rechazo criptografico en validate_token() cuando la firma digital es alterada en transito."""
        tampered_token = self._forge_signed_token(corrupt_signature=True)
        with self.assertRaises(InvalidSignatureError):
            self.validator.validate_token(tampered_token)

    def test_10_invalid_audience_rejection_end_to_end(self):
        """10. Rechazo en validate_token() cuando el token tiene una audiencia ajena al recurso solicitado."""
        token_wrong_aud = self._forge_signed_token(payload_overrides={"aud": ["billing-service-api"]})
        with self.assertRaises(InvalidAudienceError):
            self.validator.validate_token(token_wrong_aud)

    def test_11_expired_token_rejection_end_to_end(self):
        """11. Rechazo en validate_token() cuando el token ha expirado segun su claim 'exp'."""
        expired_token = self._forge_signed_token(payload_overrides={"exp": int(time.time()) - 120})
        with self.assertRaises(TokenExpiredError):
            self.validator.validate_token(expired_token)

    def _get_authenticated_medico_token(self) -> str:
        """Obtiene un token real para medico.test, reutilizandolo dentro de la suite para respetar la proteccion contra repeticion RFC 6238."""
        if hasattr(self.__class__, "_cached_medico_token") and self.__class__._cached_medico_token:
            return self.__class__._cached_medico_token
        pwd = get_user_password("medico.test")
        seed = get_or_create_medico_totp_seed()
        res = self.client.execute_login("medico.test", pwd, totp_seed=seed)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertTrue(res.get("has_access_token"))
        self.__class__._cached_medico_token = res["access_token"]
        return self.__class__._cached_medico_token

    @unittest.skipUnless(TLS_ENABLED, "FASE 3 Zero Trust: Requiere endpoint HTTPS/TLS local para transmitir cookies 'Secure' sin eludir RFC 6265.")
    def test_12_real_mfa_totp_login_and_token_verification(self):
        """12. Autenticacion completa de medico.test con Password + TOTP real y verificacion criptografica de claims."""
        token = self._get_authenticated_medico_token()
        context = self.real_validator.validate_token(token)

        self.assertEqual(context.username, "medico.test")
        self.assertIn("ROLE_PATHOLOGIST", context.roles)
        self.assertIn(AUDIENCE, context.audience)
        self.assertEqual(context.issuer, BASE_URL)
        self.assertTrue(context.mfa_verified, "El token real de Keycloak tras TOTP debe tener mfa_verified=True")
        self.assertIn("otp", context.amr, "El claim AMR real de Keycloak debe contener 'otp' tras el segundo factor")

    @unittest.skipUnless(TLS_ENABLED, "FASE 3 Zero Trust: Requiere endpoint HTTPS/TLS local para transmitir cookies 'Secure' sin eludir RFC 6265.")
    def test_13_real_mfa_authorizes_validate_order(self):
        """13. Token autentico de medico con evidencia TOTP autoriza exitosamente la operacion critica VALIDATE_ORDER."""
        token = self._get_authenticated_medico_token()
        context = self.real_validator.validate_token(token)

        # Enforce debe completarse sin excepciones
        enforce_clinical_action(context, "VALIDATE_ORDER")

    @unittest.skipUnless(TLS_ENABLED, "FASE 3 Zero Trust: Requiere endpoint HTTPS/TLS local para transmitir cookies 'Secure' sin eludir RFC 6265.")
    def test_14_real_admission_token_rejected_for_sensitive_action(self):
        """14. Token autentico de admision (sin MFA) permite CREATE_ORDER pero es bloqueado para VALIDATE_ORDER."""
        pwd = get_user_password("admision.test")
        res = self.client.execute_login("admision.test", pwd)
        context = self.real_validator.validate_token(res["access_token"])

        self.assertEqual(context.username, "admision.test")
        self.assertIn("ROLE_RECEPTION", context.roles)
        self.assertFalse(context.mfa_verified, "Admision autenticado solo con password no debe tener mfa_verified")
        self.assertNotIn("otp", context.amr, "El claim AMR de admision no debe contener 'otp'")

        # Operacion estandar permitida
        enforce_clinical_action(context, "CREATE_ORDER")

        # Operacion critica bloqueada
        with self.assertRaises(InsufficientPermissionsError):
            enforce_clinical_action(context, "VALIDATE_ORDER")

    @unittest.skipUnless(TLS_ENABLED, "FASE 3 Zero Trust: Requiere endpoint HTTPS/TLS local para transmitir cookies 'Secure' sin eludir RFC 6265.")
    def test_15_doctor_without_mfa_denied_sensitive_action(self):
        """15. Contexto de medico autenticado pero sin evidencia MFA es bloqueado estrictamente por MFARequiredError."""
        token = self._get_authenticated_medico_token()
        context = self.real_validator.validate_token(token)

        # Simular contexto donde el token carece de acreditacion MFA
        context_no_mfa = dataclasses.replace(context, mfa_verified=False)
        with self.assertRaises(MFARequiredError):
            enforce_clinical_action(context_no_mfa, "VALIDATE_ORDER")

    @unittest.skipUnless(TLS_ENABLED, "FASE 3 Zero Trust: Requiere endpoint HTTPS/TLS local para transmitir cookies 'Secure' sin eludir RFC 6265.")
    def test_16_doctor_omitting_otp_denied_authorization_code(self):
        """16. Keycloak no emite codigo de autorizacion ni token cuando el medico omite el desafio OTP."""
        pwd = get_user_password("medico.test")
        # Intento de login sin proporcionar semilla/codigo TOTP
        res = self.client.execute_login("medico.test", pwd, totp_seed=None)
        self.assertEqual(res["status"], "MFA_CHALLENGE_TRIGGERED")
        self.assertFalse(res.get("has_access_token", False))
        self.assertNotIn("access_token", res)


if __name__ == "__main__":
    unittest.main()
