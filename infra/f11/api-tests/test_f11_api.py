#!/usr/bin/env python3
"""F11 API suite: JWT validation, RBAC, MFA/TOTP and the audit trail.

Runs against a live F11 stack over the loopback interface. It never starts a
service, never builds an image and never touches the Playwright path: Stage C
is decoupled from it. ``infra/f11/run-api-tests.sh`` performs the preflight
admission before calling this suite.

Only the Python standard library is used. The OIDC login flow is reused from
``infra/local-test/setup_realm.py``, which already drives the real Keycloak
authorization code + PKCE exchange and answers the TOTP challenge.

Coverage:

* JWT   - missing, malformed and valid bearer tokens
* RBAC  - reception, laboratory, pathologist and auditor policies
* MFA   - TOTP evidence is required for VALIDATE_ORDER and refused without it
* audit - every denial and every success reaches the immutable trail

The synthetic users are the ones provisioned by ``setup_realm.py``:
``recepcion.test`` (admision), ``laboratorio.test`` (laboratorio),
``medico.test`` (medico + MFA), ``medico.sinmfa`` (medico, no MFA) and
``auditor.test`` (auditor).
"""

import hashlib
import hmac
import importlib.util
import json
import os
import secrets
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
RUNTIME = Path(os.environ.get("F11_RUNTIME_DIR", "/home/elcra/sgsi-zta-runtime/f11"))
CREDENTIALS_FILE = Path(
    os.environ.get("F11_CREDENTIALS_FILE", str(RUNTIME / "credentials.json"))
)
BACKEND_ENV = ROOT / "infra" / "f11" / "backend.env"
BACKEND_URL = os.environ.get("F11_API_BASE_URL", "http://127.0.0.1:8010").rstrip("/")

# Synthetic analytes, inside the ranges accepted by the clinical schema.
MEASUREMENTS = {
    "hemoglobina_g_dl": 14.2,
    "hematocrito_pct": 44.0,
    "leucocitos_mm3": 6800.0,
    "plaquetas_k_ul": 250.0,
    "glucosa_mg_dl": 92.0,
}


def _load_setup_realm():
    """Import infra/local-test/setup_realm.py without executing its main()."""
    path = ROOT / "infra" / "local-test" / "setup_realm.py"
    spec = importlib.util.spec_from_file_location("f11_setup_realm", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _read_env_value(path, key):
    """Read one key from a KEY=VALUE env file. The value is never printed."""
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        if name.strip() == key:
            return value.strip().strip("'\"")
    raise KeyError(f"{key} is missing from {path}")


class ApiClient:
    """Minimal JSON client over the loopback interface."""

    def __init__(self, base_url):
        self.base_url = base_url

    def request(self, method, path, token=None, body=None, headers=None, raw_body=None):
        url = self.base_url + path
        request_headers = dict(headers or {})
        if raw_body is not None:
            data = raw_body.encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        elif body is not None:
            data = json.dumps(body).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        else:
            data = None
        if token:
            request_headers["Authorization"] = "Bearer " + token
        req = urllib.request.Request(
            url, data=data, headers=request_headers, method=method
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode("utf-8")
                status = resp.status
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8")
            status = exc.code
        try:
            payload = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            payload = {"raw": raw}
        return status, payload


def _find_event(events, action, status):
    """Return the first audit event matching action and status, or None."""
    for event in events:
        if event.get("action") == action and event.get("status") == status:
            return event
    for event in events:
        blob = json.dumps(event, ensure_ascii=False)
        if action in blob and status in blob:
            return event
    return None


class F11ApiSuite(unittest.TestCase):
    """End-to-end checks of the F11 API with a real Keycloak issuer."""

    @classmethod
    def setUpClass(cls):
        if not CREDENTIALS_FILE.is_file():
            raise unittest.SkipTest(
                f"missing {CREDENTIALS_FILE}; run setup_realm.py to provision the realm"
            )
        credentials = json.loads(CREDENTIALS_FILE.read_text(encoding="utf-8"))
        cls.users = credentials["users"]
        cls.realm = credentials["realm"]
        cls.issuer = credentials["issuer"]
        cls.client_id = credentials["clientId"]
        cls.redirect_uri = credentials["redirectUri"]
        cls.keycloak_url = cls.issuer.split(f"/realms/{cls.realm}")[0]
        cls.setup_realm = _load_setup_realm()
        cls.client = ApiClient(BACKEND_URL)
        devices = json.loads(_read_env_value(BACKEND_ENV, "IOMT_DEVICE_KEYS_JSON"))
        cls.device_id = next(iter(devices))
        cls.device_key = devices[cls.device_id]
        cls._tokens = {}
        # unittest builds a fresh instance for every test method, so state
        # shared by several tests has to live on the class, not the instance.
        cls.order_id = "F11-API-%d" % (int(time.time()) * 1000 + os.getpid() % 1000)

    def token(self, username):
        """Mint an access token through the real OIDC flow."""
        if username not in self._tokens:
            user = self.users[username]
            # Un codigo TOTP solo sirve una vez por ventana de 30 s. Si otra
            # suite lo acaba de consumir, se espera a la ventana siguiente.
            for attempt in range(2):
                flow = self.setup_realm.BrowserFlow(
                    self.keycloak_url, self.realm, self.client_id, self.redirect_uri
                )
                try:
                    result = flow.login(
                        username, user["password"], user.get("totp_secret")
                    )
                    break
                except Exception as exc:  # noqa: BLE001
                    if attempt == 1 or "authorization code" not in str(exc):
                        raise
                    time.sleep(32)
            self._tokens[username] = result["access_token"]
        return self._tokens[username]

    def api(self, method, path, token=None, body=None):
        return self.client.request(method, path, token=token, body=body)

    def post_iomt_results(self, order_id, measurements):
        """Post analyser results signed with the device key, as the channel expects."""
        body = json.dumps({"order_id": order_id, "measurements": measurements})
        timestamp = f"{time.time():.3f}"
        nonce = secrets.token_hex(8)
        signing_input = "%s\n%s\n%s\n%s" % (
            self.device_id,
            timestamp,
            nonce,
            body,
        )
        signature = hmac.new(
            self.device_key.encode("utf-8"),
            signing_input.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        headers = {
            "X-Device-Id": self.device_id,
            "X-Device-Timestamp": timestamp,
            "X-Device-Nonce": nonce,
            "X-Device-Signature": signature,
        }
        return self.client.request(
            "POST", "/api/v1/iomt/results", raw_body=body, headers=headers
        )

    # -- JWT -------------------------------------------------------------

    def test_01_request_without_token_is_rejected(self):
        status, payload = self.api("GET", "/api/v1/orders")
        self.assertEqual(401, status, payload)
        self.assertEqual("MISSING_AUTHORIZATION_HEADER", payload.get("code"))

    def test_02_malformed_token_is_rejected(self):
        status, payload = self.api("GET", "/api/v1/orders", token="not-a-jwt")
        self.assertEqual(401, status, payload)
        self.assertIn(
            payload.get("code"),
            {
                "JWT_VALIDATION_FAILED",
                "INVALID_TOKEN_SIGNATURE",
                "INVALID_TOKEN_TYPE",
                "UNTRUSTED_ISSUER",
                "INVALID_AUDIENCE",
                "TOKEN_EXPIRED",
            },
            payload,
        )

    def test_03_valid_token_is_accepted(self):
        status, payload = self.api(
            "GET", "/api/v1/orders", token=self.token("laboratorio.test")
        )
        self.assertEqual(200, status, payload)
        self.assertIn("orders", payload)
        self.assertIsInstance(payload.get("count"), int)

    # -- RBAC ------------------------------------------------------------

    def test_04_reception_creates_an_order(self):
        status, payload = self.api(
            "POST",
            "/api/v1/orders",
            token=self.token("recepcion.test"),
            body={
                "order_id": self.order_id,
                "patient_dni": "00000000",
                "test_type": "HEMOGRAMA COMPLETO",
            },
        )
        self.assertEqual(201, status, payload)
        self.assertEqual("CREATED", payload.get("status"))

    def test_05_laboratory_cannot_create_orders(self):
        status, payload = self.api(
            "POST",
            "/api/v1/orders",
            token=self.token("laboratorio.test"),
            body={
                "order_id": "F11-API-DENIED-%d" % int(time.time()),
                "patient_dni": "00000000",
            },
        )
        self.assertEqual(403, status, payload)
        self.assertEqual("RECEPTION_ROLE_REQUIRED", payload.get("code"))

    def test_06_reception_cannot_read_the_audit_trail(self):
        status, payload = self.api(
            "GET", "/api/v1/audit/events", token=self.token("recepcion.test")
        )
        self.assertEqual(403, status, payload)
        self.assertEqual("AUDITOR_ROLE_REQUIRED", payload.get("code"))

    def test_07_legacy_login_endpoint_is_refused(self):
        status, payload = self.api(
            "POST",
            "/api/v1/auth/login",
            body={
                "username": "recepcion.test",
                "password": self.users["recepcion.test"]["password"],
            },
        )
        # 410 when legacy auth is disabled (the F11 configuration), 403 when it
        # is enabled and a clinical user tries to bypass Keycloak.
        self.assertIn(status, (403, 410), payload)
        self.assertIn(
            payload.get("code"),
            {"AUTH_DELEGATED_TO_KEYCLOAK", "LEGACY_CLINICAL_LOGIN_PROHIBITED"},
            payload,
        )

    # -- MFA -------------------------------------------------------------

    def test_08_pathologist_without_mfa_cannot_validate(self):
        status, payload = self.api(
            "POST",
            "/api/v1/orders/validate",
            token=self.token("medico.sinmfa"),
            body={"order_id": self.order_id},
        )
        self.assertEqual(403, status, payload)
        self.assertEqual("MFA_AUTHENTICATION_REQUIRED", payload.get("code"))

    def test_09_analyser_results_move_the_order_to_analyzed(self):
        status, payload = self.post_iomt_results(self.order_id, MEASUREMENTS)
        self.assertIn(status, (200, 201), payload)

    def test_10_pathologist_with_mfa_validates_and_releases(self):
        status, payload = self.api(
            "POST",
            "/api/v1/orders/validate",
            token=self.token("medico.test"),
            body={"order_id": self.order_id, "observations": "Valores analiticos conformes"},
        )
        self.assertEqual(200, status, payload)
        self.assertEqual("SUCCESS", payload.get("status"))
        self.assertEqual("VALIDATED_AND_RELEASED", payload.get("order", {}).get("status"))

    # -- audit -----------------------------------------------------------

    def test_11_auditor_reads_the_audit_trail(self):
        status, payload = self.api(
            "GET", "/api/v1/audit/events", token=self.token("auditor.test")
        )
        self.assertEqual(200, status, payload)
        self.assertTrue(payload.get("audit_chain_valid"), payload)
        self.assertIsInstance(payload.get("events"), list)

    def test_12_audit_trail_records_the_denials(self):
        status, payload = self.api(
            "GET", "/api/v1/audit/events", token=self.token("auditor.test")
        )
        self.assertEqual(200, status, payload)
        events = payload.get("events", [])
        self.assertIsNotNone(
            _find_event(events, "VALIDATE_ORDER", "DENIED_MFA_REQUIRED"),
            "the MFA denial is missing from the audit trail",
        )
        self.assertIsNotNone(
            _find_event(events, "GET_AUDIT_LOGS", "DENIED_FORBIDDEN"),
            "the audit access denial is missing from the audit trail",
        )
        self.assertIsNotNone(
            _find_event(events, "CREATE_ORDER", "SUCCESS"),
            "the successful order creation is missing from the audit trail",
        )
        self.assertIsNotNone(
            _find_event(events, "VALIDATE_ORDER", "SUCCESS"),
            "the successful validation is missing from the audit trail",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
