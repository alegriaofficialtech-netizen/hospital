#!/usr/bin/env python3
"""Pruebas del modulo M1: administracion de identidades sinteticas.

Casos:
  * un administrador con MFA acreditada puede listar, crear y desactivar
  * un administrador sin evidencia OTP es denegado por MFA
  * una identidad clinica sin rol de plataforma es denegada por rol
  * cada operacion de administracion queda en la cadena de auditoria
"""

import json
import os
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
ADMIN_SINMFA_FILE = RUNTIME / "admin-sinmfa-credentials.json"
BACKEND_URL = os.environ.get("F11_API_BASE_URL", "http://127.0.0.1:8010").rstrip("/")
KC_URL = os.environ.get("F11_KEYCLOAK_URL", "http://127.0.0.1:8085").rstrip("/")


def load_setup_realm():
    import importlib.util

    path = ROOT / "infra" / "local-test" / "setup_realm.py"
    spec = importlib.util.spec_from_file_location("f11_setup_realm", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class IdentityAdminSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not CREDENTIALS_FILE.is_file():
            raise unittest.SkipTest(f"missing {CREDENTIALS_FILE}")
        cls.credentials = json.loads(CREDENTIALS_FILE.read_text(encoding="utf-8"))
        cls.users = cls.credentials["users"]
        cls.setup_realm = load_setup_realm()
        cls._tokens = {}

    def token(self, username, password=None, totp_secret=None):
        key = (username, bool(totp_secret))
        if key in self._tokens:
            return self._tokens[key]
        user = self.users.get(username)
        if user is None:
            raise unittest.SkipTest(f"unknown identity {username}")
        secret = totp_secret if totp_secret is not None else user.get("totp_secret")
        flow = self.setup_realm.BrowserFlow(
            KC_URL,
            self.credentials["realm"],
            self.credentials["clientId"],
            self.credentials["redirectUri"],
        )
        # Un codigo TOTP solo sirve una vez por ventana de 30 s. Si otro
        # login del mismo usuario acaba de consumirlo, se espera a la ventana
        # siguiente y se reintenta una vez.
        for attempt in range(2):
            try:
                result = flow.login(
                    username, password or user["password"], secret,
                )
                break
            except Exception as exc:  # noqa: BLE001
                if attempt == 1 or "no respondio" not in str(exc) and "authorization code" not in str(exc):
                    raise
                time.sleep(32)
                flow = self.setup_realm.BrowserFlow(
                    KC_URL,
                    self.credentials["realm"],
                    self.credentials["clientId"],
                    self.credentials["redirectUri"],
                )
        self._tokens[key] = result["access_token"]
        return result["access_token"]

    def call(self, token, method, path, body=None):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Authorization": "Bearer " + token}
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            BACKEND_URL + path, data=data, headers=headers, method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    # ------------------------------------------------------------------ casos

    def test_01_admin_with_mfa_lists_identities(self):
        token = self.token("medico.test")
        status, payload = self.call(token, "GET", "/api/v1/admin/identities")
        self.assertEqual(200, status, payload)
        self.assertIn("identities", payload)
        self.assertIn("summary", payload)
        self.assertGreaterEqual(payload["summary"]["total"], 1)

    def test_02_admin_with_mfa_lists_roles(self):
        token = self.token("medico.test")
        status, payload = self.call(token, "GET", "/api/v1/admin/roles")
        self.assertEqual(200, status, payload)
        names = [role["name"] for role in payload["roles"]]
        self.assertIn("sgsi-admin", names)

    def test_03_admin_without_mfa_is_denied(self):
        if not ADMIN_SINMFA_FILE.is_file():
            self.skipTest("no hay cuenta de administracion sin MFA disponible")
        creds = json.loads(ADMIN_SINMFA_FILE.read_text(encoding="utf-8"))
        token = self.token(
            creds["username"], password=creds["password"], totp_secret=None,
        )
        status, payload = self.call(token, "GET", "/api/v1/admin/identities")
        self.assertEqual(403, status, payload)
        self.assertEqual("MFA_AUTHENTICATION_REQUIRED", payload.get("code"))

    def test_04_identity_without_admin_role_is_denied(self):
        token = self.token("recepcion.test")
        status, payload = self.call(token, "GET", "/api/v1/admin/identities")
        self.assertEqual(403, status, payload)
        self.assertEqual("PLATFORM_ADMIN_ROLE_REQUIRED", payload.get("code"))

    def test_05_admin_creates_and_deactivates_a_synthetic_identity(self):
        token = self.token("medico.test")
        username = "prueba.test"
        status, payload = self.call(
            token, "POST", "/api/v1/admin/identities",
            {"username": username, "roles": ["medico"], "require_mfa": True},
        )
        self.assertEqual(201, status, payload)
        self.assertIn("temporary_password", payload)
        created = payload["identity"]
        self.assertEqual(username, created["username"])

        status, payload = self.call(
            token, "POST", f"/api/v1/admin/identities/{created['id']}/state",
            {"enabled": False},
        )
        self.assertEqual(200, status, payload)
        self.assertFalse(payload.get("enabled"))

    def test_06_non_synthetic_username_is_rejected(self):
        token = self.token("medico.test")
        status, payload = self.call(
            token, "POST", "/api/v1/admin/identities",
            {"username": "paciente.real", "roles": ["medico"]},
        )
        self.assertEqual(400, status, payload)
        self.assertEqual("IDENTITY_INVALID", payload.get("code"))

    def test_07_admin_actions_are_audited(self):
        token = self.token("auditor.test")
        status, payload = self.call(token, "GET", "/api/v1/audit/events")
        self.assertEqual(200, status, payload)
        self.assertTrue(payload.get("audit_chain_valid"), payload)
        actions = {event.get("action") for event in payload.get("events", [])}
        self.assertTrue(
            actions & {"LIST_IDENTITIES", "CREATE_IDENTITY", "UPDATE_IDENTITY"},
            "las operaciones de administracion no aparecen en la auditoria: %s" % sorted(actions),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
