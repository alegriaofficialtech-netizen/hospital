#!/usr/bin/env python3
"""Pruebas del canal de solicitud de cuentas y de la unicidad del acceso.

Casos:
  * una solicitud valida se registra y queda pendiente de autorizacion
  * una solicitud con datos invalidos se rechaza y queda auditada
  * el canal no concede acceso: no emite sesion ni crea identidades
  * el canal se acota por origen para no usarse como buzon de spam
  * Angular no captura credenciales: el formulario vive en el tema de Keycloak
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
BACKEND_URL = os.environ.get("F11_API_BASE_URL", "http://127.0.0.1:8010").rstrip("/")
KC_URL = os.environ.get("F11_KEYCLOAK_URL", "http://127.0.0.1:8085").rstrip("/")


def load_setup_realm():
    import importlib.util

    path = ROOT / "infra" / "local-test" / "setup_realm.py"
    spec = importlib.util.spec_from_file_location("f11_setup_realm_request", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def mfa_evidence(result):
    """True solo si el token acredita el segundo factor en ``amr``.

    Debe coincidir con el criterio del backend (``jwt_validator.py``): ``amr``
    como lista que contenga ``otp``, ``totp`` o ``mfa-otp``. El claim ``acr``
    no se acepta aqui porque el backend tampoco lo acepta: un arnes mas laxo
    que el servidor esconde denegaciones reales.
    """
    claims = result.get("claims") or {}
    amr = claims.get("amr")
    if not isinstance(amr, list):
        return False
    return any(
        isinstance(m, str) and m.strip().lower() in ("otp", "totp", "mfa-otp")
        for m in amr
    )


def events_of(payload):
    """Normaliza la respuesta de auditoria a una lista de eventos."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("events", "audit_events", "data", "results"):
            if isinstance(payload.get(key), list):
                return payload[key]
    return []


class IdentityRequestSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not CREDENTIALS_FILE.is_file():
            raise unittest.SkipTest(f"missing {CREDENTIALS_FILE}")
        cls.credentials = json.loads(CREDENTIALS_FILE.read_text(encoding="utf-8"))
        cls.setup_realm = load_setup_realm()
        cls._tokens = {}
        # Reset defensive rate limits
        try:
            user = cls.credentials["users"]["medico.test"]
            flow = cls.setup_realm.BrowserFlow(
                KC_URL,
                cls.credentials["realm"],
                cls.credentials["clientId"],
                cls.credentials["redirectUri"],
            )
            res = flow.login("medico.test", user["password"], user.get("totp_secret"))
            token = res.get("access_token")
            if token:
                req = urllib.request.Request(
                    BACKEND_URL + "/api/v1/admin/rate-limits/reset",
                    data=b"{}",
                    headers={"Content-Type": "application/json", "Authorization": "Bearer " + token},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    resp.read()
        except Exception:
            pass

    def login(self, username):
        """Emite un token fresco para la cuenta indicada."""
        if username in self._tokens:
            return self._tokens[username]
        user = self.credentials["users"][username]
        flow = self.setup_realm.BrowserFlow(
            KC_URL,
            self.credentials["realm"],
            self.credentials["clientId"],
            self.credentials["redirectUri"],
        )
        result = None
        for attempt in range(2):
            try:
                result = flow.login(
                    username, user["password"], user.get("totp_secret")
                )
                break
            except Exception:  # noqa: BLE001
                if attempt == 1:
                    raise
                time.sleep(32)
                flow = self.setup_realm.BrowserFlow(
                    KC_URL,
                    self.credentials["realm"],
                    self.credentials["clientId"],
                    self.credentials["redirectUri"],
                )
        # Un codigo TOTP solo sirve una vez por ventana de 30 s: si el token
        # llega sin evidencia OTP, se espera a la ventana siguiente y se
        # reintenta una vez.
        if user.get("totp_secret") and not mfa_evidence(result):
            time.sleep(32)
            flow = self.setup_realm.BrowserFlow(
                KC_URL,
                self.credentials["realm"],
                self.credentials["clientId"],
                self.credentials["redirectUri"],
            )
            result = flow.login(
                username, user["password"], user.get("totp_secret")
            )
        self._tokens[username] = result["access_token"]
        return self._tokens[username]

    def post(self, path, body, token=None, headers=None):
        data = json.dumps(body).encode("utf-8")
        h = {"Content-Type": "application/json"}
        if headers:
            h.update(headers)
        if token:
            h["Authorization"] = "Bearer " + token
        request = urllib.request.Request(
            BACKEND_URL + path, data=data, headers=h, method="POST"
        )
        return self._send(request)

    def get(self, path, token=None):
        headers = {}
        if token:
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(BACKEND_URL + path, headers=headers)
        return self._send(request)

    @staticmethod
    def _send(request):
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                raw = response.read().decode("utf-8")
                return response.status, json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8")
            try:
                return exc.code, json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                return exc.code, {"raw": raw}

    def audit_events(self):
        # La auditoria es territorio exclusivo del Oficial de Seguridad.
        status, payload = self.get("/api/v1/audit/events", self.login("auditor.test"))
        self.assertEqual(200, status, f"no se pudo leer la auditoria: {payload}")
        return events_of(payload)

    def test_01_valid_request_is_recorded_as_pending_authorization(self):
        status, payload = self.post(
            "/api/v1/identity-requests",
            {
                "full_name": "Personal de guardia",
                "email": "guardia@hospital.local",
                "justification": "Necesito acceso al laboratorio para la guardia de la manana.",
            },
        )
        self.assertEqual(201, status, payload)
        self.assertTrue(str(payload.get("request_id", "")).startswith("REQ-"))
        self.assertEqual("PENDING_ADMIN_AUTHORIZATION", payload.get("status"))

        events = self.audit_events()
        matched = [
            event
            for event in events
            if event.get("action") == "IDENTITY_REQUEST"
            and event.get("status") == "REQUESTED"
        ]
        self.assertTrue(matched, "la solicitud no quedo en la cadena de auditoria")

    def test_02_invalid_request_is_rejected_and_audited(self):
        status, payload = self.post(
            "/api/v1/identity-requests",
            {"full_name": "x", "email": "no-es-un-correo", "justification": "corto"},
        )
        self.assertEqual(400, status, payload)
        fields = payload.get("fields", {})
        self.assertIn("email", fields)
        self.assertIn("justification", fields)

        events = self.audit_events()
        matched = [
            event
            for event in events
            if event.get("action") == "IDENTITY_REQUEST"
            and event.get("status") == "REJECTED"
        ]
        self.assertTrue(matched, "el rechazo no quedo en la cadena de auditoria")

    def test_03_channel_grants_no_access(self):
        """Pedir una cuenta no habilita nada: ni sesion ni identidad."""
        status, _ = self.get("/api/v1/orders")
        self.assertEqual(401, status, "las rutas clinicas siguen exigiendo un token")

        status, payload = self.get(
            "/api/v1/admin/identities", self.login("medico.test")
        )
        self.assertEqual(200, status, payload)
        identities = (
            payload.get("identities", payload)
            if isinstance(payload, dict)
            else payload
        )
        usernames = {
            str(identity.get("username", "")).lower()
            for identity in identities
            if isinstance(identity, dict)
        }
        self.assertNotIn("guardia@hospital.local", usernames)
        self.assertNotIn("personal de guardia", usernames)

    def test_04_channel_is_rate_limited_per_origin(self):
        """El canal publico se acota: no puede usarse como buzon de spam."""
        status = 0
        payload = {}
        test_ip = f"198.51.100.{(int(time.time() * 1000) % 200) + 1}"
        for _ in range(12):
            status, payload = self.post(
                "/api/v1/identity-requests",
                {
                    "full_name": "Prueba de limite",
                    "email": "limite@hospital.local",
                    "justification": "Solicitud repetida para comprobar el limite por origen.",
                },
                headers={"X-Forwarded-For": test_ip},
            )
            if status == 429:
                break
        self.assertEqual(429, status, payload)
        self.assertEqual("IDENTITY_REQUEST_RATE_LIMITED", payload.get("code"))

        events = self.audit_events()
        matched = [
            event
            for event in events
            if event.get("action") == "IDENTITY_REQUEST"
            and event.get("status") == "RATE_LIMITED"
        ]
        self.assertTrue(matched, "el limite no quedo en la cadena de auditoria")

    def test_05_frontend_never_captures_credentials(self):
        """El navegador no captura contrasenas: el formulario vive en Keycloak."""
        login_html = (
            ROOT / "frontend/src/app/features/login/login.component.html"
        ).read_text(encoding="utf-8")
        login_ts = (
            ROOT / "frontend/src/app/features/login/login.component.ts"
        ).read_text(encoding="utf-8")
        theme_ftl = (
            ROOT / "infra/f11/keycloak-theme/sgsi-zta/login/login.ftl"
        ).read_text(encoding="utf-8")

        # el login de Angular no es un formulario de credenciales
        self.assertNotIn('type="password"', login_html)
        self.assertNotIn('name="password"', login_html)
        self.assertNotIn("[(ngModel)]", login_html)
        self.assertNotIn("<form", login_html)
        self.assertIn("loginWithKeycloak", login_ts)

        # el formulario real es el de Keycloak, con el diseno del hospital
        self.assertIn('action="${url.loginAction}"', theme_ftl)
        self.assertIn('name="username"', theme_ftl)
        self.assertIn('name="password"', theme_ftl)
        self.assertIn("solicitud-cuenta", theme_ftl)

        # ninguna credencial de ejemplo queda en el codigo del navegador
        for source in (ROOT / "frontend/src").rglob("*.ts"):
            text = source.read_text(encoding="utf-8")
            self.assertNotIn(
                "Clinica2026", text, f"credencial de ejemplo en {source.name}"
            )


if __name__ == "__main__":
    unittest.main()