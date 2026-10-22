#!/usr/bin/env python3
"""F2 API suite: diagnostico de seguridad (M2) e inventario de activos (M3).

Casos:
  * el Oficial de Seguridad lee el catalogo de comprobadores, el historial de
    ejecuciones, los hallazgos y el resumen de indicadores
  * el catalogo respeta el objetivo (O1/O2) y la severidad del vocabulario cerrado
  * un usuario clinico sin rol de auditoria no puede leer el diagnostico
  * el administrador sin MFA no puede ejecutar el diagnostico ni gestionar activos
  * el administrador con MFA ejecuta el diagnostico y cada hallazgo trae evidencia real
  * la ejecucion del diagnostico queda persistida y auditada
  * cualquier identidad autenticada lee el inventario; solo el administrador con
    MFA da de alta, actualiza y evalua activos
  * la cadena de auditoria sigue encadenando despues de todas las operaciones de F2

La suite habla siempre con el laboratorio sintetico ``f11-local``: ninguna
afirmacion de este fichero sostiene nada sobre el hospital real.

Solo se usa la biblioteca estandar. El login OIDC real se reutiliza desde
``infra/local-test/setup_realm.py``, que ya conduce el authorization code + PKCE
contra Keycloak y responde al desafio TOTP.
"""

import hashlib
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

# Vocabulario cerrado del contrato de F2 (backend/database.py y
# backend/asset_inventory.py). Las aserciones se apoyan en el, no en supuestos.
ENVIRONMENT = "f11-local"
FINDING_STATUSES = ("passed", "failed", "warning")
FINDING_SEVERITIES = ("critical", "high", "medium", "low")
OBJECTIVES = ("O1", "O2")
ASSET_CLASSIFICATIONS = (
    "container", "service", "dataset", "identity_store", "code", "configuration",
)
ASSET_CRITICALITIES = ("critical", "high", "medium", "low")
ASSET_SOURCES = ("compose", "runtime", "manual")

# Marca inequivoca del activo que crea la suite: no se borra, se deja
# identificado como dato de prueba sintetico del laboratorio.
TEST_ASSET_OWNER = "prueba-automatica"
TEST_ASSET_PREFIX = "prueba-f2-"

# Cache de tokens compartida por las dos clases de esta suite. Un codigo TOTP
# solo sirve una vez por ventana de 30 s: cachear evita gastar ventanas, y la
# vigencia se comprueba contra la claim 'exp' antes de reutilizar el token.
_TOKENS = {}


def load_setup_realm():
    """Importa infra/local-test/setup_realm.py sin ejecutar su main()."""
    import importlib.util

    path = ROOT / "infra" / "local-test" / "setup_realm.py"
    spec = importlib.util.spec_from_file_location("f11_setup_realm_f2", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def mfa_evidence(result):
    """True si el token emitido acredita el segundo factor."""
    claims = result.get("claims") or {}
    amr = claims.get("amr") or []
    if isinstance(amr, str):
        amr = [amr]
    acr = str(claims.get("acr", "")).lower()
    return (
        any(str(value).lower() == "otp" for value in amr)
        or "otp" in acr
        or "mfa" in acr
    )


def mint_token(setup_realm, credentials, username, password=None, totp_secret=None):
    """Emite un token de acceso con el flujo OIDC real de Keycloak.

    Un codigo TOTP solo sirve una vez por ventana de 30 s. Si otro login del
    mismo usuario acaba de consumirlo, el token llega sin evidencia OTP: se
    espera a la ventana siguiente (32 s) y se reintenta, igual que en la suite
    de administracion de identidades de F1.
    """
    user = credentials["users"][username]
    secret = totp_secret if totp_secret is not None else user.get("totp_secret")
    secret_password = password or user["password"]
    result = None
    for attempt in range(3):
        flow = setup_realm.BrowserFlow(
            KC_URL,
            credentials["realm"],
            credentials["clientId"],
            credentials["redirectUri"],
        )
        try:
            result = flow.login(username, secret_password, secret)
        except Exception as exc:  # noqa: BLE001
            if attempt == 2 or (
                "no respondio" not in str(exc) and "authorization code" not in str(exc)
            ):
                raise
            time.sleep(32)
            continue
        if secret and not mfa_evidence(result):
            # La ventana TOTP ya se consumio: se espera a la siguiente y se
            # reintenta antes de desconfiar del token.
            if attempt == 2:
                break
            time.sleep(32)
            continue
        break
    if result is None:
        raise unittest.SkipTest(f"no se pudo emitir token para {username}")
    return result


def token_usable(result, secret):
    """True si el token cacheado sigue vivo y acredita el segundo factor."""
    claims = result.get("claims") or {}
    try:
        expires_at = float(claims.get("exp") or 0)
    except (TypeError, ValueError):
        expires_at = 0.0
    if expires_at and expires_at - time.time() < 120:
        return False
    if secret and not mfa_evidence(result):
        return False
    return True


def admin_token(credentials, setup_realm):
    """Token del administrador de plataforma, reutilizando la cache si sigue vigente."""
    username = "medico.test"
    secret = credentials["users"][username].get("totp_secret")
    cached = _TOKENS.get(username)
    if cached is not None and token_usable(cached, secret):
        return cached["access_token"]
    result = mint_token(setup_realm, credentials, username)
    _TOKENS[username] = result
    return result["access_token"]


def events_of(payload):
    """Normaliza la respuesta de auditoria a una lista de eventos."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("events", "audit_events", "data", "results"):
            if isinstance(payload.get(key), list):
                return payload[key]
    return []


class F2ApiSuite(unittest.TestCase):
    """Base comun de las suites de F2: login OIDC real y llamadas JSON por urllib."""

    @classmethod
    def setUpClass(cls):
        if not CREDENTIALS_FILE.is_file():
            raise unittest.SkipTest(
                f"missing {CREDENTIALS_FILE}; ejecuta setup_realm.py para provisionar el realm"
            )
        cls.credentials = json.loads(CREDENTIALS_FILE.read_text(encoding="utf-8"))
        cls.users = cls.credentials["users"]
        cls.setup_realm = load_setup_realm()

    # ------------------------------------------------------------------ helpers

    def token(self, username, password=None, totp_secret=None):
        """Devuelve un token de acceso vigente para la identidad indicada."""
        user = self.users.get(username)
        if user is None and password is None:
            raise unittest.SkipTest(f"unknown identity {username}")
        secret = totp_secret if totp_secret is not None else (user or {}).get("totp_secret")

        cached = _TOKENS.get(username)
        if cached is not None and token_usable(cached, secret):
            return cached["access_token"]

        result = mint_token(
            self.setup_realm, self.credentials, username, password, totp_secret,
        )
        _TOKENS[username] = result
        return result["access_token"]

    def call(self, token, method, path, body=None, timeout=30):
        """Llama a la API y devuelve (status, payload)."""
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {}
        if token:
            headers["Authorization"] = "Bearer " + token
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            BACKEND_URL + path, data=data, headers=headers, method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                return exc.code, json.loads(raw or b"{}")
            except json.JSONDecodeError:
                return exc.code, {"raw": raw.decode("utf-8", "replace")}

    def get(self, path, token=None, timeout=30):
        return self.call(token, "GET", path, timeout=timeout)

    def post(self, path, body, token=None, timeout=30):
        return self.call(token, "POST", path, body, timeout=timeout)

    def audit_payload(self):
        """Lee la cadena de auditoria con el Oficial de Seguridad."""
        status, payload = self.call(
            self.token("auditor.test"), "GET", "/api/v1/audit/events",
        )
        self.assertEqual(200, status, f"no se pudo leer la auditoria: {payload}")
        return payload

    def audit_events(self):
        return events_of(self.audit_payload())


class F2DiagnosticsApiSuite(F2ApiSuite):
    """M2: diagnostico de seguridad ejecutable sobre la configuracion real del F11."""

    # Estado compartido entre los casos de la clase (unittest crea una
    # instancia nueva por metodo: el estado vive en la clase, no en la instancia).
    run_id = None
    findings = []

    # ------------------------------------------------------------------ casos

    def test_01_auditor_reads_checkers_runs_findings_and_summary(self):
        """El Oficial de Seguridad lee el diagnostico completo."""
        token = self.token("auditor.test")

        status, payload = self.get("/api/v1/diagnostics/checkers", token)
        self.assertEqual(200, status, payload)
        self.assertEqual(ENVIRONMENT, payload.get("environment"))
        self.assertIsInstance(payload.get("checkers"), list)

        status, payload = self.get("/api/v1/diagnostics/runs?limit=20", token)
        self.assertEqual(200, status, payload)
        self.assertEqual(ENVIRONMENT, payload.get("environment"))
        self.assertIsInstance(payload.get("runs"), list)

        status, payload = self.get("/api/v1/diagnostics/findings?limit=100", token)
        self.assertEqual(200, status, payload)
        self.assertIsInstance(payload.get("findings"), list)
        self.assertEqual(
            len(payload["findings"]), payload.get("total"),
            "el total de hallazgos no coincide con la lista devuelta",
        )

        status, payload = self.get("/api/v1/diagnostics/summary", token)
        self.assertEqual(200, status, payload)
        for key in (
            "total_findings", "open_findings", "by_status", "by_severity",
            "by_objective", "by_checker", "runs_total", "last_run",
        ):
            self.assertIn(key, payload, "el resumen no trae la clave %s" % key)

    def test_02_checker_catalog_declares_objective_and_severity(self):
        """Cada comprobador del catalogo declara id, objetivo y severidad."""
        status, payload = self.get("/api/v1/diagnostics/checkers", self.token("auditor.test"))
        self.assertEqual(200, status, payload)
        checkers = payload.get("checkers") or []
        self.assertTrue(checkers, "el catalogo de comprobadores viene vacio")

        seen = set()
        objectives = set()
        for checker in checkers:
            checker_id = checker.get("id")
            self.assertTrue(checker_id, "un comprobador no trae id: %s" % checker)
            self.assertNotIn(checker_id, seen, "el catalogo repite el comprobador %s" % checker_id)
            seen.add(checker_id)
            self.assertIn(checker.get("objective"), OBJECTIVES, checker_id)
            self.assertIn(checker.get("severity"), FINDING_SEVERITIES, checker_id)
            self.assertTrue(str(checker.get("title") or "").strip(), "%s no trae titulo" % checker_id)
            self.assertTrue(
                str(checker.get("description") or "").strip(), "%s no trae descripcion" % checker_id,
            )
            objectives.add(checker.get("objective"))

        # El modulo cubre los dos objetivos de la tesis con evidencia propia.
        self.assertIn("O1", objectives, "el catalogo no cubre el objetivo O1")
        self.assertIn("O2", objectives, "el catalogo no cubre el objetivo O2")

    def test_03_clinical_user_without_auditor_role_is_denied(self):
        """Un usuario clinico no puede leer el diagnostico de seguridad."""
        token = self.token("recepcion.test")

        status, payload = self.get("/api/v1/diagnostics/checkers", token)
        self.assertEqual(403, status, payload)
        self.assertEqual("DIAGNOSTICS_ROLE_REQUIRED", payload.get("code"))

        status, payload = self.get("/api/v1/diagnostics/summary", token)
        self.assertEqual(403, status, payload)
        self.assertEqual("DIAGNOSTICS_ROLE_REQUIRED", payload.get("code"))

    def test_04_admin_without_mfa_cannot_run_the_diagnostics(self):
        """El administrador con rol pero sin OTP recibe 403 por MFA.

        La cuenta es medico.sinmfa: tiene el rol de plataforma, pero su token
        llega sin evidencia OTP, de modo que la ejecucion se deniega por MFA.
        """
        token = self.token("medico.sinmfa", totp_secret=None)
        status, payload = self.post("/api/v1/diagnostics/runs", {"checker_ids": None}, token)
        self.assertEqual(403, status, payload)
        self.assertEqual("MFA_AUTHENTICATION_REQUIRED", payload.get("code"))

    def test_05_admin_with_mfa_runs_the_diagnostics(self):
        """El administrador con MFA ejecuta el catalogo completo de comprobadores."""
        token = self.token("medico.test")
        status, payload = self.post(
            "/api/v1/diagnostics/runs", {"checker_ids": None}, token, timeout=300,
        )
        self.assertEqual(201, status, payload)

        run = payload.get("run") or {}
        findings = payload.get("findings") or []
        self.assertTrue(run.get("id"), "la ejecucion no trae identificador")
        self.assertEqual("completed", run.get("status"))
        self.assertEqual(ENVIRONMENT, run.get("environment"))
        self.assertEqual(ENVIRONMENT, payload.get("environment"))
        self.assertEqual(
            run.get("checker_count"), len(findings),
            "el numero de comprobadores no coincide con los hallazgos devueltos",
        )
        self.assertEqual(
            int(run.get("passed") or 0) + int(run.get("failed") or 0) + int(run.get("warnings") or 0),
            len(findings),
            "los contadores por estado no suman el total de hallazgos",
        )

        status, catalog_payload = self.get("/api/v1/diagnostics/checkers", token)
        self.assertEqual(200, status, catalog_payload)
        catalog = catalog_payload.get("checkers") or []
        self.assertEqual(
            len(catalog), len(findings),
            "la ejecucion no cubrio el catalogo completo de comprobadores",
        )
        self.assertEqual(
            sorted(checker["id"] for checker in catalog),
            sorted(finding.get("checker_id") for finding in findings),
            "la ejecucion no ejecuto exactamente los comprobadores del catalogo",
        )

        type(self).run_id = run["id"]
        type(self).findings = findings

    def test_06_findings_carry_real_evidence(self):
        """Cada hallazgo trae la evidencia real del comprobador que lo produjo."""
        run_id = type(self).run_id
        self.assertTrue(run_id, "no hay ninguna ejecucion de diagnostico que comprobar")

        status, payload = self.get(
            "/api/v1/diagnostics/findings?run_id=%s&limit=100" % run_id,
            self.token("auditor.test"),
        )
        self.assertEqual(200, status, payload)
        findings = payload.get("findings") or []
        self.assertTrue(findings, "la ejecucion %s no dejo ningun hallazgo" % run_id)

        status, catalog_payload = self.get(
            "/api/v1/diagnostics/checkers", self.token("auditor.test"),
        )
        self.assertEqual(200, status, catalog_payload)
        catalog_ids = {checker["id"] for checker in catalog_payload.get("checkers") or []}

        for finding in findings:
            checker_id = finding.get("checker_id")
            self.assertIn(
                checker_id, catalog_ids,
                "el hallazgo pertenece a un comprobador que no esta en el catalogo: %s" % checker_id,
            )
            self.assertEqual(run_id, finding.get("run_id"))
            self.assertIn(finding.get("status"), FINDING_STATUSES, checker_id)
            self.assertIn(finding.get("severity"), FINDING_SEVERITIES, checker_id)
            self.assertIn(finding.get("objective"), OBJECTIVES, checker_id)
            self.assertTrue(
                str(finding.get("evidence_command") or "").strip(),
                "el hallazgo %s no trae comando de evidencia" % checker_id,
            )
            self.assertTrue(
                str(finding.get("evidence_output") or "").strip(),
                "el hallazgo %s no trae salida de evidencia" % checker_id,
            )
            self.assertTrue(
                str(finding.get("remediation") or "").strip(),
                "el hallazgo %s no trae remediacion" % checker_id,
            )

    def test_07_run_is_persisted_in_history_detail_and_summary(self):
        """La ejecucion queda guardada y se puede recuperar con sus hallazgos."""
        run_id = type(self).run_id
        self.assertTrue(run_id, "no hay ninguna ejecucion de diagnostico que comprobar")
        token = self.token("auditor.test")

        status, payload = self.get("/api/v1/diagnostics/runs?limit=20", token)
        self.assertEqual(200, status, payload)
        runs = payload.get("runs") or []
        matching = [run for run in runs if run.get("id") == run_id]
        self.assertTrue(
            matching, "la ejecucion %s no aparece en el historial de ejecuciones" % run_id,
        )
        listed = matching[0]
        self.assertEqual(run_id, listed.get("id"))
        self.assertEqual(ENVIRONMENT, listed.get("environment"))

        status, payload = self.get("/api/v1/diagnostics/runs/%s" % run_id, token)
        self.assertEqual(200, status, payload)
        detail = payload.get("run") or {}
        self.assertEqual(run_id, detail.get("id"))
        detail_findings = payload.get("findings") or []
        self.assertEqual(
            listed.get("checker_count"), len(detail_findings),
            "el detalle no devuelve los mismos comprobadores que el historial",
        )
        self.assertEqual(
            sorted(finding.get("id") for finding in type(self).findings),
            sorted(finding.get("id") for finding in detail_findings),
            "el detalle de la ejecucion no devuelve los mismos hallazgos",
        )

        status, payload = self.get("/api/v1/diagnostics/summary", token)
        self.assertEqual(200, status, payload)
        self.assertGreaterEqual(payload.get("runs_total") or 0, 1)
        self.assertGreaterEqual(
            payload.get("total_findings") or 0, len(detail_findings),
            "el resumen no refleja los hallazgos de la ejecucion",
        )

        # Una ejecucion que no existe se distingue con su propio codigo.
        status, payload = self.get("/api/v1/diagnostics/runs/RUN-NO-EXISTE", token)
        self.assertEqual(404, status, payload)
        self.assertEqual("DIAGNOSTIC_RUN_NOT_FOUND", payload.get("code"))

    def test_08_diagnostic_run_is_audited(self):
        """La ejecucion del diagnostico queda en la cadena de auditoria."""
        run_id = type(self).run_id
        self.assertTrue(run_id, "no hay ninguna ejecucion de diagnostico que comprobar")

        events = self.audit_events()
        matched = [
            event for event in events
            if event.get("action") == "DIAGNOSTIC_RUN" and event.get("status") == "ALLOWED"
        ]
        self.assertTrue(
            matched, "la ejecucion del diagnostico no queda en la cadena de auditoria",
        )
        self.assertTrue(
            any(run_id in str(event.get("details") or "") for event in matched),
            "el evento de auditoria no identifica la ejecucion %s" % run_id,
        )


class F2InventoryApiSuite(F2ApiSuite):
    """M3: inventario de activos del laboratorio sintetico f11-local."""

    # Activo de prueba compartido por los casos de escritura.
    asset = None

    ASSET_BODY = {
        "classification": "service",
        "criticality": "medium",
        "owner": TEST_ASSET_OWNER,
        "source": "manual",
        "version": "f2-suite",
        "description": "Activo sintetico del laboratorio f11-local creado por la suite de F2.",
        "synthetic": 1,
    }

    # ------------------------------------------------------------------ helpers

    def _asset_body(self, name, **overrides):
        body = dict(self.ASSET_BODY)
        body["name"] = name
        body.update(overrides)
        return body

    def _asset_by_name(self, token, name):
        status, payload = self.get("/api/v1/assets", token)
        self.assertEqual(200, status, payload)
        for asset in payload.get("assets") or []:
            if asset.get("name") == name:
                return asset
        self.fail("el activo de prueba %s no aparece en el inventario" % name)

    def _post_asset(self, token, name, **overrides):
        """Da de alta el activo de prueba y devuelve (asset, payload, creado).

        Si el nombre ya existe (la suite se repite) no se falla: se actualiza
        el activo existente y se sigue, para que el caso sea repetible.
        """
        body = self._asset_body(name, **overrides)
        status, payload = self.post("/api/v1/assets", body, token)
        if status == 409:
            self.assertEqual("ASSET_ALREADY_EXISTS", payload.get("code"), payload)
            existing = self._asset_by_name(token, name)
            status, payload = self.post("/api/v1/assets/%s" % existing["id"], body, token)
            self.assertEqual(200, status, payload)
            return payload["asset"], payload, False
        self.assertEqual(201, status, payload)
        return payload["asset"], payload, True

    def _ensure_asset(self, token):
        """Devuelve el activo de prueba, creandolo si todavia no existe."""
        asset = type(self).asset
        if asset is None:
            asset, _, _ = self._post_asset(
                token, "%sactivo-%d" % (TEST_ASSET_PREFIX, int(time.time())),
            )
            type(self).asset = asset
            return asset
        status, payload = self.get("/api/v1/assets/%s" % asset["id"], token)
        self.assertEqual(200, status, payload)
        return payload["asset"]

    @classmethod
    def tearDownClass(cls):
        """Deja el activo de prueba marcado como tal. No se borra: no hay endpoint."""
        asset = cls.asset
        if not asset:
            return
        try:
            credentials = json.loads(CREDENTIALS_FILE.read_text(encoding="utf-8"))
            token = admin_token(credentials, load_setup_realm())
            request = urllib.request.Request(
                BACKEND_URL + "/api/v1/assets/%s" % asset["id"],
                data=json.dumps({
                    "description": (
                        "Activo de prueba automatica de la suite F2 (%s). "
                        "No representa ningun activo real del hospital." % asset["id"]
                    ),
                    "owner": TEST_ASSET_OWNER,
                }).encode("utf-8"),
                headers={
                    "Authorization": "Bearer " + token,
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=30) as response:
                response.read()
        except Exception:  # noqa: BLE001 - la limpieza nunca debe romper la suite
            pass

    # ------------------------------------------------------------------ casos

    def test_09_any_authenticated_user_lists_the_inventory(self):
        """Cualquier identidad autenticada puede leer el inventario y su resumen."""
        token = self.token("recepcion.test")

        status, payload = self.get("/api/v1/assets", token)
        self.assertEqual(200, status, payload)
        self.assertEqual(ENVIRONMENT, payload.get("environment"))
        assets = payload.get("assets")
        self.assertIsInstance(assets, list)
        summary = payload.get("summary")
        self.assertIsInstance(summary, dict)
        for key in ("total", "by_classification", "by_criticality", "by_source"):
            self.assertIn(key, summary, "el resumen del inventario no trae la clave %s" % key)
        self.assertEqual(
            len(assets), summary.get("total"),
            "el resumen no coincide con el numero de activos listados",
        )

        status, payload = self.get("/api/v1/assets/summary", token)
        self.assertEqual(200, status, payload)
        self.assertEqual(ENVIRONMENT, payload.get("environment"))
        self.assertEqual(summary.get("total"), payload.get("summary", {}).get("total"))

    def test_10_auditor_reads_an_asset_with_its_evaluations(self):
        """El auditor lee el detalle de un activo y su historial de evaluaciones."""
        token = self.token("auditor.test")

        status, payload = self.get("/api/v1/assets", token)
        self.assertEqual(200, status, payload)
        assets = payload.get("assets") or []
        self.assertTrue(assets, "el inventario no tiene activos registrados")

        for asset in assets:
            self.assertIn(
                asset.get("classification"), ASSET_CLASSIFICATIONS, asset.get("name"),
            )
            self.assertIn(asset.get("criticality"), ASSET_CRITICALITIES, asset.get("name"))
            self.assertIn(asset.get("source"), ASSET_SOURCES, asset.get("name"))
            self.assertEqual(ENVIRONMENT, asset.get("environment"), asset.get("name"))

        target = assets[0]
        status, payload = self.get("/api/v1/assets/%s" % target["id"], token)
        self.assertEqual(200, status, payload)
        self.assertEqual(target["id"], payload.get("asset", {}).get("id"))
        evaluations = payload.get("evaluations")
        self.assertIsInstance(evaluations, list)
        for evaluation in evaluations:
            self.assertEqual(target["id"], evaluation.get("asset_id"))

        # Un activo que no existe se distingue con su propio codigo.
        status, payload = self.get("/api/v1/assets/AST-NO-EXISTE", token)
        self.assertEqual(404, status, payload)
        self.assertEqual("ASSET_NOT_FOUND", payload.get("code"))

    def test_11_auditor_cannot_create_an_asset(self):
        """El Oficial de Seguridad no puede dar de alta activos en el inventario."""
        token = self.token("auditor.test")
        name = "%sauditor-%d" % (TEST_ASSET_PREFIX, int(time.time()))
        status, payload = self.post("/api/v1/assets", self._asset_body(name), token)
        self.assertEqual(403, status, payload)
        self.assertIn(
            payload.get("code"),
            ("PLATFORM_ADMIN_ROLE_REQUIRED", "MFA_AUTHENTICATION_REQUIRED"),
            "el rechazo por rol o por MFA no trae un codigo reconocible",
        )
        message = str(payload.get("message") or "").lower()
        self.assertTrue(
            any(word in message for word in ("plataforma", "administrador", "rol", "mfa")),
            "el mensaje del rechazo no menciona el rol ni la MFA: %s" % payload.get("message"),
        )

        # Un rechazo por rol no deja activos huerfanos en el inventario.
        status, listing = self.get("/api/v1/assets", token)
        self.assertEqual(200, status, listing)
        names = [asset.get("name") for asset in listing.get("assets") or []]
        self.assertNotIn(name, names, "el rechazo dejo el activo creado")

    def test_12_admin_without_mfa_cannot_create_an_asset(self):
        """El administrador con rol pero sin OTP recibe 403 por MFA al dar de alta."""
        token = self.token("medico.sinmfa", totp_secret=None)
        name = "%ssinmfa-%d" % (TEST_ASSET_PREFIX, int(time.time()))
        status, payload = self.post("/api/v1/assets", self._asset_body(name), token)
        self.assertEqual(403, status, payload)
        self.assertEqual("MFA_AUTHENTICATION_REQUIRED", payload.get("code"))

        status, listing = self.get("/api/v1/assets", token)
        self.assertEqual(200, status, listing)
        names = [asset.get("name") for asset in listing.get("assets") or []]
        self.assertNotIn(name, names, "el rechazo por MFA dejo el activo creado")

    def test_13_admin_with_mfa_creates_a_synthetic_asset(self):
        """El administrador con MFA da de alta un activo sintetico del laboratorio."""
        token = self.token("medico.test")
        name = "%sactivo-%d" % (TEST_ASSET_PREFIX, int(time.time()))

        asset, payload, created = self._post_asset(token, name)
        if created:
            self.assertEqual(1, asset.get("revision"), payload)
        else:
            self.assertGreaterEqual(
                asset.get("revision") or 0, 1,
                "el activo ya existente deberia conservar su revision",
            )

        self.assertEqual(name, asset.get("name"))
        self.assertIn(asset.get("classification"), ASSET_CLASSIFICATIONS, payload)
        self.assertIn(asset.get("criticality"), ASSET_CRITICALITIES, payload)
        self.assertIn(asset.get("source"), ASSET_SOURCES, payload)
        self.assertEqual(TEST_ASSET_OWNER, asset.get("owner"), payload)
        self.assertEqual(ENVIRONMENT, asset.get("environment"), payload)
        self.assertEqual(1, asset.get("synthetic"), payload)
        self.assertEqual(ENVIRONMENT, payload.get("environment"))

        type(self).asset = asset

    def test_14_duplicate_asset_is_rejected(self):
        """Un activo duplicado se rechaza con conflicto y no duplica la fila."""
        token = self.token("medico.test")
        name = "%sduplicado-%d" % (TEST_ASSET_PREFIX, int(time.time()))

        status, payload = self.post("/api/v1/assets", self._asset_body(name), token)
        self.assertEqual(201, status, payload)
        first_id = payload["asset"]["id"]

        status, payload = self.post("/api/v1/assets", self._asset_body(name), token)
        self.assertEqual(409, status, payload)
        self.assertEqual("ASSET_ALREADY_EXISTS", payload.get("code"))

        status, listing = self.get("/api/v1/assets", token)
        self.assertEqual(200, status, listing)
        matching = [
            asset for asset in listing.get("assets") or [] if asset.get("name") == name
        ]
        self.assertEqual(1, len(matching), "el duplicado se guardo dos veces")
        self.assertEqual(first_id, matching[0]["id"])

    def test_15_invalid_asset_is_rejected_with_the_field_map(self):
        """Un activo con datos fuera del vocabulario se rechaza campo a campo."""
        token = self.token("medico.test")
        name = "%sinvalido-%d" % (TEST_ASSET_PREFIX, int(time.time()))

        status, payload = self.post(
            "/api/v1/assets",
            self._asset_body(name, classification="hardware"),
            token,
        )
        self.assertEqual(400, status, payload)
        self.assertEqual("ASSET_INVALID", payload.get("code"), payload)
        self.assertIn("error", payload)
        self.assertIn("message", payload)
        fields = payload.get("fields")
        self.assertIsInstance(fields, dict, payload)
        self.assertIn(
            "classification", fields,
            "el mapa de errores no senala el campo erroneo: %s" % fields,
        )

        # El rechazo no deja nada en el inventario.
        status, listing = self.get("/api/v1/assets", token)
        self.assertEqual(200, status, listing)
        names = [asset.get("name") for asset in listing.get("assets") or []]
        self.assertNotIn(name, names, "el activo invalido se guardo")

    def test_16_update_increments_revision_and_is_audited(self):
        """Actualizar un activo incrementa su revision y queda auditado."""
        token = self.token("medico.test")
        asset = self._ensure_asset(token)
        before = int(asset.get("revision") or 0)

        status, payload = self.post(
            "/api/v1/assets/%s" % asset["id"],
            {
                "criticality": "high",
                "description": "Activo de prueba de F2 revisado en %d." % int(time.time()),
            },
            token,
        )
        self.assertEqual(200, status, payload)
        updated = payload.get("asset") or {}
        self.assertEqual(asset["id"], updated.get("id"))
        self.assertEqual(
            before + 1, updated.get("revision"),
            "la actualizacion no incrementa la revision del activo",
        )
        self.assertEqual("high", updated.get("criticality"))
        type(self).asset = updated

        events = self.audit_events()
        matched = [
            event for event in events
            if event.get("action") == "ASSET_UPDATE" and event.get("status") == "ALLOWED"
        ]
        self.assertTrue(
            matched, "la actualizacion del activo no queda en la cadena de auditoria",
        )
        self.assertTrue(
            any(asset.get("name") in str(event.get("details") or "") for event in matched),
            "el evento de auditoria no identifica el activo %s" % asset.get("name"),
        )

    def test_17_asset_evaluation_is_recorded(self):
        """Una evaluacion de criticidad se guarda y aparece en el historial."""
        token = self.token("medico.test")
        asset = self._ensure_asset(token)

        status, payload = self.post(
            "/api/v1/assets/%s/evaluations" % asset["id"],
            {
                "criticality": "medium",
                "notes": (
                    "Evaluacion registrada por la suite de API de F2 sobre el "
                    "laboratorio sintetico f11-local."
                ),
            },
            token,
        )
        self.assertEqual(201, status, payload)
        evaluation = payload.get("evaluation") or {}
        self.assertTrue(evaluation.get("id"), payload)
        self.assertEqual(asset["id"], evaluation.get("asset_id"))
        self.assertEqual("medico.test", evaluation.get("evaluated_by"))
        self.assertIn(evaluation.get("criticality"), ASSET_CRITICALITIES)
        self.assertIsInstance(evaluation.get("findings_count"), int)
        self.assertGreaterEqual(evaluation.get("findings_count") or 0, 0)
        self.assertTrue(str(evaluation.get("notes") or "").strip())

        status, payload = self.get("/api/v1/assets/%s" % asset["id"], token)
        self.assertEqual(200, status, payload)
        evaluations = payload.get("evaluations") or []
        ids = [item.get("id") for item in evaluations]
        self.assertIn(
            evaluation.get("id"), ids,
            "la evaluacion no aparece en el historial de evaluaciones del activo",
        )
        stored = next(item for item in evaluations if item.get("id") == evaluation.get("id"))
        self.assertEqual("medico.test", stored.get("evaluated_by"))
        self.assertEqual(asset["id"], stored.get("asset_id"))

    def test_18_audit_chain_remains_valid_after_f2_operations(self):
        """La cadena de auditoria sigue encadenando tras todas las operaciones de F2."""
        payload = self.audit_payload()
        self.assertTrue(
            payload.get("audit_chain_valid"),
            "la plataforma declara la cadena de auditoria invalida: %s" % payload.get("chain_error"),
        )
        events = events_of(payload)
        self.assertTrue(events, "la cadena de auditoria esta vacia")

        # Recalculo del encadenamiento tal y como lo hace verify_audit_chain
        # en backend/server.py: el hash de cada evento encadena con el anterior.
        expected_prev = "0" * 64
        for event in events:
            record = {key: value for key, value in event.items() if key != "hash"}
            digest = hashlib.sha256(
                json.dumps(record, sort_keys=True).encode("utf-8")
            ).hexdigest()
            self.assertEqual(
                expected_prev, event.get("prev_hash"),
                "ruptura de cadena en el evento %s" % event.get("action"),
            )
            self.assertEqual(
                digest, event.get("hash"),
                "el hash del evento %s no recalcula sobre su propio contenido" % event.get("action"),
            )
            expected_prev = digest

        actions = {event.get("action") for event in events}
        expected_actions = ["ASSET_CREATE", "ASSET_UPDATE", "ASSET_EVALUATE"]
        if F2DiagnosticsApiSuite.run_id:
            # La suite de diagnostico ya dejo una ejecucion: tambien debe estar.
            expected_actions.append("DIAGNOSTIC_RUN")
        for action in expected_actions:
            self.assertIn(
                action, actions,
                "la accion %s de F2 no queda en la cadena de auditoria" % action,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
