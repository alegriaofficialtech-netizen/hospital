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
import copy
import json
import os
import sys
import tempfile
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
# identificado como dato de prueba sintetico del laboratorio. Cada caso usa un
# nombre fijo con este prefijo para que la suite sea idempotente.
TEST_ASSET_OWNER = "prueba-automatica"

# Catalogo semilla del inventario (backend/asset_inventory.py SEED_CATALOG).
# Los nombres son parte del contrato de F2: la suite comprueba que la siembra
# del arranque no duplica ninguno de ellos.
SEED_ASSET_NAMES = (
    "keycloak-iam",
    "keycloak-realm-hospital-lab",
    "oidc-client-clinical-poc",
    "keycloak-theme-hospital-lab",
    "backend-api",
    "frontend-caddy",
    "frontend-angular-bundle",
    "clinical-sqlite-db",
    "audit-chain",
    "compose-f11",
    "api-test-suite",
)

# Accion de auditoria con la que la siembra del inventario queda auditada.
SEED_AUDIT_ACTION = "ASSET_SEED"

# Acciones sensibles que el backend declara con require_mfa y que ademas estan
# en HUMAN_ONLY_ACTIONS (backend/jwt_validator.py).
SENSITIVE_ACTIONS = ("MANAGE_IDENTITIES", "RUN_DIAGNOSTICS", "MANAGE_ASSETS")

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
    """True si el token emitido acredita el segundo factor con el criterio del backend.

    Alineado con la plataforma: ``amr`` debe ser una lista de metodos y solo
    cuentan ``otp``, ``totp`` o ``mfa-otp``. Un ``amr`` escalar y el claim
    ``acr`` no acreditan MFA por si solos. El arnes puede producir falsos
    negativos, pero nunca acepta un token que el backend rechazaria.
    """
    claims = result.get("claims") or {}
    amr = claims.get("amr")
    if not isinstance(amr, list):
        return False
    return any(
        isinstance(method, str) and method.strip().lower() in ("otp", "totp", "mfa-otp")
        for method in amr
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

    def post_raw(self, token, path, raw, timeout=30):
        """Envia un cuerpo tal cual, sin serializarlo: permite probar JSON roto."""
        data = raw.encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(
            BACKEND_URL + path, data=data, headers=headers, method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as exc:
            raw_body = exc.read()
            try:
                return exc.code, json.loads(raw_body or b"{}")
            except json.JSONDecodeError:
                return exc.code, {"raw": raw_body.decode("utf-8", "replace")}

    def audit_payload(self):
        """Lee la cadena de auditoria con el Oficial de Seguridad."""
        status, payload = self.call(
            self.token("auditor.test"), "GET", "/api/v1/audit/events",
        )
        self.assertEqual(200, status, f"no se pudo leer la auditoria: {payload}")
        return payload

    def audit_events(self):
        return events_of(self.audit_payload())

    # ------------------------------------------------------------------ activos
    # Un unico cuerpo base y helpers de alta idempotente: la suite reutiliza un
    # nombre fijo por caso, de modo que una segunda ejecucion actualiza el
    # activo vigente en lugar de acumular filas nuevas en el inventario.

    ASSET_BODY = {
        "classification": "service",
        "criticality": "medium",
        "owner": TEST_ASSET_OWNER,
        "source": "manual",
        "version": "f2-suite",
        "description": "Activo sintetico del laboratorio f11-local creado por la suite de F2.",
        "synthetic": 1,
    }

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

    def _ensure_asset_named(self, token, name, **overrides):
        """Alta idempotente por nombre fijo: crea o actualiza, nunca duplica."""
        asset, _payload, _created = self._post_asset(token, name, **overrides)
        return asset


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

    # ------------------------------------------------------------------ helpers

    def _ensure_asset(self, token):
        """Devuelve el activo de prueba, creandolo si todavia no existe."""
        asset = type(self).asset
        if asset is None:
            asset = self._ensure_asset_named(token, "prueba-f2-activo")
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
        name = "prueba-f2-rechazo-auditor"
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
        name = "prueba-f2-rechazo-sinmfa"
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
        name = "prueba-f2-alta"

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
        name = "prueba-f2-duplicado"

        # Alta idempotente: si ya existe de una ejecucion anterior se actualiza,
        # de modo que el caso no acumula filas nuevas.
        first, _payload, _created = self._post_asset(token, name)
        first_id = first["id"]

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
        name = "prueba-f2-invalido"

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


class F2CorrectionsApiSuite(F2ApiSuite):
    """Correcciones de la revision independiente del trabajo F2.

    Cada caso fija una correccion concreta: la siembra auditada, la seleccion
    de comprobadores, los rechazos con evento en la cadena, el comprobador de
    MFA, el cuerpo JSON que no es un objeto y la validacion del nombre en la
    capa de persistencia.
    """

    # ------------------------------------------------------------------ helpers

    def _new_events(self, before):
        """Devuelve los eventos de auditoria anadidos despues de la lectura inicial."""
        return self.audit_events()[len(before):]

    def _database_module(self):
        """Importa backend/database.py del repositorio (sin efectos al importar)."""
        backend_dir = str(ROOT / "backend")
        if backend_dir not in sys.path:
            sys.path.insert(0, backend_dir)
        import database
        return database

    # ------------------------------------------------------------------ casos

    def test_19_seed_is_audited_and_does_not_duplicate_assets(self):
        """La siembra del inventario queda auditada una sola vez y no duplica activos."""
        events = self.audit_events()
        seeds = [event for event in events if event.get("action") == SEED_AUDIT_ACTION]
        self.assertEqual(
            1, len(seeds),
            "la siembra del inventario debe quedar auditada una sola vez, no %d veces"
            % len(seeds),
        )
        seed = seeds[0]
        self.assertEqual("SYSTEM", seed.get("actor"), seed)
        self.assertEqual("ALLOWED", seed.get("status"), seed)
        self.assertIn("activos", str(seed.get("details") or ""), seed)

        status, payload = self.get("/api/v1/assets", self.token("auditor.test"))
        self.assertEqual(200, status, payload)
        assets = payload.get("assets") or []
        for name in SEED_ASSET_NAMES:
            matching = [asset for asset in assets if asset.get("name") == name]
            self.assertEqual(
                1, len(matching),
                "el activo sembrado %s aparece %d veces en el inventario"
                % (name, len(matching)),
            )

    def test_20_checker_ids_selects_exactly_what_was_requested(self):
        """checker_ids vacio no ejecuta nada, uno ejecuta solo ese y null el catalogo."""
        token = self.token("medico.test")

        status, catalog_payload = self.get(
            "/api/v1/diagnostics/checkers", self.token("auditor.test"),
        )
        self.assertEqual(200, status, catalog_payload)
        catalog_ids = [checker["id"] for checker in catalog_payload.get("checkers") or []]
        self.assertTrue(catalog_ids, "el catalogo de comprobadores viene vacio")

        # Una lista vacia significa "ningun comprobador", no "el catalogo".
        status, payload = self.post(
            "/api/v1/diagnostics/runs", {"checker_ids": []}, token, timeout=120,
        )
        self.assertEqual(201, status, payload)
        self.assertEqual(0, (payload.get("run") or {}).get("checker_count"), payload)
        self.assertEqual([], payload.get("findings"), payload)

        # Una lista con un solo identificador ejecuta solo ese comprobador.
        only = catalog_ids[0]
        status, payload = self.post(
            "/api/v1/diagnostics/runs", {"checker_ids": [only]}, token, timeout=120,
        )
        self.assertEqual(201, status, payload)
        self.assertEqual(1, (payload.get("run") or {}).get("checker_count"), payload)
        self.assertEqual(
            [only],
            [finding.get("checker_id") for finding in payload.get("findings") or []],
            payload,
        )

        # null significa "el catalogo completo".
        status, payload = self.post(
            "/api/v1/diagnostics/runs", {"checker_ids": None}, token, timeout=300,
        )
        self.assertEqual(201, status, payload)
        self.assertEqual(
            len(catalog_ids), (payload.get("run") or {}).get("checker_count"), payload,
        )
        self.assertEqual(
            sorted(catalog_ids),
            sorted(finding.get("checker_id") for finding in payload.get("findings") or []),
            payload,
        )

    def test_21_validation_and_duplicate_rejections_are_audited(self):
        """Un rechazo por validacion y un rechazo por duplicado dejan evento."""
        token = self.token("medico.test")
        name = "prueba-f2-auditado"

        before = self.audit_events()
        status, payload = self.post(
            "/api/v1/assets",
            self._asset_body(name, classification="hardware"),
            token,
        )
        self.assertEqual(400, status, payload)
        new_events = self._new_events(before)
        self.assertTrue(
            any(
                event.get("action") == "ASSET_CREATE"
                and event.get("status") == "DENIED_INVALID"
                for event in new_events
            ),
            "el rechazo por validacion no deja evento en la cadena: %s" % new_events,
        )

        # La primera escritura del caso es idempotente: si el activo ya existe
        # de una ejecucion anterior, se actualiza en lugar de acumular otro.
        self._ensure_asset_named(token, name)

        before = self.audit_events()
        status, payload = self.post("/api/v1/assets", self._asset_body(name), token)
        self.assertEqual(409, status, payload)
        self.assertEqual("ASSET_ALREADY_EXISTS", payload.get("code"))
        new_events = self._new_events(before)
        self.assertTrue(
            any(
                event.get("action") == "ASSET_CREATE"
                and event.get("status") == "DENIED_DUPLICATE"
                for event in new_events
            ),
            "el rechazo por duplicado no deja evento en la cadena: %s" % new_events,
        )

    def test_22_mfa_checker_detects_a_sensitive_action_without_mfa(self):
        """Una accion sensible sin MFA o fuera de HUMAN_ONLY hace fallar al comprobador.

        La prueba es negativa: no se conforma con que el comprobador imprima la
        lista que vigila (eso se cumpliria solo). Se manipula una copia en
        memoria de la tabla de permisos del modulo importado y se demuestra que
        el comprobador devuelve ``failed`` cuando la politica se debilita. El
        fichero ``backend/jwt_validator.py`` no se toca y la tabla se restaura.
        """
        token = self.token("medico.test")
        status, payload = self.post(
            "/api/v1/diagnostics/runs",
            {"checker_ids": ["BACKEND_ADMIN_REQUIRES_MFA"]},
            token, timeout=120,
        )
        self.assertEqual(201, status, payload)
        findings = payload.get("findings") or []
        self.assertEqual(1, len(findings), payload)
        finding = findings[0]
        self.assertEqual("BACKEND_ADMIN_REQUIRES_MFA", finding.get("checker_id"))
        self.assertEqual(
            "passed", finding.get("status"),
            "el comprobador de MFA no pasa: %s" % finding.get("evidence_output"),
        )
        output = str(finding.get("evidence_output") or "")
        for action in SENSITIVE_ACTIONS:
            self.assertIn(action, output, "la evidencia no menciona la accion %s" % action)
        self.assertIn("HUMAN_ONLY_ACTIONS", output)
        # El comando de evidencia describe la operacion real: no cita un
        # comando que no llega a ejecutarse.
        self.assertNotIn("python3 -c", str(finding.get("evidence_command") or ""))

        backend_dir = str(ROOT / "backend")
        if backend_dir not in sys.path:
            sys.path.insert(0, backend_dir)
        import jwt_validator
        import security_diagnostics

        # La tabla real sigue diciendo lo que el comprobador declara.
        for action in SENSITIVE_ACTIONS:
            policy = jwt_validator.CLINICAL_PERMISSIONS.get(action)
            self.assertIsNotNone(
                policy, "el backend no declara la accion sensible %s" % action,
            )
            self.assertIs(
                True, policy.get("require_mfa"),
                "la politica de %s no exige MFA acreditada" % action,
            )
            self.assertIn(
                action, jwt_validator.HUMAN_ONLY_ACTIONS,
                "la accion %s no esta en HUMAN_ONLY_ACTIONS: una cuenta de servicio "
                "podria ejecutarla" % action,
            )

        original_permissions = security_diagnostics.CLINICAL_PERMISSIONS
        original_human_only = security_diagnostics.HUMAN_ONLY_ACTIONS
        try:
            # Escenario 1: una accion sensible pierde require_mfa.
            permissions = copy.deepcopy(original_permissions)
            permissions["MANAGE_ASSETS"]["require_mfa"] = False
            security_diagnostics.CLINICAL_PERMISSIONS = permissions
            result = security_diagnostics.check_backend_admin_requires_mfa()
            self.assertEqual(
                "failed", result.status,
                "el comprobador no detecta una accion sensible sin MFA",
            )
            self.assertIn("MANAGE_ASSETS", result.evidence_output)

            # Escenario 2: una accion sensible sale de HUMAN_ONLY_ACTIONS.
            security_diagnostics.CLINICAL_PERMISSIONS = copy.deepcopy(
                original_permissions
            )
            security_diagnostics.HUMAN_ONLY_ACTIONS = set(original_human_only) - {
                "MANAGE_IDENTITIES"
            }
            result = security_diagnostics.check_backend_admin_requires_mfa()
            self.assertEqual(
                "failed", result.status,
                "el comprobador no detecta una accion sensible fuera de HUMAN_ONLY_ACTIONS",
            )
            self.assertIn("MANAGE_IDENTITIES", result.evidence_output)
        finally:
            security_diagnostics.CLINICAL_PERMISSIONS = original_permissions
            security_diagnostics.HUMAN_ONLY_ACTIONS = original_human_only

    def test_23_malformed_or_non_object_json_body_is_rejected_with_400(self):
        """Un cuerpo JSON roto o que no es objeto responde 400 y no ejecuta nada."""
        token = self.token("medico.test")
        asset = self._ensure_asset_named(token, "prueba-f2-json")
        paths = (
            "/api/v1/assets",
            "/api/v1/assets/%s" % asset["id"],
            "/api/v1/assets/%s/evaluations" % asset["id"],
            "/api/v1/diagnostics/runs",
        )

        status, summary_before = self.get(
            "/api/v1/diagnostics/summary", self.token("auditor.test"),
        )
        self.assertEqual(200, status, summary_before)
        runs_before = summary_before.get("runs_total")

        for path in paths:
            # JSON que no parsea: antes acababa en payload={} y, en
            # /diagnostics/runs, disparaba el catalogo completo.
            status, payload = self.post_raw(token, path, '{"checker_ids":')
            self.assertEqual(400, status, "%s -> %s" % (path, payload))
            self.assertEqual("INVALID_JSON_BODY", payload.get("code"), payload)
            for key in ("error", "message", "code"):
                self.assertIn(key, payload, payload)

            # JSON valido que no es un objeto.
            status, payload = self.post(path, [], token)
            self.assertEqual(400, status, "%s -> %s" % (path, payload))
            self.assertEqual("INVALID_JSON_BODY", payload.get("code"), payload)
            for key in ("error", "message", "code"):
                self.assertIn(key, payload, payload)

        # Ningun cuerpo roto ejecuto comprobadores ni creo una ejecucion.
        status, summary_after = self.get(
            "/api/v1/diagnostics/summary", self.token("auditor.test"),
        )
        self.assertEqual(200, status, summary_after)
        self.assertEqual(
            runs_before, summary_after.get("runs_total"),
            "un cuerpo JSON roto ejecuto el diagnostico",
        )

    def test_24_persistence_layer_rejects_invalid_asset_names(self):
        """La capa de persistencia aplica la misma regla de nombre que la API."""
        database = self._database_module()
        self.assertIsNotNone(database, "no se pudo importar backend/database.py")

        with tempfile.TemporaryDirectory(prefix="f11-f2-persistencia-") as tmp:
            manager = database.ClinicalDatabaseManager(db_path=os.path.join(tmp, "lis.db"))
            try:
                base = {
                    "id": "AST-PRUEBA-F2",
                    "classification": "service",
                    "criticality": "medium",
                    "owner": TEST_ASSET_OWNER,
                    "source": "manual",
                    "version": "f2-suite",
                    "environment": ENVIRONMENT,
                    "synthetic": 1,
                    "description": "Activo de prueba de la capa de persistencia.",
                }
                invalid_names = (
                    "activo con espacios",
                    'activo"con"comillas',
                    "activo\ncon\ncontrol",
                    "ab",
                    "x" * 81,
                )
                for invalid_name in invalid_names:
                    payload = dict(base)
                    payload["name"] = invalid_name
                    with self.assertRaises(database.AssetValidationError):
                        manager.insert_asset(payload)

                # Un nombre valido si se escribe: la regla no cierra mas de lo
                # que debe.
                payload = dict(base)
                payload["name"] = "prueba-f2-persistencia"
                stored = manager.insert_asset(payload)
                self.assertEqual("prueba-f2-persistencia", stored.get("name"))
            finally:
                manager.close()


    def test_25_every_finding_records_the_origin_of_its_evidence(self):
        """Cada hallazgo declara de que mecanismo real salio su evidencia."""
        token = self.token("medico.test")
        status, payload = self.post(
            "/api/v1/diagnostics/runs", {"checker_ids": None}, token, timeout=180,
        )
        self.assertEqual(201, status, payload)
        findings = payload.get("findings") or []
        self.assertTrue(findings, "la ejecucion no produjo hallazgos")

        origenes = {
            "keycloak_admin_api", "filesystem", "sqlite", "docker_inspect",
            "docker_exec", "in_process",
        }
        # El centinela de omision no es un origen valido: si un comprobador no
        # declara de donde salio su evidencia, la prueba debe fallar en vez de
        # aceptarlo como si fuera ``in_process``.
        self.assertNotIn(
            "undeclared", origenes,
            "el centinela de origen no declarado no puede ser un origen valido",
        )
        for finding in findings:
            origen = finding.get("evidence_source")
            self.assertNotEqual(
                "undeclared", origen,
                "el comprobador %s no declara el origen de su evidencia"
                % finding.get("checker_id"),
            )
            self.assertIn(
                origen, origenes,
                "el hallazgo %s no declara un origen de evidencia valido: %r"
                % (finding.get("checker_id"), origen),
            )
            self.assertTrue(
                str(finding.get("evidence_command") or "").strip(),
                "el hallazgo %s no conserva la operacion que lo produjo"
                % finding.get("checker_id"),
            )
            self.assertTrue(
                str(finding.get("evidence_output") or "").strip(),
                "el hallazgo %s no conserva el resultado de esa operacion"
                % finding.get("checker_id"),
            )
            self.assertIsNotNone(
                finding.get("detected_at"),
                "el hallazgo %s no registra cuando se detecto" % finding.get("checker_id"),
            )

        # El origen declarado tiene que corresponder al mecanismo real de cada
        # comprobador: validar solo el vocabulario no detecta un mapeo erroneo.
        by_checker = {
            finding.get("checker_id"): finding.get("evidence_source")
            for finding in findings
        }
        fixed_mechanisms = {
            "BACKEND_ADMIN_REQUIRES_MFA": "in_process",
            "BACKEND_AUDIT_CHAIN_VALID": "sqlite",
            "BACKEND_AUDIT_CHECKPOINT_CONSISTENT": "sqlite",
            "BACKEND_AUTH_DELEGATED_TO_KEYCLOAK": "filesystem",
            "CONTAINER_HARDENING": "docker_inspect",
            "DATA_FILES_OWNER_ONLY": "filesystem",
        }
        for checker_id, expected in fixed_mechanisms.items():
            self.assertEqual(
                expected, by_checker.get(checker_id),
                "el comprobador %s declara un origen que no es el suyo (%r)"
                % (checker_id, by_checker.get(checker_id)),
            )
        for checker_id, origen in by_checker.items():
            if str(checker_id).startswith("KC_"):
                self.assertEqual(
                    "keycloak_admin_api", origen,
                    "el comprobador %s no declara la API de Keycloak" % checker_id,
                )

        # El bundle Angular es el unico con dos mecanismos posibles: debe
        # declarar el que de verdad produjo la evidencia en esta ejecucion.
        bundle_dir = ROOT / "frontend" / ".f11-dist" / "browser"
        expected_bundle = "filesystem" if bundle_dir.is_dir() else "docker_exec"
        self.assertEqual(
            expected_bundle, by_checker.get("FRONTEND_BUNDLE_HAS_NO_PASSWORD_FIELD"),
            "el comprobador del bundle no declara el mecanismo que ejecuto",
        )

    def test_26_seed_runs_clean_and_is_idempotent_on_an_empty_database(self):
        """La siembra crea los 11 activos y su unico ASSET_SEED en una base limpia."""
        database = self._database_module()
        backend_dir = str(ROOT / "backend")
        if backend_dir not in sys.path:
            sys.path.insert(0, backend_dir)
        import asset_inventory

        with tempfile.TemporaryDirectory(prefix="f11-f2-siembra-") as tmp:
            manager = database.ClinicalDatabaseManager(
                db_path=os.path.join(tmp, "lis.db")
            )
            try:
                first = asset_inventory.seed_catalog(manager)
                self.assertFalse(first.get("already_seeded"), first)
                self.assertEqual(11, len(first.get("created") or []), first)
                self.assertEqual(11, len(asset_inventory.SEED_CATALOG))

                assets = manager.list_assets()
                self.assertEqual(11, len(assets), "la siembra no creo los 11 activos")
                self.assertEqual(
                    set(SEED_ASSET_NAMES), {asset["name"] for asset in assets},
                    "la siembra no escribio exactamente el catalogo semilla",
                )

                events = [
                    event for event in manager.get_audit_events()
                    if event.get("action") == SEED_AUDIT_ACTION
                ]
                self.assertEqual(1, len(events), "la siembra no dejo un unico evento")
                seed = events[0]
                self.assertEqual("SYSTEM", seed.get("actor"), seed)
                self.assertEqual("ALLOWED", seed.get("status"), seed)
                self.assertIn("11 activos creados", str(seed.get("details") or ""))
                self.assertIn("0 ya existentes", str(seed.get("details") or ""))

                # Segunda ejecucion: no crea ni audita de nuevo.
                second = asset_inventory.seed_catalog(manager)
                self.assertTrue(second.get("already_seeded"), second)
                self.assertEqual([], second.get("created"), second)
                self.assertEqual(
                    11, len(manager.list_assets()),
                    "la segunda siembra duplico activos",
                )
                self.assertEqual(
                    1,
                    manager.count_audit_events_by_action(SEED_AUDIT_ACTION),
                    "la segunda siembra volvio a auditar",
                )
            finally:
                manager.close()

    def test_27_asset_write_and_its_audit_event_commit_together(self):
        """Si la auditoria falla, la transaccion revierte el activo completo."""
        database = self._database_module()

        with tempfile.TemporaryDirectory(prefix="f11-f2-atomico-") as tmp:
            manager = database.ClinicalDatabaseManager(
                db_path=os.path.join(tmp, "lis.db")
            )
            original_insert = manager._insert_audit_event

            def failing_audit(cur, **kwargs):
                raise database.DatabaseError("fallo de auditoria simulado en la prueba")

            base = {
                "id": "AST-PRUEBA-ATOMICA",
                "name": "prueba-f2-atomico",
                "classification": "service",
                "criticality": "medium",
                "owner": TEST_ASSET_OWNER,
                "source": "manual",
                "version": "f2-suite",
                "environment": ENVIRONMENT,
                "synthetic": 1,
                "description": "Activo de prueba de atomicidad de la transaccion.",
            }
            audit_event = {
                "action": "ASSET_CREATE",
                "actor": "medico.test",
                "role": "['ROLE_PLATFORM_ADMIN']",
                "status": "ALLOWED",
                "details": "Activo de prueba atomico",
                "ip": "127.0.0.1",
                "mfa_verified": True,
            }
            try:
                manager._insert_audit_event = failing_audit
                with self.assertRaises(database.DatabaseError):
                    manager.insert_asset_with_audit_event(dict(base), dict(audit_event))

                self.assertEqual(
                    [], manager.list_assets(),
                    "la transaccion no revirtio el activo cuando fallo la auditoria",
                )
                self.assertEqual(
                    0, manager.count_audit_events_by_action("ASSET_CREATE"),
                    "la transaccion dejo un evento de auditoria con la escritura revertida",
                )

                # Con la auditoria restaurada, la misma operacion confirma las dos.
                manager._insert_audit_event = original_insert
                asset, record = manager.insert_asset_with_audit_event(
                    dict(base), dict(audit_event),
                )
                self.assertEqual("prueba-f2-atomico", asset.get("name"))
                self.assertEqual("ASSET_CREATE", record.get("action"))
                self.assertEqual(1, len(manager.list_assets()))
                self.assertEqual(
                    1, manager.count_audit_events_by_action("ASSET_CREATE")
                )

                # La actualizacion sigue la misma regla: si la auditoria falla,
                # la revision no avanza.
                manager._insert_audit_event = failing_audit
                with self.assertRaises(database.DatabaseError):
                    manager.update_asset_with_audit_event(
                        "AST-PRUEBA-ATOMICA",
                        {"criticality": "high"},
                        dict(audit_event),
                    )
                current = manager.get_asset("AST-PRUEBA-ATOMICA")
                self.assertEqual(1, int(current.get("revision") or 0))
                self.assertEqual("medium", current.get("criticality"))
            finally:
                manager._insert_audit_event = original_insert
                manager.close()

    def test_28_diagnostic_run_and_its_audit_event_commit_together(self):
        """Si la auditoria falla, no quedan ni la ejecucion ni sus hallazgos."""
        database = self._database_module()

        with tempfile.TemporaryDirectory(prefix="f11-f2-run-atomico-") as tmp:
            manager = database.ClinicalDatabaseManager(
                db_path=os.path.join(tmp, "lis.db")
            )
            original_insert = manager._insert_audit_event
            run_id = "RUN-PRUEBA-ATOMICA"

            def failing_audit(cur, **kwargs):
                raise database.DatabaseError("fallo de auditoria simulado en la prueba")

            run = {
                "id": run_id,
                "started_at": 1700000000.0,
                "finished_at": 1700000005.0,
                "status": "completed",
                "checker_count": 2,
                "passed": 1,
                "failed": 1,
                "warnings": 0,
                "triggered_by": "medico.test",
                "environment": ENVIRONMENT,
                "notes": "Ejecucion de prueba de atomicidad.",
            }
            findings = [
                {
                    "id": "FND-PRUEBA-ATOMICA-1",
                    "run_id": run_id,
                    "checker_id": "BACKEND_AUDIT_CHAIN_VALID",
                    "title": "Cadena de auditoria valida",
                    "objective": "O2",
                    "severity": "high",
                    "status": "passed",
                    "asset_ref": "backend",
                    "evidence_command": "verificar cadena",
                    "evidence_output": "cadena valida",
                    "evidence_source": "sqlite",
                    "remediation": "ninguna",
                    "detected_at": 1700000005.0,
                },
                {
                    "id": "FND-PRUEBA-ATOMICA-2",
                    "run_id": run_id,
                    "checker_id": "DATA_FILES_OWNER_ONLY",
                    "title": "Ficheros de datos con permisos del propietario",
                    "objective": "O2",
                    "severity": "medium",
                    "status": "failed",
                    "asset_ref": "backend",
                    "evidence_command": "revisar permisos",
                    "evidence_output": "permisos amplios",
                    "evidence_source": "filesystem",
                    "remediation": "restringir permisos",
                    "detected_at": 1700000005.0,
                },
            ]
            audit_event = {
                "action": "DIAGNOSTIC_RUN",
                "actor": "medico.test",
                "role": "['ROLE_PLATFORM_ADMIN']",
                "status": "ALLOWED",
                "details": "Ejecucion de prueba atomica",
                "ip": "127.0.0.1",
                "mfa_verified": True,
            }
            try:
                manager._insert_audit_event = failing_audit
                with self.assertRaises(database.DatabaseError):
                    manager.insert_diagnostic_run_with_findings_and_audit_event(
                        dict(run), [dict(finding) for finding in findings], dict(audit_event),
                    )

                self.assertIsNone(
                    manager.get_diagnostic_run(run_id),
                    "la transaccion no revirtio la ejecucion cuando fallo la auditoria",
                )
                self.assertEqual(
                    [], manager.list_security_findings(run_id=run_id),
                    "la transaccion no revirtio los hallazgos cuando fallo la auditoria",
                )
                self.assertEqual(
                    0, manager.count_audit_events_by_action("DIAGNOSTIC_RUN"),
                    "la transaccion dejo un evento con la ejecucion revertida",
                )

                # Con la auditoria restaurada, la misma operacion confirma las tres.
                manager._insert_audit_event = original_insert
                stored_run, stored_findings, record = (
                    manager.insert_diagnostic_run_with_findings_and_audit_event(
                        dict(run), [dict(finding) for finding in findings], dict(audit_event),
                    )
                )
                self.assertEqual(run_id, stored_run.get("id"))
                self.assertEqual(2, len(stored_findings))
                self.assertEqual("DIAGNOSTIC_RUN", record.get("action"))
                self.assertIsNotNone(manager.get_diagnostic_run(run_id))
                self.assertEqual(
                    2, len(manager.list_security_findings(run_id=run_id)),
                )
                self.assertEqual(
                    1, manager.count_audit_events_by_action("DIAGNOSTIC_RUN"),
                )
            finally:
                manager._insert_audit_event = original_insert
                manager.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
