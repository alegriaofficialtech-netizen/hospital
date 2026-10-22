#!/usr/bin/env python3
"""F3 API suite: Gestion de Riesgos (M4) y Gestion de Controles (M5).

Verifica los Objetivos O2 y O3 de la tesis doctoral:
  * El Oficial de Seguridad y el Administrador consultan la matriz de riesgos y el catalogo de controles
  * Los roles clinicos sin autorizacion son rechazados (403)
  * Las operaciones de alta, modificacion y verificacion exigen MFA (403 sin OTP)
  * El calculo de riesgo inherente y residual respeta la matriz 5x5
  * Un control no puede pasar a VERIFICADO sin evidencia real enlazada
  * La vinculacion riesgo-control es biunívoca y auditable
  * La atomicidad de persistencia y auditoria se comprueba por rollback
  * La cadena criptografica de auditoria SHA-256 permanece integra
"""

import copy
import hashlib
import json
import os
import re
import sqlite3
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BACKEND_DIR = str(ROOT / "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

RUNTIME = Path(os.environ.get("F11_RUNTIME_DIR", "/home/elcra/sgsi-zta-runtime/f11"))
CREDENTIALS_FILE = Path(
    os.environ.get("F11_CREDENTIALS_FILE", str(RUNTIME / "credentials.json"))
)
BACKEND_URL = os.environ.get("F11_API_BASE_URL", "http://127.0.0.1:8010").rstrip("/")
KC_URL = os.environ.get("F11_KEYCLOAK_URL", "http://127.0.0.1:8085").rstrip("/")

_TOKENS = {}


def load_setup_realm():
    """Importa infra/local-test/setup_realm.py."""
    import importlib.util

    path = ROOT / "infra" / "local-test" / "setup_realm.py"
    spec = importlib.util.spec_from_file_location("f11_setup_realm_f3", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def mfa_evidence(result):
    """Verifica si el token acredita MFA con amr lista."""
    claims = result.get("claims") or {}
    amr = claims.get("amr")
    if not isinstance(amr, list):
        return False
    return any(
        isinstance(m, str) and m.strip().lower() in ("otp", "totp", "mfa-otp")
        for m in amr
    )


def mint_token(setup_realm, credentials, username, password=None, totp_secret=None):
    """Emite token de acceso con flujo OIDC real."""
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
        except Exception as exc:
            if attempt == 2 or ("no respondio" not in str(exc) and "authorization code" not in str(exc)):
                raise
            time.sleep(32)
            continue
        if secret and not mfa_evidence(result):
            if attempt == 2:
                break
            time.sleep(32)
            continue
        break
    if result is None:
        raise unittest.SkipTest(f"no se pudo emitir token para {username}")
    return result


def token_usable(result, secret):
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


class FailingLinkDatabase:
    """Envuelve una base real y simula el fallo de un enlace concreto.

    Solo intercepta la escritura del enlace: el resto de la API del gestor se
    delega sin cambios para que la siembra se ejecute igual que en produccion.
    """

    def __init__(self, real, failing_control_id):
        self._real = real
        self._failing_control_id = failing_control_id

    def __getattr__(self, name):
        return getattr(self._real, name)

    def link_risk_control_with_audit_event(
        self, risk_id, control_id, effectiveness, audit_event
    ):
        if control_id == self._failing_control_id:
            raise RuntimeError("fallo simulado al escribir el enlace riesgo-control")
        return self._real.link_risk_control_with_audit_event(
            risk_id, control_id, effectiveness, audit_event
        )


SEED_AUDIT_EVENT = {
    "action": "RISK_SEED",
    "actor": "TEST",
    "role": "NONE",
    "status": "ALLOWED",
    "details": "Preparacion de riesgos semilla sobre base temporal",
    "ip": "127.0.0.1",
    "mfa_verified": False,
}


class F3SeedIntegritySuite(unittest.TestCase):
    """Integridad de la siembra de enlaces riesgo-control (M4 <-> M5, O2/O3).

    Usa una base SQLite temporal en /tmp: no depende de la API ni de la base
    viva del laboratorio.
    """

    def _temp_db(self):
        from database import ClinicalDatabaseManager

        directory = tempfile.mkdtemp(prefix="f3-seed-")
        return ClinicalDatabaseManager(str(Path(directory) / "seed.db"))

    def _seed_risks(self, db, codes):
        db.insert_risks_with_audit_event(
            [
                {
                    "code": code,
                    "name": f"Riesgo semilla {code}",
                    "category": "identidad",
                    "threat": "Amenaza de prueba",
                    "vulnerability": "Vulnerabilidad de prueba",
                    "probability_inherent": 3,
                    "impact_inherent": 3,
                    "treatment": "MITIGAR",
                    "status": "IDENTIFICADO",
                    "synthetic": 0,
                }
                for code in codes
            ],
            SEED_AUDIT_EVENT,
        )

    def _insert_finding(self, db, checker_id):
        """Inserta una ejecucion de diagnostico y un hallazgo real de un comprobador."""
        from database import F11_ENVIRONMENT

        stamp = int(time.time() * 1000)
        run_id = f"RUN-{checker_id}-{stamp}"
        db.insert_diagnostic_run(
            {
                "id": run_id,
                "started_at": time.time(),
                "status": "completed",
                "checker_count": 1,
                "passed": 0,
                "failed": 1,
                "warnings": 0,
                "triggered_by": "test_suite",
                "environment": F11_ENVIRONMENT,
            }
        )
        finding_id = f"FND-{checker_id}-{stamp}"
        db.insert_security_findings(
            [
                {
                    "id": finding_id,
                    "run_id": run_id,
                    "checker_id": checker_id,
                    "title": f"Hallazgo real de prueba {checker_id}",
                    "objective": "O1",
                    "severity": "high",
                    "status": "failed",
                    "asset_ref": "keycloak-iam",
                    "evidence_command": "test-suite --checker " + checker_id,
                    "evidence_output": "resultado sintetico de prueba",
                    "evidence_source": "in_process",
                    "remediation": "accion de prueba",
                    "detected_at": time.time(),
                }
            ]
        )
        return finding_id

    def test_28_seed_links_finding_id_to_real_finding(self):
        """Con hallazgo previo, finding_id guarda el id real del hallazgo."""
        from risk_management import seed_risk_catalog

        db = self._temp_db()
        finding_id = self._insert_finding(db, "KC_MFA_ON_ADMIN_IDENTITIES")

        result = seed_risk_catalog(db)
        self.assertFalse(result["already_seeded"])

        risk = db.get_risk("RSK-F11-IAM-01")
        self.assertIsNotNone(risk)
        self.assertEqual(risk["finding_id"], finding_id)
        self.assertEqual(risk["source_checker"], "KC_MFA_ON_ADMIN_IDENTITIES")

        # El vinculo apunta a una fila real de security_findings, no a un texto.
        con = sqlite3.connect(str(Path(db.db_path)))
        try:
            row = con.execute(
                "SELECT id FROM security_findings WHERE id = ?;", (risk["finding_id"],)
            ).fetchone()
        finally:
            con.close()
        self.assertIsNotNone(row, "finding_id debe ser el id de un hallazgo real")
        db.close()

    def test_29_seed_keeps_finding_id_null_without_diagnostic(self):
        """Sin hallazgo ejecutado, finding_id queda en null y el origen se declara aparte."""
        from risk_management import seed_risk_catalog

        db = self._temp_db()
        seed_risk_catalog(db)

        risk = db.get_risk("RSK-F11-IAM-01")
        self.assertIsNotNone(risk)
        self.assertIsNone(risk["finding_id"], "sin diagnostico no hay hallazgo que enlazar")
        self.assertEqual(risk["source_checker"], "KC_MFA_ON_ADMIN_IDENTITIES")

        # Otro comprobador distinto: el codigo tampoco se cuela en finding_id.
        risk2 = db.get_risk("RSK-F11-CONT-02")
        self.assertIsNone(risk2["finding_id"])
        self.assertEqual(risk2["source_checker"], "CONTAINER_HARDENING")
        db.close()

    def test_30_migration_7_repairs_legacy_finding_id_on_populated_db(self):
        """La migracion 7 mueve el codigo de comprobador a source_checker en bases ya pobladas."""
        from database import ClinicalDatabaseManager

        directory = tempfile.mkdtemp(prefix="f3-migration-")
        path = str(Path(directory) / "migrated.db")
        db = ClinicalDatabaseManager(path)

        # Simula la siembra antigua: el codigo del comprobador dentro de finding_id
        # y source_checker todavia sin existir como dato.
        db.insert_risk_with_audit_event(
            {
                "code": "RSK-LEGACY-01",
                "name": "Riesgo con vinculo antiguo",
                "category": "identidad",
                "threat": "Amenaza de prueba",
                "vulnerability": "Vulnerabilidad de prueba",
                "probability_inherent": 3,
                "impact_inherent": 3,
                "treatment": "MITIGAR",
                "status": "IDENTIFICADO",
                "finding_id": "KC_MFA_ON_ADMIN_IDENTITIES",
                "synthetic": 0,
            },
            SEED_AUDIT_EVENT,
        )
        finding_id = self._insert_finding(db, "KC_MFA_ON_ADMIN_IDENTITIES")
        db.close()

        # Retroceder la marca de version fuerza a reejecutar la migracion 7.
        con = sqlite3.connect(path)
        con.execute("DELETE FROM schema_migrations WHERE version = 7;")
        con.commit()
        con.close()

        db2 = ClinicalDatabaseManager(path)
        repaired = db2.get_risk("RSK-LEGACY-01")
        self.assertEqual(repaired["source_checker"], "KC_MFA_ON_ADMIN_IDENTITIES")
        self.assertEqual(repaired["finding_id"], finding_id)
        db2.close()

        # Reabrir de nuevo no altera nada (migracion idempotente).
        db3 = ClinicalDatabaseManager(path)
        stable = db3.get_risk("RSK-LEGACY-01")
        self.assertEqual(stable["source_checker"], "KC_MFA_ON_ADMIN_IDENTITIES")
        self.assertEqual(stable["finding_id"], finding_id)
        db3.close()

    def test_33_control_update_ignores_synthetic_at_persistence_layer(self):
        """La persistencia no cambia la sinteticidad de un control en la actualizacion."""
        db = self._temp_db()
        control, _ = db.insert_control_with_audit_event(
            {
                "code": "CTL-RB-SINT-01",
                "framework": "ISO_27001_2022",
                "clause_or_pillar": "A.5 Organizacional",
                "name": "Control sintetico de prueba",
                "description": "Prueba de inmutabilidad de la sinteticidad",
                "owner_role": "ROLE_PLATFORM_ADMIN",
                "status": "PROPUESTO",
                "synthetic": 1,
            },
            SEED_AUDIT_EVENT,
        )
        self.assertEqual(control["synthetic"], 1)

        updated, _ = db.update_control_with_audit_event(
            control["id"],
            {"description": "Intento de cambio de sinteticidad", "synthetic": 0},
            SEED_AUDIT_EVENT,
        )
        self.assertEqual(updated["synthetic"], 1, "la actualizacion no puede cambiar la sinteticidad")
        db.close()

    def test_21_seed_aborts_when_a_risk_control_link_fails(self):
        """Un enlace que falla aborta la siembra en lugar de dejar la matriz incompleta."""
        from control_management import (
            SEED_RISK_CONTROL_LINKS,
            ControlSeedError,
            seed_control_catalog,
            seed_control_id,
        )

        db = self._temp_db()
        risk_codes = sorted({link[0] for link in SEED_RISK_CONTROL_LINKS})
        self._seed_risks(db, risk_codes)

        # El tercer enlace semilla (RSK-F11-AUDIT-03 -> ISO-A.8.15) falla al
        # escribir: la siembra no puede terminar "bien" con la matriz cortada.
        failing_control_id = seed_control_id("ISO-A.8.15")
        faulty = FailingLinkDatabase(db, failing_control_id)

        with self.assertRaises(ControlSeedError) as raised:
            seed_control_catalog(faulty)

        message = str(raised.exception)
        self.assertIn("RSK-F11-AUDIT-03", message)
        self.assertIn("ISO-A.8.15", message)
        self.assertIn("fallo simulado", message)

        # La matriz quedo incompleta: la siembra aborto en vez de declarar exito.
        con = sqlite3.connect(str(Path(db.db_path)))
        try:
            links = con.execute("SELECT COUNT(*) FROM risk_controls;").fetchone()[0]
        finally:
            con.close()
        self.assertLess(links, len(SEED_RISK_CONTROL_LINKS))
        db.close()

    def test_22_seed_aborts_when_a_link_endpoint_is_missing(self):
        """Un enlace semilla sin su riesgo tambien aborta: no se omite en silencio."""
        from control_management import (
            SEED_RISK_CONTROL_LINKS,
            ControlSeedError,
            seed_control_catalog,
        )

        db = self._temp_db()
        risk_codes = sorted({link[0] for link in SEED_RISK_CONTROL_LINKS})
        # Se omite RSK-F11-DATA-05: su enlace semilla no tiene extremo posible.
        self._seed_risks(db, [code for code in risk_codes if code != "RSK-F11-DATA-05"])

        with self.assertRaises(ControlSeedError) as raised:
            seed_control_catalog(db)

        message = str(raised.exception)
        self.assertIn("RSK-F11-DATA-05", message)
        self.assertIn("NIST-ZTA-T1", message)
        self.assertIn("no existe en la base de datos", message)
        db.close()


class F3ApiSuite(unittest.TestCase):
    """Base comun de pruebas F3."""

    @classmethod
    def setUpClass(cls):
        if not CREDENTIALS_FILE.is_file():
            raise unittest.SkipTest(f"missing {CREDENTIALS_FILE}")
        cls.credentials = json.loads(CREDENTIALS_FILE.read_text(encoding="utf-8"))
        cls.users = cls.credentials["users"]
        cls.setup_realm = load_setup_realm()

    def token(self, username, password=None, totp_secret=None):
        user = self.users.get(username)
        if user is None and password is None:
            raise unittest.SkipTest(f"unknown identity {username}")
        secret = totp_secret if totp_secret is not None else (user or {}).get("totp_secret")

        cached = _TOKENS.get(username)
        if cached is not None and token_usable(cached, secret):
            return cached["access_token"]

        result = mint_token(self.setup_realm, self.credentials, username, password, totp_secret)
        _TOKENS[username] = result
        return result["access_token"]

    def call(self, token, method, path, body=None, timeout=30):
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

    def assert_distribution_matches_rows(self, reparto, rows, field):
        """Comprueba que un reparto del resumen cuadra fila a fila con la lista.

        No basta con que exista la clave: por cada nivel, estado, tratamiento,
        categoria o marco, el conteo del resumen debe igualar el numero de filas
        listadas con ese valor, y ninguna fila puede traer un valor fuera del
        reparto (eso descuadraria el total en silencio).
        """
        conocidos = set(reparto)
        for row in rows:
            self.assertIn(
                row.get(field),
                conocidos,
                f"{field}='{row.get(field)}' no aparece en el reparto del resumen",
            )
        for key, expected in reparto.items():
            actual = sum(1 for row in rows if row.get(field) == key)
            self.assertEqual(
                expected,
                actual,
                f"el resumen declara {field}='{key}': {expected}, pero hay {actual} filas",
            )


class F3RisksApiSuite(F3ApiSuite):
    """Pruebas de la API de Gestion de Riesgos (M4, O2)."""

    def test_01_auditor_reads_risks_and_summary(self):
        """El Oficial de Seguridad lee la matriz de riesgos y su resumen."""
        token = self.token("auditor.test")
        status, body = self.call(token, "GET", "/api/v1/risks")
        self.assertEqual(status, 200)
        self.assertIn("risks", body)
        self.assertIn("summary", body)
        risks = body["risks"]
        self.assertGreaterEqual(len(risks), 5)

        # Verificar presencia de riesgos semilla
        codes = {r["code"] for r in risks}
        self.assertIn("RSK-F11-IAM-01", codes)
        self.assertIn("RSK-F11-CONT-02", codes)
        self.assertIn("RSK-F11-AUDIT-03", codes)

        # Verificar resumen
        summary = body["summary"]
        self.assertIn("total_risks", summary)
        self.assertIn("inherent_levels", summary)
        self.assertIn("residual_levels", summary)
        self.assertIn("by_status", summary)

    def test_02_clinical_user_without_risks_role_is_denied(self):
        """Un usuario clinico sin rol de auditoria ni admin recibe 403."""
        token = self.token("recepcion.test")
        status, body = self.call(token, "GET", "/api/v1/risks")
        self.assertEqual(status, 403)
        self.assertEqual(body.get("code"), "RISKS_ROLE_REQUIRED")

    def test_03_admin_without_mfa_cannot_create_risk(self):
        """El administrador con rol pero sin OTP recibe 403 por MFA."""
        token = self.token("medico.sinmfa")
        status, body = self.call(token, "POST", "/api/v1/risks", {
            "code": "RSK-SINT-NO-MFA",
            "name": "Riesgo no autorizado sin MFA",
            "category": "software",
            "threat": "Amenaza",
            "vulnerability": "Vulnerabilidad",
        })
        self.assertEqual(status, 403)
        self.assertEqual(body.get("code"), "MFA_AUTHENTICATION_REQUIRED")

    def test_04_admin_with_mfa_creates_synthetic_risk(self):
        """El administrador con MFA da de alta un riesgo sintetico calculando la matriz 5x5."""
        token = self.token("medico.test")
        test_code = f"RSK-PRB-{int(time.time()*1000)%10000000}"
        payload = {
            "code": test_code,
            "name": "Riesgo sintetico de prueba automatizada F3",
            "description": "Prueba de calculo de matriz de riesgo 5x5",
            "category": "software",
            "threat": "Inyeccion de parametros en endpoint no validado",
            "vulnerability": "Falta de validacion de tipo en capa HTTP",
            "probability_inherent": 4,
            "impact_inherent": 3,
            "treatment": "MITIGAR",
            "probability_residual": 2,
            "impact_residual": 2,
            "owner_role": "ROLE_PLATFORM_ADMIN",
            "status": "IDENTIFICADO",
            "synthetic": 1,
        }
        status, body = self.call(token, "POST", "/api/v1/risks", payload)
        self.assertEqual(status, 201)
        risk = body["risk"]

        self.assertEqual(risk["code"], test_code)
        # Inherent score = 4 * 3 = 12 -> ALTO
        self.assertEqual(risk["inherent_risk_score"], 12)
        self.assertEqual(risk["inherent_risk_level"], "ALTO")
        # Residual score = 2 * 2 = 4 -> BAJO
        self.assertEqual(risk["residual_risk_score"], 4)
        self.assertEqual(risk["residual_risk_level"], "BAJO")

    def test_05_duplicate_risk_code_is_rejected(self):
        """Un riesgo con codigo duplicado se rechaza con conflicto 409."""
        token = self.token("medico.test")
        payload = {
            "code": "RSK-F11-IAM-01",  # Ya existe en semilla
            "name": "Riesgo duplicado",
            "category": "identidad",
            "threat": "Amenaza existente",
            "vulnerability": "Vulnerabilidad existente",
            "probability_inherent": 3,
            "impact_inherent": 3,
            "treatment": "MITIGAR",
            "status": "IDENTIFICADO",
        }
        status, body = self.call(token, "POST", "/api/v1/risks", payload)
        self.assertEqual(status, 409)
        self.assertEqual(body.get("code"), "RISK_ALREADY_EXISTS")

    def test_06_invalid_risk_payload_is_rejected(self):
        """Un riesgo con campos invalidos se rechaza con 400 y mapa de campos."""
        token = self.token("medico.test")
        payload = {
            "code": "X",  # Demasiado corto
            "name": "",
            "category": "categoria_invalida",
            "probability_inherent": 99,  # Fuera de rango 1..5
        }
        status, body = self.call(token, "POST", "/api/v1/risks", payload)
        self.assertEqual(status, 400)
        self.assertEqual(body.get("code"), "RISK_INVALID")
        self.assertIn("fields", body)

    def test_07_risk_update_increments_revision_and_is_audited(self):
        """Actualizar un riesgo recalcula el nivel y avanza revision."""
        token = self.token("medico.test")
        # Primero leer el riesgo semilla
        status, body = self.call(token, "GET", "/api/v1/risks/RSK-F11-DATA-05")
        self.assertEqual(status, 200)
        risk_id = body["risk"]["id"]
        old_rev = body["risk"]["revision"]

        # Modificar residual a P=1, I=2 -> BAJO (score=2)
        update_payload = {
            "probability_residual": 1,
            "impact_residual": 2,
            "status": "CONTROLADO",
        }
        status, body = self.call(token, "POST", f"/api/v1/risks/{risk_id}", update_payload)
        self.assertEqual(status, 200)
        updated = body["risk"]
        self.assertEqual(updated["revision"], old_rev + 1)
        self.assertEqual(updated["residual_risk_score"], 2)
        self.assertEqual(updated["residual_risk_level"], "BAJO")
        self.assertEqual(updated["status"], "CONTROLADO")


    def test_34_summary_contract_matches_listed_rows(self):
        """La forma de los resumenes coincide con la API y sus totales cuadran con las filas.

        Cubre el defecto F3-D8: RiskSummary y ControlSummary deben declarar los
        mismos campos que devuelve la API, y los indicadores que la interfaz
        consume deben derivarse de ellos. Ademas de que exista la clave, los
        numeros concuerdan: cada reparto suma el total, el total iguala las
        filas listadas y el reparto coincide fila a fila con la lista.
        """
        token = self.token("auditor.test")

        # --- Resumen de riesgos (M4, O2) ---
        status, listado = self.call(token, "GET", "/api/v1/risks")
        self.assertEqual(status, 200)
        riesgos = listado["risks"]
        status, dedicado = self.call(token, "GET", "/api/v1/risks/summary")
        self.assertEqual(status, 200)
        resumen = dedicado["summary"]

        self.assertEqual(
            set(resumen.keys()),
            {
                "total_risks",
                "inherent_levels",
                "residual_levels",
                "by_status",
                "by_treatment",
                "by_category",
            },
            "la forma del resumen de riesgos no coincide con lo que consume la interfaz",
        )

        total = resumen["total_risks"]
        self.assertEqual(total, len(riesgos), "total_risks debe cuadrar con las filas listadas")
        self.assertEqual(
            total,
            listado["summary"]["total_risks"],
            "el resumen dedicado y el embebido en la lista deben coincidir",
        )

        # Los KPI de la matriz 5x5 salen de inherent_levels y residual_levels.
        for campo in ("inherent_levels", "residual_levels"):
            self.assertTrue(resumen[campo], f"{campo} no puede venir vacio")
            self.assertEqual(
                sum(resumen[campo].values()),
                total,
                f"la suma de {campo} debe igualar total_risks",
            )
        for campo in ("by_status", "by_treatment", "by_category"):
            self.assertEqual(
                sum(resumen[campo].values()),
                total,
                f"la suma de {campo} debe igualar total_risks",
            )

        self.assert_distribution_matches_rows(
            resumen["inherent_levels"], riesgos, "inherent_risk_level"
        )
        self.assert_distribution_matches_rows(
            resumen["residual_levels"], riesgos, "residual_risk_level"
        )
        self.assert_distribution_matches_rows(resumen["by_status"], riesgos, "status")
        self.assert_distribution_matches_rows(resumen["by_treatment"], riesgos, "treatment")
        self.assert_distribution_matches_rows(resumen["by_category"], riesgos, "category")

        # Indicadores que enlaza indicators.component.html: deben existir de verdad.
        self.assertIn("CRITICO", resumen["inherent_levels"])
        self.assertIn("ALTO", resumen["inherent_levels"])
        self.assertIn("BAJO", resumen["residual_levels"])
        self.assertIn("MEDIO", resumen["residual_levels"])
        self.assertIn("CONTROLADO", resumen["by_status"])

        # --- Resumen de controles (M5, O3) ---
        status, listado = self.call(token, "GET", "/api/v1/controls")
        self.assertEqual(status, 200)
        controles = listado["controls"]
        status, dedicado = self.call(token, "GET", "/api/v1/controls/summary")
        self.assertEqual(status, 200)
        resumen_c = dedicado["summary"]

        self.assertEqual(
            set(resumen_c.keys()),
            {"total_controls", "by_framework", "by_status", "compliance_percentage"},
            "el resumen de controles tiene campos que la API no devuelve o le faltan otros",
        )

        total_c = resumen_c["total_controls"]
        self.assertEqual(
            total_c, len(controles), "total_controls debe cuadrar con las filas listadas"
        )
        self.assertEqual(
            total_c,
            listado["summary"]["total_controls"],
            "el resumen dedicado y el embebido en la lista deben coincidir",
        )
        self.assertEqual(
            sum(resumen_c["by_framework"].values()),
            total_c,
            "la suma de by_framework debe igualar total_controls",
        )
        self.assertEqual(
            sum(resumen_c["by_status"].values()),
            total_c,
            "la suma de by_status debe igualar total_controls",
        )

        self.assert_distribution_matches_rows(resumen_c["by_framework"], controles, "framework")
        self.assert_distribution_matches_rows(resumen_c["by_status"], controles, "status")

        # "verificados", "implementados" y "propuestos" se derivan de by_status.
        for estado in ("VERIFICADO", "IMPLEMENTADO", "PROPUESTO"):
            self.assertIn(estado, resumen_c["by_status"])
        self.assertIsInstance(resumen_c["compliance_percentage"], (int, float))

    def test_23_auditor_cannot_create_risk(self):
        """El auditor consulta la matriz pero no puede darla de alta (403 por rol)."""
        token = self.token("auditor.test")
        status, body = self.call(token, "POST", "/api/v1/risks", {
            "code": "RSK-AUDITOR-NO-PUEDE",
            "name": "Riesgo que el auditor no puede crear",
            "category": "software",
            "threat": "Amenaza",
            "vulnerability": "Vulnerabilidad",
        })
        self.assertEqual(status, 403)
        self.assertEqual(body.get("code"), "PLATFORM_ADMIN_ROLE_REQUIRED")

    def test_24_risk_keeps_asset_and_finding_ids(self):
        """El alta por API persiste los vinculos O2 reales (asset_id y finding_id)."""
        token = self.token("medico.test")
        _, assets_body = self.call(token, "GET", "/api/v1/assets")
        _, findings_body = self.call(token, "GET", "/api/v1/diagnostics/findings?limit=1")
        asset_id = assets_body["assets"][0]["id"]
        finding_id = findings_body["findings"][0]["id"]

        test_code = f"RSK-LNK-{int(time.time()*1000)%10000000}"
        status, body = self.call(token, "POST", "/api/v1/risks", {
            "code": test_code,
            "name": "Riesgo con vinculos O2 explicitos",
            "description": "Comprueba la trazabilidad con M3 y M2",
            "category": "identidad",
            "asset_id": asset_id,
            "finding_id": finding_id,
            "threat": "Amenaza",
            "vulnerability": "Vulnerabilidad",
            "probability_inherent": 3,
            "impact_inherent": 3,
            "treatment": "MITIGAR",
            "status": "IDENTIFICADO",
        })
        self.assertEqual(status, 201)
        created = body["risk"]
        self.assertEqual(created["asset_id"], asset_id)
        self.assertEqual(created["finding_id"], finding_id)

        status, body = self.call(token, "GET", f"/api/v1/risks/{created['id']}")
        self.assertEqual(status, 200)
        self.assertEqual(body["risk"]["asset_id"], asset_id)
        self.assertEqual(body["risk"]["finding_id"], finding_id)

    def test_25_backend_forces_synthetic_on_risk_creation(self):
        """La API marca el riesgo como sintetico aunque el cliente no lo declare."""
        token = self.token("medico.test")
        test_code = f"RSK-SINT-{int(time.time()*1000)%10000000}"
        status, body = self.call(token, "POST", "/api/v1/risks", {
            "code": test_code,
            "name": "Riesgo sin declaracion de sinteticidad",
            "description": "El servidor impone la regla de evidencia",
            "category": "software",
            "threat": "Amenaza",
            "vulnerability": "Vulnerabilidad",
            "probability_inherent": 2,
            "impact_inherent": 2,
            "treatment": "MITIGAR",
            "status": "IDENTIFICADO",
        })
        self.assertEqual(status, 201)
        self.assertEqual(body["risk"]["synthetic"], 1)

    def test_26_frontend_gates_management_to_admin_with_mfa(self):
        """La interfaz solo ofrece gestion con admin + MFA y no declara sinteticidad."""
        features = ROOT / "frontend" / "src" / "app" / "features"
        for relative in ("controls/controls.component.ts", "risks/risks.component.ts"):
            source = (features / relative).read_text(encoding="utf-8")
            match = re.search(r"readonly canManage = computed\(\s*(.*?)\s*\);", source, re.S)
            self.assertIsNotNone(match, f"no se encontro canManage en {relative}")
            condition = match.group(1)
            self.assertIn("ROLE_PLATFORM_ADMIN", condition, relative)
            self.assertNotIn("ROLE_SECURITY_AUDITOR", condition, relative)
            self.assertIn("mfaVerified", condition, relative)

        risks_source = (features / "risks/risks.component.ts").read_text(encoding="utf-8")
        self.assertNotIn("synthetic:", risks_source, "el cliente no debe declarar sinteticidad")
        self.assertIn("asset_id:", risks_source)
        self.assertIn("finding_id:", risks_source)


class F3ControlsApiSuite(F3ApiSuite):
    """Pruebas de la API de Gestion de Controles (M5, O3)."""

    def test_08_auditor_reads_controls_and_summary(self):
        """El Oficial de Seguridad lee el catalogo de controles y su cumplimiento."""
        token = self.token("auditor.test")
        status, body = self.call(token, "GET", "/api/v1/controls")
        self.assertEqual(status, 200)
        self.assertIn("controls", body)
        self.assertIn("summary", body)
        controls = body["controls"]
        self.assertGreaterEqual(len(controls), 9)

        # Verificar presencia de los 3 marcos
        frameworks = {c["framework"] for c in controls}
        self.assertIn("ISO_27001_2022", frameworks)
        self.assertIn("NIST_SP_800_207", frameworks)
        self.assertIn("CISA_ZTM", frameworks)

        # Verificar resumen de cumplimiento
        summary = body["summary"]
        self.assertIn("total_controls", summary)
        self.assertIn("compliance_percentage", summary)
        self.assertGreater(summary["compliance_percentage"], 0.0)

    def test_09_admin_without_mfa_cannot_create_control(self):
        """El administrador sin OTP recibe 403 al dar de alta un control."""
        token = self.token("medico.sinmfa")
        status, body = self.call(token, "POST", "/api/v1/controls", {
            "code": "CTL-NO-MFA",
            "framework": "ISO_27001_2022",
            "name": "Control sin MFA",
        })
        self.assertEqual(status, 403)
        self.assertEqual(body.get("code"), "MFA_AUTHENTICATION_REQUIRED")

    def test_27_auditor_cannot_create_control(self):
        """El auditor consulta el catalogo pero no puede crear controles (403 por rol)."""
        token = self.token("auditor.test")
        status, body = self.call(token, "POST", "/api/v1/controls", {
            "code": "CTL-AUDITOR-NO-PUEDE",
            "framework": "ISO_27001_2022",
            "clause_or_pillar": "A.5 Organizacional",
            "name": "Control que el auditor no puede crear",
            "description": "Debe ser rechazado por politica MANAGE_CONTROLS",
            "status": "PROPUESTO",
        })
        self.assertEqual(status, 403)
        self.assertEqual(body.get("code"), "PLATFORM_ADMIN_ROLE_REQUIRED")

    def test_10_admin_with_mfa_creates_synthetic_control(self):
        """El administrador con MFA da de alta un control propuesto."""
        token = self.token("medico.test")
        test_code = f"CTL-PRB-{int(time.time()*1000)%10000000}"
        payload = {
            "code": test_code,
            "framework": "ISO_27001_2022",
            "clause_or_pillar": "A.8 Tecnologico",
            "name": "Control de prueba sintetica F3",
            "description": "Verificacion automatica de creacion de controles",
            "owner_role": "ROLE_PLATFORM_ADMIN",
            "status": "PROPUESTO",
            "synthetic": 1,
        }
        status, body = self.call(token, "POST", "/api/v1/controls", payload)
        self.assertEqual(status, 201)
        ctl = body["control"]

        self.assertEqual(ctl["code"], test_code)
        self.assertEqual(ctl["status"], "PROPUESTO")

    def test_11_control_marked_verificado_without_evidence_is_rejected(self):
        """Un control no puede crearse como VERIFICADO sin evidencia real."""
        token = self.token("medico.test")
        payload = {
            "code": "CTL-PRUEBA-VERIF-SIN-EVID",
            "framework": "NIST_SP_800_207",
            "clause_or_pillar": "Tenet 3",
            "name": "Control sin evidencia",
            "description": "Debe ser rechazado",
            "owner_role": "ROLE_SECURITY_AUDITOR",
            "status": "VERIFICADO",  # Sin evidence_type ni reference
        }
        status, body = self.call(token, "POST", "/api/v1/controls", payload)
        self.assertEqual(status, 400)
        self.assertEqual(body.get("code"), "CONTROL_INVALID")

    def test_12_admin_verifies_control_with_evidence(self):
        """Verificacion formal de un control enlazando evidencia real observada."""
        token = self.token("medico.test")
        test_code = f"CTL-VRF-{int(time.time()*1000)%10000000}"
        payload = {
            "code": test_code,
            "framework": "ISO_27001_2022",
            "clause_or_pillar": "A.5 Organizacional",
            "name": "Control para verificar con evidencia",
            "description": "Demostracion de transicion a verificado",
            "owner_role": "ROLE_PLATFORM_ADMIN",
            "status": "IMPLEMENTADO",
            "synthetic": 1,
        }
        status, body = self.call(token, "POST", "/api/v1/controls", payload)
        self.assertEqual(status, 201)
        ctl_id = body["control"]["id"]

        # Verificar formalmente con evidencia
        verify_payload = {
            "evidence_source": "test_suite",
            "reference_id": "test_12_admin_verifies_control_with_evidence",
            "observed_result": "Prueba de suite automatizada aprobada con aserciones estrictas",
        }
        status, body = self.call(token, "POST", f"/api/v1/controls/{ctl_id}/verify", verify_payload)

        self.assertEqual(status, 200)
        self.assertTrue(body.get("verified"))

        # Comprobar que el control ahora es VERIFICADO
        status, body = self.call(token, "GET", f"/api/v1/controls/{ctl_id}")
        self.assertEqual(status, 200)
        ctl = body["control"]
        self.assertEqual(ctl["status"], "VERIFICADO")
        self.assertEqual(ctl["compliance_score"], 1.0)
        self.assertGreaterEqual(len(ctl.get("evidences", [])), 1)

    def test_13_admin_links_risk_and_control(self):
        """Vinculacion biunívoca entre un riesgo y un control."""
        token = self.token("medico.test")
        # Usar riesgo y control semilla que siempre existen
        _, r_body = self.call(token, "GET", "/api/v1/risks/RSK-F11-IAM-01")
        _, c_body = self.call(token, "GET", "/api/v1/controls/ISO-A.5.15")
        risk_id = r_body["risk"]["id"]
        control_id = c_body["control"]["id"]

        # Vincular
        link_payload = {
            "control_id": control_id,
            "effectiveness": "PREVENTIVO",
        }
        status, body = self.call(token, "POST", f"/api/v1/risks/{risk_id}/controls", link_payload)
        self.assertEqual(status, 200)
        self.assertTrue(body.get("linked"))

        # Comprobar que el riesgo muestra el control
        status, body = self.call(token, "GET", f"/api/v1/risks/{risk_id}")
        self.assertEqual(status, 200)
        linked_controls = {c["id"] for c in body["risk"].get("controls", [])}
        self.assertIn(control_id, linked_controls)

        # Comprobar que el control muestra el riesgo
        status, body = self.call(token, "GET", f"/api/v1/controls/{control_id}")
        self.assertEqual(status, 200)
        linked_risks = {r["id"] for r in body["control"].get("risks", [])}
        self.assertIn(risk_id, linked_risks)

    def test_14_atomic_rollback_on_risk_creation(self):
        """Si la auditoria falla, no queda el riesgo en la base de datos (rollback total)."""
        import sqlite3
        con = sqlite3.connect(str(RUNTIME / "lis.db"))
        con.execute("DELETE FROM risks WHERE code = 'RSK-ROLLBACK-TEST';")
        con.commit()

        from database import ClinicalDatabaseManager
        db = ClinicalDatabaseManager(str(RUNTIME / "lis.db"))

        bad_audit_event = {
            "actor": "TEST",
        }
        risk_payload = {
            "code": "RSK-ROLLBACK-TEST",
            "name": "Riesgo que debe ser revertido",
            "category": "software",
            "threat": "Amenaza",
            "vulnerability": "Vulnerabilidad",
        }

        with self.assertRaises(Exception):
            db.insert_risk_with_audit_event(risk_payload, bad_audit_event)

        row = con.execute("SELECT id FROM risks WHERE code = 'RSK-ROLLBACK-TEST';").fetchone()
        self.assertIsNone(row, "El riesgo debio ser revertido atomicamente ante el fallo de auditoria")
        con.close()

    def test_15_audit_chain_remains_valid_after_f3_operations(self):
        """La cadena criptografica SHA-256 sigue intacta tras todas las operaciones de F3."""
        token = self.token("auditor.test")
        status, body = self.call(token, "GET", "/api/v1/audit/events")
        self.assertEqual(status, 200)
        events = body.get("events") or []
        self.assertGreater(len(events), 0)

        expected_prev = "0" * 64
        for event in events:
            self.assertEqual(event.get("prev_hash"), expected_prev)
            clean = {k: v for k, v in event.items() if k != "hash"}
            digest = hashlib.sha256(json.dumps(clean, sort_keys=True).encode("utf-8")).hexdigest()
            self.assertEqual(event.get("hash"), digest)
            expected_prev = digest


    def test_16_atomic_rollback_on_control_creation(self):
        """Si la auditoria falla, el control no persiste en la base de datos (rollback atomico)."""
        import sqlite3
        con = sqlite3.connect(str(RUNTIME / "lis.db"))
        con.execute("DELETE FROM controls WHERE code = 'CTL-ROLLBACK-TEST';")
        con.commit()

        from database import ClinicalDatabaseManager
        db = ClinicalDatabaseManager(str(RUNTIME / "lis.db"))

        bad_audit_event = {
            "actor": "TEST",
        }
        control_payload = {
            "code": "CTL-ROLLBACK-TEST",
            "framework": "ISO_27001_2022",
            "clause_or_pillar": "A.5 Organizacional",
            "name": "Control que debe revertirse",
            "description": "Prueba de rollback atomico",
            "owner_role": "ROLE_PLATFORM_ADMIN",
            "status": "PROPUESTO",
            "synthetic": 1,
        }

        with self.assertRaises(Exception):
            db.insert_control_with_audit_event(control_payload, bad_audit_event)

        row = con.execute("SELECT id FROM controls WHERE code = 'CTL-ROLLBACK-TEST';").fetchone()
        self.assertIsNone(row, "El control debio ser revertido atomicamente ante el fallo de auditoria")
        con.close()

    def test_17_atomic_rollback_on_control_verification(self):
        """Si la auditoria falla al verificar, ni la evidencia persiste ni el estado cambia."""
        import sqlite3
        con = sqlite3.connect(str(RUNTIME / "lis.db"))
        from database import ClinicalDatabaseManager
        db = ClinicalDatabaseManager(str(RUNTIME / "lis.db"))
        ctl_code = f"CTL-VRF-RB-{int(time.time()*1000)%10000000}"
        good_audit = {
            "action": "CONTROL_CREATE",
            "actor": "admin.test",
            "role": "['ROLE_PLATFORM_ADMIN']",
            "status": "ALLOWED",
            "details": "Control para rollback de verificacion",
            "ip": "127.0.0.1",
            "mfa_verified": True,
        }
        ctl, _ = db.insert_control_with_audit_event({
            "code": ctl_code,
            "framework": "ISO_27001_2022",
            "clause_or_pillar": "A.8 Tecnologico",
            "name": "Control para verificar rollback",
            "description": "Prueba de atomicidad en verificacion",
            "owner_role": "ROLE_PLATFORM_ADMIN",
            "status": "IMPLEMENTADO",
            "synthetic": 1,
        }, good_audit)
        ctl_id = ctl["id"]

        bad_audit_event = {
            "actor": "TEST",
        }
        evidence_payload = {
            "control_id": ctl_id,
            "evidence_source": "test_suite",
            "reference_id": "test_17_rollback",
            "observed_result": "Resultado que fallara al auditar",
            "verified_by": "admin.test",
            "verified_with_mfa": 1,
        }

        with self.assertRaises(Exception):
            db.add_control_evidence_with_audit_event(evidence_payload, bad_audit_event)

        row = con.execute("SELECT status, compliance_score FROM controls WHERE id = ?;", (ctl_id,)).fetchone()
        self.assertEqual(row[0], "IMPLEMENTADO", "El estado del control no debio mutar a VERIFICADO")
        self.assertEqual(row[1], 0.5)

        ev_count = con.execute("SELECT COUNT(*) FROM control_evidences WHERE control_id = ?;", (ctl_id,)).fetchone()[0]
        self.assertEqual(ev_count, 0, "No debe quedar evidencia huerfana")
        con.close()

    def test_18_control_update_increments_revision_and_is_audited(self):
        """La actualizacion de un control incrementa revision y queda auditada."""
        token = self.token("medico.test")
        test_code = f"CTL-UPD-{int(time.time()*1000)%10000000}"
        create_payload = {
            "code": test_code,
            "framework": "ISO_27001_2022",
            "clause_or_pillar": "A.5 Organizacional",
            "name": "Control para actualizar revision",
            "description": "Revision inicial",
            "owner_role": "ROLE_PLATFORM_ADMIN",
            "status": "PROPUESTO",
            "synthetic": 1,
        }
        status, body = self.call(token, "POST", "/api/v1/controls", create_payload)
        self.assertEqual(status, 201)
        ctl_id = body["control"]["id"]
        self.assertEqual(body["control"].get("revision", 1), 1)

        # Actualizar descripcion
        update_payload = {
            "description": "Revision actualizada formalmente",
            "status": "IMPLEMENTADO",
        }
        status, body = self.call(token, "POST", f"/api/v1/controls/{ctl_id}", update_payload)
        self.assertEqual(status, 200)
        self.assertEqual(body["control"]["revision"], 2)
        self.assertEqual(body["control"]["status"], "IMPLEMENTADO")
        self.assertEqual(body["control"]["description"], "Revision actualizada formalmente")

        # Verificar evento de auditoria
        auditor_token = self.token("auditor.test")
        status, audit_body = self.call(auditor_token, "GET", "/api/v1/audit/events")
        self.assertEqual(status, 200)
        events = audit_body.get("events") or []
        update_events = [
            e for e in events
            if e.get("action") == "CONTROL_UPDATE" and ctl_id in e.get("details", "")
        ]
        self.assertTrue(update_events, "No se encontro evento CONTROL_UPDATE en auditoria")
        self.assertEqual(update_events[-1]["status"], "ALLOWED")

    def test_19_filter_risks_by_category_and_status(self):
        """Filtrado de matriz de riesgos por categoria y estado."""
        token = self.token("auditor.test")
        status, body = self.call(token, "GET", "/api/v1/risks?category=software&status=IDENTIFICADO")
        self.assertEqual(status, 200)
        risks = body.get("risks", [])
        self.assertGreaterEqual(len(risks), 1)
        for r in risks:
            self.assertEqual(r["category"], "software")
            self.assertEqual(r["status"], "IDENTIFICADO")

    def test_20_filter_controls_by_framework_and_status(self):
        """Filtrado de catalogo de controles por marco y estado."""
        token = self.token("auditor.test")
        status, body = self.call(token, "GET", "/api/v1/controls?framework=ISO_27001_2022")
        self.assertEqual(status, 200)
        controls = body.get("controls", [])
        self.assertGreaterEqual(len(controls), 1)
        for c in controls:
            self.assertEqual(c["framework"], "ISO_27001_2022")

    def test_31_backend_forces_synthetic_on_control_creation(self):
        """La API marca el control como sintetico aunque el cliente no lo declare."""
        token = self.token("medico.test")
        test_code = f"CTL-SINT-{int(time.time()*1000)%10000000}"
        status, body = self.call(token, "POST", "/api/v1/controls", {
            "code": test_code,
            "framework": "ISO_27001_2022",
            "clause_or_pillar": "A.5 Organizacional",
            "name": "Control sin declaracion de sinteticidad",
            "description": "El servidor impone la regla de evidencia",
            "owner_role": "ROLE_PLATFORM_ADMIN",
            "status": "PROPUESTO",
        })
        self.assertEqual(status, 201)
        self.assertEqual(body["control"]["synthetic"], 1)

    def test_32_control_update_cannot_change_synthetic(self):
        """La actualizacion ignora el synthetic enviado por el cliente."""
        token = self.token("medico.test")
        test_code = f"CTL-SINT-UPD-{int(time.time()*1000)%10000000}"
        status, body = self.call(token, "POST", "/api/v1/controls", {
            "code": test_code,
            "framework": "ISO_27001_2022",
            "clause_or_pillar": "A.5 Organizacional",
            "name": "Control para intentar cambiar la sinteticidad",
            "description": "La actualizacion no debe poder cambiar la procedencia",
            "owner_role": "ROLE_PLATFORM_ADMIN",
            "status": "PROPUESTO",
        })
        self.assertEqual(status, 201)
        ctl_id = body["control"]["id"]
        self.assertEqual(body["control"]["synthetic"], 1)

        status, body = self.call(token, "POST", f"/api/v1/controls/{ctl_id}", {
            "description": "Intento de cambio de sinteticidad",
            "synthetic": 0,
        })
        self.assertEqual(status, 200)
        self.assertEqual(body["control"]["synthetic"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
