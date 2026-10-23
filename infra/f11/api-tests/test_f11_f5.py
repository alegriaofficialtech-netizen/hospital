#!/usr/bin/env python3
"""F5 API suite: validacion por expertos (M9), evidencia por objetivo e informes.

Verifica el cierre del backend de F5:
  * Migracion 9 aditiva e idempotente sobre una base ya poblada.
  * Siembra idempotente de UN instrumento de validacion con >= 12 items en las
    seis dimensiones del modelo Zero Trust y CERO dictamenes sembrados.
  * Registro de dictamenes: autor, rol, afiliacion, alcance, veredicto
    DECLARADO por el experto y respuestas por item; el score es una media
    ponderada descriptiva y el veredicto NO se deriva ni se corrige.
  * Inventario de evidencia derivado de datos reales, con reference y source
    reales, objetivos vacios declarados y filtro por objetivo.
  * Informes Markdown construidos solo con lo que hay en la base: secciones
    obligatorias, hash sha256 del contenido, codigo determinista y seccion de
    limitaciones que declara lo ausente (por ejemplo, cero dictamenes).
  * RBAC de los cinco roles de la plataforma y atomicidad de las escrituras.

Las pruebas de dominio usan una base SQLite temporal en /tmp: no tocan la base
viva del laboratorio. Las pruebas de API hablan con el stack ya arrancado.
"""

import hashlib
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

# Autor claramente sintetico para las pruebas: nunca el nombre de una persona
# ni de una institucion real.
SYNTHETIC_EXPERT = "EXPERTO-SINTETICO-F11"

SEED_AUDIT_EVENT = {
    "action": "SEED",
    "actor": "TEST",
    "role": "NONE",
    "status": "ALLOWED",
    "details": "Preparacion de datos de prueba sobre base temporal",
    "ip": "127.0.0.1",
    "mfa_verified": False,
}


def load_setup_realm():
    """Importa infra/local-test/setup_realm.py."""
    import importlib.util

    path = ROOT / "infra" / "local-test" / "setup_realm.py"
    spec = importlib.util.spec_from_file_location("f11_setup_realm_f5", path)
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


class F5DomainSuite(unittest.TestCase):
    """M9, evidencia e informes sobre una base SQLite temporal."""

    def _new_db(self):
        from database import ClinicalDatabaseManager

        directory = tempfile.mkdtemp(prefix="f5-domain-", dir="/tmp")
        return ClinicalDatabaseManager(str(Path(directory) / "f5.db"))

    def _seed_instrument(self, db):
        from validation_management import seed_validation_instrument

        seed_validation_instrument(db)
        return db.get_instrument("INSTR-F11-ZTA-01")

    def _seed_assets(self, db, names):
        db.insert_assets_with_audit_event([
            {
                "id": "AST-" + name.upper().replace("-", ""),
                "name": name,
                "classification": "service",
                "criticality": "high",
                "owner": "ROLE_PLATFORM_ADMIN",
                "source": "compose",
                "environment": "f11-local",
                "synthetic": 1,
                "description": "Activo de prueba F5",
            }
            for name in names
        ], SEED_AUDIT_EVENT)

    def _seed_risks(self, db, codes, synthetic=1):
        db.insert_risks_with_audit_event([
            {
                "code": code,
                "name": "Riesgo de prueba " + code,
                "category": "identidad",
                "threat": "Amenaza de prueba F5",
                "vulnerability": "Vulnerabilidad de prueba F5",
                "probability_inherent": 3,
                "impact_inherent": 3,
                "probability_residual": 2,
                "impact_residual": 2,
                "treatment": "MITIGAR",
                "status": "IDENTIFICADO",
                "synthetic": synthetic,
            }
            for code in codes
        ], SEED_AUDIT_EVENT)

    def _insert_finding(self, db, checker_id="CHECKER-F5"):
        from database import ClinicalDatabaseManager  # noqa: F401 (documenta dependencia)

        stamp = int(time.time() * 1000)
        run_id = f"RUN-F5-{stamp}"
        db.insert_diagnostic_run({
            "id": run_id,
            "started_at": time.time(),
            "status": "completed",
            "checker_count": 1,
            "passed": 0,
            "failed": 1,
            "warnings": 0,
            "triggered_by": "test_suite",
            "environment": "f11-local",
        })
        finding_id = f"FND-F5-{stamp}"
        db.insert_security_findings([{
            "id": finding_id,
            "run_id": run_id,
            "checker_id": checker_id,
            "title": "Hallazgo de prueba F5",
            "objective": "O1",
            "severity": "high",
            "status": "failed",
            "asset_ref": "activo-f5",
            "evidence_command": "test-suite --checker " + checker_id,
            "evidence_output": "resultado de prueba",
            "evidence_source": "in_process",
            "remediation": "accion de prueba",
            "detected_at": time.time(),
        }])
        return finding_id

    def _insert_control(self, db, code="ISO-A.5.15-F5"):
        db.insert_controls_with_audit_event([{
            "code": code,
            "framework": "ISO_27001_2022",
            "clause_or_pillar": "A.5 Control de accesos",
            "name": "Control de prueba F5",
            "description": "Control de prueba F5 para evidencia de O3",
            "owner_role": "ROLE_SECURITY_AUDITOR",
            "status": "PROPUESTO",
            "synthetic": 1,
        }], SEED_AUDIT_EVENT)
        return code

    def _submit(self, db, instrument, code, verdict, answers=None, synthetic=0):
        from validation_management import submit_expert_review

        items = instrument["items"]
        if answers is None:
            answers = [{"item_id": items[0]["id"], "score": 4}]
        return submit_expert_review(db, {
            "code": code,
            "instrument_id": instrument["id"],
            "expert_name": SYNTHETIC_EXPERT,
            "expert_role": "revisor sintetico de pruebas",
            "expert_affiliation": "ninguna (sintetica)",
            "scope": "prueba automatizada F5",
            "verdict": verdict,
            "observations": "dictamen sintetico de prueba",
            "reviewed_at": "2026-10-22",
            "synthetic": synthetic,
            "answers": answers,
        }, "admin.test")

    # ---------------------------------------------------------------- migracion
    def test_01_migration_9_is_additive_and_idempotent(self):
        """La migracion 9 crea sus tablas y reabrir la base conserva los datos."""
        db = self._new_db()
        tables = {
            row["name"]
            for row in db.monitoring_query(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        for name in (
            "validation_instruments",
            "instrument_items",
            "expert_reviews",
            "expert_review_answers",
            "reports",
        ):
            self.assertIn(name, tables)
        versions = [
            row["version"]
            for row in db.monitoring_query("SELECT version FROM schema_migrations")
        ]
        self.assertIn(9, versions)

        instrument = self._seed_instrument(db)
        path = db.db_path
        db.close()

        from database import ClinicalDatabaseManager

        db2 = ClinicalDatabaseManager(path)
        reloaded = db2.get_instrument("INSTR-F11-ZTA-01")
        self.assertIsNotNone(reloaded)
        self.assertEqual(len(reloaded["items"]), len(instrument["items"]))
        db2.close()

    # ------------------------------------------------------------------ siembra
    def test_02_seed_creates_one_instrument_with_at_least_12_items(self):
        """La siembra crea UN instrumento ACTIVO con >= 12 items y ningun dictamen."""
        db = self._new_db()
        instrument = self._seed_instrument(db)
        self.assertEqual(len(db.list_instruments()), 1)
        self.assertEqual(instrument["code"], "INSTR-F11-ZTA-01")
        self.assertEqual(instrument["version"], "1.0")
        self.assertEqual(instrument["status"], "ACTIVO")
        self.assertEqual((instrument["scale_min"], instrument["scale_max"]), (1, 5))
        self.assertGreaterEqual(len(instrument["items"]), 12)
        dimensions = {item["dimension"] for item in instrument["items"]}
        self.assertEqual(
            dimensions,
            {"identidad", "dispositivo", "red", "aplicacion", "datos", "monitoreo"},
        )
        self.assertEqual(db.list_expert_reviews(), [], "no se siembra ningun dictamen")
        db.close()

    def test_03_reseed_does_not_duplicate(self):
        """Reintentar la siembra no duplica el instrumento ni sus items."""
        db = self._new_db()
        first = self._seed_instrument(db)
        from validation_management import seed_validation_instrument

        result = seed_validation_instrument(db)
        self.assertTrue(result["already_seeded"])
        self.assertEqual(len(db.list_instruments()), 1)
        items = db.monitoring_query("SELECT id FROM instrument_items")
        self.assertEqual(len(items), len(first["items"]))
        db.close()

    # --------------------------------------------------------------- validaciones
    def test_04_duplicate_instrument_code_is_rejected(self):
        """Un instrumento con codigo repetido se rechaza."""
        from database import InstrumentAlreadyExistsError
        from validation_management import create_instrument, seed_instrument_payload

        db = self._new_db()
        self._seed_instrument(db)
        payload = seed_instrument_payload()
        payload["version"] = "2.0"
        with self.assertRaises(InstrumentAlreadyExistsError):
            create_instrument(db, payload, "admin.test")
        self.assertEqual(len(db.list_instruments()), 1)
        db.close()

    def test_05_instrument_without_items_is_rejected(self):
        """Un instrumento sin items no es una herramienta de medida."""
        from database import InstrumentValidationError
        from validation_management import create_instrument

        db = self._new_db()
        with self.assertRaises(InstrumentValidationError):
            create_instrument(db, {
                "code": "INSTR-SIN-ITEMS", "name": "Instrumento sin items",
                "version": "1.0", "status": "BORRADOR", "items": [],
            }, "admin.test")
        self.assertEqual(db.list_instruments(), [])
        db.close()

    def test_06_incoherent_scale_is_rejected(self):
        """Una escala con minimo >= maximo se rechaza."""
        from database import InstrumentValidationError
        from validation_management import create_instrument

        db = self._new_db()
        with self.assertRaises(InstrumentValidationError):
            create_instrument(db, {
                "code": "INSTR-ESCALA", "name": "Instrumento con escala invertida",
                "version": "1.0", "status": "BORRADOR",
                "scale_min": 5, "scale_max": 1,
                "items": [{
                    "code": "X-01", "dimension": "identidad",
                    "statement": "Enunciado de prueba", "weight": 1,
                }],
            }, "admin.test")
        self.assertEqual(db.list_instruments(), [])
        db.close()

    def test_07_review_with_unknown_instrument_is_rejected(self):
        """Un dictamen sobre un instrumento inexistente se rechaza."""
        from database import InstrumentNotFoundError
        from validation_management import submit_expert_review

        db = self._new_db()
        with self.assertRaises(InstrumentNotFoundError):
            submit_expert_review(db, {
                "code": "EVL-NO-INS", "instrument_code": "INSTR-NO-EXISTE",
                "expert_name": SYNTHETIC_EXPERT, "expert_role": "revisor",
                "verdict": "CUMPLE", "answers": [{"item_id": "ITM-X", "score": 3}],
            }, "admin.test")
        self.assertEqual(db.list_expert_reviews(), [])
        db.close()

    def test_08_review_with_item_of_another_instrument_is_rejected(self):
        """No se puede responder con un item de otro instrumento."""
        from database import ExpertReviewValidationError
        from validation_management import create_instrument

        db = self._new_db()
        instrument = self._seed_instrument(db)
        other = create_instrument(db, {
            "code": "INSTR-OTRO", "name": "Otro instrumento",
            "version": "1.0", "status": "ACTIVO",
            "items": [{
                "code": "OT-01", "dimension": "datos",
                "statement": "Enunciado de otro instrumento", "weight": 1,
            }],
        }, "admin.test")
        with self.assertRaises(ExpertReviewValidationError):
            self._submit(
                db, instrument, "EVL-ITEM-AJENO", "CUMPLE",
                answers=[{"item_id": other["items"][0]["id"], "score": 3}],
            )
        self.assertEqual(db.list_expert_reviews(), [])
        db.close()

    def test_09_answer_out_of_scale_is_rejected(self):
        """Una respuesta fuera de la escala del instrumento se rechaza."""
        from database import ExpertReviewValidationError

        db = self._new_db()
        instrument = self._seed_instrument(db)
        with self.assertRaises(ExpertReviewValidationError):
            self._submit(
                db, instrument, "EVL-FUERA", "CUMPLE",
                answers=[{"item_id": instrument["items"][0]["id"], "score": 6}],
            )
        self.assertEqual(db.list_expert_reviews(), [])
        db.close()

    def test_10_duplicate_answer_item_is_rejected(self):
        """Dos respuestas al mismo item se rechazan."""
        from database import ExpertReviewValidationError

        db = self._new_db()
        instrument = self._seed_instrument(db)
        item_id = instrument["items"][0]["id"]
        with self.assertRaises(ExpertReviewValidationError):
            self._submit(
                db, instrument, "EVL-DUPLICADO", "CUMPLE",
                answers=[
                    {"item_id": item_id, "score": 3},
                    {"item_id": item_id, "score": 4},
                ],
            )
        self.assertEqual(db.list_expert_reviews(), [])
        db.close()

    def test_11_score_is_the_descriptive_weighted_mean(self):
        """El score guardado es la media ponderada de las respuestas, redondeada."""
        db = self._new_db()
        instrument = self._seed_instrument(db)
        by_code = {item["code"]: item for item in instrument["items"]}
        # ID-01 pesa 2 y DIS-02 pesa 1: (5*2 + 2*1) / 3 = 4.0
        review = self._submit(
            db, instrument, "EVL-PESO", "CUMPLE_PARCIALMENTE",
            answers=[
                {"item_id": by_code["ID-01"]["id"], "score": 5},
                {"item_id": by_code["DIS-02"]["id"], "score": 2},
            ],
        )
        expected = round((5 * 2 + 2 * 1) / 3.0, 2)
        self.assertEqual(review["score"], expected)
        stored = db.get_expert_review("EVL-PESO")
        self.assertEqual(stored["score"], expected)
        self.assertEqual(stored["verdict"], "CUMPLE_PARCIALMENTE")
        db.close()

    def test_12_verdict_is_not_derived_from_the_score(self):
        """Mismas respuestas y veredictos distintos: se guardan como se declaran."""
        db = self._new_db()
        instrument = self._seed_instrument(db)
        answers = [
            {"item_id": instrument["items"][0]["id"], "score": 4},
            {"item_id": instrument["items"][1]["id"], "score": 4},
        ]
        positive = self._submit(db, instrument, "EVL-CUMPLE", "CUMPLE", answers=answers)
        negative = self._submit(db, instrument, "EVL-NO-CUMPLE", "NO_CUMPLE", answers=answers)

        self.assertEqual(positive["score"], negative["score"])
        self.assertEqual(positive["verdict"], "CUMPLE")
        self.assertEqual(negative["verdict"], "NO_CUMPLE")
        self.assertEqual(db.get_expert_review("EVL-CUMPLE")["verdict"], "CUMPLE")
        self.assertEqual(db.get_expert_review("EVL-NO-CUMPLE")["verdict"], "NO_CUMPLE")
        db.close()

    def test_13_synthetic_is_forced_and_stays_immutable(self):
        """El servidor fuerza synthetic = 1 aunque el payload declare 0."""
        from validation_management import create_instrument

        db = self._new_db()
        instrument = create_instrument(db, {
            "code": "INSTR-SINT", "name": "Instrumento con sinteticidad declarada",
            "version": "1.0", "status": "ACTIVO", "synthetic": 0,
            "items": [{
                "code": "S-01", "dimension": "red",
                "statement": "Enunciado verificable de prueba", "weight": 1,
            }],
        }, "admin.test")
        self.assertEqual(instrument["synthetic"], 1)

        review = self._submit(db, instrument, "EVL-SINT", "CUMPLE", synthetic=0)
        self.assertEqual(review["synthetic"], 1)
        self.assertEqual(db.get_instrument("INSTR-SINT")["synthetic"], 1)
        self.assertEqual(db.get_expert_review("EVL-SINT")["synthetic"], 1)
        db.close()

    # ---------------------------------------------------------------- atomicidad
    def test_14_atomic_rollback_on_instrument_creation(self):
        """Si la auditoria falla, no queda ni instrumento ni item huerfano."""
        from validation_management import seed_instrument_payload

        db = self._new_db()
        with self.assertRaises(Exception):
            db.insert_instrument_with_audit_event(
                seed_instrument_payload(), {"actor": "TEST"}
            )
        self.assertEqual(db.list_instruments(), [])
        self.assertEqual(db.monitoring_query("SELECT id FROM instrument_items"), [])
        db.close()

    def test_15_atomic_rollback_on_review_submission(self):
        """Si la auditoria falla, no queda ni dictamen ni respuesta huerfana."""
        db = self._new_db()
        instrument = self._seed_instrument(db)
        with self.assertRaises(Exception):
            db.insert_expert_review_with_audit_event({
                "code": "EVL-ROLLBACK",
                "instrument_id": instrument["id"],
                "expert_name": SYNTHETIC_EXPERT,
                "expert_role": "revisor sintetico de pruebas",
                "verdict": "CUMPLE",
                "score": 4.0,
                "answers": [{
                    "item_id": instrument["items"][0]["id"],
                    "score": 4,
                    "comment": "",
                }],
            }, {"actor": "TEST"})
        self.assertEqual(db.list_expert_reviews(), [])
        self.assertEqual(db.monitoring_query("SELECT id FROM expert_review_answers"), [])
        db.close()

    # ------------------------------------------------------------------ evidencia
    def test_16_every_evidence_item_declares_reference_and_source(self):
        """Cada elemento trae reference y source reales, y O1..O4 tienen contenido."""
        from incident_management import create_incident
        from report_management import derive_evidence

        db = self._new_db()
        self._seed_instrument(db)
        self._seed_assets(db, ["activo-f5"])
        db.insert_asset_evaluation_with_audit_event({
            "id": "EVA-F5-01",
            "asset_id": "AST-ACTIVOF5",
            "evaluated_by": "admin.test",
            "criticality": "high",
            "notes": "evaluacion de prueba F5",
            "findings_count": 1,
        }, SEED_AUDIT_EVENT)
        self._seed_risks(db, ["RSK-F5-EVID"])
        self._insert_finding(db)
        self._insert_control(db)
        create_incident(
            db,
            {"code": "INC-F5-EVID", "title": "Incidente de prueba F5", "severity": "ALTA"},
            "admin.test",
        )

        evidence = derive_evidence(db)
        items = [item for group in evidence["objectives"] for item in group["items"]]
        self.assertTrue(items)
        for item in items:
            self.assertTrue(str(item["reference"]).strip(), item)
            self.assertTrue(str(item["source"]).strip(), item)
            self.assertNotEqual(item["source"], "undeclared", item)
        modules = {item["module"] for item in items}
        for module in ("M2", "M3", "M4", "M5", "M6"):
            self.assertIn(module, modules)
        db.close()

    def test_17_empty_objective_is_declared_empty(self):
        """Un objetivo sin filas reales se declara vacio; no se rellena."""
        from report_management import derive_evidence

        db = self._new_db()
        evidence = derive_evidence(db)
        groups = {group["objective"]: group for group in evidence["objectives"]}
        self.assertEqual(set(groups), {"O1", "O2", "O3", "O4"})
        for objective in ("O1", "O2", "O3"):
            self.assertTrue(groups[objective]["empty"])
            self.assertEqual(groups[objective]["count"], 0)
            self.assertEqual(groups[objective]["declaration"], "SIN_EVIDENCIA")
        filtered = derive_evidence(db, "O3")["objectives"][0]
        self.assertTrue(filtered["empty"])
        db.close()

    def test_18_evidence_filter_returns_only_that_objective(self):
        """El filtro por objetivo devuelve solo elementos de ese objetivo."""
        from report_management import derive_evidence

        db = self._new_db()
        self._insert_finding(db)
        self._seed_risks(db, ["RSK-F5-FILTRO"])
        evidence = derive_evidence(db, "O1")
        self.assertEqual(evidence["objective_filter"], "O1")
        self.assertEqual(len(evidence["objectives"]), 1)
        self.assertTrue(evidence["objectives"][0]["items"])
        self.assertTrue(all(
            item["objective"] == "O1" for item in evidence["objectives"][0]["items"]
        ))
        db.close()

    # ------------------------------------------------------------------- informes
    def test_19_report_markdown_has_the_mandatory_sections(self):
        """El informe incluye cabecera, modulos, metricas, evidencia, sinteticos y limitaciones."""
        from report_management import generate_report

        db = self._new_db()
        self._insert_finding(db)
        report = generate_report(db, {
            "title": "Informe de prueba O1",
            "objective": "O1",
            "period_from": "2000-01-01",
            "period_to": "2099-12-31",
        }, "admin.test", now=1700000000.0)

        content = report["content"]
        for section in (
            "## Modulos implicados y estado real",
            "## Metricas reales",
            "## Referencias de evidencia",
            "## Datos sinteticos",
            "## Limitaciones",
        ):
            self.assertIn(section, content)
        self.assertIn("- Objetivo: O1", content)
        self.assertIn("- Periodo: 2000-01-01 a 2099-12-31", content)
        self.assertIn("- Fecha de generacion:", content)
        self.assertIn("- Autor: admin.test", content)
        db.close()

    def test_20_report_hash_and_code_are_deterministic(self):
        """Mismo contenido y periodo producen el mismo hash, codigo y una sola fila."""
        from report_management import generate_report

        db = self._new_db()
        payload = {
            "objective": "O1",
            "period_from": "2000-01-01",
            "period_to": "2099-12-31",
        }
        first = generate_report(db, payload, "admin.test", now=1700000000.0)
        second = generate_report(db, payload, "admin.test", now=1700000000.0)
        self.assertEqual(first["code"], second["code"])
        self.assertEqual(first["content"], second["content"])
        self.assertEqual(
            first["content_hash"],
            hashlib.sha256(first["content"].encode("utf-8")).hexdigest(),
        )
        self.assertEqual(first["code"], "RPT-O1-" + first["content_hash"][:8].upper())
        self.assertEqual(len(db.list_reports()), 1)

        other = generate_report(db, {**payload, "period_from": "2001-01-01"},
                                "admin.test", now=1700000000.0)
        self.assertNotEqual(first["content_hash"], other["content_hash"])
        db.close()

    def test_21_report_without_expert_reviews_says_so(self):
        """Sin dictamenes, el informe lo declara explicitamente en limitaciones."""
        from report_management import generate_report

        db = self._new_db()
        report = generate_report(db, {
            "objective": "O2",
            "period_from": "2000-01-01",
            "period_to": "2099-12-31",
        }, "admin.test", now=1700000000.0)
        self.assertIn("No hay dictamenes de expertos registrados", report["content"])
        self.assertIn("expert_reviews = 0", report["content"])
        db.close()

    def test_22_report_metrics_match_the_real_database(self):
        """Las metricas del informe coinciden con lo que hay en la base, no son constantes."""
        from report_management import generate_report

        db = self._new_db()
        self._seed_risks(db, ["RSK-F5-M1", "RSK-F5-M2", "RSK-F5-M3"])
        report = generate_report(db, {
            "objective": "O2",
            "period_from": "2000-01-01",
            "period_to": "2099-12-31",
        }, "admin.test", now=1700000000.0)
        real_total = len(db.list_risks())
        self.assertEqual(real_total, 3)
        self.assertIn("Riesgos registrados: 3", report["content"])
        self.assertIn("Elementos de evidencia en el periodo: 3", report["content"])
        db.close()

    def test_23_report_declares_a_period_without_data(self):
        """Un periodo sin datos se declara vacio explicitamente."""
        from report_management import generate_report

        db = self._new_db()
        self._insert_finding(db)
        report = generate_report(db, {
            "objective": "O1",
            "period_from": "1990-01-01",
            "period_to": "1990-12-31",
        }, "admin.test", now=1700000000.0)
        self.assertIn("se declara VACIO", report["content"])
        self.assertIn("no tiene evidencia registrada", report["content"])
        db.close()

    def test_24_report_counts_synthetic_and_real_records(self):
        """La seccion de sinteticos cuenta los registros reales por su bandera."""
        from report_management import generate_report

        db = self._new_db()
        self._seed_risks(db, ["RSK-F5-SINT"], synthetic=1)
        self._seed_risks(db, ["RSK-F5-REAL"], synthetic=0)
        report = generate_report(db, {
            "objective": "O2",
            "period_from": "2000-01-01",
            "period_to": "2099-12-31",
        }, "admin.test", now=1700000000.0)
        self.assertIn("Elementos sinteticos (synthetic = 1): 1", report["content"])
        self.assertIn("Elementos no sinteticos (synthetic = 0): 1", report["content"])
        db.close()

    def test_25_stored_report_keeps_its_hash_and_content(self):
        """El informe recuperado conserva el contenido integro y su hash."""
        from report_management import generate_report, get_report

        db = self._new_db()
        report = generate_report(db, {
            "objective": "O3",
            "period_from": "2000-01-01",
            "period_to": "2099-12-31",
        }, "admin.test", now=1700000000.0)
        stored = get_report(db, report["code"])
        self.assertIsNotNone(stored)
        self.assertEqual(stored["content"], report["content"])
        self.assertEqual(
            stored["content_hash"],
            hashlib.sha256(stored["content"].encode("utf-8")).hexdigest(),
        )
        db.close()


class F5ApiSuite(unittest.TestCase):
    """Pruebas HTTP de F5 contra el stack ya arrancado (RBAC y contrato de rutas)."""

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

    def _unique(self, prefix):
        return f"{prefix}-{int(time.time() * 1000) % 10000000}"

    def _seeded_instrument(self, token):
        status, body = self.call(token, "GET", "/api/v1/instruments/INSTR-F11-ZTA-01")
        if status != 200:
            raise unittest.SkipTest(
                f"el instrumento semilla no esta disponible (HTTP {status}: {body})"
            )
        return body["instrument"]

    def _instrument_payload(self, code):
        return {
            "code": code,
            "name": "Instrumento de prueba F5",
            "description": "Instrumento sintetico creado por la suite F5",
            "version": "1.0",
            "scale_min": 1,
            "scale_max": 5,
            "status": "ACTIVO",
            "synthetic": 0,  # el servidor debe imponer 1
            "items": [
                {
                    "code": "T-01",
                    "dimension": "identidad",
                    "statement": "Enunciado verificable de prueba uno",
                    "weight": 2,
                },
                {
                    "code": "T-02",
                    "dimension": "monitoreo",
                    "statement": "Enunciado verificable de prueba dos",
                    "weight": 1,
                },
            ],
        }

    def _review_payload(self, instrument, code, answers=None, verdict="CUMPLE_PARCIALMENTE"):
        if answers is None:
            answers = [
                {"item_id": instrument["items"][0]["id"], "score": 5},
                {"item_id": instrument["items"][1]["id"], "score": 2},
            ]
        return {
            "code": code,
            "instrument_id": instrument["id"],
            "expert_name": SYNTHETIC_EXPERT,
            "expert_role": "revisor sintetico de pruebas",
            "expert_affiliation": "ninguna (sintetica)",
            "scope": "prueba automatizada F5",
            "verdict": verdict,
            "observations": "dictamen sintetico de prueba",
            "reviewed_at": "2026-10-22",
            "synthetic": 0,  # el servidor debe imponer 1
            "answers": answers,
        }

    # ------------------------------------------------------------------- lectura
    def test_26_auditor_reads_instruments_and_seeded_detail(self):
        """El auditor lista instrumentos y ve el semilla con sus >= 12 items."""
        token = self.token("auditor.test")
        status, body = self.call(token, "GET", "/api/v1/instruments")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(body["count"], 1)
        self.assertIn("INSTR-F11-ZTA-01", {i["code"] for i in body["instruments"]})

        instrument = self._seeded_instrument(token)
        self.assertEqual(instrument["version"], "1.0")
        self.assertEqual(instrument["status"], "ACTIVO")
        self.assertEqual(instrument["synthetic"], 1)
        self.assertGreaterEqual(len(instrument["items"]), 12)
        self.assertEqual(
            {item["dimension"] for item in instrument["items"]},
            {"identidad", "dispositivo", "red", "aplicacion", "datos", "monitoreo"},
        )

    def test_27_auditor_reads_validations(self):
        """El auditor consulta la lista de dictamenes registrados."""
        token = self.token("auditor.test")
        status, body = self.call(token, "GET", "/api/v1/validations")
        self.assertEqual(status, 200)
        self.assertIn("validations", body)
        self.assertEqual(body["count"], len(body["validations"]))

    def test_28_auditor_cannot_create_or_generate(self):
        """El auditor lee pero no da de alta instrumentos, dictamenes ni informes."""
        token = self.token("auditor.test")
        status, body = self.call(
            token, "POST", "/api/v1/instruments", self._instrument_payload(self._unique("INSTR-RBAC"))
        )
        self.assertEqual(status, 403)
        self.assertEqual(body.get("code"), "PLATFORM_ADMIN_ROLE_REQUIRED")

        status, body = self.call(
            token, "POST", "/api/v1/validations",
            {"code": self._unique("EVL-RBAC"), "verdict": "CUMPLE", "answers": []},
        )
        self.assertEqual(status, 403)
        self.assertEqual(body.get("code"), "PLATFORM_ADMIN_ROLE_REQUIRED")

        status, body = self.call(token, "POST", "/api/v1/reports", {
            "objective": "O1", "period_from": "2000-01-01", "period_to": "2099-12-31",
        })
        self.assertEqual(status, 403)
        self.assertEqual(body.get("code"), "PLATFORM_ADMIN_ROLE_REQUIRED")

    def test_29_clinical_roles_are_denied_f5_routes(self):
        """Recepcion y laboratorio no acceden a instrumentos, dictamenes, evidencia ni informes."""
        for username in ("recepcion.test", "laboratorio.test"):
            token = self.token(username)
            for path, code in (
                ("/api/v1/instruments", "INSTRUMENTS_ROLE_REQUIRED"),
                ("/api/v1/validations", "VALIDATIONS_ROLE_REQUIRED"),
                ("/api/v1/evidence", "EVIDENCE_ROLE_REQUIRED"),
                ("/api/v1/reports", "REPORTS_ROLE_REQUIRED"),
            ):
                status, body = self.call(token, "GET", path)
                self.assertEqual(status, 403, f"{username} {path}")
                self.assertEqual(body.get("code"), code, f"{username} {path}")

    # ---------------------------------------------------------------------- RBAC
    def test_30_admin_without_mfa_is_denied_writes(self):
        """El administrador sin OTP no crea instrumentos, dictamenes ni informes."""
        token = self.token("medico.sinmfa")
        status, body = self.call(
            token, "POST", "/api/v1/instruments",
            self._instrument_payload(self._unique("INSTR-NOMFA")),
        )
        self.assertEqual(status, 403)
        self.assertEqual(body.get("code"), "MFA_AUTHENTICATION_REQUIRED")

        status, body = self.call(token, "POST", "/api/v1/validations", {
            "code": self._unique("EVL-NOMFA"), "verdict": "CUMPLE", "answers": [],
        })
        self.assertEqual(status, 403)
        self.assertEqual(body.get("code"), "MFA_AUTHENTICATION_REQUIRED")

        status, body = self.call(token, "POST", "/api/v1/reports", {
            "objective": "O1", "period_from": "2000-01-01", "period_to": "2099-12-31",
        })
        self.assertEqual(status, 403)
        self.assertEqual(body.get("code"), "MFA_AUTHENTICATION_REQUIRED")

    def test_31_admin_creates_instrument_with_synthetic_forced(self):
        """El administrador con MFA crea el instrumento y el servidor fuerza synthetic = 1."""
        token = self.token("medico.test")
        code = self._unique("INSTR-API")
        status, body = self.call(
            token, "POST", "/api/v1/instruments", self._instrument_payload(code)
        )
        self.assertEqual(status, 201, body)
        instrument = body["instrument"]
        self.assertEqual(instrument["code"], code)
        self.assertEqual(instrument["synthetic"], 1)
        self.assertEqual(len(instrument["items"]), 2)

        status, body = self.call(
            token, "POST", "/api/v1/instruments", self._instrument_payload(code)
        )
        self.assertEqual(status, 409)
        self.assertEqual(body.get("code"), "INSTRUMENT_ALREADY_EXISTS")

    def test_32_invalid_instrument_is_rejected(self):
        """Una escala incoherente devuelve 400 con el codigo estable."""
        token = self.token("medico.test")
        payload = self._instrument_payload(self._unique("INSTR-ESC"))
        payload["scale_min"] = 5
        payload["scale_max"] = 1
        status, body = self.call(token, "POST", "/api/v1/instruments", payload)
        self.assertEqual(status, 400)
        self.assertEqual(body.get("code"), "INSTRUMENT_INVALID")
        self.assertIn("escala", body.get("fields", {}))

    def test_33_admin_registers_a_synthetic_expert_review(self):
        """El dictamen se registra con su veredicto declarado y score descriptivo real."""
        token = self.token("medico.test")
        instrument = self._seeded_instrument(token)
        by_code = {item["code"]: item for item in instrument["items"]}
        answers = [
            {"item_id": by_code["ID-01"]["id"], "score": 5},
            {"item_id": by_code["ID-02"]["id"], "score": 4},
        ]
        code = self._unique("EVL-API")
        status, body = self.call(
            token, "POST", "/api/v1/validations",
            self._review_payload(instrument, code, answers=answers, verdict="CUMPLE"),
        )
        self.assertEqual(status, 201, body)
        review = body["validation"]
        self.assertEqual(review["code"], code)
        self.assertEqual(review["verdict"], "CUMPLE")
        self.assertEqual(review["expert_name"], SYNTHETIC_EXPERT)
        self.assertEqual(review["synthetic"], 1)
        expected = round((5 * by_code["ID-01"]["weight"] + 4 * by_code["ID-02"]["weight"])
                         / (by_code["ID-01"]["weight"] + by_code["ID-02"]["weight"]), 2)
        self.assertEqual(review["score"], expected)
        self.assertEqual(len(review["answers"]), 2)

        status, detail = self.call(token, "GET", "/api/v1/validations/" + review["id"])
        self.assertEqual(status, 200)
        self.assertEqual(detail["validation"]["verdict"], "CUMPLE")
        self.assertEqual(len(detail["validation"]["answers"]), 2)

    def test_34_invalid_validation_payloads_are_rejected(self):
        """Un veredicto fuera de catalogo es 400 y un instrumento inexistente es 404."""
        token = self.token("medico.test")
        instrument = self._seeded_instrument(token)
        status, body = self.call(
            token, "POST", "/api/v1/validations",
            self._review_payload(instrument, self._unique("EVL-INV"), verdict="APROBADO"),
        )
        self.assertEqual(status, 400)
        self.assertEqual(body.get("code"), "VALIDATION_INVALID")

        payload = self._review_payload(instrument, self._unique("EVL-NOINS"))
        payload["instrument_id"] = "INSTR-NO-EXISTE"
        status, body = self.call(token, "POST", "/api/v1/validations", payload)
        self.assertEqual(status, 404)
        self.assertEqual(body.get("code"), "INSTRUMENT_NOT_FOUND")

    # ------------------------------------------------------------------- informes
    def test_35_admin_generates_a_real_report(self):
        """El administrador genera un informe con secciones obligatorias y hash verificable."""
        token = self.token("medico.test")
        status, body = self.call(token, "POST", "/api/v1/reports", {
            "title": "Informe de prueba F5 O2",
            "objective": "O2",
            "period_from": "2000-01-01",
            "period_to": "2099-12-31",
        })
        self.assertEqual(status, 201, body)
        report = body["report"]
        self.assertEqual(report["objective"], "O2")
        self.assertEqual(report["synthetic"], 1)
        self.assertEqual(
            report["content_hash"],
            hashlib.sha256(report["content"].encode("utf-8")).hexdigest(),
        )
        self.assertEqual(report["code"], "RPT-O2-" + report["content_hash"][:8].upper())
        for section in (
            "## Modulos implicados y estado real",
            "## Metricas reales",
            "## Referencias de evidencia",
            "## Datos sinteticos",
            "## Limitaciones",
        ):
            self.assertIn(section, report["content"])

        status, detail = self.call(token, "GET", "/api/v1/reports/" + report["id"])
        self.assertEqual(status, 200)
        self.assertEqual(detail["report"]["content"], report["content"])

        status, listing = self.call(token, "GET", "/api/v1/reports")
        self.assertEqual(status, 200)
        self.assertIn(report["code"], {r["code"] for r in listing["reports"]})

    def test_36_report_rejects_invalid_objective(self):
        """Un objetivo fuera de O1..O4 devuelve 400 REPORT_INVALID."""
        token = self.token("medico.test")
        status, body = self.call(token, "POST", "/api/v1/reports", {
            "objective": "O9",
            "period_from": "2000-01-01",
            "period_to": "2099-12-31",
        })
        self.assertEqual(status, 400)
        self.assertEqual(body.get("code"), "REPORT_INVALID")

    def test_37_report_metrics_match_the_evidence_endpoint(self):
        """El conteo de evidencia del informe coincide con /api/v1/evidence (no es fijo)."""
        token = self.token("medico.test")
        status, evidence = self.call(token, "GET", "/api/v1/evidence?objective=O2")
        self.assertEqual(status, 200)
        real_count = evidence["objectives"][0]["count"]

        status, body = self.call(token, "POST", "/api/v1/reports", {
            "objective": "O2",
            "period_from": "2000-01-01",
            "period_to": "2099-12-31",
        })
        self.assertEqual(status, 201, body)
        self.assertIn(
            "Elementos de evidencia en el periodo: %d" % real_count,
            body["report"]["content"],
        )

    # ------------------------------------------------------------------ evidencia
    def test_38_evidence_declares_reference_source_and_filter(self):
        """La evidencia trae reference/source reales y el filtro aisla el objetivo."""
        token = self.token("auditor.test")
        status, body = self.call(token, "GET", "/api/v1/evidence")
        self.assertEqual(status, 200)
        self.assertEqual(
            [group["objective"] for group in body["objectives"]],
            ["O1", "O2", "O3", "O4"],
        )
        items = [item for group in body["objectives"] for item in group["items"]]
        self.assertTrue(items)
        for item in items:
            self.assertTrue(str(item["reference"]).strip())
            self.assertTrue(str(item["source"]).strip())

        status, filtered = self.call(token, "GET", "/api/v1/evidence?objective=O4")
        self.assertEqual(status, 200)
        self.assertEqual(len(filtered["objectives"]), 1)
        self.assertEqual(filtered["objectives"][0]["objective"], "O4")
        self.assertTrue(all(
            item["objective"] == "O4" for item in filtered["objectives"][0]["items"]
        ))

        status, body = self.call(token, "GET", "/api/v1/evidence?objective=O9")
        self.assertEqual(status, 400)
        self.assertEqual(body.get("code"), "EVIDENCE_OBJECTIVE_INVALID")

    def test_39_unknown_ids_return_stable_not_found_codes(self):
        """Los recursos inexistentes devuelven 404 con su codigo estable."""
        token = self.token("auditor.test")
        for path, code in (
            ("/api/v1/instruments/INSTR-NO-EXISTE", "INSTRUMENT_NOT_FOUND"),
            ("/api/v1/validations/EVL-NO-EXISTE", "VALIDATION_NOT_FOUND"),
            ("/api/v1/reports/RPT-NO-EXISTE", "REPORT_NOT_FOUND"),
        ):
            status, body = self.call(token, "GET", path)
            self.assertEqual(status, 404, path)
            self.assertEqual(body.get("code"), code, path)
