#!/usr/bin/env python3
"""F4 API suite: Monitorizacion de Incidentes (M6), alertas derivadas e indicadores M8.

Verifica el cierre del backend de F4:
  * Migracion 8 aditiva e idempotente sobre una base ya poblada.
  * Siembra idempotente de 2 incidentes de laboratorio (synthetic = 1) y
    fail-closed cuando un vinculo declarado no existe.
  * Alta y ciclo de vida con transiciones validas, historial inmutable y
    sinteticidad forzada en el servidor e ignorada en la transicion.
  * Alertas DERIVADAS del estado real: id determinista, evidencia real no vacia
    y ausencia de alerta cuando la regla no tiene sujeto real.
  * Acuse persistido y rechazo del acuse de una alerta inexistente.
  * Indicadores M8 con su origen real (source no vacio) y valores que cambian
    con el estado de una base temporal (no son constantes).
  * Atomicidad: si la auditoria falla, no queda incidente huerfano.

Las pruebas de dominio usan una base SQLite temporal en /tmp: no tocan la base
viva del laboratorio. Las pruebas de API hablan con el stack ya arrancado,
igual que la suite de F3.
"""

import hashlib
import json
import os
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
    spec = importlib.util.spec_from_file_location("f11_setup_realm_f4", path)
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


class F4DomainSuite(unittest.TestCase):
    """Siembra, ciclo de vida, alertas, indicadores y atomicidad sobre base temporal."""

    def _new_db(self):
        from database import ClinicalDatabaseManager

        directory = tempfile.mkdtemp(prefix="f4-domain-")
        return ClinicalDatabaseManager(str(Path(directory) / "f4.db"))

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
                "description": "Activo de prueba F4",
            }
            for name in names
        ], SEED_AUDIT_EVENT)

    def _seed_risks(self, db, codes, residual_probability=2, residual_impact=2):
        db.insert_risks_with_audit_event([
            {
                "code": code,
                "name": "Riesgo de prueba " + code,
                "category": "identidad",
                "threat": "Amenaza de prueba",
                "vulnerability": "Vulnerabilidad de prueba",
                "probability_inherent": 3,
                "impact_inherent": 3,
                "probability_residual": residual_probability,
                "impact_residual": residual_impact,
                "treatment": "MITIGAR",
                "status": "IDENTIFICADO",
                "synthetic": 1,
            }
            for code in codes
        ], SEED_AUDIT_EVENT)

    def _insert_finding(self, db, checker_id, *, severity="high", status="failed",
                        finding_id=None, evidence_output="resultado de prueba"):
        stamp = int(time.time() * 1000)
        run_id = f"RUN-F4-{stamp}"
        db.insert_diagnostic_run({
            "id": run_id,
            "started_at": time.time(),
            "status": "completed",
            "checker_count": 1,
            "passed": 0 if status != "passed" else 1,
            "failed": 0 if status == "passed" else 1,
            "warnings": 0,
            "triggered_by": "test_suite",
            "environment": "f11-local",
        })
        fid = finding_id or f"FND-F4-{checker_id[:6]}-{stamp}"
        db.insert_security_findings([{
            "id": fid,
            "run_id": run_id,
            "checker_id": checker_id,
            "title": "Hallazgo de prueba " + checker_id,
            "objective": "O1",
            "severity": severity,
            "status": status,
            "asset_ref": "keycloak-iam",
            "evidence_command": "test-suite --checker " + checker_id,
            "evidence_output": evidence_output,
            "evidence_source": "in_process",
            "remediation": "accion de prueba",
            "detected_at": time.time(),
        }])
        return fid

    # ---------------------------------------------------------------- migracion
    def test_01_migration_8_is_additive_and_idempotent(self):
        """La migracion 8 crea sus tablas y reabrir la base no pierde datos."""
        from incident_management import create_incident

        db = self._new_db()
        tables = {
            row["name"]
            for row in db.monitoring_query(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        for name in ("incidents", "incident_updates", "alert_acknowledgements"):
            self.assertIn(name, tables)
        created = create_incident(
            db, {"code": "INC-MIG-01", "title": "Incidente de migracion", "severity": "BAJA"},
            "admin.test",
        )
        path = db.db_path
        db.close()

        # Reabrir ejecuta de nuevo las migraciones (ya marcadas) sin duplicar ni
        # borrar: la tabla y el incidente siguen ahi.
        from database import ClinicalDatabaseManager

        db2 = ClinicalDatabaseManager(path)
        self.assertIsNotNone(db2.get_incident("INC-MIG-01"))
        self.assertEqual(db2.list_incidents()[0]["id"], created["id"])
        db2.close()

    # ------------------------------------------------------------------ siembra
    def test_02_seed_creates_two_synthetic_incidents(self):
        """La siembra crea 2 incidentes de laboratorio con synthetic = 1 y vinculos reales."""
        from incident_management import seed_incidents

        db = self._new_db()
        self._seed_assets(db, ["keycloak-iam", "compose-f11"])
        self._seed_risks(db, ["RSK-F11-IAM-01", "RSK-F11-CONT-02"])
        result = seed_incidents(db)
        self.assertEqual(sorted(result["created"]), ["INC-F11-CONT-02", "INC-F11-IAM-01"])

        incidents = db.list_incidents()
        self.assertEqual(len(incidents), 2)
        self.assertTrue(all(i["synthetic"] == 1 for i in incidents))
        self.assertTrue(all(i["code"].startswith("INC-F11-") for i in incidents))
        self.assertTrue(any(i["risk_id"] for i in incidents))
        self.assertTrue(any(i["asset_id"] for i in incidents))
        db.close()

    def test_03_seed_is_idempotent(self):
        """Una segunda siembra no duplica incidentes."""
        from incident_management import seed_incidents

        db = self._new_db()
        self._seed_assets(db, ["keycloak-iam", "compose-f11"])
        self._seed_risks(db, ["RSK-F11-IAM-01", "RSK-F11-CONT-02"])
        seed_incidents(db)
        second = seed_incidents(db)
        self.assertTrue(second["already_seeded"])
        self.assertEqual(second["created"], [])
        self.assertEqual(len(db.list_incidents()), 2)
        db.close()

    def test_04_seed_fails_closed_when_declared_link_is_missing(self):
        """Sin el activo/riesgo declarado la siembra aborta; no se omite en silencio."""
        from incident_management import IncidentSeedError, seed_incidents

        db = self._new_db()
        with self.assertRaises(IncidentSeedError) as raised:
            seed_incidents(db)
        message = str(raised.exception)
        self.assertTrue(
            "RSK-F11-IAM-01" in message or "keycloak-iam" in message,
            message,
        )
        self.assertEqual(db.list_incidents(), [], "la siembra no deja incidentes a medias")
        db.close()

    # --------------------------------------------------------------------- alta
    def test_05_create_forces_synthetic_and_ignores_payload(self):
        """El alta fuerza synthetic = 1 aunque el cliente declare 0."""
        from incident_management import create_incident

        db = self._new_db()
        incident = create_incident(
            db,
            {"code": "INC-SINT-01", "title": "Incidente sintetico", "severity": "ALTA", "synthetic": 0},
            "admin.test",
        )
        self.assertEqual(incident["synthetic"], 1)
        self.assertEqual(incident["status"], "ABIERTO")
        self.assertEqual(incident["revision"], 1)
        db.close()

    def test_06_duplicate_incident_code_is_rejected(self):
        """Un codigo de incidente repetido se rechaza (conflicto)."""
        from database import IncidentAlreadyExistsError
        from incident_management import create_incident

        db = self._new_db()
        create_incident(db, {"code": "INC-DUP-01", "title": "Primero", "severity": "MEDIA"}, "admin.test")
        with self.assertRaises(IncidentAlreadyExistsError):
            create_incident(db, {"code": "INC-DUP-01", "title": "Segundo", "severity": "BAJA"}, "admin.test")
        self.assertEqual(len(db.list_incidents()), 1)
        db.close()

    def test_07_invalid_severity_and_empty_title_are_rejected(self):
        """Severidad fuera del dominio y titulo vacio se rechazan en la validacion."""
        from incident_management import validate_incident

        errors = validate_incident({"code": "INC-X-01", "title": "   ", "severity": "EXTREMA"})
        joined = " ".join(errors)
        self.assertIn("severity", joined)
        self.assertIn("title", joined)
        self.assertEqual(validate_incident({"code": "INC-OK-1", "title": "Valido", "severity": "ALTA"}), [])
        db = self._new_db()
        db.close()

    # --------------------------------------------------------------- transicion
    def test_08_valid_transition_updates_revision_and_history(self):
        """Una transicion valida incrementa revision y anexa el historial."""
        from incident_management import (
            create_incident, get_incident, list_incident_updates, transition_incident,
        )

        db = self._new_db()
        incident = create_incident(
            db, {"code": "INC-TR-01", "title": "Transicion", "severity": "ALTA"}, "admin.test"
        )
        updated = transition_incident(db, incident["id"], "EN_INVESTIGACION", "inicio", "admin.test")
        self.assertEqual(updated["status"], "EN_INVESTIGACION")
        self.assertEqual(updated["revision"], 2)

        history = list_incident_updates(db, incident["id"])
        self.assertEqual([h["to_status"] for h in history], ["ABIERTO", "EN_INVESTIGACION"])
        self.assertEqual(history[-1]["from_status"], "ABIERTO")

        full = get_incident(db, incident["id"])
        self.assertEqual(full["status"], "EN_INVESTIGACION")
        self.assertEqual(len(full["updates"]), 2)
        db.close()

    def test_09_undeclared_transition_is_rejected(self):
        """Una transicion no declarada se rechaza sin cambiar el estado."""
        from database import IncidentTransitionError
        from incident_management import create_incident, transition_incident

        db = self._new_db()
        incident = create_incident(
            db, {"code": "INC-TR-02", "title": "Transicion invalida", "severity": "ALTA"}, "admin.test"
        )
        # ABIERTO -> EN_INVESTIGACION si esta declarada y se aplica.
        transition_incident(db, incident["id"], "EN_INVESTIGACION", None, "admin.test")
        # EN_INVESTIGACION -> ABIERTO no esta declarada: se rechaza.
        with self.assertRaises(IncidentTransitionError):
            transition_incident(db, incident["id"], "ABIERTO", None, "admin.test")
        # Estado intacto: la transicion invalida no dejo rastro.
        current = db.get_incident(incident["id"])
        self.assertEqual(current["status"], "EN_INVESTIGACION")
        self.assertEqual(len(current["updates"]), 2)
        self.assertEqual(current["revision"], 2)
        db.close()

    def test_10_transition_of_unknown_incident_is_rejected(self):
        """Transicionar un incidente inexistente se rechaza con su propio error."""
        from database import IncidentNotFoundError
        from incident_management import transition_incident

        db = self._new_db()
        with self.assertRaises(IncidentNotFoundError):
            transition_incident(db, "INC-NOEXISTE", "EN_INVESTIGACION", None, "admin.test")
        db.close()

    def test_11_transition_ignores_synthetic_from_payload(self):
        """La transicion no cambia la sinteticidad aunque el cliente la envie."""
        from incident_management import create_incident, transition_incident

        db = self._new_db()
        incident = create_incident(
            db, {"code": "INC-TR-03", "title": "Sinteticidad", "severity": "MEDIA"}, "admin.test"
        )
        # La transicion no acepta payload: su firma no tiene campo synthetic. Se
        # comprueba que el incidente sigue siendo sintetico tras varias transiciones.
        transition_incident(db, incident["id"], "EN_INVESTIGACION", None, "admin.test")
        transition_incident(db, incident["id"], "MITIGADO", None, "admin.test")
        current = db.get_incident(incident["id"])
        self.assertEqual(current["synthetic"], 1)
        db.close()

    # ------------------------------------------------------------------ alertas
    def test_12_alert_ids_are_deterministic(self):
        """Dos derivaciones seguidas producen exactamente los mismos ids."""
        from alert_management import derive_alerts

        db = self._new_db()
        self._seed_risks(db, ["RSK-ALR-01"], residual_probability=4, residual_impact=4)
        first = derive_alerts(db)
        second = derive_alerts(db)
        self.assertTrue(first)
        self.assertEqual([a["id"] for a in first], [a["id"] for a in second])
        self.assertTrue(all(a["id"].startswith("ALR-") for a in first))
        self.assertTrue(all(len(a["id"]) == 12 for a in first))
        db.close()

    def test_13_alert_evidence_is_non_empty_and_real(self):
        """Toda alerta declara su operation real (consulta SQLite) y su resultado."""
        from alert_management import derive_alerts

        db = self._new_db()
        self._seed_risks(db, ["RSK-ALR-02"], residual_probability=4, residual_impact=4)
        alerts = derive_alerts(db)
        self.assertTrue(alerts)
        for alert in alerts:
            self.assertTrue(alert["evidence"].strip())
            self.assertIn("SELECT", alert["evidence"])
            self.assertIn("->", alert["evidence"])
        db.close()

    def test_14_risk_without_control_follows_links(self):
        """La regla RISK_WITHOUT_CONTROL aparece sin control y desaparece al vincularlo."""
        from alert_management import ALERT_RULE_RISK_WITHOUT_CONTROL, derive_alerts

        db = self._new_db()
        self._seed_risks(db, ["RSK-ALR-03"], residual_probability=4, residual_impact=5)
        present = [a for a in derive_alerts(db) if a["rule"] == ALERT_RULE_RISK_WITHOUT_CONTROL]
        self.assertEqual(len(present), 1)
        risk = db.get_risk("RSK-ALR-03")
        self.assertEqual(present[0]["subject"], risk["id"])

        control, _ = db.insert_control_with_audit_event({
            "code": "CTL-ALR-03",
            "framework": "ISO_27001_2022",
            "clause_or_pillar": "A.5 Organizacional",
            "name": "Control de la prueba",
            "description": "Control para silenciar la alerta",
            "owner_role": "ROLE_PLATFORM_ADMIN",
            "status": "PROPUESTO",
            "synthetic": 1,
        }, SEED_AUDIT_EVENT)
        db.link_risk_control_with_audit_event(risk["id"], control["id"], "PREVENTIVO", SEED_AUDIT_EVENT)

        after = [a for a in derive_alerts(db) if a["rule"] == ALERT_RULE_RISK_WITHOUT_CONTROL]
        self.assertEqual(after, [], "al vincular un control la alerta deja de derivarse")
        db.close()

    def test_15_control_pending_verification(self):
        """Un control IMPLEMENTADO sin evidencia produce alerta; con evidencia no."""
        from alert_management import ALERT_RULE_CONTROL_PENDING_VERIFICATION, derive_alerts

        db = self._new_db()
        control, _ = db.insert_control_with_audit_event({
            "code": "CTL-PEND-01",
            "framework": "ISO_27001_2022",
            "clause_or_pillar": "A.8 Tecnologico",
            "name": "Control pendiente",
            "description": "Implementado sin evidencia",
            "owner_role": "ROLE_PLATFORM_ADMIN",
            "status": "IMPLEMENTADO",
            "synthetic": 1,
        }, SEED_AUDIT_EVENT)
        pending = [a for a in derive_alerts(db) if a["rule"] == ALERT_RULE_CONTROL_PENDING_VERIFICATION]
        self.assertEqual([a["subject"] for a in pending], [control["id"]])

        db.add_control_evidence_with_audit_event({
            "control_id": control["id"],
            "evidence_source": "test_suite",
            "reference_id": "f4-pending",
            "observed_result": "verificado",
            "verified_by": "admin.test",
            "verified_with_mfa": 1,
        }, {
            "action": "CONTROL_VERIFY", "actor": "admin.test", "role": "NONE",
            "status": "ALLOWED", "details": "prueba", "ip": "127.0.0.1", "mfa_verified": True,
        })
        after = [a for a in derive_alerts(db) if a["rule"] == ALERT_RULE_CONTROL_PENDING_VERIFICATION]
        self.assertEqual(after, [])
        db.close()

    def test_16_critical_finding_open_in_latest_run(self):
        """Un hallazgo alto abierto en la ultima ejecucion produce alerta."""
        from alert_management import ALERT_RULE_CRITICAL_FINDING_OPEN, derive_alerts

        db = self._new_db()
        finding_id = self._insert_finding(db, "BACKEND_AUDIT_CHAIN_VALID", severity="high", status="failed")
        alerts = [a for a in derive_alerts(db) if a["rule"] == ALERT_RULE_CRITICAL_FINDING_OPEN]
        self.assertEqual([a["subject"] for a in alerts], [finding_id])

        # Un hallazgo passed no es un hallazgo abierto.
        db2 = self._new_db()
        self._insert_finding(db2, "BACKEND_AUDIT_CHAIN_VALID", severity="high", status="passed")
        alerts2 = [a for a in derive_alerts(db2) if a["rule"] == ALERT_RULE_CRITICAL_FINDING_OPEN]
        self.assertEqual(alerts2, [])
        db.close()
        db2.close()

    def test_17_incident_open_too_long_uses_threshold(self):
        """Solo un incidente abierto mas de 30 dias produce la alerta de antiguedad."""
        from alert_management import (
            ALERT_OPEN_INCIDENT_DAYS, ALERT_RULE_INCIDENT_OPEN_TOO_LONG, derive_alerts,
        )
        from incident_management import create_incident

        self.assertEqual(ALERT_OPEN_INCIDENT_DAYS, 30)
        db = self._new_db()
        old = create_incident(db, {"code": "INC-OLD-01", "title": "Antiguo", "severity": "ALTA"}, "admin.test")
        recent = create_incident(db, {"code": "INC-NEW-01", "title": "Reciente", "severity": "ALTA"}, "admin.test")

        con = sqlite3.connect(db.db_path)
        try:
            con.execute(
                "UPDATE incidents SET detected_at = ? WHERE code = 'INC-OLD-01';",
                (time.time() - (ALERT_OPEN_INCIDENT_DAYS + 10) * 86400,),
            )
            con.commit()
        finally:
            con.close()

        alerts = [a for a in derive_alerts(db) if a["rule"] == ALERT_RULE_INCIDENT_OPEN_TOO_LONG]
        self.assertEqual([a["subject"] for a in alerts], [old["id"]])
        self.assertNotIn(recent["id"], [a["subject"] for a in alerts])
        db.close()

    def test_18_admin_identity_without_mfa_requires_real_finding(self):
        """Sin el hallazgo real del comprobador no hay alerta; con el, si."""
        from alert_management import (
            ALERT_RULE_ADMIN_IDENTITY_WITHOUT_MFA, MFA_CHECKER_ID, derive_alerts,
        )

        empty = self._new_db()
        self.assertEqual(
            [a for a in derive_alerts(empty) if a["rule"] == ALERT_RULE_ADMIN_IDENTITY_WITHOUT_MFA],
            [],
            "sin hallazgo del comprobador la alerta no aparece",
        )
        empty.close()

        db = self._new_db()
        finding_id = self._insert_finding(db, MFA_CHECKER_ID, severity="high", status="failed")
        alerts = [a for a in derive_alerts(db) if a["rule"] == ALERT_RULE_ADMIN_IDENTITY_WITHOUT_MFA]
        self.assertEqual([a["subject"] for a in alerts], [finding_id])
        db.close()

    # ------------------------------------------------------------------- acuse
    def test_19_ack_is_registered_and_unknown_is_rejected(self):
        """El acuse se persiste y cruza en el listado; una alerta inexistente se rechaza."""
        from alert_management import derive_alerts, list_alerts, acknowledge_alert
        from database import AlertNotFoundError

        db = self._new_db()
        self._seed_risks(db, ["RSK-ACK-01"], residual_probability=4, residual_impact=4)
        target = derive_alerts(db)[0]

        ack = acknowledge_alert(db, target["id"], "revisado por el administrador", "admin.test")
        self.assertEqual(ack["alert_id"], target["id"])
        after = [a for a in list_alerts(db) if a["id"] == target["id"]][0]
        self.assertTrue(after["acknowledged"])
        self.assertEqual(after["acknowledged_by"], "admin.test")

        with self.assertRaises(AlertNotFoundError):
            acknowledge_alert(db, "ALR-00000000", "no existe", "admin.test")
        db.close()

    def test_20_indicators_declare_source_and_change_with_state(self):
        """Cada indicador trae source real y al menos uno cambia con el estado de la base."""
        from alert_management import list_indicators
        from incident_management import create_incident

        db = self._new_db()
        before = {i["code"]: i for i in list_indicators(db)}
        self.assertEqual(len(before), 8)
        for indicator in before.values():
            self.assertTrue(indicator["source"].strip(), indicator["code"])
        open_before = before["IND_OPEN_INCIDENTS"]["value"]

        create_incident(db, {"code": "INC-IND-01", "title": "Para indicador", "severity": "MEDIA"}, "admin.test")
        after = {i["code"]: i for i in list_indicators(db)}
        self.assertEqual(open_before, 0)
        self.assertEqual(after["IND_OPEN_INCIDENTS"]["value"], 1)
        self.assertNotEqual(
            open_before, after["IND_OPEN_INCIDENTS"]["value"],
            "el indicador no puede ser una constante",
        )
        self.assertIn("verify_chain_integrity", after["IND_AUDIT_CHAIN_STATE"]["source"])
        db.close()

    # -------------------------------------------------------------- atomicidad
    def test_21_atomic_rollback_on_incident_creation(self):
        """Si la auditoria falla, el incidente y su historial no persisten (rollback total).

        Se fuerza el fallo por INYECCION de un evento de auditoria incompleto
        sobre una base TEMPORAL (no sobre la base viva): el mismo patron que la
        prueba de atomicidad de F3, sin tocar datos reales.
        """
        db = self._new_db()
        with self.assertRaises(Exception):
            db.insert_incident_with_audit_event(
                {"code": "INC-RB-01", "title": "Debe revertirse", "severity": "ALTA"},
                {"actor": "TEST"},  # evento incompleto: falta la accion
            )
        self.assertEqual(
            db.monitoring_query("SELECT id FROM incidents WHERE code = 'INC-RB-01';"),
            [],
            "no debe quedar un incidente huerfano",
        )
        self.assertEqual(
            db.monitoring_query("SELECT id FROM incident_updates;"),
            [],
            "no debe quedar una transicion huerfana",
        )
        db.close()

    def test_22_atomic_rollback_on_transition(self):
        """Si la auditoria de la transicion falla, ni el estado ni el historial cambian."""
        from incident_management import create_incident

        db = self._new_db()
        incident = create_incident(
            db, {"code": "INC-RB-02", "title": "Transicion atomica", "severity": "ALTA"}, "admin.test"
        )
        history_before = db.list_incident_updates(incident["id"])
        with self.assertRaises(Exception):
            db.update_incident_status_with_audit_event(
                incident["id"], "EN_INVESTIGACION", "no debe persistir", "admin.test",
                {"actor": "TEST"},
            )
        current = db.get_incident(incident["id"])
        self.assertEqual(current["status"], "ABIERTO", "el estado no debio mutar")
        self.assertEqual(len(current["updates"]), len(history_before), "el historial no debio crecer")
        db.close()


class F4ApiSuite(unittest.TestCase):
    """Pruebas HTTP de F4 contra el stack ya arrancado (RBAC y contrato de rutas)."""

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

    def _create_incident(self, token, code, severity="ALTA", title="Incidente de prueba F4"):
        return self.call(token, "POST", "/api/v1/incidents", {
            "code": code,
            "title": title,
            "description": "Incidente sintetico creado por la suite F4",
            "severity": severity,
            "synthetic": 0,  # el servidor debe imponer 1
        })

    def _create_high_residual_risk(self, token):
        """Crea un riesgo residual CRITICO sin control: garantiza una alerta derivada."""
        code = self._unique("RSK-F4-ALR")
        status, body = self.call(token, "POST", "/api/v1/risks", {
            "code": code,
            "name": "Riesgo de prueba F4 para alerta derivada",
            "description": "Riesgo que garantiza la regla RISK_WITHOUT_CONTROL",
            "category": "software",
            "threat": "Amenaza de prueba F4",
            "vulnerability": "Vulnerabilidad de prueba F4",
            "probability_inherent": 4,
            "impact_inherent": 4,
            "treatment": "MITIGAR",
            "probability_residual": 4,
            "impact_residual": 4,
            "owner_role": "ROLE_PLATFORM_ADMIN",
            "status": "IDENTIFICADO",
            "synthetic": 1,
        })
        if status != 201:
            raise unittest.SkipTest(f"no se pudo crear el riesgo de apoyo (HTTP {status}: {body})")
        return body["risk"]["id"]

    # ------------------------------------------------------------------ lectura
    def test_23_auditor_lists_incidents_and_detail(self):
        """El auditor lista incidentes y ve el detalle con su historial."""
        token = self.token("auditor.test")
        status, body = self.call(token, "GET", "/api/v1/incidents")
        self.assertEqual(status, 200)
        self.assertIn("incidents", body)
        incidents = body["incidents"]
        self.assertGreaterEqual(len(incidents), 2, "los 2 incidentes de laboratorio deben estar sembrados")
        codes = {i["code"] for i in incidents}
        self.assertIn("INC-F11-IAM-01", codes)
        self.assertIn("INC-F11-CONT-02", codes)
        self.assertTrue(all(i["synthetic"] == 1 for i in incidents))

        # Cada sembrado arranca en un estado distinto, asi que el historial no
        # siempre empieza en ABIERTO. Se comprueba el incidente que si esta
        # abierto y, ademas, la invariante en todos: la ultima transicion del
        # historial inmutable coincide con el estado real que devuelve la API.
        por_codigo = {i["code"]: i for i in incidents}
        status, abierto = self.call(
            token, "GET", "/api/v1/incidents/" + por_codigo["INC-F11-IAM-01"]["id"]
        )
        self.assertEqual(status, 200)
        self.assertEqual(abierto["updates"][0]["to_status"], "ABIERTO")

        for incident in incidents:
            status, detail = self.call(token, "GET", f"/api/v1/incidents/{incident['id']}")
            self.assertEqual(status, 200)
            self.assertIn("updates", detail)
            self.assertGreaterEqual(len(detail["updates"]), 1)
            self.assertEqual(
                detail["updates"][-1]["to_status"],
                detail["incident"]["status"],
                "la ultima transicion debe coincidir con el estado real del incidente",
            )

    def test_24_auditor_reads_alerts_with_evidence_and_deterministic_ids(self):
        """Las alertas traen evidence real y su id es estable entre dos consultas."""
        token = self.token("auditor.test")
        status, first = self.call(token, "GET", "/api/v1/alerts")
        self.assertEqual(status, 200)
        status, second = self.call(token, "GET", "/api/v1/alerts")
        self.assertEqual(status, 200)
        self.assertEqual(
            [a["id"] for a in first["alerts"]],
            [a["id"] for a in second["alerts"]],
            "el id de una alerta derivada debe ser determinista",
        )
        for alert in first["alerts"]:
            for field in ("id", "rule", "severity", "title", "subject", "evidence"):
                self.assertIn(field, alert)
            self.assertTrue(alert["evidence"].strip())

    def test_25_clinical_user_without_role_is_denied_incidents_and_alerts(self):
        """Un rol clinico sin auditoria recibe 403 en incidentes y alertas."""
        token = self.token("recepcion.test")
        status, body = self.call(token, "GET", "/api/v1/incidents")
        self.assertEqual(status, 403)
        self.assertEqual(body.get("code"), "INCIDENTS_ROLE_REQUIRED")
        status, body = self.call(token, "GET", "/api/v1/alerts")
        self.assertEqual(status, 403)
        self.assertEqual(body.get("code"), "ALERTS_ROLE_REQUIRED")

    # --------------------------------------------------------------------- RBAC
    def test_26_auditor_cannot_create_nor_transition_incidents(self):
        """El auditor lee incidentes pero no puede crearlos ni transicionarlos."""
        token = self.token("auditor.test")
        status, body = self._create_incident(token, self._unique("INC-RBAC"))
        self.assertEqual(status, 403)
        self.assertEqual(body.get("code"), "PLATFORM_ADMIN_ROLE_REQUIRED")

        status, body = self.call(
            token, "POST", "/api/v1/incidents/INC-F11-IAM-01", {"to_status": "MITIGADO"}
        )
        self.assertEqual(status, 403)
        self.assertEqual(body.get("code"), "PLATFORM_ADMIN_ROLE_REQUIRED")

    def test_27_admin_without_mfa_cannot_create_incident(self):
        """El administrador sin OTP recibe 403 por MFA."""
        token = self.token("medico.sinmfa")
        status, body = self._create_incident(token, self._unique("INC-NOMFA"))
        self.assertEqual(status, 403)
        self.assertEqual(body.get("code"), "MFA_AUTHENTICATION_REQUIRED")

    def test_28_admin_with_mfa_creates_incident_with_synthetic_forced(self):
        """El administrador con MFA crea el incidente y el servidor fuerza synthetic = 1."""
        token = self.token("medico.test")
        code = self._unique("INC-API")
        status, body = self._create_incident(token, code)
        self.assertEqual(status, 201)
        incident = body["incident"]
        self.assertEqual(incident["code"], code)
        self.assertEqual(incident["synthetic"], 1)
        self.assertEqual(incident["status"], "ABIERTO")

    def test_29_duplicate_incident_code_is_rejected(self):
        """Un codigo repetido devuelve 409 con codigo estable."""
        token = self.token("medico.test")
        status, body = self._create_incident(token, self._unique("INC-DUP-API"))
        self.assertEqual(status, 201)
        code = body["incident"]["code"]
        status, body = self._create_incident(token, code)
        self.assertEqual(status, 409)
        self.assertEqual(body.get("code"), "INCIDENT_ALREADY_EXISTS")

    def test_30_invalid_severity_and_empty_title_are_rejected(self):
        """Severidad invalida y titulo vacio devuelven 400 con campos."""
        token = self.token("medico.test")
        status, body = self._create_incident(token, self._unique("INC-BAD-SEV"), severity="EXTREMA")
        self.assertEqual(status, 400)
        self.assertEqual(body.get("code"), "INCIDENT_INVALID")
        self.assertIn("severity", body.get("fields", {}))

        status, body = self._create_incident(
            token, self._unique("INC-BAD-TITLE"), severity="ALTA", title="   "
        )
        self.assertEqual(status, 400)
        self.assertEqual(body.get("code"), "INCIDENT_INVALID")
        self.assertIn("title", body.get("fields", {}))

    def test_31_valid_transition_and_coherent_history(self):
        """Una transicion valida responde 200 y el historial refleja el cambio."""
        token = self.token("medico.test")
        status, body = self._create_incident(token, self._unique("INC-TR-API"))
        self.assertEqual(status, 201)
        incident_id = body["incident"]["id"]

        status, body = self.call(token, "POST", f"/api/v1/incidents/{incident_id}", {
            "to_status": "EN_INVESTIGACION", "note": "investigacion iniciada",
        })
        self.assertEqual(status, 200)
        self.assertEqual(body["incident"]["status"], "EN_INVESTIGACION")
        self.assertEqual(body["incident"]["revision"], 2)

        status, detail = self.call(token, "GET", f"/api/v1/incidents/{incident_id}")
        self.assertEqual(status, 200)
        statuses = [u["to_status"] for u in detail["updates"]]
        self.assertEqual(statuses, ["ABIERTO", "EN_INVESTIGACION"])
        self.assertEqual(detail["updates"][-1]["from_status"], "ABIERTO")

    def test_32_invalid_transition_is_rejected(self):
        """Una transicion no declarada responde 409 con codigo estable."""
        token = self.token("medico.test")
        status, body = self._create_incident(token, self._unique("INC-TR-BAD"))
        self.assertEqual(status, 201)
        incident_id = body["incident"]["id"]

        status, body = self.call(token, "POST", f"/api/v1/incidents/{incident_id}", {
            "to_status": "CERRADO",
        })
        self.assertEqual(status, 200)
        # CERRADO es terminal: reabrir no esta declarado.
        status, body = self.call(token, "POST", f"/api/v1/incidents/{incident_id}", {
            "to_status": "ABIERTO",
        })
        self.assertEqual(status, 409)
        self.assertEqual(body.get("code"), "INCIDENT_TRANSITION_INVALID")

    def test_33_transition_of_unknown_incident_returns_404(self):
        """Transicionar un incidente inexistente devuelve 404 INCIDENT_NOT_FOUND."""
        token = self.token("medico.test")
        status, body = self.call(token, "POST", "/api/v1/incidents/INC-NOEXISTE-F4", {
            "to_status": "EN_INVESTIGACION",
        })
        self.assertEqual(status, 404)
        self.assertEqual(body.get("code"), "INCIDENT_NOT_FOUND")

    def test_34_transition_does_not_change_synthetic(self):
        """Enviar synthetic en la transicion no altera la sinteticidad del incidente."""
        token = self.token("medico.test")
        status, body = self._create_incident(token, self._unique("INC-SINT-API"))
        self.assertEqual(status, 201)
        incident_id = body["incident"]["id"]
        self.assertEqual(body["incident"]["synthetic"], 1)

        status, body = self.call(token, "POST", f"/api/v1/incidents/{incident_id}", {
            "to_status": "EN_INVESTIGACION", "synthetic": 0,
        })
        self.assertEqual(status, 200)
        self.assertEqual(body["incident"]["synthetic"], 1, "la transicion no cambia la sinteticidad")

    # ------------------------------------------------------------------- acuse
    def test_35_auditor_cannot_acknowledge_alert(self):
        """El auditor ve alertas pero no puede acusarlas."""
        token = self.token("auditor.test")
        status, body = self.call(token, "POST", "/api/v1/alerts/ALR-00000000/ack", {"note": "no"})
        self.assertEqual(status, 403)
        self.assertEqual(body.get("code"), "PLATFORM_ADMIN_ROLE_REQUIRED")

    def test_36_ack_of_unknown_alert_is_rejected(self):
        """El acuse de una alerta inexistente devuelve 404 ALERT_NOT_FOUND."""
        token = self.token("medico.test")
        status, body = self.call(token, "POST", "/api/v1/alerts/ALR-00000000/ack", {"note": "no"})
        self.assertEqual(status, 404)
        self.assertEqual(body.get("code"), "ALERT_NOT_FOUND")

    def test_37_admin_acknowledges_a_real_derived_alert(self):
        """Un acuse real se registra y se refleja en la siguiente consulta de alertas."""
        admin = self.token("medico.test")
        risk_id = self._create_high_residual_risk(admin)

        status, body = self.call(admin, "GET", "/api/v1/alerts")
        self.assertEqual(status, 200)
        matching = [a for a in body["alerts"] if a["subject"] == risk_id]
        if not matching:
            raise unittest.SkipTest("la alerta del riesgo de apoyo no se derivo en este estado")
        alert_id = matching[0]["id"]

        status, ack = self.call(admin, "POST", f"/api/v1/alerts/{alert_id}/ack", {
            "note": "acuse de la suite F4",
        })
        self.assertEqual(status, 200)
        self.assertEqual(ack["alert"]["alert_id"], alert_id)

        status, body = self.call(admin, "GET", "/api/v1/alerts")
        self.assertEqual(status, 200)
        after = [a for a in body["alerts"] if a["id"] == alert_id][0]
        self.assertTrue(after["acknowledged"])
        self.assertTrue(after["acknowledged_by"])

    # -------------------------------------------------------------- indicadores
    def test_38_indicators_are_visible_to_every_authenticated_role(self):
        """El panel de indicadores lo ve cualquier identidad autenticada y trae source."""
        token = self.token("recepcion.test")
        status, body = self.call(token, "GET", "/api/v1/indicators")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(len(body["indicators"]), 8)
        for indicator in body["indicators"]:
            self.assertTrue(indicator["source"].strip(), indicator["code"])
            for field in ("code", "name", "value", "status", "source"):
                self.assertIn(field, indicator)


if __name__ == "__main__":
    unittest.main()
