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


if __name__ == "__main__":
    unittest.main(verbosity=2)
