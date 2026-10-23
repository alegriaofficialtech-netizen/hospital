#!/usr/bin/env python3
"""Modulo M6 de alertas derivadas e indicadores M8 del laboratorio SGSI-ZTA (F11).

Las alertas NO son una tabla mutable: se derivan de forma determinista del
estado real de la plataforma (riesgos, controles, hallazgos, incidentes y
configuracion de identidades) en cada consulta. Lo unico que se persiste es el
acuse. Asi una alerta no puede quedar obsoleta: si su causa desaparece, la
alerta deja de existir sola.

Reglas del modulo:
* Cada alerta lleva un id determinista (``ALR-`` + sha1 de ``regla|sujeto``,
  8 caracteres hex): la misma causa produce siempre la misma alerta.
* Cada alerta declara su ``evidence``: la operacion real que la produjo, es
  decir la consulta SQLite concreta y su resultado, siguiendo el patron de
  evidencia estructurada de M2. No se inventa ningun dato.
* Cada indicador de M8 declara su ``source``: la operacion real que lo produce.
  Cuando un indicador no puede declarar su origen, usa el centinela
  ``undeclared`` en lugar de un texto por defecto que pase desapercibido.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from database import (
    AlertNotFoundError,
)

# Centinela de origen no declarado. No es un origen valido: si aparece, la
# prueba y la evidencia lo ven en lugar de etiquetarse por defecto como si el
# indicador hubiera declarado un mecanismo real.
UNDECLARED_SOURCE = "undeclared"

# Umbral en dias para que un incidente en ABIERTO o EN_INVESTIGACION se
# considere abierto demasiado tiempo y derive una alerta. 30 dias es el limite
# de respuesta asumido por el laboratorio F11 para un incidente de seguridad.
ALERT_OPEN_INCIDENT_DAYS = 30
ALERT_OPEN_INCIDENT_DAYS_DOC = (
    "Incidente abierto (ABIERTO o EN_INVESTIGACION) cuyo detected_at es anterior "
    "a ALERT_OPEN_INCIDENT_DAYS dias respecto del instante de la consulta."
)

ALERT_RULE_RISK_WITHOUT_CONTROL = "RISK_WITHOUT_CONTROL"
ALERT_RULE_CONTROL_PENDING_VERIFICATION = "CONTROL_PENDING_VERIFICATION"
ALERT_RULE_CRITICAL_FINDING_OPEN = "CRITICAL_FINDING_OPEN"
ALERT_RULE_INCIDENT_OPEN_TOO_LONG = "INCIDENT_OPEN_TOO_LONG"
ALERT_RULE_ADMIN_IDENTITY_WITHOUT_MFA = "ADMIN_IDENTITY_WITHOUT_MFA"

MFA_CHECKER_ID = "KC_MFA_ON_ADMIN_IDENTITIES"


# --------------------------------------------------------------------------
# Utilidades de evidencia y de identificacion
# --------------------------------------------------------------------------
def alert_id(rule: str, subject: str) -> str:
    """Calcula el id determinista de una alerta: ALR- + sha1(regla|sujeto)[:8]."""
    digest = hashlib.sha1(("%s|%s" % (rule, subject)).encode("utf-8")).hexdigest()[:8]
    return "ALR-" + digest


def _evidence(sql: str, outcome: str) -> str:
    """Compone la evidencia de una alerta: la consulta real y su resultado."""
    compact = " ".join(str(sql).split())
    return "%s -> %s" % (compact, outcome)


def _query(db: Any, sql: str, params: Tuple[Any, ...] = ()) -> Optional[List[Dict[str, Any]]]:
    """Ejecuta una consulta de monitorizacion y devuelve sus filas, o None si falla."""
    try:
        return db.monitoring_query(sql, params)
    except Exception:
        return None


def _new_alert(
    rule: str,
    severity: str,
    title: str,
    subject: str,
    evidence: str,
    detected_at: float,
) -> Dict[str, Any]:
    """Construye el diccionario de una alerta derivada antes de cruzar su acuse."""
    return {
        "id": alert_id(rule, subject),
        "rule": rule,
        "severity": severity,
        "title": title,
        "subject": subject,
        "evidence": evidence,
        "detected_at": float(detected_at),
    }


# --------------------------------------------------------------------------
# Reglas de derivacion (todas sobre datos reales)
# --------------------------------------------------------------------------
def _alerts_risk_without_control(db: Any) -> List[Dict[str, Any]]:
    """Regla RISK_WITHOUT_CONTROL: riesgo residual ALTO/CRITICO sin control vinculado."""
    sql = (
        "SELECT r.id AS risk_id, r.code AS risk_code, r.residual_risk_level AS level, "
        "(SELECT COUNT(*) FROM risk_controls rc WHERE rc.risk_id = r.id) AS linked_controls "
        "FROM risks r WHERE r.residual_risk_level IN ('ALTO','CRITICO') "
        "ORDER BY r.residual_risk_level DESC, r.code ASC"
    )
    rows = _query(db, sql)
    alerts: List[Dict[str, Any]] = []
    if rows is None:
        return alerts
    for row in rows:
        if int(row.get("linked_controls") or 0) != 0:
            continue
        level = str(row.get("level") or "")
        severity = "CRITICA" if level == "CRITICO" else "ALTA"
        alerts.append(_new_alert(
            ALERT_RULE_RISK_WITHOUT_CONTROL,
            severity,
            "Riesgo residual %s sin control vinculado" % level,
            str(row["risk_id"]),
            _evidence(sql, "%s residual=%s controles=%s" % (
                row.get("risk_code"), level, row.get("linked_controls"),
            )),
            time.time(),
        ))
    return alerts


def _alerts_control_pending_verification(db: Any) -> List[Dict[str, Any]]:
    """Regla CONTROL_PENDING_VERIFICATION: control IMPLEMENTADO sin evidencia de verificacion."""
    sql = (
        "SELECT c.id AS control_id, c.code AS control_code, c.name AS control_name "
        "FROM controls c WHERE c.status = 'IMPLEMENTADO' "
        "AND NOT EXISTS (SELECT 1 FROM control_evidences e WHERE e.control_id = c.id) "
        "ORDER BY c.code ASC"
    )
    rows = _query(db, sql)
    alerts: List[Dict[str, Any]] = []
    if rows is None:
        return alerts
    for row in rows:
        alerts.append(_new_alert(
            ALERT_RULE_CONTROL_PENDING_VERIFICATION,
            "MEDIA",
            "Control implementado sin evidencia de verificacion",
            str(row["control_id"]),
            _evidence(sql, "%s estado=IMPLEMENTADO evidencias=0" % row.get("control_code")),
            time.time(),
        ))
    return alerts


def _alerts_critical_finding_open(db: Any) -> List[Dict[str, Any]]:
    """Regla CRITICAL_FINDING_OPEN: hallazgo alto/critico abierto en la ultima ejecucion."""
    sql = (
        "SELECT f.id AS finding_id, f.title, f.severity, f.status, f.checker_id, "
        "f.run_id, f.detected_at FROM security_findings f WHERE f.run_id = "
        "(SELECT id FROM diagnostic_runs ORDER BY started_at DESC LIMIT 1) "
        "AND f.status <> 'passed' AND f.severity IN ('critical','high') "
        "ORDER BY f.detected_at DESC"
    )
    rows = _query(db, sql)
    alerts: List[Dict[str, Any]] = []
    if rows is None:
        return alerts
    for row in rows:
        alerts.append(_new_alert(
            ALERT_RULE_CRITICAL_FINDING_OPEN,
            "ALTA",
            "Hallazgo %s abierto en la ultima ejecucion de diagnostico" % row.get("severity"),
            str(row["finding_id"]),
            _evidence(sql, "%s severity=%s status=%s run=%s" % (
                row.get("checker_id"), row.get("severity"), row.get("status"), row.get("run_id"),
            )),
            float(row.get("detected_at") or time.time()),
        ))
    return alerts


def _alerts_incident_open_too_long(db: Any) -> List[Dict[str, Any]]:
    """Regla INCIDENT_OPEN_TOO_LONG: incidente abierto mas de ALERT_OPEN_INCIDENT_DAYS dias."""
    cutoff = time.time() - (ALERT_OPEN_INCIDENT_DAYS * 86400)
    sql = (
        "SELECT i.id AS incident_id, i.code AS incident_code, i.status, i.severity, "
        "i.detected_at FROM incidents i WHERE i.status IN ('ABIERTO','EN_INVESTIGACION') "
        "AND i.detected_at < ? ORDER BY i.detected_at ASC"
    )
    rows = _query(db, sql, (cutoff,))
    alerts: List[Dict[str, Any]] = []
    if rows is None:
        return alerts
    for row in rows:
        age_days = int((time.time() - float(row.get("detected_at") or 0.0)) // 86400)
        alerts.append(_new_alert(
            ALERT_RULE_INCIDENT_OPEN_TOO_LONG,
            "ALTA",
            "Incidente abierto mas de %d dias" % ALERT_OPEN_INCIDENT_DAYS,
            str(row["incident_id"]),
            _evidence(sql, "%s status=%s dias=%s umbral=%s" % (
                row.get("incident_code"), row.get("status"), age_days, ALERT_OPEN_INCIDENT_DAYS,
            )),
            float(row.get("detected_at") or time.time()),
        ))
    return alerts


def _alerts_admin_identity_without_mfa(db: Any) -> List[Dict[str, Any]]:
    """Regla ADMIN_IDENTITY_WITHOUT_MFA: deriva del hallazgo real de KC_MFA_ON_ADMIN_IDENTITIES.

    Si ese hallazgo no existe (el comprobador no se ejecuto), la alerta NO
    aparece: no se inventa un hallazgo para forzar la alerta.
    """
    sql = (
        "SELECT f.id AS finding_id, f.status, f.severity, f.checker_id, "
        "f.detected_at FROM security_findings f WHERE f.checker_id = ? "
        "ORDER BY f.detected_at DESC LIMIT 1"
    )
    rows = _query(db, sql, (MFA_CHECKER_ID,))
    alerts: List[Dict[str, Any]] = []
    if not rows:
        return alerts
    row = rows[0]
    if str(row.get("status")) == "passed":
        return alerts
    alerts.append(_new_alert(
        ALERT_RULE_ADMIN_IDENTITY_WITHOUT_MFA,
        "CRITICA",
        "Identidad administrativa sin MFA acreditada",
        str(row["finding_id"]),
        _evidence(sql, "%s status=%s severity=%s" % (
            row.get("checker_id"), row.get("status"), row.get("severity"),
        )),
        float(row.get("detected_at") or time.time()),
    ))
    return alerts


# --------------------------------------------------------------------------
# Derivacion y acuse
# --------------------------------------------------------------------------
def derive_alerts(db: Any) -> List[Dict[str, Any]]:
    """Deriva las alertas del estado real y cruza cada una con su acuse.

    Devuelve una lista de alertas; cada una incluye ``acknowledged``,
    ``acknowledged_by`` y ``acknowledged_at`` segun el acuse persistido.
    """
    acks = db.get_alert_acknowledgements()
    alerts: List[Dict[str, Any]] = []
    alerts.extend(_alerts_risk_without_control(db))
    alerts.extend(_alerts_control_pending_verification(db))
    alerts.extend(_alerts_critical_finding_open(db))
    alerts.extend(_alerts_incident_open_too_long(db))
    alerts.extend(_alerts_admin_identity_without_mfa(db))

    severity_order = {"CRITICA": 0, "ALTA": 1, "MEDIA": 2, "BAJA": 3}
    alerts.sort(key=lambda a: (severity_order.get(a["severity"], 9), -a["detected_at"]))

    for alert in alerts:
        ack = acks.get(alert["id"])
        alert["acknowledged"] = ack is not None
        alert["acknowledged_by"] = ack["acknowledged_by"] if ack else None
        alert["acknowledged_at"] = ack["acknowledged_at"] if ack else None
    return alerts


def list_alerts(db: Any) -> List[Dict[str, Any]]:
    """Lista las alertas derivadas cruzadas con sus acuses."""
    return derive_alerts(db)


def acknowledge_alert(
    db: Any,
    alert_id_value: str,
    note: Optional[str],
    actor: str,
    role: str = "ROLE_PLATFORM_ADMIN",
) -> Dict[str, Any]:
    """Registra el acuse de una alerta derivada existente.

    El acuse de una alerta INEXISTENTE se rechaza con AlertNotFoundError: no se
    puede acusar algo que no se deriva del estado real. El acuse se audita con
    la accion ALERT_ACKNOWLEDGE en la misma transaccion que la escritura.
    """
    derived = derive_alerts(db)
    matched = next((a for a in derived if a["id"] == alert_id_value), None)
    if matched is None:
        raise AlertNotFoundError(
            "La alerta '%s' no existe entre las derivadas del estado real" % alert_id_value
        )

    audit_event = {
        "action": "ALERT_ACKNOWLEDGE",
        "actor": actor,
        "role": role,
        "status": "ALLOWED",
        "details": "Acuse de la alerta %s (regla %s)" % (alert_id_value, matched["rule"]),
        "ip": "127.0.0.1",
        "mfa_verified": True,
    }
    ack, _record = db.insert_alert_ack_with_audit_event(
        alert_id_value, actor, note or "", audit_event
    )
    return ack


# --------------------------------------------------------------------------
# Indicadores M8 con su origen real
# --------------------------------------------------------------------------
def _indicator(
    code: str,
    name: str,
    value: Any,
    unit: Optional[str],
    status: str,
    source: str,
    target: Optional[Any] = None,
) -> Dict[str, Any]:
    """Forma comun de un indicador M8 con su origen real."""
    indicator: Dict[str, Any] = {
        "code": code,
        "name": name,
        "value": value,
        "unit": unit,
        "status": status,
        "source": source,
    }
    if target is not None:
        indicator["target"] = target
    return indicator


def _source(sql: str, rows: Optional[List[Dict[str, Any]]], summary: str) -> str:
    """Origen de un indicador: la consulta real y su resultado (o undeclared)."""
    if rows is None:
        return UNDECLARED_SOURCE
    return _evidence(sql, summary)


def _pct(numerator: float, denominator: float) -> Optional[float]:
    if denominator <= 0:
        return None
    return round((numerator / denominator) * 100.0, 1)


def _ratio_status(pct: Optional[float], good: float, warn: float) -> str:
    if pct is None:
        return "ATENCION"
    if pct >= good:
        return "OK"
    if pct >= warn:
        return "ATENCION"
    return "CRITICO"


def _indicator_asset_criticality_coverage(db: Any) -> Dict[str, Any]:
    """Cobertura de evaluacion de criticidad de activos."""
    sql = (
        "SELECT (SELECT COUNT(*) FROM assets) AS total, "
        "(SELECT COUNT(DISTINCT asset_id) FROM asset_evaluations) AS evaluated"
    )
    rows = _query(db, sql)
    total = int(rows[0]["total"]) if rows else 0
    evaluated = int(rows[0]["evaluated"]) if rows else 0
    value = _pct(evaluated, total)
    return _indicator(
        "IND_ASSET_CRITICALITY_COVERAGE",
        "Cobertura de evaluacion de criticidad de activos",
        value, "%", _ratio_status(value, 100.0, 50.0),
        _source(sql, rows, "total=%s evaluados=%s" % (total, evaluated)),
        target=100.0,
    )


def _indicator_high_residual_risks(db: Any) -> Dict[str, Any]:
    """Riesgos residuales altos o criticos."""
    sql = "SELECT COUNT(*) AS high_residual FROM risks WHERE residual_risk_level IN ('ALTO','CRITICO')"
    rows = _query(db, sql)
    value = int(rows[0]["high_residual"]) if rows else 0
    status = "CRITICO" if value > 0 else "OK"
    return _indicator(
        "IND_HIGH_RESIDUAL_RISKS",
        "Riesgos residuales altos o criticos",
        value, "riesgos", status,
        _source(sql, rows, "high_residual=%s" % value),
        target=0,
    )


def _indicator_control_verification_rate(db: Any) -> Dict[str, Any]:
    """Tasa de verificacion de controles con evidencia enlazada."""
    sql = (
        "SELECT COUNT(*) AS total, "
        "SUM(CASE WHEN status = 'VERIFICADO' THEN 1 ELSE 0 END) AS verified FROM controls"
    )
    rows = _query(db, sql)
    total = int(rows[0]["total"]) if rows else 0
    verified = int(rows[0]["verified"] or 0) if rows else 0
    value = _pct(verified, total)
    return _indicator(
        "IND_CONTROL_VERIFICATION_RATE",
        "Tasa de verificacion de controles",
        value, "%", _ratio_status(value, 100.0, 50.0),
        _source(sql, rows, "total=%s verificados=%s" % (total, verified)),
        target=100.0,
    )


def _indicator_last_diagnostic_success_rate(db: Any) -> Dict[str, Any]:
    """Tasa de exito del ultimo diagnostico de seguridad."""
    sql = (
        "SELECT id, passed, failed, warnings, checker_count, started_at FROM diagnostic_runs "
        "ORDER BY started_at DESC LIMIT 1"
    )
    rows = _query(db, sql)
    if not rows:
        return _indicator(
            "IND_LAST_DIAGNOSTIC_SUCCESS_RATE",
            "Tasa de exito del ultimo diagnostico",
            None, "%", "ATENCION",
            _source(sql, rows, "sin ejecuciones de diagnostico"),
            target=100.0,
        )
    row = rows[0]
    total = int(row.get("checker_count") or 0)
    passed = int(row.get("passed") or 0)
    value = _pct(passed, total)
    status = "OK" if int(row.get("failed") or 0) == 0 else "CRITICO"
    return _indicator(
        "IND_LAST_DIAGNOSTIC_SUCCESS_RATE",
        "Tasa de exito del ultimo diagnostico",
        value, "%", status,
        _source(sql, rows, "run=%s passed=%s failed=%s checkers=%s" % (
            row.get("id"), passed, row.get("failed"), total,
        )),
        target=100.0,
    )


def _indicator_admin_mfa_coverage(db: Any) -> Dict[str, Any]:
    """Cobertura de MFA en identidades administrativas, del hallazgo real del comprobador."""
    sql = (
        "SELECT id, status, evidence_output, detected_at FROM security_findings "
        "WHERE checker_id = ? ORDER BY detected_at DESC LIMIT 1"
    )
    rows = _query(db, sql, (MFA_CHECKER_ID,))
    if not rows:
        return _indicator(
            "IND_ADMIN_MFA_COVERAGE",
            "Cobertura de MFA en identidades administrativas",
            None, "%", "ATENCION",
            _source(sql, rows, "sin hallazgo de %s" % MFA_CHECKER_ID),
            target=100.0,
        )
    row = rows[0]
    covered = total = 0
    try:
        payload = json.loads(row.get("evidence_output") or "{}")
        identities = payload.get("identidades_de_plataforma") or []
        total = len(identities)
        covered = sum(1 for i in identities if i.get("otp_credential"))
    except (ValueError, TypeError, AttributeError):
        return _indicator(
            "IND_ADMIN_MFA_COVERAGE",
            "Cobertura de MFA en identidades administrativas",
            None, "%", "ATENCION",
            UNDECLARED_SOURCE,
            target=100.0,
        )
    value = _pct(covered, total)
    return _indicator(
        "IND_ADMIN_MFA_COVERAGE",
        "Cobertura de MFA en identidades administrativas",
        value, "%", _ratio_status(value, 100.0, 50.0),
        _source(sql, rows, "hallazgo=%s identidades=%s con_otp=%s" % (
            row.get("id"), total, covered,
        )),
        target=100.0,
    )


def _indicator_open_incidents(db: Any) -> Dict[str, Any]:
    """Incidentes abiertos (ABIERTO o EN_INVESTIGACION)."""
    sql = (
        "SELECT COUNT(*) AS open_incidents FROM incidents "
        "WHERE status IN ('ABIERTO','EN_INVESTIGACION')"
    )
    rows = _query(db, sql)
    value = int(rows[0]["open_incidents"]) if rows else 0
    status = "CRITICO" if value > 0 else "OK"
    return _indicator(
        "IND_OPEN_INCIDENTS",
        "Incidentes abiertos",
        value, "incidentes", status,
        _source(sql, rows, "open_incidents=%s" % value),
        target=0,
    )


def _indicator_open_alerts(db: Any) -> Dict[str, Any]:
    """Alertas derivadas que siguen abiertas (sin acuse)."""
    derived = derive_alerts(db)
    open_alerts = [a for a in derived if not a.get("acknowledged")]
    total = len(derived)
    value = len(open_alerts)
    status = "CRITICO" if any(a["severity"] == "CRITICA" for a in open_alerts) else (
        "ATENCION" if value > 0 else "OK"
    )
    source = _evidence(
        "derive_alerts() sobre risks/risk_controls/controls/control_evidences/"
        "security_findings/diagnostic_runs/incidents y alert_acknowledgements",
        "derivadas=%s abiertas=%s" % (total, value),
    )
    return _indicator(
        "IND_OPEN_ALERTS",
        "Alertas abiertas",
        value, "alertas", status,
        source,
        target=0,
    )


def _indicator_audit_chain_state(db: Any) -> Dict[str, Any]:
    """Estado de la cadena de auditoria: recalculo real de encadenamiento y checkpoint."""
    try:
        valid, error = db.verify_chain_integrity()
    except Exception:
        return _indicator(
            "IND_AUDIT_CHAIN_STATE",
            "Estado de la cadena de auditoria",
            None, None, "CRITICO",
            UNDECLARED_SOURCE,
        )
    return _indicator(
        "IND_AUDIT_CHAIN_STATE",
        "Estado de la cadena de auditoria",
        "VALIDA" if valid else "INVALIDA", None,
        "OK" if valid else "CRITICO",
        "verify_chain_integrity() -> (%s, %s)" % (valid, error),
    )


def list_indicators(db: Any) -> List[Dict[str, Any]]:
    """Devuelve el panel de indicadores M8, cada uno con su origen real."""
    return [
        _indicator_asset_criticality_coverage(db),
        _indicator_high_residual_risks(db),
        _indicator_control_verification_rate(db),
        _indicator_last_diagnostic_success_rate(db),
        _indicator_admin_mfa_coverage(db),
        _indicator_open_incidents(db),
        _indicator_open_alerts(db),
        _indicator_audit_chain_state(db),
    ]
