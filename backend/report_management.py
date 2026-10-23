#!/usr/bin/env python3
"""Registro de evidencias por objetivo e informes generados desde datos reales.

Soporta el cierre documental de la tesis (F11):
* ``derive_evidence`` construye el inventario de evidencia agrupado por los
  objetivos O1..O4 a partir de las filas REALES de la base. No es una tabla
  mutable: si una fuente desaparece, su evidencia desaparece con ella.
* ``generate_report`` construye un informe Markdown con lo que hay en la base
  en el momento de generarlo. Si un dato no existe, el informe lo declara como
  ausente en la seccion de limitaciones; nunca lo rellena ni lo estima.

Reglas del modulo:
* Cada elemento de evidencia declara ``reference`` (id o codigo real) y
  ``source`` (la operacion real que lo produce: la consulta ejecutada y su
  resultado). Cuando una fuente no puede declarar su origen se usa el centinela
  ``undeclared``, igual que en las alertas derivadas de M6.
* Los objetivos sin datos se devuelven con ``empty = true``; no se rellenan con
  texto de ejemplo.
* El ``content_hash`` de un informe es el sha256 exacto de su Markdown y el
  codigo ``RPT-<objetivo>-<hash corto>`` se deriva de ese hash.
* Lo unico que se persiste de un informe es el documento y su auditoria
  (REPORT_GENERATE, con el hash en el evento).
"""

from __future__ import annotations

import hashlib
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from database import (
    F11_ENVIRONMENT,
    REPORT_OBJECTIVES,
    ReportValidationError,
)
from alert_management import UNDECLARED_SOURCE, list_indicators


# --------------------------------------------------------------------------
# Utilidades de evidencia
# --------------------------------------------------------------------------
def _evidence(sql: str, outcome: str) -> str:
    """Compone la evidencia: la consulta real ejecutada y su resultado."""
    compact = " ".join(str(sql).split())
    return "%s -> %s" % (compact, outcome)


def _query(db: Any, sql: str, params: Tuple[Any, ...] = ()) -> Optional[List[Dict[str, Any]]]:
    """Ejecuta una consulta de solo lectura; devuelve None si la fuente falla."""
    try:
        return db.monitoring_query(sql, params)
    except Exception:
        return None


def _iso_from_epoch(value: Any) -> Optional[str]:
    """Convierte un epoch a fecha ISO UTC; None si el valor no es una fecha."""
    try:
        stamp = float(value)
    except (TypeError, ValueError):
        return None
    if stamp <= 0:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stamp))


def _iso_from_date(value: Any) -> Optional[str]:
    """Normaliza una fecha textual (YYYY-MM-DD) o epoch a ISO UTC."""
    text = str(value or "").strip()
    if len(text) >= 10 and text[4] == "-" and text[7] == "-":
        return text[:10]
    return _iso_from_epoch(value)


def _item(
    objective: str,
    module: str,
    kind: str,
    reference: Any,
    description: str,
    date: Optional[str],
    source: str,
    synthetic: Optional[int] = None,
    links: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Forma comun de un elemento de evidencia."""
    element: Dict[str, Any] = {
        "objective": objective,
        "module": module,
        "kind": kind,
        "reference": str(reference or ""),
        "description": str(description or "").strip(),
        "date": date,
        "source": source or UNDECLARED_SOURCE,
        "synthetic": synthetic,
    }
    if links:
        element["links"] = links
    return element


# --------------------------------------------------------------------------
# Derivacion de evidencia por objetivo (siempre sobre datos reales)
# --------------------------------------------------------------------------
def _evidence_o1(db: Any) -> List[Dict[str, Any]]:
    """O1: hallazgos reales de M2, cada uno con su operacion y su origen."""
    sql = (
        "SELECT f.id, f.title, f.severity, f.status, f.checker_id, f.run_id, "
        "f.asset_ref, f.evidence_source, f.detected_at "
        "FROM security_findings f ORDER BY f.detected_at DESC"
    )
    rows = _query(db, sql)
    if rows is None:
        return []
    items: List[Dict[str, Any]] = []
    for row in rows:
        items.append(_item(
            "O1", "M2", "HALLAZGO", row.get("id"),
            "%s (severidad=%s, estado=%s, comprobador=%s)"
            % (row.get("title"), row.get("severity"), row.get("status"), row.get("checker_id")),
            _iso_from_epoch(row.get("detected_at")),
            _evidence(sql, "%s status=%s severity=%s origen=%s run=%s" % (
                row.get("checker_id"), row.get("status"), row.get("severity"),
                row.get("evidence_source") or UNDECLARED_SOURCE, row.get("run_id"),
            )),
            synthetic=None,
            links={
                "checker_id": row.get("checker_id"),
                "run_id": row.get("run_id"),
                "asset_ref": row.get("asset_ref"),
                "evidence_source": row.get("evidence_source") or UNDECLARED_SOURCE,
            },
        ))
    return items


def _evidence_o2(db: Any) -> List[Dict[str, Any]]:
    """O2: riesgos de M4 con sus vinculos reales y evaluaciones de activos de M3."""
    items: List[Dict[str, Any]] = []

    risk_sql = (
        "SELECT r.*, (SELECT COUNT(*) FROM risk_controls rc WHERE rc.risk_id = r.id) "
        "AS linked_controls FROM risks r ORDER BY r.created_at DESC"
    )
    risks = _query(db, risk_sql)
    if risks is not None:
        for row in risks:
            items.append(_item(
                "O2", "M4", "RIESGO", row.get("code"),
                "%s (residual=%s, nivel=%s, estado=%s)"
                % (
                    row.get("name"), row.get("residual_risk_score"),
                    row.get("residual_risk_level"), row.get("status"),
                ),
                _iso_from_epoch(row.get("created_at")),
                _evidence(risk_sql, "%s residual=%s nivel=%s controles=%s" % (
                    row.get("code"), row.get("residual_risk_score"),
                    row.get("residual_risk_level"),
                    row.get("linked_controls"),
                )),
                synthetic=int(row.get("synthetic") or 0),
                links={
                    "finding_id": row.get("finding_id"),
                    "source_checker": row.get("source_checker"),
                    "asset_id": row.get("asset_id"),
                },
            ))

    evaluation_sql = (
        "SELECT e.*, a.name AS asset_name, a.synthetic AS asset_synthetic "
        "FROM asset_evaluations e JOIN assets a ON a.id = e.asset_id "
        "ORDER BY e.evaluated_at DESC"
    )
    evaluations = _query(db, evaluation_sql)
    if evaluations is not None:
        for row in evaluations:
            items.append(_item(
                "O2", "M3", "EVALUACION_ACTIVO", row.get("id"),
                "Evaluacion del activo %s: criticidad=%s, hallazgos=%s"
                % (row.get("asset_name"), row.get("criticality"), row.get("findings_count")),
                _iso_from_epoch(row.get("evaluated_at")),
                _evidence(evaluation_sql, "%s asset=%s criticality=%s findings=%s" % (
                    row.get("id"), row.get("asset_name"),
                    row.get("criticality"), row.get("findings_count"),
                )),
                synthetic=None,
                links={"asset_id": row.get("asset_id")},
            ))
    return items


def _evidence_o3(db: Any) -> List[Dict[str, Any]]:
    """O3: controles de M5 con su evidencia real de verificacion."""
    items: List[Dict[str, Any]] = []

    control_sql = (
        "SELECT c.*, (SELECT COUNT(*) FROM control_evidences e WHERE e.control_id = c.id) "
        "AS evidence_count FROM controls c ORDER BY c.code ASC"
    )
    controls = _query(db, control_sql)
    if controls is not None:
        for row in controls:
            items.append(_item(
                "O3", "M5", "CONTROL", row.get("code"),
                "%s (%s %s, estado=%s, cumplimiento=%s, evidencias=%s)"
                % (
                    row.get("name"), row.get("framework"), row.get("clause_or_pillar"),
                    row.get("status"), row.get("compliance_score"), row.get("evidence_count"),
                ),
                _iso_from_date(row.get("verification_date") or row.get("updated_at")),
                _evidence(control_sql, "%s estado=%s compliance=%s evidencias=%s" % (
                    row.get("code"), row.get("status"),
                    row.get("compliance_score"), row.get("evidence_count"),
                )),
                synthetic=int(row.get("synthetic") or 0),
            ))

    evidence_sql = (
        "SELECT e.*, c.code AS control_code, c.name AS control_name "
        "FROM control_evidences e JOIN controls c ON c.id = e.control_id "
        "ORDER BY e.verified_at DESC"
    )
    evidences = _query(db, evidence_sql)
    if evidences is not None:
        for row in evidences:
            items.append(_item(
                "O3", "M5", "EVIDENCIA_CONTROL", row.get("id"),
                "Verificacion del control %s mediante %s: %s"
                % (row.get("control_code"), row.get("evidence_source"),
                   str(row.get("observed_result") or "")[:160]),
                _iso_from_epoch(row.get("verified_at")),
                _evidence(evidence_sql, "%s control=%s source=%s ref=%s mfa=%s" % (
                    row.get("id"), row.get("control_code"), row.get("evidence_source"),
                    row.get("reference_id"), row.get("verified_with_mfa"),
                )),
                synthetic=None,
                links={
                    "control_code": row.get("control_code"),
                    "evidence_source": row.get("evidence_source"),
                    "reference_id": row.get("reference_id"),
                },
            ))
    return items


def _evidence_o4(db: Any) -> List[Dict[str, Any]]:
    """O4: incidentes con historial, estado de la cadena de auditoria e indicadores M8."""
    items: List[Dict[str, Any]] = []

    incident_sql = (
        "SELECT i.*, (SELECT COUNT(*) FROM incident_updates u WHERE u.incident_id = i.id) "
        "AS update_count FROM incidents i ORDER BY i.detected_at DESC"
    )
    incidents = _query(db, incident_sql)
    if incidents is not None:
        for row in incidents:
            items.append(_item(
                "O4", "M6", "INCIDENTE", row.get("code"),
                "%s (severidad=%s, estado=%s, transiciones=%s)"
                % (row.get("title"), row.get("severity"), row.get("status"),
                   row.get("update_count")),
                _iso_from_epoch(row.get("detected_at")),
                _evidence(incident_sql, "%s status=%s severity=%s transiciones=%s" % (
                    row.get("code"), row.get("status"),
                    row.get("severity"), row.get("update_count"),
                )),
                synthetic=int(row.get("synthetic") or 0),
                links={
                    "asset_id": row.get("asset_id"),
                    "risk_id": row.get("risk_id"),
                    "control_id": row.get("control_id"),
                },
            ))

    update_sql = (
        "SELECT u.*, i.code AS incident_code FROM incident_updates u "
        "JOIN incidents i ON i.id = u.incident_id ORDER BY u.occurred_at ASC"
    )
    updates = _query(db, update_sql)
    if updates is not None:
        for row in updates:
            items.append(_item(
                "O4", "M6", "TRANSICION_INCIDENTE", row.get("id"),
                "Incidente %s: %s -> %s (%s)"
                % (
                    row.get("incident_code"), row.get("from_status") or "INICIO",
                    row.get("to_status"), str(row.get("note") or "")[:120],
                ),
                _iso_from_epoch(row.get("occurred_at")),
                _evidence(update_sql, "%s %s->%s actor=%s" % (
                    row.get("incident_code"), row.get("from_status") or "INICIO",
                    row.get("to_status"), row.get("actor"),
                )),
                synthetic=None,
                links={"incident_code": row.get("incident_code")},
            ))

    try:
        chain_valid, chain_error = db.verify_chain_integrity()
        chain_source = "verify_chain_integrity() -> (%s, %s)" % (chain_valid, chain_error)
        chain_date = None
        chain_description = "Cadena de auditoria %s" % (
            "VALIDA" if chain_valid else "INVALIDA"
        )
        if chain_error:
            chain_description += " (error: %s)" % chain_error
    except Exception:
        chain_source = UNDECLARED_SOURCE
        chain_description = "Estado de la cadena de auditoria no verificable"
        chain_date = None

    items.append(_item(
        "O4", "M7", "CADENA_AUDITORIA", "AUDIT-CHAIN",
        chain_description, chain_date, chain_source, synthetic=None,
    ))

    for indicator in list_indicators(db):
        items.append(_item(
            "O4", "M8", "INDICADOR", indicator.get("code"),
            "%s: %s%s (estado=%s)"
            % (
                indicator.get("name"), indicator.get("value"),
                indicator.get("unit") or "", indicator.get("status"),
            ),
            None,
            str(indicator.get("source") or UNDECLARED_SOURCE),
            synthetic=None,
        ))
    return items


_EVIDENCE_BUILDERS = {
    "O1": _evidence_o1,
    "O2": _evidence_o2,
    "O3": _evidence_o3,
    "O4": _evidence_o4,
}


def derive_evidence(db: Any, objective: Optional[str] = None) -> Dict[str, Any]:
    """Deriva el inventario de evidencia agrupado por objetivo.

    No persiste nada y no rellena objetivos sin datos: cada grupo declara
    ``empty = true`` cuando no hay filas reales que lo sostengan.
    """
    if objective is not None:
        target = str(objective).strip().upper()
        if target not in REPORT_OBJECTIVES:
            raise ReportValidationError(
                "Objetivo '%s' no admitido. Opciones: %s"
                % (objective, ", ".join(REPORT_OBJECTIVES))
            )
        objectives = [target]
    else:
        objectives = list(REPORT_OBJECTIVES)

    groups: List[Dict[str, Any]] = []
    total = 0
    for code in objectives:
        items = _EVIDENCE_BUILDERS[code](db)
        total += len(items)
        groups.append({
            "objective": code,
            "items": items,
            "count": len(items),
            "empty": len(items) == 0,
            "declaration": "SIN_EVIDENCIA" if not items else "CON_EVIDENCIA",
        })
    return {
        "objectives": groups,
        "total": total,
        "objective_filter": objectives[0] if objective is not None else None,
        "environment": F11_ENVIRONMENT,
    }


# --------------------------------------------------------------------------
# Estado real de los modulos implicados y metricas
# --------------------------------------------------------------------------
def _module_states(db: Any, objective: str) -> List[Dict[str, Any]]:
    """Estado real de cada modulo que sostiene el objetivo, con su origen."""
    states: List[Dict[str, Any]] = []

    if objective == "O1":
        runs_sql = (
            "SELECT id, status, checker_count, passed, failed, warnings, started_at "
            "FROM diagnostic_runs ORDER BY started_at DESC LIMIT 1"
        )
        runs = _query(db, runs_sql) or []
        total_runs = db.count_diagnostic_runs()
        if runs:
            last = runs[0]
            state = (
                "%d ejecuciones; ultima=%s estado=%s pasados=%s fallados=%s"
                % (
                    total_runs, last.get("id"), last.get("status"),
                    last.get("passed"), last.get("failed"),
                )
            )
            source = _evidence(runs_sql, "run=%s status=%s" % (
                last.get("id"), last.get("status"),
            ))
        else:
            state = "sin ejecuciones de diagnostico registradas"
            source = _evidence(runs_sql, "0 filas")
        states.append({
            "module": "M2", "name": "Diagnostico de seguridad",
            "state": state, "source": source,
        })
        assets = db.list_assets()
        states.append({
            "module": "M3", "name": "Inventario de activos",
            "state": "%d activos registrados" % len(assets),
            "source": "list_assets() -> %d filas" % len(assets),
        })
        return states

    if objective == "O2":
        summary = db.get_risks_summary()
        states.append({
            "module": "M4", "name": "Matriz de riesgos",
            "state": "%d riesgos; residuales: %s"
            % (summary.get("total_risks"), summary.get("residual_levels")),
            "source": "get_risks_summary() -> total_risks=%s residual_levels=%s"
            % (summary.get("total_risks"), summary.get("residual_levels")),
        })
        evaluation_sql = (
            "SELECT COUNT(*) AS total_evaluations, "
            "COUNT(DISTINCT asset_id) AS evaluated_assets, "
            "(SELECT COUNT(*) FROM assets) AS total_assets FROM asset_evaluations"
        )
        rows = _query(db, evaluation_sql) or []
        if rows:
            states.append({
                "module": "M3", "name": "Evaluacion de activos",
                "state": "%s evaluaciones sobre %s de %s activos"
                % (
                    rows[0].get("total_evaluations"),
                    rows[0].get("evaluated_assets"),
                    rows[0].get("total_assets"),
                ),
                "source": _evidence(evaluation_sql, "evaluaciones=%s activos_evaluados=%s"
                                    % (rows[0].get("total_evaluations"),
                                       rows[0].get("evaluated_assets"))),
            })
        return states

    if objective == "O3":
        summary = db.get_controls_summary()
        states.append({
            "module": "M5", "name": "Catalogo de controles",
            "state": "%d controles; por estado: %s; cumplimiento medio: %s%%"
            % (
                summary.get("total_controls"), summary.get("by_status"),
                summary.get("compliance_percentage"),
            ),
            "source": "get_controls_summary() -> total_controls=%s"
            % summary.get("total_controls"),
        })
        return states

    # O4
    incident_sql = (
        "SELECT COUNT(*) AS total, SUM(CASE WHEN status IN ('ABIERTO','EN_INVESTIGACION') "
        "THEN 1 ELSE 0 END) AS open_incidents FROM incidents"
    )
    rows = _query(db, incident_sql) or []
    if rows:
        states.append({
            "module": "M6", "name": "Monitorizacion de incidentes",
            "state": "%s incidentes; abiertos: %s"
            % (rows[0].get("total"), rows[0].get("open_incidents") or 0),
            "source": _evidence(incident_sql, "total=%s abiertos=%s"
                                % (rows[0].get("total"), rows[0].get("open_incidents") or 0)),
        })
    try:
        valid, error = db.verify_chain_integrity()
        states.append({
            "module": "M7", "name": "Cadena de auditoria",
            "state": "VALIDA" if valid else "INVALIDA (%s)" % error,
            "source": "verify_chain_integrity() -> (%s, %s)" % (valid, error),
        })
    except Exception:
        states.append({
            "module": "M7", "name": "Cadena de auditoria",
            "state": "no verificable",
            "source": UNDECLARED_SOURCE,
        })
    indicators = list_indicators(db)
    states.append({
        "module": "M8", "name": "Indicadores",
        "state": "%d indicadores calculados" % len(indicators),
        "source": "list_indicators() -> %d indicadores" % len(indicators),
    })
    return states


def _real_metrics(
    db: Any, objective: str, items: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Metricas calculadas en el momento de generar el informe."""
    metrics: List[Dict[str, Any]] = [
        {
            "name": "Elementos de evidencia en el periodo",
            "value": len(items),
            "source": "derive_evidence(%s) filtrado por periodo" % objective,
        },
    ]
    by_module: Dict[str, int] = {}
    for item in items:
        by_module[item["module"]] = by_module.get(item["module"], 0) + 1
    for module in sorted(by_module):
        metrics.append({
            "name": "Elementos del modulo %s" % module,
            "value": by_module[module],
            "source": "recuento sobre derive_evidence(%s)" % objective,
        })

    if objective == "O1":
        summary_sql = (
            "SELECT COUNT(*) AS total, "
            "SUM(CASE WHEN status <> 'passed' THEN 1 ELSE 0 END) AS failed "
            "FROM security_findings"
        )
        rows = _query(db, summary_sql) or []
        if rows:
            metrics.append({
                "name": "Hallazgos registrados (total)",
                "value": rows[0].get("total"),
                "source": _evidence(summary_sql, "total=%s no_pasados=%s"
                                    % (rows[0].get("total"), rows[0].get("failed") or 0)),
            })
    elif objective == "O2":
        summary = db.get_risks_summary()
        metrics.append({
            "name": "Riesgos registrados",
            "value": summary.get("total_risks"),
            "source": "get_risks_summary() -> total_risks",
        })
        metrics.append({
            "name": "Riesgos residuales ALTO o CRITICO",
            "value": len([
                r for r in db.list_risks()
                if str(r.get("residual_risk_level")) in ("ALTO", "CRITICO")
            ]),
            "source": "list_risks() filtrado por residual_risk_level",
        })
    elif objective == "O3":
        summary = db.get_controls_summary()
        metrics.append({
            "name": "Controles registrados",
            "value": summary.get("total_controls"),
            "source": "get_controls_summary() -> total_controls",
        })
        metrics.append({
            "name": "Controles verificados",
            "value": (summary.get("by_status") or {}).get("VERIFICADO", 0),
            "source": "get_controls_summary() -> by_status[VERIFICADO]",
        })
    else:
        rows = _query(
            db,
            "SELECT COUNT(*) AS total FROM incidents WHERE status IN "
            "('ABIERTO','EN_INVESTIGACION')",
        ) or []
        metrics.append({
            "name": "Incidentes abiertos",
            "value": rows[0].get("total") if rows else 0,
            "source": "consulta sobre incidents por estado abierto",
        })
        metrics.append({
            "name": "Indicadores M8 calculados",
            "value": len(list_indicators(db)),
            "source": "list_indicators()",
        })
    return metrics


# --------------------------------------------------------------------------
# Generacion del informe
# --------------------------------------------------------------------------
def _parse_period(payload: Dict[str, Any]) -> Tuple[str, str]:
    """Valida y normaliza el periodo del informe (YYYY-MM-DD, inclusivo)."""
    period_from = str(payload.get("period_from") or "").strip()
    period_to = str(payload.get("period_to") or "").strip()
    if not period_from or not period_to:
        raise ReportValidationError(
            "El informe requiere period_from y period_to (YYYY-MM-DD)."
        )
    try:
        start = time.strptime(period_from, "%Y-%m-%d")
        end = time.strptime(period_to, "%Y-%m-%d")
    except ValueError as exc:
        raise ReportValidationError(
            "El periodo debe usar el formato YYYY-MM-DD."
        ) from exc
    if start > end:
        raise ReportValidationError(
            "period_from no puede ser posterior a period_to."
        )
    return period_from, period_to


def _in_period(item: Dict[str, Any], period_from: str, period_to: str) -> bool:
    """Indica si la fecha declarada del elemento cae dentro del periodo."""
    date = item.get("date")
    if not date:
        return False
    day = str(date)[:10]
    return period_from <= day <= period_to


def _synthetic_counts(items: List[Dict[str, Any]]) -> Dict[str, int]:
    """Cuenta elementos por su declaracion real de sinteticidad."""
    counts = {"synthetic": 0, "real": 0, "undeclared": 0}
    for item in items:
        value = item.get("synthetic")
        if value is None:
            counts["undeclared"] += 1
        elif int(value) == 1:
            counts["synthetic"] += 1
        else:
            counts["real"] += 1
    return counts


def build_report_markdown(
    db: Any,
    title: str,
    objective: str,
    period_from: str,
    period_to: str,
    actor: str,
    generated_at: float,
) -> Tuple[str, List[Dict[str, Any]]]:
    """Construye el Markdown del informe y devuelve (contenido, elementos usados).

    Solo usa filas existentes en la base. Las ausencias se declaran en la
    seccion de limitaciones; no se estima ni se ejemplifica ningun dato.
    """
    group = derive_evidence(db, objective)["objectives"][0]
    all_items = group["items"]
    items = [i for i in all_items if _in_period(i, period_from, period_to)]
    without_date = [i for i in all_items if not i.get("date")]
    outside_period = [
        i for i in all_items
        if i.get("date") and not _in_period(i, period_from, period_to)
    ]

    states = _module_states(db, objective)
    metrics = _real_metrics(db, objective, items)
    synthetic = _synthetic_counts(items)
    expert_reviews = db.list_expert_reviews()
    instruments = db.list_instruments()

    generated_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(generated_at))
    lines: List[str] = []
    lines.append("# %s" % title)
    lines.append("")
    lines.append("- Objetivo: %s" % objective)
    lines.append("- Periodo: %s a %s" % (period_from, period_to))
    lines.append("- Fecha de generacion: %s" % generated_iso)
    lines.append("- Autor: %s" % actor)
    lines.append("- Entorno: %s" % F11_ENVIRONMENT)
    lines.append("")

    lines.append("## Modulos implicados y estado real")
    lines.append("")
    for state in states:
        lines.append(
            "- %s - %s: %s (origen: %s)"
            % (state["module"], state["name"], state["state"], state["source"])
        )
    if not states:
        lines.append("- No hay modulos implicados declarados para este objetivo.")
    lines.append("")

    lines.append("## Metricas reales")
    lines.append("")
    for metric in metrics:
        lines.append(
            "- %s: %s (origen: %s)"
            % (metric["name"], metric["value"], metric["source"])
        )
    lines.append("")

    lines.append("## Referencias de evidencia")
    lines.append("")
    if items:
        for item in items:
            lines.append(
                "- [%s/%s] %s - %s (fecha: %s; origen: %s)"
                % (
                    item["module"], item["kind"], item["reference"],
                    item["description"], item.get("date") or "no declarada",
                    item["source"],
                )
            )
    else:
        lines.append(
            "- El objetivo %s se declara VACIO para el periodo %s a %s: no hay "
            "filas de evidencia con fecha dentro de ese intervalo."
            % (objective, period_from, period_to)
        )
    lines.append("")

    lines.append("## Datos sinteticos")
    lines.append("")
    lines.append("- Elementos sinteticos (synthetic = 1): %d" % synthetic["synthetic"])
    lines.append("- Elementos no sinteticos (synthetic = 0): %d" % synthetic["real"])
    lines.append(
        "- Elementos que no declaran sinteticidad: %d" % synthetic["undeclared"]
    )
    lines.append("- Total de elementos en el periodo: %d" % len(items))
    if synthetic["undeclared"]:
        lines.append(
            "- Los elementos que no declaran sinteticidad provienen de fuentes que no "
            "guardan ese atributo; el informe no lo supone."
        )
    lines.append("")

    lines.append("## Limitaciones")
    lines.append("")
    if not items:
        lines.append(
            "- El periodo %s a %s no tiene evidencia registrada para el objetivo %s. "
            "El informe no rellena ese vacio." % (period_from, period_to, objective)
        )
    if without_date:
        lines.append(
            "- %d elementos del objetivo no declaran fecha y no se atribuyen al periodo."
            % len(without_date)
        )
    if outside_period:
        lines.append(
            "- %d elementos con fecha quedan fuera del periodo y no se incluyen."
            % len(outside_period)
        )
    if not expert_reviews:
        lines.append(
            "- No hay dictamenes de expertos registrados (expert_reviews = 0). El "
            "modulo M9 no puede afirmarse con la base actual: el sistema registra "
            "dictamenes, no los genera."
        )
    else:
        lines.append(
            "- Dictamenes de expertos registrados en la base: %d." % len(expert_reviews)
        )
    if not instruments:
        lines.append(
            "- No hay instrumentos de validacion registrados (validation_instruments = 0)."
        )
    else:
        lines.append(
            "- Instrumentos de validacion registrados: %d (el instrumento es una "
            "herramienta; su existencia no equivale a una evaluacion)." % len(instruments)
        )
    if objective == "O4":
        lines.append(
            "- Los indicadores M8 y el estado de la cadena de auditoria son una "
            "instantanea del momento de generacion, no un historico del periodo."
        )
    lines.append(
        "- El informe se construye exclusivamente con filas existentes en la base; "
        "no incorpora datos externos, estimaciones ni texto de ejemplo."
    )
    lines.append("")

    content = "\n".join(lines)
    return content, items


def generate_report(
    db: Any,
    payload: Dict[str, Any],
    actor: str,
    role: str = "ROLE_PLATFORM_ADMIN",
    now: Optional[float] = None,
) -> Dict[str, Any]:
    """Genera y persiste un informe Markdown a partir de datos reales.

    ``now`` solo existe para pruebas deterministas del propio modulo: la API
    siempre usa el reloj real. El codigo se deriva del hash del contenido
    (``RPT-<objetivo>-<hash corto>``); si ese informe ya existe se devuelve el
    registrado, sin duplicar ni reescribir el documento.
    """
    objective = str(payload.get("objective") or "").strip().upper()
    if objective not in REPORT_OBJECTIVES:
        raise ReportValidationError(
            "Objetivo '%s' no admitido. Opciones: %s"
            % (payload.get("objective"), ", ".join(REPORT_OBJECTIVES))
        )
    period_from, period_to = _parse_period(payload)
    title = str(payload.get("title") or "").strip() or (
        "Informe de evidencia del objetivo %s" % objective
    )

    generated_at = float(now if now is not None else time.time())
    content, _items = build_report_markdown(
        db, title, objective, period_from, period_to, actor, generated_at
    )
    content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    code = "RPT-%s-%s" % (objective, content_hash[:8].upper())

    existing = db.get_report(code)
    if existing is not None:
        return existing

    report = {
        "code": code,
        "title": title,
        "objective": objective,
        "period_from": period_from,
        "period_to": period_to,
        "content": content,
        "content_hash": content_hash,
        "generated_by": actor,
        "synthetic": 1,  # el informe es un artefacto de laboratorio
    }
    audit = {
        "action": "REPORT_GENERATE",
        "actor": actor,
        "role": role,
        "status": "ALLOWED",
        "details": "Generacion del informe %s (objetivo %s, hash %s)"
        % (code, objective, content_hash),
        "ip": "127.0.0.1",
        "mfa_verified": True,
    }
    stored, _record = db.insert_report_with_audit_event(report, audit)
    return stored


def list_reports(db: Any) -> List[Dict[str, Any]]:
    """Lista los informes registrados sin su contenido."""
    return db.list_reports()


def get_report(db: Any, report_id: str) -> Optional[Dict[str, Any]]:
    """Recupera un informe con su contenido Markdown integro."""
    return db.get_report(report_id)
