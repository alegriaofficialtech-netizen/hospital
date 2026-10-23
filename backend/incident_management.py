#!/usr/bin/env python3
"""Modulo M6 de Monitorizacion de Incidentes del laboratorio SGSI-ZTA (F11).

Soporta el seguimiento operativo de incidentes reales de la plataforma: alta,
ciclo de vida con transiciones validas, propietario funcional, vinculos con
activos (M3), riesgos (M4) y controles (M5), e historial de transiciones
inmutable.

Reglas del modulo:
* El ciclo de vida es un vocabulario cerrado: ABIERTO, EN_INVESTIGACION,
  MITIGADO y CERRADO. Una transicion no declarada en INCIDENT_TRANSITIONS se
  rechaza; CERRADO es terminal.
* Todo incidente creado desde la plataforma es de laboratorio sintetico
  (``synthetic = 1``). La declaracion del cliente no lo cambia, ni en el alta ni
  en una transicion.
* La siembra de laboratorio es idempotente y auditada con la accion
  'INCIDENT_SEED'. Falla cerrada: si un vinculo declarado a un activo o riesgo
  semilla no existe, la siembra se aborta con IncidentSeedError en lugar de
  dejar la trazabilidad incompleta sin rastro.
* Toda escritura y su evento de auditoria van en la misma transaccion
  (run_clinical_transaction): o quedan ambos, o no queda ninguno. Las acciones
  de auditoria del modulo son INCIDENT_CREATE e INCIDENT_UPDATE.
"""

from __future__ import annotations

import hashlib
import os
import sys
from typing import Any, Dict, List, Optional

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from database import (
    INCIDENT_SEVERITIES,
    INCIDENT_STATUSES,
    INCIDENT_TRANSITIONS,
    IncidentValidationError,
)

SEED_AUDIT_ACTION = "INCIDENT_SEED"

# Catalogo semilla de incidentes de LABORATORIO del entorno f11-local. Son
# pocos (2) y declaradamente sinteticos: no representan ningun incidente
# institucional real, solo el ejercicio de la trazabilidad del ciclo de vida
# sobre datos reales ya sembrados (activos de M3 y riesgos de M4).
SEED_INCIDENTS: List[Dict[str, Any]] = [
    {
        "code": "INC-F11-IAM-01",
        "title": "Posible acceso administrativo sin segundo factor en el laboratorio",
        "description": (
            "Incidente de laboratorio derivado del riesgo RSK-F11-IAM-01: se "
            "detecto una identidad de plataforma sin credencial OTP acreditada. "
            "Incidente sintetico del entorno f11-local, no institucional."
        ),
        "severity": "ALTA",
        "status": "ABIERTO",
        "risk_code": "RSK-F11-IAM-01",
        "asset_name": "keycloak-iam",
        "owner_role": "ROLE_SECURITY_AUDITOR",
        "synthetic": 1,
    },
    {
        "code": "INC-F11-CONT-02",
        "title": "Contenedor de gestion de identidades con capacidades excesivas",
        "description": (
            "Incidente de laboratorio derivado del riesgo RSK-F11-CONT-02: el "
            "contenedor de Keycloak no descarta todas las capacidades del kernel. "
            "Incidente sintetico del entorno f11-local, no institucional."
        ),
        "severity": "MEDIA",
        "status": "EN_INVESTIGACION",
        "risk_code": "RSK-F11-CONT-02",
        "asset_name": "compose-f11",
        "owner_role": "ROLE_PLATFORM_ADMIN",
        "synthetic": 1,
    },
]


class IncidentSeedError(RuntimeError):
    """Siembra abortada: la trazabilidad de incidentes quedaria incompleta.

    La siembra de incidentes es idempotente, igual que la del inventario de
    activos y la de controles. Un incidente semilla que declara un vinculo a un
    activo o riesgo que no existe se reporta con esta excepcion en lugar de
    ignorarse: el arranque falla cerrado y el operador ve exactamente que
    vinculo quedo sin resolver. Un reintento completa lo que falte.
    """


def seed_incident_id(code: str) -> str:
    """Calcula un ID determinista para un incidente a partir de su codigo."""
    digest = hashlib.sha256(code.encode("utf-8")).hexdigest()[:8].upper()
    return f"INC-{digest}"


def validate_incident(payload: Dict[str, Any], partial: bool = False) -> List[str]:
    """Valida los campos de un incidente segun el contrato de F4."""
    errors: List[str] = []

    def present(field: str) -> bool:
        return field in payload and payload[field] is not None

    if not partial or present("code"):
        code = str(payload.get("code") or "").strip()
        if not code or len(code) < 3 or len(code) > 64:
            errors.append("code: debe tener entre 3 y 64 caracteres")

    if not partial or present("title"):
        title = str(payload.get("title") or "").strip()
        if not title:
            errors.append("title: el titulo del incidente es obligatorio")
        elif len(title) > 200:
            errors.append("title: no puede superar los 200 caracteres")

    if not partial or present("severity"):
        severity = str(payload.get("severity") or "").strip().upper()
        if severity not in INCIDENT_SEVERITIES:
            errors.append(f"severity: debe ser una de {list(INCIDENT_SEVERITIES)}")

    if not partial or present("status"):
        status = str(payload.get("status") or "ABIERTO").strip().upper()
        if status not in INCIDENT_STATUSES:
            errors.append(f"status: debe ser uno de {list(INCIDENT_STATUSES)}")

    return errors


def _create_audit_event(payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
    """Construye el evento de auditoria del alta de un incidente."""
    return {
        "action": "INCIDENT_CREATE",
        "actor": actor,
        "role": role,
        "status": "ALLOWED",
        "details": f"Alta de incidente {payload.get('code')} ({payload.get('severity')})",
        "ip": "127.0.0.1",
        "mfa_verified": True,
    }


def create_incident(
    db: Any,
    payload: Dict[str, Any],
    actor: str,
    role: str = "ROLE_PLATFORM_ADMIN",
) -> Dict[str, Any]:
    """Da de alta un incidente forzando la sinteticidad y auditando el alta.

    El servidor impone ``synthetic = 1`` e ignora cualquier valor de
    ``synthetic`` que venga en el payload: un incidente creado desde la
    plataforma es siempre de laboratorio. El ID se deriva del codigo para que
    sea determinista y no dependa del cliente.
    """
    errors = validate_incident(payload)
    if errors:
        raise IncidentValidationError(
            "Incidente invalido: " + ", ".join(sorted(errors))
        )

    item = dict(payload)
    item["synthetic"] = 1  # se impone en el servidor; se ignora el del payload
    item["id"] = seed_incident_id(str(item.get("code")).strip())
    item["status"] = str(item.get("status") or "ABIERTO").strip().upper()
    item["created_by"] = actor

    incident, _record = db.insert_incident_with_audit_event(
        item, _create_audit_event(item, actor, role)
    )
    return incident


def transition_incident(
    db: Any,
    incident_id: str,
    to_status: str,
    note: Optional[str],
    actor: str,
    role: str = "ROLE_PLATFORM_ADMIN",
) -> Dict[str, Any]:
    """Aplica una transicion de estado validada y auditada.

    La validez de la transicion la decide la capa de persistencia contra
    INCIDENT_TRANSITIONS; aqui solo se normaliza el estado destino. Una
    transicion no declarada se rechaza sin tocar el estado ni el historial.
    """
    status = str(to_status or "").strip().upper()
    if status not in INCIDENT_STATUSES:
        raise IncidentValidationError(
            "Estado '%s' no admitido. Opciones: %s"
            % (status, ", ".join(INCIDENT_STATUSES))
        )

    audit_event = {
        "action": "INCIDENT_UPDATE",
        "actor": actor,
        "role": role,
        "status": "ALLOWED",
        "details": f"Transicion del incidente {incident_id} hacia {status}",
        "ip": "127.0.0.1",
        "mfa_verified": True,
    }
    incident, _record = db.update_incident_status_with_audit_event(
        incident_id, status, note or "", actor, audit_event
    )
    return incident


def list_incidents(
    db: Any, status: Optional[str] = None, severity: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Lista incidentes con filtros opcionales de estado y severidad."""
    filters: Dict[str, Any] = {}
    if status:
        filters["status"] = status
    if severity:
        filters["severity"] = severity
    return db.list_incidents(filters or None)


def get_incident(db: Any, incident_id: str) -> Optional[Dict[str, Any]]:
    """Recupera un incidente con su historial de transiciones, o None."""
    return db.get_incident(incident_id)


def list_incident_updates(db: Any, incident_id: str) -> List[Dict[str, Any]]:
    """Lista el historial de transiciones de un incidente."""
    return db.list_incident_updates(incident_id)


def seed_incidents(db: Any) -> Dict[str, Any]:
    """Siembra idempotente y auditada de los 2 incidentes de laboratorio.

    Resuelve los vinculos declarados (activo de M3 y riesgo de M4) contra el
    estado real de la base. Un vinculo declarado que no existe aborta la
    siembra con IncidentSeedError (fail-closed): nunca se siembra un incidente
    con la trazabilidad cortada en silencio.
    """
    existing_codes = {str(i["code"]) for i in db.list_incidents()}
    assets_by_name = {a["name"]: a["id"] for a in db.list_assets()}
    risks_by_code = {r["code"]: r["id"] for r in db.list_risks()}

    created_codes: List[str] = []
    skipped_codes: List[str] = []
    pending_payloads: List[Dict[str, Any]] = []

    for seed in SEED_INCIDENTS:
        if seed["code"] in existing_codes:
            skipped_codes.append(seed["code"])
            continue

        risk_code = seed.get("risk_code")
        asset_name = seed.get("asset_name")

        risk_id: Optional[str] = None
        if risk_code:
            risk_id = risks_by_code.get(risk_code)
            if not risk_id:
                raise IncidentSeedError(
                    "No se pudo sembrar el incidente %s: el riesgo semilla %s "
                    "no existe en la base de datos" % (seed["code"], risk_code)
                )

        asset_id: Optional[str] = None
        if asset_name:
            asset_id = assets_by_name.get(asset_name)
            if not asset_id:
                raise IncidentSeedError(
                    "No se pudo sembrar el incidente %s: el activo semilla %s "
                    "no existe en el inventario" % (seed["code"], asset_name)
                )

        item = dict(seed)
        item["id"] = seed_incident_id(seed["code"])
        item["asset_id"] = asset_id
        item["risk_id"] = risk_id
        item["synthetic"] = 1
        item["created_by"] = "SYSTEM"
        pending_payloads.append(item)

    if pending_payloads:
        audit_event = {
            "action": SEED_AUDIT_ACTION,
            "actor": "SYSTEM",
            "role": "NONE",
            "status": "ALLOWED",
            "details": (
                "Siembra de incidentes de laboratorio F11 (M6): %d incidentes "
                "sinteticos registrados" % len(pending_payloads)
            ),
            "ip": "127.0.0.1",
            "mfa_verified": False,
        }
        created_codes, _record = db.insert_incidents_with_audit_event(
            pending_payloads, audit_event
        )

    return {
        "created": created_codes,
        "skipped": skipped_codes,
        "total_catalog": len(SEED_INCIDENTS),
        "already_seeded": len(created_codes) == 0,
    }
