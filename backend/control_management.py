#!/usr/bin/env python3
"""Modulo M5 de Gestion de Controles del laboratorio SGSI-ZTA (F11).

Soporta el Objetivo O3 de la tesis doctoral: catalogo de controles alineados
con ISO/IEC 27001:2022, NIST SP 800-207 y CISA Zero Trust Maturity Model.
Vinculacion con riesgos (M4), activos (M3), responsables y evidencias reales.

Regla central de evidencia:
* Los controles se clasifican estrictamente en PROPUESTO, IMPLEMENTADO o VERIFICADO.
* Un control NUNCA puede declararse VERIFICADO sin evidencia real enlazada
  (comprobador ejecutable, prueba automatizada o evento de auditoria verificado).
* La siembra es idempotente y auditada con la accion 'CONTROL_SEED'.
* La siembra falla cerrada: si un enlace riesgo-control no se puede crear, la
  siembra se aborta con ControlSeedError en lugar de dejar la matriz de
  trazabilidad incompleta sin rastro.
"""

from __future__ import annotations

import hashlib
import os
import sys
import time
from typing import Any, Dict, List, Optional

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from database import (
    CONTROL_EFFECTIVENESS,
    CONTROL_EVIDENCE_TYPES,
    CONTROL_FRAMEWORKS,
    CONTROL_STATUSES,
)

SEED_AUDIT_ACTION = "CONTROL_SEED"


class ControlSeedError(RuntimeError):
    """Siembra abortada: la matriz de trazabilidad quedaria incompleta.

    La siembra de controles es idempotente, igual que la del inventario de
    activos. Un enlace riesgo-control que no se puede crear se reporta con esta
    excepcion en lugar de ignorarse: el arranque falla cerrado y el operador ve
    exactamente que par quedo sin vincular. Un reintento completa lo que falte.
    """


# Catalogo semilla de controles alineados con ISO 27001:2022, NIST SP 800-207 y CISA ZTM.
SEED_CONTROLS: List[Dict[str, Any]] = [
    {
        "code": "ISO-A.5.15",
        "framework": "ISO_27001_2022",
        "clause_or_pillar": "A.5 Control de accesos",
        "name": "Autenticacion multifactor para accesos privilegiados",
        "description": (
            "Exigencia obligatoria de segundo factor TOTP para toda identidad con privilegios "
            "administrativos y operaciones de modificacion de la plataforma."
        ),
        "owner_role": "ROLE_SECURITY_AUDITOR",
        "status": "VERIFICADO",
        "evidence_type": "checker",
        "evidence_reference": "BACKEND_ADMIN_REQUIRES_MFA",
        "compliance_score": 1.0,
        "synthetic": 0,
    },
    {
        "code": "ISO-A.8.2",
        "framework": "ISO_27001_2022",
        "clause_or_pillar": "A.8 Tecnologico - Privilegios",
        "name": "Menor privilegio y proteccion del rol de plataforma",
        "description": (
            "El rol sgsi-admin no puede ser asignado ni auto-concedido desde la interfaz "
            "ni desde llamadas ordinarias de la API."
        ),
        "owner_role": "ROLE_PLATFORM_ADMIN",
        "status": "VERIFICADO",
        "evidence_type": "checker",
        "evidence_reference": "KC_PROTECTED_ROLE_NOT_GRANTABLE",
        "compliance_score": 1.0,
        "synthetic": 0,
    },
    {
        "code": "ISO-A.8.15",
        "framework": "ISO_27001_2022",
        "clause_or_pillar": "A.8 Tecnologico - Registro",
        "name": "Registro de eventos y cadena de auditoria inmutable",
        "description": (
            "Registro de toda accion clinica y administrativa encadenada criptograficamente "
            "mediante SHA-256 y ancla HMAC con verificacion continua de integridad."
        ),
        "owner_role": "ROLE_SECURITY_AUDITOR",
        "status": "VERIFICADO",
        "evidence_type": "checker",
        "evidence_reference": "BACKEND_AUDIT_CHAIN_VALID",
        "compliance_score": 1.0,
        "synthetic": 0,
    },
    {
        "code": "ISO-A.8.24",
        "framework": "ISO_27001_2022",
        "clause_or_pillar": "A.8 Tecnologico - Criptografia",
        "name": "Flujo de autorizacion OIDC con PKCE S256",
        "description": (
            "El intercambio del codigo de autorizacion exige prueba de clave con SHA-256, "
            "impidiendo la interceptacion del codigo en clientes publicos."
        ),
        "owner_role": "ROLE_PLATFORM_ADMIN",
        "status": "VERIFICADO",
        "evidence_type": "checker",
        "evidence_reference": "KC_PKCE_S256",
        "compliance_score": 1.0,
        "synthetic": 0,
    },
    {
        "code": "NIST-ZTA-T1",
        "framework": "NIST_SP_800_207",
        "clause_or_pillar": "Tenet 1: Recursos",
        "name": "Todos los servicios y origenes de datos se consideran recursos protegidos",
        "description": (
            "La API del LIS clinico delega la verificacion al emisor de identidades (Keycloak) "
            "y no expone endpoints clinicos sin validacion criptografica del JWT."
        ),
        "owner_role": "ROLE_PLATFORM_ADMIN",
        "status": "VERIFICADO",
        "evidence_type": "checker",
        "evidence_reference": "BACKEND_AUTH_DELEGATED_TO_KEYCLOAK",
        "compliance_score": 1.0,
        "synthetic": 0,
    },
    {
        "code": "NIST-ZTA-T6",
        "framework": "NIST_SP_800_207",
        "clause_or_pillar": "Tenet 6: Acceso Dinamico",
        "name": "Autorizacion dinamica en PEP antes de otorgar acceso a recursos sensibles",
        "description": (
            "El PEP en backend valida roles del token y segundo factor acreditado (amr otp) "
            "en tiempo de ejecucion para cada solicitud individual."
        ),
        "owner_role": "ROLE_SECURITY_AUDITOR",
        "status": "VERIFICADO",
        "evidence_type": "checker",
        "evidence_reference": "BACKEND_ADMIN_REQUIRES_MFA",
        "compliance_score": 1.0,
        "synthetic": 0,
    },
    {
        "code": "CISA-ID-01",
        "framework": "CISA_ZTM",
        "clause_or_pillar": "Identidad",
        "name": "Validacion de identidad con MFA obligatoria basada en estandares",
        "description": (
            "Realm de Keycloak configurado con politicas de contrasena y segundo factor "
            "TOTP estandar RFC 6238 en identidades funcionales."
        ),
        "owner_role": "ROLE_SECURITY_AUDITOR",
        "status": "VERIFICADO",
        "evidence_type": "checker",
        "evidence_reference": "KC_MFA_ON_ADMIN_IDENTITIES",
        "compliance_score": 1.0,
        "synthetic": 0,
    },
    {
        "code": "CISA-APP-01",
        "framework": "CISA_ZTM",
        "clause_or_pillar": "Aplicaciones y Cargas de Trabajo",
        "name": "Aplicaciones seguras sin captura ni almacenamiento de credenciales",
        "description": (
            "El bundle de Angular no contiene formularios de contrasena ni captura credenciales; "
            "la autenticacion se delega por completo a la ventana de Keycloak."
        ),
        "owner_role": "ROLE_PLATFORM_ADMIN",
        "status": "VERIFICADO",
        "evidence_type": "checker",
        "evidence_reference": "FRONTEND_BUNDLE_HAS_NO_PASSWORD_FIELD",
        "compliance_score": 1.0,
        "synthetic": 0,
    },
    {
        "code": "CISA-DEV-01",
        "framework": "CISA_ZTM",
        "clause_or_pillar": "Dispositivos e Infraestructura",
        "name": "Aislamiento de privilegios y reduccion de capacidades de contenedores",
        "description": (
            "Endurecimiento de los servicios dockerizados con no-new-privileges y cap_drop. "
            "Estado IMPLEMENTADO en Caddy; pendiente completar cap_drop: ALL en Keycloak."
        ),
        "owner_role": "ROLE_PLATFORM_ADMIN",
        "status": "IMPLEMENTADO",
        "evidence_type": "config_file",
        "evidence_reference": "infra/f11/compose.yaml",
        "compliance_score": 0.5,
        "synthetic": 0,
    },
]

# Enlaces entre riesgos (M4) y controles (M5)
SEED_RISK_CONTROL_LINKS = [
    ("RSK-F11-IAM-01", "ISO-A.5.15", "PREVENTIVO"),
    ("RSK-F11-IAM-01", "NIST-ZTA-T6", "PREVENTIVO"),
    ("RSK-F11-IAM-01", "CISA-ID-01", "PREVENTIVO"),
    ("RSK-F11-CONT-02", "CISA-DEV-01", "PREVENTIVO"),
    ("RSK-F11-AUDIT-03", "ISO-A.8.15", "DETECTIVO"),
    ("RSK-F11-CRED-04", "ISO-A.8.24", "PREVENTIVO"),
    ("RSK-F11-CRED-04", "CISA-APP-01", "PREVENTIVO"),
    ("RSK-F11-DATA-05", "NIST-ZTA-T1", "PREVENTIVO"),
]


def seed_control_id(code: str) -> str:
    """Calcula un ID determinista para un control a partir de su codigo."""
    digest = hashlib.sha256(code.encode("utf-8")).hexdigest()[:8].upper()
    return f"CTL-{digest}"


def validate_control(payload: Dict[str, Any], partial: bool = False) -> List[str]:
    """Valida los campos de un control segun el contrato de F3."""
    errors: List[str] = []

    def present(f: str) -> bool:
        return f in payload and payload[f] is not None

    if not partial or present("code"):
        code = str(payload.get("code") or "").strip()
        if not code or len(code) < 3 or len(code) > 64:
            errors.append("code: debe tener entre 3 y 64 caracteres")

    if not partial or present("framework"):
        fw = str(payload.get("framework") or "").strip()
        if fw not in CONTROL_FRAMEWORKS:
            errors.append(f"framework: debe ser uno de {list(CONTROL_FRAMEWORKS)}")

    if not partial or present("clause_or_pillar"):
        cl = str(payload.get("clause_or_pillar") or "").strip()
        if not cl or len(cl) < 2 or len(cl) > 120:
            errors.append("clause_or_pillar: debe tener entre 2 y 120 caracteres")

    if not partial or present("name"):
        name = str(payload.get("name") or "").strip()
        if not name or len(name) < 3 or len(name) > 150:
            errors.append("name: debe tener entre 3 y 150 caracteres")

    if not partial or present("description"):
        desc = str(payload.get("description") or "").strip()
        if not desc or len(desc) < 3:
            errors.append("description: debe describir el objetivo del control")

    if not partial or present("status"):
        st = str(payload.get("status") or "").strip().upper()
        if st not in CONTROL_STATUSES:
            errors.append(f"status: debe ser uno de {list(CONTROL_STATUSES)}")

        # Regla estricta: VERIFICADO requiere evidencia
        if st == "VERIFICADO":
            ev_type = payload.get("evidence_type")
            ev_ref = payload.get("evidence_reference")
            if not ev_type or ev_type == "none" or not ev_ref:
                errors.append("status: un control VERIFICADO requiere evidence_type y evidence_reference validos")

    return errors


def seed_control_catalog(db: Any) -> Dict[str, Any]:
    """Siembra idempotente y auditada del catalogo de controles y enlaces de riesgo."""
    existing_controls = db.list_controls()
    existing_codes = {c["code"] for c in existing_controls}

    created_codes: List[str] = []
    skipped_codes: List[str] = []

    pending_payloads: List[Dict[str, Any]] = []
    for c in SEED_CONTROLS:
        if c["code"] in existing_codes:
            skipped_codes.append(c["code"])
        else:
            item = dict(c)
            item["id"] = seed_control_id(c["code"])
            pending_payloads.append(item)

    if pending_payloads:
        audit_event = {
            "action": SEED_AUDIT_ACTION,
            "actor": "SYSTEM",
            "role": "NONE",
            "status": "ALLOWED",
            "details": f"Siembra de controles SGSI-ZTA (O3): {len(pending_payloads)} controles registrados",
            "ip": "127.0.0.1",
            "mfa_verified": False,
        }
        created_codes, _record = db.insert_controls_with_audit_event(pending_payloads, audit_event)

    # Vincular riesgos con controles de forma idempotente
    risks_map = {r["code"]: r["id"] for r in db.list_risks()}
    controls_map = {c["code"]: c["id"] for c in db.list_controls()}

    for risk_code, ctl_code, eff in SEED_RISK_CONTROL_LINKS:
        r_id = risks_map.get(risk_code)
        c_id = controls_map.get(ctl_code)

        # Un enlace semilla sin extremo existente tambien deja la matriz
        # incompleta: se trata como fallo, no como enlace omitido.
        if not r_id or not c_id:
            missing = "riesgo" if not r_id else "control"
            raise ControlSeedError(
                f"No se pudo crear el enlace {risk_code} -> {ctl_code} ({eff}): "
                f"el {missing} semilla no existe en la base de datos"
            )

        try:
            risk_data = db.get_risk(r_id)
            if risk_data is None:
                raise LookupError(f"el riesgo {risk_code} no se puede releer tras la siembra")
            already_linked = any(c.get("id") == c_id for c in (risk_data.get("controls") or []))
            if not already_linked:
                link_audit = {
                    "action": "RISK_CONTROL_LINK",
                    "actor": "SYSTEM",
                    "role": "NONE",
                    "status": "ALLOWED",
                    "details": f"Vinculacion de riesgo {risk_code} con control {ctl_code} ({eff})",
                    "ip": "127.0.0.1",
                    "mfa_verified": False,
                }
                db.link_risk_control_with_audit_event(r_id, c_id, eff, link_audit)
        except Exception as exc:
            # Fail-closed: nunca se ignora en silencio. El mensaje identifica el
            # par concreto y la causa original para que el operador pueda actuar.
            raise ControlSeedError(
                f"Fallo al vincular el riesgo {risk_code} con el control {ctl_code} "
                f"({eff}): {exc}"
            ) from exc

    return {
        "created": created_codes,
        "skipped": skipped_codes,
        "total_catalog": len(SEED_CONTROLS),
        "already_seeded": len(created_codes) == 0,
    }
