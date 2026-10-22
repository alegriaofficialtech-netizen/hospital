#!/usr/bin/env python3
"""Modulo M4 de Gestion de Riesgos del laboratorio SGSI-ZTA (F11).

Soporta el Objetivo O2 de la tesis doctoral: matriz de riesgos, amenazas,
vulnerabilidades, probabilidad e impacto segun matriz 5x5, calculo de riesgo
inherente y residual, responsables funcionales, tratamientos y seguimiento.

Reglas del modulo:
* Los riesgos se apoyan en los activos reales de M3 y en los hallazgos de M2.
* El vinculo O1 -> O2 (finding_id) apunta a un hallazgo real de
  security_findings; el comprobador de origen declarado se guarda aparte en
  source_checker y no se confunde con un hallazgo.
* 'owner_role' es siempre un rol o equipo, nunca el nombre de una persona.
* El calculo de riesgo es determinista: Score = Probabilidad (1..5) x Impacto (1..5).
* La siembra es idempotente y auditada con la accion 'RISK_SEED'.
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
    RISK_CATEGORIES,
    RISK_LEVELS,
    RISK_STATUSES,
    RISK_TREATMENTS,
    calculate_risk_level,
)

SEED_AUDIT_ACTION = "RISK_SEED"

# Catalogo semilla de riesgos tecnicos reales sobre el laboratorio F11.
# Vinculados a activos reales de M3 y hallazgos reales de comprobadores de M2.
SEED_RISKS: List[Dict[str, Any]] = [
    {
        "code": "RSK-F11-IAM-01",
        "name": "Acceso administrativo sin segundo factor TOTP",
        "description": (
            "Riesgo de compromiso de privilegios administrativos por identidades que "
            "tienen asignado el rol sgsi-admin sin obligatoriedad de MFA (caso medico.sinmfa "
            "o cuentas antes de su enrolamiento)."
        ),
        "category": "identidad",
        "asset_name": "keycloak-iam",
        "source_checker": "KC_MFA_ON_ADMIN_IDENTITIES",
        "threat": "Suplantacion de credenciales administrativas en consola de gestion",
        "vulnerability": "Configuracion de identidades administrativas sin enforcement estricto de OTP",
        "probability_inherent": 4,
        "impact_inherent": 5,
        "treatment": "MITIGAR",
        "probability_residual": 1,
        "impact_residual": 4,
        "owner_role": "ROLE_SECURITY_AUDITOR",
        "status": "CONTROLADO",
        "synthetic": 0,
    },
    {
        "code": "RSK-F11-CONT-02",
        "name": "Capacidades excesivas en contenedor de gestion de identidades",
        "description": (
            "El contenedor Keycloak en compose.yaml no define cap_drop: ALL, dejando "
            "capacidades del kernel Linux innecesarias para el servicio IAM."
        ),
        "category": "infraestructura",
        "asset_name": "compose-f11",
        "source_checker": "CONTAINER_HARDENING",
        "threat": "Escape de contenedor o persistencia de atacante mediante capacidades privilegiadas",
        "vulnerability": "Ausencia de restriccion cap_drop: ALL en el servicio keycloak",
        "probability_inherent": 3,
        "impact_inherent": 4,
        "treatment": "MITIGAR",
        "probability_residual": 2,
        "impact_residual": 3,
        "owner_role": "ROLE_PLATFORM_ADMIN",
        "status": "EN_TRATAMIENTO",
        "synthetic": 0,
    },
    {
        "code": "RSK-F11-AUDIT-03",
        "name": "Riesgo de manipulacion o discontinuidad en registros de auditoria clinica",
        "description": (
            "Manipulacion no detectada de historiales de ordenes medicas o eventos de gestion "
            "si fallara la verificacion del ancla HMAC o la cadena SHA-256."
        ),
        "category": "datos",
        "asset_name": "audit-chain",
        "source_checker": "BACKEND_AUDIT_CHAIN_VALID",
        "threat": "Repudio de acciones clinicas o administrativas por alteracion de bitacora",
        "vulnerability": "Dependencia critica de la continuidad criptografica en SQLite",
        "probability_inherent": 4,
        "impact_inherent": 5,
        "treatment": "MITIGAR",
        "probability_residual": 1,
        "impact_residual": 5,
        "owner_role": "ROLE_SECURITY_AUDITOR",
        "status": "CONTROLADO",
        "synthetic": 0,
    },
    {
        "code": "RSK-F11-CRED-04",
        "name": "Exposicion de credenciales en el navegador o bundle frontend",
        "description": (
            "Captura de contrasenas de usuarios en el navegador si los formularios de autenticacion "
            "fueran renderizados directamente por la SPA en lugar de delegarse a Keycloak."
        ),
        "category": "software",
        "asset_name": "frontend-angular-bundle",
        "source_checker": "FRONTEND_BUNDLE_HAS_NO_PASSWORD_FIELD",
        "threat": "Robo de credenciales de medicos o analistas mediante ataques Cross-Site Scripting (XSS)",
        "vulnerability": "Manejo inseguro de contrasenas en memoria de la aplicacion frontend",
        "probability_inherent": 4,
        "impact_inherent": 4,
        "treatment": "EVITAR",
        "probability_residual": 1,
        "impact_residual": 4,
        "owner_role": "ROLE_PLATFORM_ADMIN",
        "status": "CONTROLADO",
        "synthetic": 0,
    },
    {
        "code": "RSK-F11-DATA-05",
        "name": "Acceso no autorizado a ficheros SQLite y secretos locales en disco",
        "description": (
            "Procesos locales del host Debian que pudieran leer lis.db o credentials.json si "
            "los permisos del sistema de ficheros fueran mas permisivos que 0600."
        ),
        "category": "datos",
        "asset_name": "clinical-sqlite-db",
        "source_checker": "DATA_FILES_OWNER_ONLY",
        "threat": "Exfiltracion directa de datos clinicos o tokens por usuarios o daemons del servidor",
        "vulnerability": "Permisos de lectura a grupos u otros usuarios en archivos sensibles",
        "probability_inherent": 3,
        "impact_inherent": 5,
        "treatment": "MITIGAR",
        "probability_residual": 1,
        "impact_residual": 5,
        "owner_role": "ROLE_PLATFORM_ADMIN",
        "status": "CONTROLADO",
        "synthetic": 0,
    },
]


def seed_risk_id(code: str) -> str:
    """Calcula un ID determinista para un riesgo a partir de su codigo."""
    digest = hashlib.sha256(code.encode("utf-8")).hexdigest()[:8].upper()
    return f"RSK-{digest}"


def validate_risk(payload: Dict[str, Any], partial: bool = False) -> List[str]:
    """Valida los campos de un riesgo segun el contrato de F3."""
    errors: List[str] = []

    def present(f: str) -> bool:
        return f in payload and payload[f] is not None

    if not partial or present("code"):
        code = str(payload.get("code") or "").strip()
        if not code or len(code) < 3 or len(code) > 64:
            errors.append("code: debe tener entre 3 y 64 caracteres")

    if not partial or present("name"):
        name = str(payload.get("name") or "").strip()
        if not name or len(name) < 3 or len(name) > 120:
            errors.append("name: debe tener entre 3 y 120 caracteres")

    if not partial or present("category"):
        cat = str(payload.get("category") or "").strip().lower()
        if cat not in RISK_CATEGORIES:
            errors.append(f"category: debe ser una de {list(RISK_CATEGORIES)}")

    if not partial or present("threat"):
        threat = str(payload.get("threat") or "").strip()
        if not threat or len(threat) < 3:
            errors.append("threat: debe describir la amenaza (minimo 3 caracteres)")

    if not partial or present("vulnerability"):
        vuln = str(payload.get("vulnerability") or "").strip()
        if not vuln or len(vuln) < 3:
            errors.append("vulnerability: debe describir la vulnerabilidad (minimo 3 caracteres)")

    if not partial or present("probability_inherent"):
        try:
            val = int(payload.get("probability_inherent"))
            if not 1 <= val <= 5:
                errors.append("probability_inherent: debe ser un entero entre 1 y 5")
        except (ValueError, TypeError):
            errors.append("probability_inherent: debe ser numerico entre 1 y 5")

    if not partial or present("impact_inherent"):
        try:
            val = int(payload.get("impact_inherent"))
            if not 1 <= val <= 5:
                errors.append("impact_inherent: debe ser un entero entre 1 y 5")
        except (ValueError, TypeError):
            errors.append("impact_inherent: debe ser numerico entre 1 y 5")

    if not partial or present("treatment"):
        tto = str(payload.get("treatment") or "").strip().upper()
        if tto not in RISK_TREATMENTS:
            errors.append(f"treatment: debe ser uno de {list(RISK_TREATMENTS)}")

    if not partial or present("status"):
        st = str(payload.get("status") or "").strip().upper()
        if st not in RISK_STATUSES:
            errors.append(f"status: debe ser uno de {list(RISK_STATUSES)}")

    return errors


def latest_finding_id(db: Any, checker_id: Optional[str]) -> Optional[str]:
    """Id del hallazgo real mas reciente de un comprobador de M2, o None.

    El vinculo O1 -> O2 solo apunta a filas reales de security_findings. Un
    comprobador que todavia no se ejecuto no tiene hallazgo y NO se sustituye
    por su codigo: en ese caso el vinculo queda en None y el codigo del
    comprobador sigue visible en source_checker como origen declarado.
    """
    if not checker_id:
        return None
    findings = db.list_security_findings(checker_id=str(checker_id), limit=1)
    if not findings:
        return None
    return str(findings[0]["id"])


def seed_risk_catalog(db: Any) -> Dict[str, Any]:
    """Siembra idempotente y auditada del catalogo de riesgos."""
    if db.count_audit_events_by_action(SEED_AUDIT_ACTION) > 0:
        return {
            "created": [],
            "skipped": [r["code"] for r in SEED_RISKS],
            "total_catalog": len(SEED_RISKS),
            "already_seeded": True,
        }

    assets = {a["name"]: a["id"] for a in db.list_assets()}
    payloads: List[Dict[str, Any]] = []

    for r in SEED_RISKS:
        item = dict(r)
        item["id"] = seed_risk_id(r["code"])
        item["asset_id"] = assets.get(r.get("asset_name"))
        # Trazabilidad O1 -> O2 real: el origen declarado es el comprobador de
        # M2 (source_checker), pero el vinculo (finding_id) apunta al id de un
        # hallazgo real de security_findings. Si el diagnostico aun no se
        # ejecuto y no hay hallazgo, el vinculo queda en None en lugar de
        # guardar el codigo del comprobador como si fuera un hallazgo.
        checker = r.get("source_checker")
        item["source_checker"] = checker
        item["finding_id"] = latest_finding_id(db, checker)
        payloads.append(item)

    audit_event = {
        "action": SEED_AUDIT_ACTION,
        "actor": "SYSTEM",
        "role": "NONE",
        "status": "ALLOWED",
        "details": f"Siembra de matriz de riesgos F11 (O2): {len(payloads)} riesgos registrados",
        "ip": "127.0.0.1",
        "mfa_verified": False,
    }

    created, _record = db.insert_risks_with_audit_event(payloads, audit_event)
    return {
        "created": created,
        "skipped": [],
        "total_catalog": len(SEED_RISKS),
        "already_seeded": False,
    }
