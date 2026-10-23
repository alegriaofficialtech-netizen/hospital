#!/usr/bin/env python3
"""Modulo M9 de validacion por expertos del laboratorio SGSI-ZTA (F11).

Soporta el registro de la validacion del modelo Zero Trust por parte de
expertos: el instrumento de medida (herramienta), los items verificables
agrupados por las seis dimensiones del modelo y los dictamenes que cada experto
emite sobre ese instrumento.

Reglas del modulo:
* El sistema REGISTRA dictamenes; nunca los genera. No hay siembra de
  dictamenes ni valores por defecto que simulen una evaluacion. Solo se siembra
  el instrumento, que es una herramienta de medida y no un resultado.
* El ``score`` de un dictamen es una media ponderada DESCRIPTIVA de las
  respuestas (peso de cada item). Es un dato auxiliar, no el veredicto.
* El VEREDICTO lo declara el experto (NO_CUMPLE, CUMPLE_PARCIALMENTE o
  CUMPLE). El sistema no lo deriva del score, no lo corrige y no lo invierte:
  dos dictamenes con exactamente las mismas respuestas y veredictos distintos
  se guardan tal cual, porque la responsabilidad es humana.
* ``synthetic`` se impone en el servidor (siempre 1). La declaracion del
  cliente se ignora, igual que en riesgos, controles e incidentes.
* Toda escritura y su evento de auditoria van en la misma transaccion
  (run_clinical_transaction): o quedan ambos, o no queda ninguno. Las acciones
  de auditoria son INSTRUMENT_CREATE, INSTRUMENT_SEED y VALIDATION_SUBMIT.
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
    INSTRUMENT_STATUSES,
    VALIDATION_DIMENSIONS,
    VERDICTS,
    ExpertReviewValidationError,
    InstrumentValidationError,
    InstrumentNotFoundError,
)

SEED_AUDIT_ACTION = "INSTRUMENT_SEED"

# Codigo del instrumento semilla de la tesis. Es una herramienta de medida:
# declara QUE se observa, no COMO resulta la observacion. No se siembra ningun
# dictamen sobre el.
SEED_INSTRUMENT_CODE = "INSTR-F11-ZTA-01"

# Seis dimensiones del modelo Zero Trust, con al menos dos items verificables
# por dimension. Cada enunciado es comprobable contra la plataforma o sus
# artefactos; ninguno es una opinion.
SEED_INSTRUMENT_ITEMS: List[Dict[str, Any]] = [
    {
        "code": "ID-01",
        "dimension": "identidad",
        "statement": (
            "Toda identidad con privilegios administrativos tiene una credencial "
            "TOTP enrolada y activa en el emisor de identidades."
        ),
        "weight": 2,
    },
    {
        "code": "ID-02",
        "dimension": "identidad",
        "statement": (
            "El rol administrativo de la plataforma no puede asignarse desde la "
            "interfaz ni desde llamadas ordinarias de la API."
        ),
        "weight": 2,
    },
    {
        "code": "ID-03",
        "dimension": "identidad",
        "statement": (
            "El token de acceso de una sesion administrativa acredita segundo "
            "factor (amr otp) y el PEP lo exige en cada operacion sensible."
        ),
        "weight": 1,
    },
    {
        "code": "DIS-01",
        "dimension": "dispositivo",
        "statement": (
            "Los contenedores de la plataforma declaran no-new-privileges y "
            "cap_drop ALL en su configuracion de despliegue."
        ),
        "weight": 2,
    },
    {
        "code": "DIS-02",
        "dimension": "dispositivo",
        "statement": (
            "Los servicios publicados escuchan en la interfaz local o en una red "
            "interna, sin exposicion directa a Internet."
        ),
        "weight": 1,
    },
    {
        "code": "RED-01",
        "dimension": "red",
        "statement": (
            "El flujo OIDC utiliza PKCE con S256 en el intercambio del codigo de "
            "autorizacion."
        ),
        "weight": 2,
    },
    {
        "code": "RED-02",
        "dimension": "red",
        "statement": (
            "Las llamadas a la API clinica exigen un token Bearer con firma "
            "RS256, emisor esperado y audiencia del servicio."
        ),
        "weight": 2,
    },
    {
        "code": "APP-01",
        "dimension": "aplicacion",
        "statement": (
            "El bundle de la aplicacion no contiene formularios de contrasena ni "
            "captura credenciales de usuario."
        ),
        "weight": 1,
    },
    {
        "code": "APP-02",
        "dimension": "aplicacion",
        "statement": (
            "La API delega la autenticacion en el emisor OIDC y no valida "
            "credenciales locales de usuarios clinicos."
        ),
        "weight": 2,
    },
    {
        "code": "DAT-01",
        "dimension": "datos",
        "statement": (
            "Los ficheros de base de datos, credenciales y claves tienen permisos "
            "0600 y pertenecen al usuario del servicio."
        ),
        "weight": 2,
    },
    {
        "code": "DAT-02",
        "dimension": "datos",
        "statement": (
            "La base de datos clinica registra un sello de integridad verificable "
            "por cada orden de laboratorio."
        ),
        "weight": 1,
    },
    {
        "code": "MON-01",
        "dimension": "monitoreo",
        "statement": (
            "Toda accion administrativa o clinica genera un evento encadenado en "
            "la cadena de auditoria SHA-256."
        ),
        "weight": 2,
    },
    {
        "code": "MON-02",
        "dimension": "monitoreo",
        "statement": (
            "El arranque verifica la cadena de auditoria y su checkpoint HMAC "
            "antes de aceptar trafico."
        ),
        "weight": 2,
    },
    {
        "code": "MON-03",
        "dimension": "monitoreo",
        "statement": (
            "El diagnostico de seguridad registra, por cada hallazgo, la operacion "
            "real que lo produjo."
        ),
        "weight": 1,
    },
]


def seed_instrument_payload() -> Dict[str, Any]:
    """Construye el instrumento semilla completo, con sus items numerados."""
    items: List[Dict[str, Any]] = []
    for position, item in enumerate(SEED_INSTRUMENT_ITEMS):
        entry = dict(item)
        entry["position"] = position
        items.append(entry)
    return {
        "code": SEED_INSTRUMENT_CODE,
        "name": "Instrumento de validacion del modelo Zero Trust del laboratorio F11",
        "description": (
            "Instrumento de medida para la validacion por expertos del modelo Zero "
            "Trust aplicado al laboratorio clinico. Agrupa enunciados verificables "
            "en las seis dimensiones del modelo. Es una herramienta: no contiene "
            "ninguna evaluacion ni dictamen."
        ),
        "version": "1.0",
        "scale_min": 1,
        "scale_max": 5,
        "status": "ACTIVO",
        "items": items,
    }


def validate_instrument(payload: Dict[str, Any]) -> List[str]:
    """Valida los campos de un instrumento y devuelve una lista de errores."""
    errors: List[str] = []

    def present(field: str) -> bool:
        return field in payload and payload[field] is not None

    code = str(payload.get("code") or "").strip()
    if not code or len(code) < 3 or len(code) > 64:
        errors.append("code: debe tener entre 3 y 64 caracteres")

    name = str(payload.get("name") or "").strip()
    if not name or len(name) < 3 or len(name) > 200:
        errors.append("name: debe tener entre 3 y 200 caracteres")

    version = str(payload.get("version") or "").strip()
    if not version or len(version) > 32:
        errors.append("version: es obligatoria (maximo 32 caracteres)")

    status = str(payload.get("status") or "BORRADOR").strip().upper()
    if status not in INSTRUMENT_STATUSES:
        errors.append("status: debe ser uno de %s" % list(INSTRUMENT_STATUSES))

    try:
        scale_min = int(payload.get("scale_min", 1))
        scale_max = int(payload.get("scale_max", 5))
        if scale_min >= scale_max:
            errors.append("escala: scale_min debe ser menor que scale_max")
        if scale_min < 0:
            errors.append("escala: scale_min no puede ser negativo")
    except (TypeError, ValueError):
        errors.append("escala: scale_min y scale_max deben ser enteros")

    items = payload.get("items")
    if not isinstance(items, list) or not items:
        errors.append("items: el instrumento debe declarar al menos un item")
    else:
        codes = set()
        for raw in items:
            if not isinstance(raw, dict):
                errors.append("items: cada item debe ser un objeto JSON")
                continue
            item_code = str(raw.get("code") or "").strip()
            if not item_code:
                errors.append("items: todo item requiere un code")
            elif item_code in codes:
                errors.append("items: codigo de item duplicado '%s'" % item_code)
            else:
                codes.add(item_code)
            dimension = str(raw.get("dimension") or "").strip().lower()
            if dimension not in VALIDATION_DIMENSIONS:
                errors.append(
                    "items.%s.dimension: debe ser una de %s"
                    % (item_code or "?", list(VALIDATION_DIMENSIONS))
                )
            statement = str(raw.get("statement") or "").strip()
            if not statement:
                errors.append("items.%s.statement: falta el enunciado" % (item_code or "?"))
            try:
                weight = float(raw.get("weight", 1))
                if weight <= 0:
                    errors.append("items.%s.weight: debe ser mayor que cero" % (item_code or "?"))
            except (TypeError, ValueError):
                errors.append("items.%s.weight: debe ser numerico" % (item_code or "?"))

    return errors


def _audit_event(
    action: str, actor: str, role: str, details: str, mfa_verified: bool = True
) -> Dict[str, Any]:
    """Construye el evento de auditoria de una escritura de M9."""
    return {
        "action": action,
        "actor": actor,
        "role": role,
        "status": "ALLOWED",
        "details": details,
        "ip": "127.0.0.1",
        "mfa_verified": mfa_verified,
    }


def create_instrument(
    db: Any,
    payload: Dict[str, Any],
    actor: str,
    role: str = "ROLE_PLATFORM_ADMIN",
) -> Dict[str, Any]:
    """Da de alta un instrumento de validacion y audita el alta.

    El servidor impone ``synthetic = 1`` e ignora cualquier 'synthetic' del
    payload. El alta registra la herramienta, nunca una evaluacion: un
    instrumento recien creado no tiene dictamenes.
    """
    errors = validate_instrument(payload)
    if errors:
        raise InstrumentValidationError(
            "Instrumento invalido: " + ", ".join(sorted(errors))
        )

    item = dict(payload)
    item["synthetic"] = 1  # se impone en el servidor; se ignora el del payload
    item["status"] = str(item.get("status") or "BORRADOR").strip().upper()
    item["created_by"] = actor
    audit = _audit_event(
        "INSTRUMENT_CREATE",
        actor,
        role,
        "Alta del instrumento %s v%s (%d items)"
        % (item.get("code"), item.get("version"), len(item.get("items") or [])),
    )
    instrument, _record = db.insert_instrument_with_audit_event(item, audit)
    return instrument


def list_instruments(db: Any) -> List[Dict[str, Any]]:
    """Lista los instrumentos registrados con su numero real de items."""
    return db.list_instruments()


def get_instrument(db: Any, instrument_id: str) -> Optional[Dict[str, Any]]:
    """Recupera un instrumento con sus items, o None si no existe."""
    return db.get_instrument(instrument_id)


def _resolve_items(
    instrument: Dict[str, Any], raw_answers: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Resuelve cada respuesta contra un item del instrumento y la normaliza.

    Acepta ``item_id`` o ``item_code``. Un item que no pertenece al instrumento
    se rechaza: no se puede responder a un enunciado de otra herramienta. La
    respuesta duplicada al mismo item tambien se rechaza.
    """
    by_id = {str(i["id"]): i for i in instrument.get("items") or []}
    by_code = {str(i["code"]).upper(): i for i in instrument.get("items") or []}
    resolved: List[Dict[str, Any]] = []
    seen: set = set()
    for raw in raw_answers:
        if not isinstance(raw, dict):
            raise ExpertReviewValidationError("Cada respuesta debe ser un objeto JSON.")
        item = None
        item_id = str(raw.get("item_id") or "").strip()
        item_code = str(raw.get("item_code") or "").strip().upper()
        if item_id:
            item = by_id.get(item_id)
        elif item_code:
            item = by_code.get(item_code)
        if item is None:
            raise ExpertReviewValidationError(
                "El item '%s' no pertenece al instrumento '%s'."
                % (item_id or item_code or "?", instrument.get("code"))
            )
        if item["id"] in seen:
            raise ExpertReviewValidationError(
                "Respuesta duplicada para el item '%s'." % item["code"]
            )
        seen.add(item["id"])
        try:
            score = int(raw.get("score"))
        except (TypeError, ValueError) as exc:
            raise ExpertReviewValidationError(
                "La respuesta del item '%s' debe ser un entero." % item["code"]
            ) from exc
        if not int(instrument["scale_min"]) <= score <= int(instrument["scale_max"]):
            raise ExpertReviewValidationError(
                "La respuesta del item '%s' (%s) queda fuera de la escala %s..%s."
                % (item["code"], score, instrument["scale_min"], instrument["scale_max"])
            )
        resolved.append({
            "item_id": item["id"],
            "score": score,
            "comment": str(raw.get("comment") or "").strip(),
        })
    return resolved


def weighted_score(answers: List[Dict[str, Any]], instrument: Dict[str, Any]) -> float:
    """Media ponderada DESCRIPTIVA de las respuestas, redondeada a 2 decimales.

    El peso de cada item es el declarado en el instrumento. Este valor es solo
    un resumen aritmetico de lo respondido: no decide el veredicto ni lo
    sustituye. Si no hay respuestas devuelve 0.0.
    """
    weights = {str(i["id"]): float(i["weight"]) for i in instrument.get("items") or []}
    total_weight = sum(weights.get(a["item_id"], 1.0) for a in answers)
    if total_weight <= 0:
        return 0.0
    accumulated = sum(a["score"] * weights.get(a["item_id"], 1.0) for a in answers)
    return round(accumulated / total_weight, 2)


def submit_expert_review(
    db: Any,
    payload: Dict[str, Any],
    actor: str,
    role: str = "ROLE_PLATFORM_ADMIN",
) -> Dict[str, Any]:
    """Registra un dictamen emitido por un experto humano y lo audita.

    El dictamen es una DECLARACION del experto: nombre, rol, afiliacion,
    alcance, veredicto y observaciones se guardan tal como los declara. El
    sistema calcula el ``score`` como media ponderada descriptiva de las
    respuestas y lo guarda como dato auxiliar; NO lo usa para asignar, corregir
    ni validar el veredicto. La sinteticidad se impone en el servidor.
    """
    instrument_ref = str(
        payload.get("instrument_id") or payload.get("instrument_code") or ""
    ).strip()
    if not instrument_ref:
        raise ExpertReviewValidationError("El dictamen debe referir un instrumento.")
    instrument = db.get_instrument(instrument_ref)
    if instrument is None:
        raise InstrumentNotFoundError(
            "El instrumento '%s' no existe." % instrument_ref
        )
    if str(instrument["status"]) != "ACTIVO":
        raise ExpertReviewValidationError(
            "El instrumento '%s' no esta ACTIVO (estado: %s)."
            % (instrument["code"], instrument["status"])
        )

    verdict = str(payload.get("verdict") or "").strip().upper()
    if verdict not in VERDICTS:
        raise ExpertReviewValidationError(
            "Veredicto '%s' no admitido. Opciones: %s"
            % (verdict, ", ".join(VERDICTS))
        )
    expert_name = str(payload.get("expert_name") or "").strip()
    if not expert_name:
        raise ExpertReviewValidationError(
            "El dictamen debe registrar el nombre del experto que lo emite."
        )
    expert_role = str(payload.get("expert_role") or "").strip()
    if not expert_role:
        raise ExpertReviewValidationError(
            "El dictamen debe registrar el rol o cargo del experto."
        )

    raw_answers = payload.get("answers")
    if not isinstance(raw_answers, list) or not raw_answers:
        raise ExpertReviewValidationError(
            "El dictamen debe incluir al menos una respuesta por item."
        )
    answers = _resolve_items(instrument, raw_answers)
    score = weighted_score(answers, instrument)

    reviewed_at = str(payload.get("reviewed_at") or "").strip()
    if not reviewed_at:
        reviewed_at = time.strftime("%Y-%m-%d", time.gmtime())
    if len(reviewed_at) < 10:
        raise ExpertReviewValidationError(
            "reviewed_at debe declarar una fecha (YYYY-MM-DD)."
        )

    code = str(payload.get("code") or "").strip()
    if not code:
        code = "EVL-" + hashlib.sha256(
            ("%s|%s|%s|%s" % (instrument["id"], expert_name, reviewed_at, verdict))
            .encode("utf-8")
        ).hexdigest()[:8].upper()

    review = {
        "code": code,
        "instrument_id": instrument["id"],
        "expert_name": expert_name,
        "expert_role": expert_role,
        "expert_affiliation": str(payload.get("expert_affiliation") or "").strip(),
        "scope": str(payload.get("scope") or "").strip(),
        "verdict": verdict,
        "observations": str(payload.get("observations") or "").strip(),
        "score": score,
        "reviewed_at": reviewed_at,
        "synthetic": 1,  # se impone en el servidor; se ignora el del payload
        "created_by": actor,
        "answers": answers,
    }
    audit = _audit_event(
        "VALIDATION_SUBMIT",
        actor,
        role,
        "Registro del dictamen %s sobre %s: veredicto declarado %s (score descriptivo %.2f)"
        % (code, instrument["code"], verdict, score),
    )
    stored, _record = db.insert_expert_review_with_audit_event(review, audit)
    return stored


def list_expert_reviews(db: Any) -> List[Dict[str, Any]]:
    """Lista los dictamenes registrados."""
    return db.list_expert_reviews()


def get_expert_review(db: Any, review_id: str) -> Optional[Dict[str, Any]]:
    """Recupera un dictamen con sus respuestas, o None si no existe."""
    return db.get_expert_review(review_id)


def seed_validation_instrument(db: Any) -> Dict[str, Any]:
    """Siembra idempotente y auditada del UNICO instrumento de validacion.

    No siembra dictamenes: el instrumento es una herramienta y sembrar una
    evaluacion equivaldria a inventar la opinion de un experto. Reintentar la
    siembra no duplica el instrumento ni sus items: si el codigo ya existe, se
    omite.
    """
    existing = db.get_instrument(SEED_INSTRUMENT_CODE)
    if existing is not None:
        return {
            "created": [],
            "skipped": [SEED_INSTRUMENT_CODE],
            "total_catalog": 1,
            "already_seeded": True,
        }

    payload = seed_instrument_payload()
    payload["synthetic"] = 1
    payload["created_by"] = "SYSTEM"
    audit = _audit_event(
        SEED_AUDIT_ACTION,
        "SYSTEM",
        "NONE",
        "Siembra del instrumento de validacion F11 (M9): %s v%s con %d items"
        % (payload["code"], payload["version"], len(payload["items"])),
        mfa_verified=False,
    )
    instrument, _record = db.insert_instrument_with_audit_event(payload, audit)
    return {
        "created": [instrument["code"]],
        "skipped": [],
        "total_catalog": 1,
        "already_seeded": False,
    }
