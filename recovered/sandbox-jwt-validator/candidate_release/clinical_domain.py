#!/usr/bin/env python3
"""
clinical_domain.py - Reglas de dominio clínico puras para el LIS
SGSI-ZTA Hospital Lab — ISO/IEC 27001:2022 Control A.8.15 & NIST SP 800-207

Este módulo concentra la máquina de estados de la orden clínica, el esquema de
mediciones aceptadas, la pseudonimización del paciente y el sello de integridad
del contenido validado. No realiza E/S, no accede a variables de entorno y no
depende de la capa de persistencia.
"""

import hashlib
import hmac
import json
import math
from typing import Any, Dict


class ClinicalRuleError(Exception):
    """Violación de una regla de dominio clínico (estado o mediciones)."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


# Estados de la orden clínica (máquina de estados explícita)
ORDER_CREATED = "CREATED"
ORDER_SAMPLE_COLLECTED = "SAMPLE_COLLECTED"
ORDER_ANALYZED = "ANALYZED"
ORDER_RELEASED = "VALIDATED_AND_RELEASED"

ORDER_STATUSES = frozenset({
    ORDER_CREATED,
    ORDER_SAMPLE_COLLECTED,
    ORDER_ANALYZED,
    ORDER_RELEASED,
})

ALLOWED_TRANSITIONS = {
    ORDER_CREATED: frozenset({ORDER_SAMPLE_COLLECTED}),
    ORDER_SAMPLE_COLLECTED: frozenset({ORDER_ANALYZED}),
    ORDER_ANALYZED: frozenset({ORDER_RELEASED}),
    ORDER_RELEASED: frozenset(),
}

TERMINAL_STATUSES = frozenset({ORDER_RELEASED})

# Esquema de mediciones: clave -> (mínimo inclusive, máximo inclusive, unidad)
MEASUREMENT_SCHEMA = {
    "hemoglobina_g_dl": (3.0, 25.0, "g/dL"),
    "hematocrito_pct": (10.0, 75.0, "%"),
    "leucocitos_mm3": (100.0, 100000.0, "/mm3"),
    "plaquetas_k_ul": (5.0, 1500.0, "10^3/uL"),
    "glucosa_mg_dl": (10.0, 900.0, "mg/dL"),
    "glucosa": (10.0, 900.0, "mg/dL"),
    "creatinina_mg_dl": (0.1, 20.0, "mg/dL"),
    "sodio_mmol_l": (90.0, 190.0, "mmol/L"),
    "potasio_mmol_l": (1.0, 10.0, "mmol/L"),
}

# Claves canónicas del contenido de la orden cubiertas por el sello de integridad.
CANONICAL_ORDER_KEYS = (
    "order_id",
    "patient_dni",
    "test_type",
    "status",
    "created_by",
    "created_at",
    "measurements",
    "validated_by",
    "observations",
    "validated_at",
    "version",
)


def validate_measurements(measurements: Any) -> Dict[str, float]:
    """
    Valida un conjunto de mediciones contra el esquema clínico permitido.

    Exige un diccionario no vacío, claves conocidas, valores numéricos finitos
    (los booleanos no son mediciones válidas) y dentro del rango inclusive.
    Devuelve una copia nueva con valores normalizados a float.
    """
    if measurements is None or not isinstance(measurements, dict) or not measurements:
        raise ClinicalRuleError(
            "MEASUREMENTS_REQUIRED",
            "Se requiere al menos una medición clínica para la orden.",
        )

    validated: Dict[str, float] = {}
    for key, value in measurements.items():
        if not isinstance(key, str) or key not in MEASUREMENT_SCHEMA:
            raise ClinicalRuleError(
                "INVALID_MEASUREMENTS",
                f"Analito no reconocido en el esquema clínico: {key!r}.",
            )
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ClinicalRuleError(
                "INVALID_MEASUREMENTS",
                f"El valor de '{key}' debe ser numérico, recibido: {type(value).__name__}.",
            )
        try:
            finite = math.isfinite(value)
        except (OverflowError, TypeError, ValueError):
            finite = False
        if not finite:
            raise ClinicalRuleError(
                "INVALID_MEASUREMENTS",
                f"El valor de '{key}' debe ser un número finito.",
            )

        minimum, maximum, unit = MEASUREMENT_SCHEMA[key]
        if value < minimum or value > maximum:
            raise ClinicalRuleError(
                "INVALID_MEASUREMENTS",
                f"El valor de '{key}' está fuera de rango ({minimum}-{maximum} {unit}).",
            )
        validated[key] = float(value)

    return validated


def assert_transition(current: str, target: str) -> None:
    """
    Comprueba que la transición de estado solicitada es legal.

    La reingesta del mismo estado sobre una orden no terminal se acepta como
    operación idempotente (no-op). Los estados terminales no admiten transición.
    """
    if current not in ORDER_STATUSES or target not in ORDER_STATUSES:
        raise ClinicalRuleError(
            "INVALID_ORDER_TRANSITION",
            f"Estado desconocido en la transición '{current}' -> '{target}'.",
        )

    if current == target:
        if current in TERMINAL_STATUSES:
            raise ClinicalRuleError(
                "INVALID_ORDER_TRANSITION",
                f"La orden está en estado terminal '{current}' y no admite transiciones.",
            )
        return

    if target not in ALLOWED_TRANSITIONS[current]:
        raise ClinicalRuleError(
            "INVALID_ORDER_TRANSITION",
            f"Transición no permitida: '{current}' -> '{target}'.",
        )


def patient_reference(patient_dni: str) -> str:
    """Devuelve una referencia pseudonimizada y estable del paciente (sin PHI)."""
    if not isinstance(patient_dni, str) or not patient_dni.strip():
        return "ref:unknown"
    digest = hashlib.sha256(patient_dni.strip().encode("utf-8")).hexdigest()
    return "ref:" + digest[:12]


def canonical_order_content(order: Dict[str, Any]) -> Dict[str, Any]:
    """
    Construye la representación canónica y determinista del contenido de la orden.

    Excluye campos volátiles o derivados (sello, algoritmo, alcance, resultado de
    verificación y dispositivo) para que el sello sea reproducible.
    """
    measurements = order.get("measurements")
    if not isinstance(measurements, dict):
        measurements = {}

    content: Dict[str, Any] = {
        key: order.get(key) for key in CANONICAL_ORDER_KEYS
    }
    content["measurements"] = dict(measurements)
    return content


def _canonical_bytes(order: Dict[str, Any]) -> bytes:
    """Serializa el contenido canónico con separadores estables."""
    return json.dumps(
        canonical_order_content(order),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def order_content_hash(order: Dict[str, Any]) -> str:
    """Calcula el hash SHA-256 del contenido canónico de la orden."""
    return hashlib.sha256(_canonical_bytes(order)).hexdigest()


def compute_integrity_seal(order: Dict[str, Any], key: bytes) -> str:
    """Calcula el sello HMAC-SHA256 del contenido canónico de la orden."""
    return hmac.new(key, _canonical_bytes(order), hashlib.sha256).hexdigest()


def verify_integrity_seal(order: Dict[str, Any], key: bytes) -> bool:
    """Verifica el sello de integridad; falla cerrado ante ausencia o error."""
    try:
        stored = order.get("integrity_seal", "")
        if not isinstance(stored, str) or not stored:
            return False
        expected = compute_integrity_seal(order, key)
        return hmac.compare_digest(expected, stored)
    except Exception:
        return False
