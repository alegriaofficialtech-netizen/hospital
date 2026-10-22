#!/usr/bin/env python3
"""
Clinical PoC: LIS Backend con Integracion Zero Trust Keycloak JWT/OIDC y Persistencia ACID
SGSI-ZTA Hospital Lab
ISO/IEC 27001:2022 & NIST SP 800-207

Version Candidata de Integracion para Despliegue Principal.
Reemplaza la autenticacion local HMAC por verificacion criptografica RS256 de Keycloak,
aplicando RBAC granular y obligatoriedad de MFA contextual para la validacion clinica.
Mantiene el aislamiento del canal IoMT (/api/v1/iomt/results) y la cadena de auditoria hash.
PERSISTENCIA DURADERA ACID: Almacenamiento relacional en SQLite con modo WAL y colecciones proxy.
"""

import hashlib
import hmac
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

# Asegurar resolucion del modulo de validacion JWT y base de datos
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from identity_admin import (
    IdentityAdminClient,
    IdentityAdminError,
    deliver_credential,
    generate_password,
    summarise_users,
    validate_username,
)
from database import (
    AssetAlreadyExistsError,
    AssetNotFoundError,
    AssetValidationError,
    ClinicalDatabaseManager,
    DatabaseBackedAuditLogs,
    DatabaseBackedOrdersDict,
    DatabaseError,
    DuplicateOrderError,
    F11_ENVIRONMENT,
    IomtReplayError,
    OrderVersionConflictError,
)
from asset_inventory import (
    classifications,
    criticalities,
    seed_catalog,
    validate_asset,
)
from security_diagnostics import (
    CheckResult,
    checker_catalog,
    run_checks,
)
from clinical_domain import (
    ORDER_ANALYZED,
    ORDER_RELEASED,
    ORDER_SAMPLE_COLLECTED,
    TERMINAL_STATUSES,
    ClinicalRuleError,
    assert_transition,
    compute_integrity_seal,
    patient_reference,
    validate_measurements,
    verify_integrity_seal,
)
from jwt_validator import (
    ClinicalAuthContext,
    InsufficientPermissionsError,
    InvalidAudienceError,
    InvalidSignatureError,
    InvalidTokenTypeError,
    JWTValidationError,
    MalformedTokenError,
    MFARequiredError,
    TokenExpiredError,
    TokenNotYetValidError,
    UntrustedIssuerError,
    ZeroTrustJWTValidator,
    enforce_clinical_action,
)

# Cadena de auditoría: hash inicial canónico
ZERO_HASH = "0" * 64

# Marcador de un cuerpo POST que no se pudo parsear como JSON. Las rutas de F2
# lo reciben para responder 400 sin ejecutar nada: un cuerpo roto no puede
# convertirse en un diccionario vacio y, en /diagnostics/runs, disparar la
# ejecucion del catalogo completo por "checker_ids ausente".
INVALID_JSON_BODY = object()

# Claves simétricas por dispositivo IoMT (Canal M2M aislado). Sin defaults.
IOMT_DEVICE_KEYS: Dict[str, bytes] = {}
IOMT_MAX_CLOCK_SKEW_SECONDS = int(os.environ.get("IOMT_MAX_CLOCK_SKEW_SECONDS", "300"))
IOMT_NONCE_TTL_SECONDS = int(os.environ.get("IOMT_NONCE_TTL_SECONDS", "900"))


def load_iomt_device_keys() -> Dict[str, bytes]:
    """
    Carga las claves por dispositivo desde IOMT_DEVICE_KEYS_JSON.

    El valor debe ser un objeto JSON {device-id: secreto}. Los secretos con
    longitud inferior a 16 caracteres se descartan. Ante JSON malformado se
    deshabilita el canal (fail-closed), sin claves por defecto.
    """
    global IOMT_DEVICE_KEYS

    keys: Dict[str, bytes] = {}
    raw_config = os.environ.get("IOMT_DEVICE_KEYS_JSON", "")
    if raw_config:
        try:
            parsed = json.loads(raw_config)
            if not isinstance(parsed, dict):
                raise ValueError("IOMT_DEVICE_KEYS_JSON debe ser un objeto JSON")
            for device_id, secret in parsed.items():
                if isinstance(secret, str) and len(secret) >= 16:
                    keys[str(device_id)] = secret.encode("utf-8")
                else:
                    print(f"[WARN] Secreto IoMT insuficiente para el dispositivo '{device_id}'; ignorado.")
        except Exception as e:
            print(f"[WARN] IOMT_DEVICE_KEYS_JSON inválido ({e}); canal IoMT deshabilitado (fail-closed).")
            keys = {}

    IOMT_DEVICE_KEYS = keys
    return IOMT_DEVICE_KEYS


load_iomt_device_keys()

# Compatibilidad temporal restringida exclusivamente a audit-monitor (Fase 3 Zero Trust)
# Requiere configuracion explicita en almacenamiento externo protegido; sin valores hardcodeados por defecto.
ENABLE_LEGACY_AUTH = os.environ.get("ENABLE_LEGACY_AUTH", "0") == "1"
LEGACY_HMAC_SECRET_STR = os.environ.get("LEGACY_TRANSITION_HMAC_SECRET", "")
LEGACY_HMAC_SECRET = LEGACY_HMAC_SECRET_STR.encode("utf-8") if LEGACY_HMAC_SECRET_STR else None
LEGACY_AUDITOR_HASH = os.environ.get("LEGACY_AUDITOR_PASSWORD_HASH", "")

# Parametros de configuracion OIDC / Keycloak
DEFAULT_DISCOVERY_URL = os.environ.get(
    "KEYCLOAK_DISCOVERY_URL",
    "http://127.0.0.1:8085/realms/hospital-lab/.well-known/openid-configuration"
)
DEFAULT_AUDIENCE = os.environ.get("KEYCLOAK_AUDIENCE", "clinical-poc-api")
DEFAULT_AZP = os.environ.get("KEYCLOAK_EXPECTED_AZP", None)

# Administracion de identidades: el backend es el proxy de confianza hacia la
# API de administracion de Keycloak. La credencial vive en el entorno del
# servidor y nunca se devuelve al navegador.
KEYCLOAK_ADMIN_URL = os.environ.get("KEYCLOAK_ADMIN_URL", "http://127.0.0.1:8085")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "hospital-lab-local")
KEYCLOAK_ADMIN_USERNAME = os.environ.get("KEYCLOAK_ADMIN_USERNAME", "")
KEYCLOAK_ADMIN_PASSWORD = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "")
IDENTITY_RUNTIME_DIR = os.environ.get(
    "F11_RUNTIME_DIR", "/home/elcra/sgsi-zta-runtime/f11"
)


def get_identity_admin() -> IdentityAdminClient:
    if not KEYCLOAK_ADMIN_USERNAME or not KEYCLOAK_ADMIN_PASSWORD:
        raise IdentityAdminError(
            "la administracion de identidades no esta configurada en el servidor",
            status=503,
            code="IDENTITY_ADMIN_NOT_CONFIGURED",
        )
    return IdentityAdminClient(
        KEYCLOAK_ADMIN_URL,
        KEYCLOAK_REALM,
        KEYCLOAK_ADMIN_USERNAME,
        KEYCLOAK_ADMIN_PASSWORD,
    )

# Inicializacion del Gestor de Persistencia Duradera ACID (SQLite WAL)
DB_PATH = os.environ.get("LIS_DB_PATH", os.path.join(CURRENT_DIR, "data", "lis.db"))
db_manager = ClinicalDatabaseManager(db_path=DB_PATH)

# M3 Inventario: el catalogo semilla de activos del laboratorio F11 se inserta
# de forma idempotente, atomica y auditada en el arranque. La siembra se
# ejecuta una sola vez (queda auditada con un evento ASSET_SEED) y un activo
# ya existente no se duplica ni se sobrescribe: su correccion se hace por la
# API, que queda auditada.
# Si la siembra falla el backend NO arranca (fail-closed): arrancar con el
# inventario vacio o a medias publicaria un inventario que no describe lo que
# hay, que es exactamente lo que el modulo M3 no puede hacer.
try:
    SEED_RESULT = seed_catalog(db_manager)
    print(
        "[*] Inventario F11: %d activos creados, %d ya existentes"
        % (len(SEED_RESULT.get("created", [])), len(SEED_RESULT.get("skipped", [])))
    )
except Exception as e:
    print("[FATAL] No se pudo sembrar el inventario de activos: %s" % e, file=sys.stderr)
    raise

# Clave del sello de integridad clínico. Override explícito solo para pruebas.
CLINICAL_SEAL_KEY: Optional[bytes] = None


def get_seal_key() -> bytes:
    """
    Resuelve la clave HMAC del sello de integridad clínico.

    Prioridad: override de módulo (pruebas), CLINICAL_SIGNING_KEY (hex o UTF-8,
    mínimo 16 bytes) o derivación de la clave de anclaje de auditoría.
    """
    if CLINICAL_SEAL_KEY is not None:
        return CLINICAL_SEAL_KEY

    raw_key = os.environ.get("CLINICAL_SIGNING_KEY", "")
    if raw_key:
        try:
            candidate = bytes.fromhex(raw_key)
        except ValueError:
            candidate = raw_key.encode("utf-8")
        if len(candidate) < 16:
            raise RuntimeError("CLINICAL_SIGNING_KEY debe tener al menos 16 bytes de entropía.")
        return candidate

    return hmac.new(db_manager.anchor_key, b"clinical-validation-v1", hashlib.sha256).digest()


class ApiError(Exception):
    """Error de aplicación con mapeo HTTP explícito (se propaga fuera de la transacción)."""

    def __init__(self, status_code: int, code: str, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message

# Estado respaldado en base de datos relacional para el laboratorio clinico
ORDERS_DB = DatabaseBackedOrdersDict(db_manager)
AUDIT_LOGS = DatabaseBackedAuditLogs(db_manager)
LAST_AUDIT_HASH = db_manager.get_last_audit_hash()
LOCK = threading.Lock()

# Account requests: public channel without authentication. The request grants
# no access at all, so it is rate limited per origin to avoid a spam relay.
IDENTITY_REQUEST_LIMIT = 5
IDENTITY_REQUEST_WINDOW_SECONDS = 3600
IDENTITY_REQUEST_HITS: Dict[str, List[float]] = {}


def record_audit_event(
    action: str,
    actor: str,
    role: str,
    status: str,
    details: str,
    ip: str = "127.0.0.1",
    mfa_verified: bool = False,
) -> Dict[str, Any]:
    """Registra un evento en la cadena de auditoria relacional inmutable y duradera."""
    global LAST_AUDIT_HASH
    with LOCK:
        record = db_manager.record_audit_event(
            action=action,
            actor=actor,
            role=role,
            status=status,
            details=details,
            ip=ip,
            mfa_verified=mfa_verified,
        )
        LAST_AUDIT_HASH = record["hash"]
        return record


def _fields_from_errors(errors: List[str]) -> Dict[str, str]:
    """Convierte una lista de errores 'campo: mensaje' en el mapa fields de la respuesta 400."""
    fields: Dict[str, str] = {}
    for error in errors:
        field, _, message = str(error).partition(": ")
        fields[field.strip() or "payload"] = message.strip() or str(error)
    return fields


def verify_audit_chain(events: List[Dict[str, Any]]) -> bool:
    """Verifica la integridad de la cadena local de bloques de auditoria."""
    expected_prev = "0" * 64
    for event in events:
        record = {key: value for key, value in event.items() if key != "hash"}
        digest = hashlib.sha256(json.dumps(record, sort_keys=True).encode("utf-8")).hexdigest()
        if event.get("prev_hash") != expected_prev or event.get("hash") != digest:
            return False
        expected_prev = digest
    return True


class ZeroTrustRequestHandler(BaseHTTPRequestHandler):
    """
    Manejador HTTP Zero Trust para el LIS hospitalario.
    Actua como Policy Enforcement Point (PEP) estricto.
    """

    # Validador inyectable (permite testing o configuracion personalizada)
    validator: Optional[ZeroTrustJWTValidator] = None

    def get_validator(self) -> ZeroTrustJWTValidator:
        if self.validator is not None:
            return self.validator
        if hasattr(self.server, "validator") and self.server.validator is not None:
            return self.server.validator

        # Inicializacion singleton predeterminada
        if not hasattr(self.__class__, "_default_validator") or self.__class__._default_validator is None:
            self.__class__._default_validator = ZeroTrustJWTValidator(
                discovery_url=DEFAULT_DISCOVERY_URL,
                expected_audience=DEFAULT_AUDIENCE,
                expected_authorized_party=DEFAULT_AZP,
                require_bearer_type=False,
            )
        return self.__class__._default_validator

    def send_json(self, status_code: int, data: Dict[str, Any], extra_headers: Optional[Dict[str, str]] = None) -> None:
        """Envia respuesta JSON estandarizada con cabeceras de endurecimiento."""
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'none'")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))

    def extract_and_validate_legacy_audit_token(self) -> Optional[ClinicalAuthContext]:
        """
        Valida token legacy HMAC exclusivamente para el servicio audit-monitor durante la fase de transicion.
        Restringido por sub=auditor y scope=audit_only. Rechaza si faltan secretos o son insuficientes.
        """
        if not ENABLE_LEGACY_AUTH or not LEGACY_HMAC_SECRET or len(LEGACY_HMAC_SECRET) < 32:
            return None
        auth_header = self.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return None
        token_str = auth_header[7:].strip()
        if "::" not in token_str:
            return None
        try:
            payload_str, sig = token_str.split("::", 1)
            expected_sig = hmac.new(LEGACY_HMAC_SECRET, payload_str.encode("utf-8"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, expected_sig):
                return None
            payload = json.loads(payload_str)
            if time.time() > payload.get("exp", 0):
                return None
            if payload.get("sub") != "auditor" or payload.get("scope") != "audit_only":
                return None
            return ClinicalAuthContext(
                subject=payload["sub"],
                username=payload["sub"],
                roles={payload.get("role", "ROLE_SECURITY_AUDITOR")},
                raw_realm_roles={"auditor"},
                mfa_verified=False,
                issuer="legacy-hmac-temporal",
                audience=["clinical-poc-api"],
                issued_at=payload.get("iat", 0),
                expires_at=payload.get("exp", 0),
                token_id=f"legacy-{payload.get('iat', 0)}",
                amr=["pwd"],
                acr=None,
            )
        except Exception:
            return None

    def extract_and_validate_auth(self) -> Tuple[Optional[ClinicalAuthContext], Optional[Tuple[int, Dict[str, Any]]]]:
        """
        Extrae el token Bearer del encabezado Authorization y lo valida criptograficamente.
        Aplica fail-closed y rechazo explicito de tokens malformados o legacy.
        """
        auth_header = self.headers.get("Authorization")
        if not auth_header:
            return None, (401, {
                "error": "Unauthorized",
                "message": "Zero Trust: Encabezado Authorization requerido",
                "code": "MISSING_AUTHORIZATION_HEADER"
            })

        if not auth_header.startswith("Bearer "):
            return None, (401, {
                "error": "Unauthorized",
                "message": "Zero Trust: Esquema de autenticacion debe ser Bearer",
                "code": "INVALID_AUTH_SCHEME"
            })

        token_str = auth_header[7:].strip()
        if not token_str:
            return None, (401, {
                "error": "Unauthorized",
                "message": "Zero Trust: Bearer token vacio",
                "code": "EMPTY_BEARER_TOKEN"
            })

        try:
            validator = self.get_validator()
            context = validator.validate_token(token_str)
            return context, None
        except TokenExpiredError:
            return None, (401, {
                "error": "Unauthorized",
                "message": "Token de acceso expirado",
                "code": "TOKEN_EXPIRED"
            })
        except (InvalidSignatureError, MalformedTokenError):
            return None, (401, {
                "error": "Unauthorized",
                "message": "Firma digital o estructura de token invalida",
                "code": "INVALID_TOKEN_SIGNATURE"
            })
        except InvalidAudienceError:
            return None, (401, {
                "error": "Unauthorized",
                "message": "Audiencia del token no autorizada para el servicio clinico",
                "code": "INVALID_AUDIENCE"
            })
        except InvalidTokenTypeError as e:
            return None, (401, {
                "error": "Unauthorized",
                "message": str(e),
                "code": "INVALID_TOKEN_TYPE"
            })
        except UntrustedIssuerError:
            return None, (401, {
                "error": "Unauthorized",
                "message": "Emisor de identidad no confiable",
                "code": "UNTRUSTED_ISSUER"
            })
        except InsufficientPermissionsError:
            return None, (403, {
                "error": "Forbidden",
                "message": "El sujeto autenticado no posee roles clinicos validos en el LIS",
                "code": "NO_CLINICAL_ROLES"
            })
        except JWTValidationError:
            return None, (401, {
                "error": "Unauthorized",
                "message": "Validacion de credencial OIDC/JWT fallida",
                "code": "JWT_VALIDATION_FAILED"
            })
        except Exception:
            return None, (500, {
                "error": "InternalServerError",
                "message": "Error interno durante la evaluacion de seguridad",
                "code": "SECURITY_EVALUATION_ERROR"
            })

    def do_GET(self) -> None:
        try:
            self._do_GET_internal()
        except DatabaseError as e:
            self.send_json(500, {
                "error": "InternalServerError",
                "message": f"Fallo critico de persistencia duradera (Fail-Closed): {str(e)}",
                "code": "PERSISTENCE_TRANSACTION_FAILED"
            })
        except Exception as e:
            self.send_json(500, {
                "error": "InternalServerError",
                "message": f"Error interno no controlado: {str(e)}",
                "code": "INTERNAL_SERVER_ERROR"
            })

    def _do_GET_internal(self) -> None:
        parsed = urlparse(self.path)
        client_ip = self.client_address[0]

        # 1. Endpoint publico de monitoreo y healthcheck
        if parsed.path == "/health":
            self.send_json(200, {
                "status": "HEALTHY",
                "system": "SGSI-ZTA Hospital LIS (Keycloak Integrated)",
                "timestamp": time.time(),
            })
            return

        # 2. Consulta de Ordenes de Laboratorio (Fase Analitica / Monitoreo)
        if parsed.path == "/api/v1/orders":
            context, err = self.extract_and_validate_auth()
            if err:
                status_code, err_body = err
                record_audit_event("GET_ORDERS", "ANONYMOUS", "NONE", f"DENIED_{status_code}", err_body["message"], client_ip)
                self.send_json(status_code, err_body)
                return

            # Menor privilegio: la política VIEW_ORDERS es la única fuente de verdad
            try:
                enforce_clinical_action(context, "VIEW_ORDERS")
            except InsufficientPermissionsError:
                record_audit_event("GET_ORDERS", context.username, str(list(context.roles)), "DENIED_FORBIDDEN", "Rol no autorizado para listar ordenes (politica VIEW_ORDERS)", client_ip, context.mfa_verified)
                self.send_json(403, {
                    "error": "Forbidden",
                    "message": "Zero Trust: Privilegios insuficientes para consultar ordenes",
                    "code": "INSUFFICIENT_ROLE_PERMISSIONS"
                })
                return

            with LOCK:
                orders_list = list(ORDERS_DB.values())

            # Verificación no persistida del sello de integridad de cada orden
            seal_key = get_seal_key()
            visible_orders = []
            for order in orders_list:
                view = dict(order)
                view["integrity_verified"] = (
                    verify_integrity_seal(order, seal_key) if order.get("integrity_seal") else None
                )
                visible_orders.append(view)

            record_audit_event("GET_ORDERS", context.username, str(list(context.roles)), "ALLOWED", f"Consulta de {len(visible_orders)} ordenes", client_ip, context.mfa_verified)
            self.send_json(200, {"orders": visible_orders, "count": len(visible_orders)})
            return

        # 3. Consulta de Registros de Auditoria (Oficial de Seguridad / Auditor CISO)
        if parsed.path == "/api/v1/admin/identities":
            self._handle_admin_identities_get(client_ip)
            return

        if parsed.path == "/api/v1/admin/roles":
            self._handle_admin_roles_get(client_ip)
            return

        if parsed.path == "/api/v1/audit/events":
            context, err = self.extract_and_validate_auth()
            is_legacy_audit = False
            if err and ENABLE_LEGACY_AUTH:
                legacy_ctx = self.extract_and_validate_legacy_audit_token()
                if legacy_ctx:
                    context = legacy_ctx
                    err = None
                    is_legacy_audit = True

            if err:
                status_code, err_body = err
                record_audit_event("GET_AUDIT_LOGS", "ANONYMOUS", "NONE", f"DENIED_{status_code}", err_body["message"], client_ip)
                self.send_json(status_code, err_body)
                return

            try:
                enforce_clinical_action(context, "VIEW_AUDIT_LOGS")
            except InsufficientPermissionsError:
                record_audit_event("GET_AUDIT_LOGS", context.username, str(list(context.roles)), "DENIED_FORBIDDEN", "Intento de leer auditoria sin rol CISO", client_ip, context.mfa_verified)
                self.send_json(403, {
                    "error": "Forbidden",
                    "message": "Acceso restringido exclusivamente a Oficial de Seguridad",
                    "code": "AUDITOR_ROLE_REQUIRED"
                })
                return

            with LOCK:
                events = [dict(event) for event in AUDIT_LOGS]

            # La fuente de verdad es la base: el checkpoint y el conteo real se
            # comparan siempre, incluso cuando la lista de eventos está vacía.
            chain_valid, chain_error = db_manager.verify_chain_integrity()
            self.send_json(200, {
                "audit_chain_valid": chain_valid,
                "chain_error": chain_error,
                "total_events": len(events),
                "events": events
            })
            return

        # 4. Diagnostico de Seguridad (M2): comprobadores, ejecuciones y hallazgos
        if parsed.path == "/api/v1/diagnostics/checkers":
            self._handle_diagnostics_checkers_get(client_ip)
            return

        if parsed.path == "/api/v1/diagnostics/summary":
            self._handle_diagnostics_summary_get(client_ip)
            return

        if parsed.path == "/api/v1/diagnostics/findings":
            self._handle_diagnostics_findings_get(parsed.query, client_ip)
            return

        if parsed.path == "/api/v1/diagnostics/runs":
            self._handle_diagnostics_runs_get(parsed.query, client_ip)
            return

        if parsed.path.startswith("/api/v1/diagnostics/runs/"):
            run_id = parsed.path[len("/api/v1/diagnostics/runs/"):].strip("/")
            if run_id:
                self._handle_diagnostic_run_get(run_id, client_ip)
                return

        # 5. Inventario de Activos (M3). La ruta de resumen se resuelve ANTES
        #    que la de un activo concreto: /api/v1/assets/summary no es un id.
        if parsed.path == "/api/v1/assets":
            self._handle_assets_get(parsed.query, client_ip)
            return

        if parsed.path == "/api/v1/assets/summary":
            self._handle_assets_summary_get(client_ip)
            return

        if parsed.path.startswith("/api/v1/assets/"):
            asset_id = parsed.path[len("/api/v1/assets/"):].strip("/")
            if asset_id:
                self._handle_asset_get(asset_id, client_ip)
                return

        self.send_json(404, {"error": "NotFound", "message": "Ruta no encontrada"})

    # ------------------------------------------------- administracion de identidades

    def _require_identity_admin(self, action: str, client_ip: str):
        """Autentica y autoriza la administracion de identidades.

        Devuelve (contexto, None) cuando la operacion esta permitida y
        (None, (codigo, cuerpo)) cuando debe rechazarse.
        """
        context, err = self.extract_and_validate_auth()
        if err:
            status_code, err_body = err
            record_audit_event(
                action, "ANONYMOUS", "NONE", f"DENIED_{status_code}",
                err_body["message"], client_ip,
            )
            return None, (status_code, err_body)
        try:
            enforce_clinical_action(context, "MANAGE_IDENTITIES")
        except InsufficientPermissionsError:
            record_audit_event(
                action, context.username, str(list(context.roles)), "DENIED_FORBIDDEN",
                "Intento de administracion de identidades sin rol de administrador de plataforma",
                client_ip, context.mfa_verified,
            )
            return None, (403, {
                "error": "Forbidden",
                "message": "Acceso restringido al administrador de plataforma",
                "code": "PLATFORM_ADMIN_ROLE_REQUIRED",
            })
        except MFARequiredError:
            record_audit_event(
                action, context.username, str(list(context.roles)), "DENIED_MFA_REQUIRED",
                "Intento de administracion de identidades sin MFA acreditada",
                client_ip, context.mfa_verified,
            )
            return None, (403, {
                "error": "Forbidden",
                "message": "La administracion de identidades exige MFA acreditada",
                "code": "MFA_AUTHENTICATION_REQUIRED",
            })
        return context, None

    def _handle_admin_identities_get(self, client_ip: str) -> None:
        context, failure = self._require_identity_admin("LIST_IDENTITIES", client_ip)
        if failure is not None:
            self.send_json(failure[0], failure[1])
            return
        try:
            identities = get_identity_admin().list_users()
        except IdentityAdminError as exc:
            record_audit_event(
                "LIST_IDENTITIES", context.username, str(list(context.roles)),
                "DENIED_ERROR", str(exc)[:200], client_ip, context.mfa_verified,
            )
            self.send_json(exc.status, {
                "error": "IdentityAdminError", "message": str(exc), "code": exc.code,
            })
            return
        record_audit_event(
            "LIST_IDENTITIES", context.username, str(list(context.roles)), "ALLOWED",
            "Listado de %d identidades" % len(identities), client_ip, context.mfa_verified,
        )
        self.send_json(200, {
            "identities": identities,
            "summary": summarise_users(identities),
        })

    def _handle_admin_roles_get(self, client_ip: str) -> None:
        context, failure = self._require_identity_admin("LIST_ROLES", client_ip)
        if failure is not None:
            self.send_json(failure[0], failure[1])
            return
        try:
            roles = get_identity_admin().list_roles()
        except IdentityAdminError as exc:
            record_audit_event(
                "LIST_ROLES", context.username, str(list(context.roles)), "DENIED_ERROR",
                str(exc)[:200], client_ip, context.mfa_verified,
            )
            self.send_json(exc.status, {
                "error": "IdentityAdminError", "message": str(exc), "code": exc.code,
            })
            return
        record_audit_event(
            "LIST_ROLES", context.username, str(list(context.roles)), "ALLOWED",
            "Listado de %d roles" % len(roles), client_ip, context.mfa_verified,
        )
        self.send_json(200, {"roles": roles})

    def _handle_admin_identity_create(self, payload: Dict[str, Any], client_ip: str) -> None:
        context, failure = self._require_identity_admin("CREATE_IDENTITY", client_ip)
        if failure is not None:
            self.send_json(failure[0], failure[1])
            return
        username = str(payload.get("username") or "").strip()
        reason = validate_username(username)
        if reason:
            record_audit_event(
                "CREATE_IDENTITY", context.username, str(list(context.roles)),
                "DENIED_INVALID", reason, client_ip, context.mfa_verified,
            )
            self.send_json(400, {
                "error": "BadRequest", "message": reason, "code": "IDENTITY_INVALID",
            })
            return
        roles = [str(role) for role in (payload.get("roles") or [])]
        require_mfa = bool(payload.get("require_mfa", False))
        temporary_password = generate_password()
        try:
            identity = get_identity_admin().create_user(
                username, temporary_password, roles, require_mfa,
            )
        except IdentityAdminError as exc:
            record_audit_event(
                "CREATE_IDENTITY", context.username, str(list(context.roles)),
                "DENIED_ERROR", str(exc)[:200], client_ip, context.mfa_verified,
            )
            self.send_json(exc.status, {
                "error": "IdentityAdminError", "message": str(exc), "code": exc.code,
            })
            return
        record_audit_event(
            "CREATE_IDENTITY", context.username, str(list(context.roles)), "ALLOWED",
            "Identidad sintetica creada con roles %s" % ",".join(sorted(roles)),
            client_ip, context.mfa_verified,
        )
        credential_file = deliver_credential(
            IDENTITY_RUNTIME_DIR, username, temporary_password,
        )
        self.send_json(201, {
            "identity": identity,
            "credential_file": credential_file,
            "note": (
                "La contrasena no se devuelve al navegador: queda en un fichero "
                "0600 en el servidor, que el operador recoge por un canal fuera "
                "de banda. No se registra en la auditoria."
            ),
        })

    def _handle_admin_identity_state(
        self, user_id: str, payload: Dict[str, Any], client_ip: str,
    ) -> None:
        context, failure = self._require_identity_admin("UPDATE_IDENTITY", client_ip)
        if failure is not None:
            self.send_json(failure[0], failure[1])
            return
        enabled = payload.get("enabled")
        roles = payload.get("roles")
        if enabled is None and roles is None:
            self.send_json(400, {
                "error": "BadRequest",
                "message": "Indica enabled o roles",
                "code": "IDENTITY_NO_CHANGE",
            })
            return
        try:
            admin = get_identity_admin()
            applied_roles = None
            if roles is not None:
                applied_roles = admin.set_user_roles(
                    user_id, [str(role) for role in roles],
                )
            if enabled is not None:
                admin.set_user_enabled(user_id, bool(enabled))
        except IdentityAdminError as exc:
            record_audit_event(
                "UPDATE_IDENTITY", context.username, str(list(context.roles)),
                "DENIED_ERROR", str(exc)[:200], client_ip, context.mfa_verified,
            )
            self.send_json(exc.status, {
                "error": "IdentityAdminError", "message": str(exc), "code": exc.code,
            })
            return
        record_audit_event(
            "UPDATE_IDENTITY", context.username, str(list(context.roles)), "ALLOWED",
            "Identidad %s actualizada (enabled=%s, roles=%s)" % (
                user_id, enabled, ",".join(applied_roles or []),
            ),
            client_ip, context.mfa_verified,
        )
        self.send_json(200, {"id": user_id, "enabled": enabled, "roles": applied_roles})

    def _handle_admin_identity_password(self, user_id: str, client_ip: str) -> None:
        context, failure = self._require_identity_admin("RESET_IDENTITY_PASSWORD", client_ip)
        if failure is not None:
            self.send_json(failure[0], failure[1])
            return
        temporary_password = generate_password()
        try:
            get_identity_admin().reset_password(user_id, temporary_password)
        except IdentityAdminError as exc:
            record_audit_event(
                "RESET_IDENTITY_PASSWORD", context.username, str(list(context.roles)),
                "DENIED_ERROR", str(exc)[:200], client_ip, context.mfa_verified,
            )
            self.send_json(exc.status, {
                "error": "IdentityAdminError", "message": str(exc), "code": exc.code,
            })
            return
        record_audit_event(
            "RESET_IDENTITY_PASSWORD", context.username, str(list(context.roles)),
            "ALLOWED", "Contrasena rotada de la identidad %s" % user_id,
            client_ip, context.mfa_verified,
        )
        credential_file = deliver_credential(
            IDENTITY_RUNTIME_DIR, user_id, temporary_password,
        )
        self.send_json(200, {
            "id": user_id,
            "credential_file": credential_file,
            "note": (
                "La contrasena no se devuelve al navegador: queda en un fichero "
                "0600 en el servidor."
            ),
        })

    def _authorize_policy(
        self,
        action: str,
        audit_action: str,
        client_ip: str,
        forbidden_message: str,
        forbidden_code: str,
    ):
        """Autentica y autoriza una accion del PEP.

        Devuelve (contexto, None) cuando la operacion esta permitida y
        (None, (codigo, cuerpo)) cuando debe rechazarse. El rechazo por rol y
        el rechazo por MFA se distinguen, igual que en la administracion de
        identidades.
        """
        context, err = self.extract_and_validate_auth()
        if err:
            status_code, err_body = err
            record_audit_event(
                audit_action, "ANONYMOUS", "NONE", f"DENIED_{status_code}",
                err_body["message"], client_ip,
            )
            return None, (status_code, err_body)
        try:
            enforce_clinical_action(context, action)
        except InsufficientPermissionsError:
            record_audit_event(
                audit_action, context.username, str(list(context.roles)), "DENIED_FORBIDDEN",
                forbidden_message, client_ip, context.mfa_verified,
            )
            return None, (403, {
                "error": "Forbidden",
                "message": forbidden_message,
                "code": forbidden_code,
            })
        except MFARequiredError:
            record_audit_event(
                audit_action, context.username, str(list(context.roles)), "DENIED_MFA_REQUIRED",
                "Intento de operacion sensible sin MFA acreditada",
                client_ip, context.mfa_verified,
            )
            return None, (403, {
                "error": "Forbidden",
                "message": "La operacion exige autenticacion multifactor (MFA) acreditada",
                "code": "MFA_AUTHENTICATION_REQUIRED",
            })
        return context, None

    def _json_object_error(self, payload: Any) -> Optional[Dict[str, Any]]:
        """
        Devuelve el cuerpo 400 si el payload no es un objeto JSON, o None si lo es.

        Las rutas de F2 reciben un objeto: una lista o un escalar no tienen
        campos que validar y antes producian un 500 por AttributeError. El
        formato de la respuesta es el mismo que usan las demas validaciones.
        """
        if isinstance(payload, dict):
            return None
        return {
            "error": "BadRequest",
            "message": "El cuerpo de la peticion debe ser un objeto JSON",
            "code": "INVALID_JSON_BODY",
        }

    def _handle_diagnostics_checkers_get(self, client_ip: str) -> None:
        """Catalogo de comprobadores ejecutables del diagnostico de seguridad."""
        context, failure = self._authorize_policy(
            "VIEW_DIAGNOSTICS", "LIST_DIAGNOSTIC_CHECKERS", client_ip,
            "Acceso al diagnostico de seguridad restringido al auditor de seguridad "
            "y al administrador de plataforma",
            "DIAGNOSTICS_ROLE_REQUIRED",
        )
        if failure is not None:
            self.send_json(failure[0], failure[1])
            return
        record_audit_event(
            "LIST_DIAGNOSTIC_CHECKERS", context.username, str(list(context.roles)), "ALLOWED",
            "Consulta del catalogo de %d comprobadores de diagnostico" % len(checker_catalog()),
            client_ip, context.mfa_verified,
        )
        self.send_json(200, {
            "checkers": checker_catalog(),
            "environment": F11_ENVIRONMENT,
        })

    def _handle_diagnostics_runs_get(self, query: str, client_ip: str) -> None:
        """Ejecuciones de diagnostico mas recientes."""
        context, failure = self._authorize_policy(
            "VIEW_DIAGNOSTICS", "LIST_DIAGNOSTIC_RUNS", client_ip,
            "Acceso al diagnostico de seguridad restringido al auditor de seguridad "
            "y al administrador de plataforma",
            "DIAGNOSTICS_ROLE_REQUIRED",
        )
        if failure is not None:
            self.send_json(failure[0], failure[1])
            return
        params = parse_qs(query or "")
        try:
            limit = max(1, min(500, int((params.get("limit") or ["20"])[0])))
        except (TypeError, ValueError):
            limit = 20
        runs = db_manager.list_diagnostic_runs(limit=limit)
        record_audit_event(
            "LIST_DIAGNOSTIC_RUNS", context.username, str(list(context.roles)), "ALLOWED",
            "Consulta de %d ejecuciones de diagnostico" % len(runs),
            client_ip, context.mfa_verified,
        )
        self.send_json(200, {"runs": runs, "environment": F11_ENVIRONMENT})

    def _handle_diagnostic_run_get(self, run_id: str, client_ip: str) -> None:
        """Detalle de una ejecucion de diagnostico con sus hallazgos."""
        context, failure = self._authorize_policy(
            "VIEW_DIAGNOSTICS", "GET_DIAGNOSTIC_RUN", client_ip,
            "Acceso al diagnostico de seguridad restringido al auditor de seguridad "
            "y al administrador de plataforma",
            "DIAGNOSTICS_ROLE_REQUIRED",
        )
        if failure is not None:
            self.send_json(failure[0], failure[1])
            return
        run = db_manager.get_diagnostic_run(run_id)
        if run is None:
            record_audit_event(
                "GET_DIAGNOSTIC_RUN", context.username, str(list(context.roles)), "DENIED_NOT_FOUND",
                "Ejecucion de diagnostico no encontrada: %s" % run_id, client_ip, context.mfa_verified,
            )
            self.send_json(404, {
                "error": "NotFound",
                "message": "La ejecucion de diagnostico '%s' no existe" % run_id,
                "code": "DIAGNOSTIC_RUN_NOT_FOUND",
            })
            return
        findings = db_manager.list_security_findings(run_id=run_id, limit=1000)
        record_audit_event(
            "GET_DIAGNOSTIC_RUN", context.username, str(list(context.roles)), "ALLOWED",
            "Consulta de la ejecucion %s con %d hallazgos" % (run_id, len(findings)),
            client_ip, context.mfa_verified,
        )
        self.send_json(200, {
            "run": run,
            "findings": findings,
            "environment": F11_ENVIRONMENT,
        })

    def _handle_diagnostics_findings_get(self, query: str, client_ip: str) -> None:
        """Hallazgos de diagnostico con filtros opcionales."""
        context, failure = self._authorize_policy(
            "VIEW_DIAGNOSTICS", "LIST_DIAGNOSTIC_FINDINGS", client_ip,
            "Acceso al diagnostico de seguridad restringido al auditor de seguridad "
            "y al administrador de plataforma",
            "DIAGNOSTICS_ROLE_REQUIRED",
        )
        if failure is not None:
            self.send_json(failure[0], failure[1])
            return
        params = parse_qs(query or "")
        try:
            limit = max(1, min(1000, int((params.get("limit") or ["100"])[0])))
        except (TypeError, ValueError):
            limit = 100
        findings = db_manager.list_security_findings(
            status=(params.get("status") or [None])[0],
            severity=(params.get("severity") or [None])[0],
            objective=(params.get("objective") or [None])[0],
            checker_id=(params.get("checker_id") or [None])[0],
            run_id=(params.get("run_id") or [None])[0],
            limit=limit,
        )
        record_audit_event(
            "LIST_DIAGNOSTIC_FINDINGS", context.username, str(list(context.roles)), "ALLOWED",
            "Consulta de %d hallazgos de diagnostico" % len(findings),
            client_ip, context.mfa_verified,
        )
        self.send_json(200, {
            "findings": findings,
            "total": len(findings),
            "environment": F11_ENVIRONMENT,
        })

    def _handle_diagnostics_summary_get(self, client_ip: str) -> None:
        """Resumen del diagnostico: totales por estado, severidad, objetivo y comprobador."""
        context, failure = self._authorize_policy(
            "VIEW_DIAGNOSTICS", "GET_DIAGNOSTIC_SUMMARY", client_ip,
            "Acceso al diagnostico de seguridad restringido al auditor de seguridad "
            "y al administrador de plataforma",
            "DIAGNOSTICS_ROLE_REQUIRED",
        )
        if failure is not None:
            self.send_json(failure[0], failure[1])
            return
        by_status = db_manager.count_findings_by_status()
        by_severity = db_manager.count_findings_by_severity()
        by_objective = db_manager.count_findings_by_objective()
        runs = db_manager.list_diagnostic_runs(limit=1)
        last_run = runs[0] if runs else None
        catalog = {entry["id"]: entry for entry in checker_catalog()}
        latest: Dict[str, Dict[str, Any]] = {}
        for finding in db_manager.list_security_findings(limit=1000):
            checker_id = str(finding.get("checker_id") or "")
            if not checker_id or checker_id in latest:
                continue
            latest[checker_id] = {
                "checker_id": checker_id,
                "title": catalog.get(checker_id, {}).get("title") or finding.get("title"),
                "status": finding.get("status"),
                "objective": finding.get("objective"),
            }
        total_findings = sum(by_status.values())
        record_audit_event(
            "GET_DIAGNOSTIC_SUMMARY", context.username, str(list(context.roles)), "ALLOWED",
            "Resumen del diagnostico: %d hallazgos" % total_findings,
            client_ip, context.mfa_verified,
        )
        self.send_json(200, {
            "total_findings": total_findings,
            "open_findings": total_findings - int(by_status.get("passed", 0)),
            "by_status": by_status,
            "by_severity": by_severity,
            "by_objective": by_objective,
            "by_checker": [latest[checker_id] for checker_id in sorted(latest)],
            "runs_total": db_manager.count_diagnostic_runs(),
            "last_run": last_run,
            "environment": F11_ENVIRONMENT,
        })

    def _handle_assets_get(self, query: str, client_ip: str) -> None:
        """Inventario de activos con filtros opcionales y su resumen."""
        context, failure = self._authorize_policy(
            "VIEW_ASSETS", "LIST_ASSETS", client_ip,
            "Acceso al inventario de activos restringido a los roles autorizados",
            "ASSETS_ROLE_REQUIRED",
        )
        if failure is not None:
            self.send_json(failure[0], failure[1])
            return
        params = parse_qs(query or "")
        assets = db_manager.list_assets(
            classification=(params.get("classification") or [None])[0],
            criticality=(params.get("criticality") or [None])[0],
            source=(params.get("source") or [None])[0],
            environment=(params.get("environment") or [None])[0],
        )
        summary = db_manager.asset_summary()
        record_audit_event(
            "LIST_ASSETS", context.username, str(list(context.roles)), "ALLOWED",
            "Consulta de %d activos del inventario" % len(assets),
            client_ip, context.mfa_verified,
        )
        self.send_json(200, {
            "assets": assets,
            "summary": summary,
            "environment": F11_ENVIRONMENT,
        })

    def _handle_assets_summary_get(self, client_ip: str) -> None:
        """Resumen del inventario sin el detalle de los activos."""
        context, failure = self._authorize_policy(
            "VIEW_ASSETS", "GET_ASSET_SUMMARY", client_ip,
            "Acceso al inventario de activos restringido a los roles autorizados",
            "ASSETS_ROLE_REQUIRED",
        )
        if failure is not None:
            self.send_json(failure[0], failure[1])
            return
        summary = db_manager.asset_summary()
        record_audit_event(
            "GET_ASSET_SUMMARY", context.username, str(list(context.roles)), "ALLOWED",
            "Resumen del inventario: %d activos" % int(summary.get("total", 0)),
            client_ip, context.mfa_verified,
        )
        self.send_json(200, {"summary": summary, "environment": F11_ENVIRONMENT})

    def _handle_asset_get(self, asset_id: str, client_ip: str) -> None:
        """Detalle de un activo con sus evaluaciones."""
        context, failure = self._authorize_policy(
            "VIEW_ASSETS", "GET_ASSET", client_ip,
            "Acceso al inventario de activos restringido a los roles autorizados",
            "ASSETS_ROLE_REQUIRED",
        )
        if failure is not None:
            self.send_json(failure[0], failure[1])
            return
        asset = db_manager.get_asset(asset_id)
        if asset is None:
            record_audit_event(
                "GET_ASSET", context.username, str(list(context.roles)), "DENIED_NOT_FOUND",
                "Activo no encontrado en el inventario: %s" % asset_id,
                client_ip, context.mfa_verified,
            )
            self.send_json(404, {
                "error": "NotFound",
                "message": "El activo '%s' no existe en el inventario" % asset_id,
                "code": "ASSET_NOT_FOUND",
            })
            return
        evaluations = db_manager.list_asset_evaluations(asset_id)
        record_audit_event(
            "GET_ASSET", context.username, str(list(context.roles)), "ALLOWED",
            "Consulta del activo %s con %d evaluaciones" % (asset_id, len(evaluations)),
            client_ip, context.mfa_verified,
        )
        self.send_json(200, {
            "asset": asset,
            "evaluations": evaluations,
            "environment": F11_ENVIRONMENT,
        })

    def _handle_diagnostic_run_post(self, payload: Dict[str, Any], client_ip: str) -> None:
        """Ejecuta los comprobadores de verdad y persiste la ejecucion con sus hallazgos."""
        context, failure = self._authorize_policy(
            "RUN_DIAGNOSTICS", "DIAGNOSTIC_RUN", client_ip,
            "La ejecucion del diagnostico de seguridad esta reservada al administrador "
            "de plataforma",
            "PLATFORM_ADMIN_ROLE_REQUIRED",
        )
        if failure is not None:
            self.send_json(failure[0], failure[1])
            return

        invalid_body = self._json_object_error(payload)
        if invalid_body is not None:
            record_audit_event(
                "DIAGNOSTIC_RUN", context.username, str(list(context.roles)), "DENIED_INVALID",
                "Ejecucion de diagnostico rechazada: el cuerpo de la peticion no es un "
                "objeto JSON",
                client_ip, context.mfa_verified,
            )
            self.send_json(400, invalid_body)
            return

        requested = payload.get("checker_ids")
        checker_ids: Optional[List[str]] = None
        if requested is not None:
            if not isinstance(requested, list) or not all(
                isinstance(item, str) for item in requested
            ):
                record_audit_event(
                    "DIAGNOSTIC_RUN", context.username, str(list(context.roles)),
                    "DENIED_INVALID",
                    "Ejecucion de diagnostico rechazada: checker_ids no es una lista de "
                    "identificadores de comprobador",
                    client_ip, context.mfa_verified,
                )
                self.send_json(400, {
                    "error": "BadRequest",
                    "message": "checker_ids debe ser una lista de identificadores de comprobador",
                    "code": "DIAGNOSTIC_CHECKER_IDS_INVALID",
                    "fields": {"checker_ids": "se espera una lista de cadenas"},
                })
                return
            known = {entry["id"] for entry in checker_catalog()}
            unknown = [item for item in requested if item not in known]
            if unknown:
                record_audit_event(
                    "DIAGNOSTIC_RUN", context.username, str(list(context.roles)),
                    "DENIED_INVALID",
                    "Ejecucion de diagnostico rechazada: comprobadores desconocidos: %s"
                    % ", ".join(sorted(unknown)),
                    client_ip, context.mfa_verified,
                )
                self.send_json(400, {
                    "error": "BadRequest",
                    "message": "Hay comprobadores desconocidos en la peticion",
                    "code": "DIAGNOSTIC_CHECKER_UNKNOWN",
                    "fields": {
                        "checker_ids": "comprobadores desconocidos: %s" % ", ".join(sorted(unknown))
                    },
                })
                return
            checker_ids = list(dict.fromkeys(requested))

        started_at = time.time()
        results: List[CheckResult] = run_checks(checker_ids)
        finished_at = time.time()

        by_status: Dict[str, int] = {"passed": 0, "failed": 0, "warning": 0}
        by_severity: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        run_id = "RUN-" + os.urandom(4).hex().upper()
        findings: List[Dict[str, Any]] = []
        for result in results:
            by_status[result.status] = by_status.get(result.status, 0) + 1
            by_severity[result.severity] = by_severity.get(result.severity, 0) + 1
            findings.append({
                "id": "FND-" + os.urandom(4).hex().upper(),
                "run_id": run_id,
                "checker_id": result.checker_id,
                "title": result.title,
                "objective": result.objective,
                "severity": result.severity,
                "status": result.status,
                "asset_ref": result.asset_ref,
                "evidence_command": result.evidence_command,
                "evidence_source": result.evidence_source,
                "evidence_output": result.evidence_output,
                "remediation": result.remediation,
                "detected_at": finished_at,
            })

        run = {
            "id": run_id,
            "started_at": started_at,
            "finished_at": finished_at,
            "status": "completed",
            "checker_count": len(results),
            "passed": by_status.get("passed", 0),
            "failed": by_status.get("failed", 0),
            "warnings": by_status.get("warning", 0),
            "triggered_by": context.username,
            "environment": F11_ENVIRONMENT,
            "notes": "Ejecucion de %d comprobadores sobre el entorno %s" % (
                len(results), F11_ENVIRONMENT,
            ),
        }
        stored_run, stored_findings = db_manager.insert_diagnostic_run_with_findings(run, findings)
        record_audit_event(
            "DIAGNOSTIC_RUN", context.username, str(list(context.roles)), "ALLOWED",
            "Ejecucion %s: %d comprobadores, hallazgos por severidad: critical=%d high=%d "
            "medium=%d low=%d" % (
                run_id, len(results),
                by_severity.get("critical", 0), by_severity.get("high", 0),
                by_severity.get("medium", 0), by_severity.get("low", 0),
            ),
            client_ip, context.mfa_verified,
        )
        self.send_json(201, {
            "run": stored_run,
            "findings": stored_findings,
            "environment": F11_ENVIRONMENT,
        })

    def _handle_asset_create_post(self, payload: Dict[str, Any], client_ip: str) -> None:
        """Alta de un activo en el inventario."""
        context, failure = self._authorize_policy(
            "MANAGE_ASSETS", "ASSET_CREATE", client_ip,
            "La gestion del inventario de activos esta reservada al administrador de plataforma",
            "PLATFORM_ADMIN_ROLE_REQUIRED",
        )
        if failure is not None:
            self.send_json(failure[0], failure[1])
            return

        invalid_body = self._json_object_error(payload)
        if invalid_body is not None:
            record_audit_event(
                "ASSET_CREATE", context.username, str(list(context.roles)), "DENIED_INVALID",
                "Alta de activo rechazada: el cuerpo de la peticion no es un objeto JSON",
                client_ip, context.mfa_verified,
            )
            self.send_json(400, invalid_body)
            return

        errors = validate_asset(payload)
        if errors:
            record_audit_event(
                "ASSET_CREATE", context.username, str(list(context.roles)), "DENIED_INVALID",
                "Alta de activo con datos invalidos: %s" % ", ".join(sorted(errors)),
                client_ip, context.mfa_verified,
            )
            self.send_json(400, {
                "error": "BadRequest",
                "message": "El activo no tiene los datos minimos para registrarse",
                "code": "ASSET_INVALID",
                "fields": _fields_from_errors(errors),
            })
            return
        asset_id = "AST-" + os.urandom(4).hex().upper()
        record = {
            "id": asset_id,
            "name": str(payload.get("name")).strip(),
            "classification": str(payload.get("classification")).strip(),
            "criticality": str(payload.get("criticality")).strip(),
            "owner": str(payload.get("owner")).strip(),
            "source": str(payload.get("source")).strip(),
            "version": payload.get("version"),
            "environment": str(payload.get("environment") or F11_ENVIRONMENT).strip(),
            "synthetic": 1 if payload.get("synthetic", 1) else 0,
            "description": str(payload.get("description")).strip(),
            "revision": 1,
        }
        audit_event = {
            "action": "ASSET_CREATE",
            "actor": context.username,
            "role": str(list(context.roles)),
            "status": "ALLOWED",
            "details": "Activo %s (%s, %s, origen %s) dado de alta" % (
                record["name"], record["classification"], record["criticality"],
                record["source"],
            ),
            "ip": client_ip,
            "mfa_verified": context.mfa_verified,
        }
        try:
            # El alta y su evento se confirman en la misma transaccion: no
            # puede quedar un activo escrito sin el evento que lo declara.
            asset, _audit_record = db_manager.insert_asset_with_audit_event(
                record, audit_event,
            )
        except AssetAlreadyExistsError as exc:
            record_audit_event(
                "ASSET_CREATE", context.username, str(list(context.roles)), "DENIED_DUPLICATE",
                str(exc)[:200], client_ip, context.mfa_verified,
            )
            self.send_json(409, {
                "error": "Conflict",
                "message": str(exc),
                "code": "ASSET_ALREADY_EXISTS",
            })
            return
        except AssetValidationError as exc:
            record_audit_event(
                "ASSET_CREATE", context.username, str(list(context.roles)), "DENIED_INVALID",
                "Alta de activo con datos invalidos: %s" % str(exc)[:200],
                client_ip, context.mfa_verified,
            )
            self.send_json(400, {
                "error": "BadRequest",
                "message": str(exc),
                "code": "ASSET_INVALID",
            })
            return
        self.send_json(201, {"asset": asset, "environment": F11_ENVIRONMENT})

    def _handle_asset_update_post(
        self, asset_id: str, payload: Dict[str, Any], client_ip: str,
    ) -> None:
        """Actualizacion parcial de un activo: la revision se incrementa."""
        context, failure = self._authorize_policy(
            "MANAGE_ASSETS", "ASSET_UPDATE", client_ip,
            "La gestion del inventario de activos esta reservada al administrador de plataforma",
            "PLATFORM_ADMIN_ROLE_REQUIRED",
        )
        if failure is not None:
            self.send_json(failure[0], failure[1])
            return

        invalid_body = self._json_object_error(payload)
        if invalid_body is not None:
            record_audit_event(
                "ASSET_UPDATE", context.username, str(list(context.roles)), "DENIED_INVALID",
                "Actualizacion de activo rechazada: el cuerpo de la peticion no es un "
                "objeto JSON",
                client_ip, context.mfa_verified,
            )
            self.send_json(400, invalid_body)
            return

        updatable = (
            "name", "classification", "criticality", "owner", "source",
            "version", "environment", "synthetic", "description",
        )
        changes = {key: payload[key] for key in updatable if key in payload}
        if not changes:
            record_audit_event(
                "ASSET_UPDATE", context.username, str(list(context.roles)), "DENIED_INVALID",
                "Actualizacion de activo rechazada: no se ha indicado ningun campo "
                "modificable",
                client_ip, context.mfa_verified,
            )
            self.send_json(400, {
                "error": "BadRequest",
                "message": "Indica al menos un campo a actualizar",
                "code": "ASSET_NO_CHANGE",
                "fields": {"payload": "no se ha indicado ningun campo modificable"},
            })
            return
        errors = validate_asset(changes, partial=True)
        if errors:
            record_audit_event(
                "ASSET_UPDATE", context.username, str(list(context.roles)), "DENIED_INVALID",
                "Actualizacion de activo con datos invalidos: %s" % ", ".join(sorted(errors)),
                client_ip, context.mfa_verified,
            )
            self.send_json(400, {
                "error": "BadRequest",
                "message": "La actualizacion no tiene los datos minimos",
                "code": "ASSET_INVALID",
                "fields": _fields_from_errors(errors),
            })
            return
        audit_event = {
            "action": "ASSET_UPDATE",
            "actor": context.username,
            "role": str(list(context.roles)),
            "status": "ALLOWED",
            "details": "Activo %s actualizado" % asset_id,
            "ip": client_ip,
            "mfa_verified": context.mfa_verified,
        }
        try:
            # La actualizacion y su evento se confirman juntos: el detalle se
            # construye con la revision real ya aplicada dentro de la transaccion.
            asset, _audit_record = db_manager.update_asset_with_audit_event(
                asset_id,
                changes,
                audit_event,
                details_builder=lambda updated: "Activo %s actualizado a la revision %s" % (
                    updated["name"], updated["revision"],
                ),
            )
        except AssetNotFoundError as exc:
            record_audit_event(
                "ASSET_UPDATE", context.username, str(list(context.roles)), "DENIED_NOT_FOUND",
                str(exc)[:200], client_ip, context.mfa_verified,
            )
            self.send_json(404, {
                "error": "NotFound",
                "message": str(exc),
                "code": "ASSET_NOT_FOUND",
            })
            return
        except AssetAlreadyExistsError as exc:
            record_audit_event(
                "ASSET_UPDATE", context.username, str(list(context.roles)), "DENIED_DUPLICATE",
                str(exc)[:200], client_ip, context.mfa_verified,
            )
            self.send_json(409, {
                "error": "Conflict",
                "message": str(exc),
                "code": "ASSET_ALREADY_EXISTS",
            })
            return
        except AssetValidationError as exc:
            record_audit_event(
                "ASSET_UPDATE", context.username, str(list(context.roles)), "DENIED_INVALID",
                "Actualizacion de activo con datos invalidos: %s" % str(exc)[:200],
                client_ip, context.mfa_verified,
            )
            self.send_json(400, {
                "error": "BadRequest",
                "message": str(exc),
                "code": "ASSET_INVALID",
            })
            return
        self.send_json(200, {"asset": asset, "environment": F11_ENVIRONMENT})

    def _handle_asset_evaluation_post(
        self, asset_id: str, payload: Dict[str, Any], client_ip: str,
    ) -> None:
        """Registra la evaluacion de criticidad de un activo."""
        context, failure = self._authorize_policy(
            "MANAGE_ASSETS", "ASSET_EVALUATE", client_ip,
            "La gestion del inventario de activos esta reservada al administrador de plataforma",
            "PLATFORM_ADMIN_ROLE_REQUIRED",
        )
        if failure is not None:
            self.send_json(failure[0], failure[1])
            return

        invalid_body = self._json_object_error(payload)
        if invalid_body is not None:
            record_audit_event(
                "ASSET_EVALUATE", context.username, str(list(context.roles)), "DENIED_INVALID",
                "Evaluacion de activo rechazada: el cuerpo de la peticion no es un objeto JSON",
                client_ip, context.mfa_verified,
            )
            self.send_json(400, invalid_body)
            return

        errors: List[str] = []
        criticality = str(payload.get("criticality") or "").strip()
        if criticality not in criticalities():
            errors.append(
                "criticality: la criticidad debe ser una de: %s" % ", ".join(criticalities())
            )
        notes = str(payload.get("notes") or "").strip()
        if not notes:
            errors.append("notes: las notas de la evaluacion son obligatorias")
        elif len(notes) > 600:
            errors.append("notes: las notas no pueden superar los 600 caracteres")
        if errors:
            record_audit_event(
                "ASSET_EVALUATE", context.username, str(list(context.roles)), "DENIED_INVALID",
                "Evaluacion de activo con datos invalidos: %s" % ", ".join(sorted(errors)),
                client_ip, context.mfa_verified,
            )
            self.send_json(400, {
                "error": "BadRequest",
                "message": "La evaluacion no tiene los datos minimos para registrarse",
                "code": "ASSET_EVALUATION_INVALID",
                "fields": _fields_from_errors(errors),
            })
            return
        asset = db_manager.get_asset(asset_id)
        if asset is None:
            record_audit_event(
                "ASSET_EVALUATE", context.username, str(list(context.roles)), "DENIED_NOT_FOUND",
                "Activo no encontrado en el inventario: %s" % asset_id,
                client_ip, context.mfa_verified,
            )
            self.send_json(404, {
                "error": "NotFound",
                "message": "El activo '%s' no existe en el inventario" % asset_id,
                "code": "ASSET_NOT_FOUND",
            })
            return
        findings_count = len(
            db_manager.list_security_findings(asset_ref=str(asset.get("name")), limit=1000)
        )
        evaluation = {
            "id": "EVA-" + os.urandom(4).hex().upper(),
            "asset_id": asset_id,
            "evaluated_at": time.time(),
            "evaluated_by": context.username,
            "criticality": criticality,
            "notes": notes,
            "findings_count": findings_count,
        }
        audit_event = {
            "action": "ASSET_EVALUATE",
            "actor": context.username,
            "role": str(list(context.roles)),
            "status": "ALLOWED",
            "details": (
                "Evaluacion del activo %s: criticidad %s, %d hallazgos asociados"
                % (asset_id, criticality, findings_count)
            ),
            "ip": client_ip,
            "mfa_verified": context.mfa_verified,
        }
        try:
            # La evaluacion y su evento se confirman en la misma transaccion.
            stored, _audit_record = db_manager.insert_asset_evaluation_with_audit_event(
                evaluation, audit_event,
            )
        except AssetNotFoundError as exc:
            record_audit_event(
                "ASSET_EVALUATE", context.username, str(list(context.roles)), "DENIED_NOT_FOUND",
                str(exc)[:200], client_ip, context.mfa_verified,
            )
            self.send_json(404, {
                "error": "NotFound",
                "message": str(exc),
                "code": "ASSET_NOT_FOUND",
            })
            return
        except AssetValidationError as exc:
            record_audit_event(
                "ASSET_EVALUATE", context.username, str(list(context.roles)), "DENIED_INVALID",
                "Evaluacion de activo con datos invalidos: %s" % str(exc)[:200],
                client_ip, context.mfa_verified,
            )
            self.send_json(400, {
                "error": "BadRequest",
                "message": str(exc),
                "code": "ASSET_EVALUATION_INVALID",
            })
            return
        self.send_json(201, {"evaluation": stored, "environment": F11_ENVIRONMENT})

    def do_POST(self) -> None:
        try:
            self._do_POST_internal()
        except DatabaseError as e:
            self.send_json(500, {
                "error": "InternalServerError",
                "message": f"Fallo critico de persistencia duradera (Fail-Closed): {str(e)}",
                "code": "PERSISTENCE_TRANSACTION_FAILED"
            })
        except Exception as e:
            self.send_json(500, {
                "error": "InternalServerError",
                "message": f"Error interno no controlado: {str(e)}",
                "code": "INTERNAL_SERVER_ERROR"
            })

    def _handle_identity_request(self, payload: Dict[str, Any], client_ip: str) -> None:
        """Registra una solicitud de cuenta pendiente de autorizacion administrativa.

        El canal es publico y no autentica a nadie: la solicitud no concede
        ningun acceso. Queda en la cadena de auditoria para que un
        administrador la revise y la materialice en Keycloak desde el modulo F1b.
        """
        full_name = str(payload.get("full_name", "")).strip()
        email = str(payload.get("email", "")).strip().lower()
        justification = str(payload.get("justification", "")).strip()

        errors: Dict[str, str] = {}
        if not 3 <= len(full_name) <= 120:
            errors["full_name"] = "Indique el nombre completo (3 a 120 caracteres)."
        if not (
            5 <= len(email) <= 160
            and "@" in email
            and not email.startswith("@")
            and not email.endswith("@")
            and "." in email.split("@")[-1]
        ):
            errors["email"] = "Indique un correo corporativo valido."
        if not 10 <= len(justification) <= 600:
            errors["justification"] = "Explique el motivo de la solicitud (10 a 600 caracteres)."

        if errors:
            record_audit_event(
                "IDENTITY_REQUEST",
                "ANONYMOUS",
                "NONE",
                "REJECTED",
                "Solicitud de cuenta con datos invalidos: " + ", ".join(sorted(errors)),
                client_ip,
            )
            self.send_json(400, {
                "error": "BadRequest",
                "message": "La solicitud no tiene los datos minimos para tramitarla.",
                "code": "INVALID_IDENTITY_REQUEST",
                "fields": errors,
            })
            return

        now = time.time()
        with LOCK:
            window = [
                stamp
                for stamp in IDENTITY_REQUEST_HITS.get(client_ip, [])
                if now - stamp < IDENTITY_REQUEST_WINDOW_SECONDS
            ]
            limited = len(window) >= IDENTITY_REQUEST_LIMIT
            if not limited:
                window.append(now)
            IDENTITY_REQUEST_HITS[client_ip] = window

        if limited:
            record_audit_event(
                "IDENTITY_REQUEST",
                "ANONYMOUS",
                "NONE",
                "RATE_LIMITED",
                "Solicitud de cuenta rechazada por limite de solicitudes por origen",
                client_ip,
            )
            self.send_json(429, {
                "error": "TooManyRequests",
                "message": "Se alcanzo el limite de solicitudes. Contacte con el administrador del sistema.",
                "code": "IDENTITY_REQUEST_RATE_LIMITED",
            })
            return

        request_id = "REQ-" + os.urandom(4).hex().upper()
        record_audit_event(
            "IDENTITY_REQUEST",
            "ANONYMOUS",
            "NONE",
            "REQUESTED",
            f"Solicitud {request_id} de {full_name} <{email}>: {justification[:200]}",
            client_ip,
        )
        self.send_json(201, {
            "request_id": request_id,
            "status": "PENDING_ADMIN_AUTHORIZATION",
            "message": "Su solicitud quedo registrada. Un administrador debe autorizarla antes de crear la cuenta.",
        })

    def _do_POST_internal(self) -> None:
        parsed = urlparse(self.path)
        client_ip = self.client_address[0]
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"

        try:
            payload = json.loads(body)
            body_parsed = True
        except Exception:
            payload = {}
            body_parsed = False

        # Las rutas de F2 reciben un marcador cuando el cuerpo no parsea: el
        # handler responde 400 con el formato {error, message, code} sin
        # ejecutar comprobadores ni escribir nada. Las rutas que no son de F2
        # conservan el comportamiento previo.
        f2_payload: Any = payload if body_parsed else INVALID_JSON_BODY

        # Account request: recorded in the audit trail and granting no access.
        # Authorization and identity creation belong to the administrator.
        if parsed.path == "/api/v1/identity-requests":
            self._handle_identity_request(payload, client_ip)
            return

        # 1. Control de Autenticacion Local / Deprecacion con Fallback Restringido
        if parsed.path == "/api/v1/admin/identities":
            self._handle_admin_identity_create(payload, client_ip)
            return

        if parsed.path.startswith("/api/v1/admin/identities/"):
            remainder = parsed.path[len("/api/v1/admin/identities/"):]
            parts = [segment for segment in remainder.split("/") if segment]
            if len(parts) == 2 and parts[1] == "state":
                self._handle_admin_identity_state(parts[0], payload, client_ip)
                return
            if len(parts) == 2 and parts[1] == "password":
                self._handle_admin_identity_password(parts[0], client_ip)
                return

        # 1.b Diagnostico de Seguridad (M2): ejecucion de comprobadores reales
        if parsed.path == "/api/v1/diagnostics/runs":
            self._handle_diagnostic_run_post(f2_payload, client_ip)
            return

        # 1.c Inventario de Activos (M3): alta, actualizacion y evaluacion.
        # El handler es http.server puro: solo hay do_GET y do_POST, asi que la
        # actualizacion de un activo va por POST a /api/v1/assets/{id}.
        if parsed.path == "/api/v1/assets":
            self._handle_asset_create_post(f2_payload, client_ip)
            return

        if parsed.path.startswith("/api/v1/assets/"):
            remainder = parsed.path[len("/api/v1/assets/"):]
            parts = [segment for segment in remainder.split("/") if segment]
            if len(parts) == 2 and parts[1] == "evaluations":
                self._handle_asset_evaluation_post(parts[0], f2_payload, client_ip)
                return
            if len(parts) == 1:
                self._handle_asset_update_post(parts[0], f2_payload, client_ip)
                return

        if parsed.path == "/api/v1/auth/login":
            if not ENABLE_LEGACY_AUTH:
                record_audit_event("AUTH_LOGIN", "ANONYMOUS", "NONE", "DENIED", "Intento de login local deprecado", client_ip)
                self.send_json(410, {
                    "error": "Gone",
                    "message": "Autenticacion local deshabilitada: delegada formalmente a Keycloak OIDC (SGSI-ZTA)",
                    "code": "AUTH_DELEGATED_TO_KEYCLOAK"
                })
                return

            # Si la bandera de transicion esta activa pero no se configuraron secretos externos validos, denegar operacion
            if not LEGACY_HMAC_SECRET or len(LEGACY_HMAC_SECRET) < 32 or not LEGACY_AUDITOR_HASH:
                record_audit_event("AUTH_LOGIN", "SYSTEM", "NONE", "DENIED_CONFIG_ERROR", "Fallback legacy denegado: secretos externos ausentes o entropia insuficiente", client_ip)
                self.send_json(503, {
                    "error": "ServiceUnavailable",
                    "message": "Autenticacion de transicion no disponible: secretos de configuracion ausentes",
                    "code": "LEGACY_TRANSITION_SECRETS_MISSING"
                })
                return

            username = payload.get("username", "")
            password = payload.get("password", "")

            # Restriccion estricta Zero Trust: SOLO el servicio audit-monitor tiene permiso temporal de transicion.
            # Los usuarios clinicos (medico, recepcionista) tienen TERMINANTEMENTE PROHIBIDO eludir Keycloak.
            if username != "auditor":
                record_audit_event("LEGACY_CLINICAL_LOGIN_BLOCKED", username or "ANONYMOUS", "UNKNOWN", "DENIED", "Intento de eludir Keycloak OIDC en rol clinico", client_ip)
                self.send_json(403, {
                    "error": "Forbidden",
                    "message": "Acceso denegado: los roles clinicos y de admision deben autenticarse exclusivamente via Keycloak OIDC con MFA",
                    "code": "LEGACY_CLINICAL_LOGIN_PROHIBITED"
                })
                return

            pass_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
            if not hmac.compare_digest(pass_hash, LEGACY_AUDITOR_HASH):
                record_audit_event("AUTH_LOGIN", username, "ROLE_SECURITY_AUDITOR", "DENIED", "Credenciales de auditor invalidas", client_ip)
                self.send_json(401, {
                    "error": "Unauthorized",
                    "message": "Credenciales de auditor invalidas",
                    "code": "INVALID_CREDENTIALS"
                })
                return

            now = int(time.time())
            legacy_payload = {
                "sub": "auditor",
                "role": "ROLE_SECURITY_AUDITOR",
                "scope": "audit_only",
                "iat": now,
                "exp": now + 900
            }
            payload_str = json.dumps(legacy_payload, sort_keys=True)
            sig = hmac.new(LEGACY_HMAC_SECRET, payload_str.encode("utf-8"), hashlib.sha256).hexdigest()
            legacy_token = f"{payload_str}::{sig}"

            record_audit_event("LEGACY_AUDIT_LOGIN_ALLOWED", "auditor", "ROLE_SECURITY_AUDITOR", "ALLOWED", "Transicion temporal activa para audit-monitor", client_ip)

            extra_headers = {
                "Warning": '299 - "Legacy audit login is deprecated. Transition to OAuth2 Client Credentials before 2026-11-01"',
                "Sunset": "Sun, 01 Nov 2026 00:00:00 GMT",
                "Deprecation": "@1793491200"
            }
            self.send_json(200, {
                "status": "LEGACY_SESSION_ACTIVE",
                "token": legacy_token,
                "scope": "audit_only",
                "expires_in": 900,
                "warning": "Autenticacion legacy temporal sujeta a retiro programado."
            }, extra_headers=extra_headers)
            return

        # 2. Ingesta de Resultados Biomedicos IoMT (Canal M2M Aislado)
        if parsed.path == "/api/v1/iomt/results":
            device_id = self.headers.get("X-Device-Id")
            device_sig = self.headers.get("X-Device-Signature")
            device_ts = self.headers.get("X-Device-Timestamp")
            device_nonce = self.headers.get("X-Device-Nonce")

            # Sin claves configuradas el canal se cierra por completo (fail-closed).
            if not IOMT_DEVICE_KEYS:
                record_audit_event("IOMT_INGEST", device_id or "UNKNOWN", "ROLE_IOMT_DEVICE", "DENIED_CONFIG_ERROR", "Canal IoMT sin claves de dispositivo configuradas", client_ip)
                self.send_json(503, {
                    "error": "ServiceUnavailable",
                    "message": "Canal IoMT no configurado: no existen claves de dispositivo autorizadas",
                    "code": "IOMT_NOT_CONFIGURED"
                })
                return

            if not device_id or not device_sig or not device_ts or not device_nonce:
                record_audit_event("IOMT_INGEST", device_id or "UNKNOWN", "ROLE_IOMT_DEVICE", "DENIED", "Faltan cabeceras de firma biomedica completas", client_ip)
                self.send_json(401, {
                    "error": "Unauthorized",
                    "message": "Dispositivo IoMT no autenticado: se requieren X-Device-Id, X-Device-Signature, X-Device-Timestamp y X-Device-Nonce",
                    "code": "IOMT_MISSING_CREDENTIALS"
                })
                return

            device_key = IOMT_DEVICE_KEYS.get(device_id)
            if device_key is None:
                record_audit_event("IOMT_INGEST", device_id, "ROLE_IOMT_DEVICE", "DENIED", "Dispositivo IoMT no registrado", client_ip)
                self.send_json(403, {
                    "error": "Forbidden",
                    "message": "Dispositivo IoMT no autorizado",
                    "code": "IOMT_UNKNOWN_DEVICE"
                })
                return

            try:
                received_at = float(device_ts)
            except (TypeError, ValueError):
                received_at = 0.0

            if received_at <= 0 or abs(time.time() - received_at) > IOMT_MAX_CLOCK_SKEW_SECONDS:
                record_audit_event("IOMT_INGEST", device_id, "ROLE_IOMT_DEVICE", "DENIED", "Marca temporal IoMT fuera de la ventana permitida", client_ip)
                self.send_json(401, {
                    "error": "Unauthorized",
                    "message": "Marca temporal del dispositivo fuera de la ventana permitida",
                    "code": "IOMT_STALE_TIMESTAMP"
                })
                return

            # La firma cubre dispositivo, marca temporal, nonce y cuerpo completo.
            signing_input = "%s\n%s\n%s\n%s" % (device_id, device_ts, device_nonce, body)
            expected_sig = hmac.new(device_key, signing_input.encode("utf-8"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(device_sig, expected_sig):
                record_audit_event("IOMT_INGEST", device_id, "ROLE_IOMT_DEVICE", "DENIED", "Firma criptografica de dispositivo corrupta o no autorizada", client_ip)
                self.send_json(403, {
                    "error": "Forbidden",
                    "message": "Firma de dispositivo corrupta o no autorizada",
                    "code": "IOMT_INVALID_SIGNATURE"
                })
                return

            order_id = payload.get("order_id")
            if not order_id or not isinstance(order_id, str):
                record_audit_event("IOMT_INGEST", device_id, "ROLE_IOMT_DEVICE", "DENIED", "Resultado IoMT sin order_id valido", client_ip)
                self.send_json(400, {
                    "error": "BadRequest",
                    "message": "order_id es requerido para incorporar resultados",
                    "code": "MISSING_ORDER_ID"
                })
                return

            try:
                measurements = validate_measurements(payload.get("measurements"))
            except ClinicalRuleError as exc:
                record_audit_event("IOMT_INGEST", device_id, "ROLE_IOMT_DEVICE", "DENIED", f"Mediciones rechazadas para orden {order_id}: {exc.message}", client_ip)
                self.send_json(422, {
                    "error": "UnprocessableEntity",
                    "message": exc.message,
                    "code": exc.code
                })
                return

            audit_event = {
                "action": "IOMT_INGEST",
                "actor": device_id,
                "role": "ROLE_IOMT_DEVICE",
                "status": "SUCCESS",
                "details": f"Resultados IoMT aceptados para orden {order_id}",
                "ip": client_ip,
                "mfa_verified": False,
            }

            def apply_iomt_results(cur):
                # Registro durable del nonce dentro de la misma transaccion clinica.
                db_manager.register_iomt_nonce_cursor(
                    cur, device_nonce, device_id, received_at, IOMT_NONCE_TTL_SECONDS
                )
                order = db_manager.fetch_order_cursor(cur, order_id)
                if order is None:
                    raise ApiError(404, "ORDER_NOT_FOUND", f"Orden {order_id} no encontrada")

                current_status = order.get("status")
                if current_status in TERMINAL_STATUSES:
                    raise ApiError(
                        409,
                        "ORDER_LOCKED",
                        f"Orden {order_id} liberada: no admite modificaciones de resultados",
                    )
                if order.get("device_id") and order["device_id"] != device_id:
                    raise ApiError(
                        409,
                        "DEVICE_MISMATCH",
                        f"La orden {order_id} esta asociada a otro dispositivo analizador",
                    )

                merged = dict(order.get("measurements") or {})
                merged.update(measurements)
                order["measurements"] = merged
                order["device_id"] = device_id
                if current_status != ORDER_ANALYZED:
                    assert_transition(current_status, ORDER_ANALYZED)
                    order["status"] = ORDER_ANALYZED

                db_manager.replace_order_cursor(
                    cur, order, expected_version=int(order.get("version", 1))
                )
                audit_event["details"] = (
                    f"Resultados IoMT aceptados para orden {order_id} "
                    f"(ref paciente {patient_reference(str(order.get('patient_dni', '')))})"
                )
                return order

            try:
                updated_order, _ = db_manager.run_clinical_transaction(apply_iomt_results, audit_event)
            except ApiError as exc:
                record_audit_event("IOMT_INGEST", device_id, "ROLE_IOMT_DEVICE", "DENIED", f"Orden {order_id}: {exc.message}", client_ip)
                self.send_json(exc.status_code, {
                    "error": "Conflict" if exc.status_code == 409 else "NotFound",
                    "message": exc.message,
                    "code": exc.code
                })
                return
            except IomtReplayError:
                record_audit_event("IOMT_INGEST", device_id, "ROLE_IOMT_DEVICE", "DENIED_REPLAY", f"Nonce reutilizado para orden {order_id}", client_ip)
                self.send_json(409, {
                    "error": "Conflict",
                    "message": "Nonce de dispositivo ya utilizado: posible reenvio de resultados",
                    "code": "IOMT_REPLAY_DETECTED"
                })
                return
            except ClinicalRuleError as exc:
                self.send_json(409, {
                    "error": "Conflict",
                    "message": exc.message,
                    "code": exc.code
                })
                return
            except OrderVersionConflictError:
                self.send_json(409, {
                    "error": "Conflict",
                    "message": "La orden fue modificada por otra operacion concurrente",
                    "code": "ORDER_VERSION_CONFLICT"
                })
                return

            self.send_json(200, {
                "status": "ACCEPTED",
                "order_id": order_id,
                "order_status": updated_order.get("status"),
                "message": "Resultados de analizador incorporados al LIS"
            })
            return

        # 3. Operaciones Clinicas Humanas Protegidas (Exigen Bearer Access Token)
        context, err = self.extract_and_validate_auth()
        if err:
            status_code, err_body = err
            record_audit_event("API_ACCESS", "ANONYMOUS", "NONE", f"DENIED_{status_code}", f"POST en {parsed.path}: {err_body['message']}", client_ip)
            self.send_json(status_code, err_body)
            return

        actor = context.username
        roles_str = str(list(context.roles))

        # A) Creacion de Orden de Laboratorio (Fase Pre-analitica)
        if parsed.path == "/api/v1/orders":
            try:
                enforce_clinical_action(context, "CREATE_ORDER")
            except InsufficientPermissionsError:
                record_audit_event("CREATE_ORDER", actor, roles_str, "DENIED_FORBIDDEN", "Intento de crear orden sin rol de admision", client_ip, context.mfa_verified)
                self.send_json(403, {
                    "error": "Forbidden",
                    "message": "Solo el personal de Admision/Recepcion puede generar ordenes",
                    "code": "RECEPTION_ROLE_REQUIRED"
                })
                return

            order_id = payload.get("order_id")
            patient_dni = payload.get("patient_dni")
            test_type = payload.get("test_type", "HEMOGRAMA COMPLETO")

            if not order_id or not patient_dni:
                self.send_json(400, {
                    "error": "BadRequest",
                    "message": "order_id y patient_dni son requeridos",
                    "code": "MISSING_REQUIRED_FIELDS"
                })
                return

            order = {
                "order_id": order_id,
                "patient_dni": patient_dni,
                "test_type": test_type,
                "status": ORDER_SAMPLE_COLLECTED,
                "created_by": actor,
                "measurements": {},
                "validated_by": None,
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "version": 1,
            }

            audit_event = {
                "action": "CREATE_ORDER",
                "actor": actor,
                "role": roles_str,
                "status": "SUCCESS",
                "details": (
                    f"Orden {order_id} creada para paciente "
                    f"{patient_reference(patient_dni)}"
                ),
                "ip": client_ip,
                "mfa_verified": context.mfa_verified,
            }

            try:
                # Insercion pura + auditoria en una sola transaccion: nunca sobrescribe.
                created = db_manager.create_order(order, audit_event=audit_event)
            except DuplicateOrderError:
                record_audit_event("CREATE_ORDER", actor, roles_str, "DENIED_DUPLICATE", f"order_id duplicado rechazado: {order_id}", client_ip, context.mfa_verified)
                self.send_json(409, {
                    "error": "Conflict",
                    "message": f"La orden {order_id} ya existe: no se permite sobrescribirla",
                    "code": "ORDER_ALREADY_EXISTS"
                })
                return

            self.send_json(201, {"status": "CREATED", "order": created})
            return

        # B) Validacion Medica Facultativa (Fase Post-analitica - Requiere MFA Obligatorio)
        if parsed.path == "/api/v1/orders/validate":
            order_id = payload.get("order_id")
            if not order_id:
                self.send_json(400, {
                    "error": "BadRequest",
                    "message": "order_id es requerido para validacion facultativa",
                    "code": "MISSING_ORDER_ID"
                })
                return

            try:
                enforce_clinical_action(context, "VALIDATE_ORDER")
            except InsufficientPermissionsError:
                record_audit_event("VALIDATE_ORDER", actor, roles_str, "DENIED_FORBIDDEN", "Intento de validacion sin rol de Patologo", client_ip, context.mfa_verified)
                self.send_json(403, {
                    "error": "Forbidden",
                    "message": "Solo el Medico Patologo puede validar y firmar informes clinicos",
                    "code": "PATHOLOGIST_ROLE_REQUIRED"
                })
                return
            except MFARequiredError:
                record_audit_event("VALIDATE_ORDER", actor, roles_str, "DENIED_MFA_REQUIRED", "Intento de validacion sin evidencia de MFA (TOTP)", client_ip, context.mfa_verified)
                self.send_json(403, {
                    "error": "Forbidden",
                    "message": "Operacion clinica critica VALIDATE_ORDER denegada: requiere autenticacion multifactor (MFA) acreditada",
                    "code": "MFA_AUTHENTICATION_REQUIRED"
                })
                return

            observations = payload.get("observations", "Valores analiticos conformes")

            def apply_validation(cur):
                order = db_manager.fetch_order_cursor(cur, order_id)
                if order is None:
                    raise ApiError(404, "ORDER_NOT_FOUND", f"Orden {order_id} no encontrada")

                current_status = order.get("status")
                if current_status == ORDER_RELEASED:
                    raise ApiError(
                        409,
                        "ORDER_ALREADY_VALIDATED",
                        f"La orden {order_id} ya fue validada y liberada",
                    )
                if current_status != ORDER_ANALYZED:
                    raise ApiError(
                        409,
                        "INVALID_ORDER_TRANSITION",
                        f"Transicion no permitida para validar: '{current_status}' -> '{ORDER_RELEASED}'",
                    )

                # Sin mediciones validas no hay informe clinico que liberar.
                validated_measurements = validate_measurements(order.get("measurements"))

                previous_version = int(order.get("version", 1))
                target_version = previous_version + 1

                order["version"] = target_version
                order["measurements"] = validated_measurements
                order["status"] = ORDER_RELEASED
                order["validated_by"] = actor
                order["observations"] = observations
                order["validated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                order["seal_algorithm"] = "HMAC-SHA256"
                order["seal_scope"] = "order_content_v1"
                # Sello de integridad sobre el contenido exacto, incluida la version.
                order["integrity_seal"] = compute_integrity_seal(order, get_seal_key())

                db_manager.replace_order_cursor(cur, order, expected_version=previous_version)
                audit_event["details"] = (
                    f"Orden {order_id} validada y liberada por patologo con MFA "
                    f"(ref paciente {patient_reference(str(order.get('patient_dni', '')))})"
                )
                return order

            audit_event = {
                "action": "VALIDATE_ORDER",
                "actor": actor,
                "role": roles_str,
                "status": "SUCCESS",
                "details": f"Orden {order_id} validada y liberada por patologo con MFA",
                "ip": client_ip,
                "mfa_verified": context.mfa_verified,
            }

            try:
                released_order, _ = db_manager.run_clinical_transaction(apply_validation, audit_event)
            except ApiError as exc:
                record_audit_event("VALIDATE_ORDER", actor, roles_str, f"DENIED_{exc.status_code}", exc.message, client_ip, context.mfa_verified)
                self.send_json(exc.status_code, {
                    "error": "Conflict" if exc.status_code == 409 else "NotFound",
                    "message": exc.message,
                    "code": exc.code
                })
                return
            except ClinicalRuleError as exc:
                record_audit_event("VALIDATE_ORDER", actor, roles_str, "DENIED_INVALID_CONTENT", exc.message, client_ip, context.mfa_verified)
                self.send_json(422, {
                    "error": "UnprocessableEntity",
                    "message": exc.message,
                    "code": exc.code
                })
                return
            except OrderVersionConflictError:
                self.send_json(409, {
                    "error": "Conflict",
                    "message": "La orden fue modificada por otra operacion concurrente",
                    "code": "ORDER_VERSION_CONFLICT"
                })
                return

            self.send_json(200, {
                "status": "SUCCESS",
                "message": "Resultado clinico validado y liberado con garantia de autenticacion MFA",
                "order": released_order
            })
            return

        self.send_json(404, {"error": "NotFound", "message": "Ruta no encontrada"})


def run_server(port: int = 8000, validator: Optional[ZeroTrustJWTValidator] = None, host: Optional[str] = None) -> None:
    host_addr = host or os.environ.get("HOST", "127.0.0.1")
    # Los archivos clínicos y de respaldo se crean solo para el propietario.
    os.umask(0o077)
    server_address = (host_addr, port)
    httpd = HTTPServer(server_address, ZeroTrustRequestHandler)
    if validator is not None:
        httpd.validator = validator
    print(f"[*] SGSI-ZTA Clinical LIS Backend en http://{host_addr}:{port}")
    print(f"[*] Persistencia Relacional Duradera: {DB_PATH}")
    print("[*] Integrado con Keycloak 26.8 OIDC (Zero Trust Architecture)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Deteniendo servidor LIS...")
        httpd.shutdown()
        db_manager.close()


if __name__ == "__main__":
    port_val = int(os.environ.get("PORT", 8000))
    run_server(port_val)
