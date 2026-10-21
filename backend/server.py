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
from urllib.parse import urlparse

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
    ClinicalDatabaseManager,
    DatabaseBackedAuditLogs,
    DatabaseBackedOrdersDict,
    DatabaseError,
    DuplicateOrderError,
    IomtReplayError,
    OrderVersionConflictError,
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

    def _do_POST_internal(self) -> None:
        parsed = urlparse(self.path)
        client_ip = self.client_address[0]
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"

        try:
            payload = json.loads(body)
        except Exception:
            payload = {}

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
