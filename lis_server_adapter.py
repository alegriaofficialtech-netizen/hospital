#!/usr/bin/env python3
"""
Clinical PoC: LIS Backend Adapter con Integracion Zero Trust Keycloak JWT/OIDC
SGSI-ZTA Hospital Lab
ISO/IEC 27001:2022 & NIST SP 800-207

Adaptador de laboratorio para integrar ZeroTrustJWTValidator en el servidor HTTP nativo del LIS.
Sustituye la autenticacion HMAC local por verificacion criptografica de Access Tokens RS256 de Keycloak,
aplicando autorizacion granular RBAC y requerimiento de MFA contextual.
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

# Asegurar importacion del validador JWT en el sandbox
SANDBOX_DIR = os.path.dirname(os.path.abspath(__file__))
if SANDBOX_DIR not in sys.path:
    sys.path.insert(0, SANDBOX_DIR)

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

# Configuracion de claves y contexto sintetico
IOMT_DEVICE_KEY = os.environ.get("IOMT_DEVICE_KEY", "Secret_IoMT_Key_Hematology_2026").encode("utf-8")

# Estado en memoria para el laboratorio clinico
ORDERS_DB: Dict[str, Dict[str, Any]] = {}
AUDIT_LOGS: List[Dict[str, Any]] = []
LAST_AUDIT_HASH = "0" * 64
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
    """Registra un evento en la cadena de auditoria criptografica en memoria."""
    global LAST_AUDIT_HASH
    with LOCK:
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        record = {
            "timestamp": timestamp,
            "action": action,
            "actor": actor,
            "role": role,
            "status": status,
            "ip_source": ip,
            "details": details,
            "mfa_verified": mfa_verified,
            "prev_hash": LAST_AUDIT_HASH,
        }
        serialized = json.dumps(record, sort_keys=True)
        record_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        record["hash"] = record_hash
        LAST_AUDIT_HASH = record_hash
        AUDIT_LOGS.append(record)
        return record


def verify_audit_chain(events: List[Dict[str, Any]]) -> bool:
    """Verifica la integridad de la cadena local de auditoria."""
    expected_prev = "0" * 64
    for event in events:
        record = {key: value for key, value in event.items() if key != "hash"}
        digest = hashlib.sha256(json.dumps(record, sort_keys=True).encode("utf-8")).hexdigest()
        if event.get("prev_hash") != expected_prev or event.get("hash") != digest:
            return False
        expected_prev = digest
    return True


class ZeroTrustLISRequestHandler(BaseHTTPRequestHandler):
    """
    Manejador HTTP Zero Trust para el backend LIS.
    Exige Access Tokens RS256 de Keycloak en rutas clinicas y preserva la ingesta IoMT via HMAC.
    """

    # Validador inyectable a nivel de clase o instancia
    validator: Optional[ZeroTrustJWTValidator] = None

    def get_validator(self) -> ZeroTrustJWTValidator:
        if self.validator is not None:
            return self.validator
        if hasattr(self.server, "validator") and self.server.validator is not None:
            return self.server.validator
        raise RuntimeError("ZeroTrustJWTValidator no configurado en el servidor LIS")

    def send_json(self, status_code: int, data: Dict[str, Any]) -> None:
        """Envia respuesta JSON con cabeceras de endurecimiento de seguridad."""
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))

    def extract_and_validate_auth(self) -> Tuple[Optional[ClinicalAuthContext], Optional[Tuple[int, Dict[str, Any]]]]:
        """
        Extrae el token Bearer del encabezado Authorization y lo valida criptograficamente.
        Retorna (contexto, None) si es valido, o (None, (http_status, error_dict)) si falla.
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
        except TokenExpiredError as e:
            return None, (401, {
                "error": "Unauthorized",
                "message": "Token de acceso expirado",
                "code": "TOKEN_EXPIRED"
            })
        except (InvalidSignatureError, MalformedTokenError) as e:
            return None, (401, {
                "error": "Unauthorized",
                "message": "Firma digital o estructura de token invalida",
                "code": "INVALID_TOKEN_SIGNATURE"
            })
        except InvalidAudienceError as e:
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
        except UntrustedIssuerError as e:
            return None, (401, {
                "error": "Unauthorized",
                "message": "Emisor de identidad no confiable",
                "code": "UNTRUSTED_ISSUER"
            })
        except InsufficientPermissionsError as e:
            # Token criptograficamente valido pero el usuario carece de roles mapeables al LIS
            return None, (403, {
                "error": "Forbidden",
                "message": "El sujeto autenticado no posee roles clinicos asignados en el LIS",
                "code": "NO_CLINICAL_ROLES"
            })
        except JWTValidationError as e:
            return None, (401, {
                "error": "Unauthorized",
                "message": "Validacion de credencial OIDC/JWT fallida",
                "code": "JWT_VALIDATION_FAILED"
            })
        except Exception as e:
            return None, (500, {
                "error": "InternalServerError",
                "message": "Error interno durante la evaluacion de seguridad",
                "code": "SECURITY_EVALUATION_ERROR"
            })

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        client_ip = self.client_address[0]

        # 1. Endpoint publico de salud del servicio
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

            # Politica ZTA: Roles autorizados para visualizar ordenes
            allowed_roles = {"ROLE_RECEPTION", "ROLE_LAB_TECH", "ROLE_PATHOLOGIST", "ROLE_SECURITY_AUDITOR"}
            user_roles = context.roles
            if not user_roles.intersection(allowed_roles):
                record_audit_event("GET_ORDERS", context.username, str(list(user_roles)), "DENIED_FORBIDDEN", "Rol no autorizado para listar ordenes", client_ip, context.mfa_verified)
                self.send_json(403, {
                    "error": "Forbidden",
                    "message": "Zero Trust: Privilegios insuficientes para consultar ordenes",
                    "code": "INSUFFICIENT_ROLE_PERMISSIONS"
                })
                return

            with LOCK:
                orders_list = list(ORDERS_DB.values())
            record_audit_event("GET_ORDERS", context.username, str(list(user_roles)), "ALLOWED", f"Consulta de {len(orders_list)} ordenes", client_ip, context.mfa_verified)
            self.send_json(200, {"orders": orders_list, "count": len(orders_list)})
            return

        # 3. Consulta de Auditoria y Cadena de Custodia (Oficial de Seguridad / Auditor CISO)
        if parsed.path == "/api/v1/audit/events":
            context, err = self.extract_and_validate_auth()
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
            self.send_json(200, {
                "audit_chain_valid": verify_audit_chain(events),
                "total_events": len(events),
                "events": events
            })
            return

        self.send_json(404, {"error": "NotFound", "message": "Ruta no encontrada"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        client_ip = self.client_address[0]
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"

        try:
            payload = json.loads(body)
        except Exception:
            payload = {}

        # 1. Autenticacion de usuarios delegada a Keycloak OIDC
        if parsed.path == "/api/v1/auth/login":
            record_audit_event("AUTH_LOGIN", "ANONYMOUS", "NONE", "DENIED", "Intento de uso de login local deprecado", client_ip)
            self.send_json(410, {
                "error": "Gone",
                "message": "Autenticacion local deshabilitada: autenticacion delegada formalmente a Keycloak OIDC (SGSI-ZTA)",
                "code": "AUTH_DELEGATED_TO_KEYCLOAK"
            })
            return

        # 2. Ingesta de Resultados Biomedicos IoMT (Canal M2M Aislado)
        if parsed.path == "/api/v1/iomt/results":
            device_id = self.headers.get("X-Device-Id")
            device_sig = self.headers.get("X-Device-Signature")

            if not device_id or not device_sig:
                record_audit_event("IOMT_INGEST", device_id or "UNKNOWN", "ROLE_IOMT_DEVICE", "DENIED", "Faltan cabeceras de firma biomedica", client_ip)
                self.send_json(401, {
                    "error": "Unauthorized",
                    "message": "Dispositivo IoMT no autenticado: se requieren X-Device-Id y X-Device-Signature",
                    "code": "IOMT_MISSING_CREDENTIALS"
                })
                return

            expected_sig = hmac.new(IOMT_DEVICE_KEY, body.encode("utf-8"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(device_sig, expected_sig):
                record_audit_event("IOMT_INGEST", device_id, "ROLE_IOMT_DEVICE", "DENIED", "Firma criptografica de dispositivo corrupta o no autorizada", client_ip)
                self.send_json(403, {
                    "error": "Forbidden",
                    "message": "Firma de dispositivo corrupta o no autorizada",
                    "code": "IOMT_INVALID_SIGNATURE"
                })
                return

            order_id = payload.get("order_id")
            measurements = payload.get("measurements", {})

            with LOCK:
                if order_id not in ORDERS_DB:
                    ORDERS_DB[order_id] = {
                        "order_id": order_id,
                        "patient_dni": payload.get("patient_dni", "DESC-001"),
                        "status": "ANALYZED",
                        "device_id": device_id,
                        "measurements": measurements,
                        "validated_by": None,
                        "timestamp": time.time(),
                    }
                else:
                    ORDERS_DB[order_id]["measurements"] = measurements
                    ORDERS_DB[order_id]["device_id"] = device_id
                    ORDERS_DB[order_id]["status"] = "ANALYZED"

            record_audit_event("IOMT_INGEST", device_id, "ROLE_IOMT_DEVICE", "SUCCESS", f"Resultados recibidos para orden {order_id}", client_ip)
            self.send_json(200, {
                "status": "ACCEPTED",
                "order_id": order_id,
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
                record_audit_event("CREATE_ORDER", actor, roles_str, "DENIED_FORBIDDEN", "Intento de crear orden sin permisos de admision", client_ip, context.mfa_verified)
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

            with LOCK:
                ORDERS_DB[order_id] = {
                    "order_id": order_id,
                    "patient_dni": patient_dni,
                    "test_type": test_type,
                    "status": "SAMPLE_COLLECTED",
                    "created_by": actor,
                    "measurements": {},
                    "validated_by": None,
                    "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }

            record_audit_event("CREATE_ORDER", actor, roles_str, "SUCCESS", f"Orden {order_id} creada para paciente {patient_dni}", client_ip, context.mfa_verified)
            self.send_json(201, {"status": "CREATED", "order": ORDERS_DB[order_id]})
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
                record_audit_event("VALIDATE_ORDER", actor, roles_str, "DENIED_MFA_REQUIRED", "Intento de validacion clinica sin evidencia de MFA (TOTP)", client_ip, context.mfa_verified)
                self.send_json(403, {
                    "error": "Forbidden",
                    "message": "Operacion clinica critica VALIDATE_ORDER denegada: requiere autenticacion multifactor (MFA) acreditada",
                    "code": "MFA_AUTHENTICATION_REQUIRED"
                })
                return

            observations = payload.get("observations", "Valores analiticos conformes")

            with LOCK:
                if order_id not in ORDERS_DB:
                    self.send_json(404, {
                        "error": "NotFound",
                        "message": f"Orden {order_id} no encontrada",
                        "code": "ORDER_NOT_FOUND"
                    })
                    return

                order = ORDERS_DB[order_id]
                order["status"] = "VALIDATED_AND_RELEASED"
                order["validated_by"] = actor
                order["observations"] = observations
                order["digital_signature"] = hashlib.sha256(f"{order_id}::{actor}::{time.time()}".encode("utf-8")).hexdigest()

            record_audit_event("VALIDATE_ORDER", actor, roles_str, "SUCCESS", f"Orden {order_id} firmada y validada por patologo con MFA", client_ip, context.mfa_verified)
            self.send_json(200, {
                "status": "SUCCESS",
                "message": "Resultado clinico validado y liberado con garantia de autenticacion MFA",
                "order": ORDERS_DB[order_id]
            })
            return

        self.send_json(404, {"error": "NotFound", "message": "Ruta no encontrada"})


def create_lis_server(host: str = "127.0.0.1", port: int = 0, validator: Optional[ZeroTrustJWTValidator] = None) -> HTTPServer:
    """Crea una instancia de servidor LIS con el validador Zero Trust inyectado."""
    server_address = (host, port)
    httpd = HTTPServer(server_address, ZeroTrustLISRequestHandler)
    httpd.validator = validator
    return httpd


def run_server(port: int = 8000, validator: Optional[ZeroTrustJWTValidator] = None) -> None:
    host = os.environ.get("HOST", "127.0.0.1")
    httpd = create_lis_server(host, port, validator)
    print(f"[*] SGSI-ZTA LIS Backend Adapter escuchando en http://{host}:{port}")
    print("[*] Integrado con ZeroTrustJWTValidator (Keycloak OIDC RS256)")
    httpd.serve_forever()


if __name__ == "__main__":
    port_val = int(os.environ.get("PORT", 8000))
    run_server(port_val)
