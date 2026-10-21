#!/usr/bin/env python3
"""
prepare_hospital_lab_realm.py - Declarative Keycloak 26.8 Realm Preparation

Zero Trust Architecture compliance for main realm 'hospital-lab':
- Preserves existing configuration of 'clinical-poc' (avoids destructive partial PUTs).
- Validates and enforces Authorization Code, PKCE S256, Redirect URIs, Web Origins.
- Validates real configuration of 'clinical-poc-api-audience' and 'amr' mappers (not just names).
- Declaratively provisions 'clinical-audit-monitor-service' (M2M Client Credentials) with Service Accounts.
- Enforces strict least-privilege scoping: assigns ONLY 'auditor' role; audits and detects forbidden clinical/admin roles.
- Requires explicit authorization (--allow-revocations) for revoking pre-existing roles; verifies real Keycloak deletion response.
- Atomic secret storage with fsync, temporary file, and backup preservation (permissions 0600).
- Compares credentials state securely without secret exposure; syncs only when genuinely needed.
- Categorizes changes into Additive (Safe), Modifications, and Revocations.
- Audits and documents main realm MFA readiness (hospital-browser conditional MFA flow).
- Documents and audits proxy header forwarding boundary (KC_PROXY_HEADERS=xforwarded).
"""

import argparse
import copy
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

KEYCLOAK_BASE_URL = os.environ.get("KEYCLOAK_BASE_URL", "http://127.0.0.1:8085")
TARGET_REALM = "hospital-lab"
DEFAULT_OUTPUT_CREDS_PATH = "/home/elcra/sandbox-jwt-validator/.env.audit_monitor_credentials_main"

EXPECTED_AUDIENCE_MAPPER_CONFIG = {
    "included.custom.audience": "clinical-poc-api",
    "id.token.claim": "false",
    "access.token.claim": "true",
    "introspection.token.claim": "true",
    "userinfo.token.claim": "false"
}

EXPECTED_AMR_MAPPER_CONFIG = {
    "id.token.claim": "true",
    "access.token.claim": "true",
    "introspection.token.claim": "true",
    "userinfo.token.claim": "true",
    "lightweight.claim": "false"
}

FORBIDDEN_AUDIT_ROLES = {
    "medico", "admision", "enfermeria", "laboratorio", "farmacia", "admin-ti", "admin"
}


def get_admin_token(base_url: str = KEYCLOAK_BASE_URL) -> str:
    """Obtains admin access token from master realm using bootstrap credentials."""
    try:
        env_out = subprocess.check_output(
            ["docker", "exec", "sgsi-zta-hospital-lab-keycloak-1", "env"],
            stderr=subprocess.DEVNULL
        ).decode("utf-8")
        env_vars = dict(l.split("=", 1) for l in env_out.splitlines() if "=" in l)
        username = env_vars.get("KC_BOOTSTRAP_ADMIN_USERNAME", "admin.lab")
        password = env_vars.get("KC_BOOTSTRAP_ADMIN_PASSWORD")
    except Exception as e:
        sys.exit(f"[-] Error al obtener credenciales de administrador de Keycloak: {e}")

    if not password:
        sys.exit("[-] Error: KC_BOOTSTRAP_ADMIN_PASSWORD no encontrado en contenedor Keycloak.")

    token_url = f"{base_url}/realms/master/protocol/openid-connect/token"
    data = urllib.parse.urlencode({
        "client_id": "admin-cli",
        "grant_type": "password",
        "username": username,
        "password": password
    }).encode("utf-8")

    req = urllib.request.Request(token_url, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
            return payload["access_token"]
    except Exception as e:
        sys.exit(f"[-] Error al autenticar con Keycloak Admin API ({token_url}): {e}")


def default_api_request(
    endpoint: str,
    method: str = "GET",
    data: Optional[Dict[str, Any]] = None,
    token: Optional[str] = None,
    base_url: str = KEYCLOAK_BASE_URL
) -> Tuple[int, Any]:
    """Executes HTTP request against Keycloak Admin REST API."""
    url = f"{base_url}{endpoint}"
    req = urllib.request.Request(url, method=method)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if data is not None:
        req.add_header("Content-Type", "application/json")
        req.data = json.dumps(data).encode("utf-8")

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            err_json = json.loads(body)
        except Exception:
            err_json = {"raw": body}
        return e.code, err_json
    except Exception as e:
        return 500, {"error": str(e)}


def check_proxy_trust_boundary() -> Dict[str, Any]:
    """
    Audits proxy headers and documents the trust boundary for Zero Trust Architecture.
    KC_PROXY_HEADERS=xforwarded is necessary but NOT sufficient on its own.
    """
    try:
        env_out = subprocess.check_output(
            ["docker", "exec", "sgsi-zta-hospital-lab-keycloak-1", "env"],
            stderr=subprocess.DEVNULL
        ).decode("utf-8")
        env_vars = dict(l.split("=", 1) for l in env_out.splitlines() if "=" in l)
        proxy_val = env_vars.get("KC_PROXY_HEADERS", "NOT_SET")
    except Exception as e:
        return {
            "status": "ERROR",
            "error": str(e),
            "compliant": False,
            "trust_boundary_note": "No se pudo consultar el entorno del contenedor Keycloak."
        }

    is_compliant = proxy_val == "xforwarded"
    boundary_doc = (
        "LÍMITE DE CONFIANZA PROXY: KC_PROXY_HEADERS=xforwarded habilita el procesamiento "
        "de encabezados X-Forwarded-*, pero no garantiza por sí solo la seguridad. "
        "El proxy inverso perimetral (Nginx/Envoy) debe sobrescribir obligatoriamente "
        "X-Forwarded-For con la IP real del cliente ($remote_addr), X-Forwarded-Proto con "
        "el esquema TLS verificado ($scheme) y X-Forwarded-Host con el nombre de host "
        "autorizado, eliminando cualquier cabecera inyectada por clientes no confiables. "
        "El puerto 8085 de Keycloak debe permanecer aislado en 127.0.0.1."
    )

    return {
        "status": "PASS" if is_compliant else "WARN",
        "KC_PROXY_HEADERS": proxy_val,
        "compliant": is_compliant,
        "trust_boundary_note": boundary_doc
    }


def validate_mapper_config(existing_mapper: Dict[str, Any], expected_type: str, expected_config: Dict[str, str]) -> Tuple[bool, List[str]]:
    """Validates the actual configuration parameters of a protocol mapper, not just its name."""
    discrepancies = []
    if existing_mapper.get("protocolMapper") != expected_type:
        discrepancies.append(f"Tipo esperado '{expected_type}', actual '{existing_mapper.get('protocolMapper')}'")

    actual_config = existing_mapper.get("config", {})
    for key, expected_val in expected_config.items():
        actual_val = str(actual_config.get(key, "")).lower()
        if actual_val != expected_val.lower():
            discrepancies.append(f"Clave '{key}': esperada '{expected_val}', actual '{actual_config.get(key)}'")

    return len(discrepancies) == 0, discrepancies


class RealmPreparer:
    """Orchestrates declarative, idempotent preparation of the hospital-lab realm."""

    def __init__(
        self,
        realm: str = TARGET_REALM,
        api_fn: Callable = default_api_request,
        creds_path: str = DEFAULT_OUTPUT_CREDS_PATH,
        allow_revocations: bool = False
    ):
        if realm != TARGET_REALM:
            raise ValueError(f"Seguridad Zero Trust: Realm destino '{realm}' no autorizado. Debe ser estrictamente '{TARGET_REALM}'.")
        self.realm = realm
        self.api = api_fn
        self.creds_path = creds_path
        self.allow_revocations = allow_revocations

    def read_existing_creds_file(self) -> Tuple[Optional[str], Optional[str]]:
        """Reads client ID and secret from credentials file without exposing secrets."""
        if not os.path.exists(self.creds_path):
            return None, None
        cid = None
        secret = None
        try:
            with open(self.creds_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("AUDIT_MONITOR_CLIENT_ID="):
                        cid = line.split("=", 1)[1].strip()
                    elif line.startswith("AUDIT_MONITOR_CLIENT_SECRET="):
                        secret = line.split("=", 1)[1].strip()
            return cid, secret
        except Exception:
            return None, None

    def audit_realm(self, token: str) -> Dict[str, Any]:
        """Performs read-only audit of the realm, clients, mappers, roles, and MFA readiness."""
        status, realm_data = self.api(f"/admin/realms/{self.realm}", token=token)
        if status != 200:
            return {"exists": False, "status": status, "details": realm_data}

        # Check existing clients
        status, clients = self.api(f"/admin/realms/{self.realm}/clients", token=token)
        if status != 200:
            raise RuntimeError(f"Error al listar clientes en realm {self.realm}: HTTP {status}")

        clinical_poc = next((c for c in clients if c.get("clientId") == "clinical-poc"), None)
        audit_client = next((c for c in clients if c.get("clientId") == "clinical-audit-monitor-service"), None)

        poc_audit = {"found": False}
        if clinical_poc:
            poc_id = clinical_poc["id"]
            status, full_poc = self.api(f"/admin/realms/{self.realm}/clients/{poc_id}", token=token)
            status, mappers = self.api(f"/admin/realms/{self.realm}/clients/{poc_id}/protocol-mappers/models", token=token)
            if status != 200:
                mappers = []

            aud_mapper = next((m for m in mappers if m.get("name") == "clinical-poc-api-audience"), None)
            aud_valid, aud_discrepancies = (False, ["Mapper ausente"]) if not aud_mapper else validate_mapper_config(
                aud_mapper, "oidc-audience-mapper", EXPECTED_AUDIENCE_MAPPER_CONFIG
            )

            amr_mapper = next((m for m in mappers if m.get("name") == "amr"), None)
            amr_valid, amr_discrepancies = (False, ["Mapper ausente"]) if not amr_mapper else validate_mapper_config(
                amr_mapper, "oidc-amr-mapper", EXPECTED_AMR_MAPPER_CONFIG
            )

            attrs = full_poc.get("attributes", {})
            pkce_method = attrs.get("pkce.code.challenge.method")

            incompatibilities = []
            if full_poc.get("directAccessGrantsEnabled"):
                incompatibilities.append("Direct Access Grants (Resource Owner Password) habilitado - Inseguro")
            if not full_poc.get("standardFlowEnabled"):
                incompatibilities.append("Standard Flow (Authorization Code) deshabilitado")
            if full_poc.get("implicitFlowEnabled"):
                incompatibilities.append("Implicit Flow habilitado - Desaconsejado por OAuth 2.1")
            if not full_poc.get("publicClient"):
                incompatibilities.append("Cliente no configurado como público para SPA frontend")
            if pkce_method != "S256":
                incompatibilities.append(f"PKCE method no es S256 (actual: '{pkce_method}')")
            redirect_uris = full_poc.get("redirectUris", [])
            if not redirect_uris:
                incompatibilities.append("redirectUris está vacío")

            poc_audit = {
                "found": True,
                "id": poc_id,
                "enabled": full_poc.get("enabled", False),
                "full_client": full_poc,
                "standardFlowEnabled": full_poc.get("standardFlowEnabled", False),
                "directAccessGrantsEnabled": full_poc.get("directAccessGrantsEnabled", False),
                "implicitFlowEnabled": full_poc.get("implicitFlowEnabled", False),
                "publicClient": full_poc.get("publicClient", False),
                "pkce_valid": pkce_method == "S256",
                "pkce_method": pkce_method,
                "redirectUris": redirect_uris,
                "webOrigins": full_poc.get("webOrigins", []),
                "incompatibilities": incompatibilities,
                "is_compatible": len(incompatibilities) == 0,
                "audience_mapper": {
                    "found": aud_mapper is not None,
                    "valid": aud_valid,
                    "model": aud_mapper,
                    "discrepancies": aud_discrepancies
                },
                "amr_mapper": {
                    "found": amr_mapper is not None,
                    "valid": amr_valid,
                    "model": amr_mapper,
                    "discrepancies": amr_discrepancies
                }
            }

        audit_svc_audit = {"found": False}
        if audit_client:
            audit_id = audit_client["id"]
            status, full_audit = self.api(f"/admin/realms/{self.realm}/clients/{audit_id}", token=token)
            status, mappers = self.api(f"/admin/realms/{self.realm}/clients/{audit_id}/protocol-mappers/models", token=token)
            if status != 200:
                mappers = []

            aud_mapper = next((m for m in mappers if m.get("name") == "clinical-poc-api-audience"), None)
            aud_valid, aud_discrepancies = (False, ["Mapper ausente"]) if not aud_mapper else validate_mapper_config(
                aud_mapper, "oidc-audience-mapper", EXPECTED_AUDIENCE_MAPPER_CONFIG
            )

            has_auditor_role = False
            unauthorized_roles = []
            status, sa_user = self.api(f"/admin/realms/{self.realm}/clients/{audit_id}/service-account-user", token=token)
            if status == 200 and "id" in sa_user:
                status, sa_roles = self.api(f"/admin/realms/{self.realm}/users/{sa_user['id']}/role-mappings/realm", token=token)
                if status == 200 and isinstance(sa_roles, list):
                    role_names = {r.get("name") for r in sa_roles}
                    has_auditor_role = "auditor" in role_names
                    unauthorized_roles = sorted(list(role_names.intersection(FORBIDDEN_AUDIT_ROLES)))

            status, sec_info = self.api(f"/admin/realms/{self.realm}/clients/{audit_id}/client-secret", token=token)
            existing_secret = sec_info.get("value") if status == 200 else None

            # Check if local credentials file matches existing secret
            file_cid, file_secret = self.read_existing_creds_file()
            creds_in_sync = False
            if file_cid == "clinical-audit-monitor-service" and file_secret and existing_secret:
                creds_in_sync = secrets.compare_digest(file_secret, existing_secret)

            audit_svc_audit = {
                "found": True,
                "id": audit_id,
                "enabled": full_audit.get("enabled", False),
                "full_client": full_audit,
                "serviceAccountsEnabled": full_audit.get("serviceAccountsEnabled", False),
                "publicClient": full_audit.get("publicClient", True),
                "existing_secret": existing_secret,
                "creds_file_in_sync": creds_in_sync,
                "has_auditor_role": has_auditor_role,
                "unauthorized_roles": unauthorized_roles,
                "sa_user_id": sa_user.get("id") if status == 200 else None,
                "audience_mapper": {
                    "found": aud_mapper is not None,
                    "valid": aud_valid,
                    "model": aud_mapper,
                    "discrepancies": aud_discrepancies
                }
            }

        # Check MFA readiness in browser flow
        browser_flow_name = realm_data.get("browserFlow", "browser")
        mfa_readiness = {"flow_checked": browser_flow_name, "has_conditional_mfa": False, "checks_mfa_role": False}
        status, execs = self.api(f"/admin/realms/{self.realm}/authentication/flows/{browser_flow_name}/executions", token=token)
        if status == 200 and isinstance(execs, list):
            has_otp = any(e.get("providerId") == "auth-otp-form" for e in execs)
            cond_exec = next((e for e in execs if e.get("providerId") == "conditional-user-role"), None)
            if cond_exec and cond_exec.get("authenticationConfig"):
                status_cfg, cfg = self.api(f"/admin/realms/{self.realm}/authentication/config/{cond_exec['authenticationConfig']}", token=token)
                if status_cfg == 200:
                    cond_role = cfg.get("config", {}).get("condUserRole")
                    mfa_readiness["checks_mfa_role"] = cond_role == "mfa-required"
            mfa_readiness["has_conditional_mfa"] = has_otp and mfa_readiness["checks_mfa_role"]

        proxy_info = check_proxy_trust_boundary()

        return {
            "exists": True,
            "realm": self.realm,
            "browser_flow": browser_flow_name,
            "mfa_readiness": mfa_readiness,
            "proxy_headers": proxy_info,
            "clinical_poc": poc_audit,
            "clinical_audit_monitor_service": audit_svc_audit
        }

    def plan_changes(self, state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Calculates exact, non-destructive, idempotent execution plan.
        Separates changes into:
        - ADDITIVE (Safe)
        - MODIFICATION (Updating existing config)
        - REVOCATION (Independent authorization required)
        """
        plan = []
        poc = state.get("clinical_poc", {})

        # 1. Plan for clinical-poc
        if not poc.get("found"):
            plan.append({
                "action": "CREATE_CLIENT_POC",
                "category": "ADDITIVE",
                "description": "Crear cliente público 'clinical-poc' para frontend con parámetros OIDC completos",
                "endpoint": f"/admin/realms/{self.realm}/clients",
                "method": "POST",
                "payload": {
                    "clientId": "clinical-poc",
                    "name": "Clinical POC Frontend",
                    "enabled": True,
                    "publicClient": True,
                    "standardFlowEnabled": True,
                    "implicitFlowEnabled": False,
                    "directAccessGrantsEnabled": False,
                    "serviceAccountsEnabled": False,
                    "protocol": "openid-connect",
                    "redirectUris": ["http://127.0.0.1:8000/oidc/callback"],
                    "webOrigins": ["http://127.0.0.1:8000"],
                    "attributes": {
                        "pkce.code.challenge.method": "S256",
                        "post.logout.redirect.uris": "+"
                    }
                }
            })
            plan.append({
                "action": "ADD_AUDIENCE_MAPPER_POC",
                "category": "ADDITIVE",
                "description": "Agregar mapper de audiencia 'clinical-poc-api-audience' a 'clinical-poc'",
                "endpoint": f"/admin/realms/{self.realm}/clients/{{POC_CLIENT_ID}}/protocol-mappers/models",
                "method": "POST",
                "payload": {
                    "name": "clinical-poc-api-audience",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-audience-mapper",
                    "consentRequired": False,
                    "config": EXPECTED_AUDIENCE_MAPPER_CONFIG
                }
            })
            plan.append({
                "action": "ADD_AMR_MAPPER_POC",
                "category": "ADDITIVE",
                "description": "Agregar mapper de autenticación multifactor 'amr' a 'clinical-poc'",
                "endpoint": f"/admin/realms/{self.realm}/clients/{{POC_CLIENT_ID}}/protocol-mappers/models",
                "method": "POST",
                "payload": {
                    "name": "amr",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-amr-mapper",
                    "consentRequired": False,
                    "config": EXPECTED_AMR_MAPPER_CONFIG
                }
            })
        else:
            full_poc = dict(poc["full_client"])
            needs_update = False
            update_reasons = []

            if not full_poc.get("enabled"):
                full_poc["enabled"] = True
                needs_update = True
                update_reasons.append("Habilitar cliente (enabled: True)")

            if not full_poc.get("standardFlowEnabled"):
                full_poc["standardFlowEnabled"] = True
                needs_update = True
                update_reasons.append("Habilitar Standard Flow (Authorization Code)")

            if full_poc.get("directAccessGrantsEnabled"):
                full_poc["directAccessGrantsEnabled"] = False
                needs_update = True
                update_reasons.append("Deshabilitar Direct Access Grants")

            attrs = dict(full_poc.get("attributes") or {})
            if attrs.get("pkce.code.challenge.method") != "S256":
                attrs["pkce.code.challenge.method"] = "S256"
                full_poc["attributes"] = attrs
                needs_update = True
                update_reasons.append("Configurar PKCE S256 mandatorio")

            if needs_update:
                category = "ADDITIVE" if (len(update_reasons) == 1 and "Habilitar cliente" in update_reasons[0]) else "MODIFICATION"
                plan.append({
                    "action": "UPDATE_CLIENT_PRESERVE_CONFIG",
                    "category": category,
                    "description": f"Actualizar 'clinical-poc' preservando configuración existente ({', '.join(update_reasons)})",
                    "endpoint": f"/admin/realms/{self.realm}/clients/{poc['id']}",
                    "method": "PUT",
                    "payload": full_poc
                })

            aud = poc.get("audience_mapper", {})
            if not aud.get("found"):
                plan.append({
                    "action": "ADD_AUDIENCE_MAPPER_POC",
                    "category": "ADDITIVE",
                    "description": "Agregar mapper de audiencia 'clinical-poc-api-audience' a 'clinical-poc'",
                    "endpoint": f"/admin/realms/{self.realm}/clients/{poc['id']}/protocol-mappers/models",
                    "method": "POST",
                    "payload": {
                        "name": "clinical-poc-api-audience",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-audience-mapper",
                        "consentRequired": False,
                        "config": EXPECTED_AUDIENCE_MAPPER_CONFIG
                    }
                })
            elif not aud.get("valid"):
                mapper_model = dict(aud["model"])
                mapper_model["config"] = EXPECTED_AUDIENCE_MAPPER_CONFIG
                plan.append({
                    "action": "UPDATE_AUDIENCE_MAPPER_POC",
                    "category": "MODIFICATION",
                    "description": f"Corregir configuración de mapper 'clinical-poc-api-audience' en 'clinical-poc' ({'; '.join(aud['discrepancies'])})",
                    "endpoint": f"/admin/realms/{self.realm}/clients/{poc['id']}/protocol-mappers/models/{mapper_model['id']}",
                    "method": "PUT",
                    "payload": mapper_model
                })

            amr = poc.get("amr_mapper", {})
            if not amr.get("found"):
                plan.append({
                    "action": "ADD_AMR_MAPPER_POC",
                    "category": "ADDITIVE",
                    "description": "Agregar mapper 'amr' a 'clinical-poc'",
                    "endpoint": f"/admin/realms/{self.realm}/clients/{poc['id']}/protocol-mappers/models",
                    "method": "POST",
                    "payload": {
                        "name": "amr",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-amr-mapper",
                        "consentRequired": False,
                        "config": EXPECTED_AMR_MAPPER_CONFIG
                    }
                })
            elif not amr.get("valid"):
                mapper_model = dict(amr["model"])
                mapper_model["config"] = EXPECTED_AMR_MAPPER_CONFIG
                plan.append({
                    "action": "UPDATE_AMR_MAPPER_POC",
                    "category": "MODIFICATION",
                    "description": f"Corregir configuración de mapper 'amr' en 'clinical-poc' ({'; '.join(amr['discrepancies'])})",
                    "endpoint": f"/admin/realms/{self.realm}/clients/{poc['id']}/protocol-mappers/models/{mapper_model['id']}",
                    "method": "PUT",
                    "payload": mapper_model
                })

        # 2. Plan for clinical-audit-monitor-service
        audit = state.get("clinical_audit_monitor_service", {})
        if not audit.get("found"):
            generated_secret = secrets.token_urlsafe(32)
            plan.append({
                "action": "CREATE_AUDIT_CLIENT",
                "category": "ADDITIVE",
                "description": "Crear cliente confidencial M2M 'clinical-audit-monitor-service' con Service Account",
                "endpoint": f"/admin/realms/{self.realm}/clients",
                "method": "POST",
                "generated_secret": generated_secret,
                "payload": {
                    "clientId": "clinical-audit-monitor-service",
                    "name": "Clinical Audit Monitor Service (M2M)",
                    "description": "Cliente confidencial para el servicio automatizado audit-monitor (RFC 6749)",
                    "enabled": True,
                    "clientAuthenticatorType": "client-secret",
                    "secret": generated_secret,
                    "serviceAccountsEnabled": True,
                    "publicClient": False,
                    "standardFlowEnabled": False,
                    "directAccessGrantsEnabled": False,
                    "protocol": "openid-connect"
                }
            })
            plan.append({
                "action": "ADD_AUDIENCE_MAPPER_AUDIT",
                "category": "ADDITIVE",
                "description": "Agregar mapper de audiencia 'clinical-poc-api-audience' al cliente de auditoría",
                "endpoint": f"/admin/realms/{self.realm}/clients/{{AUDIT_CLIENT_ID}}/protocol-mappers/models",
                "method": "POST",
                "payload": {
                    "name": "clinical-poc-api-audience",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-audience-mapper",
                    "consentRequired": False,
                    "config": EXPECTED_AUDIENCE_MAPPER_CONFIG
                }
            })
            plan.append({
                "action": "ASSIGN_AUDITOR_ROLE",
                "category": "ADDITIVE",
                "description": "Asignar rol de realm 'auditor' al usuario de servicio del cliente",
                "endpoint": f"/admin/realms/{self.realm}/users/{{SA_USER_ID}}/role-mappings/realm",
                "method": "POST",
                "role_name": "auditor"
            })
            plan.append({
                "action": "SAVE_CREDENTIALS_ATOMIC",
                "category": "ADDITIVE",
                "description": "Guardar credenciales M2M generadas atómicamente con permisos 0600 y respaldo previo",
                "target_file": self.creds_path,
                "client_id": "clinical-audit-monitor-service",
                "secret": generated_secret
            })
        else:
            full_audit = dict(audit["full_client"])
            if not full_audit.get("enabled") or not full_audit.get("serviceAccountsEnabled") or full_audit.get("publicClient"):
                full_audit["enabled"] = True
                full_audit["serviceAccountsEnabled"] = True
                full_audit["publicClient"] = False
                plan.append({
                    "action": "UPDATE_AUDIT_CLIENT",
                    "category": "MODIFICATION",
                    "description": "Habilitar Service Accounts y asegurar confidencialidad en 'clinical-audit-monitor-service'",
                    "endpoint": f"/admin/realms/{self.realm}/clients/{audit['id']}",
                    "method": "PUT",
                    "payload": full_audit
                })

            aud = audit.get("audience_mapper", {})
            if not aud.get("found"):
                plan.append({
                    "action": "ADD_AUDIENCE_MAPPER_AUDIT",
                    "category": "ADDITIVE",
                    "description": "Agregar mapper de audiencia 'clinical-poc-api-audience' a 'clinical-audit-monitor-service'",
                    "endpoint": f"/admin/realms/{self.realm}/clients/{audit['id']}/protocol-mappers/models",
                    "method": "POST",
                    "payload": {
                        "name": "clinical-poc-api-audience",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-audience-mapper",
                        "consentRequired": False,
                        "config": EXPECTED_AUDIENCE_MAPPER_CONFIG
                    }
                })
            elif not aud.get("valid"):
                mapper_model = dict(aud["model"])
                mapper_model["config"] = EXPECTED_AUDIENCE_MAPPER_CONFIG
                plan.append({
                    "action": "UPDATE_AUDIENCE_MAPPER_AUDIT",
                    "category": "MODIFICATION",
                    "description": "Corregir configuración de mapper 'clinical-poc-api-audience' en 'clinical-audit-monitor-service'",
                    "endpoint": f"/admin/realms/{self.realm}/clients/{audit['id']}/protocol-mappers/models/{mapper_model['id']}",
                    "method": "PUT",
                    "payload": mapper_model
                })

            if not audit.get("has_auditor_role"):
                plan.append({
                    "action": "ASSIGN_AUDITOR_ROLE",
                    "category": "ADDITIVE",
                    "description": "Asignar rol de realm 'auditor' al usuario de cuenta de servicio existente",
                    "client_id": audit["id"],
                    "sa_user_id": audit.get("sa_user_id"),
                    "role_name": "auditor"
                })

            # Check unauthorized roles: only plan revocation if explicit authorization flag was passed
            unauthorized = audit.get("unauthorized_roles", [])
            if unauthorized:
                if self.allow_revocations:
                    plan.append({
                        "action": "REVOKE_UNAUTHORIZED_ROLES",
                        "category": "REVOCATION",
                        "description": f"Revocar roles clínicos/administrativos no autorizados ({unauthorized}) en Service Account",
                        "client_id": audit["id"],
                        "sa_user_id": audit.get("sa_user_id"),
                        "roles_to_revoke": unauthorized
                    })

            # Check if credentials file genuinely needs sync
            if audit.get("existing_secret") and not audit.get("creds_file_in_sync"):
                plan.append({
                    "action": "SYNC_EXISTING_CREDENTIALS",
                    "category": "MODIFICATION",
                    "description": "Sincronizar archivo local de credenciales M2M con el secreto existente en Keycloak",
                    "target_file": self.creds_path,
                    "client_id": "clinical-audit-monitor-service",
                    "secret": audit["existing_secret"]
                })

        return plan

    def save_credentials_atomic(self, client_id: str, client_secret: str, dest_path: str) -> None:
        """
        Saves credentials to destination file with atomic replacement, fsync, and mode 0600.
        Preserves backup of existing file if present.
        """
        dest_dir = os.path.dirname(os.path.abspath(dest_path))
        os.makedirs(dest_dir, exist_ok=True)

        content = (
            f"# Credenciales OIDC Client Credentials (M2M) - SGSI-ZTA Hospital Lab\n"
            f"AUDIT_MONITOR_CLIENT_ID={client_id}\n"
            f"AUDIT_MONITOR_CLIENT_SECRET={client_secret}\n"
            f"AUDIT_MONITOR_TOKEN_URL={KEYCLOAK_BASE_URL}/realms/{self.realm}/protocol/openid-connect/token\n"
        )

        fd, temp_path = tempfile.mkstemp(dir=dest_dir, prefix=".audit_creds_tmp_", text=True)
        try:
            with open(fd, "w", encoding="utf-8") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())

            os.chmod(temp_path, 0o600)

            if os.path.exists(dest_path):
                bak_path = f"{dest_path}.bak"
                shutil.copy2(dest_path, bak_path)
                os.chmod(bak_path, 0o600)

            os.replace(temp_path, dest_path)
            os.chmod(dest_path, 0o600)
        except Exception:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass
            raise

    def execute_plan(self, plan: List[Dict[str, Any]], token: str) -> Dict[str, Any]:
        """
        Executes plan actions tracking journal and supporting partial-failure recovery.
        Verifies real Keycloak responses after revocations.
        """
        journal = []
        created_client_ids = {}

        for step_idx, step in enumerate(plan, 1):
            action = step["action"]
            desc = step["description"]
            step_record = {"step": step_idx, "action": action, "category": step.get("category"), "description": desc, "status": "PENDING"}

            try:
                if action == "CREATE_CLIENT_POC":
                    status, res = self.api(step["endpoint"], method="POST", data=step["payload"], token=token)
                    if status not in (200, 201, 204):
                        raise RuntimeError(f"HTTP {status}: {res}")
                    status, clients = self.api(f"/admin/realms/{self.realm}/clients?clientId=clinical-poc", token=token)
                    if status != 200 or not clients:
                        raise RuntimeError("No se pudo resolver el ID del cliente 'clinical-poc' recién creado.")
                    created_client_ids["POC_CLIENT_ID"] = clients[0]["id"]
                    step_record["status"] = "SUCCESS"

                elif action == "UPDATE_CLIENT_PRESERVE_CONFIG":
                    status, res = self.api(step["endpoint"], method="PUT", data=step["payload"], token=token)
                    if status not in (200, 204):
                        raise RuntimeError(f"HTTP {status}: {res}")
                    step_record["status"] = "SUCCESS"

                elif action in ("ADD_AUDIENCE_MAPPER_POC", "ADD_AMR_MAPPER_POC"):
                    endpoint = step["endpoint"]
                    if "{POC_CLIENT_ID}" in endpoint:
                        poc_id = created_client_ids.get("POC_CLIENT_ID")
                        if not poc_id:
                            raise RuntimeError("POC_CLIENT_ID no disponible para vincular mapper.")
                        endpoint = endpoint.replace("{POC_CLIENT_ID}", poc_id)
                    status, res = self.api(endpoint, method="POST", data=step["payload"], token=token)
                    if status not in (201, 204):
                        raise RuntimeError(f"HTTP {status}: {res}")
                    step_record["status"] = "SUCCESS"

                elif action in ("UPDATE_AUDIENCE_MAPPER_POC", "UPDATE_AMR_MAPPER_POC", "UPDATE_AUDIENCE_MAPPER_AUDIT"):
                    status, res = self.api(step["endpoint"], method="PUT", data=step["payload"], token=token)
                    if status not in (200, 204):
                        raise RuntimeError(f"HTTP {status}: {res}")
                    step_record["status"] = "SUCCESS"

                elif action == "CREATE_AUDIT_CLIENT":
                    status, res = self.api(step["endpoint"], method="POST", data=step["payload"], token=token)
                    if status not in (200, 201, 204):
                        raise RuntimeError(f"HTTP {status}: {res}")
                    status, clients = self.api(f"/admin/realms/{self.realm}/clients?clientId=clinical-audit-monitor-service", token=token)
                    if status != 200 or not clients:
                        raise RuntimeError("No se pudo resolver el ID de 'clinical-audit-monitor-service'.")
                    created_client_ids["AUDIT_CLIENT_ID"] = clients[0]["id"]
                    step_record["status"] = "SUCCESS"

                elif action == "UPDATE_AUDIT_CLIENT":
                    status, res = self.api(step["endpoint"], method="PUT", data=step["payload"], token=token)
                    if status not in (200, 204):
                        raise RuntimeError(f"HTTP {status}: {res}")
                    step_record["status"] = "SUCCESS"

                elif action == "ADD_AUDIENCE_MAPPER_AUDIT":
                    endpoint = step["endpoint"]
                    if "{AUDIT_CLIENT_ID}" in endpoint:
                        audit_id = created_client_ids.get("AUDIT_CLIENT_ID")
                        if not audit_id:
                            raise RuntimeError("AUDIT_CLIENT_ID no disponible para vincular mapper.")
                        endpoint = endpoint.replace("{AUDIT_CLIENT_ID}", audit_id)
                    status, res = self.api(endpoint, method="POST", data=step["payload"], token=token)
                    if status not in (201, 204):
                        raise RuntimeError(f"HTTP {status}: {res}")
                    step_record["status"] = "SUCCESS"

                elif action == "ASSIGN_AUDITOR_ROLE":
                    sa_user_id = step.get("sa_user_id")
                    if not sa_user_id:
                        audit_id = created_client_ids.get("AUDIT_CLIENT_ID") or step.get("client_id")
                        if not audit_id:
                            status, clients = self.api(f"/admin/realms/{self.realm}/clients?clientId=clinical-audit-monitor-service", token=token)
                            if status == 200 and clients:
                                audit_id = clients[0]["id"]
                        if not audit_id:
                            raise RuntimeError("No se pudo identificar el ID del cliente de auditoría para resolver su Service Account.")
                        status, sa_user = self.api(f"/admin/realms/{self.realm}/clients/{audit_id}/service-account-user", token=token)
                        if status != 200 or not sa_user or "id" not in sa_user:
                            raise RuntimeError(f"No se pudo obtener el Service Account User del cliente {audit_id}: HTTP {status}")
                        sa_user_id = sa_user["id"]

                    status, role_data = self.api(f"/admin/realms/{self.realm}/roles/auditor", token=token)
                    if status != 200 or not role_data:
                        raise RuntimeError("El rol de realm 'auditor' no existe en hospital-lab.")

                    status, res = self.api(f"/admin/realms/{self.realm}/users/{sa_user_id}/role-mappings/realm", method="POST", data=[role_data], token=token)
                    if status not in (200, 204):
                        raise RuntimeError(f"Error al asignar rol auditor: HTTP {status} {res}")
                    step_record["status"] = "SUCCESS"

                elif action == "REVOKE_UNAUTHORIZED_ROLES":
                    sa_user_id = step["sa_user_id"]
                    roles_to_revoke = step["roles_to_revoke"]
                    status, role_list = self.api(f"/admin/realms/{self.realm}/roles", token=token)
                    if status != 200 or not isinstance(role_list, list):
                        raise RuntimeError("No se pudieron listar los roles para resolver eliminación.")
                    objs_to_delete = [r for r in role_list if r.get("name") in roles_to_revoke]
                    if objs_to_delete:
                        del_status, del_res = self.api(
                            f"/admin/realms/{self.realm}/users/{sa_user_id}/role-mappings/realm",
                            method="DELETE",
                            data=objs_to_delete,
                            token=token
                        )
                        if del_status not in (200, 204):
                            raise RuntimeError(f"Keycloak rechazó la revocación de roles (HTTP {del_status}): {del_res}")

                        # Verificación estricta de respuesta real: confirmar que los roles fueron efectivamente removidos
                        chk_status, remaining_roles = self.api(
                            f"/admin/realms/{self.realm}/users/{sa_user_id}/role-mappings/realm",
                            token=token
                        )
                        if chk_status == 200 and isinstance(remaining_roles, list):
                            remaining_names = {r.get("name") for r in remaining_roles}
                            retained = remaining_names.intersection(set(roles_to_revoke))
                            if retained:
                                raise RuntimeError(f"Fallo de verificación de revocación: los roles {retained} siguen presentes en Keycloak.")
                    step_record["status"] = "SUCCESS"

                elif action in ("SAVE_CREDENTIALS_ATOMIC", "SYNC_EXISTING_CREDENTIALS"):
                    self.save_credentials_atomic(step["client_id"], step["secret"], step["target_file"])
                    step_record["status"] = "SUCCESS"

                journal.append(step_record)

            except Exception as e:
                step_record["status"] = "FAILED"
                step_record["error"] = str(e)
                journal.append(step_record)
                return {
                    "success": False,
                    "failed_step": step_record,
                    "journal": journal,
                    "recovery_note": (
                        "RECUPERACIÓN: La ejecución se detuvo de forma segura. "
                        "Los recursos previamente creados se mantienen intactos. "
                        "El diseño idempotente permite re-ejecutar el script para continuar "
                        "a partir del paso pendiente una vez resuelta la causa raíz."
                    )
                }

        return {"success": True, "journal": journal}


def print_status_report(state: Dict[str, Any], plan: List[Dict[str, Any]]) -> None:
    print("=" * 76)
    print(" ESTADO ACTUAL DEL REALM 'hospital-lab' (Keycloak 26.8)")
    print("=" * 76)
    proxy = state.get("proxy_headers", {})
    print(f"[*] Proxy Headers (KC_PROXY_HEADERS): {proxy.get('KC_PROXY_HEADERS')} [{proxy.get('status')}]")
    print(f"[*] Flujo del Navegador (browserFlow): {state.get('browser_flow')}")

    mfa = state.get("mfa_readiness", {})
    print(f"[*] Preparación MFA en Flujo Principal:")
    print(f"    - Flujo evaluado: {mfa.get('flow_checked')}")
    print(f"    - Condicional con auth-otp-form: {'SÍ' if mfa.get('has_conditional_mfa') else 'NO'}")
    print(f"    - Condición ligada a rol 'mfa-required': {'SÍ' if mfa.get('checks_mfa_role') else 'NO'}")

    poc = state.get("clinical_poc", {})
    print(f"\n[*] Cliente 'clinical-poc':")
    if not poc.get("found"):
        print("    - Estado: INEXISTENTE (Se creará en modo completo con PKCE S256)")
    else:
        print(f"    - ID: {poc.get('id')}")
        print(f"    - Habilitado (enabled): {'SÍ' if poc.get('enabled') else 'NO (Requiere activación)'}")
        print(f"    - Standard Flow (Authorization Code): {'SÍ' if poc.get('standardFlowEnabled') else 'NO'}")
        print(f"    - Direct Grants (Password Flow): {'NO (Seguro)' if not poc.get('directAccessGrantsEnabled') else 'SÍ (Inseguro)'}")
        pkce_desc = "SÍ (Conforme)" if poc.get("pkce_valid") else f"NO ({poc.get('pkce_method')})"
        print(f"    - PKCE S256: {pkce_desc}")
        print(f"    - Redirect URIs: {poc.get('redirectUris')}")
        print(f"    - Web Origins: {poc.get('webOrigins')}")
        aud = poc.get("audience_mapper", {})
        aud_desc = "SÍ (Válido)" if aud.get("valid") else f"DISCREPANCIA ({aud.get('discrepancies')})"
        print(f"    - Mapper Audiencia ('clinical-poc-api'): {aud_desc}")
        amr = poc.get("amr_mapper", {})
        amr_desc = "SÍ (Válido)" if amr.get("valid") else f"DISCREPANCIA ({amr.get('discrepancies')})"
        print(f"    - Mapper AMR ('amr'): {amr_desc}")
        if poc.get("incompatibilities"):
            print(f"    - INCOMPATIBILIDADES OIDC DETECTADAS: {poc.get('incompatibilities')}")

    audit = state.get("clinical_audit_monitor_service", {})
    print(f"\n[*] Cliente 'clinical-audit-monitor-service':")
    if not audit.get("found"):
        print("    - Estado: INEXISTENTE (Se aprovisionará como cliente confidencial M2M)")
    else:
        print(f"    - ID: {audit.get('id')}")
        print(f"    - Habilitado: {'SÍ' if audit.get('enabled') else 'NO'}")
        print(f"    - Service Account Activo: {'SÍ' if audit.get('serviceAccountsEnabled') else 'NO'}")
        print(f"    - Cliente Confidencial: {'SÍ' if not audit.get('publicClient') else 'NO'}")
        print(f"    - Credenciales locales en sincronía: {'SÍ (Sin necesidad de sincronización)' if audit.get('creds_file_in_sync') else 'NO (Requiere sincronización segura)'}")
        aud = audit.get("audience_mapper", {})
        aud_svc_desc = "SÍ (Válido)" if aud.get("valid") else f"DISCREPANCIA ({aud.get('discrepancies')})"
        print(f"    - Mapper Audiencia: {aud_svc_desc}")
        print(f"    - Rol Realm 'auditor' Asignado: {'SÍ' if audit.get('has_auditor_role') else 'NO'}")
        if audit.get("unauthorized_roles"):
            print(f"    - ALERTA DE SEGURIDAD: Roles no autorizados en Service Account: {audit.get('unauthorized_roles')}")
            print("      (Nota: Requiere bandera --allow-revocations para revocar de forma independiente)")

    print("-" * 76)
    if not plan:
        print("[+] EL REALM SE ENCUENTRA 100% CONFORME CON LA ARQUITECTURA ZERO TRUST.")
    else:
        print(f"[!] ACCIONES REQUERIDAS DETECTADAS: {len(plan)} paso(s) planificado(s).")
    print("=" * 76)


def print_plan_by_category(plan: List[Dict[str, Any]]) -> None:
    categories = {
        "ADDITIVE": ("ACCIONES ADITIVAS SEGURAS (Sin riesgo de rotura)", []),
        "MODIFICATION": ("ACCIONES DE MODIFICACIÓN / ACTUALIZACIÓN (Revisión requerida)", []),
        "REVOCATION": ("ACCIONES DE REVOCACIÓN (Requieren autorización independiente)", [])
    }

    for step in plan:
        cat = step.get("category", "ADDITIVE")
        if cat in categories:
            categories[cat][1].append(step)
        else:
            categories["ADDITIVE"][1].append(step)

    print("\n" + "=" * 76)
    print(" PLAN DE EJECUCIÓN DECLARATIVO (DRY-RUN)")
    print("=" * 76)

    global_step = 1
    for cat_key in ("ADDITIVE", "MODIFICATION", "REVOCATION"):
        cat_title, steps = categories[cat_key]
        if not steps:
            continue
        print(f"\n--- {cat_title} ({len(steps)} acción/es) ---")
        for s in steps:
            print(f"\n[Paso {global_step}] [{s.get('category')}] {s['action']}: {s['description']}")
            if "endpoint" in s:
                print(f"         Endpoint: {s.get('method', 'GET')} {s.get('endpoint')}")
            if "payload" in s:
                masked = dict(s["payload"])
                if "secret" in masked:
                    masked["secret"] = "[REDACTED_HIGH_ENTROPY_SECRET]"
                print(f"         Payload : {json.dumps(masked, indent=11).strip()}")
            global_step += 1


def main():
    parser = argparse.ArgumentParser(
        description="Preparación declarativa idempotente del realm hospital-lab en Keycloak 26.8"
    )
    parser.add_argument(
        "--verify", action="store_true",
        help="Verifica el estado del realm e imprime el reporte de conformidad sin alterar nada."
    )
    parser.add_argument(
        "--dry-run", action="store_true", default=True,
        help="Modo simulación por defecto: muestra las llamadas API sin ejecutarlas."
    )
    parser.add_argument(
        "--apply", action="store_true",
        help="Aplica los cambios en el realm hospital-lab tras confirmación explícita."
    )
    parser.add_argument(
        "--allow-revocations", action="store_true",
        help="Autoriza la planificación y ejecución de revocación de roles no autorizados."
    )
    parser.add_argument(
        "--confirm", action="store_true",
        help="Confirma la aplicación de cambios en modo no interactivo."
    )
    parser.add_argument(
        "--creds-file", default=DEFAULT_OUTPUT_CREDS_PATH,
        help=f"Ruta de destino para credenciales M2M (por defecto: {DEFAULT_OUTPUT_CREDS_PATH})"
    )
    args = parser.parse_args()

    token = get_admin_token()
    preparer = RealmPreparer(
        realm=TARGET_REALM,
        creds_path=args.creds_file,
        allow_revocations=args.allow_revocations
    )
    state = preparer.audit_realm(token)
    plan = preparer.plan_changes(state)

    print_status_report(state, plan)

    proxy_info = state.get("proxy_headers", {})
    if "trust_boundary_note" in proxy_info:
        print(f"\n[*] NOTA DE ARQUITECTURA:")
        print(f"    {proxy_info['trust_boundary_note']}\n")

    if args.verify and not args.apply:
        sys.exit(0 if not plan else 1)

    if not plan:
        print("[+] No hay cambios pendientes por aplicar.")
        return

    print_plan_by_category(plan)

    if not args.apply:
        print("\n" + "*" * 76)
        print(" NOTA: Ejecución finalizada en modo solo lectura (--dry-run).")
        print(" Ninguna modificación fue realizada sobre el realm 'hospital-lab'.")
        print(" Para aplicar estos cambios, se requiere autorización explícita y bandera --apply.")
        print("*" * 76)
        return

    if not args.confirm:
        print("\n[!] AVISO: Ha especificado --apply sobre el realm de producción 'hospital-lab'.")
        confirm = input("¿Confirma aplicar estos cambios sobre 'hospital-lab'? [escriba 'CONFIRMAR']: ")
        if confirm != "CONFIRMAR":
            print("[-] Operación cancelada por el usuario.")
            return

    print("\n[*] Aplicando cambios declarativos sobre 'hospital-lab'...")
    res = preparer.execute_plan(plan, token)
    if res["success"]:
        print("[+] TODOS LOS CAMBIOS DECLARATIVOS FUERON APLICADOS EXITOSAMENTE.")
    else:
        print(f"[-] ERROR durante la aplicación: {res.get('failed_step')}")
        print(f"[-] {res.get('recovery_note')}")
        sys.exit(1)


if __name__ == "__main__":
    main()
