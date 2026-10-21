#!/usr/bin/env python3
"""
provision_monitor_client.py - Aprovisiona el cliente M2M del audit-monitor.

Crea (o reutiliza) el cliente confidencial `clinical-audit-monitor-service` en
el realm indicado, le habilita service accounts, le asigna el rol de reino
`auditor`, le añade un mapper de audiencia `clinical-poc-api` y deja el secreto
en un archivo 0600. El secreto nunca se imprime: solo su huella.

La operación es idempotente:
  - sin --rotate, reutiliza el secreto existente;
  - con --rotate, regenera el secreto y actualiza el archivo.

Uso típico (contra el Keycloak interno, sin pasar por el gateway):
  KC_ADMIN_PASSWORD=... python3 cutover_prep/provision_monitor_client.py \
    --server http://127.0.0.1:8085 \
    --admin-user admin.lab \
    --realm hospital-lab \
    --out /home/elcra/sgsi-backups/secrets/audit-monitor.env \
    --verify-token-url http://127.0.0.1:8085/realms/hospital-lab/protocol/openid-connect/token
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import ssl
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cutover_common import canonical_token_url  # noqa: E402
from kc_admin import KeycloakAdmin, KeycloakError, read_secret  # noqa: E402

DEFAULT_CLIENT_ID = "clinical-audit-monitor-service"
DEFAULT_AUDIENCE = "clinical-poc-api"
DEFAULT_ROLE = "auditor"


def decode_jwt_payload(token: str) -> Dict[str, Any]:
    """Decodifica el payload sin verificar la firma (el emisor es nuestro KC)."""
    parts = token.split(".")
    if len(parts) != 3:
        raise SystemExit("el token no tiene formato JWT")
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(payload.encode("ascii")).decode("utf-8"))


def fetch_client_token(
    token_url: str, client_id: str, client_secret: str, timeout: float = 15.0
) -> str:
    data = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }
    ).encode("utf-8")
    context = (
        ssl.create_default_context() if token_url.startswith("https://") else None
    )
    request = urllib.request.Request(
        token_url,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:300]
        raise SystemExit(f"client_credentials falló ({exc.code}): {detail}") from exc
    token = payload.get("access_token")
    if not token:
        raise SystemExit("la respuesta no contiene access_token")
    return token


def write_secret_file(path: str, client_id: str, secret: str, token_url: str) -> None:
    content = (
        f"AUDIT_MONITOR_CLIENT_ID={client_id}\n"
        f"AUDIT_MONITOR_CLIENT_SECRET={secret}\n"
        f"AUDIT_MONITOR_TOKEN_URL={token_url}\n"
    )
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, mode=0o700, exist_ok=True)
    descriptor, tmp_path = tempfile.mkstemp(dir=directory, prefix=".monitor-", text=True)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def ensure_client(
    admin: KeycloakAdmin, realm: str, client_id: str, rotate: bool
) -> tuple[Dict[str, Any], str, str]:
    """Devuelve (representación del cliente, secreto, estado)."""
    existing = admin.find_client(realm, client_id)
    if existing:
        client_uuid = existing["id"]
        changed = False
        if not existing.get("serviceAccountsEnabled"):
            existing["serviceAccountsEnabled"] = True
            changed = True
        if existing.get("publicClient"):
            existing["publicClient"] = False
            changed = True
        if existing.get("standardFlowEnabled"):
            existing["standardFlowEnabled"] = False
            changed = True
        if existing.get("directAccessGrantsEnabled"):
            existing["directAccessGrantsEnabled"] = False
            changed = True
        if changed:
            admin.put(f"/admin/realms/{realm}/clients/{client_uuid}", existing)
        secret = (
            admin.regenerate_client_secret(realm, client_uuid)
            if rotate
            else admin.client_secret(realm, client_uuid)
        )
        if not secret:
            raise SystemExit(
                "el cliente existe pero no expone secreto; use --rotate para regenerarlo"
            )
        return existing, secret, "existing"

    secret = secrets.token_urlsafe(36)
    representation = {
        "clientId": client_id,
        "name": "Clinical Audit Monitor (M2M)",
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": False,
        "serviceAccountsEnabled": True,
        "standardFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "implicitFlowEnabled": False,
        "clientAuthenticatorType": "client-secret",
        "secret": secret,
        "attributes": {"access.token.lifespan": "300"},
        "protocolMappers": [
            {
                "name": f"audience-{DEFAULT_AUDIENCE}",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "consentRequired": False,
                "config": {
                    "included.custom.audience": DEFAULT_AUDIENCE,
                    "access.token.claim": "true",
                    "id.token.claim": "false",
                    "introspection.token.claim": "true",
                },
            }
        ],
    }
    admin.post(f"/admin/realms/{realm}/clients", representation)
    created = admin.find_client(realm, client_id)
    if not created:
        raise SystemExit("el cliente se creó pero no se puede leer de vuelta")
    return created, secret, "created"


def ensure_audience_mapper(
    admin: KeycloakAdmin, realm: str, client_uuid: str, audience: str
) -> None:
    path = f"/admin/realms/{realm}/clients/{client_uuid}/protocol-mappers/models"
    mappers = admin.get(path) or []
    if any(mapper.get("name") == f"audience-{audience}" for mapper in mappers):
        return
    admin.post(
        path,
        {
            "name": f"audience-{audience}",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "consentRequired": False,
            "config": {
                "included.custom.audience": audience,
                "access.token.claim": "true",
                "id.token.claim": "false",
                "introspection.token.claim": "true",
            },
        },
    )


def ensure_realm_role(
    admin: KeycloakAdmin, realm: str, client_uuid: str, role_name: str
) -> None:
    role = admin.realm_role(realm, role_name)
    service_account = admin.service_account_user(realm, client_uuid)
    user_id = service_account.get("id")
    if not user_id:
        raise SystemExit("el cliente no tiene service-account-user")
    path = f"/admin/realms/{realm}/users/{user_id}/role-mappings/realm"
    current = admin.get(path) or []
    if any(item.get("id") == role.get("id") for item in current):
        return
    admin.post(path, [role])


def verify_against_lis(base_url: str, token: str, timeout: float) -> int:
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/api/v1/audit/events",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except urllib.error.URLError as exc:
        raise SystemExit(f"no se pudo contactar el LIS en {base_url}: {exc.reason}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Aprovisiona el cliente M2M del audit-monitor en Keycloak"
    )
    parser.add_argument("--server", default="http://127.0.0.1:8085", help="Admin API de Keycloak")
    parser.add_argument("--realm", default="hospital-lab")
    parser.add_argument("--client-id", default=DEFAULT_CLIENT_ID)
    parser.add_argument("--audience", default=DEFAULT_AUDIENCE)
    parser.add_argument("--role", default=DEFAULT_ROLE)
    parser.add_argument("--admin-user", default="admin.lab")
    parser.add_argument("--admin-password-env", default="KC_ADMIN_PASSWORD")
    parser.add_argument("--admin-password-file", default=None)
    parser.add_argument("--cafile", default=None, help="CA para el Admin API HTTPS")
    parser.add_argument("--rotate", action="store_true", help="Regenera el secreto")
    parser.add_argument("--out", required=True, help="Archivo de credenciales (0600)")
    parser.add_argument("--token-url", default=canonical_token_url(), help="Token URL canónico a escribir")
    parser.add_argument(
        "--verify-token-url",
        default=None,
        help="Token URL para la verificación (por defecto, --token-url)",
    )
    parser.add_argument("--verify-against", default=None, help="URL base del LIS para probar el token")
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()

    password = read_secret(
        args.admin_password_env,
        args.admin_password_file,
        label="contraseña admin de Keycloak",
    )
    admin = KeycloakAdmin(
        args.server, args.admin_user, password, timeout=args.timeout, cafile=args.cafile
    )

    try:
        client, secret, state = ensure_client(admin, args.realm, args.client_id, args.rotate)
        ensure_audience_mapper(admin, args.realm, client["id"], args.audience)
        ensure_realm_role(admin, args.realm, client["id"], args.role)
    except KeycloakError as exc:
        raise SystemExit(f"[FAIL] {exc}") from exc

    verify_url = args.verify_token_url or args.token_url
    token = fetch_client_token(verify_url, args.client_id, secret, timeout=args.timeout)
    claims = decode_jwt_payload(token)
    audiences = claims.get("aud") if isinstance(claims.get("aud"), list) else [claims.get("aud")]
    roles = (claims.get("realm_access") or {}).get("roles", [])
    problems = []
    if args.audience not in audiences:
        problems.append(f"aud={audiences} no incluye {args.audience}")
    if args.role not in roles:
        problems.append(f"realm_access.roles={roles} no incluye {args.role}")
    if claims.get("azp") != args.client_id:
        problems.append(f"azp={claims.get('azp')!r} != {args.client_id!r}")
    if problems:
        raise SystemExit("[FAIL] token emitido pero inválido: " + "; ".join(problems))

    lis_status: Optional[int] = None
    if args.verify_against:
        lis_status = verify_against_lis(args.verify_against, token, args.timeout)
        if lis_status != 200:
            raise SystemExit(
                f"[FAIL] el LIS rechazó el token M2M en {args.verify_against}: HTTP {lis_status}"
            )

    write_secret_file(args.out, args.client_id, secret, args.token_url)
    fingerprint = hashlib.sha256(secret.encode("utf-8")).hexdigest()[:12]
    print(f"[PASS] cliente {args.client_id} ({state}) uuid={client['id']}")
    print(f"[PASS] rol de reino asignado: {args.role}")
    print(f"[PASS] audiencia en el token: {args.audience}")
    print(f"[PASS] token verificado contra {verify_url}")
    if lis_status is not None:
        print(f"[PASS] token aceptado por el LIS ({args.verify_against}): HTTP {lis_status}")
    print(f"[PASS] credenciales en {args.out} (0600) huella_sha256={fingerprint}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
