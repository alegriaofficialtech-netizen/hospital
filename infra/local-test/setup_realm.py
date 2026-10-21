#!/usr/bin/env python3
"""Provision the isolated local Keycloak realm used by the SGSI-ZTA integration tests.

This script is intentionally local-only:
- It talks to Keycloak on 127.0.0.1:8085.
- It recreates the realm ``hospital-lab-local`` from scratch.
- It stores generated synthetic credentials in an ignored file.
- It never reads production secrets, production realm exports, or clinical data.

The resulting realm contains a public PKCE client, an audience mapper, the native
``oidc-amr-mapper`` mapper, a conditional TOTP flow for the ``mfa-required`` role,
and synthetic users for each clinical role.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

DEFAULT_KEYCLOAK_URL = "http://127.0.0.1:8085"
DEFAULT_REALM = "hospital-lab-local"
DEFAULT_CLIENT_ID = "clinical-poc"
DEFAULT_REDIRECT_URI = "http://127.0.0.1:4200/"
DEFAULT_CREDENTIALS_FILE = Path(__file__).with_name(".test-credentials.local.json")

USERS = [
    {"username": "recepcion.test", "roles": ["admision"], "mfa": False, "label": "Reception"},
    {"username": "laboratorio.test", "roles": ["laboratorio"], "mfa": False, "label": "Laboratory"},
    {"username": "medico.test", "roles": ["medico", "mfa-required"], "mfa": True, "label": "Pathologist"},
    {"username": "medico.sinmfa", "roles": ["medico"], "mfa": False, "label": "Pathologist without MFA"},
    {"username": "auditor.test", "roles": ["auditor"], "mfa": False, "label": "Security auditor"},
]


class SetupError(RuntimeError):
    """A deterministic setup failure with a clear, non-secret message."""


class KeycloakRedirect(urllib.request.HTTPRedirectHandler):
    """Follow Keycloak-internal redirects and stop at the application callback."""

    def __init__(self, keycloak_url: str):
        super().__init__()
        self.keycloak_url = keycloak_url

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        if newurl.startswith(self.keycloak_url):
            return super().redirect_request(req, fp, code, msg, headers, newurl)
        return None


def read_env_file(path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def request_json(
    method: str,
    url: str,
    *,
    token: Optional[str] = None,
    body: Optional[Any] = None,
    form: Optional[Dict[str, str]] = None,
    timeout: int = 20,
) -> Tuple[int, Any]:
    headers = {"Accept": "application/json"}
    data: Optional[bytes] = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if form is not None:
        data = urllib.parse.urlencode(form).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read()
            return response.status, json.loads(payload.decode("utf-8")) if payload else None
    except urllib.error.HTTPError as error:
        payload = error.read()
        try:
            parsed = json.loads(payload.decode("utf-8")) if payload else None
        except ValueError:
            parsed = payload.decode("utf-8", errors="replace")
        return error.code, parsed


def wait_for_keycloak(keycloak_url: str, timeout_seconds: int = 90) -> None:
    deadline = time.time() + timeout_seconds
    discovery = f"{keycloak_url}/realms/master/.well-known/openid-configuration"
    last_error = ""
    while time.time() < deadline:
        try:
            status, _ = request_json("GET", discovery, timeout=5)
            if status == 200:
                return
            last_error = f"HTTP {status}"
        except Exception as error:  # noqa: BLE001 - surface the last transport error
            last_error = str(error)
        time.sleep(2)
    raise SetupError(f"Keycloak did not become ready at {keycloak_url}: {last_error}")


def admin_token(keycloak_url: str, username: str, password: str) -> str:
    status, payload = request_json(
        "POST",
        f"{keycloak_url}/realms/master/protocol/openid-connect/token",
        form={
            "client_id": "admin-cli",
            "grant_type": "password",
            "username": username,
            "password": password,
        },
    )
    if status != 200 or not isinstance(payload, dict) or not payload.get("access_token"):
        raise SetupError(f"Could not obtain a Keycloak admin token (HTTP {status}).")
    return str(payload["access_token"])


def admin_api(
    keycloak_url: str,
    token: str,
    method: str,
    path: str,
    body: Optional[Any] = None,
    ok: Tuple[int, ...] = (200, 201, 204),
) -> Any:
    status, payload = request_json(
        method, f"{keycloak_url}{path}", token=token, body=body
    )
    if status not in ok:
        raise SetupError(f"{method} {path} returned HTTP {status}: {payload}")
    return payload


def delete_existing_realm(keycloak_url: str, token: str, realm: str) -> None:
    status, _ = request_json(
        "GET", f"{keycloak_url}/admin/realms/{realm}", token=token
    )
    if status == 404:
        return
    if status != 200:
        raise SetupError(f"Could not inspect realm {realm} (HTTP {status}).")
    # Unbind the custom flow before deleting the realm's child objects.
    request_json(
        "PUT",
        f"{keycloak_url}/admin/realms/{realm}",
        token=token,
        body={"browserFlow": "browser"},
    )
    status, payload = request_json(
        "DELETE", f"{keycloak_url}/admin/realms/{realm}", token=token
    )
    if status not in (204, 404):
        raise SetupError(f"Could not delete realm {realm} (HTTP {status}): {payload}")


def create_realm(keycloak_url: str, token: str, realm: str) -> None:
    admin_api(
        keycloak_url,
        token,
        "POST",
        "/admin/realms",
        {
            "realm": realm,
            "enabled": True,
            "displayName": "SGSI-ZTA Hospital Lab - Local Test",
            "displayNameHtml": "<strong>SGSI-ZTA Hospital Lab</strong> local test realm",
            "sslRequired": "none",
            "registrationAllowed": False,
            "resetPasswordAllowed": False,
            "rememberMe": False,
            "loginWithEmailAllowed": False,
            "duplicateEmailsAllowed": False,
            "accessTokenLifespan": 600,
            "ssoSessionIdleTimeout": 1800,
            "ssoSessionMaxLifespan": 36000,
            "otpPolicyType": "totp",
            "otpPolicyAlgorithm": "HmacSHA1",
            "otpPolicyInitialCounter": 0,
            "otpPolicyDigits": 6,
            "otpPolicyLookAheadWindow": 1,
            "otpPolicyPeriod": 30,
        },
        ok=(201,),
    )


def create_roles(keycloak_url: str, token: str, realm: str) -> Dict[str, Dict[str, Any]]:
    roles: Dict[str, Dict[str, Any]] = {}
    for name, description in (
        ("admision", "Admission and order registration"),
        ("laboratorio", "Laboratory sample and analyzer workflow"),
        ("medico", "Pathologist medical validation"),
        ("auditor", "Security audit and chain oversight"),
        ("mfa-required", "Conditional TOTP requirement for this role"),
    ):
        status, payload = request_json(
            "POST",
            f"{keycloak_url}/admin/realms/{realm}/roles",
            token=token,
            body={"name": name, "description": description},
        )
        if status not in (201, 409):
            raise SetupError(f"Could not create role {name} (HTTP {status}): {payload}")
    status, payload = request_json(
        "GET", f"{keycloak_url}/admin/realms/{realm}/roles", token=token
    )
    if status != 200 or not isinstance(payload, list):
        raise SetupError(f"Could not list roles (HTTP {status}).")
    for role in payload:
        roles[str(role["name"])] = role
    return roles


def create_client(
    keycloak_url: str, token: str, realm: str, client_id: str
) -> str:
    client = {
        "clientId": client_id,
        "name": "SGSI-ZTA local clinical frontend",
        "description": "Local test public client with Authorization Code + PKCE S256",
        "enabled": True,
        "publicClient": True,
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        "implicitFlowEnabled": False,
        "serviceAccountsEnabled": False,
        "redirectUris": [
            "http://127.0.0.1:4200/*",
            "http://localhost:4200/*",
        ],
        "webOrigins": [
            "http://127.0.0.1:4200",
            "http://localhost:4200",
        ],
        "attributes": {
            "pkce.code.challenge.method": "S256",
            "post.logout.redirect.uris": "http://127.0.0.1:4200/*##http://localhost:4200/*",
        },
        "protocolMappers": [
            {
                "name": "clinical-poc-api-audience",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "consentRequired": False,
                "config": {
                    "included.custom.audience": "clinical-poc-api",
                    "id.token.claim": "false",
                    "access.token.claim": "true",
                },
            },
            {
                "name": "amr",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-amr-mapper",
                "consentRequired": False,
                "config": {
                    "id.token.claim": "true",
                    "access.token.claim": "true",
                    "lightweight.claim": "false",
                },
            },
        ],
    }
    admin_api(
        keycloak_url,
        token,
        "POST",
        f"/admin/realms/{realm}/clients",
        client,
        ok=(201,),
    )
    status, clients = request_json(
        "GET",
        f"{keycloak_url}/admin/realms/{realm}/clients?clientId={urllib.parse.quote(client_id)}",
        token=token,
    )
    if status != 200 or not clients:
        raise SetupError(f"Could not read back client {client_id} (HTTP {status}).")
    return str(clients[0]["id"])


def find_user(keycloak_url: str, token: str, realm: str, username: str) -> Optional[Dict[str, Any]]:
    status, users = request_json(
        "GET",
        f"{keycloak_url}/admin/realms/{realm}/users?username={urllib.parse.quote(username)}&exact=true",
        token=token,
    )
    if status != 200 or not isinstance(users, list):
        raise SetupError(f"Could not query user {username} (HTTP {status}).")
    return users[0] if users else None


def create_users(
    keycloak_url: str,
    token: str,
    realm: str,
    roles: Dict[str, Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    created: Dict[str, Dict[str, Any]] = {}
    for spec in USERS:
        username = spec["username"]
        password = secrets.token_urlsafe(24)
        user_payload: Dict[str, Any] = {
            "username": username,
            "enabled": True,
            "email": f"{username}@local.test.invalid",
            "emailVerified": True,
            "firstName": spec["label"],
            "lastName": "Local Test",
            "requiredActions": [],
        }
        if spec["mfa"]:
            user_payload["requiredActions"] = ["CONFIGURE_TOTP"]
        admin_api(
            keycloak_url,
            token,
            "POST",
            f"/admin/realms/{realm}/users",
            user_payload,
            ok=(201,),
        )
        user = find_user(keycloak_url, token, realm, username)
        if not user:
            raise SetupError(f"User {username} was not created.")
        user_id = str(user["id"])
        admin_api(
            keycloak_url,
            token,
            "PUT",
            f"/admin/realms/{realm}/users/{user_id}/reset-password",
            {"type": "password", "value": password, "temporary": False},
            ok=(204,),
        )
        role_mappings = [roles[name] for name in spec["roles"] if name in roles]
        admin_api(
            keycloak_url,
            token,
            "POST",
            f"/admin/realms/{realm}/users/{user_id}/role-mappings/realm",
            role_mappings,
            ok=(204,),
        )
        created[username] = {
            "id": user_id,
            "password": password,
            "roles": spec["roles"],
            "mfa": spec["mfa"],
        }
    return created


def flow_executions(
    keycloak_url: str, token: str, realm: str, alias: str
) -> list[Dict[str, Any]]:
    status, payload = request_json(
        "GET",
        f"{keycloak_url}/admin/realms/{realm}/authentication/flows/{urllib.parse.quote(alias)}/executions",
        token=token,
    )
    if status != 200 or not isinstance(payload, list):
        raise SetupError(f"Could not read flow {alias} executions (HTTP {status}).")
    return payload


def set_requirement(
    keycloak_url: str,
    token: str,
    realm: str,
    alias: str,
    execution_id: str,
    requirement: str,
) -> None:
    admin_api(
        keycloak_url,
        token,
        "PUT",
        f"/admin/realms/{realm}/authentication/flows/{urllib.parse.quote(alias)}/executions",
        {"id": execution_id, "requirement": requirement},
        ok=(204,),
    )


def configure_execution(
    keycloak_url: str,
    token: str,
    realm: str,
    execution_id: str,
    alias: str,
    config: Dict[str, str],
) -> None:
    admin_api(
        keycloak_url,
        token,
        "POST",
        f"/admin/realms/{realm}/authentication/executions/{execution_id}/config",
        {"alias": alias, "config": config},
        ok=(201, 204),
    )


def create_conditional_flow(keycloak_url: str, token: str, realm: str) -> None:
    base = f"/admin/realms/{realm}/authentication"
    top_alias = "hospital-test-browser"
    forms_alias = "hospital-test-forms"
    mfa_alias = "hospital-test-conditional-mfa"

    for alias in (mfa_alias, forms_alias, top_alias):
        status, _ = request_json(
            "DELETE",
            f"{keycloak_url}{base}/flows/{urllib.parse.quote(alias)}",
            token=token,
        )
        if status not in (204, 404):
            raise SetupError(f"Could not delete existing flow {alias} (HTTP {status}).")

    admin_api(
        keycloak_url,
        token,
        "POST",
        f"{base}/flows",
        {
            "alias": top_alias,
            "description": "Local test browser flow with conditional OTP",
            "providerId": "basic-flow",
            "topLevel": True,
            "builtIn": False,
        },
        ok=(201,),
    )
    for provider in ("auth-cookie", "identity-provider-redirector"):
        admin_api(
            keycloak_url,
            token,
            "POST",
            f"{base}/flows/{top_alias}/executions/execution",
            {"provider": provider},
            ok=(201,),
        )
    admin_api(
        keycloak_url,
        token,
        "POST",
        f"{base}/flows/{top_alias}/executions/flow",
        {
            "alias": forms_alias,
            "type": "basic-flow",
            "description": "Username/password plus conditional OTP",
            "provider": "basic-flow",
        },
        ok=(201,),
    )
    for execution in flow_executions(keycloak_url, token, realm, top_alias):
        if execution.get("providerId") in ("auth-cookie", "identity-provider-redirector") or execution.get("displayName") == forms_alias:
            set_requirement(
                keycloak_url, token, realm, top_alias, str(execution["id"]), "ALTERNATIVE"
            )

    admin_api(
        keycloak_url,
        token,
        "POST",
        f"{base}/flows/{forms_alias}/executions/execution",
        {"provider": "auth-username-password-form"},
        ok=(201,),
    )
    admin_api(
        keycloak_url,
        token,
        "POST",
        f"{base}/flows/{forms_alias}/executions/flow",
        {
            "alias": mfa_alias,
            "type": "basic-flow",
            "description": "Require OTP only for the mfa-required role",
            "provider": "basic-flow",
        },
        ok=(201,),
    )
    for execution in flow_executions(keycloak_url, token, realm, forms_alias):
        if execution.get("providerId") == "auth-username-password-form":
            set_requirement(
                keycloak_url, token, realm, forms_alias, str(execution["id"]), "REQUIRED"
            )
            configure_execution(
                keycloak_url,
                token,
                realm,
                str(execution["id"]),
                "amr-pwd-config",
                {"default.reference.value": "pwd"},
            )
        elif execution.get("displayName") == mfa_alias:
            set_requirement(
                keycloak_url, token, realm, forms_alias, str(execution["id"]), "CONDITIONAL"
            )

    admin_api(
        keycloak_url,
        token,
        "POST",
        f"{base}/flows/{mfa_alias}/executions/execution",
        {"provider": "conditional-user-role"},
        ok=(201,),
    )
    admin_api(
        keycloak_url,
        token,
        "POST",
        f"{base}/flows/{mfa_alias}/executions/execution",
        {"provider": "auth-otp-form"},
        ok=(201,),
    )
    for execution in flow_executions(keycloak_url, token, realm, mfa_alias):
        set_requirement(
            keycloak_url, token, realm, mfa_alias, str(execution["id"]), "REQUIRED"
        )
        if execution.get("providerId") == "conditional-user-role":
            configure_execution(
                keycloak_url,
                token,
                realm,
                str(execution["id"]),
                "require-mfa-local-config",
                {"condUserRole": "mfa-required", "negate": "false"},
            )
        elif execution.get("providerId") == "auth-otp-form":
            configure_execution(
                keycloak_url,
                token,
                realm,
                str(execution["id"]),
                "amr-otp-config",
                {"default.reference.value": "otp"},
            )

    admin_api(
        keycloak_url,
        token,
        "PUT",
        f"/admin/realms/{realm}",
        {"browserFlow": top_alias},
        ok=(204,),
    )


def pkce_pair() -> Tuple[str, str]:
    verifier = secrets.token_urlsafe(64)[:96]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


def generate_totp(secret_base32: str) -> str:
    normalized = secret_base32.strip().replace(" ", "").upper()
    padding = "=" * ((8 - len(normalized) % 8) % 8)
    key = base64.b32decode(normalized + padding, casefold=True)
    counter = int(time.time()) // 30
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{binary % 1000000:06d}"


class BrowserFlow:
    def __init__(self, keycloak_url: str, realm: str, client_id: str, redirect_uri: str):
        self.keycloak_url = keycloak_url
        self.realm = realm
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.cookies = CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookies),
            KeycloakRedirect(keycloak_url),
        )

    def _open(self, request: urllib.request.Request) -> Tuple[int, str, Optional[str]]:
        # Keycloak marks its local HTTP session cookies Secure; relax them only for
        # this isolated 127.0.0.1 test client so the cookie jar will send them.
        for cookie in self.cookies:
            if cookie.secure:
                cookie.secure = False
        try:
            with self.opener.open(request, timeout=20) as response:
                final_url = response.geturl()
                location = final_url if has_authorization_code(final_url) else response.headers.get("Location")
                return response.status, response.read().decode("utf-8", errors="replace"), location
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode("utf-8", errors="replace"), error.headers.get("Location")

    def _get(self, url: str) -> Tuple[int, str, Optional[str]]:
        return self._open(urllib.request.Request(url))

    def _post(self, url: str, fields: Dict[str, str]) -> Tuple[int, str, Optional[str]]:
        data = urllib.parse.urlencode(fields).encode("utf-8")
        request = urllib.request.Request(url, data=data, method="POST")
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
        return self._open(request)

    @staticmethod
    def _form_action(html: str) -> str:
        match = re.search(r'<form[^>]+action="([^"]+)"', html)
        if not match:
            raise SetupError("Keycloak login page did not expose a form action.")
        return match.group(1).replace("&amp;", "&")

    @staticmethod
    def _totp_secret(html: str) -> str:
        patterns = (
            r'id="kc-totp-secret-key"[^>]*>([^<]+)<',
            r'name="totpSecret"[^>]*value="([^"]+)"',
            r'value="([^"]+)"[^>]*name="totpSecret"',
        )
        for pattern in patterns:
            match = re.search(pattern, html)
            if match:
                value = match.group(1).replace(" ", "").strip().upper()
                if value:
                    return value
        raise SetupError("Keycloak TOTP page did not expose a Base32 secret.")

    @staticmethod
    def _hidden_value(html: str, name: str) -> str:
        patterns = (
            rf'name="{re.escape(name)}"[^>]*value="([^"]*)"',
            rf'value="([^"]*)"[^>]*name="{re.escape(name)}"',
        )
        for pattern in patterns:
            match = re.search(pattern, html)
            if match:
                return match.group(1)
        return ""

    def _otp_form_action(self, html: str) -> str:
        action = self._form_action(html)
        return action

    def _submit_totp(
        self,
        action: str,
        secret: str,
        *,
        enroll: bool = False,
        hidden_secret: str = "",
        selected_credential_id: str = "",
    ) -> Tuple[int, str, Optional[str]]:
        if enroll:
            fields = {
                "totp": generate_totp(secret),
                "totpSecret": hidden_secret or secret,
                "userLabel": "SGSI-ZTA local test authenticator",
            }
        else:
            fields = {
                "otp": generate_totp(secret),
                "login": "Sign In",
            }
            if selected_credential_id:
                fields["selectedCredentialId"] = selected_credential_id
        return self._post(action, fields)

    def _follow_login_action(self, location: str) -> Tuple[str, Optional[str]]:
        """Follow a required-action or OTP page and return (html, final_location)."""
        status, html, next_location = self._get(location)
        if status not in (200, 302):
            raise SetupError(f"Keycloak login action returned HTTP {status}.")
        if status == 302 and next_location:
            return self._follow_login_action(next_location)
        return html, next_location

    def login(
        self,
        username: str,
        password: str,
        totp_secret: Optional[str] = None,
        *,
        enroll_totp: bool = False,
    ) -> Dict[str, Any]:
        verifier, challenge = pkce_pair()
        state = secrets.token_hex(16)
        authorize_url = (
            f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/auth?"
            + urllib.parse.urlencode(
                {
                    "client_id": self.client_id,
                    "response_type": "code",
                    "redirect_uri": self.redirect_uri,
                    "scope": "openid profile email",
                    "state": state,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                }
            )
        )
        status, html, _ = self._get(authorize_url)
        if status != 200:
            raise SetupError(f"Authorization endpoint returned HTTP {status}.")
        action = self._form_action(html)
        status, html, location = self._post(
            action, {"username": username, "password": password, "credentialId": ""}
        )

        discovered_secret: Optional[str] = None
        discovered_hidden_secret: Optional[str] = None
        for _ in range(6):
            if os.environ.get("SGSI_SETUP_DEBUG") == "1":
                debug_dir = DEFAULT_CREDENTIALS_FILE.parent / "runtime"
                debug_dir.mkdir(parents=True, exist_ok=True)
                (debug_dir / f"login-step-{_}.html").write_text(html, encoding="utf-8")
                page_text = re.sub(
                    r"<[^>]+>", " ", re.sub(r"<script.*?</script>", " ", html, flags=re.S | re.I)
                )
                print(
                    f"  [debug] status={status} location={'yes' if location else 'no'} "
                    f"secret={'kc-totp-secret-key' in html} manual={'mode-manual' in html} "
                    f"otp={'otp' in html.lower()} configure={'CONFIGURE_TOTP' in html} "
                    f"text={re.sub(r'\\s+', ' ', page_text).strip()[:180]}"
                )
            if location and has_authorization_code(location):
                break
            # La deteccion no puede depender del idioma: el realm puede
            # funcionar en espanol. Los identificadores de la plantilla son
            # estables y la marca en ingles se conserva como tercer caso.
            if status == 200 and (
                "kc-totp-secret-key" in html
                or "mode-manual" in html
                or "CONFIGURE_TOTP" in html
                or "CONFIGURAR" in html.upper()
            ):
                manual_match = re.search(r'id="mode-manual"[^>]+href="([^"]+)"', html)
                if not manual_match:
                    manual_match = re.search(r'href="([^"]+)"[^>]+id="mode-manual"', html)
                if manual_match:
                    status, html, location = self._get(
                        manual_match.group(1).replace("&amp;", "&")
                    )
                    continue
                discovered_secret = self._totp_secret(html)
                hidden_secret = self._hidden_value(html, "totpSecret")
                discovered_hidden_secret = hidden_secret
                action = self._otp_form_action(html)
                secret = totp_secret or discovered_secret
                if not secret:
                    raise SetupError("Keycloak requested TOTP but no TOTP secret was provided.")
                status, html, location = self._submit_totp(
                    action, secret, enroll=True, hidden_secret=hidden_secret
                )
                continue
            if status == 200 and ("otp" in html.lower() or "kc-otp" in html.lower()):
                action = self._otp_form_action(html)
                secret = totp_secret or discovered_secret
                if not secret:
                    raise SetupError("Keycloak requested OTP but no TOTP secret was provided.")
                status, html, location = self._submit_totp(
                    action,
                    secret,
                    enroll=False,
                    selected_credential_id=self._hidden_value(html, "selectedCredentialId"),
                )
                continue
            if location:
                status, html, location = self._get(location)
                continue
            break

        if not location or not has_authorization_code(location):
            snippet = re.sub(r"\s+", " ", html)[:400]
            raise SetupError(
                f"Keycloak did not return an authorization code for {username}. "
                f"Last status: {status}; page markers: "
                f"otp={'otp' in html.lower()}, totp_secret={'kc-totp-secret-key' in html}, "
                f"manual={'mode-manual' in html}, configure={'CONFIGURE_TOTP' in html}. "
                f"Page: {snippet}"
            )
        query = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
        if query.get("state", [""])[0] != state:
            raise SetupError(
                "OIDC state mismatch during local login "
                f"(expected length {len(state)}, received length "
                f"{len(query.get('state', [''])[0])}, "
                f"query keys {sorted(query.keys())})."
            )
        code = query["code"][0]
        status, payload = request_json(
            "POST",
            f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/token",
            form={
                "client_id": self.client_id,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.redirect_uri,
                "code_verifier": verifier,
            },
        )
        if status != 200 or not isinstance(payload, dict):
            raise SetupError(f"Token exchange failed for {username} (HTTP {status}): {payload}")
        access_token = str(payload["access_token"])
        claims = decode_jwt_payload(access_token)
        return {
            "access_token": access_token,
            "claims": claims,
            "discovered_totp_secret": discovered_secret,
            "discovered_hidden_secret": discovered_hidden_secret,
        }


def has_authorization_code(url: str) -> bool:
    """Return True only when the URL carries an OAuth ``code`` parameter.

    ``session_code`` is part of every Keycloak login-action URL and must not be
    mistaken for the authorization code.
    """
    try:
        return "code" in urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    except ValueError:
        return False


def decode_jwt_payload(token: str) -> Dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise SetupError("Token is not a JWS.")
    payload = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
    return json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))


def clear_required_actions(
    keycloak_url: str, token: str, realm: str, user_id: str
) -> None:
    admin_api(
        keycloak_url,
        token,
        "PUT",
        f"/admin/realms/{realm}/users/{user_id}",
        {"requiredActions": []},
        ok=(204,),
    )


def verify_realm(
    keycloak_url: str,
    realm: str,
    client_id: str,
    redirect_uri: str,
    credentials: Dict[str, Dict[str, Any]],
) -> None:
    # The TOTP credential was just enrolled with the current 30-second step.
    # Keycloak rejects a replay of that same step, so wait for the next window
    # before verifying the OTP login path.
    if any(record.get("mfa") for record in credentials.values()):
        wait_seconds = 31 - (time.time() % 30)
        print(f"  Waiting {wait_seconds:.1f}s for a fresh TOTP window ...")
        time.sleep(wait_seconds + 1)
    checks = [
        ("recepcion.test", "admision", False),
        ("laboratorio.test", "laboratorio", False),
        ("medico.test", "medico", True),
        ("medico.sinmfa", "medico", False),
        ("auditor.test", "auditor", False),
    ]
    for username, expected_role, expect_otp in checks:
        record = credentials[username]
        flow = BrowserFlow(keycloak_url, realm, client_id, redirect_uri)
        result = flow.login(
            username,
            record["password"],
            record.get("totp_secret"),
        )
        claims = result["claims"]
        roles = set(claims.get("realm_access", {}).get("roles", []))
        amr = claims.get("amr", [])
        if expected_role not in roles:
            raise SetupError(f"{username} token is missing realm role {expected_role}: {sorted(roles)}")
        if "clinical-poc-api" not in (claims.get("aud") if isinstance(claims.get("aud"), list) else [claims.get("aud")]):
            raise SetupError(f"{username} token is missing the clinical-poc-api audience.")
        if expect_otp and "otp" not in [str(item).lower() for item in amr]:
            raise SetupError(f"{username} did not obtain an OTP AMR claim: {amr}")
        if not expect_otp and "otp" in [str(item).lower() for item in amr]:
            raise SetupError(f"{username} unexpectedly obtained an OTP AMR claim: {amr}")
        print(f"  PASS {username}: roles={sorted(roles)} amr={amr}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keycloak-url", default=os.environ.get("KEYCLOAK_URL", DEFAULT_KEYCLOAK_URL))
    parser.add_argument("--realm", default=os.environ.get("KEYCLOAK_REALM", DEFAULT_REALM))
    parser.add_argument("--client-id", default=os.environ.get("KEYCLOAK_CLIENT_ID", DEFAULT_CLIENT_ID))
    parser.add_argument("--redirect-uri", default=os.environ.get("KEYCLOAK_REDIRECT_URI", DEFAULT_REDIRECT_URI))
    parser.add_argument("--credentials-file", type=Path, default=DEFAULT_CREDENTIALS_FILE)
    parser.add_argument("--admin-user", default=os.environ.get("KEYCLOAK_ADMIN_USERNAME", "admin"))
    parser.add_argument("--admin-password", default=os.environ.get("KEYCLOAK_ADMIN_PASSWORD"))
    args = parser.parse_args()

    env_file = Path(__file__).with_name(".env")
    env_values = read_env_file(env_file)
    admin_password = args.admin_password or env_values.get("KEYCLOAK_ADMIN_PASSWORD")
    if not admin_password:
        raise SetupError(
            "KEYCLOAK_ADMIN_PASSWORD is not set. Create infra/local-test/.env or pass --admin-password."
        )

    keycloak_url = args.keycloak_url.rstrip("/")
    print(f"Waiting for Keycloak at {keycloak_url} ...")
    wait_for_keycloak(keycloak_url)
    token = admin_token(keycloak_url, args.admin_user, admin_password)

    print(f"Recreating local realm {args.realm} ...")
    delete_existing_realm(keycloak_url, token, args.realm)
    create_realm(keycloak_url, token, args.realm)
    roles = create_roles(keycloak_url, token, args.realm)
    create_client(keycloak_url, token, args.realm, args.client_id)
    users = create_users(keycloak_url, token, args.realm, roles)
    create_conditional_flow(keycloak_url, token, args.realm)

    print("Enrolling the pathologist TOTP credential through the real login flow ...")
    medico = users["medico.test"]
    enrollment = BrowserFlow(keycloak_url, args.realm, args.client_id, args.redirect_uri).login(
        "medico.test",
        medico["password"],
        enroll_totp=True,
    )
    totp_secret = enrollment.get("discovered_totp_secret")
    if not totp_secret:
        raise SetupError("TOTP enrollment did not expose the generated secret.")
    users["medico.test"]["totp_secret"] = totp_secret
    clear_required_actions(keycloak_url, token, args.realm, medico["id"])

    credentials = {
        "realm": args.realm,
        "issuer": f"{keycloak_url}/realms/{args.realm}",
        "clientId": args.client_id,
        "redirectUri": args.redirect_uri,
        "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "users": users,
    }
    args.credentials_file.parent.mkdir(parents=True, exist_ok=True)
    args.credentials_file.write_text(json.dumps(credentials, indent=2), encoding="utf-8")
    try:
        os.chmod(args.credentials_file, 0o600)
    except OSError:
        pass

    print("Verifying synthetic tokens and AMR claims ...")
    verify_realm(
        keycloak_url,
        args.realm,
        args.client_id,
        args.redirect_uri,
        users,
    )
    print(f"PASS: local realm ready. Credentials written to {args.credentials_file}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SetupError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
