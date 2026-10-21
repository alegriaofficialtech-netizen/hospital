#!/usr/bin/env python3
"""Administracion de identidades de la plataforma SGSI-ZTA.

Este modulo es el proxy de confianza hacia la API de administracion de
Keycloak. El navegador nunca ve la credencial de administracion: solo el
backend la usa, y cada operacion devuelve un registro que el servidor
incorpora a la cadena de auditoria inmutable.

Reglas del diseno:

* Solo identidades sinteticas. Las cuentas se crean con sufijo ``.test`` y
  llevan un atributo ``f11=sintetico`` que las marca sin ambiguedad.
* Baja por desactivacion. El borrado destruiria evidencia de auditoria, asi
  que no se expone.
* La generacion de contrasena ocurre aqui y se devuelve una sola vez, al
  administrador que la solicito. Nunca entra en la auditoria ni en un
  registro persistente.
* La gestion exige rol de administrador de plataforma y MFA acreditado, que
  el servidor comprueba antes de llamar a este modulo.
"""

from __future__ import annotations

import json
import secrets
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

SYNTHETIC_SUFFIX = ".test"
SYNTHETIC_ATTRIBUTE = "f11"
SYNTHETIC_MARKER = "sintetico"
MIN_PASSWORD_LENGTH = 16


class IdentityAdminError(RuntimeError):
    """Error de la API de administracion de identidades."""

    def __init__(self, message: str, status: int = 502, code: str = "IDENTITY_ADMIN_ERROR"):
        super().__init__(message)
        self.status = status
        self.code = code


class IdentityAdminClient:
    """Cliente de la API de administracion de Keycloak para el realm F11."""

    def __init__(
        self,
        base_url: str,
        realm: str,
        admin_user: str,
        admin_password: str,
        timeout: int = 20,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.realm = realm
        self.admin_user = admin_user
        self.admin_password = admin_password
        self.timeout = timeout
        self._token: Optional[str] = None

    # ------------------------------------------------------------------ http

    def _request(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
        form: Optional[Dict[str, str]] = None,
        authenticated: bool = True,
    ) -> Tuple[int, Any]:
        url = self.base_url + path
        body: Optional[bytes] = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif form is not None:
            body = urllib.parse.urlencode(form).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if authenticated:
            headers["Authorization"] = "Bearer " + self.admin_token()
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", "replace")
                if not raw:
                    return resp.status, {}
                try:
                    return resp.status, json.loads(raw)
                except json.JSONDecodeError:
                    return resp.status, {"raw": raw}
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            try:
                detail = json.loads(raw)
            except json.JSONDecodeError:
                detail = {"raw": raw}
            raise IdentityAdminError(
                "Keycloak admin API responded %s: %s" % (exc.code, detail),
                status=exc.code,
                code="IDENTITY_ADMIN_HTTP_%s" % exc.code,
            ) from exc
        except urllib.error.URLError as exc:
            raise IdentityAdminError(
                "no se pudo contactar con el emisor: %s" % exc.reason,
                status=503,
                code="IDENTITY_ADMIN_UNREACHABLE",
            ) from exc

    def admin_token(self) -> str:
        if self._token:
            return self._token
        status, payload = self._request(
            "POST",
            "/realms/master/protocol/openid-connect/token",
            form={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": self.admin_user,
                "password": self.admin_password,
            },
            authenticated=False,
        )
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if status != 200 or not token:
            raise IdentityAdminError(
                "el emisor no concedio token de administracion",
                status=503,
                code="IDENTITY_ADMIN_NO_TOKEN",
            )
        self._token = str(token)
        return self._token

    # --------------------------------------------------------------- lecturas

    def list_roles(self) -> List[Dict[str, Any]]:
        status, payload = self._request(
            "GET", "/admin/realms/%s/roles" % self.realm
        )
        if status != 200 or not isinstance(payload, list):
            raise IdentityAdminError("no se pudieron leer los roles del realm")
        return [
            {
                "id": str(role.get("id")),
                "name": str(role.get("name")),
                "description": str(role.get("description") or ""),
                "composite": bool(role.get("composite")),
            }
            for role in payload
            if role.get("name")
        ]

    def list_users(self) -> List[Dict[str, Any]]:
        status, payload = self._request(
            "GET", "/admin/realms/%s/users" % self.realm
        )
        if status != 200 or not isinstance(payload, list):
            raise IdentityAdminError("no se pudieron leer las identidades del realm")
        users: List[Dict[str, Any]] = []
        for user in payload:
            username = str(user.get("username") or "")
            attributes = user.get("attributes") or {}
            users.append(
                {
                    "id": str(user.get("id")),
                    "username": username,
                    "enabled": bool(user.get("enabled")),
                    "synthetic": attributes.get(SYNTHETIC_ATTRIBUTE) == [SYNTHETIC_MARKER]
                    or attributes.get(SYNTHETIC_ATTRIBUTE) == SYNTHETIC_MARKER,
                    "realm_roles": sorted(
                        str(r) for r in (user.get("realmRoles") or [])
                    ),
                    "email_verified": bool(user.get("emailVerified")),
                }
            )
        users.sort(key=lambda u: u["username"])
        return users

    def get_user(self, user_id: str) -> Dict[str, Any]:
        status, payload = self._request(
            "GET", "/admin/realms/%s/users/%s" % (self.realm, user_id)
        )
        if status != 200 or not isinstance(payload, dict):
            raise IdentityAdminError("no se pudo leer la identidad", status=404)
        return payload

    # --------------------------------------------------------------- escrituras

    def create_user(
        self,
        username: str,
        password: str,
        roles: Sequence[str],
        require_mfa: bool = False,
    ) -> Dict[str, Any]:
        if not username.endswith(SYNTHETIC_SUFFIX):
            raise IdentityAdminError(
                "las identidades sinteticas terminan en %s" % SYNTHETIC_SUFFIX,
                status=400,
                code="IDENTITY_NOT_SYNTHETIC",
            )
        if len(password) < MIN_PASSWORD_LENGTH:
            raise IdentityAdminError(
                "la contrasena debe tener al menos %d caracteres" % MIN_PASSWORD_LENGTH,
                status=400,
                code="IDENTITY_WEAK_PASSWORD",
            )
        payload: Dict[str, Any] = {
            "username": username,
            "enabled": True,
            "emailVerified": True,
            "firstName": "Cuenta",
            "lastName": "Sintetica",
            "attributes": {SYNTHETIC_ATTRIBUTE: [SYNTHETIC_MARKER]},
            "credentials": [
                {
                    "type": "password",
                    "value": password,
                    "temporary": True,
                }
            ],
        }
        status, _ = self._request(
            "POST", "/admin/realms/%s/users" % self.realm, payload=payload
        )
        if status not in (201, 204):
            raise IdentityAdminError("el emisor no acepto la identidad", status=status)
        created = next(
            (u for u in self.list_users() if u["username"] == username), None
        )
        if created is None:
            raise IdentityAdminError(
                "la identidad se creo pero no se pudo leer", status=500
            )
        if roles:
            self.set_user_roles(created["id"], roles)
        if require_mfa:
            self.enable_mfa_requirement(created["id"])
        return created

    def set_user_roles(self, user_id: str, roles: Sequence[str]) -> List[str]:
        catalogue = {r["name"]: r for r in self.list_roles()}
        available = set(catalogue)
        wanted = [r for r in roles if r in available]
        unknown = [r for r in roles if r not in available]
        if unknown:
            raise IdentityAdminError(
                "roles desconocidos en el realm: %s" % ", ".join(sorted(unknown)),
                status=400,
                code="IDENTITY_UNKNOWN_ROLE",
            )
        # La API de Keycloak asigna los mapeos de rol con POST, no con PUT.
        # La API espera objetos de rol con id y nombre, no cadenas sueltas.
        mappings = [
            {"id": catalogue[name]["id"], "name": name} for name in wanted
        ]
        status, _ = self._request(
            "POST",
            "/admin/realms/%s/users/%s/role-mappings/realm" % (self.realm, user_id),
            payload=mappings,
        )
        if status not in (204, 200):
            raise IdentityAdminError("no se pudieron asignar los roles", status=status)
        return sorted(wanted)

    def set_user_enabled(self, user_id: str, enabled: bool) -> None:
        status, _ = self._request(
            "PUT",
            "/admin/realms/%s/users/%s" % (self.realm, user_id),
            payload={"enabled": bool(enabled)},
        )
        if status not in (200, 204):
            raise IdentityAdminError("no se pudo cambiar el estado", status=status)

    def reset_password(self, user_id: str, password: str) -> None:
        if len(password) < MIN_PASSWORD_LENGTH:
            raise IdentityAdminError(
                "la contrasena debe tener al menos %d caracteres" % MIN_PASSWORD_LENGTH,
                status=400,
                code="IDENTITY_WEAK_PASSWORD",
            )
        status, _ = self._request(
            "PUT",
            "/admin/realms/%s/users/%s/reset-password" % (self.realm, user_id),
            payload={"type": "password", "value": password, "temporary": True},
        )
        if status not in (200, 204):
            raise IdentityAdminError("no se pudo restablecer la contrasena", status=status)

    def enable_mfa_requirement(self, user_id: str) -> None:
        """Anade el rol que exige TOTP al usuario, si el realm lo define."""
        mfa_role = next(
            (r["name"] for r in self.list_roles() if "mfa" in r["name"].lower()), None
        )
        if not mfa_role:
            return
        current = self.get_user(user_id)
        roles = list(current.get("realmRoles") or [])
        if mfa_role not in roles:
            roles.append(mfa_role)
            self.set_user_roles(user_id, roles)

    def require_role(self, user_id: str, role: str) -> bool:
        current = self.get_user(user_id)
        return role in (current.get("realmRoles") or [])


def generate_password(length: int = 20) -> str:
    """Genera una contrasena sintética de un solo uso."""
    return secrets.token_urlsafe(length)


def validate_username(username: str) -> Optional[str]:
    """Valida el nombre de una identidad sintetica. Devuelve el motivo o None."""
    if not username or len(username) > 64:
        return "el nombre debe tener entre 1 y 64 caracteres"
    if not username.endswith(SYNTHETIC_SUFFIX):
        return "las identidades sinteticas terminan en %s" % SYNTHETIC_SUFFIX
    if not username[:-len(SYNTHETIC_SUFFIX)].replace("_", "").replace("-", "").isalnum():
        return "el nombre solo admite letras, digitos, guion y guion bajo"
    return None


def summarise_users(users: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Resumen por rol y estado, sin datos de credencial."""
    users = list(users)
    by_role: Dict[str, int] = {}
    enabled = 0
    mfa_required = 0
    for user in users:
        if user.get("enabled"):
            enabled += 1
        roles = user.get("realm_roles") or []
        if any("mfa" in str(r).lower() for r in roles):
            mfa_required += 1
        for role in roles:
            by_role[str(role)] = by_role.get(str(role), 0) + 1
    return {
        "total": len(users),
        "enabled": enabled,
        "disabled": len(users) - enabled,
        "mfa_required": mfa_required,
        "by_role": dict(sorted(by_role.items())),
    }
