#!/usr/bin/env python3
"""
kc_admin.py - Cliente mínimo de la Admin REST API de Keycloak (solo stdlib).

Se usa para aprovisionar el cliente M2M del monitor y para exportar el realm.
Nunca imprime secretos: el llamador decide qué mostrar.

Autenticación: password grant contra el realm 'master' con el usuario admin.
La contraseña se toma de una variable de entorno o de un archivo 0600, nunca
de un argumento de línea de comandos (quedaría visible en 'ps').
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple


class KeycloakError(RuntimeError):
    """Error de la Admin REST API con el detalle acotado del servidor."""


class KeycloakAdmin:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        timeout: float = 20.0,
        cafile: Optional[str] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout
        self._token: Optional[str] = None
        self._context: Optional[ssl.SSLContext] = None
        if self.base_url.startswith("https://"):
            self._context = (
                ssl.create_default_context(cafile=cafile)
                if cafile
                else ssl.create_default_context()
            )

    # ------------------------------------------------------------------ HTTP
    def _urlopen(self, request: urllib.request.Request):
        return urllib.request.urlopen(
            request, timeout=self.timeout, context=self._context
        )

    def _request(
        self,
        method: str,
        path: str,
        payload: Optional[Any] = None,
        expected: Tuple[int, ...] = (200, 201, 204),
    ) -> Any:
        url = f"{self.base_url}{path}"
        headers = {
            "Authorization": f"Bearer {self.token()}",
            "Accept": "application/json",
        }
        data = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with self._urlopen(request) as response:
                status = response.status
                body = response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:400]
            raise KeycloakError(f"{method} {path} -> {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise KeycloakError(f"{method} {path} -> {exc.reason}") from exc
        if status not in expected:
            raise KeycloakError(f"{method} {path} -> {status}")
        if not body:
            return None
        try:
            return json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            return body.decode("utf-8", errors="replace")

    def get(self, path: str) -> Any:
        return self._request("GET", path)

    def post(self, path: str, payload: Optional[Any] = None, expected=(200, 201, 204)) -> Any:
        return self._request("POST", path, payload, expected)

    def put(self, path: str, payload: Optional[Any] = None) -> Any:
        return self._request("PUT", path, payload, (200, 204))

    def delete(self, path: str) -> Any:
        return self._request("DELETE", path, None, (200, 204))

    # --------------------------------------------------------------- token
    def token(self) -> str:
        if self._token:
            return self._token
        data = urllib.parse.urlencode(
            {
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": self.username,
                "password": self.password,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/realms/master/protocol/openid-connect/token",
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with self._urlopen(request) as response:
                self._token = json.loads(response.read().decode("utf-8"))["access_token"]
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:300]
            raise KeycloakError(f"token admin falló ({exc.code}): {detail}") from exc
        return self._token

    # ------------------------------------------------------------ helpers
    def find_client(self, realm: str, client_id: str) -> Optional[Dict[str, Any]]:
        quoted = urllib.parse.quote(client_id, safe="")
        clients = self.get(f"/admin/realms/{realm}/clients?clientId={quoted}")
        if isinstance(clients, list) and clients:
            return clients[0]
        return None

    def client_secret(self, realm: str, client_uuid: str) -> str:
        payload = self.get(f"/admin/realms/{realm}/clients/{client_uuid}/client-secret")
        return str((payload or {}).get("value", ""))

    def regenerate_client_secret(self, realm: str, client_uuid: str) -> str:
        payload = self.post(
            f"/admin/realms/{realm}/clients/{client_uuid}/client-secret"
        )
        return str((payload or {}).get("value", ""))

    def service_account_user(self, realm: str, client_uuid: str) -> Dict[str, Any]:
        return self.get(
            f"/admin/realms/{realm}/clients/{client_uuid}/service-account-user"
        )

    def realm_role(self, realm: str, role_name: str) -> Dict[str, Any]:
        return self.get(f"/admin/realms/{realm}/roles/{urllib.parse.quote(role_name, safe='')}")


def read_secret(
    env_name: str, file_path: Optional[str] = None, label: str = "secreto"
) -> str:
    """Lee un secreto de un archivo 0600 o de una variable de entorno."""
    if file_path:
        with open(file_path, "r", encoding="utf-8") as handle:
            value = handle.readline().strip()
        if not value:
            raise SystemExit(f"{label}: archivo vacío: {file_path}")
        return value
    import os

    value = os.environ.get(env_name, "").strip()
    if not value:
        raise SystemExit(
            f"{label}: defina {env_name} o use un archivo 0600 (nunca en argv)."
        )
    return value
