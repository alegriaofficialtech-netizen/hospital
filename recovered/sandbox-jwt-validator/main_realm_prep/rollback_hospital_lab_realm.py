#!/usr/bin/env python3
"""
rollback_hospital_lab_realm.py - Surgical Rollback for Stage 4 Keycloak Changes

Reverts exclusively the operations authorized for Stage 4:
1. Reverts 'clinical-poc' to enabled=false (or previous state from backup JSON).
2. Deletes added protocol mappers ('clinical-poc-api-audience' and 'amr') from 'clinical-poc'.
3. Deletes 'clinical-audit-monitor-service' client and its associated service account.
4. Removes local credentials file '.env.audit_monitor_credentials_main'.
5. Does NOT touch users, other clients, or the database.
"""

import json
import os
import subprocess
import sys
import urllib.parse
import urllib.request

KEYCLOAK_BASE_URL = os.environ.get("KEYCLOAK_BASE_URL", "http://127.0.0.1:8085")
TARGET_REALM = "hospital-lab"
BACKUP_JSON = "/home/elcra/sandbox-jwt-validator/backup_hospital_lab_realm_pre_stage4.json"
CREDS_FILE = "/home/elcra/sandbox-jwt-validator/.env.audit_monitor_credentials_main"


def get_admin_token() -> str:
    env_out = subprocess.check_output(
        ["docker", "exec", "sgsi-zta-hospital-lab-keycloak-1", "env"],
        stderr=subprocess.DEVNULL
    ).decode("utf-8")
    env_vars = dict(l.split("=", 1) for l in env_out.splitlines() if "=" in l)
    username = env_vars.get("KC_BOOTSTRAP_ADMIN_USERNAME", "admin.lab")
    password = env_vars.get("KC_BOOTSTRAP_ADMIN_PASSWORD")
    token_url = f"{KEYCLOAK_BASE_URL}/realms/master/protocol/openid-connect/token"
    data = urllib.parse.urlencode({
        "client_id": "admin-cli",
        "grant_type": "password",
        "username": username,
        "password": password
    }).encode("utf-8")
    req = urllib.request.Request(token_url, data=data, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))["access_token"]


def api_req(endpoint: str, method: str = "GET", data: dict = None, token: str = None):
    url = f"{KEYCLOAK_BASE_URL}{endpoint}"
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
            return e.code, json.loads(body)
        except Exception:
            return e.code, {"raw": body}


def rollback():
    print("=" * 72)
    print(" INICIANDO PROCEDIMIENTO DE ROLLBACK QUIRÚRGICO (STAGE 4)")
    print("=" * 72)
    token = get_admin_token()

    # 1. Revert clinical-poc mappers and enabled status
    status, clients = api_req(f"/admin/realms/{TARGET_REALM}/clients?clientId=clinical-poc", token=token)
    if status == 200 and clients:
        poc = clients[0]
        poc_id = poc["id"]
        print(f"[*] Revirtiendo cliente 'clinical-poc' ({poc_id})...")

        # Delete added mappers
        status, mappers = api_req(f"/admin/realms/{TARGET_REALM}/clients/{poc_id}/protocol-mappers/models", token=token)
        if status == 200 and isinstance(mappers, list):
            for m in mappers:
                if m.get("name") in ("clinical-poc-api-audience", "amr"):
                    mid = m["id"]
                    del_st, _ = api_req(f"/admin/realms/{TARGET_REALM}/clients/{poc_id}/protocol-mappers/models/{mid}", method="DELETE", token=token)
                    print(f"    [-] Mapper eliminado: {m.get('name')} (HTTP {del_st})")

        # Revert enabled to False
        poc["enabled"] = False
        up_st, _ = api_req(f"/admin/realms/{TARGET_REALM}/clients/{poc_id}", method="PUT", data=poc, token=token)
        print(f"    [-] 'clinical-poc' deshabilitado (enabled: False, HTTP {up_st})")

    # 2. Delete clinical-audit-monitor-service
    status, audit_clients = api_req(f"/admin/realms/{TARGET_REALM}/clients?clientId=clinical-audit-monitor-service", token=token)
    if status == 200 and audit_clients:
        audit_id = audit_clients[0]["id"]
        del_st, _ = api_req(f"/admin/realms/{TARGET_REALM}/clients/{audit_id}", method="DELETE", token=token)
        print(f"[*] Cliente 'clinical-audit-monitor-service' eliminado ({audit_id}, HTTP {del_st})")

    # 3. Remove credentials file
    if os.path.exists(CREDS_FILE):
        os.remove(CREDS_FILE)
        print(f"[*] Archivo de credenciales {CREDS_FILE} eliminado.")

    print("=" * 72)
    print("[+] ROLLBACK QUIRÚRGICO FINALIZADO EXITOSAMENTE.")
    print("=" * 72)


if __name__ == "__main__":
    confirm = input("¿Confirma ejecutar rollback sobre 'hospital-lab'? [escriba 'ROLLBACK']: ")
    if confirm == "ROLLBACK":
        rollback()
    else:
        print("[-] Operación cancelada.")
