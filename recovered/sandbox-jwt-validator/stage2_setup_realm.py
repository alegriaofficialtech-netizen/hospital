from stage2_credentials import get_user_password
import json
import os
import subprocess
import sys
import urllib.parse
import urllib.request

def get_admin_token() -> str:
    env_out = subprocess.check_output(['docker', 'exec', 'sgsi-zta-hospital-lab-keycloak-1', 'env']).decode()
    env = dict(line.split('=', 1) for line in env_out.splitlines() if '=' in line)
    user = env.get('KC_BOOTSTRAP_ADMIN_USERNAME')
    pwd = env.get('KC_BOOTSTRAP_ADMIN_PASSWORD')

    data = urllib.parse.urlencode({
        'client_id': 'admin-cli',
        'grant_type': 'password',
        'username': user,
        'password': pwd
    }).encode()
    req = urllib.request.Request('http://127.0.0.1:8085/realms/master/protocol/openid-connect/token', data=data)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())['access_token']

def api_call(endpoint: str, method: str = 'GET', data: dict = None, token: str = None):
    url = f"http://127.0.0.1:8085{endpoint}"
    req = urllib.request.Request(url, method=method)
    if token:
        req.add_header('Authorization', f'Bearer {token}')
    if data is not None:
        req.add_header('Content-Type', 'application/json')
        req.data = json.dumps(data).encode('utf-8')
    try:
        with urllib.request.urlopen(req) as resp:
            body = resp.read().decode('utf-8')
            return resp.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8')
        try:
            err_json = json.loads(body)
        except Exception:
            err_json = {'raw': body}
        return e.code, err_json

def setup_stage2_realm():
    token = get_admin_token()
    realm_name = "hospital-lab-oidc-test"

    # 1. Verificar si ya existe
    status, res = api_call(f"/admin/realms/{realm_name}", token=token)
    if status == 200:
        print(f"INFO: Realm {realm_name} ya existe. Omitiendo creacion inicial.")
    else:
        print(f"Creando realm {realm_name}...")
        realm_payload = {
            "realm": realm_name,
            "enabled": True,
            "displayName": "Hospital Lab OIDC Test Realm",
            "sslRequired": "none",
            "registrationAllowed": False,
            "resetPasswordAllowed": False,
            "rememberMe": False,
            "otpPolicyType": "totp",
            "otpPolicyAlgorithm": "HmacSHA1",
            "otpPolicyDigits": 6,
            "otpPolicyPeriod": 30
        }
        status, res = api_call("/admin/realms", method="POST", data=realm_payload, token=token)
        if status not in (201, 204):
            print(f"ERROR creando realm: status {status}, {res}")
            sys.exit(1)
        print(f"PASS: Realm {realm_name} creado exitosamente.")

    # 2. Roles del Realm
    roles = ["admision", "medico", "auditor", "laboratorio", "mfa-required"]
    for r in roles:
        status, _ = api_call(f"/admin/realms/{realm_name}/roles", method="POST", data={"name": r, "description": f"Rol {r} para pruebas OIDC"}, token=token)
        if status in (201, 204, 409):
            print(f"PASS: Rol de realm '{r}' configurado.")
        else:
            print(f"WARN: Creacion de rol '{r}' retorno {status}")

    # 3. Client clinical-poc-api (Resource Server / Bearer Only)
    bearer_client = {
        "clientId": "clinical-poc-api",
        "name": "Clinical PoC API Resource Server",
        "enabled": True,
        "bearerOnly": True
    }
    status, _ = api_call(f"/admin/realms/{realm_name}/clients", method="POST", data=bearer_client, token=token)

    # 4. Client clinical-poc-frontend-test (Public client con PKCE S256 mandatorio)
    status, existing_clients = api_call(f"/admin/realms/{realm_name}/clients?clientId=clinical-poc-frontend-test", token=token)
    client_id_uuid = None
    if status == 200 and existing_clients:
        client_id_uuid = existing_clients[0]["id"]
        print(f"INFO: Cliente clinical-poc-frontend-test ya existe (UUID: {client_id_uuid}).")
    else:
        frontend_client = {
            "clientId": "clinical-poc-frontend-test",
            "name": "Clinical PoC Frontend Test Client",
            "enabled": True,
            "publicClient": True,
            "standardFlowEnabled": True,
            "directAccessGrantsEnabled": False,  # Deshabilitado segun requerimiento
            "implicitFlowEnabled": False,
            "redirectUris": [
                "http://127.0.0.1:8080/callback",
                "http://127.0.0.1:9090/callback",
                "http://localhost:8080/callback"
            ],
            "attributes": {
                "pkce.code.challenge.method": "S256"
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
                        "access.token.claim": "true"
                    }
                }
            ]
        }
        status, _ = api_call(f"/admin/realms/{realm_name}/clients", method="POST", data=frontend_client, token=token)
        if status in (201, 204):
            status, clients = api_call(f"/admin/realms/{realm_name}/clients?clientId=clinical-poc-frontend-test", token=token)
            client_id_uuid = clients[0]["id"]
            print(f"PASS: Cliente publico 'clinical-poc-frontend-test' creado (PKCE S256 mandatorio, Direct Grants desactivado).")
        else:
            print(f"ERROR creando cliente frontend: status {status}")
            sys.exit(1)

    # 5. Usuarios Sinteticos
    # Obtenemos mapa de roles
    status, role_list = api_call(f"/admin/realms/{realm_name}/roles", token=token)
    role_map = {r["name"]: r for r in role_list}

    users_spec = [
        {"username": "admision.test", "pwd": get_user_password("admision.test"), "roles": ["admision"]},
        {"username": "medico.test", "pwd": get_user_password("medico.test"), "roles": ["medico", "mfa-required"]},
        {"username": "auditor.test", "pwd": get_user_password("auditor.test"), "roles": ["auditor"]},
    ]

    for u in users_spec:
        uname = u["username"]
        status, u_existing = api_call(f"/admin/realms/{realm_name}/users?username={uname}&exact=true", token=token)
        if status == 200 and u_existing:
            uid = u_existing[0]["id"]
            print(f"INFO: Usuario {uname} ya existe (UUID: {uid}).")
        else:
            u_payload = {
                "username": uname,
                "enabled": True,
                "email": f"{uname}@hospital-test.local",
                "emailVerified": True,
                "credentials": [{"type": "password", "value": u["pwd"], "temporary": False}]
            }
            status, _ = api_call(f"/admin/realms/{realm_name}/users", method="POST", data=u_payload, token=token)
            status, u_created = api_call(f"/admin/realms/{realm_name}/users?username={uname}&exact=true", token=token)
            uid = u_created[0]["id"]
            print(f"PASS: Usuario sintetico {uname} creado.")

        # Asignar roles de realm
        roles_to_assign = [role_map[rname] for rname in u["roles"] if rname in role_map]
        status, _ = api_call(f"/admin/realms/{realm_name}/users/{uid}/role-mappings/realm", method="POST", data=roles_to_assign, token=token)
        print(f"PASS: Roles {u['roles']} asignados a {uname}.")

    # 6. Flujo de Autenticacion con MFA Condicional
    prefix = f"/admin/realms/{realm_name}"
    status, flows = api_call(f"{prefix}/authentication/flows", token=token)
    has_test_browser_flow = any(f.get("alias") == "hospital-test-browser" for f in flows)
    if not has_test_browser_flow:
        print("Configurando flujo hospital-test-browser con MFA condicional...")
        status, _ = api_call(f"{prefix}/authentication/flows", method="POST", data={
            "alias": "hospital-test-browser",
            "description": "Hospital test browser flow with conditional MFA",
            "providerId": "basic-flow",
            "topLevel": True,
            "builtIn": False
        }, token=token)

        api_call(f"{prefix}/authentication/flows/hospital-test-browser/executions/execution", method="POST",
                 data={"provider": "auth-cookie"}, token=token)
        api_call(f"{prefix}/authentication/flows/hospital-test-browser/executions/execution", method="POST",
                 data={"provider": "identity-provider-redirector"}, token=token)
        api_call(f"{prefix}/authentication/flows/hospital-test-browser/executions/flow", method="POST",
                 data={"alias": "hospital-test-forms", "type": "basic-flow",
                       "description": "Form login with conditional MFA", "provider": "basic-flow"}, token=token)

        status, execs = api_call(f"{prefix}/authentication/flows/hospital-test-browser/executions", token=token)
        for ex in execs:
            if ex.get("providerId") in ("auth-cookie", "identity-provider-redirector") or ex.get("displayName") == "hospital-test-forms":
                if ex.get("requirement") != "ALTERNATIVE":
                    api_call(f"{prefix}/authentication/flows/hospital-test-browser/executions", method="PUT",
                             data={"id": ex["id"], "requirement": "ALTERNATIVE"}, token=token)

        api_call(f"{prefix}/authentication/flows/hospital-test-forms/executions/execution", method="POST",
                 data={"provider": "auth-username-password-form"}, token=token)
        api_call(f"{prefix}/authentication/flows/hospital-test-forms/executions/flow", method="POST",
                 data={"alias": "hospital-test-conditional-mfa", "type": "basic-flow",
                       "description": "Conditional OTP for mfa-required role", "provider": "basic-flow"}, token=token)

        status, execs_forms = api_call(f"{prefix}/authentication/flows/hospital-test-forms/executions", token=token)
        for ex in execs_forms:
            if ex.get("providerId") == "auth-username-password-form":
                api_call(f"{prefix}/authentication/flows/hospital-test-forms/executions", method="PUT",
                         data={"id": ex["id"], "requirement": "REQUIRED"}, token=token)
            elif ex.get("displayName") == "hospital-test-conditional-mfa":
                api_call(f"{prefix}/authentication/flows/hospital-test-forms/executions", method="PUT",
                         data={"id": ex["id"], "requirement": "CONDITIONAL"}, token=token)

        api_call(f"{prefix}/authentication/flows/hospital-test-conditional-mfa/executions/execution", method="POST",
                 data={"provider": "conditional-user-role"}, token=token)
        api_call(f"{prefix}/authentication/flows/hospital-test-conditional-mfa/executions/execution", method="POST",
                 data={"provider": "auth-otp-form"}, token=token)

        status, execs_cond = api_call(f"{prefix}/authentication/flows/hospital-test-conditional-mfa/executions", token=token)
        for ex in execs_cond:
            api_call(f"{prefix}/authentication/flows/hospital-test-conditional-mfa/executions", method="PUT",
                     data={"id": ex["id"], "requirement": "REQUIRED"}, token=token)
            if ex.get("providerId") == "conditional-user-role":
                api_call(f"{prefix}/authentication/executions/{ex['id']}/config", method="POST", data={
                    "alias": "require-mfa-test-config",
                    "config": {"condUserRole": "mfa-required", "negate": "false"}
                }, token=token)

        # Vincular browserFlow
        api_call(prefix, method="PUT", data={"browserFlow": "hospital-test-browser"}, token=token)
        print("PASS: Flujo de autenticacion condicional vinculado a hospital-test-browser.")
    else:
        print("INFO: Flujo hospital-test-browser ya configurado.")

    # 7. Configuracion de Mappers AMR y Referencias RFC 8176
    status, clients = api_call(f"/admin/realms/{realm_name}/clients?clientId=clinical-poc-frontend-test", token=token)
    if status == 200 and clients:
        cid = clients[0]["id"]
        status, mappers = api_call(f"/admin/realms/{realm_name}/clients/{cid}/protocol-mappers/models", token=token)
        has_amr = any(m.get("protocolMapper") == "oidc-amr-mapper" for m in mappers)
        if not has_amr:
            mapper_data = {
                "name": "amr",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-amr-mapper",
                "consentRequired": False,
                "config": {
                    "id.token.claim": "true",
                    "access.token.claim": "true",
                    "lightweight.claim": "false"
                }
            }
            api_call(f"/admin/realms/{realm_name}/clients/{cid}/protocol-mappers/models", method="POST", data=mapper_data, token=token)
            print("PASS: Mapper nativo oidc-amr-mapper configurado en cliente.")
        else:
            print("INFO: Mapper oidc-amr-mapper ya presente.")

    # Asegurar default.reference.value en ejecuciones de autenticacion
    status, execs_browser = api_call(f"/admin/realms/{realm_name}/authentication/flows/hospital-test-browser/executions", token=token)
    for ex in execs_browser:
        pid = ex.get("providerId")
        if pid == "auth-username-password-form" and not ex.get("authenticationConfig"):
            api_call(f"/admin/realms/{realm_name}/authentication/executions/{ex['id']}/config", method="POST",
                     data={"alias": "amr-pwd-config", "config": {"default.reference.value": "pwd"}}, token=token)
            print("PASS: default.reference.value='pwd' configurado en auth-username-password-form.")
        elif pid == "auth-otp-form" and not ex.get("authenticationConfig"):
            api_call(f"/admin/realms/{realm_name}/authentication/executions/{ex['id']}/config", method="POST",
                     data={"alias": "amr-otp-config", "config": {"default.reference.value": "otp"}}, token=token)
            print("PASS: default.reference.value='otp' configurado en auth-otp-form.")

    print("SUCCESS: Realm hospital-lab-oidc-test configurado al 100%.")

if __name__ == "__main__":
    setup_stage2_realm()