#!/usr/bin/env python3
"""
Procedimiento de Reversion y Limpieza Segura del Realm de Pruebas Etapa 2.
Elimina exclusivamente el realm 'hospital-lab-oidc-test' de Keycloak sin afectar
el realm de produccion 'hospital-lab' ni la base de datos principal.
USO: python3 stage2_revert_realm.py --confirm-delete-realm
"""

import sys
import json
import subprocess
import urllib.parse
import urllib.request

def revert_test_realm():
    if "--confirm-delete-realm" not in sys.argv:
        print("ERROR: Debe proporcionar la bandera explícita '--confirm-delete-realm' para autorizar el desmantelamiento.")
        print("Sintaxis: python3 stage2_revert_realm.py --confirm-delete-realm")
        sys.exit(1)

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
        token = json.loads(resp.read().decode())['access_token']

    realm_to_delete = "hospital-lab-oidc-test"
    req_del = urllib.request.Request(f"http://127.0.0.1:8085/admin/realms/{realm_to_delete}", method='DELETE')
    req_del.add_header('Authorization', f'Bearer {token}')

    try:
        with urllib.request.urlopen(req_del) as resp:
            if resp.status in (200, 204):
                print(f"PASS: Realm '{realm_to_delete}' eliminado exitosamente de Keycloak.")
            else:
                print(f"WARN: Respuesta inesperada al eliminar realm: {resp.status}")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print(f"INFO: Realm '{realm_to_delete}' ya no existe en Keycloak.")
        else:
            print(f"ERROR: Fallo al eliminar realm '{realm_to_delete}': {e.code} - {e.read().decode()}")

if __name__ == '__main__':
    revert_test_realm()