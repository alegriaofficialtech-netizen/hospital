import json
import sys
sys.path.insert(0, "/home/elcra/sandbox-jwt-validator")
from stage2_setup_realm import get_admin_token, api_call

REALM = "hospital-lab-oidc-test"
token = get_admin_token()
status, clients = api_call(f"/admin/realms/{REALM}/clients?clientId=clinical-poc-frontend-test", token=token)
client = clients[0]
cid = client["id"]
status, mappers = api_call(f"/admin/realms/{REALM}/clients/{cid}/protocol-mappers/models", token=token)

print(f"Client {client['clientId']} (ID: {cid}) has {len(mappers)} protocol mappers:")
for m in mappers:
    print(f"  - {m.get('name')}: provider={m.get('protocolMapper')}, config={m.get('config')}")
