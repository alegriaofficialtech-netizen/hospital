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
    st, res = api_call(f"/admin/realms/{REALM}/clients/{cid}/protocol-mappers/models", method="POST", data=mapper_data, token=token)
    print(f"Added oidc-amr-mapper to client {cid}: status={st}")
else:
    print("oidc-amr-mapper is already present on client")

# Also check for clinical-poc-api audience mapper to ensure both access and id tokens are configured
status, mappers_after = api_call(f"/admin/realms/{REALM}/clients/{cid}/protocol-mappers/models", token=token)
print(f"Total protocol mappers now: {len(mappers_after)}")
for m in mappers_after:
    print(f"  - {m.get('name')}: {m.get('protocolMapper')}")
