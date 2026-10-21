import json, sys
sys.path.insert(0, "/home/elcra/sandbox-jwt-validator")
from stage2_setup_realm import get_admin_token, api_call

token = get_admin_token()
status, info = api_call("/admin/serverinfo", token=token)

for p in info.get("protocolMapperTypes", {}).get("openid-connect", []):
    if p.get("id") == "oidc-amr-mapper":
        print(json.dumps(p, indent=2))
