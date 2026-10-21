import json, sys
sys.path.insert(0, "/home/elcra/sandbox-jwt-validator")
from stage2_setup_realm import get_admin_token, api_call

token = get_admin_token()
status, info = api_call("/admin/serverinfo", token=token)

auth_factories = info.get("authenticatorConfigProperties", {})
for k in ["conditional-level-of-authentication", "auth-otp-form", "oidc-amr-mapper"]:
    props = auth_factories.get(k, [])
    print(f"=== {k} properties ===")
    for p in props:
        print(f"  {p.get('name')}: {p.get('label')} ({p.get('type')}) - {p.get('helpText')}")
