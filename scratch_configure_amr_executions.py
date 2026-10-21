import json, sys
sys.path.insert(0, "/home/elcra/sandbox-jwt-validator")
from stage2_setup_realm import get_admin_token, api_call

REALM = "hospital-lab-oidc-test"
token = get_admin_token()

# 1. Config for auth-username-password-form
pwd_exec_id = "e8078558-32fb-4209-9606-d3535e75a3a9"
pwd_config = {
    "alias": "amr-pwd-config",
    "config": {
        "default.reference.value": "pwd"
    }
}
st_pwd, res_pwd = api_call(f"/admin/realms/{REALM}/authentication/executions/{pwd_exec_id}/config", method="POST", data=pwd_config, token=token)
print(f"Configure pwd execution: status={st_pwd}")

# 2. Config for auth-otp-form
otp_exec_id = "e4fd5475-e3d2-4532-92d9-40878f3afeb3"
otp_config = {
    "alias": "amr-otp-config",
    "config": {
        "default.reference.value": "otp"
    }
}
st_otp, res_otp = api_call(f"/admin/realms/{REALM}/authentication/executions/{otp_exec_id}/config", method="POST", data=otp_config, token=token)
print(f"Configure otp execution: status={st_otp}")
