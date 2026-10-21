import json, sys
sys.path.insert(0, "/home/elcra/sandbox-jwt-validator")
from stage2_setup_realm import get_admin_token, api_call

REALM = "hospital-lab-oidc-test"
token = get_admin_token()

status, execs = api_call(f"/admin/realms/{REALM}/authentication/flows/hospital-test-browser/executions", token=token)
print(f"Executions in hospital-test-browser ({len(execs)}):")
for ex in execs:
    print(f"  ID: {ex.get('id')} | Display: {ex.get('displayName')} | Provider: {ex.get('providerId')} | Requirement: {ex.get('requirement')} | Config: {ex.get('authenticationConfig')}")

status, execs_forms = api_call(f"/admin/realms/{REALM}/authentication/flows/hospital-test-forms/executions", token=token)
print(f"\nExecutions in hospital-test-forms ({len(execs_forms)}):")
for ex in execs_forms:
    print(f"  ID: {ex.get('id')} | Display: {ex.get('displayName')} | Provider: {ex.get('providerId')} | Requirement: {ex.get('requirement')} | Config: {ex.get('authenticationConfig')}")

status, execs_mfa = api_call(f"/admin/realms/{REALM}/authentication/flows/hospital-test-conditional-mfa/executions", token=token)
print(f"\nExecutions in hospital-test-conditional-mfa ({len(execs_mfa)}):")
for ex in execs_mfa:
    print(f"  ID: {ex.get('id')} | Display: {ex.get('displayName')} | Provider: {ex.get('providerId')} | Requirement: {ex.get('requirement')} | Config: {ex.get('authenticationConfig')}")
