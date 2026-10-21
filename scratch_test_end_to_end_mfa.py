import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import struct
import sys
import time
import urllib.parse
import urllib.request
import urllib.error

sys.path.insert(0, "/home/elcra/sandbox-jwt-validator")
from stage2_credentials import get_user_password
from test_stage2_real_tokens import PKCEAuthClient
from jwt_validator import (
    ZeroTrustJWTValidator,
    enforce_clinical_action,
    InsufficientPermissionsError,
    MFARequiredError
)

os.environ["KEYCLOAK_BASE_URL"] = "https://127.0.0.1:8444/realms/hospital-lab-oidc-test"
os.environ["SSL_CERT_FILE"] = "/home/elcra/sandbox-jwt-validator/tls/ca.crt"

DISCOVERY_URL = "https://127.0.0.1:8444/realms/hospital-lab-oidc-test/.well-known/openid-configuration"
AUDIENCE = "clinical-poc-api"
CLIENT_ID = "clinical-poc-frontend-test"

def generate_totp(secret_base32: str) -> str:
    secret = secret_base32.strip().replace(" ", "").upper()
    padding = '=' * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(secret + padding, casefold=True)
    counter = int(time.time()) // 30
    counter_bytes = struct.pack(">Q", counter)
    h = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    binary = struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF
    code = binary % 1000000
    return f"{code:06d}"

# 1. Medico login with password + OTP
client_med = PKCEAuthClient()
pwd_med = get_user_password("medico.test")

with open("/home/elcra/sandbox-jwt-validator/.env.medico_totp_seed") as f:
    med_seed = f.read().strip()

verifier_med, challenge_med = client_med.generate_pkce()
state_med = secrets.token_hex(16)
auth_url = "https://127.0.0.1:8444/realms/hospital-lab-oidc-test/protocol/openid-connect/auth?" + urllib.parse.urlencode({
    "client_id": CLIENT_ID,
    "response_type": "code",
    "redirect_uri": "http://127.0.0.1:8080/callback",
    "scope": "openid roles",
    "code_challenge": challenge_med,
    "code_challenge_method": "S256",
    "state": state_med
})

resp = client_med.normal_opener.open(urllib.request.Request(auth_url))
m_act = re.search(r'<form[^>]+action="([^"]+)"[^>]*>', resp.read().decode("utf-8"))
action_med = m_act.group(1).replace("&amp;", "&")

data_med = urllib.parse.urlencode({"username": "medico.test", "password": pwd_med, "credentialId": ""}).encode("utf-8")
req_login_med = urllib.request.Request(action_med, data=data_med, method="POST")
req_login_med.add_header("Content-Type", "application/x-www-form-urlencoded")

try:
    resp_l = client_med.post_opener.open(req_login_med)
    body_l = resp_l.read().decode("utf-8")
except urllib.error.HTTPError as e:
    body_l = e.read().decode("utf-8")

m_otp_act = re.search(r'<form[^>]+action="([^"]+)"[^>]*>', body_l)
otp_action = m_otp_act.group(1).replace("&amp;", "&")

otp_code = generate_totp(med_seed)
otp_data = urllib.parse.urlencode({"otp": otp_code, "login": "Sign In"}).encode("utf-8")
req_otp = urllib.request.Request(otp_action, data=otp_data, method="POST")
req_otp.add_header("Content-Type", "application/x-www-form-urlencoded")
try:
    resp_otp = client_med.post_opener.open(req_otp)
    loc_final = resp_otp.headers.get("Location")
except urllib.error.HTTPError as e:
    loc_final = e.headers.get("Location")

qs_med = urllib.parse.parse_qs(urllib.parse.urlparse(loc_final).query)
assert qs_med["state"][0] == state_med, "State mismatch"
code_med = qs_med["code"][0]

token_data_med = urllib.parse.urlencode({
    "client_id": CLIENT_ID,
    "grant_type": "authorization_code",
    "code": code_med,
    "redirect_uri": "http://127.0.0.1:8080/callback",
    "code_verifier": verifier_med
}).encode("utf-8")
req_tok_med = urllib.request.Request("https://127.0.0.1:8444/realms/hospital-lab-oidc-test/protocol/openid-connect/token", data=token_data_med, method="POST")
req_tok_med.add_header("Content-Type", "application/x-www-form-urlencoded")
with client_med.normal_opener.open(req_tok_med) as resp_tok_m:
    toks_med = json.loads(resp_tok_m.read().decode("utf-8"))

med_token = toks_med["access_token"]

# Validate real Keycloak token with ZeroTrustJWTValidator
validator = ZeroTrustJWTValidator(
    discovery_url=DISCOVERY_URL,
    expected_audience=AUDIENCE,
    expected_authorized_party=CLIENT_ID,
    require_bearer_type=True
)

ctx_med = validator.validate_token(med_token)
print("PASS: Token de medico validado exitosamente!")
print(f"  Usuario: {ctx_med.username}")
print(f"  Roles: {ctx_med.roles}")
print(f"  AMR: {ctx_med.amr}")
print(f"  MFA Verified: {ctx_med.mfa_verified}")

# Enforce VALIDATE_ORDER on medico
enforce_clinical_action(ctx_med, "VALIDATE_ORDER")
print("PASS: VALIDATE_ORDER autorizado para medico con MFA real!")

# 2. Validate admision token
client_adm = PKCEAuthClient()
pwd_adm = get_user_password("admision.test")
verifier_adm, challenge_adm = client_adm.generate_pkce()
state_adm = secrets.token_hex(16)
auth_url_adm = "https://127.0.0.1:8444/realms/hospital-lab-oidc-test/protocol/openid-connect/auth?" + urllib.parse.urlencode({
    "client_id": CLIENT_ID,
    "response_type": "code",
    "redirect_uri": "http://127.0.0.1:8080/callback",
    "scope": "openid roles",
    "code_challenge": challenge_adm,
    "code_challenge_method": "S256",
    "state": state_adm
})
resp_a = client_adm.normal_opener.open(urllib.request.Request(auth_url_adm))
m_act_a = re.search(r'<form[^>]+action="([^"]+)"[^>]*>', resp_a.read().decode("utf-8"))
data_a = urllib.parse.urlencode({"username": "admision.test", "password": pwd_adm, "credentialId": ""}).encode("utf-8")
req_a = urllib.request.Request(m_act_a.group(1).replace("&amp;", "&"), data=data_a, method="POST")
req_a.add_header("Content-Type", "application/x-www-form-urlencoded")
try:
    resp_la = client_adm.post_opener.open(req_a)
    loc_a = resp_la.headers.get("Location")
except urllib.error.HTTPError as e:
    loc_a = e.headers.get("Location")

qs_adm = urllib.parse.parse_qs(urllib.parse.urlparse(loc_a).query)
assert qs_adm["state"][0] == state_adm, "State mismatch"
code_adm = qs_adm["code"][0]

token_data_a = urllib.parse.urlencode({
    "client_id": CLIENT_ID,
    "grant_type": "authorization_code",
    "code": code_adm,
    "redirect_uri": "http://127.0.0.1:8080/callback",
    "code_verifier": verifier_adm
}).encode("utf-8")
req_tok_a = urllib.request.Request("https://127.0.0.1:8444/realms/hospital-lab-oidc-test/protocol/openid-connect/token", data=token_data_a, method="POST")
req_tok_a.add_header("Content-Type", "application/x-www-form-urlencoded")
with client_adm.normal_opener.open(req_tok_a) as resp_tok_a:
    toks_adm = json.loads(resp_tok_a.read().decode("utf-8"))

adm_token = toks_adm["access_token"]
ctx_adm = validator.validate_token(adm_token)
print("\nPASS: Token de admision validado exitosamente!")
print(f"  Usuario: {ctx_adm.username}")
print(f"  Roles: {ctx_adm.roles}")
print(f"  AMR: {ctx_adm.amr}")
print(f"  MFA Verified: {ctx_adm.mfa_verified}")

# Enforce actions on admision
enforce_clinical_action(ctx_adm, "CREATE_ORDER")
print("PASS: CREATE_ORDER autorizado para admision.")

try:
    enforce_clinical_action(ctx_adm, "VALIDATE_ORDER")
    print("FAIL: No debio autorizar VALIDATE_ORDER a admision!")
except InsufficientPermissionsError:
    print("PASS: VALIDATE_ORDER bloqueado para admision por falta de rol medico!")

# 3. Simulate doctor context without MFA
ctx_med_no_mfa = validator.validate_token(med_token)
# Forzar mfa_verified=False para probar denegacion de accion sensible en medico sin MFA
ctx_med_no_mfa.mfa_verified = False
try:
    enforce_clinical_action(ctx_med_no_mfa, "VALIDATE_ORDER")
    print("FAIL: No debio autorizar a medico sin MFA!")
except MFARequiredError:
    print("PASS: VALIDATE_ORDER bloqueado estrictamente por MFARequiredError cuando medico no tiene MFA!")
