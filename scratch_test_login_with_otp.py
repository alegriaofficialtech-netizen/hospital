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

os.environ["KEYCLOAK_BASE_URL"] = "https://127.0.0.1:8444/realms/hospital-lab-oidc-test"
os.environ["SSL_CERT_FILE"] = "/home/elcra/sandbox-jwt-validator/tls/ca.crt"

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

# 1. Login medico.test
client_med = PKCEAuthClient()
pwd_med = get_user_password("medico.test")

with open("/home/elcra/sandbox-jwt-validator/.env.medico_totp_seed") as f:
    med_seed = f.read().strip()

verifier, challenge = client_med.generate_pkce()
state_med = secrets.token_hex(16)
auth_url = "https://127.0.0.1:8444/realms/hospital-lab-oidc-test/protocol/openid-connect/auth?" + urllib.parse.urlencode({
    "client_id": "clinical-poc-frontend-test",
    "response_type": "code",
    "redirect_uri": "http://127.0.0.1:8080/callback",
    "scope": "openid roles",
    "code_challenge": challenge,
    "code_challenge_method": "S256",
    "state": state_med
})

resp = client_med.normal_opener.open(urllib.request.Request(auth_url))
html = resp.read().decode("utf-8")
m_action = re.search(r'<form[^>]+action="([^"]+)"[^>]*>', html)
action = m_action.group(1).replace("&amp;", "&")

data = urllib.parse.urlencode({"username": "medico.test", "password": pwd_med, "credentialId": ""}).encode("utf-8")
req_login = urllib.request.Request(action, data=data, method="POST")
req_login.add_header("Content-Type", "application/x-www-form-urlencoded")

try:
    resp_login = client_med.post_opener.open(req_login)
    loc = resp_login.headers.get("Location")
    body = resp_login.read().decode("utf-8")
except urllib.error.HTTPError as e:
    loc = e.headers.get("Location")
    body = e.read().decode("utf-8")

print("Medico Step 1: Password submit loc:", loc, "body length:", len(body))

# Check if there is an OTP form in body
otp_action = None
if body and "otp" in body.lower():
    m_otp_act = re.search(r'<form[^>]+action="([^"]+)"[^>]*>', body)
    if m_otp_act:
        otp_action = m_otp_act.group(1).replace("&amp;", "&")
        print("Found OTP form action in body:", otp_action[:80])
elif loc:
    resp_otp_page = client_med.normal_opener.open(urllib.request.Request(loc))
    otp_html = resp_otp_page.read().decode("utf-8")
    m_otp_act = re.search(r'<form[^>]+action="([^"]+)"[^>]*>', otp_html)
    if m_otp_act:
        otp_action = m_otp_act.group(1).replace("&amp;", "&")
        print("Found OTP form action via redirect:", otp_action[:80])

if otp_action:
    otp_code = generate_totp(med_seed)
    print("Submitting OTP code:", len(otp_code), "digits...")
    otp_data = urllib.parse.urlencode({"otp": otp_code, "login": "Sign In"}).encode("utf-8")
    req_otp = urllib.request.Request(otp_action, data=otp_data, method="POST")
    req_otp.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        resp_otp = client_med.post_opener.open(req_otp)
        loc_final = resp_otp.headers.get("Location")
    except urllib.error.HTTPError as e:
        loc_final = e.headers.get("Location")
    print("Medico Step 2: Post-OTP redirect:", loc_final)

    if loc_final and "code=" in loc_final:
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(loc_final).query)
        code = qs["code"][0]
        token_data = urllib.parse.urlencode({
            "client_id": "clinical-poc-frontend-test",
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://127.0.0.1:8080/callback",
            "code_verifier": verifier
        }).encode("utf-8")
        req_token = urllib.request.Request("https://127.0.0.1:8444/realms/hospital-lab-oidc-test/protocol/openid-connect/token", data=token_data, method="POST")
        req_token.add_header("Content-Type", "application/x-www-form-urlencoded")
        with client_med.normal_opener.open(req_token) as resp_tok:
            tokens = json.loads(resp_tok.read().decode("utf-8"))
        raw_access = tokens.get("access_token")
        payload = json.loads(base64.urlsafe_b64decode(raw_access.split(".")[1] + "==").decode("utf-8"))
        print("\n=== Medico Access Token Claims ===")
        for k in sorted(payload.keys()):
            if k in ("sub", "iss", "aud", "azp", "typ", "realm_access", "amr", "acr", "scope"):
                print(f"  {k}: {payload[k]}")

# 2. Login admision.test
client_adm = PKCEAuthClient()
pwd_adm = get_user_password("admision.test")
res_adm = client_adm.execute_login("admision.test", pwd_adm)
print("\n=== Admision Login Result ===", res_adm.get("status"))

# Get raw token of admision to check claims
verifier_adm, challenge_adm = client_adm.generate_pkce()
auth_url_adm = "https://127.0.0.1:8444/realms/hospital-lab-oidc-test/protocol/openid-connect/auth?" + urllib.parse.urlencode({
    "client_id": "clinical-poc-frontend-test",
    "response_type": "code",
    "redirect_uri": "http://127.0.0.1:8080/callback",
    "scope": "openid roles",
    "code_challenge": challenge_adm,
    "code_challenge_method": "S256",
    "state": "s_adm"
})
resp_a = client_adm.normal_opener.open(urllib.request.Request(auth_url_adm))
m_act = re.search(r'<form[^>]+action="([^"]+)"[^>]*>', resp_a.read().decode("utf-8"))
data_a = urllib.parse.urlencode({"username": "admision.test", "password": pwd_adm, "credentialId": ""}).encode("utf-8")
req_a = urllib.request.Request(m_act.group(1).replace("&amp;", "&"), data=data_a, method="POST")
req_a.add_header("Content-Type", "application/x-www-form-urlencoded")
try:
    resp_l = client_adm.post_opener.open(req_a)
    loc_a = resp_l.headers.get("Location")
except urllib.error.HTTPError as e:
    loc_a = e.headers.get("Location")

qs_a = urllib.parse.parse_qs(urllib.parse.urlparse(loc_a).query)
code_a = qs_a["code"][0]
token_data_a = urllib.parse.urlencode({
    "client_id": "clinical-poc-frontend-test",
    "grant_type": "authorization_code",
    "code": code_a,
    "redirect_uri": "http://127.0.0.1:8080/callback",
    "code_verifier": verifier_adm
}).encode("utf-8")
req_tok_a = urllib.request.Request("https://127.0.0.1:8444/realms/hospital-lab-oidc-test/protocol/openid-connect/token", data=token_data_a, method="POST")
req_tok_a.add_header("Content-Type", "application/x-www-form-urlencoded")
with client_adm.normal_opener.open(req_tok_a) as resp_tok_a:
    tokens_a = json.loads(resp_tok_a.read().decode("utf-8"))
payload_a = json.loads(base64.urlsafe_b64decode(tokens_a.get("access_token").split(".")[1] + "==").decode("utf-8"))
print("\n=== Admision Access Token Claims ===")
for k in sorted(payload_a.keys()):
    if k in ("sub", "iss", "aud", "azp", "typ", "realm_access", "amr", "acr", "scope"):
        print(f"  {k}: {payload_a[k]}")
