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

client = PKCEAuthClient()
pwd = get_user_password("medico.test")

verifier, challenge = client.generate_pkce()
state = secrets.token_hex(16)
auth_url = "https://127.0.0.1:8444/realms/hospital-lab-oidc-test/protocol/openid-connect/auth?" + urllib.parse.urlencode({
    "client_id": "clinical-poc-frontend-test",
    "response_type": "code",
    "redirect_uri": "http://127.0.0.1:8080/callback",
    "scope": "openid roles",
    "code_challenge": challenge,
    "code_challenge_method": "S256",
    "state": state
})

resp = client.normal_opener.open(urllib.request.Request(auth_url))
html = resp.read().decode("utf-8")
m_action = re.search(r'<form[^>]+action="([^"]+)"[^>]*>', html)
action = m_action.group(1).replace("&amp;", "&")

data = urllib.parse.urlencode({"username": "medico.test", "password": pwd, "credentialId": ""}).encode("utf-8")
req_login = urllib.request.Request(action, data=data, method="POST")
req_login.add_header("Content-Type", "application/x-www-form-urlencoded")

try:
    resp_login = client.post_opener.open(req_login)
    loc = resp_login.headers.get("Location")
except urllib.error.HTTPError as e:
    loc = e.headers.get("Location")

print("1. Password submit redirect:", loc)

if loc and "CONFIGURE_TOTP" in loc:
    print("2. Opening CONFIGURE_TOTP page...")
    resp_totp_page = client.normal_opener.open(urllib.request.Request(loc))
    totp_html = resp_totp_page.read().decode("utf-8")
    
    m_manual = re.search(r'<a[^>]+href="([^"]+)"[^>]+id="mode-manual"', totp_html)
    if not m_manual:
        m_manual = re.search(r'<a[^>]+id="mode-manual"[^>]+href="([^"]+)"', totp_html)
    
    manual_url = m_manual.group(1).replace("&amp;", "&")
    print("3. Opening mode=manual URL...")
    resp_man = client.normal_opener.open(urllib.request.Request(manual_url))
    man_html = resp_man.read().decode("utf-8")
    
    m_key = re.search(r'id="kc-totp-secret-key">([^<]+)<', man_html)
    secret_b32 = m_key.group(1).replace(" ", "").strip().upper()
    print("Found Base32 secret! Length:", len(secret_b32))
    
    # Save seed securely for medico.test in sandbox with 0600 permissions
    seed_file = "/home/elcra/sandbox-jwt-validator/.env.medico_totp_seed"
    with open(seed_file, "w") as sf:
        sf.write(secret_b32)
    os.chmod(seed_file, 0o600)
    print("Saved seed securely to .env.medico_totp_seed (0600)")

    m_form_act = re.search(r'<form[^>]+action="([^"]+)"[^>]*>', man_html)
    totp_submit_action = m_form_act.group(1).replace("&amp;", "&")
    
    m_hidden = re.search(r'<input[^>]+name="totpSecret"[^>]+value="([^"]+)"', man_html)
    hidden_secret = m_hidden.group(1) if m_hidden else ""

    totp_code = generate_totp(secret_b32)
    print("Generated TOTP code:", len(totp_code), "digits")

    post_fields = {
        "totp": totp_code,
        "totpSecret": hidden_secret,
        "userLabel": "Medico TOTP Authenticator"
    }
    encoded_data = urllib.parse.urlencode(post_fields).encode("utf-8")
    req_totp = urllib.request.Request(totp_submit_action, data=encoded_data, method="POST")
    req_totp.add_header("Content-Type", "application/x-www-form-urlencoded")

    try:
        resp_post_totp = client.post_opener.open(req_totp)
        loc_code = resp_post_totp.headers.get("Location")
        body_code = resp_post_totp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        loc_code = e.headers.get("Location")
        body_code = e.read().decode("utf-8")

    print("4. Post-TOTP redirect Location:", loc_code)
    if not loc_code and body_code:
        alerts = re.findall(r'<div[^>]+class="[^"]*(?:alert|feedback|error)[^"]*"[^>]*>(.*?)</div>', body_code, re.DOTALL)
        print("Alerts if failed:", [re.sub(r'<[^>]+>', ' ', a).strip() for a in alerts])

    if loc_code and "code=" in loc_code:
        parsed = urllib.parse.urlparse(loc_code)
        qs = urllib.parse.parse_qs(parsed.query)
        auth_code = qs.get("code", [None])[0]
        returned_state = qs.get("state", [None])[0]
        print(f"PASS: Authorization code received! Length: {len(auth_code)}, state verified: {returned_state == state}")

        # Canje por token
        token_data = urllib.parse.urlencode({
            "client_id": "clinical-poc-frontend-test",
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": "http://127.0.0.1:8080/callback",
            "code_verifier": verifier
        }).encode("utf-8")
        req_token = urllib.request.Request("https://127.0.0.1:8444/realms/hospital-lab-oidc-test/protocol/openid-connect/token", data=token_data, method="POST")
        req_token.add_header("Content-Type", "application/x-www-form-urlencoded")

        with client.normal_opener.open(req_token) as resp_tok:
            tokens = json.loads(resp_tok.read().decode("utf-8"))

        print("5. Tokens received successfully! Token type:", tokens.get("token_type"))
        raw_access = tokens.get("access_token")
        payload_b64 = raw_access.split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "==").decode("utf-8"))
        print("Claims in Access Token:")
        for k in sorted(payload.keys()):
            if k in ("sub", "iss", "aud", "azp", "typ", "realm_access", "amr", "acr", "scope"):
                print(f"  - {k}: {payload[k]}")
