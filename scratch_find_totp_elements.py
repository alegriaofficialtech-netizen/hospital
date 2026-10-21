import os, re, sys, urllib.parse, urllib.request, urllib.error
sys.path.insert(0, "/home/elcra/sandbox-jwt-validator")
from stage2_credentials import get_user_password
from test_stage2_real_tokens import PKCEAuthClient

os.environ["KEYCLOAK_BASE_URL"] = "https://127.0.0.1:8444/realms/hospital-lab-oidc-test"
os.environ["SSL_CERT_FILE"] = "/home/elcra/sandbox-jwt-validator/tls/ca.crt"

client = PKCEAuthClient()
pwd = get_user_password("medico.test")
verifier, challenge = client.generate_pkce()
auth_url = "https://127.0.0.1:8444/realms/hospital-lab-oidc-test/protocol/openid-connect/auth?" + urllib.parse.urlencode({
    "client_id": "clinical-poc-frontend-test",
    "response_type": "code",
    "redirect_uri": "http://127.0.0.1:8080/callback",
    "scope": "openid roles",
    "code_challenge": challenge,
    "code_challenge_method": "S256",
    "state": "s"
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

resp_page = client.normal_opener.open(urllib.request.Request(loc))
totp_html = resp_page.read().decode("utf-8")

m_manual = re.search(r'<a[^>]+href="([^"]+)"[^>]+id="mode-manual"', totp_html)
if not m_manual:
    m_manual = re.search(r'<a[^>]+id="mode-manual"[^>]+href="([^"]+)"', totp_html)

manual_url = m_manual.group(1).replace("&amp;", "&") if m_manual else None
print("Manual mode URL:", manual_url[:100] if manual_url else "Not found")

if manual_url:
    resp_man = client.normal_opener.open(urllib.request.Request(manual_url))
    man_html = resp_man.read().decode("utf-8")
    print("Manual HTML length:", len(man_html))
    m_key = re.search(r'id="kc-totp-secret-key">([^<]+)<', man_html)
    if m_key:
        print("Found kc-totp-secret-key in manual mode! Length:", len(m_key.group(1).strip()), "chars:", sorted(set(m_key.group(1).strip().replace(" ", "").upper())))
    else:
        print("kc-totp-secret-key not found in manual HTML")
