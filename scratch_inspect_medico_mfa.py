import os
import re
import sys
import urllib.parse
import urllib.request
import urllib.error

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
    "state": "teststate"
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
    body = resp_login.read().decode("utf-8")
except urllib.error.HTTPError as e:
    loc = e.headers.get("Location")
    body = e.read().decode("utf-8")

print("Location header:", loc)
print("Body length:", len(body))

# If there was a redirect location, let's open it with normal_opener to see the next page!
if loc:
    print("Following redirect Location:", loc)
    resp_redirect = client.normal_opener.open(urllib.request.Request(loc))
    next_html = resp_redirect.read().decode("utf-8")
    print("Next page length:", len(next_html))
    forms = re.findall(r'<form[^>]*>.*?</form>', next_html, re.DOTALL)
    print("Next page forms count:", len(forms))
    for i, f in enumerate(forms):
        print(f"--- Form {i+1} ---")
        m_act = re.search(r'action="([^"]+)"', f)
        print("Action:", m_act.group(1) if m_act else "No action")
        inputs = re.findall(r'<input[^>]+>', f)
        for inp in inputs:
            t = re.search(r'type="([^"]+)"', inp)
            n = re.search(r'name="([^"]+)"', inp)
            print(f"  Input type={t.group(1) if t else '?'} name={n.group(1) if n else '?'}")
