import re
# Print error or alert from HTML
with open("/home/elcra/sandbox-jwt-validator/scratch_test_totp_enrollment.py") as f:
    text = f.read()

# Add code to print error / alerts in body_final
addition = """
    if body_final:
        alerts = re.findall(r'<div[^>]+class="[^"]*(?:alert|feedback|error)[^"]*"[^>]*>(.*?)</div>', body_final, re.DOTALL)
        print("Alerts in body_final:", [re.sub(r'<[^>]+>', '', a).strip() for a in alerts])
        m_form = re.findall(r'<form[^>]+action="([^"]+)"[^>]*>', body_final)
        print("Forms in body_final:", len(m_form))
        for act in m_form:
            print("Form action:", act[:80])
"""
