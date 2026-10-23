#!/usr/bin/env python3
# SGSI-ZTA Hospital Lab: Verificacion integral E2E sobre HTTPS Tailscale
import json, os, sys, time, urllib.request, urllib.parse, urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = Path(os.environ.get("F11_RUNTIME_DIR", "/home/elcra/sgsi-zta-runtime/f11"))
BASE = "https://servidor-1.tailb0f78a.ts.net:8443"

# Setup realm loader
import importlib.util
spec = importlib.util.spec_from_file_location("setup_realm", str(ROOT / "infra" / "local-test" / "setup_realm.py"))
setup_realm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup_realm)

creds_file = RUNTIME / "credentials.json"
creds = json.loads(creds_file.read_text(encoding="utf-8"))

def get_token(username):
    user = creds["users"][username]
    for attempt in range(3):
        try:
            flow = setup_realm.BrowserFlow(BASE, creds["realm"], creds["clientId"], f"{BASE}/")
            res = flow.login(username, user["password"], user.get("totp_secret"))
            return res["access_token"]
        except Exception as e:
            if attempt < 2:
                time.sleep(15)
            else:
                raise

def api_call(path, token=None, method="GET", body=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode("utf-8") if body else None
    req = urllib.request.Request(f"{BASE}{path}", headers=headers, data=data, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            return e.code, json.loads(body) if body else {}
        except Exception:
            return e.code, {"raw": body}

print("=== SGSI-ZTA HOSPITAL LAB: VERIFICACION E2E HTTPS PERMANENTE ===")
print(f"URL de entrada: {BASE}")

print("\n[1] Autenticando usuarios mediante Keycloak OIDC sobre HTTPS...")
token_admin = get_token("medico.test")
print("    [+] medico.test (con MFA TOTP): Token obtenido exitosamente.")
token_auditor = get_token("auditor.test")
print("    [+] auditor.test (Auditor SGSI): Token obtenido exitosamente.")
token_lab = get_token("laboratorio.test")
print("    [+] laboratorio.test (Tecnico Lab): Token obtenido exitosamente.")
token_recep = get_token("recepcion.test")
print("    [+] recepcion.test (Admision): Token obtenido exitosamente.")

print("\n[2] Verificacion de los 12 modulos funcionales a traves del Gateway HTTPS:")

# M0: Clinico
st, res = api_call("/api/v1/orders", token=token_lab)
print(f"    [M0 Ordenes Clinicas] GET /api/v1/orders: status={st}, ordenes={len(res.get('orders', []))}")
assert st == 200

# M1: Identidades
st, res = api_call("/api/v1/admin/identities", token=token_admin)
print(f"    [M1 Identidades] GET /api/v1/admin/identities: status={st}, total={len(res.get('identities', []))}")
assert st == 200

# RBAC M1
st, res = api_call("/api/v1/admin/identities", token=token_lab)
print(f"    [RBAC M1] Denegacion de laboratorio a identidades: status={st} (esperado 403)")
assert st == 403

# M2: Diagnostico
st, res = api_call("/api/v1/diagnostics/checkers", token=token_auditor)
print(f"    [M2 Comprobadores] GET /api/v1/diagnostics/checkers: status={st}, checkers={len(res.get('checkers', []))}")
assert st == 200

# M3: Activos
st, res = api_call("/api/v1/assets", token=token_admin)
print(f"    [M3 Activos] GET /api/v1/assets: status={st}, activos={len(res.get('assets', []))}")
assert st == 200

# M4: Riesgos
st, res = api_call("/api/v1/risks", token=token_admin)
print(f"    [M4 Riesgos] GET /api/v1/risks: status={st}, riesgos={len(res.get('risks', []))}")
assert st == 200

# M5: Controles
st, res = api_call("/api/v1/controls", token=token_admin)
print(f"    [M5 Controles] GET /api/v1/controls: status={st}, controles={len(res.get('controls', []))}")
assert st == 200

# M6: Incidentes
st, res = api_call("/api/v1/incidents", token=token_admin)
print(f"    [M6 Incidentes] GET /api/v1/incidents: status={st}, incidentes={len(res.get('incidents', []))}")
assert st == 200

# M6: Alertas
st, res = api_call("/api/v1/alerts", token=token_admin)
print(f"    [M6 Alertas] GET /api/v1/alerts: status={st}, alertas={len(res.get('alerts', []))}")
assert st == 200

# M7: Auditoria
st, res = api_call("/api/v1/audit/events", token=token_auditor)
print(f"    [M7 Auditoria] GET /api/v1/audit/events: status={st}, cadena valida={res.get('audit_chain_valid')}")
assert st == 200
assert res.get("audit_chain_valid") is True

# M8: Indicadores
st, res = api_call("/api/v1/indicators", token=token_auditor)
print(f"    [M8 Indicadores] GET /api/v1/indicators: status={st}, posture_score={res.get('posture_score')}")
assert st == 200

# M9: Instrumentos
st, res = api_call("/api/v1/instruments", token=token_admin)
print(f"    [M9 Instrumentos] GET /api/v1/instruments: status={st}, instrumentos={len(res.get('instruments', []))}")
assert st == 200

# M9: Dictamenes
st, res = api_call("/api/v1/validations", token=token_auditor)
print(f"    [M9 Dictamenes] GET /api/v1/validations: status={st}, dictamenes={len(res.get('validations', []))}")
assert st == 200

# Bloqueo de endpoints administrativos en Gateway
st, _ = api_call("/admin")
print(f"    [Seguridad Perimetral] Bloqueo de /admin en Gateway: status={st} (esperado 403)")
assert st == 403

print("\n=== TODAS LAS PRUEBAS E2E SOBRE HTTPS PERMANENTE PASARON AL 100% ===")
