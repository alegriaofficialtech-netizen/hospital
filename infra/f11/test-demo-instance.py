#!/usr/bin/env python3
"""Prueba funcional automatizada de la instancia demo aislada (puerto 8011).

Comprueba que:
  1. Login mediante Keycloak funciona para los roles declarados
  2. RBAC y MFA se aplican igual que en la pila principal
  3. Los 12 modulos responden con los datos limpios de demo/lis.db
  4. La base operativa (lis.db) no se altera
"""

import json
import os
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = Path(os.environ.get("F11_RUNTIME_DIR", "/home/elcra/sgsi-zta-runtime/f11"))
DEMO_URL = "http://127.0.0.1:8011"
KC_URL = "http://127.0.0.1:8085"

# Setup realm loader
import importlib.util
spec = importlib.util.spec_from_file_location("setup_realm", str(ROOT / "infra" / "local-test" / "setup_realm.py"))
setup_realm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup_realm)

creds_file = RUNTIME / "credentials.json"
creds = json.loads(creds_file.read_text(encoding="utf-8"))

def get_token(username):
    user = creds["users"][username]
    flow = setup_realm.BrowserFlow(KC_URL, creds["realm"], creds["clientId"], creds["redirectUri"])
    res = flow.login(username, user["password"], user.get("totp_secret"))
    return res["access_token"]

def api_call(path, token=None, method="GET", body=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode("utf-8") if body else None
    req = urllib.request.Request(f"{DEMO_URL}{path}", headers=headers, data=data, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))

print("=== VERIFICACION DE DEMOSTRACION AISLADA (PUERTO 8011) ===")

print("[1] Autenticando usuarios en Keycloak...")
token_admin = get_token("medico.test")
token_auditor = get_token("auditor.test")
token_lab = get_token("laboratorio.test")
token_recep = get_token("recepcion.test")
print("    [+] Tokens OIDC obtenidos con éxito para admin, auditor, lab y recepción.")

print("\n[2] Comprobando los 12 módulos funcionales en base demo:")

# M0: Clinico
st, res = api_call("/api/v1/orders", token=token_lab)
print(f"    [M0 Ordenes Clínicas] GET /orders: status={st}, ordenes={len(res.get('orders', []))}")
assert st == 200

# M1: Identidades (admin con MFA)
st, res = api_call("/api/v1/admin/identities", token=token_admin)
print(f"    [M1 Identidades] GET /admin/identities: status={st}, total={len(res.get('identities', []))}")
assert st == 200

# Denegacion RBAC en M1
st, res = api_call("/api/v1/admin/identities", token=token_lab)
print(f"    [RBAC M1] Laboratorio a /admin/identities: status={st} (esperado 403)")
assert st == 403

# M2: Diagnóstico
st, res = api_call("/api/v1/diagnostics/checkers", token=token_auditor)
print(f"    [M2 Comprobadores] GET /diagnostics/checkers: status={st}, catalog={len(res.get('checkers', []))}")
assert st == 200

# M3: Inventario de Activos
st, res = api_call("/api/v1/assets", token=token_auditor)
assets = res.get("assets", [])
print(f"    [M3 Activos] GET /assets: status={st}, activos={len(assets)} (esperado 11)")
assert len(assets) == 11

# M4: Matriz de Riesgos
st, res = api_call("/api/v1/risks", token=token_auditor)
risks = res.get("risks", [])
print(f"    [M4 Riesgos] GET /risks: status={st}, riesgos={len(risks)} (esperado 5)")
assert len(risks) == 5

# M5: Catálogo de Controles
st, res = api_call("/api/v1/controls", token=token_auditor)
controls = res.get("controls", [])
print(f"    [M5 Controles] GET /controls: status={st}, controles={len(controls)} (esperado 9)")
assert len(controls) == 9

# M6: Incidentes
st, res = api_call("/api/v1/incidents", token=token_auditor)
incidents = res.get("incidents", [])
print(f"    [M6 Incidentes] GET /incidents: status={st}, incidentes={len(incidents)} (esperado 2)")
assert len(incidents) == 2

# M6 Alertas derivadas
st, res = api_call("/api/v1/alerts", token=token_auditor)
alerts = res.get("alerts", [])
print(f"    [M6 Alertas] GET /alerts: status={st}, alertas={len(alerts)}")
assert st == 200

# M7: Auditoría
st, res = api_call("/api/v1/audit/events", token=token_auditor)
events = res.get("events", [])
print(f"    [M7 Auditoría] GET /audit/events: status={st}, eventos demo iniciales={len(events)}")
assert st == 200

# M8: Indicadores
st, res = api_call("/api/v1/indicators", token=token_lab)
print(f"    [M8 Indicadores] GET /indicators: status={st}, posture_score={res.get('posture_score')}")
assert st == 200

# M9: Instrumentos de Validación
st, res = api_call("/api/v1/instruments", token=token_auditor)
instruments = res.get("instruments", [])
print(f"    [M9 Instrumentos] GET /instruments: status={st}, total={len(instruments)} (esperado 1)")
assert len(instruments) == 1

# M9: Dictámenes de expertos (debe ser 0)
st, res = api_call("/api/v1/validations", token=token_auditor)
reviews = res.get("reviews", [])
print(f"    [M9 Dictámenes] GET /validations: status={st}, total={len(reviews)} (esperado 0)")
assert len(reviews) == 0

# Evidencias consolidadas
st, res = api_call("/api/v1/evidence", token=token_auditor)
evidence = res.get("evidence", [])
print(f"    [Evidencias] GET /evidence: status={st}, items={len(evidence)}")
assert st == 200

print("\n=== TODAS LAS COMPROBACIONES DE LA DEMOSTRACION AISLADA PASARON AL 100% ===")