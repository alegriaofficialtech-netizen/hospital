#!/usr/bin/env python3
"""
Clinical Audit Monitor — Migración Zero Trust (OAuth 2.0 Client Credentials)
SGSI-ZTA Hospital Lab — ISO/IEC 27001:2022 Control A.8.15 & NIST SP 800-207

Servicio automatizado M2M para verificación criptográfica continua de la
cadena de auditoría del LIS y detección de anomalías de seguridad.
"""

import hashlib
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

AUDIT_URL = os.environ.get("AUDIT_URL", "http://127.0.0.1:8000/api/v1/audit/events")
LOGIN_URL = os.environ.get("LOGIN_URL", "http://127.0.0.1:8000/api/v1/auth/login")
CA_CERT_PATH = os.environ.get("SSL_CERT_FILE", "/home/elcra/sandbox-jwt-validator/tls/ca.crt")

# Credenciales OIDC Client Credentials (M2M) - Extraídas exclusivamente de entorno o almacenamiento protegido
CLIENT_ID = os.environ.get("AUDIT_MONITOR_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("AUDIT_MONITOR_CLIENT_SECRET", "")
TOKEN_URL = os.environ.get("AUDIT_MONITOR_TOKEN_URL", "")

# Credenciales legacy para modo de transición (Sin contraseñas por defecto)
AUDITOR_USER = os.environ.get("AUDITOR_USER", "")
AUDITOR_PASS = os.environ.get("AUDITOR_PASS", "")
USE_LEGACY_AUTH = os.environ.get("AUDIT_MONITOR_USE_LEGACY", "0") == "1"

# Cache de token en memoria (evita solicitar token en cada ciclo de 30s)
_CACHED_TOKEN: Optional[str] = None
_TOKEN_EXPIRES_AT: float = 0.0


def load_credentials_from_file(file_path: str = "/home/elcra/sandbox-jwt-validator/.env.audit_monitor_credentials") -> None:
    """Carga credenciales desde archivo seguro con permisos 0600 si no están en variables de entorno."""
    global CLIENT_ID, CLIENT_SECRET, TOKEN_URL
    if CLIENT_ID and CLIENT_SECRET and TOKEN_URL:
        return
    if os.path.exists(file_path):
        try:
            stat_info = os.stat(file_path)
            mode = stat_info.st_mode & 0o777
            if mode & 0o077:
                print(f"[WARN] Archivo de credenciales {file_path} tiene permisos inseguros ({oct(mode)}). Debe ser 0600.")
        except Exception:
            pass

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if "=" in line and not line.startswith("#"):
                        k, v = line.split("=", 1)
                        if k == "AUDIT_MONITOR_CLIENT_ID" and not CLIENT_ID:
                            CLIENT_ID = v
                        elif k == "AUDIT_MONITOR_CLIENT_SECRET" and not CLIENT_SECRET:
                            CLIENT_SECRET = v
                        elif k == "AUDIT_MONITOR_TOKEN_URL" and not TOKEN_URL:
                            TOKEN_URL = v
        except Exception as e:
            print(f"[WARN] No se pudo leer archivo de credenciales {file_path}: {e}")


def get_ssl_context() -> Optional[ssl.SSLContext]:
    """Crea contexto SSL seguro con CA local si el endpoint es HTTPS."""
    if os.path.exists(CA_CERT_PATH):
        ctx = ssl.create_default_context(cafile=CA_CERT_PATH)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx
    return None


def get_oauth_token() -> Optional[str]:
    """
    Obtiene Access Token OIDC RS256 mediante OAuth 2.0 Client Credentials Grant (RFC 6749 §4.4).
    Reutiliza el token en memoria si aún es válido (buffer de 30 segundos).
    """
    global _CACHED_TOKEN, _TOKEN_EXPIRES_AT
    now = time.time()
    if _CACHED_TOKEN and now < (_TOKEN_EXPIRES_AT - 30):
        return _CACHED_TOKEN

    load_credentials_from_file()
    if not CLIENT_ID or not CLIENT_SECRET or not TOKEN_URL:
        return None

    data = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }).encode("utf-8")

    ctx = get_ssl_context() if TOKEN_URL.startswith("https://") else None
    req = urllib.request.Request(TOKEN_URL, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as res:
            payload = json.loads(res.read().decode("utf-8"))
            _CACHED_TOKEN = payload.get("access_token")
            expires_in = payload.get("expires_in", 300)
            _TOKEN_EXPIRES_AT = now + float(expires_in)
            return _CACHED_TOKEN
    except Exception as e:
        print(f"[-] Error al obtener token OAuth 2.0 Client Credentials: {e}")
        return None


def get_legacy_token() -> Optional[str]:
    """
    Modo de transición temporal: obtiene token legacy exclusivamente si AUDITOR_USER y
    AUDITOR_PASS están provistos externamente en variables de entorno y el servidor tiene
    habilitado el fallback.
    """
    if not AUDITOR_USER or not AUDITOR_PASS:
        print("[-] Error: Credenciales legacy no configuradas en el entorno (AUDITOR_USER / AUDITOR_PASS ausentes).")
        return None

    payload = json.dumps({"username": AUDITOR_USER, "password": AUDITOR_PASS}).encode("utf-8")
    req = urllib.request.Request(LOGIN_URL, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as res:
            warning = res.headers.get("Warning")
            if warning:
                print(f"[!] AVISO DE DEPRECACIÓN DEL SERVIDOR: {warning}")
            data = json.loads(res.read().decode("utf-8"))
            return data.get("token")
    except urllib.error.HTTPError as e:
        if e.code == 410:
            print("[-] HTTP 410 Gone: La autenticación legacy fue deshabilitada definitivamente en el LIS.")
        elif e.code == 403:
            print("[-] HTTP 403 Forbidden: El acceso legacy está estrictamente prohibido para roles clínicos.")
        else:
            print(f"[-] Error al autenticar auditor vía endpoint legacy (HTTP {e.code})")
        return None
    except Exception as e:
        print(f"[-] Error de conexión con login legacy: {e}")
        return None


def get_auditor_token() -> Optional[str]:
    """
    Estrategia estricta de resolución de credenciales:
    - Si USE_LEGACY_AUTH es False (modo estándar): utiliza EXCLUSIVAMENTE OAuth 2.0 Client Credentials.
      Si OAuth falla, devuelve None de inmediato (Fail-Closed). NUNCA intenta automáticamente el login legacy.
    - Si USE_LEGACY_AUTH es True (modo temporal de transición explícito): utiliza get_legacy_token().
    - No registra tokens ni secretos en logs o salidas estándar.
    """
    if not USE_LEGACY_AUTH:
        token = get_oauth_token()
        if not token:
            print("[-] Error: Fallo de autenticación OAuth 2.0 Client Credentials (Fail-Closed, sin fallback automático).")
        return token

    return get_legacy_token()


def verify_audit_chain(events: List[Dict[str, Any]]) -> bool:
    """Verifica criptográficamente que la cadena de hashes de auditoría no ha sido manipulada."""
    if not events:
        # Una lista vacía no es una cadena válida: puede ser un borrado total.
        print("[!] ALERTA CRÍTICA: la cadena de auditoría está vacía (posible borrado o truncado).")
        return False

    expected_prev = "0" * 64
    for idx, event in enumerate(events):
        curr_hash = event.get("hash")
        prev_hash = event.get("prev_hash")

        if prev_hash != expected_prev:
            print(f"[!] ALERTA CRÍTICA: Ruptura de cadena en evento #{idx}! Esperado: {expected_prev}, Encontrado: {prev_hash}")
            return False

        record_copy = {k: v for k, v in event.items() if k != "hash"}
        computed_hash = hashlib.sha256(json.dumps(record_copy, sort_keys=True).encode("utf-8")).hexdigest()
        if computed_hash != curr_hash:
            print(f"[!] ALERTA CRÍTICA: Hash manipulado en evento #{idx}!")
            return False

        expected_prev = curr_hash

    return True


def check_security_anomalies(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Identifica accesos denegados, intentos de elusión o violaciones de política."""
    anomalies = []
    for ev in events:
        status = ev.get("status", "")
        if "DENIED" in status or status == "FAILED" or "BLOCKED" in status:
            anomalies.append(ev)
    return anomalies


def run_audit_cycle(custom_audit_url: Optional[str] = None) -> Dict[str, Any]:
    """Ejecuta un ciclo completo de auditoría e inspección criptográfica."""
    target_url = custom_audit_url or AUDIT_URL
    token = get_auditor_token()
    if not token:
        print("[-] Ciclo abortado: No se dispone de credencial válida para el auditor.")
        return {"status": "AUTH_FAILED", "events_count": 0, "chain_valid": False, "anomalies": []}

    req = urllib.request.Request(target_url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=10) as res:
            data = json.loads(res.read().decode("utf-8"))
            events = data.get("events", [])

            # La verificación local no basta: el chequeo de checkpoint del servidor
            # también debe declarar la cadena íntegra (fail-closed si falta).
            server_verdict = data.get("audit_chain_valid") is True
            is_intact = verify_audit_chain(events) and server_verdict
            anomalies = check_security_anomalies(events)

            print(f"[*] CLINICAL AUDIT MONITOR: {len(events)} eventos verificados.")
            print(f"[*] Cadena Criptográfica: {'INTACTA' if is_intact else 'COMPROMETIDA'}")
            print(f"[*] Anomalías Detectadas: {len(anomalies)}")

            return {
                "status": "SUCCESS",
                "events_count": len(events),
                "chain_valid": is_intact,
                "anomalies": anomalies,
            }
    except Exception as e:
        print(f"[-] Error al consultar eventos de auditoría en {target_url}: {e}")
        return {"status": "REQUEST_ERROR", "error": str(e), "events_count": 0, "chain_valid": False, "anomalies": []}


def audit_exit_code(result: Dict[str, Any]) -> int:
    """
    Código de salida para el bucle de supervisión (A-04).

    Devuelve 0 solo si el ciclo terminó correctamente y la cadena se reportó
    íntegra; cualquier otro caso debe marcar el servicio como no saludable.
    """
    return 0 if result.get("status") == "SUCCESS" and result.get("chain_valid") is True else 1


if __name__ == "__main__":
    sys.exit(audit_exit_code(run_audit_cycle()))
