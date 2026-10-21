#!/usr/bin/env python3
"""
Manejador de Proxy TLS Efímero en Espacio de Usuario para Pruebas OIDC / Keycloak
Proyecto: SGSI-ZTA Hospital Lab
Ubicación: /home/elcra/sandbox-jwt-validator/stage2_ephemeral_proxy.py
"""

import os
import sys
import time
import signal
import socket
import ssl
import json
import urllib.request
import urllib.error
import subprocess

SANDBOX_DIR = "/home/elcra/sandbox-jwt-validator"
TLS_DIR = os.path.join(SANDBOX_DIR, "tls")
NGINX_BIN = "/usr/sbin/nginx"
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8444
TARGET_PORT = 8085
REALM = "hospital-lab-oidc-test"

CA_KEY = os.path.join(TLS_DIR, "ca.key")
CA_CRT = os.path.join(TLS_DIR, "ca.crt")
SERVER_KEY = os.path.join(TLS_DIR, "server.key")
SERVER_CRT = os.path.join(TLS_DIR, "server.crt")
OPENSSL_CNF = os.path.join(TLS_DIR, "openssl.cnf")
NGINX_CONF = os.path.join(TLS_DIR, "nginx.conf")
PID_FILE = os.path.join(TLS_DIR, "nginx.pid")

def ensure_tls_certs():
    os.makedirs(TLS_DIR, mode=0o700, exist_ok=True)
    # Clear old certs to ensure fresh RFC 5280 compliant X509v3 extensions
    for f in [CA_KEY, CA_CRT, SERVER_KEY, SERVER_CRT]:
        if os.path.exists(f):
            try:
                os.remove(f)
            except OSError:
                pass

    cnf_content = """[req]
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
CN = 127.0.0.1

[ca_ext]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash

[server_ext]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
IP.1 = 127.0.0.1
DNS.1 = localhost
"""
    with open(OPENSSL_CNF, "w") as f:
        f.write(cnf_content)
    os.chmod(OPENSSL_CNF, 0o600)

    # 1. CA key & self-signed CA cert with CA:TRUE and keyCertSign
    subprocess.run(["openssl", "genrsa", "-out", CA_KEY, "2048"], check=True, capture_output=True)
    subprocess.run([
        "openssl", "req", "-x509", "-new", "-nodes", "-key", CA_KEY,
        "-sha256", "-days", "1", "-out", CA_CRT,
        "-subj", "/CN=ZeroTrust Local Test CA",
        "-config", OPENSSL_CNF, "-extensions", "ca_ext"
    ], check=True, capture_output=True)

    # 2. Server key & CSR
    subprocess.run(["openssl", "genrsa", "-out", SERVER_KEY, "2048"], check=True, capture_output=True)
    csr_file = os.path.join(TLS_DIR, "server.csr")
    subprocess.run([
        "openssl", "req", "-new", "-key", SERVER_KEY,
        "-out", csr_file, "-config", OPENSSL_CNF
    ], check=True, capture_output=True)

    # 3. Sign server cert with CA, including server_ext (SAN + serverAuth)
    subprocess.run([
        "openssl", "x509", "-req", "-in", csr_file,
        "-CA", CA_CRT, "-CAkey", CA_KEY, "-CAcreateserial",
        "-out", SERVER_CRT, "-days", "1", "-sha256",
        "-extfile", OPENSSL_CNF, "-extensions", "server_ext"
    ], check=True, capture_output=True)

    for fname in os.listdir(TLS_DIR):
        fpath = os.path.join(TLS_DIR, fname)
        if os.path.isfile(fpath):
            os.chmod(fpath, 0o600)

def write_nginx_conf():
    conf_content = f"""error_log {TLS_DIR}/nginx_error.log info;
pid {PID_FILE};
events {{
    worker_connections 64;
}}
http {{
    access_log {TLS_DIR}/nginx_access.log;
    client_body_temp_path {TLS_DIR}/client_body;
    proxy_temp_path {TLS_DIR}/proxy_temp;
    fastcgi_temp_path {TLS_DIR}/fastcgi_temp;
    uwsgi_temp_path {TLS_DIR}/uwsgi_temp;
    scgi_temp_path {TLS_DIR}/scgi_temp;

    server {{
        listen {PROXY_HOST}:{PROXY_PORT} ssl;
        server_name 127.0.0.1 localhost;

        ssl_certificate {SERVER_CRT};
        ssl_certificate_key {SERVER_KEY};
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;

        location / {{
            proxy_pass http://127.0.0.1:{TARGET_PORT};
            proxy_set_header Host $http_host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header X-Forwarded-Host $http_host;
            proxy_set_header X-Forwarded-Port $server_port;
            
            proxy_redirect off;
            proxy_buffering off;
        }}
    }}
}}
"""
    with open(NGINX_CONF, "w") as f:
        f.write(conf_content)
    os.chmod(NGINX_CONF, 0o600)

def is_port_listening(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        s.connect((host, port))
        s.close()
        return True
    except (socket.error, ConnectionRefusedError):
        return False

def verify_compatibility():
    """
    Verifica de forma estricta:
    1. TLS handshake con ca.crt (CERT_REQUIRED, check_hostname=True).
    2. OIDC discovery devuelve issuer y endpoints con https://127.0.0.1:8444.
    3. Solicitud de auth devuelve form action HTTPS y cookies con flag Secure.
    """
    ctx = ssl.create_default_context(cafile=CA_CRT)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    discovery_url = f"https://{PROXY_HOST}:{PROXY_PORT}/realms/{REALM}/.well-known/openid-configuration"
    req = urllib.request.Request(discovery_url)
    with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
        if resp.status != 200:
            raise RuntimeError(f"Discovery fallo con HTTP {resp.status}")
        data = json.loads(resp.read().decode("utf-8"))

    expected_iss = f"https://{PROXY_HOST}:{PROXY_PORT}/realms/{REALM}"
    actual_iss = data.get("issuer")
    if actual_iss != expected_iss:
        raise RuntimeError(f"Issuer no coincide: esperado '{expected_iss}', obtenido '{actual_iss}'")

    auth_endpoint = data.get("authorization_endpoint")
    if not auth_endpoint or not auth_endpoint.startswith(f"https://{PROXY_HOST}:{PROXY_PORT}/"):
        raise RuntimeError(f"Authorization endpoint invalido: {auth_endpoint}")

    test_auth_url = (
        f"{auth_endpoint}?client_id=clinical-poc-frontend-test&response_type=code"
        f"&redirect_uri=http://127.0.0.1:8080/callback&scope=openid"
        f"&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&state=chkstate"
    )
    req_auth = urllib.request.Request(test_auth_url)
    with urllib.request.urlopen(req_auth, context=ctx, timeout=5) as resp_auth:
        headers = resp_auth.headers
        cookies = headers.get_all("Set-Cookie") or []
        body = resp_auth.read().decode("utf-8")

    has_secure = any("Secure" in c for c in cookies)
    if not has_secure:
        raise RuntimeError("Keycloak no marco cookies con Secure flag a traves del proxy HTTPS.")

    if f"https://{PROXY_HOST}:{PROXY_PORT}/" not in body:
        raise RuntimeError("El formulario de login no contiene la URL HTTPS del proxy en su accion.")

    return True

def start_proxy():
    if is_port_listening(PROXY_HOST, PROXY_PORT):
        print(f"Error: Puerto {PROXY_PORT} ya esta en uso.")
        sys.exit(1)

    ensure_tls_certs()
    write_nginx_conf()

    # Test config
    res_t = subprocess.run([NGINX_BIN, "-t", "-c", NGINX_CONF], capture_output=True, text=True)
    if res_t.returncode != 0:
        print("Error en configuracion nginx:", res_t.stderr)
        sys.exit(1)

    # Start nginx
    res = subprocess.run([NGINX_BIN, "-c", NGINX_CONF], capture_output=True, text=True)
    if res.returncode != 0:
        print("Error al iniciar nginx:", res.stderr)
        sys.exit(1)

    # Wait for port
    ready = False
    for _ in range(20):
        if is_port_listening(PROXY_HOST, PROXY_PORT):
            ready = True
            break
        time.sleep(0.1)

    if not ready:
        print("Timeout esperando que nginx escuche en puerto", PROXY_PORT)
        stop_proxy()
        sys.exit(1)

    print(f"Proxy Nginx TLS activo en https://{PROXY_HOST}:{PROXY_PORT} -> http://127.0.0.1:{TARGET_PORT}")

    try:
        verify_compatibility()
        print("Verificacion de compatibilidad HTTPS y cookies Secure: APROBADA.")
    except Exception as e:
        print(f"FALLO DE COMPATIBILIDAD: {e}")
        stop_proxy()
        sys.exit(2)

def stop_proxy():
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE) as f:
                pid = int(f.read().strip())
            os.kill(pid, signal.SIGQUIT)
            time.sleep(0.2)
            if is_port_listening(PROXY_HOST, PROXY_PORT):
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.2)
        except ProcessLookupError:
            pass
        except Exception as e:
            print(f"Aviso al detener pid: {e}")

    # Ensure port is released
    for _ in range(20):
        if not is_port_listening(PROXY_HOST, PROXY_PORT):
            break
        time.sleep(0.1)

    if not is_port_listening(PROXY_HOST, PROXY_PORT):
        print(f"Proxy TLS en puerto {PROXY_PORT} detenido correctamente.")
    else:
        print(f"ADVERTENCIA: Puerto {PROXY_PORT} sigue escuchando.")

def status_proxy():
    listening = is_port_listening(PROXY_HOST, PROXY_PORT)
    pid_exists = os.path.exists(PID_FILE)
    pid = None
    if pid_exists:
        try:
            with open(PID_FILE) as f:
                pid = int(f.read().strip())
        except Exception:
            pass
    print(json.dumps({
        "listening": listening,
        "pid_exists": pid_exists,
        "pid": pid,
        "port": PROXY_PORT
    }))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: stage2_ephemeral_proxy.py [start|stop|status|verify]")
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "start":
        start_proxy()
    elif cmd == "stop":
        stop_proxy()
    elif cmd == "status":
        status_proxy()
    elif cmd == "verify":
        try:
            verify_compatibility()
            print("Verificacion OK")
        except Exception as e:
            print("Fallo:", e)
            sys.exit(1)
    else:
        print(f"Comando desconocido: {cmd}")
        sys.exit(1)
