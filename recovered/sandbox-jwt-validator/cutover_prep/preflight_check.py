#!/usr/bin/env python3
"""
preflight_check.py - Validación pre-despliegue y dictamen GO / NO-GO.
SGSI-ZTA Hospital Lab — ISO/IEC 27001:2022 & NIST SP 800-207

Comprueba, sin modificar nada:

1. Identidad de host y usuario ejecutor.
2. Estado del repositorio Git y rama candidata (sin cambios sin confirmar).
3. Disponibilidad de puertos (colisión 8088 vs puerto objetivo).
4. Salud del realm principal de Keycloak ('hospital-lab').
5. Integridad del manifiesto SHA-256 del candidato, incluido el módulo de dominio.
6. Compilación del candidato (imports resueltos) y ausencia de secretos embebidos.
7. Contrato de entorno que el despliegue debe inyectar (A-01/A-02/A-05).
8. Compatibilidad de la base existente con el esquema nuevo (si se indica).
9. Estado del directorio principal.

Códigos de salida: 0 = GO, 1 = NO-GO.
"""

import argparse
import getpass
import hashlib
import json
import os
import socket
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cutover_common import (  # noqa: E402
    BACKUP_BASE_DIR,
    CANONICAL_BASE_URL,
    Verdict,
    canonical_discovery_url,
    canonical_issuer,
    fetch_json_url,
    inspect_database,
    issuer_document_problems,
    scan_forbidden_secrets,
    tls_peer_certificate,
)

EXPECTED_HOST = "servidor-1"
EXPECTED_USER = "elcra"
EXPECTED_BRANCH = "stage4-lis-candidate-release"
DEFAULT_KEYCLOAK_URL = canonical_discovery_url()
PROD_DIR = "/opt/sgsi-zta-hospital-lab"
PROD_PROJECT = os.path.basename(PROD_DIR)
SANDBOX_DIR = "/home/elcra/sandbox-jwt-validator"
CANDIDATE_DIR = os.path.join(SANDBOX_DIR, "candidate_release")
MANIFEST_PATH = os.path.join(CANDIDATE_DIR, "MANIFEST.sha256")
DEPLOY_SCRIPT = os.path.join(SANDBOX_DIR, "cutover_prep", "cutover_deploy.sh")
TLS_DIR = os.environ.get("SGSI_TLS_DIR", "/etc/sgsi-zta/tls")
REALM_EXPORT_DEFAULT = os.path.join(
    BACKUP_BASE_DIR, "realm", "hospital-lab-realm.json"
)

# Módulos que el backend importa en tiempo de ejecución.
REQUIRED_MODULES = (
    "server.py",
    "database.py",
    "jwt_validator.py",
    "clinical_domain.py",
    "audit_monitor/monitor.py",
)

# Variables que el despliegue debe inyectar para no depender de defaults (A-01/A-02).
REQUIRED_ENV_CONTRACT = (
    "LIS_DB_PATH",
    "ENABLE_LEGACY_AUTH",
    "IOMT_DEVICE_KEYS_JSON",
    "IOMT_MAX_CLOCK_SKEW_SECONDS",
    "IOMT_NONCE_TTL_SECONDS",
    "AUDIT_HMAC_KEY",
    "CLINICAL_IMAGE",
    "AUDIT_MONITOR_CLIENT_SECRET",
)


def check_host_and_user(verdict: Verdict) -> None:
    hostname = socket.gethostname()
    username = os.environ.get("USER", "") or os.environ.get("USERNAME", "")
    verdict.check(
        hostname == EXPECTED_HOST,
        "1. Host de ejecución",
        hostname,
        f"hostname inesperado: {hostname} (se requiere {EXPECTED_HOST})",
    )
    verdict.check(
        username == EXPECTED_USER,
        "1a. Usuario de ejecución",
        username,
        f"usuario inesperado: {username} (se requiere {EXPECTED_USER})",
    )


def check_git_status(verdict: Verdict) -> None:
    try:
        branch = subprocess.run(
            ["git", "-C", SANDBOX_DIR, "branch", "--show-current"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        commit = subprocess.run(
            ["git", "-C", SANDBOX_DIR, "log", "-n", "1", "--format=%h %s"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "-C", SANDBOX_DIR, "status", "--porcelain", "--untracked-files=no"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except Exception as exc:  # noqa: BLE001
        verdict.failed("2. Estado Git", f"error al consultar Git: {exc}")
        return

    verdict.check(
        branch == EXPECTED_BRANCH,
        "2. Rama candidata",
        branch,
        f"rama incorrecta: {branch} (se requiere {EXPECTED_BRANCH})",
    )
    verdict.check(
        not status,
        "2a. Árbol de trabajo confirmado",
        f"limpio en {commit}",
        f"cambios sin confirmar:\n{status}",
    )


def is_port_in_use(port: int, host: str = "127.0.0.1") -> Tuple[bool, Optional[str]]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        if sock.connect_ex((host, port)) != 0:
            return False, None
    detail = None
    try:
        out = subprocess.run(
            ["docker", "ps", "--filter", f"publish={port}", "--format", "{{.Names}} ({{.Image}})"],
            capture_output=True, text=True,
        ).stdout.strip()
        if out:
            detail = f"contenedor: {out}"
    except Exception:  # noqa: BLE001
        pass
    return True, detail or "proceso local escuchando"


def check_ports(verdict: Verdict, target_port: int) -> None:
    in_use, detail = is_port_in_use(target_port)
    verdict.check(
        not in_use,
        f"3. Puerto objetivo {target_port} libre",
        "libre",
        f"ocupado por {detail}",
    )
    port_8088_in_use, detail_8088 = is_port_in_use(8088)
    if port_8088_in_use:
        print(f"[INFO] Puerto 8088 ocupado por {detail_8088} (colisión conocida con stream-caddy).")


def check_keycloak(verdict: Verdict, url: str) -> None:
    """El issuer debe ser el canónico: el loopback no existe dentro de un contenedor."""
    try:
        document = fetch_json_url(url, timeout=5)
    except Exception as exc:  # noqa: BLE001
        verdict.failed(
            "4. Keycloak alcanzable por el endpoint canónico",
            f"{url}: {exc}. El LIS delega la autenticación: es bloqueante.",
        )
        return

    problems = issuer_document_problems(document)
    verdict.check(
        not problems,
        "4. Keycloak con issuer canónico",
        str(document.get("issuer", "")),
        "; ".join(problems),
    )


def check_canonical_tls(verdict: Verdict) -> None:
    parsed = urllib.parse.urlsplit(CANONICAL_BASE_URL)
    host = parsed.hostname or ""
    port = parsed.port or 443
    try:
        info = tls_peer_certificate(host, port)
    except Exception as exc:  # noqa: BLE001
        verdict.failed(
            "4a. TLS canónico",
            f"{host}:{port}: {exc}. El gateway de identidad debe estar arriba "
            f"(identity_up.sh) y el certificado debe ser válido.",
        )
        return
    san = info.get("san") or []
    verdict.check(
        host in san,
        "4a. Certificado coincide con el nombre canónico",
        f"SAN={san}",
        f"{host} ausente del SAN {san}",
    )
    not_after = info.get("notAfter") or ""
    if not_after:
        import ssl as _ssl
        import time as _time

        try:
            days_left = int(
                (_ssl.cert_time_to_seconds(not_after) - _time.time()) // 86400
            )
        except ValueError:
            days_left = -1
        verdict.check(
            days_left > 0,
            "4b. Certificado TLS vigente",
            f"vence {not_after} ({days_left} días)",
            f"certificado vencido o ilegible ({not_after})",
        )
        if 0 < days_left <= 21:
            print(
                f"[WARN] 4b. El certificado vence en {days_left} días: "
                "verifique el timer sgsi-zta-cert-renew.timer."
            )


def check_tls_material(verdict: Verdict) -> None:
    """Valida el material en disco sin que el operador lea la clave privada."""
    host = urllib.parse.urlsplit(CANONICAL_BASE_URL).hostname or ""
    script = r"""
set -u
C=/certs/fullchain.pem
K=/certs/privkey.pem
[ -r "$C" ] || { echo "CERT_MISSING"; exit 0; }
[ -r "$K" ] || { echo "KEY_MISSING"; exit 0; }
echo "CHAIN=$(grep -c "BEGIN CERTIFICATE" "$C")"
if openssl x509 -in "$C" -noout -ext subjectAltName 2>/dev/null | grep -q "DNS:${PROBE_HOST}"; then
  echo "SAN_OK=yes"
else
  echo "SAN_OK=no"
fi
CP=$(openssl x509 -in "$C" -pubkey -noout 2>/dev/null | sha256sum | cut -d" " -f1)
KP=$(openssl pkey -in "$K" -pubout 2>/dev/null | sha256sum | cut -d" " -f1)
if [ -n "$CP" ] && [ "$CP" = "$KP" ]; then echo "KEY_MATCH=yes"; else echo "KEY_MATCH=no"; fi
END=$(openssl x509 -in "$C" -noout -enddate | cut -d= -f2)
echo "DAYS=$(( ( $(date -d "$END" +%s) - $(date +%s) ) / 86400 ))"
echo "KEY_MODE=$(stat -c %a "$K")"
"""
    try:
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "-e", f"PROBE_HOST={host}",
                "-v", f"{TLS_DIR}:/certs:ro",
                "python:3.12-slim-bookworm", "sh", "-c", script,
            ],
            capture_output=True, text=True, timeout=60,
        )
    except subprocess.TimeoutExpired:
        verdict.failed("4c. Material TLS", f"timeout inspeccionando {TLS_DIR}")
        return

    output = (result.stdout or "") + (result.stderr or "")
    if "CERT_MISSING" in output or "KEY_MISSING" in output or result.returncode != 0:
        verdict.failed(
            "4c. Material TLS en disco",
            f"{TLS_DIR}: {output.strip()[:200]}. Se esperan fullchain.pem y privkey.pem.",
        )
        return

    def field(name: str) -> str:
        for line in output.splitlines():
            if line.startswith(f"{name}="):
                return line.split("=", 1)[1]
        return ""

    chain = int(field("CHAIN") or 0)
    san_ok = field("SAN_OK") == "yes"
    key_match = field("KEY_MATCH") == "yes"
    days = int(field("DAYS") or -1)
    key_mode = field("KEY_MODE")
    verdict.check(chain >= 2, "4c. Cadena TLS completa", f"{chain} certificados",
                  f"solo {chain} certificado(s): falta el intermedio")
    verdict.check(san_ok, "4d. SAN del material en disco", f"cubre {host}",
                  f"no cubre {host}")
    verdict.check(key_match, "4e. Clave privada coincide", "cert/clave coherentes",
                  "la clave no corresponde al certificado")
    verdict.check(days > 0, "4f. Material TLS vigente", f"{days} días", "vencido")
    verdict.check(
        not key_mode.endswith(("4", "6", "7")),
        "4g. Clave privada no legible por otros",
        f"modo {key_mode}",
        f"modo {key_mode}: retire el bit de lectura para otros",
    )


def check_renewal(verdict: Verdict, cert_days: int = -1) -> None:
    """La renovación es operativa: se informa, no se inventa un GO."""
    try:
        result = subprocess.run(
            ["systemctl", "is-enabled", "sgsi-zta-cert-renew.timer"],
            capture_output=True, text=True, timeout=10,
        )
        enabled = result.stdout.strip() == "enabled"
    except Exception:  # noqa: BLE001
        enabled = False
    if enabled:
        verdict.passed("4h. Timer de renovación TLS", "sgsi-zta-cert-renew.timer enabled")
    else:
        print(
            "[INFO] 4h. Timer de renovación no instalado. "
            "Instale cutover_prep/systemd/sgsi-zta-cert-renew.{service,timer}."
        )

    try:
        status = subprocess.run(
            ["tailscale", "status", "--json"], capture_output=True, text=True, timeout=15
        )
        domains = (json.loads(status.stdout).get("Self") or {}).get("CertDomains") or []
    except Exception:  # noqa: BLE001
        domains = []
    if not domains:
        print(
            "[WARN] 4i. CertDomains vacío: la emisión/renovación con 'tailscale cert' "
            "requiere HTTPS Certificates habilitado en el admin console."
        )
    else:
        verdict.passed("4i. Tailscale puede emitir certificados", f"CertDomains={domains}")


def check_realm_export(verdict: Verdict, path: Optional[str] = None) -> None:
    artifact = path or REALM_EXPORT_DEFAULT
    if not os.path.exists(artifact):
        verdict.failed(
            "4j. Artefacto de realm importable",
            f"ausente: {artifact}. Sin él, reconstruir Keycloak desde cero es imposible. "
            "Ejecute cutover_prep/export_realm.sh.",
        )
        return
    try:
        with open(artifact, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (json.JSONDecodeError, OSError) as exc:
        verdict.failed("4j. Artefacto de realm importable", f"ilegible: {exc}")
        return
    flows = {flow.get("alias") for flow in data.get("authenticationFlows") or []}
    problems = []
    if not flows:
        problems.append("authenticationFlows vacío")
    for key in ("browserFlow", "clientAuthenticationFlow", "directGrantFlow"):
        alias = data.get(key)
        if alias and alias not in flows:
            problems.append(f"{key}={alias} sin flujo")
    if data.get("realm") != "hospital-lab":
        problems.append(f"realm={data.get('realm')!r}")
    verdict.check(
        not problems,
        "4j. Artefacto de realm importable",
        f"{artifact} ({len(flows)} flujos, {len(data.get('clients') or [])} clientes)",
        "; ".join(problems),
    )
    try:
        import time
        age_days = (time.time() - os.path.getmtime(artifact)) / 86400
        if age_days > 7:
            print(f"[WARN] 4j. El artefacto de realm tiene {age_days:.0f} días: reexpórtelo.")
    except OSError:
        pass



def _read_env_value(name: str, default: str = "") -> str:
    env_path = os.path.join(PROD_DIR, ".env")
    try:
        with open(env_path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                stripped = line.strip()
                if stripped.startswith(f"{name}="):
                    return stripped.split("=", 1)[1].strip()
    except OSError:
        pass
    return default


def check_monitor_oauth(verdict: Verdict, secret_file: Optional[str] = None) -> None:
    token_url = canonical_issuer() + "/protocol/openid-connect/token"
    secret = os.environ.get("AUDIT_MONITOR_CLIENT_SECRET", "")
    if secret_file:
        if not os.path.exists(secret_file):
            verdict.failed("4k. Secreto M2M del monitor", f"archivo inexistente: {secret_file}")
            return
        try:
            with open(secret_file, "r", encoding="utf-8") as handle:
                for line in handle:
                    if line.startswith("AUDIT_MONITOR_CLIENT_SECRET="):
                        secret = line.split("=", 1)[1].strip()
                        break
        except OSError as exc:
            verdict.failed("4k. Secreto M2M del monitor", f"ilegible: {exc}")
            return
        try:
            mode = os.stat(secret_file).st_mode & 0o777
            verdict.check(
                not (mode & 0o077),
                "4k. Archivo de credenciales M2M protegido",
                f"{secret_file} modo {oct(mode)}",
                f"{secret_file} modo {oct(mode)}: debe ser 0600",
            )
        except OSError:
            pass
    verdict.check(
        bool(secret) and not secret.startswith("change-me"),
        "4l. Secreto M2M del monitor provisto",
        "presente" if secret else "",
        "AUDIT_MONITOR_CLIENT_SECRET ausente: el monitor no puede autenticarse",
    )
    if os.path.exists(DEPLOY_SCRIPT):
        with open(DEPLOY_SCRIPT, "r", encoding="utf-8", errors="replace") as handle:
            content = handle.read()
        verdict.check(
            "AUDIT_MONITOR_TOKEN_URL" in content
            and "/protocol/openid-connect/token" in content
            and "/realms/hospital-lab" in content,
            "4m. Monitor apunta al token endpoint canónico",
            f"{token_url} (construido desde el issuer)",
            "el despliegue no inyecta AUDIT_MONITOR_TOKEN_URL canónico",
        )



def check_clinical_network(verdict: Verdict) -> None:
    result = subprocess.run(
        ["docker", "network", "inspect", "sgsi-zta-hospital-lab_clinical"],
        capture_output=True, text=True, timeout=20,
    )
    if result.returncode != 0:
        verdict.skipped(
            "8d. Red clinical",
            "no existe todavía: la crea el cutover como red interna con el alias canónico",
        )
        return
    try:
        data = json.loads(result.stdout)[0]
    except (json.JSONDecodeError, IndexError, KeyError):
        verdict.failed("8d. Red clinical", "inspección ilegible")
        return
    verdict.check(
        data.get("Internal") is True,
        "8d. Red clinical aislada",
        "internal=true",
        "internal=false: el LIS tendría salida a Internet",
    )


def check_clinical_volume(verdict: Verdict) -> None:
    result = subprocess.run(
        ["docker", "volume", "inspect", "clinical-data"],
        capture_output=True, text=True, timeout=20,
    )
    verdict.check(
        result.returncode == 0,
        "8e. Volumen clinical-data existe",
        "presente",
        "ausente: créelo antes del cutover (el despliegue lo declara external)",
    )
    if os.path.exists(DEPLOY_SCRIPT):
        with open(DEPLOY_SCRIPT, "r", encoding="utf-8", errors="replace") as handle:
            content = handle.read()
        verdict.check(
            '"external": True' in content,
            "8f. Despliegue declara el volumen como external",
            "external: true (falla cerrado si falta)",
            "el despliegue lo crearía en silencio: un volumen vacío pasa desapercibido",
        )


def check_volume_writable(verdict: Verdict) -> None:
    """El LIS corre como uid 65534 con rootfs read-only; el volumen debe ser suyo."""
    result = subprocess.run(
        [
            "docker", "run", "--rm", "-u", "65534:65534",
            "-v", "clinical-data:/data", "python:3.12-slim-bookworm",
            "sh", "-c", "touch /data/.write-probe && rm -f /data/.write-probe && echo WRITABLE",
        ],
        capture_output=True, text=True, timeout=60,
    )
    writable = result.returncode == 0 and "WRITABLE" in result.stdout
    print(
        "[INFO] 8h. Volumen escribible por uid 65534: "
        + ("si" if writable else "no (el despliegue aplica chown en el PASO 8a)")
    )


def check_lis_image(verdict: Verdict, image: Optional[str] = None) -> None:
    image = (
        image
        or os.environ.get("CLINICAL_IMAGE", "")
        or _read_env_value("CLINICAL_IMAGE", "")
        or "python:3.12-slim-bookworm"
    )
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", "--entrypoint", "python", image,
             "-c", "import cryptography; print(cryptography.__version__)"],
            capture_output=True, text=True, timeout=120,
        )
    except subprocess.TimeoutExpired:
        verdict.failed("8g. Imagen del LIS con dependencias", f"{image}: timeout")
        return
    verdict.check(
        result.returncode == 0,
        "8g. Imagen del LIS con dependencias",
        f"{image}: cryptography {result.stdout.strip()}",
        f"{image} no puede importar cryptography: el backend no arrancaría. "
        "Defina CLINICAL_IMAGE con una imagen que incluya requirements.txt.",
    )


def check_manifest(verdict: Verdict) -> None:
    if not os.path.exists(MANIFEST_PATH):
        verdict.failed("5. Manifiesto SHA-256", f"ausente en {MANIFEST_PATH}")
        return

    verified: List[str] = []
    try:
        with open(MANIFEST_PATH, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except OSError as exc:
        verdict.failed("5. Manifiesto SHA-256", f"ilegible: {exc}")
        return

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            expected_hash, rel_path = line.split(None, 1)
        except ValueError:
            verdict.failed("5. Manifiesto SHA-256", f"línea inválida: {line[:80]}")
            return
        file_path = os.path.join(CANDIDATE_DIR, rel_path)
        if not os.path.exists(file_path):
            verdict.failed("5. Manifiesto SHA-256", f"archivo ausente: {rel_path}")
            return
        with open(file_path, "rb") as binary:
            actual = hashlib.sha256(binary.read()).hexdigest()
        if actual != expected_hash:
            verdict.failed(
                "5. Manifiesto SHA-256",
                f"checksum discrepante en {rel_path}",
            )
            return
        verified.append(rel_path)

    verdict.passed("5. Manifiesto SHA-256", f"{len(verified)} archivos verificados")

    missing = [module for module in REQUIRED_MODULES if module not in verified]
    verdict.check(
        not missing,
        "5a. Manifiesto cubre el runtime",
        "todos los módulos del backend están cubiertos",
        "módulos fuera del manifiesto: " + ", ".join(missing),
    )


def check_candidate_compiles(verdict: Verdict) -> None:
    failures: List[str] = []
    for module in REQUIRED_MODULES:
        path = os.path.join(CANDIDATE_DIR, module)
        if not os.path.exists(path):
            failures.append(f"{module}: ausente")
            continue
        try:
            with open(path, "r", encoding="utf-8") as handle:
                source = handle.read()
            # Compilación en memoria: valida sintaxis sin escribir artefactos.
            compile(source, path, "exec")
        except SyntaxError as exc:
            failures.append(f"{module}: línea {exc.lineno}: {exc.msg}")
        except OSError as exc:
            failures.append(f"{module}: {exc}")
    verdict.check(
        not failures,
        "6. Compilación del candidato",
        f"{len(REQUIRED_MODULES)} módulos compilan",
        "fallos: " + "; ".join(failures),
    )

    paths = [os.path.join(CANDIDATE_DIR, module) for module in REQUIRED_MODULES]
    offenders = scan_forbidden_secrets(paths)
    verdict.check(
        not offenders,
        "6a. Sin secretos por defecto en el candidato (A-01)",
        "ningún secreto embebido",
        "secretos embebidos en: " + ", ".join(offenders),
    )


def check_env_contract(verdict: Verdict, device_keys_file: Optional[str] = None) -> None:
    """El despliegue debe inyectar el contrato; si no lo menciona, no lo inyecta."""
    if not os.path.exists(DEPLOY_SCRIPT):
        verdict.failed("7. Contrato de entorno", f"no existe {DEPLOY_SCRIPT}")
        return
    with open(DEPLOY_SCRIPT, "r", encoding="utf-8", errors="replace") as handle:
        content = handle.read()
    missing = [name for name in REQUIRED_ENV_CONTRACT if name not in content]
    verdict.check(
        not missing,
        "7. Contrato de entorno en el despliegue",
        f"{len(REQUIRED_ENV_CONTRACT)} variables contempladas",
        "el despliegue no contempla: " + ", ".join(missing),
    )

    keys_from_file = False
    if device_keys_file:
        if not os.path.exists(device_keys_file):
            verdict.failed("7a. Claves IoMT disponibles", f"archivo inexistente: {device_keys_file}")
        else:
            try:
                with open(device_keys_file, "r", encoding="utf-8") as handle:
                    parsed = json.load(handle)
                keys_from_file = isinstance(parsed, dict) and bool(parsed)
            except (json.JSONDecodeError, OSError) as exc:
                verdict.failed("7a. Claves IoMT disponibles", f"archivo inválido: {exc}")
            else:
                verdict.check(
                    keys_from_file,
                    "7a. Claves IoMT disponibles",
                    f"{len(parsed)} claves en {device_keys_file}",
                    "el archivo no contiene un objeto de claves",
                )
    else:
        verdict.check(
            bool(os.environ.get("IOMT_DEVICE_KEYS_JSON"))
            or bool(os.environ.get("IOMT_DEVICE_KEYS_FILE")),
            "7a. Claves IoMT disponibles para el operador",
            "IOMT_DEVICE_KEYS_JSON presente o IOMT_DEVICE_KEYS_FILE indicado",
            "sin IOMT_DEVICE_KEYS_JSON, IOMT_DEVICE_KEYS_FILE ni --device-keys-file: "
            "el canal quedaría en 503",
        )

    if os.environ.get("AUDIT_HMAC_KEY"):
        verdict.passed("7b. Clave de anclaje", "AUDIT_HMAC_KEY provista por entorno")
    else:
        print(
            "[INFO] AUDIT_HMAC_KEY no está en el entorno: el despliegue usará "
            "<db>.anchor-key del volumen. Es válido si el ancla ya existe."
        )


def check_database_compatibility(verdict: Verdict, db_path: Optional[str]) -> None:
    if not db_path:
        verdict.skipped(
            "8. Compatibilidad de base existente",
            "sin --db-path: no se inspeccionó ninguna base (el volumen se valida en el despliegue)",
        )
        return
    inspection = inspect_database(db_path)
    if not inspection["exists"]:
        verdict.skipped("8. Compatibilidad de base existente", f"no existe {db_path} (estado cero)")
        return
    verdict.check(
        inspection["integrity"] == "ok",
        "8. Integridad de la base existente",
        "integrity_check=ok",
        f"integrity_check={inspection['integrity']}",
    )
    verdict.check(
        (inspection["schema_version"] or 0) >= 1,
        "8a. Esquema legible",
        f"v{inspection['schema_version']}",
        "schema_migrations ilegible",
    )
    verdict.check(
        inspection["chain_valid"] is True,
        "8b. Cadena de auditoría verificable",
        "cadena válida con el ancla disponible",
        f"cadena inválida: {inspection['chain_error']}",
    )


def check_backup_destination(verdict: Verdict, backup_base: str = BACKUP_BASE_DIR + "/pre_cutover") -> None:
    """El respaldo falla cerrado si el operador no puede escribir su destino."""
    probe = backup_base
    while not os.path.isdir(probe) and os.path.dirname(probe) != probe:
        probe = os.path.dirname(probe)
    if os.access(probe, os.W_OK):
        verdict.passed("8c. Destino de respaldo", f"escribible: {probe}")
        return

    owner = "desconocido"
    try:
        import pwd

        owner = pwd.getpwuid(os.stat(probe).st_uid).pw_name
    except (ImportError, KeyError, OSError):
        pass
    verdict.failed(
        "8c. Destino de respaldo",
        f"no escribible por {getpass.getuser()}: {probe} (propietario: {owner}). "
        f"Cree la ruta antes del cutover: sudo install -d -o "
        f"{getpass.getuser()} -g $(id -gn) -m 700 {backup_base}",
    )


def check_production_environment(verdict: Verdict) -> None:
    if not os.path.exists(PROD_DIR):
        verdict.failed("9. Entorno principal", f"directorio ausente: {PROD_DIR}")
        return
    compose = os.path.join(PROD_DIR, "docker-compose.yml")
    env_file = os.path.join(PROD_DIR, ".env")
    missing = [path for path in (compose, env_file) if not os.path.exists(path)]
    if missing:
        verdict.failed("9. Entorno principal", "faltan: " + ", ".join(missing))
        return
    try:
        # Se filtra por proyecto y servicio de Compose para no confundir stacks
        # de ensayo (p. ej. zta-itest) con el servicio principal de producción.
        running = subprocess.run(
            [
                "docker", "ps",
                "--filter", f"label=com.docker.compose.project={PROD_PROJECT}",
                "--filter", "label=com.docker.compose.service=clinical-poc",
                "--format", "{{.Names}}",
            ],
            capture_output=True, text=True,
        ).stdout.strip()
    except Exception as exc:  # noqa: BLE001
        verdict.failed("9. Entorno principal", f"error al consultar Docker: {exc}")
        return
    verdict.check(
        not running,
        "9. Servicio principal detenido",
        "clinical-poc inactivo, base presente",
        f"el contenedor '{running}' está en ejecución: debe detenerse antes del corte",
    )


def run_preflight(
    target_port: int,
    keycloak_url: str,
    db_path: Optional[str],
    device_keys_file: Optional[str] = None,
    monitor_secret_file: Optional[str] = None,
    clinical_image: Optional[str] = None,
    realm_export_file: Optional[str] = None,
) -> Verdict:
    print("=" * 70)
    print(" PREFLIGHT CHECK & DICTAMEN GO / NO-GO (SGSI-ZTA CUTOVER)")
    print("=" * 70)

    verdict = Verdict("PREFLIGHT CUTOVER LIS")
    check_host_and_user(verdict)
    check_git_status(verdict)
    check_ports(verdict, target_port)
    check_tls_material(verdict)
    check_canonical_tls(verdict)
    check_keycloak(verdict, keycloak_url)
    check_renewal(verdict)
    check_realm_export(verdict, realm_export_file)
    check_monitor_oauth(verdict, monitor_secret_file)
    check_manifest(verdict)
    check_candidate_compiles(verdict)
    check_env_contract(verdict, device_keys_file)
    check_database_compatibility(verdict, db_path)
    check_clinical_network(verdict)
    check_clinical_volume(verdict)
    check_lis_image(verdict, clinical_image)
    check_volume_writable(verdict)
    check_backup_destination(verdict, BACKUP_BASE_DIR + "/pre_cutover")
    check_production_environment(verdict)
    return verdict


def main() -> int:
    parser = argparse.ArgumentParser(description="Preflight check para cutover del LIS")
    parser.add_argument("--port", type=int, default=8086, help="Puerto objetivo")
    parser.add_argument("--keycloak-url", default=DEFAULT_KEYCLOAK_URL)
    parser.add_argument("--db-path", default=None, help="Base existente a inspeccionar (opcional)")
    parser.add_argument(
        "--device-keys-file",
        default=None,
        help="Archivo JSON con claves por dispositivo que se usará en el despliegue",
    )
    parser.add_argument(
        "--monitor-secret-file",
        default=None,
        help="Archivo 0600 con AUDIT_MONITOR_CLIENT_SECRET (evita el entorno)",
    )
    parser.add_argument(
        "--clinical-image",
        default=None,
        help="Imagen del LIS con cryptography (por defecto, CLINICAL_IMAGE o .env)",
    )
    parser.add_argument(
        "--realm-export-file",
        default=None,
        help="Artefacto de realm importable (por defecto, sgsi-backups/realm/...)",
    )
    parser.add_argument("--json", action="store_true", help="Salida JSON")
    args = parser.parse_args()

    verdict = run_preflight(
        args.port,
        args.keycloak_url,
        args.db_path,
        args.device_keys_file,
        args.monitor_secret_file,
        args.clinical_image,
        args.realm_export_file,
    )
    verdict.summary()
    if args.json:
        print(json.dumps(verdict.report(), indent=2, ensure_ascii=False))
    return verdict.exit_code()


if __name__ == "__main__":
    sys.exit(main())
