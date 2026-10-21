#!/usr/bin/env python3
"""
cutover_common.py - Utilidades compartidas de los scripts de cutover.
SGSI-ZTA Hospital Lab — ISO/IEC 27001:2022 & NIST SP 800-207

Sin dependencias externas, sin secretos embebidos y sin escrituras sobre la base
clínica. Todo lo de este módulo es seguro para ejecutarse contra producción en
modo lectura.
"""

import hashlib
import hmac
import json
import os
import sqlite3
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

ZERO_HASH = "0" * 64
DEFAULT_TIMEOUT = 5.0
ANCHOR_ENV = "AUDIT_HMAC_KEY"
ANCHOR_SUFFIX = ".anchor-key"
CANARY_PREFIX = "CANARY-"

# Endpoint canónico verificado del laboratorio.
# 80/443 pertenecen a coolify-proxy (Traefik), por eso el gateway de identidad
# usa 8443 sobre el nombre MagicDNS de Tailscale, resoluble desde Windows y
# desde la red interna de Docker mediante alias de red.
CANONICAL_BASE_URL = os.environ.get(
    "LIS_CANONICAL_BASE_URL", "https://servidor-1.tailb0f78a.ts.net:8443"
).rstrip("/")
CANONICAL_REALM = "hospital-lab"

# Respaldos del operador: escribibles sin sudo (a diferencia de /home/elcra/backups).
BACKUP_BASE_DIR = os.environ.get("LIS_BACKUP_BASE", "/home/elcra/sgsi-backups")

# Cadenas que jamás deben reaparecer en un artefacto desplegable (hallazgo A-01).
FORBIDDEN_SECRET_MARKERS = (
    "Secret_IoMT_Key_Hematology_2026",
    "SGSI-ZTA-Default-Audit-Anchor-2026",
)

SECRET_ENV_NAMES = (
    "AUDIT_MONITOR_CLIENT_SECRET",
    "AUDIT_HMAC_KEY",
    "CLINICAL_SIGNING_KEY",
    "IOMT_DEVICE_KEYS_JSON",
)


# ---------------------------------------------------------------------------
# Secretos y configuración
# ---------------------------------------------------------------------------
def redact(value: Any, visible: int = 4) -> str:
    """Redacta un secreto dejando solo una pista no reversible."""
    if value is None:
        return "<ausente>"
    text = str(value)
    if len(text) <= visible:
        return "*" * len(text)
    return f"{text[:visible]}…({len(text)} chars)"


def read_env_file(path: str) -> Dict[str, str]:
    """Lee un archivo KEY=VALUE ignorando comentarios y líneas vacías."""
    values: Dict[str, str] = {}
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            if key.startswith("export "):
                key = key[len("export "):].strip()
            values[key] = value.strip().strip('"').strip("'")
    return values


def resolve_credentials(
    creds_path: Optional[str] = None,
    token_endpoint: Optional[str] = None,
) -> Dict[str, str]:
    """
    Resuelve credenciales M2M desde entorno o desde un archivo explícito.

    No hay rutas candidatas ni valores por defecto: si falta el archivo o las
    variables, se lanza una excepción. Un secreto ausente nunca se sustituye.
    """
    client_id = os.environ.get("AUDIT_MONITOR_CLIENT_ID")
    client_secret = os.environ.get("AUDIT_MONITOR_CLIENT_SECRET")
    token_url = token_endpoint or os.environ.get("AUDIT_MONITOR_TOKEN_URL")

    if creds_path:
        if not os.path.exists(creds_path):
            raise RuntimeError(f"Archivo de credenciales inexistente: {creds_path}")
        with open(creds_path, "r", encoding="utf-8") as handle:
            raw = handle.read()
        if creds_path.endswith(".json"):
            data = json.loads(raw)
        else:
            data = read_env_file(creds_path)
        client_id = client_id or data.get("client_id") or data.get("AUDIT_MONITOR_CLIENT_ID")
        client_secret = (
            client_secret
            or data.get("client_secret")
            or data.get("AUDIT_MONITOR_CLIENT_SECRET")
        )
        token_url = (
            token_url
            or data.get("token_url")
            or data.get("AUDIT_MONITOR_TOKEN_URL")
        )

    missing = [
        name
        for name, value in (
            ("AUDIT_MONITOR_CLIENT_ID", client_id),
            ("AUDIT_MONITOR_CLIENT_SECRET", client_secret),
            ("AUDIT_MONITOR_TOKEN_URL / --token-url", token_url),
        )
        if not value
    ]
    if missing:
        raise RuntimeError(
            "Credenciales M2M incompletas. Falta: "
            + ", ".join(missing)
            + ". Use variables de entorno o --creds=RUTA (sin valores por defecto)."
        )

    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "token_url": token_url,
    }


def fetch_client_token(credentials: Dict[str, str], timeout: float = DEFAULT_TIMEOUT) -> str:
    """Obtiene un access_token por OAuth 2.0 Client Credentials."""
    payload = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "client_id": credentials["client_id"],
            "client_secret": credentials["client_secret"],
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        credentials["token_url"],
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:200]
        raise RuntimeError(f"OAuth rechazado: HTTP {exc.code} {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Keycloak inalcanzable en {credentials['token_url']}: {exc}") from exc

    token = body.get("access_token")
    if not token:
        raise RuntimeError("Respuesta OAuth sin access_token")
    return token


def load_device_keys(raw_json: Optional[str] = None) -> Dict[str, bytes]:
    """
    Carga claves IoMT por dispositivo desde IOMT_DEVICE_KEYS_JSON.

    Sin configuración devuelve un diccionario vacío. No existe clave por defecto.
    """
    raw = raw_json if raw_json is not None else os.environ.get("IOMT_DEVICE_KEYS_JSON", "")
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"IOMT_DEVICE_KEYS_JSON inválido: {exc}") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError("IOMT_DEVICE_KEYS_JSON debe ser un objeto {device_id: secreto}")
    keys: Dict[str, bytes] = {}
    for device_id, secret in parsed.items():
        if isinstance(secret, str) and len(secret) >= 16:
            keys[str(device_id)] = secret.encode("utf-8")
    return keys


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
def http_json(
    url: str,
    method: str = "GET",
    token: Optional[str] = None,
    data: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> Tuple[int, Dict[str, Any]]:
    """Petición JSON tolerante a cuerpos de error no JSON."""
    request_headers = {"Content-Type": "application/json"}
    if token:
        request_headers["Authorization"] = f"Bearer {token}"
    if headers:
        request_headers.update(headers)

    body = json.dumps(data).encode("utf-8") if data is not None else None
    request = urllib.request.Request(url, data=body, headers=request_headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", "replace")
            return response.status, _parse_json(raw)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        return exc.code, _parse_json(raw)
    except urllib.error.URLError as exc:
        return 0, {"error": "UNREACHABLE", "message": str(exc)}


def _parse_json(raw: str) -> Dict[str, Any]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {"raw": parsed}
    except json.JSONDecodeError:
        return {"raw": raw[:500]}


# ---------------------------------------------------------------------------
# Firma IoMT (device_id \n timestamp \n nonce \n body)
# ---------------------------------------------------------------------------
def iomt_signature(device_key: bytes, device_id: str, timestamp: str, nonce: str, body: str) -> str:
    signing_input = f"{device_id}\n{timestamp}\n{nonce}\n{body}"
    return hmac.new(device_key, signing_input.encode("utf-8"), hashlib.sha256).hexdigest()


def iomt_headers(device_key: bytes, device_id: str, timestamp: str, nonce: str, body: str) -> Dict[str, str]:
    return {
        "X-Device-Id": device_id,
        "X-Device-Signature": iomt_signature(device_key, device_id, timestamp, nonce, body),
        "X-Device-Timestamp": timestamp,
        "X-Device-Nonce": nonce,
    }


# ---------------------------------------------------------------------------
# SQLite en modo lectura
# ---------------------------------------------------------------------------
def _readonly_uri(path: str) -> str:
    return "file:" + urllib.parse.quote(os.path.abspath(path)) + "?mode=ro"


def open_readonly(path: str) -> sqlite3.Connection:
    """
    Abre la base en solo lectura.

    No usa immutable=1: si existe WAL pendiente, immutable devolvería una vista
    obsoleta. mode=ro sí provoca la lectura del WAL sin escribir en la base.
    """
    connection = sqlite3.connect(_readonly_uri(path), uri=True, timeout=10.0)
    connection.row_factory = sqlite3.Row
    return connection


def file_mode(path: str) -> Optional[int]:
    if not os.path.exists(path):
        return None
    return stat.S_IMODE(os.stat(path).st_mode)


def anchor_key_path(db_path: str) -> str:
    return db_path + ANCHOR_SUFFIX


def load_anchor_key(db_path: str, env_key: Optional[str] = None) -> Tuple[Optional[bytes], str]:
    """
    Resuelve la clave de anclaje igual que el backend.

    Prioridad: variable de entorno, luego archivo lateral. Devuelve (clave, origen).
    """
    raw = env_key if env_key is not None else os.environ.get(ANCHOR_ENV)
    if raw:
        try:
            return bytes.fromhex(raw), f"env:{ANCHOR_ENV}"
        except ValueError:
            return raw.encode("utf-8"), f"env:{ANCHOR_ENV}"

    path = anchor_key_path(db_path)
    if os.path.exists(path):
        with open(path, "r", encoding="ascii") as handle:
            content = handle.read().strip()
        try:
            return bytes.fromhex(content), path
        except ValueError:
            return content.encode("utf-8"), path
    return None, "ausente"


def verify_chain(
    connection: sqlite3.Connection,
    anchor_key: Optional[bytes],
) -> Tuple[bool, Optional[str], Dict[str, Any]]:
    """
    Recalcula la cadena de auditoría y el anclaje sin escribir nada.

    Reproduce exactamente el algoritmo del backend:
      record_hash = sha256(json.dumps(record, sort_keys=True))
      anchor      = sha256(anchor_key + f"{last_hash}:{total_events}")
    """
    details: Dict[str, Any] = {}
    try:
        rows = connection.execute(
            "SELECT id, raw_json, prev_hash, event_hash FROM audit_events ORDER BY id ASC;"
        ).fetchall()
        checkpoint = connection.execute(
            "SELECT last_hash, total_events, anchor_signature FROM audit_checkpoints WHERE checkpoint_id = 1;"
        ).fetchone()
    except sqlite3.Error as exc:
        return False, f"Error de lectura SQLite: {exc}", details

    if checkpoint is None:
        return False, "Checkpoint de auditoría ausente", details

    total_declared = int(checkpoint["total_events"])
    last_hash = checkpoint["last_hash"]
    anchor_signature = checkpoint["anchor_signature"]
    details["events_row_count"] = len(rows)
    details["checkpoint_total_events"] = total_declared
    details["checkpoint_last_hash"] = last_hash

    if len(rows) != total_declared:
        return (
            False,
            f"Discrepancia de conteo: checkpoint={total_declared}, eventos={len(rows)}",
            details,
        )

    expected_prev = ZERO_HASH
    for row in rows:
        try:
            record = json.loads(row["raw_json"])
        except json.JSONDecodeError as exc:
            return False, f"Evento ID {row['id']} con raw_json ilegible: {exc}", details

        declared_hash = record.get("hash")
        candidate = {key: value for key, value in record.items() if key != "hash"}
        recomputed = hashlib.sha256(
            json.dumps(candidate, sort_keys=True).encode("utf-8")
        ).hexdigest()

        if declared_hash != recomputed:
            return False, f"Evento ID {row['id']}: hash recalculado no coincide", details
        if row["prev_hash"] != expected_prev:
            return (
                False,
                f"Evento ID {row['id']}: prev_hash esperado {expected_prev[:16]}…, "
                f"encontrado {row['prev_hash'][:16]}…",
                details,
            )
        if row["event_hash"] != recomputed:
            return False, f"Evento ID {row['id']}: event_hash almacenado no coincide", details
        expected_prev = recomputed

    expected_last = expected_prev if rows else ZERO_HASH
    if last_hash != expected_last:
        return (
            False,
            f"checkpoint.last_hash {last_hash[:16]}… no coincide con el último evento {expected_last[:16]}…",
            details,
        )

    if anchor_key is None:
        return (
            False,
            "Clave de anclaje ausente: no se puede verificar el anclaje del checkpoint",
            details,
        )

    expected_anchor = hashlib.sha256(
        anchor_key + f"{last_hash}:{total_declared}".encode("utf-8")
    ).hexdigest()
    details["anchor_matches"] = hmac.compare_digest(str(anchor_signature), expected_anchor)
    if not details["anchor_matches"]:
        return False, "Anclaje del checkpoint no coincide con la clave provista", details

    return True, None, details


def canonical_issuer(base_url: Optional[str] = None) -> str:
    """Issuer único del realm, idéntico para Windows, host y contenedores."""
    base = (base_url or CANONICAL_BASE_URL).rstrip("/")
    return f"{base}/realms/{CANONICAL_REALM}"


def canonical_discovery_url(base_url: Optional[str] = None) -> str:
    return canonical_issuer(base_url) + "/.well-known/openid-configuration"


def canonical_token_url(base_url: Optional[str] = None) -> str:
    return canonical_issuer(base_url) + "/protocol/openid-connect/token"


def fetch_json_url(
    url: str, timeout: float = DEFAULT_TIMEOUT, cafile: Optional[str] = None
) -> Dict[str, Any]:
    import ssl

    context = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        return json.loads(response.read().decode("utf-8"))


def issuer_document_problems(
    document: Dict[str, Any], base_url: Optional[str] = None
) -> List[str]:
    """Un discovery sano no filtra loopback ni habla HTTP."""
    expected = canonical_issuer(base_url)
    origin = expected.rsplit("/realms/", 1)[0]
    problems: List[str] = []
    if document.get("issuer") != expected:
        problems.append(f"issuer={document.get('issuer')!r}, esperado {expected!r}")
    for key in ("jwks_uri", "token_endpoint", "authorization_endpoint"):
        value = str(document.get(key) or "")
        if not value.startswith(origin + "/"):
            problems.append(f"{key}={value!r} fuera del origen canónico")
    blob = json.dumps(document)
    for needle in ("127.0.0.1", "localhost", "keycloak:8080", "http://"):
        if needle in blob:
            problems.append(f"discovery contiene {needle!r}")
    return problems


def tls_peer_certificate(
    host: str, port: int, cafile: Optional[str] = None, timeout: float = DEFAULT_TIMEOUT
) -> Dict[str, Any]:
    import socket as _socket
    import ssl

    context = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
    with _socket.create_connection((host, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            cert = tls.getpeercert() or {}
            subject = {key: value for item in cert.get("subject", ()) for key, value in item}
            san = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]
            return {"subject": subject, "san": san, "notAfter": cert.get("notAfter")}


def inspect_database(db_path: str, env_anchor_key: Optional[str] = None) -> Dict[str, Any]:
    """Inspección completa y no destructiva de una base clínica."""
    result: Dict[str, Any] = {
        "path": db_path,
        "exists": os.path.exists(db_path),
        "mode": None,
        "integrity": None,
        "journal_mode": None,
        "schema_version": None,
        "orders": None,
        "events": None,
        "anchor_path": anchor_key_path(db_path),
        "anchor_mode": file_mode(anchor_key_path(db_path)),
        "anchor_source": None,
        "chain_valid": None,
        "chain_error": None,
        "chain_details": {},
        "errors": [],
    }
    if not result["exists"]:
        result["errors"].append("La base no existe")
        return result

    result["mode"] = file_mode(db_path)
    connection = None
    try:
        connection = open_readonly(db_path)
        result["integrity"] = connection.execute("PRAGMA integrity_check;").fetchone()[0]
        result["journal_mode"] = connection.execute("PRAGMA journal_mode;").fetchone()[0]
        try:
            result["schema_version"] = connection.execute(
                "SELECT MAX(version) FROM schema_migrations;"
            ).fetchone()[0]
        except sqlite3.Error as exc:
            result["errors"].append(f"schema_migrations: {exc}")
        for table, key in (("clinical_orders", "orders"), ("audit_events", "events")):
            try:
                result[key] = connection.execute(
                    f"SELECT COUNT(*) FROM {table};"
                ).fetchone()[0]
            except sqlite3.Error as exc:
                result["errors"].append(f"{table}: {exc}")

        anchor_key, anchor_source = load_anchor_key(db_path, env_anchor_key)
        result["anchor_source"] = anchor_source
        valid, reason, details = verify_chain(connection, anchor_key)
        result["chain_valid"] = valid
        result["chain_error"] = reason
        result["chain_details"] = details
    except sqlite3.Error as exc:
        result["errors"].append(f"SQLite: {exc}")
    finally:
        if connection is not None:
            connection.close()

    return result


def durability_policy_ok(source_path: str) -> Tuple[bool, str]:
    """
    Verifica la política de durabilidad en el código desplegado.

    PRAGMA synchronous es un ajuste por conexión con default FULL: consultarlo en
    una conexión nueva no demuestra nada. Se inspecciona el artefacto.
    """
    if not os.path.exists(source_path):
        return False, f"no existe {source_path}"
    with open(source_path, "r", encoding="utf-8", errors="replace") as handle:
        content = handle.read()
    if "PRAGMA synchronous=FULL" not in content:
        return False, "database.py no declara PRAGMA synchronous=FULL"
    return True, "PRAGMA synchronous=FULL presente en database.py"


def scan_forbidden_secrets(paths: List[str]) -> List[str]:
    """Devuelve los archivos que todavía contienen secretos por defecto (A-01)."""
    offenders: List[str] = []
    for path in paths:
        if not os.path.isfile(path):
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            content = handle.read()
        if any(marker in content for marker in FORBIDDEN_SECRET_MARKERS):
            offenders.append(path)
    return offenders


# ---------------------------------------------------------------------------
# Veredicto
# ---------------------------------------------------------------------------
class Verdict:
    """Acumula comprobaciones PASS/FAIL/SKIP y decide el dictamen."""

    def __init__(self, title: str):
        self.title = title
        self.results: List[Dict[str, str]] = []

    def _add(self, status: str, name: str, detail: str, blocking: bool = False) -> None:
        self.results.append(
            {"status": status, "name": name, "detail": detail, "blocking": blocking}
        )
        print(f"[{status}] {name}: {detail}")

    def passed(self, name: str, detail: str = "") -> None:
        self._add("PASS", name, detail)

    def failed(self, name: str, detail: str = "") -> None:
        self._add("FAIL", name, detail)

    def skipped(self, name: str, detail: str = "", blocking: bool = False) -> None:
        """Un SKIP bloqueante impide el dictamen GO: no se pudo comprobar, no es un aprobado."""
        self._add("SKIP", name, detail, blocking=blocking)

    def check(self, condition: bool, name: str, ok_detail: str, fail_detail: str) -> bool:
        if condition:
            self.passed(name, ok_detail)
        else:
            self.failed(name, fail_detail)
        return condition

    @property
    def ok(self) -> bool:
        return not any(item["status"] == "FAIL" for item in self.results)

    @property
    def verdict(self) -> str:
        if any(item["status"] == "FAIL" for item in self.results):
            return "NO-GO"
        if any(
            item["status"] == "SKIP" and item.get("blocking")
            for item in self.results
        ):
            return "INCOMPLETE"
        return "GO"

    def counts(self) -> Dict[str, int]:
        counts = {"PASS": 0, "FAIL": 0, "SKIP": 0}
        for item in self.results:
            counts[item["status"]] = counts.get(item["status"], 0) + 1
        return counts

    def report(self) -> Dict[str, Any]:
        blocking = [i["name"] for i in self.results if i["status"] == "SKIP" and i.get("blocking")]
        return {
            "title": self.title,
            "verdict": self.verdict,
            "counts": self.counts(),
            "blocking_skips": blocking,
            "results": self.results,
        }

    def summary(self) -> None:
        counts = self.counts()
        print("-" * 70)
        print(
            f"[DICTAMEN: {self.verdict}] "
            f"PASS={counts['PASS']} FAIL={counts['FAIL']} SKIP={counts['SKIP']}"
        )
        if self.verdict == "INCOMPLETE":
            blocking = [i["name"] for i in self.results if i["status"] == "SKIP" and i.get("blocking")]
            print("[PENDIENTE] Comprobaciones no ejecutables: " + ", ".join(blocking))
        print("=" * 70)

    def exit_code(self) -> int:
        return {"GO": 0, "NO-GO": 1, "INCOMPLETE": 2}[self.verdict]


def die(message: str, code: int = 1) -> int:
    print(f"[ERROR] {message}", file=sys.stderr)
    return code


# ---------------------------------------------------------------------------
# CLI mínima: permite a los scripts de shell verificar una base sin duplicar
# criptografía.
#   python3 cutover_common.py inspect  --db RUTA [--anchor-env] [--json]
#   python3 cutover_common.py durability --source RUTA/database.py
# ---------------------------------------------------------------------------
def _main(argv: List[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Utilidades de verificación de cutover")
    sub = parser.add_subparsers(dest="command", required=True)

    inspect_parser = sub.add_parser("inspect", help="Inspección read-only de una base SQLite")
    inspect_parser.add_argument("--db", required=True)
    inspect_parser.add_argument(
        "--anchor-env",
        action="store_true",
        help="Usa AUDIT_HMAC_KEY del entorno en lugar del archivo lateral",
    )
    inspect_parser.add_argument("--json", action="store_true")

    durability_parser = sub.add_parser("durability", help="Verifica la política de durabilidad")
    durability_parser.add_argument("--source", required=True)

    args = parser.parse_args(argv)

    if args.command == "inspect":
        env_key = os.environ.get(ANCHOR_ENV) if args.anchor_env else None
        result = inspect_database(args.db, env_key)
        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print(f"base                : {result['path']}")
            print(f"existe              : {result['exists']}")
            print(f"modo                : {oct(result['mode']) if result['mode'] is not None else 'ausente'}")
            print(f"integrity_check     : {result['integrity']}")
            print(f"journal_mode        : {result['journal_mode']}")
            print(f"schema_version      : {result['schema_version']}")
            print(f"ordenes             : {result['orders']}")
            print(f"eventos             : {result['events']}")
            print(f"ancla               : {result['anchor_source']}")
            print(f"ancla_modo          : {oct(result['anchor_mode']) if result['anchor_mode'] is not None else 'ausente'}")
            print(f"cadena_valida       : {result['chain_valid']}")
            print(f"cadena_error        : {result['chain_error']}")
            for error in result["errors"]:
                print(f"error               : {error}")
        if not result["exists"]:
            return 3
        return 0 if result["chain_valid"] is True and result["integrity"] == "ok" else 4

    ok, detail = durability_policy_ok(args.source)
    print(("[PASS] " if ok else "[FAIL] ") + detail)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
