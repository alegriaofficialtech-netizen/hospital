#!/usr/bin/env python3
"""
post_cutover_verify.py - Verificación funcional posterior al cutover (no destructiva).
SGSI-ZTA Hospital Lab — ISO/IEC 27001:2022 & NIST SP 800-207

Por defecto opera en modo ESTRICTO DE SOLO LECTURA:

- No crea órdenes, no valida órdenes y no ingesta resultados clínicos.
- Las pruebas del canal IoMT son negativas: envían peticiones que el backend debe
  rechazar, siempre contra un `order_id` con prefijo CANARY- inexistente, de modo
  que ningún dato clínico real pueda resultar alcanzado.
- Las pruebas de menor privilegio usan un token M2M y esperan 403: si el backend
  estuviera mal, la petición sería rechazada igualmente por diseño del contrato.
- La base SQLite se abre con `mode=ro` y la cadena se recalcula en Python puro.

Las pruebas que sí escriben requieren `--write-probe` y un `--canary-order-id`
explícito con prefijo CANARY-. Sin esa bandera, el script nunca mutará datos.

Nota: las pruebas negativas generan eventos DENIED en la auditoría (append-only).
Eso es el comportamiento correcto de un sistema auditado, no una mutación clínica.

Códigos de salida: 0 = GO, 1 = NO-GO, 2 = INCOMPLETO (comprobación bloqueante no
ejecutable, p. ej. Keycloak inaccesible).
"""

import argparse
import json
import os
import sys
import time
import uuid
from typing import Any, Dict, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cutover_common import (  # noqa: E402
    CANARY_PREFIX,
    CANONICAL_BASE_URL,
    canonical_discovery_url,
    canonical_issuer,
    fetch_json_url,
    issuer_document_problems,
    Verdict,
    durability_policy_ok,
    fetch_client_token,
    http_json,
    iomt_headers,
    inspect_database,
    load_device_keys,
    redact,
    resolve_credentials,
    scan_forbidden_secrets,
)

DEFAULT_BASE_URL = "http://127.0.0.1:8086"


def _short(payload: Dict[str, Any]) -> str:
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    return text if len(text) <= 220 else text[:217] + "…"


def _expect(
    verdict: Verdict,
    label: str,
    status: int,
    payload: Dict[str, Any],
    expected_status: int,
    expected_code: Optional[str] = None,
    blocking_skip_on: Optional[int] = None,
) -> bool:
    """Evalúa una respuesta esperada con código de error explícito."""
    if status == 0:
        verdict.failed(label, f"sin respuesta del servidor: {payload.get('message')}")
        return False
    if blocking_skip_on is not None and status == blocking_skip_on:
        verdict.skipped(
            label,
            f"HTTP {status} {payload.get('code')}: comprobación no ejecutable en este entorno",
            blocking=True,
        )
        return False
    code = payload.get("code")
    if status == expected_status and (expected_code is None or code == expected_code):
        verdict.passed(label, f"HTTP {status} {code or ''}".strip())
        return True
    verdict.failed(
        label,
        f"esperado HTTP {expected_status}"
        + (f"/{expected_code}" if expected_code else "")
        + f", obtenido HTTP {status}/{code}: {_short(payload)}",
    )
    return False


def _iomt_probe(
    verdict: Verdict,
    base_url: str,
    label: str,
    order_id: str,
    headers: Dict[str, str],
    expected_status: int,
    expected_code: str,
) -> None:
    payload = {"order_id": order_id, "measurements": {"plaquetas_k_ul": 250.0}}
    status, body = http_json(
        f"{base_url}/api/v1/iomt/results", method="POST", data=payload, headers=headers
    )
    _expect(verdict, label, status, body, expected_status, expected_code)


def run_verification(args: argparse.Namespace) -> Verdict:
    verdict = Verdict("VERIFICACIÓN POST-CUTOVER LIS (ZERO TRUST)")
    base_url = args.url.rstrip("/")
    mode = "WRITE-PROBE (canario)" if args.write_probe else "SOLO LECTURA (estricto)"

    print("=" * 70)
    print(" VERIFICACIÓN POST-CUTOVER LIS (ZERO TRUST & PERSISTENCIA)")
    print(f" URL base: {base_url}")
    print(f" Modo    : {mode}")
    if args.db_path:
        print(f" Base    : {args.db_path}")
    print("=" * 70)

    # ------------------------------------------------------------------
    # 1. Healthcheck
    # ------------------------------------------------------------------
    status, body = http_json(f"{base_url}/health", timeout=args.timeout)
    _expect(verdict, "1. Healthcheck /health", status, body, 200)

    # ------------------------------------------------------------------
    # 2. Autenticación legacy desactivada
    # ------------------------------------------------------------------
    status, body = http_json(
        f"{base_url}/api/v1/auth/login",
        method="POST",
        data={"username": "auditor", "password": "no-aplica"},
        timeout=args.timeout,
    )
    _expect(
        verdict,
        "2. Login legacy desactivado",
        status,
        body,
        410,
        "AUTH_DELEGATED_TO_KEYCLOAK",
    )

    # ------------------------------------------------------------------
    # 3. Token M2M OAuth 2.0
    # ------------------------------------------------------------------
    audit_token: Optional[str] = None
    try:
        credentials = resolve_credentials(args.creds, args.token_url)
        print(
            f"[INFO] Credenciales M2M: client_id={credentials['client_id']} "
            f"secret={redact(credentials['client_secret'])} "
            f"token_url={credentials['token_url']}"
        )
        audit_token = fetch_client_token(credentials, timeout=args.timeout)
        verdict.passed("3. Token OAuth 2.0 Client Credentials", "access_token obtenido")
    except Exception as exc:  # noqa: BLE001 - el motivo se reporta tal cual
        verdict.skipped(
            "3. Token OAuth 2.0 Client Credentials",
            f"no ejecutable: {exc}",
            blocking=True,
        )

    # ------------------------------------------------------------------
    # 4. Auditoría: lectura y cadena verificada por el servidor
    # ------------------------------------------------------------------
    if audit_token:
        status, body = http_json(
            f"{base_url}/api/v1/audit/events", token=audit_token, timeout=args.timeout
        )
        ok = _expect(verdict, "4. Lectura de auditoría", status, body, 200)
        if ok:
            verdict.check(
                body.get("audit_chain_valid") is True,
                "4a. Veredicto de cadena del servidor",
                "audit_chain_valid=True",
                f"audit_chain_valid={body.get('audit_chain_valid')} "
                f"chain_error={body.get('chain_error')}",
            )
            verdict.check(
                body.get("chain_error") in (None, ""),
                "4b. Sin error de cadena",
                "chain_error vacío",
                f"chain_error={body.get('chain_error')}",
            )
            verdict.check(
                isinstance(body.get("total_events"), int) and body["total_events"] >= 0,
                "4c. Contador de eventos presente",
                f"total_events={body.get('total_events')}",
                "total_events ausente o inválido",
            )

        # 4d. Menor privilegio: el token M2M no accede a datos clínicos (C-09)
        status, body = http_json(
            f"{base_url}/api/v1/orders", token=audit_token, timeout=args.timeout
        )
        _expect(
            verdict,
            "4d. M2M sin acceso a listado de órdenes (C-09)",
            status,
            body,
            403,
        )
        status, body = http_json(
            f"{base_url}/api/v1/orders",
            method="POST",
            token=audit_token,
            data={"order_id": f"{CANARY_PREFIX}DENIED", "patient_dni": "00000000"},
            timeout=args.timeout,
        )
        _expect(verdict, "4e. M2M sin alta de órdenes", status, body, 403)
        status, body = http_json(
            f"{base_url}/api/v1/orders/validate",
            method="POST",
            token=audit_token,
            data={"order_id": f"{CANARY_PREFIX}DENIED"},
            timeout=args.timeout,
        )
        _expect(verdict, "4f. M2M sin validación de órdenes", status, body, 403)
    else:
        verdict.skipped(
            "4. Auditoría y menor privilegio con token M2M",
            "requiere token OAuth (Keycloak)",
            blocking=True,
        )

    # ------------------------------------------------------------------
    # 5. Sin autenticación: el backend no expone operaciones clínicas
    # ------------------------------------------------------------------
    status, body = http_json(
        f"{base_url}/api/v1/orders", method="GET", timeout=args.timeout
    )
    _expect(verdict, "5. Listado de órdenes sin token rechazado", status, body, 401)
    status, body = http_json(
        f"{base_url}/api/v1/orders",
        method="POST",
        data={"order_id": f"{CANARY_PREFIX}ANON", "patient_dni": "00000000"},
        timeout=args.timeout,
    )
    _expect(verdict, "5a. Alta de orden anónima rechazada", status, body, 401)

    # ------------------------------------------------------------------
    # 6. Canal IoMT: pruebas negativas (no escriben datos clínicos)
    # ------------------------------------------------------------------
    probe_order = f"{CANARY_PREFIX}PROBE-{uuid.uuid4().hex[:12]}"
    device_keys = {}
    try:
        device_keys = load_device_keys()
    except RuntimeError as exc:
        verdict.failed("6. Configuración IoMT", str(exc))

    status, body = http_json(
        f"{base_url}/api/v1/iomt/results",
        method="POST",
        data={"order_id": probe_order, "measurements": {"plaquetas_k_ul": 250.0}},
        timeout=args.timeout,
    )
    channel_disabled = status == 503 and body.get("code") == "IOMT_NOT_CONFIGURED"
    if channel_disabled and args.allow_iomt_disabled:
        verdict.skipped(
            "6. Canal IoMT",
            "deshabilitado por configuración (--allow-iomt-disabled)",
            blocking=False,
        )
    elif channel_disabled:
        verdict.failed(
            "6. Canal IoMT configurado",
            "HTTP 503 IOMT_NOT_CONFIGURED: no hay claves de dispositivo (A-01 exige configuración explícita)",
        )
    else:
        _expect(
            verdict,
            "6. IoMT sin cabeceras rechazado",
            status,
            body,
            401,
            "IOMT_MISSING_CREDENTIALS",
        )

        unknown_headers = {
            "X-Device-Id": "IOMT-NO-REGISTRADO",
            "X-Device-Signature": "0" * 64,
            "X-Device-Timestamp": str(time.time()),
            "X-Device-Nonce": uuid.uuid4().hex,
        }
        _iomt_probe(
            verdict,
            base_url,
            "6a. Dispositivo desconocido rechazado",
            probe_order,
            unknown_headers,
            403,
            "IOMT_UNKNOWN_DEVICE",
        )

        if device_keys:
            device_id, device_key = next(iter(device_keys.items()))
            timestamp = str(time.time())
            nonce = uuid.uuid4().hex
            body_text = json.dumps(
                {"order_id": probe_order, "measurements": {"plaquetas_k_ul": 250.0}}
            )

            stale_headers = iomt_headers(
                device_key, device_id, str(time.time() - 3600), nonce, body_text
            )
            _iomt_probe(
                verdict,
                base_url,
                "6b. Marca temporal vencida rechazada",
                probe_order,
                stale_headers,
                401,
                "IOMT_STALE_TIMESTAMP",
            )

            bad_headers = iomt_headers(
                b"clave-ajena-de-prueba-0000000001", device_id, timestamp, nonce, body_text
            )
            _iomt_probe(
                verdict,
                base_url,
                "6c. Firma inválida rechazada",
                probe_order,
                bad_headers,
                403,
                "IOMT_INVALID_SIGNATURE",
            )

            good_headers = iomt_headers(device_key, device_id, timestamp, nonce, body_text)
            _iomt_probe(
                verdict,
                base_url,
                "6d. Orden inexistente no se crea (C-04)",
                probe_order,
                good_headers,
                404,
                "ORDER_NOT_FOUND",
            )
        else:
            verdict.skipped(
                "6b-6d. Pruebas IoMT con dispositivo válido",
                "IOMT_DEVICE_KEYS_JSON no provisto al verificador; el servidor sí tiene canal activo",
                blocking=False,
            )

    # ------------------------------------------------------------------
    # 7. Prueba positiva opcional con orden canario
    # ------------------------------------------------------------------
    if args.write_probe:
        if not args.canary_order_id or not args.canary_order_id.startswith(CANARY_PREFIX):
            verdict.failed(
                "7. Write-probe",
                f"--canary-order-id debe empezar con {CANARY_PREFIX} para no tocar datos reales",
            )
        elif not device_keys:
            verdict.failed(
                "7. Write-probe",
                "requiere IOMT_DEVICE_KEYS_JSON para firmar como dispositivo autorizado",
            )
        else:
            device_id, device_key = next(iter(device_keys.items()))
            measurement = 250.0
            payload = {
                "order_id": args.canary_order_id,
                "measurements": {"plaquetas_k_ul": measurement},
            }
            body_text = json.dumps(payload)
            headers = iomt_headers(
                device_key, device_id, str(time.time()), uuid.uuid4().hex, body_text
            )
            status, body = http_json(
                f"{base_url}/api/v1/iomt/results",
                method="POST",
                data=payload,
                headers=headers,
                timeout=args.timeout,
            )
            _expect(
                verdict,
                "7. Ingesta IoMT sobre orden canario",
                status,
                body,
                200,
            )
            if status == 200 and args.db_path:
                inspection = inspect_database(args.db_path)
                verdict.check(
                    inspection.get("chain_valid") is True,
                    "7a. Cadena íntegra tras la ingesta",
                    "chain_valid=True",
                    f"chain_valid={inspection.get('chain_valid')} "
                    f"error={inspection.get('chain_error')}",
                )

    # ------------------------------------------------------------------
    # 8. Persistencia y criptografía en disco
    # ------------------------------------------------------------------
    if args.db_path:
        inspection = inspect_database(args.db_path)
        if not inspection["exists"]:
            verdict.failed("8. Base SQLite", f"no existe {args.db_path}")
        else:
            verdict.check(
                inspection["integrity"] == "ok",
                "8. PRAGMA integrity_check",
                "ok",
                f"resultado={inspection['integrity']}",
            )
            verdict.check(
                (inspection["schema_version"] or 0) >= args.expected_schema_version,
                "8a. Versión de esquema",
                f"v{inspection['schema_version']} (mínimo v{args.expected_schema_version})",
                f"v{inspection['schema_version']} < v{args.expected_schema_version}",
            )
            verdict.check(
                inspection["journal_mode"] == "wal",
                "8b. journal_mode",
                "wal",
                f"journal_mode={inspection['journal_mode']}",
            )
            verdict.check(
                inspection["mode"] == 0o600,
                "8c. Permisos de la base (A-05)",
                "0600",
                f"modo={oct(inspection['mode']) if inspection['mode'] is not None else 'ausente'}",
            )
            verdict.check(
                inspection["anchor_mode"] == 0o600,
                "8d. Permisos del ancla de auditoría",
                "0600",
                f"modo={oct(inspection['anchor_mode']) if inspection['anchor_mode'] is not None else 'ausente'}",
            )
            verdict.check(
                inspection["chain_valid"] is True,
                "8e. Cadena de auditoría recalculada (C-07/C-08)",
                f"válida, {inspection['chain_details'].get('events_row_count')} eventos",
                f"inválida: {inspection['chain_error']}",
            )

    if args.deployed_dir:
        database_py = os.path.join(args.deployed_dir, "database.py")
        ok_policy, detail = durability_policy_ok(database_py)
        verdict.check(ok_policy, "9. Política de durabilidad desplegada", detail, detail)

        deployed_files = [
            os.path.join(args.deployed_dir, name)
            for name in (
                "server.py",
                "database.py",
                "jwt_validator.py",
                "clinical_domain.py",
            )
        ]
        # El monitor puede estar en audit_monitor/ (sandbox) o audit-monitor/ (despliegue).
        for monitor_candidate in (
            os.path.join(args.deployed_dir, "audit_monitor", "monitor.py"),
            os.path.abspath(
                os.path.join(args.deployed_dir, "..", "audit-monitor", "monitor.py")
            ),
        ):
            if os.path.isfile(monitor_candidate):
                deployed_files.append(monitor_candidate)
                break
        offenders = scan_forbidden_secrets(deployed_files)
        verdict.check(
            not offenders,
            "10. Sin secretos por defecto desplegados (A-01)",
            "ningún secreto embebido",
            "secretos embebidos en: " + ", ".join(offenders),
        )
        verdict.check(
            os.path.exists(os.path.join(args.deployed_dir, "clinical_domain.py")),
            "10a. Módulo de dominio clínico desplegado",
            "clinical_domain.py presente",
            "clinical_domain.py ausente: el backend no arrancaría",
        )

    if args.skip_identity:
        verdict.skipped(
            "11. Identidad canónica",
            "omitida por --skip-identity (solo pruebas aisladas)",
        )
    else:
        # ------------------------------------------------------------------
        # 11. Identidad canónica: un solo issuer para Windows, host y Docker
        # ------------------------------------------------------------------
        try:
            document = fetch_json_url(canonical_discovery_url(args.canonical_base), timeout=args.timeout)
        except Exception as exc:  # noqa: BLE001
            verdict.failed(
                "11. Discovery canónico alcanzable",
                f"{canonical_discovery_url(args.canonical_base)}: {exc}",
            )
        else:
            problems = issuer_document_problems(document, args.canonical_base)
            verdict.check(
                not problems,
                "11. Issuer canónico y endpoints coherentes",
                str(document.get("issuer", "")),
                "; ".join(problems),
            )

        if os.path.exists(args.compose_path):
            with open(args.compose_path, "r", encoding="utf-8", errors="replace") as handle:
                compose_text = handle.read()
            issuer = canonical_issuer(args.canonical_base)
            verdict.check(
                issuer in compose_text,
                "11a. Compose despliega el issuer canónico",
                issuer,
                "el compose no fija el issuer canónico (riesgo de split-horizon)",
            )
            verdict.check(
                "127.0.0.1:8085" not in compose_text.split("clinical-poc", 1)[-1][:2000],
                "11b. LIS sin discovery por loopback",
                "sin 127.0.0.1:8085 en el entorno del LIS",
                "el servicio clinical-poc conserva el discovery por loopback",
            )
        else:
            verdict.skipped("11a. Compose desplegado", f"no existe {args.compose_path}")

    return verdict


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verificación post-cutover del LIS (por defecto, solo lectura)"
    )
    parser.add_argument("--url", default=DEFAULT_BASE_URL, help="URL base del LIS")
    parser.add_argument("--db-path", default=None, help="Ruta al SQLite (se abre en solo lectura)")
    parser.add_argument("--creds", default=None, help="Archivo JSON o .env con credenciales M2M")
    parser.add_argument("--token-url", default=None, help="Endpoint de token OAuth")
    parser.add_argument("--deployed-dir", default=None, help="Directorio del backend desplegado")
    parser.add_argument("--canonical-base", default=CANONICAL_BASE_URL, help="Origen HTTPS canónico")
    parser.add_argument(
        "--skip-identity",
        action="store_true",
        help="Omite la comprobación de identidad (solo pruebas aisladas sin Keycloak)",
    )
    parser.add_argument(
        "--compose-path",
        default="/opt/sgsi-zta-hospital-lab/docker-compose.yml",
        help="Compose desplegado para verificar el contrato de identidad",
    )
    parser.add_argument("--expected-schema-version", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument(
        "--allow-iomt-disabled",
        action="store_true",
        help="Trata 503 IOMT_NOT_CONFIGURED como SKIP en lugar de FAIL",
    )
    parser.add_argument(
        "--write-probe",
        action="store_true",
        help="Habilita la prueba positiva de ingesta (requiere --canary-order-id)",
    )
    parser.add_argument(
        "--canary-order-id",
        default=None,
        help=f"Orden de prueba existente con prefijo {CANARY_PREFIX}",
    )
    parser.add_argument("--json", action="store_true", help="Salida JSON")
    parser.add_argument(
        "--read-only",
        action="store_true",
        help="Explícito: modo solo lectura (es el comportamiento por defecto)",
    )
    args = parser.parse_args()

    if args.read_only and args.write_probe:
        print("[ERROR] --read-only y --write-probe son mutuamente excluyentes.", file=sys.stderr)
        return 1

    verdict = run_verification(args)
    verdict.summary()
    if args.json:
        print(json.dumps(verdict.report(), indent=2, ensure_ascii=False))
    return verdict.exit_code()


if __name__ == "__main__":
    sys.exit(main())
