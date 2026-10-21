#!/usr/bin/env python3
"""
issuer_probe.py - Verifica coherencia de issuer en un endpoint canónico.

Comprueba, sin escribir nada:
  - DNS, TLS y discovery del origen canónico.
  - Que issuer, jwks_uri, token_endpoint y authorization_endpoint compartan origen.
  - Que el discovery no filtre loopback ni HTTP.
  - Que un token emitido lleve el issuer canónico y lo acepte el validador del LIS.
  - Que un issuer distinto sea rechazado (UntrustedIssuerError).
  - Que el cliente M2M del monitor obtenga token con el mismo issuer.

Uso:
  SSL_CERT_FILE=/ruta/ca.crt TEST_USER_PASSWORD=... TEST_MONITOR_SECRET=... \\
    python3 cutover_prep/issuer_probe.py --base-url https://host:8443

Códigos: 0 = todo PASS, 1 = algún FAIL.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import ssl
import sys
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
sys.path.insert(0, os.path.join(os.path.dirname(SCRIPT_DIR), "candidate_release"))

from cutover_common import (  # noqa: E402
    CANONICAL_BASE_URL,
    canonical_discovery_url,
    canonical_issuer,
    canonical_token_url,
    issuer_document_problems,
)

RESULTS: List[Tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}")


def ssl_context(ca_file: Optional[str]) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()


def fetch(
    url: str,
    ca_file: Optional[str],
    data: Optional[bytes] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Tuple[int, Dict[str, Any]]:
    request = urllib.request.Request(url, data=data, headers=headers or {})
    with urllib.request.urlopen(request, timeout=20, context=ssl_context(ca_file)) as response:
        return response.status, json.loads(response.read().decode("utf-8"))


def decode_payload(token: str) -> Dict[str, Any]:
    part = token.split(".")[1]
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part))


def audience_list(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value]
    return list(value or [])


def main() -> int:
    parser = argparse.ArgumentParser(description="Sonda de coherencia de issuer")
    parser.add_argument("--base-url", default=CANONICAL_BASE_URL)
    parser.add_argument("--ca-file", default=os.environ.get("SSL_CERT_FILE"))
    parser.add_argument("--client-id", default="issuer-test-client")
    parser.add_argument("--username", default="issuer-test-user")
    parser.add_argument("--password-env", default="TEST_USER_PASSWORD")
    parser.add_argument("--monitor-client-id", default="clinical-audit-monitor-service")
    parser.add_argument("--monitor-secret-env", default="TEST_MONITOR_SECRET")
    parser.add_argument("--expected-audience", default="clinical-poc-api")
    parser.add_argument("--skip-monitor", action="store_true")
    parser.add_argument("--skip-validator", action="store_true")
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()

    discovery_url = canonical_discovery_url(args.base_url)
    issuer = canonical_issuer(args.base_url)
    token_url = canonical_token_url(args.base_url)
    host = urllib.parse.urlsplit(args.base_url).hostname or ""

    print(f"base={args.base_url}")
    print(f"issuer_esperado={issuer}")
    print(f"ca_file={args.ca_file}")

    try:
        check(f"DNS resuelve {host}", True, socket.gethostbyname(host))
    except Exception as error:  # noqa: BLE001
        check(f"DNS resuelve {host}", False, repr(error))

    try:
        status, document = fetch(discovery_url, args.ca_file)
        check("discovery alcanzable", status == 200, f"HTTP {status}")
    except Exception as error:  # noqa: BLE001
        check("discovery alcanzable", False, repr(error))
        return _summary(args.as_json)

    problems = issuer_document_problems(document, args.base_url)
    check("issuer y endpoints coherentes", not problems, "; ".join(problems) or issuer)

    try:
        status, jwks = fetch(str(document.get("jwks_uri")), args.ca_file)
        keys = jwks.get("keys") or []
        check("JWKS alcanzable", status == 200 and bool(keys), f"{len(keys)} claves")
    except Exception as error:  # noqa: BLE001
        check("JWKS alcanzable", False, repr(error))

    password = os.environ.get(args.password_env, "")
    if not password:
        check("credencial de prueba provista", False, f"{args.password_env} ausente")
        return _summary(args.as_json)

    form = urllib.parse.urlencode(
        {
            "grant_type": "password",
            "client_id": args.client_id,
            "username": args.username,
            "password": password,
        }
    ).encode()
    try:
        _, response = fetch(
            str(document.get("token_endpoint") or token_url),
            args.ca_file,
            data=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        access_token = response["access_token"]
        payload = decode_payload(access_token)
        check("token emitido", True, f"azp={payload.get('azp')}")
        check("iss del token es el canónico", payload.get("iss") == issuer, str(payload.get("iss")))
        check(
            f"aud incluye {args.expected_audience}",
            args.expected_audience in audience_list(payload.get("aud")),
            str(audience_list(payload.get("aud"))),
        )
    except Exception as error:  # noqa: BLE001
        check("token emitido", False, repr(error))
        return _summary(args.as_json)

    if not args.skip_validator:
        try:
            from jwt_validator import UntrustedIssuerError, ZeroTrustJWTValidator

            validator = ZeroTrustJWTValidator(
                discovery_url=discovery_url, expected_audience=args.expected_audience
            )
            context = validator.validate_token(access_token)
            check("validador del LIS acepta el token", context.issuer == issuer, context.issuer)

            negative = ZeroTrustJWTValidator(
                discovery_url=discovery_url, expected_audience=args.expected_audience
            )
            negative.cache_manager._fetch_discovery()
            negative.cache_manager._expected_issuer = "https://atacante.invalid/realms/hospital-lab"
            try:
                negative.validate_token(access_token)
                check("rechaza un issuer distinto", False, "aceptó un issuer no confiable")
            except UntrustedIssuerError as error:
                check("rechaza un issuer distinto", True, str(error)[:90])
        except Exception as error:  # noqa: BLE001
            check("validador del LIS acepta el token", False, repr(error))

    if not args.skip_monitor:
        secret = os.environ.get(args.monitor_secret_env, "")
        if not secret:
            check("credencial M2M del monitor provista", False, f"{args.monitor_secret_env} ausente")
        else:
            try:
                form = urllib.parse.urlencode(
                    {
                        "grant_type": "client_credentials",
                        "client_id": args.monitor_client_id,
                        "client_secret": secret,
                    }
                ).encode()
                _, response = fetch(
                    token_url,
                    args.ca_file,
                    data=form,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                payload = decode_payload(response["access_token"])
                check("monitor obtiene token M2M", True, f"sub={payload.get('sub')}")
                check("monitor: iss canónico", payload.get("iss") == issuer, str(payload.get("iss")))
                check(
                    f"monitor: aud incluye {args.expected_audience}",
                    args.expected_audience in audience_list(payload.get("aud")),
                    str(audience_list(payload.get("aud"))),
                )
            except Exception as error:  # noqa: BLE001
                check("monitor obtiene token M2M", False, repr(error))

    return _summary(args.as_json)


def _summary(as_json: bool) -> int:
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    total = len(RESULTS)
    if as_json:
        print(
            json.dumps(
                {
                    "passed": passed,
                    "total": total,
                    "results": [
                        {"name": name, "ok": ok, "detail": detail}
                        for name, ok, detail in RESULTS
                    ],
                },
                indent=2,
            )
        )
    else:
        print(f"\nRESUMEN: {passed}/{total} PASS")
    return 0 if passed == total and total > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
