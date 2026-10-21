#!/usr/bin/env python3
"""Direct API E2E against the isolated local Keycloak + Python backend.

This test proves that authorization is enforced by the backend, not only by the
Angular route guards. It obtains real RS256 access tokens through Keycloak's
Authorization Code + PKCE flow, including a real TOTP challenge for the
pathologist, and then exercises the backend with each role.

Prerequisites:
- ``infra/local-test/start-local.ps1`` has started Keycloak and the backend.
- ``infra/local-test/.test-credentials.local.json`` exists.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "infra" / "local-test"))

import setup_realm  # noqa: E402


class TestFailure(AssertionError):
    pass


def check(condition: bool, message: str) -> None:
    if not condition:
        raise TestFailure(message)
    print(f"  PASS {message}")


def decode_jwt(token: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    try:
        header_b64, payload_b64, _ = token.split(".")
    except ValueError as exc:
        raise TestFailure("access token is not a three-part JWT") from exc

    def decode_part(part: str) -> Dict[str, Any]:
        padding = "=" * (-len(part) % 4)
        try:
            return json.loads(base64.urlsafe_b64decode(part + padding).decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise TestFailure("access token contains invalid base64 JSON") from exc

    return decode_part(header_b64), decode_part(payload_b64)


def api(
    base_url: str,
    method: str,
    path: str,
    *,
    token: Optional[str] = None,
    body: Optional[Any] = None,
    raw_body: Optional[bytes] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Tuple[int, Any]:
    data = raw_body if raw_body is not None else (
        json.dumps(body).encode("utf-8") if body is not None else None
    )
    request = urllib.request.Request(f"{base_url}{path}", data=data, method=method)
    request.add_header("Accept", "application/json")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = response.read()
            return response.status, json.loads(payload.decode("utf-8")) if payload else None
    except urllib.error.HTTPError as error:
        payload = error.read()
        try:
            parsed = json.loads(payload.decode("utf-8")) if payload else None
        except ValueError:
            parsed = payload.decode("utf-8", errors="replace")
        return error.code, parsed


def login(
    credentials: Dict[str, Any],
    username: str,
    *,
    base_url: str,
) -> Dict[str, Any]:
    record = credentials["users"][username]
    keycloak_url = credentials["issuer"].split("/realms/", 1)[0]
    realm = credentials["realm"]
    client_id = credentials["clientId"]
    redirect_uri = credentials["redirectUri"]
    secret = record.get("totp_secret")

    def attempt() -> Dict[str, Any]:
        flow = setup_realm.BrowserFlow(keycloak_url, realm, client_id, redirect_uri)
        return flow.login(username, record["password"], secret)

    try:
        return attempt()
    except setup_realm.SetupError:
        if not secret:
            raise
        # Keycloak rejects replay of the TOTP step used during enrollment.
        wait_seconds = 31 - (time.time() % 30)
        print(f"  Waiting {wait_seconds:.1f}s for a fresh TOTP window ...")
        time.sleep(wait_seconds + 1)
        return attempt()


def login_with_amr(
    credentials: Dict[str, Any],
    username: str,
    *,
    base_url: str,
    required_amr: Optional[str] = None,
) -> Dict[str, Any]:
    result: Optional[Dict[str, Any]] = None
    for attempt in range(3):
        result = login(credentials, username, base_url=base_url)
        amr = [str(item).lower() for item in result["claims"].get("amr", [])]
        if required_amr is None or required_amr in amr:
            return result
        print(f"  AMR {required_amr!r} missing on attempt {attempt + 1}; retrying ...")
        time.sleep(1.5)
    return result  # type: ignore[return-value]


def iomt_request(
    base_url: str,
    *,
    device_id: str,
    device_key: str,
    order_id: str,
    nonce: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> Tuple[int, Any, str, str]:
    body = json.dumps(
        {
            "order_id": order_id,
            "measurements": {
                "hemoglobina_g_dl": 13.7,
                "hematocrito_pct": 41.2,
                "leucocitos_mm3": 7200,
                "plaquetas_k_ul": 240,
            },
        },
        separators=(",", ":"),
    )
    timestamp = timestamp or str(time.time())
    nonce = nonce or secrets.token_hex(16)
    signing_input = f"{device_id}\n{timestamp}\n{nonce}\n{body}"
    signature = hmac.new(
        device_key.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    status, payload = api(
        base_url,
        "POST",
        "/api/v1/iomt/results",
        headers={
            "X-Device-Id": device_id,
            "X-Device-Timestamp": timestamp,
            "X-Device-Nonce": nonce,
            "X-Device-Signature": signature,
        },
        raw_body=body.encode("utf-8"),
    )
    return status, payload, nonce, timestamp


def expect_status(
    actual: Tuple[int, Any],
    expected_status: int,
    expected_code: Optional[str],
    label: str,
) -> Any:
    status, payload = actual
    check(status == expected_status, f"{label}: HTTP {status} == {expected_status}")
    if expected_code is not None:
        code = payload.get("code") if isinstance(payload, dict) else None
        check(code == expected_code, f"{label}: code {code!r} == {expected_code!r}")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument(
        "--audience",
        default=os.environ.get("KEYCLOAK_AUDIENCE", "clinical-poc-api"),
        help="Expected access-token audience for the F11 Keycloak client.",
    )
    parser.add_argument(
        "--credentials",
        type=Path,
        default=REPO_ROOT / "infra/local-test/.test-credentials.local.json",
    )
    parser.add_argument(
        "--secrets",
        type=Path,
        default=REPO_ROOT / "infra/local-test/runtime/backend-secrets.json",
    )
    args = parser.parse_args()

    if not args.credentials.exists():
        raise TestFailure(f"Credentials file not found: {args.credentials}")
    credentials = json.loads(args.credentials.read_text(encoding="utf-8"))
    secrets_data = json.loads(args.secrets.read_text(encoding="utf-8"))

    print("== Health and anonymous access ==")
    expect_status(api(args.base_url, "GET", "/health"), 200, None, "health")
    expect_status(
        api(args.base_url, "GET", "/api/v1/orders"),
        401,
        "MISSING_AUTHORIZATION_HEADER",
        "orders without token",
    )
    expect_status(
        api(args.base_url, "GET", "/api/v1/orders", token="not.a.jwt"),
        401,
        "INVALID_TOKEN_SIGNATURE",
        "orders with malformed token",
    )

    print("== Reception role ==")
    reception = login(credentials, "recepcion.test", base_url=args.base_url)
    reception_claims = reception["claims"]
    reception_header, raw_reception_claims = decode_jwt(reception["access_token"])
    check(reception_header.get("alg") == "RS256", "access token uses RS256")
    check(
        raw_reception_claims.get("iss") == credentials["issuer"],
        "access token issuer matches realm",
    )
    audience_claim = raw_reception_claims.get("aud")
    audiences = [audience_claim] if isinstance(audience_claim, str) else (audience_claim or [])
    check(args.audience in audiences, f"access token audience contains {args.audience}")
    check(
        raw_reception_claims.get("azp") == credentials["clientId"],
        "access token azp matches client",
    )
    check("admision" in reception_claims["realm_access"]["roles"], "reception token has admision role")
    expect_status(
        api(args.base_url, "GET", "/api/v1/orders", token=reception["access_token"]),
        200,
        None,
        "reception lists orders",
    )
    order_id = f"ORD-E2E-{int(time.time())}"
    patient_dni = f"DEMO-E2E-{int(time.time())}"
    created = expect_status(
        api(
            args.base_url,
            "POST",
            "/api/v1/orders",
            token=reception["access_token"],
            body={
                "order_id": order_id,
                "patient_dni": patient_dni,
                "test_type": "HEMOGLOBIN COMPLETE",
            },
        ),
        201,
        None,
        "reception creates order",
    )
    check(created["order"]["status"] == "SAMPLE_COLLECTED", "new order starts as SAMPLE_COLLECTED")
    expect_status(
        api(
            args.base_url,
            "POST",
            "/api/v1/orders",
            token=reception["access_token"],
            body={
                "order_id": order_id,
                "patient_dni": patient_dni,
                "test_type": "HEMOGLOBIN COMPLETE",
            },
        ),
        409,
        "ORDER_ALREADY_EXISTS",
        "duplicate order rejected",
    )
    expect_status(
        api(
            args.base_url,
            "POST",
            "/api/v1/orders/validate",
            token=reception["access_token"],
            body={"order_id": order_id},
        ),
        403,
        "PATHOLOGIST_ROLE_REQUIRED",
        "reception cannot validate",
    )
    expect_status(
        api(args.base_url, "GET", "/api/v1/audit/events", token=reception["access_token"]),
        403,
        "AUDITOR_ROLE_REQUIRED",
        "reception cannot read audit",
    )

    print("== Laboratory role ==")
    laboratory = login_with_amr(credentials, "laboratorio.test", base_url=args.base_url)
    check("laboratorio" in laboratory["claims"]["realm_access"]["roles"], "lab token has laboratorio role")
    expect_status(
        api(args.base_url, "GET", "/api/v1/orders", token=laboratory["access_token"]),
        200,
        None,
        "laboratory lists orders",
    )
    expect_status(
        api(
            args.base_url,
            "POST",
            "/api/v1/orders",
            token=laboratory["access_token"],
            body={
                "order_id": f"ORD-LAB-DENIED-{int(time.time())}",
                "patient_dni": "DEMO-LAB-DENIED",
                "test_type": "HEMOGLOBIN COMPLETE",
            },
        ),
        403,
        "RECEPTION_ROLE_REQUIRED",
        "laboratory cannot create orders",
    )
    expect_status(
        api(
            args.base_url,
            "POST",
            "/api/v1/orders/validate",
            token=laboratory["access_token"],
            body={"order_id": order_id},
        ),
        403,
        "PATHOLOGIST_ROLE_REQUIRED",
        "laboratory cannot validate",
    )

    print("== IoMT analyzer channel ==")
    iomt = iomt_request(
        args.base_url,
        device_id=secrets_data["iomtDeviceId"],
        device_key=secrets_data["iomtDeviceKey"],
        order_id=order_id,
    )
    expect_status((iomt[0], iomt[1]), 200, None, "analyzer posts results")
    iomt_payload = iomt[1]
    check(iomt_payload["order_status"] == "ANALYZED", "analyzer moves order to ANALYZED")
    # Replay the exact same signed request to prove nonce replay protection.
    replay = iomt_request(
        args.base_url,
        device_id=secrets_data["iomtDeviceId"],
        device_key=secrets_data["iomtDeviceKey"],
        order_id=order_id,
        nonce=iomt[2],
        timestamp=iomt[3],
    )
    expect_status((replay[0], replay[1]), 409, "IOMT_REPLAY_DETECTED", "replayed analyzer request rejected")

    print("== Pathologist without MFA ==")
    no_mfa = login_with_amr(credentials, "medico.sinmfa", base_url=args.base_url)
    check(
        "medico" in no_mfa["claims"]["realm_access"]["roles"],
        "pathologist-without-MFA token has medico role",
    )
    no_mfa_amr = [str(item).lower() for item in no_mfa["claims"].get("amr", [])]
    check("otp" not in no_mfa_amr, "pathologist-without-MFA token has no otp AMR")
    expect_status(
        api(
            args.base_url,
            "POST",
            "/api/v1/orders/validate",
            token=no_mfa["access_token"],
            body={"order_id": order_id, "observations": "No MFA"},
        ),
        403,
        "MFA_AUTHENTICATION_REQUIRED",
        "backend denies validation without MFA",
    )

    print("== Pathologist with real TOTP ==")
    check(
        bool(credentials["users"]["medico.test"].get("totp_secret")),
        "medico.test has a real TOTP secret",
    )
    pathologist = login_with_amr(
        credentials, "medico.test", base_url=args.base_url, required_amr="otp"
    )
    amr = [str(item).lower() for item in pathologist["claims"].get("amr", [])]
    check("otp" in amr, "pathologist token contains otp AMR")
    check(
        "mfa-required" in pathologist["claims"]["realm_access"]["roles"],
        "pathologist token contains mfa-required role",
    )
    released = expect_status(
        api(
            args.base_url,
            "POST",
            "/api/v1/orders/validate",
            token=pathologist["access_token"],
            body={"order_id": order_id, "observations": "Synthetic E2E release"},
        ),
        200,
        None,
        "pathologist validates with MFA",
    )
    released_order = released["order"]
    check(
        released_order["status"] == "VALIDATED_AND_RELEASED",
        "order is VALIDATED_AND_RELEASED",
    )
    check(bool(released_order.get("integrity_seal")), "released order has an integrity seal")
    check(
        released_order.get("validated_by") == "medico.test",
        "released order records the pathologist",
    )
    expect_status(
        api(
            args.base_url,
            "POST",
            "/api/v1/orders/validate",
            token=pathologist["access_token"],
            body={"order_id": order_id, "observations": "Second release"},
        ),
        409,
        "ORDER_ALREADY_VALIDATED",
        "released order cannot be validated twice",
    )
    expect_status(
        api(
            args.base_url,
            "POST",
            "/api/v1/orders",
            token=pathologist["access_token"],
            body={
                "order_id": f"ORD-PATH-DENIED-{int(time.time())}",
                "patient_dni": "DEMO-PATH-DENIED",
                "test_type": "HEMOGLOBIN COMPLETE",
            },
        ),
        403,
        "RECEPTION_ROLE_REQUIRED",
        "pathologist cannot create orders",
    )

    print("== Security auditor role ==")
    auditor = login_with_amr(credentials, "auditor.test", base_url=args.base_url)
    check("auditor" in auditor["claims"]["realm_access"]["roles"], "auditor token has auditor role")
    audit = expect_status(
        api(args.base_url, "GET", "/api/v1/audit/events", token=auditor["access_token"]),
        200,
        None,
        "auditor reads audit events",
    )
    check(audit["audit_chain_valid"] is True, "audit chain is valid")
    actions = [event.get("action") for event in audit["events"]]
    for expected_action in ("CREATE_ORDER", "IOMT_INGEST", "VALIDATE_ORDER", "GET_AUDIT_LOGS"):
        check(expected_action in actions, f"audit contains {expected_action}")
    validate_event = next(
        event for event in reversed(audit["events"]) if event.get("action") == "VALIDATE_ORDER"
    )
    check(validate_event.get("mfa_verified") is True, "validation audit event records MFA")
    expect_status(
        api(args.base_url, "GET", "/api/v1/orders", token=auditor["access_token"]),
        403,
        "INSUFFICIENT_ROLE_PERMISSIONS",
        "auditor cannot list clinical orders",
    )
    expect_status(
        api(
            args.base_url,
            "POST",
            "/api/v1/orders",
            token=auditor["access_token"],
            body={
                "order_id": f"ORD-AUD-DENIED-{int(time.time())}",
                "patient_dni": "DEMO-AUD-DENIED",
                "test_type": "HEMOGLOBIN COMPLETE",
            },
        ),
        403,
        "RECEPTION_ROLE_REQUIRED",
        "auditor cannot create orders",
    )

    print("== Order integrity after release ==")
    orders = expect_status(
        api(args.base_url, "GET", "/api/v1/orders", token=pathologist["access_token"]),
        200,
        None,
        "pathologist lists released orders",
    )
    released_view = next(order for order in orders["orders"] if order["order_id"] == order_id)
    check(released_view["integrity_verified"] is True, "released order integrity seal verifies")

    print("PASS: direct backend E2E completed with real Keycloak tokens.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except TestFailure as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
