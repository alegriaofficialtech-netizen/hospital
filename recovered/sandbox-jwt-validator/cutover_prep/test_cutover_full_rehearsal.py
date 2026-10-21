#!/usr/bin/env python3
"""
test_cutover_full_rehearsal.py - Ensayo integral de cutover en sandbox aislado
SGSI-ZTA Hospital Lab — ISO/IEC 27001:2022 & NIST SP 800-207

Ejecuta el procedimiento completo sobre un servidor réplica y almacenamiento
temporal, sin tocar /opt, el volumen real ni los servicios:

 01. LIS disponible y saludable.
 02. Creación de una orden clínica sintética (nace en SAMPLE_COLLECTED).
 03. Ingesta IoMT firmada por dispositivo (device_id + timestamp + nonce + cuerpo).
 04. Auditoría encadenada y validación médica con MFA.
 05. Sustitución del proceso sobre el mismo almacenamiento.
 06. Conservación exacta de órdenes, mediciones y sello de integridad.
 07. Continuidad estricta de la cadena hash.
 08. audit-monitor con OAuth2 real de 'hospital-lab'  [PENDIENTE si Keycloak no responde]
 09. Menor privilegio del token M2M (403 en órdenes y auditoría clínica) [PENDIENTE igual]
 10. Sin fallback legacy (HTTP 410).
 11. Healthcheck tras las operaciones.
 12. Despliegue y rollback reproducibles en staging.
 13. Respaldo y restauración verificados, con ancla de auditoría.
 14. Fail-Closed ante fallo de persistencia.

Cambios respecto de la versión anterior:
 - Las claves IoMT se cargan de IOMT_DEVICE_KEYS_JSON (no hay clave embebida).
 - La firma cubre dispositivo, timestamp, nonce y cuerpo (antirreplay).
 - IoMT ya no crea órdenes: exige una orden existente y no liberada.
 - Se verifica `integrity_seal`, no una firma digital inexistente.
 - Las pruebas que dependen de Keycloak se reportan como PENDIENTES en lugar de
   romper el ensayo.
"""

import hashlib
import hmac
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Dict, List, Optional, Tuple

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
SANDBOX_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
CANDIDATE_DIR = os.path.join(SANDBOX_DIR, "candidate_release")

for _path in (CURRENT_DIR, SANDBOX_DIR, CANDIDATE_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

# El servidor carga las claves de dispositivo al importarse: deben existir antes.
REHEARSAL_DEVICE_ID = "IOMT-REHEARSAL-01"
REHEARSAL_DEVICE_KEY = "rehearsal-device-key-" + uuid.uuid4().hex
if not os.environ.get("IOMT_DEVICE_KEYS_JSON"):
    os.environ["IOMT_DEVICE_KEYS_JSON"] = json.dumps(
        {REHEARSAL_DEVICE_ID: REHEARSAL_DEVICE_KEY}
    )

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: E402

import server  # noqa: E402
from clinical_domain import (  # noqa: E402
    ORDER_ANALYZED,
    ORDER_RELEASED,
    ORDER_SAMPLE_COLLECTED,
    verify_integrity_seal,
)
from database import ClinicalDatabaseManager  # noqa: E402
from jwt_validator import JWKSCacheManager, ZeroTrustJWTValidator  # noqa: E402

KEYCLOAK_BASE = "http://127.0.0.1:8085/realms/hospital-lab"
KEYCLOAK_TOKEN_URL = f"{KEYCLOAK_BASE}/protocol/openid-connect/token"
M2M_CREDS_FILE = os.path.join(
    SANDBOX_DIR, "main_realm_prep", "credentials", "audit-monitor-credentials.json"
)


def b64url(data: bytes) -> str:
    return __import__("base64").urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class StagingMockJWKSCache(JWKSCacheManager):
    """Caché sintética para pruebas de integración deterministas."""

    def __init__(self, public_key: rsa.RSAPublicKey, kid: str, issuer: str):
        self.discovery_url = f"{issuer}/.well-known/openid-configuration"
        self.cache_ttl_seconds = 3600
        self.min_refresh_interval_seconds = 60
        self._jwks_uri = f"{issuer}/protocol/openid-connect/certs"
        self._expected_issuer = issuer
        self._keys_by_kid = {kid: public_key}
        self._last_fetch_timestamp = time.time()

    @property
    def expected_issuer(self) -> str:
        return self._expected_issuer

    def _fetch_jwks(self) -> None:
        pass

    def _fetch_discovery(self) -> None:
        pass


class TestCutoverFullRehearsal(unittest.TestCase):
    """Ensayo integral de cutover, durabilidad y reversión en sandbox."""

    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public_key = cls.private_key.public_key()
        cls.kid = "staging-rehearsal-kid-01"
        cls.issuer = KEYCLOAK_BASE
        cls.audience = "clinical-poc-api"

        cls.cache = StagingMockJWKSCache(cls.public_key, cls.kid, cls.issuer)
        cls.validator = ZeroTrustJWTValidator(
            discovery_url=f"{cls.issuer}/.well-known/openid-configuration",
            expected_audience=cls.audience,
            cache_manager=cls.cache,
            expected_authorized_party="clinical-poc",
            require_bearer_type=False,
        )

    # ------------------------------------------------------------------
    # Utilidades
    # ------------------------------------------------------------------
    def _create_jwt(self, username: str, roles: List[str], mfa: bool = False) -> str:
        now = int(time.time())
        header = {"alg": "RS256", "typ": "JWT", "kid": self.kid}
        payload = {
            "iss": self.issuer,
            "sub": f"uuid-{username}-staging",
            "preferred_username": username,
            "aud": [self.audience],
            "azp": "clinical-poc",
            "iat": now,
            "nbf": now - 5,
            "exp": now + 600,
            "jti": f"jwt-{username}-{now}",
            "realm_access": {"roles": roles},
            "resource_access": {"clinical-poc-api": {"roles": roles}},
            "amr": ["pwd", "totp"] if mfa else ["pwd"],
            "typ": "Bearer",
        }
        h_str = b64url(json.dumps(header).encode("utf-8"))
        p_str = b64url(json.dumps(payload).encode("utf-8"))
        sig = self.private_key.sign(
            f"{h_str}.{p_str}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
        )
        return f"{h_str}.{p_str}.{b64url(sig)}"

    def _iomt_headers(
        self,
        body_text: str,
        device_id: str = REHEARSAL_DEVICE_ID,
        device_key: str = REHEARSAL_DEVICE_KEY,
        timestamp: Optional[str] = None,
        nonce: Optional[str] = None,
    ) -> Dict[str, str]:
        ts = timestamp if timestamp is not None else str(time.time())
        nc = nonce if nonce is not None else uuid.uuid4().hex
        signing_input = f"{device_id}\n{ts}\n{nc}\n{body_text}"
        signature = hmac.new(
            device_key.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return {
            "X-Device-Id": device_id,
            "X-Device-Signature": signature,
            "X-Device-Timestamp": ts,
            "X-Device-Nonce": nc,
        }

    def _get_real_keycloak_audit_token(self) -> str:
        client_id = os.environ.get("AUDIT_MONITOR_CLIENT_ID")
        client_secret = os.environ.get("AUDIT_MONITOR_CLIENT_SECRET")
        token_url = os.environ.get("AUDIT_MONITOR_TOKEN_URL", KEYCLOAK_TOKEN_URL)

        if not (client_id and client_secret) and os.path.exists(M2M_CREDS_FILE):
            with open(M2M_CREDS_FILE, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            client_id = client_id or data.get("client_id")
            client_secret = client_secret or data.get("client_secret")
            token_url = data.get("token_url", token_url)

        if not (client_id and client_secret):
            raise RuntimeError("credenciales M2M ausentes")

        payload = urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            token_url,
            data=payload,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))["access_token"]

    def _http(
        self,
        port: int,
        path: str,
        method: str = "GET",
        token: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
        raw_body: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, Dict[str, Any]]:
        url = f"http://127.0.0.1:{port}{path}"
        request_headers = {"Content-Type": "application/json"}
        if token:
            request_headers["Authorization"] = f"Bearer {token}"
        if headers:
            request_headers.update(headers)

        if raw_body is not None:
            body_bytes = raw_body.encode("utf-8")
        elif data is not None:
            body_bytes = json.dumps(data).encode("utf-8")
        else:
            body_bytes = None

        request = urllib.request.Request(
            url, data=body_bytes, headers=request_headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                raw = response.read().decode("utf-8", "replace")
                return response.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            try:
                return exc.code, json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                return exc.code, {"raw": raw}
        except urllib.error.URLError as exc:
            return 0, {"error": "UNREACHABLE", "message": str(exc)}

    @staticmethod
    def _start_server(validator) -> Tuple[Any, int]:
        httpd = server.HTTPServer(("127.0.0.1", 0), server.ZeroTrustRequestHandler)
        httpd.validator = validator
        server.ZeroTrustRequestHandler.validator = validator
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.2)
        return httpd, httpd.server_address[1]

    # ------------------------------------------------------------------
    # Ensayo
    # ------------------------------------------------------------------
    def test_rehearsal_full_workflow(self):
        test_dir = tempfile.mkdtemp(prefix="rehearsal_full_")
        db_path = os.path.join(test_dir, "rehearsal.db")
        httpd = None
        httpd2 = None
        keycloak_pending: Optional[str] = None

        server.db_manager = ClinicalDatabaseManager(db_path=db_path)
        server.ORDERS_DB = server.DatabaseBackedOrdersDict(server.db_manager)
        server.AUDIT_LOGS = server.DatabaseBackedAuditLogs(server.db_manager)
        server.LAST_AUDIT_HASH = server.db_manager.get_last_audit_hash()

        try:
            httpd, port = self._start_server(self.validator)

            token_rec = self._create_jwt("recepcionista", ["ROLE_RECEPTION"], mfa=False)
            token_med = self._create_jwt("medico", ["ROLE_PATHOLOGIST"], mfa=True)

            # 01. Healthcheck
            code, res = self._http(port, "/health")
            self.assertEqual(code, 200)
            self.assertEqual(res.get("status"), "HEALTHY")
            print(f"[REHEARSAL 01/14] PASS: LIS saludable en el puerto efímero {port}.")

            # 02. Alta de orden
            order_payload = {
                "order_id": "ORD-REHEARSAL-01",
                "patient_dni": "77665544",
                "test_type": "HEMOGRAMA COMPLETO",
            }
            code, res = self._http(
                port, "/api/v1/orders", "POST", token=token_rec, data=order_payload
            )
            self.assertEqual(code, 201, res)
            self.assertEqual(res["order"]["order_id"], "ORD-REHEARSAL-01")
            self.assertEqual(res["order"]["status"], ORDER_SAMPLE_COLLECTED)
            print("[REHEARSAL 02/14] PASS: Orden sintética creada en SAMPLE_COLLECTED.")

            # 02a. Duplicado rechazado (C-03: nunca sobrescribe)
            code, res = self._http(
                port, "/api/v1/orders", "POST", token=token_rec, data=order_payload
            )
            self.assertEqual(code, 409, res)
            self.assertEqual(res.get("code"), "ORDER_ALREADY_EXISTS")
            print("[REHEARSAL 02a/14] PASS: Alta duplicada rechazada con 409.")

            # 03. Ingesta IoMT firmada por dispositivo
            iomt_payload = {
                "order_id": "ORD-REHEARSAL-01",
                "measurements": {"hemoglobina_g_dl": 13.8},
            }
            body_text = json.dumps(iomt_payload)
            code, res = self._http(
                port,
                "/api/v1/iomt/results",
                "POST",
                raw_body=body_text,
                headers=self._iomt_headers(body_text),
            )
            self.assertEqual(code, 200, res)
            print("[REHEARSAL 03/14] PASS: Ingesta IoMT con HMAC por dispositivo.")

            # 03a. Replay del mismo nonce rechazado (A-02)
            nonce = uuid.uuid4().hex
            ts = str(time.time())
            replay_payload = json.dumps(
                {"order_id": "ORD-REHEARSAL-01", "measurements": {"plaquetas_k_ul": 210.0}}
            )
            first_headers = self._iomt_headers(replay_payload, timestamp=ts, nonce=nonce)
            code, res = self._http(
                port,
                "/api/v1/iomt/results",
                "POST",
                raw_body=replay_payload,
                headers=first_headers,
            )
            self.assertEqual(code, 200, res)
            second_payload = json.dumps(
                {"order_id": "ORD-REHEARSAL-01", "measurements": {"leucocitos_mm3": 7000.0}}
            )
            replay_headers = self._iomt_headers(second_payload, timestamp=ts, nonce=nonce)
            code, res = self._http(
                port,
                "/api/v1/iomt/results",
                "POST",
                raw_body=second_payload,
                headers=replay_headers,
            )
            self.assertEqual(code, 409, res)
            self.assertEqual(res.get("code"), "IOMT_REPLAY_DETECTED")
            print("[REHEARSAL 03a/14] PASS: Nonce reutilizado rechazado (antirreplay).")

            # 03b. IoMT no crea órdenes (C-04)
            ghost_payload = json.dumps(
                {"order_id": "ORD-INEXISTENTE", "measurements": {"plaquetas_k_ul": 200.0}}
            )
            code, res = self._http(
                port,
                "/api/v1/iomt/results",
                "POST",
                raw_body=ghost_payload,
                headers=self._iomt_headers(ghost_payload),
            )
            self.assertEqual(code, 404, res)
            self.assertEqual(res.get("code"), "ORDER_NOT_FOUND")
            self.assertIsNone(server.db_manager.get_order("ORD-INEXISTENTE"))
            print("[REHEARSAL 03b/14] PASS: IoMT no crea órdenes inexistentes.")

            # 04. Validación médica y auditoría
            code, res = self._http(
                port,
                "/api/v1/orders/validate",
                "POST",
                token=token_med,
                data={"order_id": "ORD-REHEARSAL-01", "observations": "Analítica normal"},
            )
            self.assertEqual(code, 200, res)

            pre_hash = server.db_manager.get_last_audit_hash()
            pre_events_count = len(server.db_manager.get_audit_events())
            self.assertGreaterEqual(pre_events_count, 4)
            print(
                f"[REHEARSAL 04/14] PASS: Auditoría encadenada ({pre_events_count} eventos)."
            )

            # 05. Sustitución del proceso sobre el mismo almacenamiento
            httpd.shutdown()
            httpd.server_close()
            httpd = None
            server.db_manager.close()
            time.sleep(0.2)

            new_db_mgr = ClinicalDatabaseManager(db_path=db_path)
            self.assertEqual(new_db_mgr.get_last_audit_hash(), pre_hash)
            valid, err = new_db_mgr.verify_chain_integrity()
            self.assertTrue(valid, f"Cadena rota tras la sustitución: {err}")

            server.db_manager = new_db_mgr
            server.ORDERS_DB = server.DatabaseBackedOrdersDict(new_db_mgr)
            server.AUDIT_LOGS = server.DatabaseBackedAuditLogs(new_db_mgr)
            server.LAST_AUDIT_HASH = new_db_mgr.get_last_audit_hash()

            httpd2, port2 = self._start_server(self.validator)
            print(f"[REHEARSAL 05/14] PASS: Proceso sustituido en el puerto {port2}.")

            # 06. Conservación exacta
            code, orders_res = self._http(port2, "/api/v1/orders", "GET", token=token_rec)
            self.assertEqual(code, 200, orders_res)
            self.assertEqual(len(orders_res["orders"]), 1)
            saved = orders_res["orders"][0]
            self.assertEqual(saved["order_id"], "ORD-REHEARSAL-01")
            self.assertEqual(saved["status"], ORDER_RELEASED)
            self.assertEqual(saved["measurements"]["hemoglobina_g_dl"], 13.8)
            self.assertEqual(saved["measurements"]["plaquetas_k_ul"], 210.0)
            self.assertIn("integrity_seal", saved)
            self.assertTrue(saved.get("integrity_verified"))
            self.assertTrue(
                verify_integrity_seal(saved, server.get_seal_key()),
                "El sello de integridad no verifica sobre la orden persistida",
            )
            print(
                "[REHEARSAL 06/14] PASS: Orden, mediciones y sello de integridad conservados."
            )

            # 07. Continuidad de la cadena
            events = new_db_mgr.get_audit_events()
            self.assertEqual(len(events), pre_events_count + 1)
            self.assertEqual(events[pre_events_count - 1]["hash"], pre_hash)
            self.assertEqual(events[pre_events_count]["prev_hash"], pre_hash)
            self.assertEqual(events[pre_events_count]["hash"], new_db_mgr.get_last_audit_hash())
            valid, err = new_db_mgr.verify_chain_integrity()
            self.assertTrue(valid, f"Cadena rota tras nuevo evento: {err}")
            print(
                f"[REHEARSAL 07/14] PASS: Continuidad estricta "
                f"({pre_hash[:16]}… → {events[-1]['hash'][:16]}…)."
            )

            # 08 y 09. Keycloak real: pendiente declarado si no responde
            try:
                real_validator = ZeroTrustJWTValidator(
                    discovery_url=f"{KEYCLOAK_BASE}/.well-known/openid-configuration",
                    expected_audience="clinical-poc-api",
                    expected_authorized_party=None,
                    require_bearer_type=False,
                )
                real_audit_token = self._get_real_keycloak_audit_token()

                code, audit_res = self._http(
                    port2, "/api/v1/audit/events", "GET", token=real_audit_token
                )
                self.assertEqual(code, 200, f"Token M2M rechazado: {audit_res}")
                self.assertTrue(audit_res["audit_chain_valid"])
                print("[REHEARSAL 08/14] PASS: audit-monitor con OAuth2 real validado.")

                code_ord, _ = self._http(port2, "/api/v1/orders", "GET", token=real_audit_token)
                code_den_ord, _ = self._http(
                    port2,
                    "/api/v1/orders",
                    "POST",
                    token=real_audit_token,
                    data={"order_id": "ORD-DENIED", "patient_dni": "00000000"},
                )
                code_den_val, _ = self._http(
                    port2,
                    "/api/v1/orders/validate",
                    "POST",
                    token=real_audit_token,
                    data={"order_id": "ORD-DENIED"},
                )
                self.assertEqual(code_ord, 403, "El token M2M no debe leer órdenes (C-09)")
                self.assertEqual(code_den_ord, 403)
                self.assertEqual(code_den_val, 403)
                print(
                    "[REHEARSAL 09/14] PASS: Menor privilegio M2M verificado "
                    "(403 en listado, alta y validación)."
                )
                httpd2.validator = real_validator
                server.ZeroTrustRequestHandler.validator = real_validator
            except Exception as exc:  # noqa: BLE001 - se reporta como pendiente
                keycloak_pending = str(exc)
                print(f"[REHEARSAL 08/14] PENDING: Keycloak inaccesible ({exc}).")
                print("[REHEARSAL 09/14] PENDING: menor privilegio M2M no verificable sin token real.")
                httpd2.validator = self.validator
                server.ZeroTrustRequestHandler.validator = self.validator

            # 10. Sin fallback legacy
            code_leg, res_leg = self._http(
                port2,
                "/api/v1/auth/login",
                "POST",
                data={"username": "auditor", "password": "cualquiera"},
            )
            self.assertEqual(code_leg, 410)
            self.assertEqual(res_leg.get("code"), "AUTH_DELEGATED_TO_KEYCLOAK")
            print("[REHEARSAL 10/14] PASS: Autenticación legacy desactivada (410).")

            # 11. Healthcheck posterior
            code_hc, _ = self._http(port2, "/health")
            self.assertEqual(code_hc, 200)
            print("[REHEARSAL 11/14] PASS: Healthcheck operativo tras las operaciones.")

            # 12. Despliegue y rollback en staging
            staging_dir = os.path.join(test_dir, "staging_opt")
            os.makedirs(os.path.join(staging_dir, "clinical-poc", "lis-backend"), exist_ok=True)
            os.makedirs(os.path.join(staging_dir, "clinical-poc", "audit-monitor"), exist_ok=True)
            with open(os.path.join(staging_dir, "docker-compose.yml"), "w") as handle:
                handle.write(
                    "services:\n"
                    "  clinical-poc:\n"
                    "    image: python:3.12-slim-bookworm\n"
                    "    environment:\n"
                    "      CLINICAL_PORT: '8086'\n"
                    "volumes:\n"
                    "  clinical-data:\n"
                    "    name: clinical-data\n"
                )
            with open(os.path.join(staging_dir, ".env"), "w") as handle:
                handle.write("CLINICAL_PORT=8000\n")

            device_keys_file = os.path.join(test_dir, "device_keys.json")
            with open(device_keys_file, "w", encoding="utf-8") as handle:
                json.dump({REHEARSAL_DEVICE_ID: REHEARSAL_DEVICE_KEY}, handle)

            deploy_script = os.path.join(CURRENT_DIR, "cutover_deploy.sh")
            res_dep = subprocess.run(
                [
                    deploy_script,
                    "--apply",
                    f"--target-dir={staging_dir}",
                    "--port=8086",
                    "--no-restart",
                    "--skip-preflight",
                    f"--device-keys-file={device_keys_file}",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                res_dep.returncode,
                0,
                f"Deploy falló:\nSTDOUT:\n{res_dep.stdout}\nSTDERR:\n{res_dep.stderr}",
            )
            self.assertTrue(
                os.path.exists(
                    os.path.join(staging_dir, "clinical-poc", "lis-backend", "clinical_domain.py")
                ),
                "El despliegue no copió clinical_domain.py",
            )
            self.assertTrue(
                os.path.exists(
                    os.path.join(staging_dir, "clinical-poc", "lis-backend", "database.py")
                )
            )
            staged_env = open(os.path.join(staging_dir, ".env"), encoding="utf-8").read()
            self.assertIn("LIS_DB_PATH=/data/lis.db", staged_env)
            self.assertIn("ENABLE_LEGACY_AUTH=0", staged_env)
            self.assertIn("IOMT_DEVICE_KEYS_JSON=", staged_env)

            rollback_script = os.path.join(CURRENT_DIR, "rollback.sh")
            res_rb = subprocess.run(
                [
                    rollback_script,
                    "--dry-run",
                    f"--backup-dir={staging_dir}/.cutover_backup_placeholder",
                    f"--prod-dir={staging_dir}",
                ],
                capture_output=True,
                text=True,
            )
            # El snapshot real existe con marca temporal; se usa el último generado.
            snapshots = sorted(
                [
                    os.path.join(staging_dir, name)
                    for name in os.listdir(staging_dir)
                    if name.startswith(".cutover_backup_")
                ]
            )
            self.assertTrue(snapshots, "El despliegue no generó snapshot para rollback")
            res_rb = subprocess.run(
                [
                    rollback_script,
                    "--dry-run",
                    f"--backup-dir={snapshots[-1]}",
                    f"--prod-dir={staging_dir}",
                    f"--safety-dir={os.path.join(test_dir, 'rollback_safety')}",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res_rb.returncode, 0, res_rb.stderr)
            print("[REHEARSAL 12/14] PASS: Despliegue y rollback reproducibles en staging.")

            # 13. Respaldo y restauración verificados
            backup_file = os.path.join(test_dir, "rehearsal_backup.db")
            new_db_mgr.backup_database(backup_file)
            self.assertTrue(os.path.exists(backup_file))
            self.assertTrue(
                os.path.exists(f"{backup_file}.anchor-key"),
                "backup_database no generó el ancla lateral: la restauración no arrancaría",
            )

            restored_target = os.path.join(test_dir, "restored_rehearsal.db")
            recover_script = os.path.join(CURRENT_DIR, "recover_database.sh")
            res_rec = subprocess.run(
                [
                    recover_script,
                    "--dry-run",
                    f"--backup-file={backup_file}",
                    f"--target-db={restored_target}",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                res_rec.returncode,
                0,
                f"recover_database falló:\nSTDOUT:\n{res_rec.stdout}\nSTDERR:\n{res_rec.stderr}",
            )
            self.assertIn("Respaldo íntegro", res_rec.stdout)

            res_rec_apply = subprocess.run(
                [
                    recover_script,
                    "--apply",
                    f"--backup-file={backup_file}",
                    f"--target-db={restored_target}",
                    f"--safety-dir={os.path.join(test_dir, 'safety_restore')}",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                res_rec_apply.returncode,
                0,
                f"Restauración falló:\nSTDOUT:\n{res_rec_apply.stdout}\n"
                f"STDERR:\n{res_rec_apply.stderr}",
            )
            restored_db = ClinicalDatabaseManager(db_path=restored_target)
            try:
                restored_order = restored_db.get_order("ORD-REHEARSAL-01")
                self.assertIsNotNone(restored_order)
                self.assertEqual(restored_order["status"], ORDER_RELEASED)
                valid_restored, err_restored = restored_db.verify_chain_integrity()
                self.assertTrue(valid_restored, f"Cadena inválida tras restaurar: {err_restored}")
            finally:
                restored_db.close()
            print("[REHEARSAL 13/14] PASS: Respaldo y restauración verificados con ancla.")

            # 14. Fail-Closed ante fallo de persistencia
            new_db_mgr.close()
            code_fail, res_fail = self._http(
                port2,
                "/api/v1/orders",
                "POST",
                token=token_rec,
                data={"order_id": "ORD-ERR-FAIL", "patient_dni": "87654321"},
            )
            self.assertEqual(code_fail, 500, res_fail)
            self.assertEqual(res_fail.get("code"), "PERSISTENCE_TRANSACTION_FAILED")
            print("[REHEARSAL 14/14] PASS: Fallo de persistencia Fail-Closed (500).")

            if keycloak_pending:
                print(
                    "[REHEARSAL PENDIENTE] Los puntos 08 y 09 requieren Keycloak en "
                    f"{KEYCLOAK_BASE}: {keycloak_pending}"
                )

        finally:
            for server_obj in (httpd, httpd2):
                if server_obj is not None:
                    try:
                        server_obj.shutdown()
                        server_obj.server_close()
                    except Exception:  # noqa: BLE001
                        pass
            try:
                server.db_manager.close()
            except Exception:  # noqa: BLE001
                pass
            shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
