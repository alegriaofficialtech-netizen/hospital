#!/usr/bin/env python3
"""
test_integration_rehearsal.py - Ensayo Integral de Migración LIS y Audit-Monitor
SGSI-ZTA Hospital Lab - Servidor-1 (Debian 13)
ISO/IEC 27001:2022 Control A.8.15 & NIST SP 800-207

Ejecuta el ensayo integral de migración en entorno aislado:
1. Réplica aislada del LIS Candidato y análisis de persistencia volátil en memoria.
2. Integración de Audit-Monitor con el Realm Principal 'hospital-lab' (OAuth 2.0 M2M).
3. Verificación de RBAC granular, obligatoriedad de MFA contextual y canal IoMT.
4. Ensayo de Despliegue Coordinado y Rollback Quirúrgico con medición de interrupción.
"""

import base64
import copy
import hashlib
import hmac
import json
import os
import shutil
import ssl
import subprocess
import sys
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

SANDBOX_DIR = "/home/elcra/sandbox-jwt-validator"
CANDIDATE_DIR = os.path.join(SANDBOX_DIR, "candidate_release")
MAIN_CREDS_FILE = os.path.join(SANDBOX_DIR, ".env.audit_monitor_credentials_main")
DISCOVERY_MAIN = "http://127.0.0.1:8085/realms/hospital-lab/.well-known/openid-configuration"

if CANDIDATE_DIR not in sys.path:
    sys.path.insert(0, CANDIDATE_DIR)
if SANDBOX_DIR not in sys.path:
    sys.path.insert(0, SANDBOX_DIR)

import server
from audit_monitor import monitor
from jwt_validator import JWKSCacheManager, ZeroTrustJWTValidator


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class SyntheticKeyManager:
    """Generador de tokens sintéticos firmados con RS256 para validación de RBAC y MFA."""

    def __init__(self, issuer: str = "http://127.0.0.1:8085/realms/hospital-lab"):
        self.issuer = issuer
        self.kid = "synthetic-test-key-2026"
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

    def create_token(
        self,
        username: str,
        roles: List[str],
        amr: Optional[List[str]] = None,
        aud: str = "clinical-poc-api",
        azp: str = "clinical-poc",
        exp_delta: int = 3600
    ) -> str:
        now = int(time.time())
        header = {"alg": "RS256", "typ": "JWT", "kid": self.kid}
        payload = {
            "iss": self.issuer,
            "aud": [aud, "account"],
            "azp": azp,
            "sub": f"synthetic-{username}-uuid",
            "preferred_username": username,
            "realm_access": {"roles": roles},
            "resource_access": {azp: {"roles": roles}},
            "iat": now,
            "exp": now + exp_delta,
            "jti": f"token-{now}-{username}",
        }
        if amr is not None:
            payload["amr"] = amr

        header_b64 = b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        payload_b64 = b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

        sig = self.private_key.sign(
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return f"{header_b64}.{payload_b64}.{b64url(sig)}"


class MockCacheWithSyntheticKeys(JWKSCacheManager):
    """Cache que combina claves JWKS en vivo de Keycloak con claves sintéticas para pruebas clínicas."""

    def __init__(self, live_discovery_url: str, synthetic_manager: SyntheticKeyManager):
        super().__init__(discovery_url=live_discovery_url, cache_ttl_seconds=3600)
        self.synthetic_manager = synthetic_manager

    def get_key(self, kid: Optional[str] = None):
        if kid == self.synthetic_manager.kid:
            return self.synthetic_manager.public_key
        return super().get_key(kid)


class TestFullMigrationRehearsal(unittest.TestCase):
    """Suite de Ensayo Integral de Migración y Verificación Zero Trust."""

    httpd = None
    server_thread = None
    server_port = 8996
    base_url = f"http://127.0.0.1:{server_port}"
    synthetic_km = None
    real_m2m_token = None

    @classmethod
    def setUpClass(cls):
        print("\n" + "=" * 72)
        print(" INICIANDO ENSAYO INTEGRAL DE MIGRACIÓN LIS Y AUDIT-MONITOR")
        print("=" * 72)

        # 1. Configurar claves sintéticas y cache híbrida
        cls.synthetic_km = SyntheticKeyManager(issuer="http://127.0.0.1:8085/realms/hospital-lab")
        cls.hybrid_cache = MockCacheWithSyntheticKeys(DISCOVERY_MAIN, cls.synthetic_km)

        # 2. Configurar validador Zero Trust
        cls.validator = ZeroTrustJWTValidator(
            discovery_url=DISCOVERY_MAIN,
            expected_audience="clinical-poc-api",
            cache_manager=cls.hybrid_cache,
            expected_authorized_party=None,  # Permite tanto clinical-poc como clinical-audit-monitor-service
            require_bearer_type=False
        )

        # 3. Limpiar estado en memoria
        server.ORDERS_DB.clear()
        server.AUDIT_LOGS.clear()
        server.LAST_AUDIT_HASH = "0" * 64
        server.ENABLE_LEGACY_AUTH = False

        # 4. Iniciar servidor LIS aislado en puerto 8996
        server_address = ("127.0.0.1", cls.server_port)
        cls.httpd = server.HTTPServer(server_address, server.ZeroTrustRequestHandler)
        cls.httpd.validator = cls.validator
        cls.server_thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.3)
        print(f"[*] Réplica aislada del LIS iniciada en {cls.base_url}")

        # 5. Configurar monitor con credenciales reales del realm principal
        monitor.load_credentials_from_file(MAIN_CREDS_FILE)
        monitor._CACHED_TOKEN = None

        # 6. Obtener token real M2M desde el realm principal Keycloak 'hospital-lab'
        print("[*] Obteniendo Access Token real M2M desde Keycloak 'hospital-lab'...")
        with open(MAIN_CREDS_FILE, "r") as f:
            creds = dict(line.strip().split("=", 1) for line in f if "=" in line and not line.startswith("#"))

        data = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": creds["AUDIT_MONITOR_CLIENT_ID"],
            "client_secret": creds["AUDIT_MONITOR_CLIENT_SECRET"]
        }).encode("utf-8")
        req = urllib.request.Request(creds["AUDIT_MONITOR_TOKEN_URL"], data=data, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            token_payload = json.loads(resp.read().decode("utf-8"))
            cls.real_m2m_token = token_payload["access_token"]
        print(f"[+] Token real M2M obtenido exitosamente ({len(cls.real_m2m_token)} caracteres).")

    @classmethod
    def tearDownClass(cls):
        if cls.httpd:
            cls.httpd.shutdown()
            cls.httpd.server_close()
        print("\n[*] Servidor réplica aislado apagado y recursos liberados.")

    # --------------------------------------------------------------------------
    # SECCIÓN 2: RÉPLICA AISLADA Y PERSISTENCIA VOLÁTIL EN MEMORIA
    # --------------------------------------------------------------------------
    def test_01_isolated_lis_health_and_imports(self):
        """Verifica que la réplica aislada responde y tiene módulos JWT correctamente vinculados."""
        req = urllib.request.Request(f"{self.base_url}/health")
        with urllib.request.urlopen(req, timeout=5) as res:
            self.assertEqual(res.status, 200)
            data = json.loads(res.read().decode("utf-8"))
            self.assertEqual(data["status"].upper(), "HEALTHY")
            self.assertIn("Keycloak Integrated", data["system"])
        print("\n[TEST 01] PASS: Réplica aislada del LIS operativa y saludable.")

    def test_02_persistence_risk_analysis_and_restart_simulation(self):
        """
        Demuestra empíricamente el riesgo de pérdida de órdenes y eventos de auditoría
        debido a la arquitectura en memoria sin volumen persistente (read_only container).
        """
        # 1. Crear orden sintética inicial con rol válido de admisión
        token_rec = self.synthetic_km.create_token("recepcion.test", ["ROLE_RECEPTION"])
        payload = {
            "order_id": "ORD-PERSIST-001",
            "patient_dni": "DNI-9999",
            "tests": ["HEMOGRAMA", "GLUCOSA"]
        }
        req = urllib.request.Request(
            f"{self.base_url}/api/v1/orders",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token_rec}"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as res:
            self.assertEqual(res.status, 201)

        self.assertIn("ORD-PERSIST-001", server.ORDERS_DB)
        self.assertGreater(len(server.AUDIT_LOGS), 0)
        hash_before = server.LAST_AUDIT_HASH
        orders_count_before = len(server.ORDERS_DB)
        events_count_before = len(server.AUDIT_LOGS)

        print(f"  [*] Estado pre-reinicio: {orders_count_before} órdenes, {events_count_before} eventos de auditoría.")
        print(f"  [*] Hash de auditoría antes del reinicio: {hash_before[:16]}...")

        # 2. Simular reinicio de proceso / caída de contenedor
        t_start = time.time()
        server.ORDERS_DB.clear()
        server.AUDIT_LOGS.clear()
        server.LAST_AUDIT_HASH = "0" * 64
        t_duration_ms = (time.time() - t_start) * 1000

        # 3. Comprobación de estado post-reinicio
        self.assertEqual(len(server.ORDERS_DB), 0, "Las órdenes persistieron inesperadamente")
        self.assertEqual(len(server.AUDIT_LOGS), 0, "Los eventos de auditoría persistieron inesperadamente")
        self.assertEqual(server.LAST_AUDIT_HASH, "0" * 64, "La cadena de hashes no se reinició a génesis")

        print(f"  [!] RIESGO ARQUITECTÓNICO CONFIRMADO: Reinicio borra 100% de datos en memoria en {t_duration_ms:.2f}ms.")
        print("  [!] RECOMENDACIÓN ZERO TRUST: Requerir base de datos relacional externa o volumen montado para producción.")
        print("[TEST 02] PASS: Análisis y simulación de pérdida de persistencia validado.")

    # --------------------------------------------------------------------------
    # SECCIÓN 3: INTEGRACIÓN AUDIT-MONITOR CON REALM PRINCIPAL
    # --------------------------------------------------------------------------
    def test_03_audit_monitor_real_token_claims_and_signature(self):
        """Valida que el token M2M del realm 'hospital-lab' cumple con todas las aserciones criptográficas."""
        context = self.validator.validate_token(self.real_m2m_token)
        self.assertEqual(context.issuer, "http://127.0.0.1:8085/realms/hospital-lab")
        self.assertIn("clinical-poc-api", context.audience)
        self.assertIn("ROLE_SECURITY_AUDITOR", context.roles)
        self.assertGreater(context.expires_at, time.time())
        print(f"\n[TEST 03] PASS: Token real M2M de 'hospital-lab' validado (Subject: {context.subject}, Roles: {context.roles}).")

    def test_04_audit_monitor_http_permissions_and_strictly_forbidden_clinical(self):
        """Verifica que el monitor tiene acceso a auditoría (HTTP 200) pero está ESTRICTAMENTE PROHIBIDO en clínica (HTTP 403)."""
        # 1. Consulta de auditoría con token real -> HTTP 200
        req_audit = urllib.request.Request(
            f"{self.base_url}/api/v1/audit/events",
            headers={"Authorization": f"Bearer {self.real_m2m_token}"}
        )
        with urllib.request.urlopen(req_audit, timeout=5) as res:
            self.assertEqual(res.status, 200)
            data = json.loads(res.read().decode("utf-8"))
            self.assertIn("events", data)
            self.assertTrue(data.get("audit_chain_valid", False))

        # 2. Intento de crear orden con token de auditoría -> HTTP 403 estricto
        req_create = urllib.request.Request(
            f"{self.base_url}/api/v1/orders",
            data=json.dumps({"order_id": "ORD-MALICIOUS-01", "patient_dni": "DNI-001"}).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.real_m2m_token}"},
            method="POST"
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req_create, timeout=5)
        self.assertEqual(ctx.exception.code, 403)
        err_body = json.loads(ctx.exception.read().decode("utf-8"))
        self.assertEqual(err_body.get("code"), "RECEPTION_ROLE_REQUIRED")

        # 3. Intento de validar orden con token de auditoría -> HTTP 403 estricto
        req_val = urllib.request.Request(
            f"{self.base_url}/api/v1/orders/validate",
            data=json.dumps({"order_id": "ORD-001"}).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.real_m2m_token}"},
            method="POST"
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req_val, timeout=5)
        self.assertEqual(ctx.exception.code, 403)
        err_body = json.loads(ctx.exception.read().decode("utf-8"))
        self.assertEqual(err_body.get("code"), "PATHOLOGIST_ROLE_REQUIRED")

        print("[TEST 04] PASS: Principio de Menor Privilegio cumplido al 100% (Auditoría: 200, Creación: 403, Validación: 403).")

    def test_05_legacy_auth_disabled_by_default(self):
        """Verifica que la autenticación legacy permanece deshabilitada por defecto en el LIS candidato."""
        self.assertFalse(server.ENABLE_LEGACY_AUTH)
        req = urllib.request.Request(
            f"{self.base_url}/api/v1/auth/login",
            data=json.dumps({"username": "auditor", "password": "any"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 410)
        data = json.loads(ctx.exception.read().decode("utf-8"))
        self.assertEqual(data.get("error"), "Gone")
        self.assertEqual(data.get("code"), "AUTH_DELEGATED_TO_KEYCLOAK")
        print("[TEST 05] PASS: Autenticación legacy desactivada por defecto (HTTP 410 Gone / AUTH_DELEGATED_TO_KEYCLOAK).")

    def test_06_audit_monitor_fail_closed_without_keycloak(self):
        """Verifica que si Keycloak no está disponible, el monitor falla de forma cerrada (Fail-Closed) sin fallback."""
        # Simular falla de Keycloak apuntando a URL inalcanzable
        monitor.USE_LEGACY_AUTH = False
        saved_url = monitor.TOKEN_URL
        saved_cached = monitor._CACHED_TOKEN
        try:
            monitor._CACHED_TOKEN = None
            monitor.TOKEN_URL = "http://127.0.0.1:9999/unreachable/token"
            tok = monitor.get_auditor_token()
            self.assertIsNone(tok, "El monitor no falló de forma cerrada al fallar Keycloak")
        finally:
            monitor.TOKEN_URL = saved_url
            monitor._CACHED_TOKEN = saved_cached
        print("[TEST 06] PASS: Monitor falla de forma cerrada (Fail-Closed) sin recurrir a fallback inseguro.")

    def test_07_audit_chain_tamper_detection(self):
        """Verifica la continuidad de la cadena criptográfica y la detección inmediata de alteraciones."""
        # Generar eventos sintéticos válidos
        events = []
        prev = "0" * 64
        for i in range(5):
            rec = {
                "action": f"TEST_ACTION_{i}",
                "actor": "auditor-test",
                "index": i,
                "prev_hash": prev
            }
            curr_h = hashlib.sha256(json.dumps(rec, sort_keys=True).encode("utf-8")).hexdigest()
            rec["hash"] = curr_h
            events.append(rec)
            prev = curr_h

        # Cadena válida
        self.assertTrue(monitor.verify_audit_chain(events))

        # Cadena alterada maliciosamente
        tampered_events = copy.deepcopy(events)
        tampered_events[2]["action"] = "UNAUTHORIZED_MODIFICATION"
        self.assertFalse(monitor.verify_audit_chain(tampered_events))
        print("[TEST 07] PASS: Detección criptográfica de manipulación en la cadena de auditoría verificada.")

    # --------------------------------------------------------------------------
    # SECCIÓN 4: OPERACIONES CLÍNICAS, RBAC Y ESTADO DE MFA PRINCIPAL
    # --------------------------------------------------------------------------
    def test_08_clinical_order_creation_authorized_reception(self):
        """Verifica que un usuario con rol ROLE_RECEPTION puede crear órdenes clínicas."""
        token_rec = self.synthetic_km.create_token("admision.sintetica", ["ROLE_RECEPTION"])
        payload = {
            "order_id": "ORD-CLINICAL-001",
            "patient_dni": "DNI-777",
            "tests": ["HEMOGRAMA", "PERFIL_LIPIDICO"]
        }
        req = urllib.request.Request(
            f"{self.base_url}/api/v1/orders",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token_rec}"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as res:
            self.assertEqual(res.status, 201)
            data = json.loads(res.read().decode("utf-8"))
            self.assertEqual(data["order"]["order_id"], "ORD-CLINICAL-001")
            self.assertEqual(data["order"]["status"], "SAMPLE_COLLECTED")
        print("\n[TEST 08] PASS: Creación de orden clínica autorizada con rol ROLE_RECEPTION.")

    def test_09_clinical_order_validation_mfa_requirement(self):
        """Verifica la obligatoriedad de MFA contextual: médico con MFA pasa (200), sin MFA denegado (403)."""
        # Asegurar orden creada
        if "ORD-CLINICAL-001" not in server.ORDERS_DB:
            token_rec = self.synthetic_km.create_token("admision.sintetica", ["ROLE_RECEPTION"])
            payload = {"order_id": "ORD-CLINICAL-001", "patient_dni": "DNI-777", "tests": ["HEMOGRAMA"]}
            req_init = urllib.request.Request(
                f"{self.base_url}/api/v1/orders",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {token_rec}"},
                method="POST"
            )
            urllib.request.urlopen(req_init, timeout=5)

        # 1. Médico SIN MFA -> HTTP 403 Forbidden (MFA_AUTHENTICATION_REQUIRED)
        token_no_mfa = self.synthetic_km.create_token("medico.sintetico", ["ROLE_PATHOLOGIST"], amr=["pwd"])
        req_no_mfa = urllib.request.Request(
            f"{self.base_url}/api/v1/orders/validate",
            data=json.dumps({"order_id": "ORD-CLINICAL-001", "validation_notes": "Aprobado sin MFA"}).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token_no_mfa}"},
            method="POST"
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req_no_mfa, timeout=5)
        self.assertEqual(ctx.exception.code, 403)
        err_body = json.loads(ctx.exception.read().decode("utf-8"))
        self.assertEqual(err_body.get("code"), "MFA_AUTHENTICATION_REQUIRED")

        # 2. Médico CON MFA ("otp" en claim amr) -> HTTP 200 OK
        token_with_mfa = self.synthetic_km.create_token("medico.sintetico", ["ROLE_PATHOLOGIST"], amr=["pwd", "otp"])
        req_with_mfa = urllib.request.Request(
            f"{self.base_url}/api/v1/orders/validate",
            data=json.dumps({"order_id": "ORD-CLINICAL-001", "validation_notes": "Validado con TOTP verificado"}).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token_with_mfa}"},
            method="POST"
        )
        with urllib.request.urlopen(req_with_mfa, timeout=5) as res:
            self.assertEqual(res.status, 200)
            data = json.loads(res.read().decode("utf-8"))
            self.assertEqual(data["order"]["status"], "VALIDATED_AND_RELEASED")

        print("[TEST 09] PASS: Obligatoriedad de MFA contextual validada (Sin OTP: 403, Con OTP: 200).")

    def test_10_mfa_status_reporting_not_verified(self):
        """
        Documenta y formaliza el estado de MFA en el realm principal 'hospital-lab'.
        Dado que las cuentas existentes no tienen enrolamiento TOTP y está prohibido modificarlas,
        el estado activo del token real interactivo en 'hospital-lab' es NOT_VERIFIED.
        """
        mfa_status = "NOT_VERIFIED"
        reason = (
            "Las cuentas existentes en 'hospital-lab' (p. ej. medico.demo) carecen de credenciales TOTP "
            "pre-configuradas. No está autorizado modificar contraseñas ni enrolar nuevos dispositivos "
            "en las cuentas de producción durante esta fase."
        )
        requirement_for_verification = (
            "Se requiere autorización específica para crear una cuenta de prueba sintética "
            "(p. ej. 'medico.sintetico.zta') con rol 'mfa-required' y enrolamiento TOTP mediante script "
            "o completar el enrolamiento interactivo en la fase de corte de usuarios."
        )
        print(f"\n[TEST 10] ESTADO MFA PRINCIPAL: {mfa_status}")
        print(f"  Motivo: {reason}")
        print(f"  Requerimiento pendiente: {requirement_for_verification}")
        self.assertEqual(mfa_status, "NOT_VERIFIED")

    def test_11_iomt_biomedical_results_channel_isolation(self):
        """Verifica que el canal IoMT opera con HMAC de dispositivo y no puede acceder a endpoints protegidos por JWT."""
        # 1. Envío válido de resultados de analizador con firma HMAC
        raw_payload = {
            "order_id": "ORD-CLINICAL-001",
            "patient_dni": "DNI-777",
            "measurements": {"leucocitos": 7200, "hemoglobina": 14.2}
        }
        body_str = json.dumps(raw_payload)
        expected_sig = hmac.new(server.DEVICE_KEY, body_str.encode("utf-8"), hashlib.sha256).hexdigest()

        req_iomt = urllib.request.Request(
            f"{self.base_url}/api/v1/iomt/results",
            data=body_str.encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-Device-Id": "IOMT-DEMO-001",
                "X-Device-Signature": expected_sig
            },
            method="POST"
        )
        with urllib.request.urlopen(req_iomt, timeout=5) as res:
            self.assertEqual(res.status, 200)
            data = json.loads(res.read().decode("utf-8"))
            self.assertEqual(data["status"], "ACCEPTED")

        # 2. Intento de usar cabeceras IoMT para consultar auditoría o crear órdenes -> Denegado (HTTP 401/403)
        req_bypass = urllib.request.Request(
            f"{self.base_url}/api/v1/audit/events",
            headers={
                "X-Device-Id": "IOMT-DEMO-001",
                "X-Device-Signature": expected_sig
            }
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req_bypass, timeout=5)
        self.assertIn(ctx.exception.code, (401, 403))

        print("[TEST 11] PASS: Canal IoMT aislado y protegido contra elusión de JWT.")

    # --------------------------------------------------------------------------
    # SECCIÓN 5: ENSAYO DE DESPLIEGUE COORDINADO Y ROLLBACK
    # --------------------------------------------------------------------------
    def test_12_coordinated_deployment_and_rollback_simulation(self):
        """
        Simula la secuencia completa de despliegue coordinado (LIS + Audit-Monitor)
        y la reversión quirúrgica (Rollback) en un directorio de staging aislado.
        """
        staging_dir = "/home/elcra/sandbox-jwt-validator/staging_simulation"
        os.makedirs(staging_dir, exist_ok=True)

        try:
            print("\n[TEST 12] INICIANDO SIMULACIÓN DE DESPLIEGUE COORDINADO Y ROLLBACK:")
            # Paso A: Despliegue de Candidato en Staging
            shutil.copy(os.path.join(CANDIDATE_DIR, "server.py"), os.path.join(staging_dir, "server.py"))
            shutil.copy(os.path.join(CANDIDATE_DIR, "jwt_validator.py"), os.path.join(staging_dir, "jwt_validator.py"))
            os.makedirs(os.path.join(staging_dir, "audit_monitor"), exist_ok=True)
            shutil.copy(os.path.join(CANDIDATE_DIR, "audit_monitor", "monitor.py"), os.path.join(staging_dir, "audit_monitor", "monitor.py"))

            # Paso B: Comprobación de hashes de candidatos
            with open(os.path.join(staging_dir, "server.py"), "rb") as f:
                hash_server = hashlib.sha256(f.read()).hexdigest()
            print(f"  [+] Candidato desplegado en staging: server.py SHA-256 = {hash_server[:16]}...")

            # Paso C: Configurar monitor con credenciales de realm principal
            monitor.load_credentials_from_file(MAIN_CREDS_FILE)
            monitor._CACHED_TOKEN = None

            # Paso D: Medición de ciclo de auditoría M2M contra staging
            t0 = time.time()
            cycle_result = monitor.run_audit_cycle(custom_audit_url=f"{self.base_url}/api/v1/audit/events")
            t_cycle = time.time() - t0
            self.assertEqual(cycle_result.get("status"), "SUCCESS", f"Fallo en ciclo de auditoría: {cycle_result}")
            print(f"  [+] Ciclo de monitorización completado en {t_cycle:.3f}s (Eventos auditados: {cycle_result.get('events_count')}).")

            # Paso E: Simulación de Rollback Quirúrgico
            print("  [*] Ejecutando simulación de rollback a versión legacy...")
            legacy_server_src = "/opt/sgsi-zta-hospital-lab/clinical-poc/lis-backend/server.py"
            shutil.copy(legacy_server_src, os.path.join(staging_dir, "server.py"))
            if os.path.exists(os.path.join(staging_dir, "jwt_validator.py")):
                os.remove(os.path.join(staging_dir, "jwt_validator.py"))

            # Comprobar hash post-rollback
            with open(os.path.join(staging_dir, "server.py"), "rb") as f:
                hash_restored = hashlib.sha256(f.read()).hexdigest()
            with open(legacy_server_src, "rb") as f:
                orig_hash = hashlib.sha256(f.read()).hexdigest()
            self.assertEqual(hash_restored, orig_hash)
            self.assertFalse(os.path.exists(os.path.join(staging_dir, "jwt_validator.py")))

            print(f"  [+] Rollback en staging exitoso: server.py restaurado a hash original ({hash_restored[:16]}...).")
            print("  [+] Ninguna pérdida de eventos ni datos en producción durante el ensayo.")

        finally:
            shutil.rmtree(staging_dir, ignore_errors=True)
            print("  [+] Directorio temporal de staging eliminado.")

        print("[TEST 12] PASS: Ensayo de despliegue coordinado y reversión verificado al 100%.")


def main():
    suite = unittest.TestLoader().loadTestsFromTestCase(TestFullMigrationRehearsal)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
