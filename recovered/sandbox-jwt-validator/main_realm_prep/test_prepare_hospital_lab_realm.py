#!/usr/bin/env python3
"""
test_prepare_hospital_lab_realm.py - Unit test suite for RealmPreparer

Tests all operational scenarios required by SGSI-ZTA Prepredespliegue:
1. Existing disabled client: configuration preserved and enabled.
2. Non-existent client: complete client creation with full parameters.
3. Mappers absent or misconfigured: detection and correction.
4. Existing audit client: no duplicate creation; secret synchronization.
5. Repeated execution: idempotency (zero actions planned).
6. Failure during client creation: graceful error handling and recovery note.
7. Failure during mapper/role assignment: partial failure recorded, no resource deletion.
8. Secrets protection: atomic replacement, mode 0600, backup preservation.
9. HTTP errors & invalid admin responses: proper error wrapping.
10. Unauthorized realm modification denial: strict validation for 'hospital-lab'.
11. Dry-run and verify produce zero API mutations.
12. Least privilege: detection of unauthorized clinical roles on service account.
13. Sincronización inteligente: no planifica SYNC_EXISTING_CREDENTIALS si las credenciales ya coinciden.
14. No revocación automática: roles no autorizados se reportan pero no se revocan sin --allow-revocations.
15. Verificación de respuesta real de revocación: detección de fallos si Keycloak retiene el rol.
16. Detección de incompatibilidades OIDC en cliente frontend (Direct Grants, PKCE inválido, sin URIs).
17. Separación estricta de cambios aditivos (seguros), modificaciones y revocaciones.
"""

import copy
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from prepare_hospital_lab_realm import (
    EXPECTED_AMR_MAPPER_CONFIG,
    EXPECTED_AUDIENCE_MAPPER_CONFIG,
    FORBIDDEN_AUDIT_ROLES,
    RealmPreparer,
    TARGET_REALM,
)


class MockKeycloakAdminAPI:
    """In-memory mock of Keycloak Admin REST API for deterministic testing."""

    def __init__(self, realm: str = TARGET_REALM):
        self.realm = realm
        self.call_log: List[Tuple[str, str, Optional[Dict[str, Any]]]] = []
        self.error_triggers: Dict[str, Tuple[int, Any]] = {}

        # Default realm state
        self.realm_data = {
            "realm": realm,
            "enabled": True,
            "browserFlow": "hospital-browser"
        }
        self.clients: List[Dict[str, Any]] = []
        self.mappers: Dict[str, List[Dict[str, Any]]] = {}  # client_id -> list of mappers
        self.client_secrets: Dict[str, str] = {}
        self.service_accounts: Dict[str, Dict[str, Any]] = {}  # client_id -> sa_user
        self.user_roles: Dict[str, List[Dict[str, Any]]] = {}  # user_id -> roles
        self.roles = [
            {"id": "role-auditor-id", "name": "auditor", "composite": False},
            {"id": "role-medico-id", "name": "medico", "composite": False},
            {"id": "role-default-id", "name": "default-roles-hospital-lab", "composite": True}
        ]
        self.fail_role_revocation_verification = False

    def trigger_error(self, method_endpoint_prefix: str, status_code: int, error_body: Any):
        self.error_triggers[method_endpoint_prefix] = (status_code, error_body)

    def request(
        self,
        endpoint: str,
        method: str = "GET",
        data: Optional[Dict[str, Any]] = None,
        token: Optional[str] = None
    ) -> Tuple[int, Any]:
        self.call_log.append((method, endpoint, copy.deepcopy(data)))

        key = f"{method} {endpoint}"
        for trigger_key, (status, body) in self.error_triggers.items():
            if trigger_key in key:
                return status, body

        # Handle Realm
        if endpoint == f"/admin/realms/{self.realm}":
            if method == "GET":
                return 200, copy.deepcopy(self.realm_data)

        # Handle Flows
        if endpoint == f"/admin/realms/{self.realm}/authentication/flows/hospital-browser/executions":
            if method == "GET":
                return 200, [
                    {"id": "ex-cookie", "providerId": "auth-cookie"},
                    {"id": "ex-form", "providerId": "auth-username-password-form"},
                    {"id": "ex-cond", "providerId": "conditional-user-role", "authenticationConfig": "cfg-mfa"},
                    {"id": "ex-otp", "providerId": "auth-otp-form"}
                ]

        if endpoint == f"/admin/realms/{self.realm}/authentication/config/cfg-mfa":
            if method == "GET":
                return 200, {"id": "cfg-mfa", "config": {"condUserRole": "mfa-required"}}

        # Handle Roles
        if endpoint == f"/admin/realms/{self.realm}/roles":
            if method == "GET":
                return 200, copy.deepcopy(self.roles)

        if endpoint == f"/admin/realms/{self.realm}/roles/auditor":
            if method == "GET":
                role = next((r for r in self.roles if r["name"] == "auditor"), None)
                return 200, copy.deepcopy(role)

        # Handle Clients
        if endpoint == f"/admin/realms/{self.realm}/clients":
            if method == "GET":
                return 200, copy.deepcopy(self.clients)
            elif method == "POST":
                client_copy = copy.deepcopy(data)
                cid = client_copy.get("id") or f"uuid-{client_copy['clientId']}"
                client_copy["id"] = cid
                self.clients.append(client_copy)
                if client_copy.get("secret"):
                    self.client_secrets[cid] = client_copy["secret"]
                if client_copy.get("serviceAccountsEnabled"):
                    sa_user_id = f"sa-user-{cid}"
                    self.service_accounts[cid] = {"id": sa_user_id, "username": f"service-account-{client_copy['clientId']}"}
                    self.user_roles[sa_user_id] = [{"id": "role-default-id", "name": "default-roles-hospital-lab"}]
                return 201, {}

        if endpoint.startswith(f"/admin/realms/{self.realm}/clients?clientId="):
            query_id = endpoint.split("clientId=")[1]
            matched = [c for c in self.clients if c.get("clientId") == query_id]
            return 200, copy.deepcopy(matched)

        for c in list(self.clients):
            cid = c["id"]
            if endpoint == f"/admin/realms/{self.realm}/clients/{cid}":
                if method == "GET":
                    return 200, copy.deepcopy(c)
                elif method == "PUT":
                    c.update(copy.deepcopy(data))
                    return 204, {}

            if endpoint == f"/admin/realms/{self.realm}/clients/{cid}/client-secret":
                sec = self.client_secrets.get(cid, "default-secret-mock")
                return 200, {"type": "secret", "value": sec}

            if endpoint == f"/admin/realms/{self.realm}/clients/{cid}/service-account-user":
                sa_user = self.service_accounts.get(cid, {"id": f"sa-{cid}", "username": f"sa-{c['clientId']}"})
                return 200, copy.deepcopy(sa_user)

            if endpoint == f"/admin/realms/{self.realm}/clients/{cid}/protocol-mappers/models":
                client_mappers = self.mappers.setdefault(cid, [])
                if method == "GET":
                    return 200, copy.deepcopy(client_mappers)
                elif method == "POST":
                    m_copy = copy.deepcopy(data)
                    mid = m_copy.get("id") or f"map-{m_copy['name']}-{len(client_mappers)}"
                    m_copy["id"] = mid
                    client_mappers.append(m_copy)
                    return 201, {}

            for m in self.mappers.get(cid, []):
                mid = m["id"]
                if endpoint == f"/admin/realms/{self.realm}/clients/{cid}/protocol-mappers/models/{mid}":
                    if method == "PUT":
                        m.update(copy.deepcopy(data))
                        return 204, {}

        for uid, r_list in list(self.user_roles.items()):
            if endpoint == f"/admin/realms/{self.realm}/users/{uid}/role-mappings/realm":
                if method == "GET":
                    return 200, copy.deepcopy(r_list)
                elif method == "POST":
                    for r in data:
                        if not any(existing["name"] == r["name"] for existing in r_list):
                            r_list.append(copy.deepcopy(r))
                    return 204, {}
                elif method == "DELETE":
                    to_remove = {r["name"] for r in data}
                    if not self.fail_role_revocation_verification:
                        self.user_roles[uid] = [r for r in r_list if r["name"] not in to_remove]
                    return 204, {}

        return 404, {"error": "Not Found", "endpoint": endpoint}


class TestRealmPreparer(unittest.TestCase):
    """Test suite covering all operational scenarios of RealmPreparer."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="test_preparer_")
        self.creds_file = os.path.join(self.temp_dir, ".env.test_audit_creds")
        self.mock_api = MockKeycloakAdminAPI(realm=TARGET_REALM)
        self.preparer = RealmPreparer(
            realm=TARGET_REALM,
            api_fn=self.mock_api.request,
            creds_path=self.creds_file,
            allow_revocations=False
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # 1. Cliente existente y deshabilitado: preserva toda la configuración y lo habilita
    def test_01_existing_disabled_client_preserved_and_enabled(self):
        existing_poc = {
            "id": "poc-uuid-1234",
            "clientId": "clinical-poc",
            "enabled": False,
            "redirectUris": ["http://127.0.0.1:8000/oidc/callback"],
            "webOrigins": ["http://127.0.0.1:8000"],
            "standardFlowEnabled": True,
            "directAccessGrantsEnabled": False,
            "publicClient": True,
            "attributes": {
                "pkce.code.challenge.method": "S256",
                "custom.clinical.attr": "hospital_poc_value"
            }
        }
        self.mock_api.clients.append(existing_poc)

        state = self.preparer.audit_realm(token="mock-token")
        self.assertTrue(state["clinical_poc"]["found"])
        self.assertFalse(state["clinical_poc"]["enabled"])

        plan = self.preparer.plan_changes(state)
        update_step = next((s for s in plan if s["action"] == "UPDATE_CLIENT_PRESERVE_CONFIG"), None)
        self.assertIsNotNone(update_step)

        payload = update_step["payload"]
        self.assertTrue(payload["enabled"])
        self.assertEqual(payload["redirectUris"], ["http://127.0.0.1:8000/oidc/callback"])
        self.assertEqual(payload["webOrigins"], ["http://127.0.0.1:8000"])
        self.assertEqual(payload["attributes"]["custom.clinical.attr"], "hospital_poc_value")
        self.assertEqual(payload["attributes"]["pkce.code.challenge.method"], "S256")

        res = self.preparer.execute_plan(plan, token="mock-token")
        self.assertTrue(res["success"])
        self.assertTrue(self.mock_api.clients[0]["enabled"])
        self.assertEqual(self.mock_api.clients[0]["attributes"]["custom.clinical.attr"], "hospital_poc_value")

    # 2. Cliente inexistente: creación completa con parámetros PKCE y mappers
    def test_02_non_existent_client_created_with_full_spec(self):
        self.assertEqual(len(self.mock_api.clients), 0)

        state = self.preparer.audit_realm(token="mock-token")
        self.assertFalse(state["clinical_poc"]["found"])

        plan = self.preparer.plan_changes(state)
        create_step = next((s for s in plan if s["action"] == "CREATE_CLIENT_POC"), None)
        self.assertIsNotNone(create_step)
        self.assertEqual(create_step["payload"]["clientId"], "clinical-poc")
        self.assertEqual(create_step["payload"]["attributes"]["pkce.code.challenge.method"], "S256")

        res = self.preparer.execute_plan(plan, token="mock-token")
        self.assertTrue(res["success"])

        clients = [c for c in self.mock_api.clients if c["clientId"] == "clinical-poc"]
        self.assertEqual(len(clients), 1)
        poc_id = clients[0]["id"]
        mappers = self.mock_api.mappers.get(poc_id, [])
        mapper_names = {m["name"] for m in mappers}
        self.assertIn("clinical-poc-api-audience", mapper_names)
        self.assertIn("amr", mapper_names)

    # 3. Mappers ausentes o mal configurados: detección y corrección de parámetros reales
    def test_03_mappers_absent_or_misconfigured(self):
        poc_id = "poc-uuid-1234"
        self.mock_api.clients.append({
            "id": poc_id,
            "clientId": "clinical-poc",
            "enabled": True,
            "standardFlowEnabled": True,
            "directAccessGrantsEnabled": False,
            "publicClient": True,
            "attributes": {"pkce.code.challenge.method": "S256"}
        })
        misconfigured_aud = {
            "id": "map-aud-1",
            "name": "clinical-poc-api-audience",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "config": {
                "included.custom.audience": "wrong-audience",
                "access.token.claim": "false"
            }
        }
        self.mock_api.mappers[poc_id] = [misconfigured_aud]

        state = self.preparer.audit_realm(token="mock-token")
        poc_aud = state["clinical_poc"]["audience_mapper"]
        self.assertTrue(poc_aud["found"])
        self.assertFalse(poc_aud["valid"])

        plan = self.preparer.plan_changes(state)
        update_mapper = next((s for s in plan if s["action"] == "UPDATE_AUDIENCE_MAPPER_POC"), None)
        self.assertIsNotNone(update_mapper)
        self.assertEqual(update_mapper["payload"]["config"]["included.custom.audience"], "clinical-poc-api")
        self.assertEqual(update_mapper["payload"]["config"]["access.token.claim"], "true")

        res = self.preparer.execute_plan(plan, token="mock-token")
        self.assertTrue(res["success"])
        updated_map = self.mock_api.mappers[poc_id][0]
        self.assertEqual(updated_map["config"]["included.custom.audience"], "clinical-poc-api")
        self.assertEqual(updated_map["config"]["access.token.claim"], "true")

    # 4. Cliente de auditoría existente: no genera duplicados y sincroniza credenciales si faltan
    def test_04_existing_audit_client_preserved_and_synced(self):
        audit_id = "audit-uuid-5678"
        self.mock_api.clients.append({
            "id": audit_id,
            "clientId": "clinical-audit-monitor-service",
            "enabled": True,
            "serviceAccountsEnabled": True,
            "publicClient": False,
            "protocol": "openid-connect"
        })
        self.mock_api.client_secrets[audit_id] = "existing-known-audit-secret-2026"
        sa_user_id = "sa-audit-user-1"
        self.mock_api.service_accounts[audit_id] = {"id": sa_user_id, "username": "service-account-clinical-audit-monitor-service"}
        self.mock_api.user_roles[sa_user_id] = [{"id": "role-auditor-id", "name": "auditor"}]
        self.mock_api.mappers[audit_id] = [{
            "id": "map-aud-svc",
            "name": "clinical-poc-api-audience",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "config": EXPECTED_AUDIENCE_MAPPER_CONFIG
        }]

        # Audit realm (creds file does not exist yet)
        state = self.preparer.audit_realm(token="mock-token")
        self.assertTrue(state["clinical_audit_monitor_service"]["found"])
        self.assertTrue(state["clinical_audit_monitor_service"]["has_auditor_role"])
        self.assertEqual(state["clinical_audit_monitor_service"]["existing_secret"], "existing-known-audit-secret-2026")
        self.assertFalse(state["clinical_audit_monitor_service"]["creds_file_in_sync"])

        plan = self.preparer.plan_changes(state)
        create_audit = next((s for s in plan if s["action"] == "CREATE_AUDIT_CLIENT"), None)
        self.assertIsNone(create_audit)

        sync_step = next((s for s in plan if s["action"] == "SYNC_EXISTING_CREDENTIALS"), None)
        self.assertIsNotNone(sync_step)
        self.assertEqual(sync_step["secret"], "existing-known-audit-secret-2026")

        res = self.preparer.execute_plan(plan, token="mock-token")
        self.assertTrue(res["success"])
        self.assertTrue(os.path.exists(self.creds_file))
        with open(self.creds_file, "r") as f:
            content = f.read()
            self.assertIn("AUDIT_MONITOR_CLIENT_SECRET=existing-known-audit-secret-2026", content)

    # 5. Ejecución repetida sin cambios innecesarios (Idempotencia estricta: 0 acciones)
    def test_05_idempotency_repeated_execution_zero_actions(self):
        poc_id = "poc-compliant-1"
        self.mock_api.clients.append({
            "id": poc_id,
            "clientId": "clinical-poc",
            "enabled": True,
            "standardFlowEnabled": True,
            "directAccessGrantsEnabled": False,
            "publicClient": True,
            "attributes": {"pkce.code.challenge.method": "S256"}
        })
        self.mock_api.mappers[poc_id] = [
            {"id": "m1", "name": "clinical-poc-api-audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper", "config": EXPECTED_AUDIENCE_MAPPER_CONFIG},
            {"id": "m2", "name": "amr", "protocol": "openid-connect", "protocolMapper": "oidc-amr-mapper", "config": EXPECTED_AMR_MAPPER_CONFIG}
        ]

        audit_id = "audit-compliant-1"
        known_secret = "compliant-secret-2026"
        self.mock_api.clients.append({
            "id": audit_id,
            "clientId": "clinical-audit-monitor-service",
            "enabled": True,
            "serviceAccountsEnabled": True,
            "publicClient": False,
            "protocol": "openid-connect"
        })
        self.mock_api.client_secrets[audit_id] = known_secret
        sa_uid = "sa-compliant-uid"
        self.mock_api.service_accounts[audit_id] = {"id": sa_uid, "username": "service-account-clinical-audit-monitor-service"}
        self.mock_api.user_roles[sa_uid] = [{"id": "role-auditor-id", "name": "auditor"}]
        self.mock_api.mappers[audit_id] = [
            {"id": "m3", "name": "clinical-poc-api-audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper", "config": EXPECTED_AUDIENCE_MAPPER_CONFIG}
        ]

        # Ensure credentials file already exists and is in sync
        self.preparer.save_credentials_atomic("clinical-audit-monitor-service", known_secret, self.creds_file)

        state = self.preparer.audit_realm(token="mock-token")
        self.assertTrue(state["clinical_audit_monitor_service"]["creds_file_in_sync"])
        plan = self.preparer.plan_changes(state)

        # Plan MUST be completely empty (0 actions)
        self.assertEqual(len(plan), 0, f"Plan no está vacío en estado conforme: {plan}")

    # 6. Fallo durante creación de cliente: detención segura y reporte de recuperación
    def test_06_failure_during_client_creation(self):
        self.mock_api.trigger_error("POST /admin/realms/hospital-lab/clients", 500, {"error": "Internal Server Error"})
        state = self.preparer.audit_realm(token="mock-token")
        plan = self.preparer.plan_changes(state)

        res = self.preparer.execute_plan(plan, token="mock-token")
        self.assertFalse(res["success"])
        self.assertEqual(res["failed_step"]["status"], "FAILED")
        self.assertIn("RECUPERACIÓN", res["recovery_note"])

    # 7. Fallo al asignar un mapper o rol: registra paso fallido sin borrar recursos previos
    def test_07_failure_assigning_mapper_or_role(self):
        poc_id = "poc-uuid-1"
        self.mock_api.clients.append({
            "id": poc_id,
            "clientId": "clinical-poc",
            "enabled": False,
            "standardFlowEnabled": True,
            "directAccessGrantsEnabled": False,
            "publicClient": True,
            "attributes": {"pkce.code.challenge.method": "S256"}
        })
        self.mock_api.trigger_error(f"POST /admin/realms/hospital-lab/clients/{poc_id}/protocol-mappers/models", 502, {"error": "Bad Gateway"})

        state = self.preparer.audit_realm(token="mock-token")
        plan = self.preparer.plan_changes(state)

        res = self.preparer.execute_plan(plan, token="mock-token")
        self.assertFalse(res["success"])
        successful_steps = [r for r in res["journal"] if r["status"] == "SUCCESS"]
        self.assertGreaterEqual(len(successful_steps), 1)
        self.assertEqual(successful_steps[0]["action"], "UPDATE_CLIENT_PRESERVE_CONFIG")
        self.assertEqual(len(self.mock_api.clients), 1)

    # 8. Protección y recuperación de secretos: reemplazo atómico, 0600 y respaldo .bak
    def test_08_secrets_protection_atomic_and_backup(self):
        with open(self.creds_file, "w") as f:
            f.write("AUDIT_MONITOR_CLIENT_SECRET=old-secret-123\n")
        os.chmod(self.creds_file, 0o600)

        self.preparer.save_credentials_atomic("clinical-audit-monitor-service", "new-super-secret-456", self.creds_file)

        with open(self.creds_file, "r") as f:
            content = f.read()
            self.assertIn("AUDIT_MONITOR_CLIENT_SECRET=new-super-secret-456", content)

        mode = os.stat(self.creds_file).st_mode & 0o777
        self.assertEqual(mode, 0o600)

        bak_file = f"{self.creds_file}.bak"
        self.assertTrue(os.path.exists(bak_file))
        with open(bak_file, "r") as f:
            bak_content = f.read()
            self.assertIn("AUDIT_MONITOR_CLIENT_SECRET=old-secret-123", bak_content)
        bak_mode = os.stat(bak_file).st_mode & 0o777
        self.assertEqual(bak_mode, 0o600)

    # 9. Fallos HTTP y respuestas administrativas inválidas
    def test_09_http_errors_and_invalid_responses(self):
        self.mock_api.trigger_error(f"/admin/realms/{TARGET_REALM}/clients", 401, {"error": "Unauthorized"})
        with self.assertRaises(RuntimeError) as ctx:
            self.preparer.audit_realm(token="invalid-token")
        self.assertIn("401", str(ctx.exception))

    # 10. Denegación de modificaciones no autorizadas a otros realms
    def test_10_unauthorized_realm_denial(self):
        for unauthorized_realm in ("hospital-lab-oidc-test", "master", "other-realm"):
            with self.assertRaises(ValueError) as ctx:
                RealmPreparer(realm=unauthorized_realm, api_fn=self.mock_api.request)
            self.assertIn("Seguridad Zero Trust", str(ctx.exception))

    # 11. Verificar que --verify y --dry-run no generan cambios (0 mutaciones)
    def test_11_verify_and_dry_run_produce_zero_mutations(self):
        self.mock_api.call_log.clear()

        state = self.preparer.audit_realm(token="mock-token")
        plan = self.preparer.plan_changes(state)

        mutation_verbs = {"POST", "PUT", "DELETE", "PATCH"}
        mutating_calls = [c for c in self.mock_api.call_log if c[0] in mutation_verbs]
        self.assertEqual(len(mutating_calls), 0, f"Dry-run generó mutaciones no autorizadas: {mutating_calls}")

    # 12. Menor privilegio: detección de roles no autorizados en Service Account
    def test_12_least_privilege_audit_role_detected(self):
        audit_id = "audit-uuid-priv"
        self.mock_api.clients.append({
            "id": audit_id,
            "clientId": "clinical-audit-monitor-service",
            "enabled": True,
            "serviceAccountsEnabled": True,
            "publicClient": False,
            "protocol": "openid-connect"
        })
        sa_user_id = "sa-audit-priv"
        self.mock_api.service_accounts[audit_id] = {"id": sa_user_id, "username": "service-account-clinical-audit-monitor-service"}
        self.mock_api.user_roles[sa_user_id] = [
            {"id": "role-auditor-id", "name": "auditor"},
            {"id": "role-medico-id", "name": "medico"}
        ]

        state = self.preparer.audit_realm(token="mock-token")
        self.assertIn("medico", state["clinical_audit_monitor_service"]["unauthorized_roles"])

    # 13. Sincronización inteligente: no planifica SYNC_EXISTING_CREDENTIALS si ya coinciden
    def test_13_credentials_in_sync_does_not_plan_sync_existing_credentials(self):
        audit_id = "audit-sync-test"
        secret_value = "exact-matching-secret-999"
        self.mock_api.clients.append({
            "id": audit_id,
            "clientId": "clinical-audit-monitor-service",
            "enabled": True,
            "serviceAccountsEnabled": True,
            "publicClient": False,
            "protocol": "openid-connect"
        })
        self.mock_api.client_secrets[audit_id] = secret_value
        sa_user_id = "sa-sync-user"
        self.mock_api.service_accounts[audit_id] = {"id": sa_user_id, "username": "service-account-clinical-audit-monitor-service"}
        self.mock_api.user_roles[sa_user_id] = [{"id": "role-auditor-id", "name": "auditor"}]

        # Save exact credentials to creds_file
        self.preparer.save_credentials_atomic("clinical-audit-monitor-service", secret_value, self.creds_file)

        state = self.preparer.audit_realm(token="mock-token")
        self.assertTrue(state["clinical_audit_monitor_service"]["creds_file_in_sync"])

        plan = self.preparer.plan_changes(state)
        sync_step = next((s for s in plan if s["action"] == "SYNC_EXISTING_CREDENTIALS"), None)
        self.assertIsNone(sync_step, "No debe planificar SYNC_EXISTING_CREDENTIALS si el secreto ya coincide exactamente.")

    # 14. No revocación automática: roles no autorizados requieren --allow-revocations explícito
    def test_14_unauthorized_roles_not_revoked_without_explicit_flag(self):
        audit_id = "audit-no-auto-revoke"
        self.mock_api.clients.append({
            "id": audit_id,
            "clientId": "clinical-audit-monitor-service",
            "enabled": True,
            "serviceAccountsEnabled": True,
            "publicClient": False,
            "protocol": "openid-connect"
        })
        sa_user_id = "sa-no-auto-revoke"
        self.mock_api.service_accounts[audit_id] = {"id": sa_user_id, "username": "service-account-clinical-audit-monitor-service"}
        self.mock_api.user_roles[sa_user_id] = [
            {"id": "role-auditor-id", "name": "auditor"},
            {"id": "role-medico-id", "name": "medico"}
        ]

        # Case A: allow_revocations = False (default safe behavior)
        self.preparer.allow_revocations = False
        state = self.preparer.audit_realm(token="mock-token")
        plan = self.preparer.plan_changes(state)
        revoke_action = next((s for s in plan if s["action"] == "REVOKE_UNAUTHORIZED_ROLES"), None)
        self.assertIsNone(revoke_action, "La revocación NO debe ser planificada por defecto sin autorización explícita.")

        # Case B: allow_revocations = True (explicitly authorized)
        self.preparer.allow_revocations = True
        plan_auth = self.preparer.plan_changes(state)
        revoke_action_auth = next((s for s in plan_auth if s["action"] == "REVOKE_UNAUTHORIZED_ROLES"), None)
        self.assertIsNotNone(revoke_action_auth, "Con --allow-revocations la acción debe aparecer categorizada como REVOCATION.")
        self.assertEqual(revoke_action_auth["category"], "REVOCATION")

    # 15. Verificación de respuesta real de revocación: detecta si Keycloak falló en eliminar el rol
    def test_15_revocation_verification_failure_detected(self):
        audit_id = "audit-verify-fail"
        self.mock_api.clients.append({
            "id": audit_id,
            "clientId": "clinical-audit-monitor-service",
            "enabled": True,
            "serviceAccountsEnabled": True,
            "publicClient": False,
            "protocol": "openid-connect"
        })
        sa_user_id = "sa-verify-fail"
        self.mock_api.service_accounts[audit_id] = {"id": sa_user_id, "username": "service-account-clinical-audit-monitor-service"}
        self.mock_api.user_roles[sa_user_id] = [
            {"id": "role-auditor-id", "name": "auditor"},
            {"id": "role-medico-id", "name": "medico"}
        ]

        # Configure mock to simulate silent Keycloak retention of the role despite 204 response
        self.mock_api.fail_role_revocation_verification = True
        self.preparer.allow_revocations = True

        state = self.preparer.audit_realm(token="mock-token")
        plan = self.preparer.plan_changes(state)

        res = self.preparer.execute_plan(plan, token="mock-token")
        self.assertFalse(res["success"])
        self.assertIn("Fallo de verificación de revocación", res["failed_step"]["error"])

    # 16. Detección de incompatibilidades OIDC en cliente frontend
    def test_16_incompatible_oidc_client_detection(self):
        incompatible_client = {
            "id": "poc-incompatible",
            "clientId": "clinical-poc",
            "enabled": True,
            "standardFlowEnabled": False,  # INCOMPATIBLE
            "directAccessGrantsEnabled": True,  # INCOMPATIBLE
            "implicitFlowEnabled": True,  # INCOMPATIBLE
            "publicClient": False,  # INCOMPATIBLE
            "attributes": {"pkce.code.challenge.method": "plain"},  # INCOMPATIBLE
            "redirectUris": []  # INCOMPATIBLE
        }
        self.mock_api.clients.append(incompatible_client)

        state = self.preparer.audit_realm(token="mock-token")
        poc = state["clinical_poc"]
        self.assertFalse(poc["is_compatible"])
        self.assertGreaterEqual(len(poc["incompatibilities"]), 4)

    # 17. Separación estricta de cambios aditivos (seguros), modificaciones y revocaciones
    def test_17_separation_of_additive_vs_modification_actions(self):
        # Escenario mixto
        poc_id = "poc-mixed"
        self.mock_api.clients.append({
            "id": poc_id,
            "clientId": "clinical-poc",
            "enabled": False,  # ADDITIVE enable
            "standardFlowEnabled": True,
            "directAccessGrantsEnabled": False,
            "publicClient": True,
            "attributes": {"pkce.code.challenge.method": "S256"}
        })
        # Mapper mal configurado -> MODIFICATION
        self.mock_api.mappers[poc_id] = [{
            "id": "m-wrong",
            "name": "amr",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-amr-mapper",
            "config": {"id.token.claim": "false"}  # Wrong config
        }]
        # Audit client with unauthorized role -> REVOCATION
        audit_id = "audit-mixed"
        self.mock_api.clients.append({
            "id": audit_id,
            "clientId": "clinical-audit-monitor-service",
            "enabled": True,
            "serviceAccountsEnabled": True,
            "publicClient": False,
            "protocol": "openid-connect"
        })
        sa_uid = "sa-mixed"
        self.mock_api.service_accounts[audit_id] = {"id": sa_uid, "username": "service-account-clinical-audit-monitor-service"}
        self.mock_api.user_roles[sa_uid] = [
            {"id": "role-auditor-id", "name": "auditor"},
            {"id": "role-medico-id", "name": "medico"}
        ]

        self.preparer.allow_revocations = True
        state = self.preparer.audit_realm(token="mock-token")
        plan = self.preparer.plan_changes(state)

        categories_present = {s.get("category") for s in plan}
        self.assertIn("ADDITIVE", categories_present)
        self.assertIn("MODIFICATION", categories_present)
        self.assertIn("REVOCATION", categories_present)


if __name__ == "__main__":
    unittest.main(verbosity=2)
