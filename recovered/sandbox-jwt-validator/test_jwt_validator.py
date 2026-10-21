#!/usr/bin/env python3
"""
SGSI-ZTA Hospital Lab: Suite de Pruebas Automatizadas de Seguridad Zero Trust
Verifica jwt_validator.py mediante claves sint?ticas y mocks aislados en memoria.
Zero llamadas de red externas, zero credenciales reales.
"""

from __future__ import annotations

import base64
import json
import time
import unittest
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from jwt_validator import (
    AlgorithmMismatchError,
    ClinicalAuthContext,
    InsufficientPermissionsError,
    InvalidAudienceError,
    InvalidSignatureError,
    InvalidTokenTypeError,
    JWKSCacheManager,
    JWKSFetchError,
    KeyNotFoundError,
    MalformedTokenError,
    MFARequiredError,
    MissingClaimError,
    TokenExpiredError,
    TokenNotYetValidError,
    UntrustedIssuerError,
    ZeroTrustJWTValidator,
    enforce_clinical_action,
)


def b64url(data: bytes) -> str:
    """Codifica bytes en base64url sin relleno."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class MockJWKSCacheManager(JWKSCacheManager):
    """
    Simulador en memoria de JWKSCacheManager.
    Permite controlar las claves p?blicas y respuestas sin tocar sockets de red.
    """

    def __init__(
        self,
        key_pairs: Dict[str, rsa.RSAPrivateKey],
        expected_issuer: str,
        fail_network: bool = False,
        initial_fetch: bool = True,
    ) -> None:
        self._key_pairs = dict(key_pairs)
        self._mock_issuer = expected_issuer
        self.fail_network = fail_network
        self.fetch_count = 0

        self._keys_by_kid = {kid: key.public_key() for kid, key in key_pairs.items()}
        self._last_fetch_timestamp = time.time() if initial_fetch else 0.0
        self.cache_ttl_seconds = 3600
        self.min_refresh_interval_seconds = 60

    @property
    def expected_issuer(self) -> str:
        if self.fail_network:
            raise JWKSFetchError("Fallo simulado de red en Discovery OIDC")
        return self._mock_issuer

    def _fetch_jwks(self) -> None:
        self.fetch_count += 1
        if self.fail_network:
            raise JWKSFetchError("Fallo simulado de red al consultar JWKS")
        self._keys_by_kid = {kid: key.public_key() for kid, key in self._key_pairs.items()}
        self._last_fetch_timestamp = time.time()

    def add_key(self, kid: str, key_pair: rsa.RSAPrivateKey) -> None:
        """Simula la generaci?n o rotaci?n de una nueva clave en Keycloak."""
        self._key_pairs[kid] = key_pair


class TestZeroTrustJWTValidator(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.issuer = "http://127.0.0.1:8085/realms/hospital-lab"
        cls.audience = "clinical-poc-api"
        cls.primary_kid = "lab-rsa-key-01"
        cls.primary_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.untrusted_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        self.mock_cache = MockJWKSCacheManager(
            key_pairs={self.primary_kid: self.primary_key},
            expected_issuer=self.issuer,
        )
        self.validator = ZeroTrustJWTValidator(
            discovery_url="http://mock-discovery/openid-configuration",
            expected_audience=self.audience,
            clock_skew_seconds=10,
            cache_manager=self.mock_cache,
        )

    def _forge_token(
        self,
        payload_overrides: Optional[Dict[str, Any]] = None,
        header_overrides: Optional[Dict[str, Any]] = None,
        signing_key: Optional[rsa.RSAPrivateKey] = None,
        corrupt_signature: bool = False,
    ) -> str:
        """Construye un token JWS sint?tico firmado en memoria."""
        header = {
            "alg": "RS256",
            "typ": "JWT",
            "kid": self.primary_kid,
        }
        if header_overrides:
            header.update(header_overrides)

        now = int(time.time())
        payload = {
            "sub": "user-uuid-synthetic-001",
            "preferred_username": "medico.demo",
            "iss": self.issuer,
            "aud": [self.audience],
            "exp": now + 600,
            "nbf": now - 10,
            "iat": now,
            "typ": "Bearer",
            "realm_access": {"roles": ["medico"]},
            "amr": ["pwd", "otp"],
        }
        if payload_overrides:
            for k, v in payload_overrides.items():
                if v is None:
                    payload.pop(k, None)
                else:
                    payload[k] = v

        raw_header = b64url(json.dumps(header).encode("utf-8"))
        raw_payload = b64url(json.dumps(payload).encode("utf-8"))
        signing_input = f"{raw_header}.{raw_payload}".encode("ascii")

        key_to_use = signing_key or self.primary_key
        sig_bytes = key_to_use.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())

        if corrupt_signature:
            sig_bytes = sig_bytes[:-1] + (b"\x00" if sig_bytes[-1:] != b"\x00" else b"\xFF")

        return f"{raw_header}.{raw_payload}.{b64url(sig_bytes)}"

    # -----------------------------------------------------------------
    # 1. Casos Positivos y Mapeo de Roles
    # -----------------------------------------------------------------
    def test_01_valid_token_with_mfa_success(self):
        """Token m?dico firmado y v?lido con MFA demostrado."""
        token = self._forge_token()
        ctx = self.validator.validate_token(token)
        self.assertIsInstance(ctx, ClinicalAuthContext)
        self.assertEqual(ctx.username, "medico.demo")
        self.assertIn("ROLE_PATHOLOGIST", ctx.roles)
        self.assertTrue(ctx.mfa_verified)

    def test_02_role_mapping_reception_and_tech(self):
        """Mapeo correcto de roles institucionales a roles cl?nicos."""
        token_adm = self._forge_token(
            payload_overrides={"preferred_username": "admision.demo", "realm_access": {"roles": ["admision"]}}
        )
        ctx_adm = self.validator.validate_token(token_adm)
        self.assertIn("ROLE_RECEPTION", ctx_adm.roles)

        token_tech = self._forge_token(
            payload_overrides={"preferred_username": "laboratorio.demo", "realm_access": {"roles": ["laboratorio"]}}
        )
        ctx_tech = self.validator.validate_token(token_tech)
        self.assertIn("ROLE_LAB_TECH", ctx_tech.roles)

    # -----------------------------------------------------------------
    # 2. Casos de Seguridad de MFA (Regla de Oro: acr=1 NO es MFA)
    # -----------------------------------------------------------------
    def test_03_acr_alone_does_not_prove_mfa(self):
        """Un token con acr='1' pero sin 'otp' en amr se clasifica estrictamente como mfa_verified=False."""
        token = self._forge_token(payload_overrides={"acr": "1", "amr": ["pwd"]})
        ctx = self.validator.validate_token(token)
        self.assertFalse(ctx.mfa_verified)

    def test_04_sensitive_action_requires_mfa_success(self):
        """Pat?logo con MFA verificado puede firmar y liberar ?rdenes."""
        token = self._forge_token(payload_overrides={"amr": ["pwd", "totp"]})
        ctx = self.validator.validate_token(token)
        enforce_clinical_action(ctx, "VALIDATE_ORDER")

    def test_05_sensitive_action_denied_without_mfa(self):
        """Pat?logo sin MFA verificado es bloqueado al intentar firmar ?rdenes."""
        token = self._forge_token(payload_overrides={"amr": ["pwd"]})
        ctx = self.validator.validate_token(token)
        with self.assertRaises(MFARequiredError):
            enforce_clinical_action(ctx, "VALIDATE_ORDER")

    # -----------------------------------------------------------------
    # 3. Casos Criptogr?ficos y Algoritmos
    # -----------------------------------------------------------------
    def test_06_tampered_signature_rejected(self):
        """Firma modificada en tr?nsito debe rechazarse inmediatamente."""
        token = self._forge_token(corrupt_signature=True)
        with self.assertRaises(InvalidSignatureError):
            self.validator.validate_token(token)

    def test_07_untrusted_signing_key_rejected(self):
        """Token firmado con clave RSA no perteneciente al JWKS de Keycloak."""
        token = self._forge_token(signing_key=self.untrusted_key)
        with self.assertRaises(InvalidSignatureError):
            self.validator.validate_token(token)

    def test_08_disallowed_algorithm_none_rejected(self):
        """Ataque alg: 'none' bloqueado por lista blanca estricta."""
        raw_header = b64url(json.dumps({"alg": "none", "typ": "JWT", "kid": self.primary_kid}).encode())
        raw_payload = b64url(json.dumps({"sub": "test", "iss": self.issuer, "aud": [self.audience], "exp": int(time.time()) + 100}).encode())
        token = f"{raw_header}.{raw_payload}."
        with self.assertRaises(AlgorithmMismatchError):
            self.validator.validate_token(token)

    def test_09_disallowed_algorithm_symmetric_hs256_rejected(self):
        """Ataque de confusi?n de algoritmo 'HS256' bloqueado."""
        token = self._forge_token(header_overrides={"alg": "HS256"})
        with self.assertRaises(AlgorithmMismatchError):
            self.validator.validate_token(token)

    # -----------------------------------------------------------------
    # 4. Confusi?n de Tipos y Tokens Inv?lidos
    # -----------------------------------------------------------------
    def test_10_id_token_rejected_via_typ(self):
        """ID Token presentado en el PEP en lugar de un Access Token."""
        token = self._forge_token(header_overrides={"typ": "ID_TOKEN"})
        with self.assertRaises(InvalidTokenTypeError):
            self.validator.validate_token(token)

    def test_11_id_token_rejected_via_token_use(self):
        """Token con claim token_use='id' rechazado por el PEP."""
        token = self._forge_token(payload_overrides={"token_use": "id"})
        with self.assertRaises(InvalidTokenTypeError):
            self.validator.validate_token(token)

    def test_12_legacy_hmac_token_rejected(self):
        """Formato legacy 'payload::sig' rechazado en el nuevo validador."""
        with self.assertRaises(MalformedTokenError):
            self.validator.validate_token('{"sub":"demo","role":"medico"}::0123456789abcdef')

    def test_13_malformed_string_rejected(self):
        """Cadenas no JWS rechazadas."""
        with self.assertRaises(MalformedTokenError):
            self.validator.validate_token("this.isnot.a.valid.token")

    # -----------------------------------------------------------------
    # 5. Reclamaciones Temporales y de Identidad
    # -----------------------------------------------------------------
    def test_14_expired_token_rejected(self):
        """Token con 'exp' en el pasado rechazado."""
        token = self._forge_token(payload_overrides={"exp": int(time.time()) - 100})
        with self.assertRaises(TokenExpiredError):
            self.validator.validate_token(token)

    def test_15_future_nbf_token_rejected(self):
        """Token con 'nbf' futuro rechazado."""
        token = self._forge_token(payload_overrides={"nbf": int(time.time()) + 300})
        with self.assertRaises(TokenNotYetValidError):
            self.validator.validate_token(token)

    def test_16_future_iat_anomalous_rejected(self):
        """Token con 'iat' en el futuro an?malo rechazado."""
        token = self._forge_token(payload_overrides={"iat": int(time.time()) + 300})
        with self.assertRaises(TokenNotYetValidError):
            self.validator.validate_token(token)

    def test_17_untrusted_issuer_rejected(self):
        """Issuer de otro servidor o realm rechazado."""
        token = self._forge_token(payload_overrides={"iss": "http://rogue-server.local/realms/fake"})
        with self.assertRaises(UntrustedIssuerError):
            self.validator.validate_token(token)

    def test_18_invalid_audience_rejected(self):
        """Audience de otro cliente o API rechazada."""
        token = self._forge_token(payload_overrides={"aud": ["billing-api"]})
        with self.assertRaises(InvalidAudienceError):
            self.validator.validate_token(token)

    def test_19_missing_sub_rejected(self):
        """Token sin claim 'sub' rechazado."""
        token = self._forge_token(payload_overrides={"sub": None})
        with self.assertRaises(MissingClaimError):
            self.validator.validate_token(token)

    # -----------------------------------------------------------------
    # 6. Autorizaci?n, Menor Privilegio y Default Deny
    # -----------------------------------------------------------------
    def test_20_insufficient_roles_default_deny(self):
        """Usuario sin roles cl?nicos v?lidos es rechazado por Default Deny."""
        token = self._forge_token(payload_overrides={"realm_access": {"roles": ["offline_access"]}})
        with self.assertRaises(InsufficientPermissionsError):
            self.validator.validate_token(token)

    def test_21_role_segregation_enforced(self):
        """T?cnico de laboratorio bloqueado al intentar crear ?rdenes (solo admisi?n)."""
        token = self._forge_token(payload_overrides={"realm_access": {"roles": ["laboratorio"]}})
        ctx = self.validator.validate_token(token)
        with self.assertRaises(InsufficientPermissionsError):
            enforce_clinical_action(ctx, "CREATE_ORDER")

    # -----------------------------------------------------------------
    # 7. Resiliencia de Claves y Rotaci?n JWKS
    # -----------------------------------------------------------------
    def test_22_key_rotation_auto_refresh(self):
        """Al rotar una clave en Keycloak, el validador actualiza el JWKS y valida con la nueva."""
        new_kid = "lab-rsa-key-02"
        new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.mock_cache.add_key(new_kid, new_key)
        # Simular que transcurri? el intervalo m?nimo de seguridad desde el ?ltimo fetch
        self.mock_cache._last_fetch_timestamp = time.time() - 61

        token_new_key = self._forge_token(
            header_overrides={"kid": new_kid},
            signing_key=new_key,
        )
        ctx = self.validator.validate_token(token_new_key)
        self.assertEqual(ctx.username, "medico.demo")

    def test_23_unknown_kid_rejected(self):
        """Clave completamente inexistente es rechazada tras refresco."""
        self.mock_cache._last_fetch_timestamp = time.time() - 61
        token = self._forge_token(header_overrides={"kid": "phantom-key-999"})
        with self.assertRaises(KeyNotFoundError):
            self.validator.validate_token(token)

    def test_24_jwks_network_failure_fail_closed(self):
        """Si el endpoint JWKS falla y la clave no est? en cach?, denegar por defecto."""
        failing_cache = MockJWKSCacheManager(key_pairs={}, expected_issuer=self.issuer, fail_network=True, initial_fetch=False)
        failing_validator = ZeroTrustJWTValidator(
            discovery_url="http://fail-host/discovery",
            cache_manager=failing_cache,
        )
        token = self._forge_token()
        with self.assertRaises(JWKSFetchError):
            failing_validator.validate_token(token)

    def test_25_rate_limit_on_unknown_kid_dos_protection(self):
        """Consultas consecutivas con 'kid' falso respetan el intervalo de seguridad."""
        # Forzar estado inicial como si acabara de pasar la ventana
        self.mock_cache._last_fetch_timestamp = time.time() - 61
        token = self._forge_token(header_overrides={"kid": "flood-key-01"})
        initial_fetches = self.mock_cache.fetch_count

        # Primer fallo gatilla un refresco de JWKS
        with self.assertRaises(KeyNotFoundError):
            self.validator.validate_token(token)
        self.assertEqual(self.mock_cache.fetch_count, initial_fetches + 1)

        # Segundo fallo inmediato NO gatilla otro refresco (protecci?n de intervalo activa)
        with self.assertRaises(KeyNotFoundError):
            self.validator.validate_token(token)
        self.assertEqual(self.mock_cache.fetch_count, initial_fetches + 1)



    # -----------------------------------------------------------------
    # 8. Pruebas de Integracion Etapa 1: Audiencia, Roles y MFA Riguroso
    # -----------------------------------------------------------------
    def test_26_stage1_admission_user_without_mfa_can_create_order(self):
        """Usuario de admision autenticado sin MFA puede registrar ordenes preanaliticas."""
        token = self._forge_token(
            payload_overrides={
                "preferred_username": "recepcion.demo",
                "realm_access": {"roles": ["admision"]},
                "amr": ["pwd"],
                "acr": "1",
            }
        )
        ctx = self.validator.validate_token(token)
        self.assertFalse(ctx.mfa_verified)
        self.assertIn("ROLE_RECEPTION", ctx.roles)
        try:
            enforce_clinical_action(ctx, "CREATE_ORDER")
        except Exception as e:
            self.fail(f"CREATE_ORDER fallo inesperadamente para admision: {e}")

    def test_27_stage1_admission_user_cannot_validate_order(self):
        """Usuario de admision intentando validar ordenes es bloqueado por control de roles."""
        token = self._forge_token(
            payload_overrides={
                "preferred_username": "recepcion.demo",
                "realm_access": {"roles": ["admision"]},
                "amr": ["pwd"],
                "acr": "1",
            }
        )
        ctx = self.validator.validate_token(token)
        with self.assertRaises(InsufficientPermissionsError):
            enforce_clinical_action(ctx, "VALIDATE_ORDER")

    def test_28_stage1_doctor_with_valid_mfa_can_validate_order(self):
        """Medico patologo con evidencia MFA valida (OTP en AMR) puede validar y firmar ordenes."""
        token = self._forge_token(
            payload_overrides={
                "preferred_username": "patologo.titular",
                "realm_access": {"roles": ["medico"]},
                "amr": ["pwd", "otp"],
                "acr": "2",
            }
        )
        ctx = self.validator.validate_token(token)
        self.assertTrue(ctx.mfa_verified)
        self.assertIn("ROLE_PATHOLOGIST", ctx.roles)
        try:
            enforce_clinical_action(ctx, "VALIDATE_ORDER")
        except Exception as e:
            self.fail(f"VALIDATE_ORDER fallo para medico con MFA valido: {e}")

    def test_29_stage1_doctor_without_mfa_cannot_validate_order(self):
        """Medico patologo sin evidencia MFA es bloqueado al intentar validar ordenes criticas."""
        token = self._forge_token(
            payload_overrides={
                "preferred_username": "patologo.guardia",
                "realm_access": {"roles": ["medico"]},
                "amr": ["pwd"],
                "acr": "1",
            }
        )
        ctx = self.validator.validate_token(token)
        self.assertFalse(ctx.mfa_verified)
        with self.assertRaises(MFARequiredError):
            enforce_clinical_action(ctx, "VALIDATE_ORDER")

    def test_30_stage1_token_with_acr_1_never_proves_mfa(self):
        """Token con acr=1 (contrasena basica) clasifica estrictamente mfa_verified=False."""
        token = self._forge_token(
            payload_overrides={
                "acr": "1",
                "amr": ["pwd"],
            }
        )
        ctx = self.validator.validate_token(token)
        self.assertFalse(ctx.mfa_verified)
        with self.assertRaises(MFARequiredError):
            enforce_clinical_action(ctx, "VALIDATE_ORDER")

    def test_31_stage1_simulated_acr_2_untrusted_by_default(self):
        """Token con acr=2 sin amr explicito se rechaza por defecto en validador Zero Trust estandar."""
        token = self._forge_token(
            payload_overrides={
                "acr": "2",
                "amr": ["pwd"],
            }
        )
        ctx = self.validator.validate_token(token)
        self.assertFalse(ctx.mfa_verified)
        with self.assertRaises(MFARequiredError):
            enforce_clinical_action(ctx, "VALIDATE_ORDER")

    def test_32_stage1_simulated_acr_2_trusted_when_explicitly_configured(self):
        """Token con acr=2 se acepta como MFA cuando el validador tiene trusted_mfa_acr=2 explicito."""
        custom_validator = ZeroTrustJWTValidator(
            discovery_url="http://mock-discovery/openid-configuration",
            expected_audience=self.audience,
            cache_manager=self.mock_cache,
            trusted_mfa_acr="2",
        )
        token = self._forge_token(
            payload_overrides={
                "acr": "2",
                "amr": ["pwd"],
            }
        )
        ctx = custom_validator.validate_token(token)
        self.assertTrue(ctx.mfa_verified)
        try:
            enforce_clinical_action(ctx, "VALIDATE_ORDER")
        except Exception as e:
            self.fail(f"VALIDATE_ORDER fallo con trusted_mfa_acr configurado: {e}")

    def test_33_stage1_token_without_amr_claim_defaults_to_mfa_false(self):
        """Token sin claim amr (como los emitidos actualmente por Keycloak) resulta en mfa_verified=False."""
        token = self._forge_token(
            payload_overrides={
                "preferred_username": "patologo.legacy",
                "realm_access": {"roles": ["medico"]},
                "acr": "1",
                "amr": None,
            }
        )
        ctx = self.validator.validate_token(token)
        self.assertFalse(ctx.mfa_verified)
        with self.assertRaises(MFARequiredError):
            enforce_clinical_action(ctx, "VALIDATE_ORDER")

    def test_34_stage1_invalid_audience_rejected(self):
        """Token con claim aud diferente a clinical-poc-api debe ser rechazado inmediatamente."""
        token = self._forge_token(payload_overrides={"aud": ["account", "hospital-frontend"]})
        with self.assertRaises(InvalidAudienceError):
            self.validator.validate_token(token)

    def test_35_stage1_user_with_insufficient_permissions_rejected(self):
        """Usuario auditor intentando operaciones operativas clinicas es denegado por RBAC."""
        token = self._forge_token(
            payload_overrides={
                "preferred_username": "auditor.seguridad",
                "realm_access": {"roles": ["auditor"]},
                "amr": ["pwd", "otp"],
            }
        )
        ctx = self.validator.validate_token(token)
        self.assertIn("ROLE_SECURITY_AUDITOR", ctx.roles)
        try:
            enforce_clinical_action(ctx, "VIEW_AUDIT_LOGS")
        except Exception as e:
            self.fail(f"Auditor no pudo consultar registros de auditoria: {e}")
        with self.assertRaises(InsufficientPermissionsError):
            enforce_clinical_action(ctx, "CREATE_ORDER")
        with self.assertRaises(InsufficientPermissionsError):
            enforce_clinical_action(ctx, "VALIDATE_ORDER")

    def test_36_stage1_tampered_token_rejected(self):
        """Token con contenido manipulado en transito genera fallo criptografico de firma."""
        tampered_token = self._forge_token(corrupt_signature=True)
        with self.assertRaises(InvalidSignatureError):
            self.validator.validate_token(tampered_token)

    def test_37_stage1_expired_token_rejected(self):
        """Token expirado debe ser rechazado conforme al claim exp."""
        expired_token = self._forge_token(payload_overrides={"exp": int(time.time()) - 120})
        with self.assertRaises(TokenExpiredError):
            self.validator.validate_token(expired_token)

    def test_38_stage1_id_token_rejected_in_pep(self):
        """ID Token presentado en lugar de Access Token es rechazado formalmente."""
        id_token = self._forge_token(
            header_overrides={"typ": "JWT"},
            payload_overrides={"token_use": "id"},
        )
        with self.assertRaises(InvalidTokenTypeError):
            self.validator.validate_token(id_token)



    # -----------------------------------------------------------------
    # 9. Pruebas de Endurecimiento Fase 4: Discriminacion Taxativa de Tipo de Token y AZP
    # -----------------------------------------------------------------
    def test_39_id_token_with_valid_audience_rejected_by_type(self):
        """ID Token con typ='ID' que contenga artificialmente la audiencia clinica debe ser rechazado por tipo."""
        id_token_spoofed = self._forge_token(
            header_overrides={"typ": "JWT"},
            payload_overrides={
                "typ": "ID",
                "aud": [self.audience],  # Audiencia correcta del servicio clinico
                "token_use": None,       # Sin claim de AWS Cognito
            }
        )
        with self.assertRaises(InvalidTokenTypeError):
            self.validator.validate_token(id_token_spoofed)

    def test_40_authorized_party_azp_validation(self):
        """Validador con azp esperado rechaza tokens emitidos a clientes OIDC no autorizados."""
        strict_azp_validator = ZeroTrustJWTValidator(
            discovery_url="http://mock-discovery/openid-configuration",
            expected_audience=self.audience,
            cache_manager=self.mock_cache,
            expected_authorized_party="clinical-poc-frontend-test",
        )
        # Token con cliente autorizado valido
        token_good = self._forge_token(
            payload_overrides={"azp": "clinical-poc-frontend-test"}
        )
        ctx = strict_azp_validator.validate_token(token_good)
        self.assertEqual(ctx.username, "medico.demo")

        # Token con cliente no autorizado / sustituido
        token_bad = self._forge_token(
            payload_overrides={"azp": "malicious-third-party-client"}
        )
        with self.assertRaises(InvalidAudienceError):
            strict_azp_validator.validate_token(token_bad)


    def test_41_require_bearer_type_enforcement_positive(self):
        """Cuando require_bearer_type=True, token con typ='Bearer' es validado exitosamente."""
        strict_bearer_validator = ZeroTrustJWTValidator(
            discovery_url="http://mock-discovery/openid-configuration",
            expected_audience=self.audience,
            cache_manager=self.mock_cache,
            require_bearer_type=True,
        )
        token = self._forge_token(payload_overrides={"typ": "Bearer"})
        ctx = strict_bearer_validator.validate_token(token)
        self.assertEqual(ctx.username, "medico.demo")

    def test_42_require_bearer_type_rejects_missing_or_ambiguous(self):
        """Cuando require_bearer_type=True, rechaza tokens sin typ o con tipos ambiguos/malformados."""
        strict_bearer_validator = ZeroTrustJWTValidator(
            discovery_url="http://mock-discovery/openid-configuration",
            expected_audience=self.audience,
            cache_manager=self.mock_cache,
            require_bearer_type=True,
        )
        # Token sin claim typ
        token_no_typ = self._forge_token(payload_overrides={"typ": None})
        with self.assertRaises(InvalidTokenTypeError):
            strict_bearer_validator.validate_token(token_no_typ)

        # Token con tipo ambiguo 'refresh'
        token_refresh = self._forge_token(payload_overrides={"typ": "refresh"})
        with self.assertRaises(InvalidTokenTypeError):
            strict_bearer_validator.validate_token(token_refresh)

        # Token con tipo malformado no-string
        token_malformed = self._forge_token(payload_overrides={"typ": 12345})
        with self.assertRaises(InvalidTokenTypeError):
            strict_bearer_validator.validate_token(token_malformed)


if __name__ == "__main__":
    unittest.main()
