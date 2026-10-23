#!/usr/bin/env python3
"""
SGSI-ZTA Hospital Lab: Zero Trust JWT/OIDC Validator
M?dulo desacoplado de validaci?n criptogr?fica y autorizaci?n contextual para el PEP cl?nico.
Conforme a NIST SP 800-207, RFC 7519 (JWT), RFC 7517 (JWK) y RFC 7515 (JWS).
"""

from __future__ import annotations

import base64
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.error import URLError
from urllib.request import Request, urlopen

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

logger = logging.getLogger("jwt_validator")

# L?mites de seguridad defensiva
MAX_TOKEN_BYTES = 16384          # 16 KB l?mite de longitud de token
MAX_JWKS_RESPONSE_BYTES = 1048576 # 1 MB l?mite de respuesta JWKS
HTTP_TIMEOUT_SECONDS = 5


# =====================================================================
# Jerarqu?a de Excepciones de Seguridad (Zero Trust)
# =====================================================================
class JWTValidationError(Exception):
    """Excepci?n base para violaciones de pol?ticas Zero Trust en tokens."""


class MalformedTokenError(JWTValidationError):
    """Estructura de token JWS corrupta o no conforme a RFC 7519."""


class InvalidTokenTypeError(JWTValidationError):
    """Se present? un tipo de token no admitido (ej. ID Token en lugar de Access Token)."""


class AlgorithmMismatchError(JWTValidationError):
    """Algoritmo de firma no autorizado o inseguro (ej. 'none', 'HS256')."""


class KeyNotFoundError(JWTValidationError):
    """Identificador de clave 'kid' no registrado en el JWKS activo del emisor."""


class InvalidSignatureError(JWTValidationError):
    """Firma digital no verificable con la clave p?blica institucional."""


class TokenExpiredError(JWTValidationError):
    """El token ha expirado seg?n el claim 'exp'."""


class TokenNotYetValidError(JWTValidationError):
    """El token no es v?lido todav?a seg?n los claims 'nbf' o 'iat'."""


class UntrustedIssuerError(JWTValidationError):
    """El claim 'iss' no coincide con el Identity Provider autorizado."""


class InvalidAudienceError(JWTValidationError):
    """El claim 'aud' no incluye la audiencia designada del servicio cl?nico."""


class MissingClaimError(JWTValidationError):
    """El token carece de claims esenciales para el control de acceso."""


class InsufficientPermissionsError(JWTValidationError):
    """El sujeto autenticado carece de roles autorizados para la operaci?n cl?nica."""


class MFARequiredError(JWTValidationError):
    """Operaci?n sensible denegada por ausencia de evidencia concluyente de MFA."""


class JWKSFetchError(JWTValidationError):
    """Fallo en la comunicaci?n segura con el endpoint JWKS del emisor."""


# =====================================================================
# Estructuras de Datos
# =====================================================================
@dataclass(frozen=True)
class ClinicalAuthContext:
    """Contexto de seguridad inmutable generado tras validaci?n criptogr?fica exitosa."""

    subject: str
    username: str
    roles: Set[str]
    raw_realm_roles: Set[str]
    mfa_verified: bool
    issuer: str
    audience: List[str]
    issued_at: int
    expires_at: int
    token_id: Optional[str]
    amr: List[str] = field(default_factory=list)
    acr: Optional[str] = None
    is_service_account: bool = False


# Mapeo estricto de roles de Keycloak hacia el modelo RBAC del LIS
ROLE_MAPPING: Dict[str, str] = {
    "admision": "ROLE_RECEPTION",
    "receptionist": "ROLE_RECEPTION",
    "ROLE_RECEPTION": "ROLE_RECEPTION",
    "ROLE_RECEPTIONIST": "ROLE_RECEPTION",
    "laboratorio": "ROLE_LAB_TECH",
    "ROLE_LAB_TECH": "ROLE_LAB_TECH",
    "medico": "ROLE_PATHOLOGIST",
    "ROLE_PATHOLOGIST": "ROLE_PATHOLOGIST",
    "auditor": "ROLE_SECURITY_AUDITOR",
    "ROLE_SECURITY_AUDITOR": "ROLE_SECURITY_AUDITOR",
    "sgsi-admin": "ROLE_PLATFORM_ADMIN",
    "administrador": "ROLE_PLATFORM_ADMIN",
    "ROLE_PLATFORM_ADMIN": "ROLE_PLATFORM_ADMIN",
}

# Operaciones cl?nicas y sus pol?ticas de menor privilegio
CLINICAL_ACTIONS = frozenset({"CREATE_ORDER", "VALIDATE_ORDER", "VIEW_ORDERS"})

# Acciones que solo puede ejecutar una persona con MFA acreditada. Una cuenta
# de servicio queda excluida igual que en las acciones clinicas.
HUMAN_ONLY_ACTIONS = frozenset({"MANAGE_IDENTITIES", "RUN_DIAGNOSTICS", "MANAGE_ASSETS", "MANAGE_RISKS", "MANAGE_CONTROLS", "MANAGE_INCIDENTS", "ACK_ALERTS", "MANAGE_INSTRUMENTS", "SUBMIT_VALIDATION", "GENERATE_REPORTS"})

CLINICAL_PERMISSIONS: Dict[str, Dict[str, Any]] = {
    "CREATE_ORDER": {
        "required_roles": {"ROLE_RECEPTION"},
        "require_mfa": False,
        "description": "Admisi?n de pacientes y registro de ?rdenes preanal?ticas",
    },
    "VIEW_ORDERS": {
        "required_roles": {"ROLE_RECEPTION", "ROLE_LAB_TECH", "ROLE_PATHOLOGIST"},
        "require_mfa": False,
        "description": "Consulta de ?rdenes de laboratorio",
    },
    "VALIDATE_ORDER": {
        "required_roles": {"ROLE_PATHOLOGIST"},
        "require_mfa": True,  # Operaci?n cr?tica: exige MFA activo demostrado
        "description": "Firma m?dica y liberaci?n de resultados anal?ticos",
    },
    "VIEW_AUDIT_LOGS": {
        "required_roles": {"ROLE_SECURITY_AUDITOR"},
        "require_mfa": False,
        "description": "Acceso a registros de auditor?a y cadena inmutable",
    },
    "MANAGE_IDENTITIES": {
        "required_roles": {"ROLE_PLATFORM_ADMIN"},
        "require_mfa": True,
        "description": "Administracion de identidades sinteticas de la plataforma",
    },
    "VIEW_DIAGNOSTICS": {
        "required_roles": {"ROLE_SECURITY_AUDITOR", "ROLE_PLATFORM_ADMIN"},
        "require_mfa": False,
        "description": "Consulta de comprobadores, ejecuciones y hallazgos de diagnostico de seguridad",
    },
    "RUN_DIAGNOSTICS": {
        "required_roles": {"ROLE_PLATFORM_ADMIN"},
        "require_mfa": True,  # Operacion sensible: dispara comprobadores sobre la configuracion real
        "description": "Ejecucion de comprobadores de diagnostico de seguridad del entorno F11",
    },
    "VIEW_ASSETS": {
        "required_roles": {
            "ROLE_RECEPTION",
            "ROLE_LAB_TECH",
            "ROLE_PATHOLOGIST",
            "ROLE_SECURITY_AUDITOR",
            "ROLE_PLATFORM_ADMIN",
        },
        "require_mfa": False,
        "description": "Consulta del inventario de activos de la plataforma",
    },
    "MANAGE_ASSETS": {
        "required_roles": {"ROLE_PLATFORM_ADMIN"},
        "require_mfa": True,  # Operacion sensible: modifica el inventario que sostiene la evidencia
        "description": "Alta, actualizacion y evaluacion de activos del inventario",
    },

    "VIEW_RISKS": {
        "required_roles": {"ROLE_SECURITY_AUDITOR", "ROLE_PLATFORM_ADMIN"},
        "require_mfa": False,
        "description": "Consulta de la matriz de riesgos y vulnerabilidades (M4)",
    },
    "MANAGE_RISKS": {
        "required_roles": {"ROLE_PLATFORM_ADMIN"},
        "require_mfa": True,
        "description": "Alta, modificacion, evaluacion y vinculacion de riesgos (M4)",
    },
    "VIEW_CONTROLS": {
        "required_roles": {"ROLE_SECURITY_AUDITOR", "ROLE_PLATFORM_ADMIN"},
        "require_mfa": False,
        "description": "Consulta del catalogo de controles y su estado de verificacion (M5)",
    },
    "MANAGE_CONTROLS": {
        "required_roles": {"ROLE_PLATFORM_ADMIN"},
        "require_mfa": True,
        "description": "Alta, modificacion, verificacion con evidencia y vinculacion de controles (M5)",
    },

    "VIEW_INCIDENTS": {
        "required_roles": {"ROLE_SECURITY_AUDITOR", "ROLE_PLATFORM_ADMIN"},
        "require_mfa": False,
        "description": (
            "Consulta de incidentes y su historial de transiciones (M6). Minimo "
            "privilegio: solo el Oficial de Seguridad y el Administrador de "
            "plataforma ven el seguimiento operativo de incidentes."
        ),
    },
    "MANAGE_INCIDENTS": {
        "required_roles": {"ROLE_PLATFORM_ADMIN"},
        "require_mfa": True,
        "description": (
            "Alta y transicion de estado de incidentes (M6). Minimo privilegio: "
            "solo el Administrador de plataforma, con MFA acreditada, y en "
            "HUMAN_ONLY_ACTIONS: una cuenta de servicio nunca gestiona incidentes."
        ),
    },
    "VIEW_ALERTS": {
        "required_roles": {"ROLE_SECURITY_AUDITOR", "ROLE_PLATFORM_ADMIN"},
        "require_mfa": False,
        "description": (
            "Consulta de alertas derivadas del estado real (M6). Minimo "
            "privilegio: el Oficial de Seguridad y el Administrador; las alertas "
            "describen riesgos y hallazgos que el resto de roles no debe ver."
        ),
    },
    "ACK_ALERTS": {
        "required_roles": {"ROLE_PLATFORM_ADMIN"},
        "require_mfa": True,
        "description": (
            "Acuse de alertas derivadas (M6). Minimo privilegio: solo el "
            "Administrador de plataforma, con MFA acreditada, y en "
            "HUMAN_ONLY_ACTIONS: el acuse asume la responsabilidad de respuesta."
        ),
    },
    "VIEW_INDICATORS": {
        "required_roles": {
            "ROLE_RECEPTION",
            "ROLE_LAB_TECH",
            "ROLE_PATHOLOGIST",
            "ROLE_SECURITY_AUDITOR",
            "ROLE_PLATFORM_ADMIN",
        },
        "require_mfa": False,
        "description": (
            "Consulta del panel de indicadores M8. Es el panel de lectura: lo ve "
            "cualquier identidad autenticada; no expone datos clinicos ni permite "
            "escritura, por lo que no exige MFA ni rol de gestion."
        ),
    },

    "VIEW_INSTRUMENTS": {
        "required_roles": {"ROLE_SECURITY_AUDITOR", "ROLE_PLATFORM_ADMIN"},
        "require_mfa": False,
        "description": (
            "Consulta de instrumentos de validacion y sus items (M9). Minimo "
            "privilegio: solo el Oficial de Seguridad y el Administrador de "
            "plataforma ven la herramienta de medida; el resto de roles no la "
            "necesita para operar."
        ),
    },
    "MANAGE_INSTRUMENTS": {
        "required_roles": {"ROLE_PLATFORM_ADMIN"},
        "require_mfa": True,
        "description": (
            "Alta de instrumentos de validacion (M9). Minimo privilegio: solo el "
            "Administrador de plataforma, con MFA acreditada, y en "
            "HUMAN_ONLY_ACTIONS: una cuenta de servicio nunca define el "
            "instrumento con el que se evalua el modelo."
        ),
    },
    "VIEW_VALIDATIONS": {
        "required_roles": {"ROLE_SECURITY_AUDITOR", "ROLE_PLATFORM_ADMIN"},
        "require_mfa": False,
        "description": (
            "Consulta de dictamenes de expertos registrados (M9). Minimo "
            "privilegio: el dictamen es evidencia de tesis y solo lo leen el "
            "Oficial de Seguridad y el Administrador de plataforma."
        ),
    },
    "SUBMIT_VALIDATION": {
        "required_roles": {"ROLE_PLATFORM_ADMIN"},
        "require_mfa": True,
        "description": (
            "Registro de un dictamen de experto (M9). Minimo privilegio: solo el "
            "Administrador de plataforma, con MFA acreditada, y en "
            "HUMAN_ONLY_ACTIONS. Registrar un dictamen es un acto humano con "
            "responsabilidad: el sistema no lo genera ni lo deriva."
        ),
    },
    "VIEW_EVIDENCE": {
        "required_roles": {"ROLE_SECURITY_AUDITOR", "ROLE_PLATFORM_ADMIN"},
        "require_mfa": False,
        "description": (
            "Consulta del inventario de evidencia por objetivo (O1..O4). Minimo "
            "privilegio: la evidencia agregada expone hallazgos, riesgos, "
            "controles e incidentes, por lo que solo la ven auditoria y "
            "administracion."
        ),
    },
    "VIEW_REPORTS": {
        "required_roles": {"ROLE_SECURITY_AUDITOR", "ROLE_PLATFORM_ADMIN"},
        "require_mfa": False,
        "description": (
            "Consulta de informes generados. Minimo privilegio: el informe "
            "consolida la evidencia de todos los modulos; solo lo leen el "
            "Oficial de Seguridad y el Administrador de plataforma."
        ),
    },
    "GENERATE_REPORTS": {
        "required_roles": {"ROLE_PLATFORM_ADMIN"},
        "require_mfa": True,
        "description": (
            "Generacion de un informe desde datos reales. Minimo privilegio: "
            "solo el Administrador de plataforma, con MFA acreditada, y en "
            "HUMAN_ONLY_ACTIONS: emitir un informe es un acto humano que asume "
            "lo que la base declara y lo que declara ausente."
        ),
    },

}


# =====================================================================
# Utilidades de Decodificaci?n
# =====================================================================
def base64url_decode(input_str: str) -> bytes:
    """Decodifica cadenas base64url sin padding seg?n RFC 7515."""
    rem = len(input_str) % 4
    if rem > 0:
        input_str += "=" * (4 - rem)
    return base64.urlsafe_b64decode(input_str.encode("ascii"))


# =====================================================================
# Gestor de Cach? JWKS con Protecci?n Anti-DoS
# =====================================================================
class JWKSCacheManager:
    """
    Gestiona la obtenci?n y almacenamiento en cach? de claves p?blicas RSA del realm.
    Implementa rate-limiting ante claves desconocidas para mitigar ataques de denegaci?n de servicio.
    """

    def __init__(
        self,
        discovery_url: str,
        cache_ttl_seconds: int = 3600,
        min_refresh_interval_seconds: int = 60,
    ) -> None:
        self.discovery_url = discovery_url
        self.cache_ttl_seconds = cache_ttl_seconds
        self.min_refresh_interval_seconds = min_refresh_interval_seconds

        self._jwks_uri: Optional[str] = None
        self._expected_issuer: Optional[str] = None
        self._keys_by_kid: Dict[str, Any] = {}
        self._last_fetch_timestamp: float = 0.0

    @property
    def expected_issuer(self) -> str:
        if not self._expected_issuer:
            self._fetch_discovery()
        return self._expected_issuer or ""

    def _fetch_discovery(self) -> None:
        """Obtiene issuer y jwks_uri desde el documento .well-known/openid-configuration."""
        try:
            req = Request(self.discovery_url, headers={"Accept": "application/json"})
            with urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as response:
                if response.status != 200:
                    raise JWKSFetchError(f"Discovery OIDC fall? con HTTP {response.status}")
                raw_data = response.read(MAX_JWKS_RESPONSE_BYTES)
                data = json.loads(raw_data.decode("utf-8"))

            self._expected_issuer = data.get("issuer")
            self._jwks_uri = data.get("jwks_uri")

            if not self._expected_issuer or not self._jwks_uri:
                raise JWKSFetchError("Discovery OIDC carece de 'issuer' o 'jwks_uri'")
        except (URLError, TimeoutError, json.JSONDecodeError) as error:
            raise JWKSFetchError(f"No se pudo consultar discovery OIDC: {error}") from error

    def _fetch_jwks(self) -> None:
        """Descarga el JWKS y construye claves p?blicas RSA de forma segura."""
        if not self._jwks_uri:
            self._fetch_discovery()

        assert self._jwks_uri is not None
        try:
            req = Request(self._jwks_uri, headers={"Accept": "application/json"})
            with urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as response:
                if response.status != 200:
                    raise JWKSFetchError(f"Obtenci?n de JWKS fall? con HTTP {response.status}")
                raw_data = response.read(MAX_JWKS_RESPONSE_BYTES)
                payload = json.loads(raw_data.decode("utf-8"))

            new_keys: Dict[str, Any] = {}
            for jwk in payload.get("keys", []):
                if jwk.get("kty") == "RSA" and jwk.get("use") in ("sig", None):
                    kid = jwk.get("kid")
                    if not kid or "n" not in jwk or "e" not in jwk:
                        continue
                    n_bytes = base64url_decode(jwk["n"])
                    e_bytes = base64url_decode(jwk["e"])
                    n_int = int.from_bytes(n_bytes, byteorder="big")
                    e_int = int.from_bytes(e_bytes, byteorder="big")
                    public_key = RSAPublicNumbers(e_int, n_int).public_key()
                    new_keys[kid] = public_key

            self._keys_by_kid = new_keys
            self._last_fetch_timestamp = time.time()
            logger.info("JWKS actualizado con ?xito. Claves cargadas: %d", len(new_keys))
        except (URLError, TimeoutError, json.JSONDecodeError, KeyError, ValueError) as error:
            raise JWKSFetchError(f"Error al descargar o procesar claves JWKS: {error}") from error

    def get_key(self, kid: str) -> Any:
        """Obtiene la clave RSA por 'kid', refrescando la cach? bajo control de rate-limit."""
        now = time.time()

        # 1. Clave presente y TTL v?lido
        if kid in self._keys_by_kid and (now - self._last_fetch_timestamp) < self.cache_ttl_seconds:
            return self._keys_by_kid[kid]

        # 2. Clave ausente o TTL expirado: refrescar solo si es la primera vez o si super? el intervalo
        if self._last_fetch_timestamp == 0.0 or (now - self._last_fetch_timestamp) >= self.min_refresh_interval_seconds:
            logger.warning("Clave con kid '%s' ausente o expirada. Refrescando JWKS...", kid)
            self._fetch_jwks()

        if kid not in self._keys_by_kid:
            raise KeyNotFoundError(f"Clave p?blica con kid '{kid}' no encontrada en el JWKS activo.")

        return self._keys_by_kid[kid]


# =====================================================================
# Validador Zero Trust de Access Tokens JWT
# =====================================================================
class ZeroTrustJWTValidator:
    """
    Validador criptogr?fico y motor PEP para el Clinical PoC.
    Rechaza por defecto tokens de ID, tokens sim?tricos y accesos sin privilegios.
    """

    ALLOWED_ALGORITHMS = ("RS256",)

    def __init__(
        self,
        discovery_url: str,
        expected_audience: str = "clinical-poc-api",
        clock_skew_seconds: int = 10,
        cache_manager: Optional[JWKSCacheManager] = None,
        trusted_mfa_acr: Optional[str] = None,
        expected_authorized_party: Optional[str] = None,
        require_bearer_type: bool = False,
    ) -> None:
        self.discovery_url = discovery_url
        self.expected_audience = expected_audience
        self.clock_skew_seconds = clock_skew_seconds
        self.cache_manager = cache_manager or JWKSCacheManager(discovery_url)
        self.trusted_mfa_acr = trusted_mfa_acr
        self.expected_authorized_party = expected_authorized_party
        self.require_bearer_type = require_bearer_type

    def validate_token(self, token_str: str) -> ClinicalAuthContext:
        """
        Valida rigurosamente un Bearer Access Token.
        Aplica validaci?n de 3 partes JWS, algoritmo RS256, firma RSA, claims y roles.
        """
        if not token_str or not isinstance(token_str, str):
            raise MalformedTokenError("Token nulo o tipo de dato no admitido.")

        clean_token = token_str.strip()
        if len(clean_token.encode("utf-8")) > MAX_TOKEN_BYTES:
            raise MalformedTokenError("Longitud de token excede el l?mite m?ximo permitido.")

        # Rechazo expl?cito de tokens HMAC legacy (formato payload::sig)
        if "::" in clean_token:
            raise MalformedTokenError("Tokens HMAC heredados no est?n autorizados en endpoints JWT.")

        parts = clean_token.split(".")
        if len(parts) != 3:
            raise MalformedTokenError("Estructura de token inv?lida; se requieren exactamente 3 partes JWS.")

        raw_header, raw_payload, raw_signature = parts

        # 1. Decodificar y Validar Encabezado
        try:
            header_bytes = base64url_decode(raw_header)
            header = json.loads(header_bytes.decode("utf-8"))
        except Exception as error:
            raise MalformedTokenError("Encabezado de token corrupto o JSON inv?lido.") from error

        alg = header.get("alg")
        if alg not in self.ALLOWED_ALGORITHMS:
            raise AlgorithmMismatchError(
                f"Algoritmo '{alg}' prohibido. Se exige estrictamente {self.ALLOWED_ALGORITHMS}."
            )

        # 2. Prevencion de Confusion de Tipos (Rechazar ID Tokens en encabezado JWS)
        typ = header.get("typ", "JWT")
        if not isinstance(typ, str):
            raise MalformedTokenError("Encabezado 'typ' malformado; se requiere cadena de texto.")
        if typ.strip().upper() in ("ID", "ID_TOKEN"):
            raise InvalidTokenTypeError("Se recibio un ID Token en el encabezado JWS; el API exige un Access Token Bearer.")

        kid = header.get("kid")
        if not kid:
            raise MalformedTokenError("Encabezado JWS carece del atributo obligatorio 'kid'.")

        # 3. Verificaci?n Criptogr?fica de la Firma Digital
        public_key = self.cache_manager.get_key(kid)
        try:
            signature_bytes = base64url_decode(raw_signature)
            signing_input = f"{raw_header}.{raw_payload}".encode("ascii")
            public_key.verify(
                signature_bytes,
                signing_input,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except InvalidSignature as error:
            raise InvalidSignatureError("Firma digital RS256 no verificable con la clave del emisor.") from error
        except Exception as error:
            raise MalformedTokenError("Error al procesar la firma criptogr?fica.") from error

        # 4. Decodificar y Validar Reclamaciones (Payload)
        try:
            payload_bytes = base64url_decode(raw_payload)
            payload = json.loads(payload_bytes.decode("utf-8"))
        except Exception as error:
            raise MalformedTokenError("Cuerpo del token corrupto o JSON inv?lido.") from error

        self._validate_claims(payload)

        # 5. Extracci?n y Normalizaci?n de Privilegios (Default Deny)
        realm_roles = set(payload.get("realm_access", {}).get("roles", []))
        mapped_roles = {ROLE_MAPPING[r] for r in realm_roles if r in ROLE_MAPPING}

        if not mapped_roles:
            raise InsufficientPermissionsError(
                f"El sujeto '{payload.get('preferred_username', payload.get('sub'))}' carece de roles cl?nicos asignables."
            )

        # 6. Verificaci?n Rigurosa de MFA
        mfa_verified = self._verify_mfa_proof(payload)

        username = payload.get("preferred_username", payload["sub"])
        is_service_account = str(username).startswith("service-account-")

        return ClinicalAuthContext(
            subject=payload["sub"],
            username=username,
            roles=mapped_roles,
            raw_realm_roles=realm_roles,
            mfa_verified=mfa_verified,
            issuer=payload["iss"],
            audience=(
                payload["aud"]
                if isinstance(payload["aud"], list)
                else [payload["aud"]]
            ),
            issued_at=payload.get("iat", 0),
            expires_at=payload.get("exp", 0),
            token_id=payload.get("jti"),
            amr=payload.get("amr", []) if isinstance(payload.get("amr"), list) else [],
            acr=str(payload.get("acr")) if payload.get("acr") is not None else None,
            is_service_account=is_service_account,
        )

    def _validate_claims(self, payload: Dict[str, Any]) -> None:
        """Verifica vigencia temporal, emisor y audiencia con tolerancia de reloj."""
        now = time.time()

        # Sujeto obligatorio
        sub = payload.get("sub")
        if not sub or not isinstance(sub, str):
            raise MissingClaimError("El token carece del claim obligatorio 'sub'.")

        # Expiraci?n
        exp = payload.get("exp")
        if exp is None or not isinstance(exp, (int, float)):
            raise MissingClaimError("El token carece del claim obligatorio 'exp'.")
        if (now - self.clock_skew_seconds) >= exp:
            raise TokenExpiredError("El token ha expirado.")

        # Not Before (nbf)
        nbf = payload.get("nbf")
        if nbf is not None and isinstance(nbf, (int, float)):
            if (now + self.clock_skew_seconds) < nbf:
                raise TokenNotYetValidError("El token no es v?lido todav?a (nbf en el futuro).")

        # Issued At (iat)
        iat = payload.get("iat")
        if iat is not None and isinstance(iat, (int, float)):
            if (now + self.clock_skew_seconds) < iat:
                raise TokenNotYetValidError("El token indica fecha de emisi?n futura (iat an?malo).")

        # Emisor Confiable (Issuer)
        iss = payload.get("iss")
        expected_iss = self.cache_manager.expected_issuer
        if not iss or iss != expected_iss:
            raise UntrustedIssuerError(
                f"Emisor no confiable: recibido '{iss}', esperado '{expected_iss}'."
            )

        # Audiencia Espec?fica
        aud = payload.get("aud")
        audiences = [aud] if isinstance(aud, str) else (aud or [])
        if self.expected_audience not in audiences:
            raise InvalidAudienceError(
                f"Audiencia '{self.expected_audience}' ausente en el token (presentes: {audiences})."
            )

        # Discriminacion estricta de Tipo de Token (Access Token vs ID Token)
        token_typ = payload.get("typ")
        if self.require_bearer_type:
            if not token_typ or not isinstance(token_typ, str):
                raise InvalidTokenTypeError("El token carece del claim obligatorio 'typ' indicando 'Bearer'.")
            if token_typ.strip().upper() != "BEARER":
                raise InvalidTokenTypeError(
                    f"Tipo de token '{token_typ}' no admitido. Cuando require_bearer_type=True se exige exactamente 'Bearer'."
                )
        else:
            if token_typ is not None:
                if not isinstance(token_typ, str):
                    raise InvalidTokenTypeError("Claim 'typ' malformado; se requiere cadena de texto.")
                token_typ_str = token_typ.strip().upper()
                if token_typ_str in ("ID", "ID_TOKEN"):
                    raise InvalidTokenTypeError(
                        f"Se presento un ID Token (claim typ='{token_typ}') en el PEP; el API exige un Access Token Bearer."
                    )
                if token_typ_str not in ("BEARER", "JWT", "AT+JWT"):
                    raise InvalidTokenTypeError(
                        f"Tipo de token '{token_typ}' no admitido. Se exige 'Bearer' o 'JWT'."
                    )

        if payload.get("token_use") == "id":
            raise InvalidTokenTypeError("El claim token_use indica un ID Token.")

        # Validacion de Cliente Autorizado (azp) para mitigar sustitucion de clientes
        if self.expected_authorized_party:
            azp = payload.get("azp")
            if not azp or azp != self.expected_authorized_party:
                raise InvalidAudienceError(
                    f"Cliente autorizado (azp) invalido: recibido '{azp}', esperado '{self.expected_authorized_party}'."
                )

    def _verify_mfa_proof(self, payload: Dict[str, Any]) -> bool:
        """
        Comprobaci?n estricta de MFA.
        REGLA DE SEGURIDAD ZERO TRUST:
        1. acr=1 NUNCA demuestra TOTP (en Keycloak suele ser contrase?a b?sica).
        2. acr=2 tampoco se asume como MFA salvo que se configure expl?citamente en el validador
           tras acreditar que Keycloak asocia ese nivel a un desaf?o OTP efectivo.
        3. En ausencia de esa configuraci?n expl?cita, se exige 'amr' conteniendo 'otp' o 'totp'.
        """
        # 1. Comprobaci?n de AMR expl?cito
        amr = payload.get("amr", [])
        if isinstance(amr, list):
            if any(method.lower() in ("otp", "totp", "mfa-otp") for method in amr if isinstance(method, str)):
                return True

        # 2. Comprobaci?n de ACR solo si fue formalmente configurado como nivel confiable
        if self.trusted_mfa_acr:
            token_acr = str(payload.get("acr", ""))
            if token_acr == str(self.trusted_mfa_acr):
                return True

        # Denegaci?n por defecto si no hay evidencia expl?cita
        return False


# =====================================================================
# Funci?n de Control de Acceso Cl?nico (PEP Enforcement)
# =====================================================================
def enforce_clinical_action(context: ClinicalAuthContext, action: str) -> None:
    """
    Eval?a si el contexto autenticado satisface los requisitos de menor privilegio
    y pol?ticas contextuales de MFA para la acci?n solicitada.
    """
    policy = CLINICAL_PERMISSIONS.get(action)
    if not policy:
        raise InsufficientPermissionsError(f"Acci?n cl?nica desconocida o no autorizada: {action}")

    # Las cuentas de servicio (M2M) quedan restringidas a auditor?a, nunca a acciones cl?nicas.
    if (action in CLINICAL_ACTIONS or action in HUMAN_ONLY_ACTIONS) and context.is_service_account:
        raise InsufficientPermissionsError(
            f"Cuenta de servicio '{context.username}' no autorizada para acciones cl?nicas '{action}'."
        )

    required_roles: Set[str] = policy["required_roles"]
    if not context.roles.intersection(required_roles):
        raise InsufficientPermissionsError(
            f"El usuario '{context.username}' con roles {context.roles} no est? autorizado para '{action}'. "
            f"Se requiere al menos uno de: {required_roles}."
        )

    # Evaluaci?n obligatoria de MFA para operaciones cr?ticas (ej. validaci?n m?dica)
    if policy.get("require_mfa", False) and not context.mfa_verified:
        raise MFARequiredError(
            f"Operaci?n cl?nica cr?tica '{action}' DENEGADA para '{context.username}'. "
            "Se exige autenticaci?n multifactor (TOTP) verificada."
        )
