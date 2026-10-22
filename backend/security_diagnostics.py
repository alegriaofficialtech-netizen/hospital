#!/usr/bin/env python3
"""Modulo M2 de diagnostico de seguridad del laboratorio SGSI-ZTA (F11).

Este modulo ejecuta comprobadores sobre la configuracion EFECTIVA del
laboratorio F11 y publica hallazgos con el comando que los produjo y la
salida real de ese comando. No diagnostica por opinion: un comprobador que
no puede obtener evidencia devuelve ``warning`` con el motivo real, nunca
``passed`` por suposicion.

Reglas heredadas de la plataforma:

* La evidencia real es solo la del entorno F11 (``f11-local``).
* Los datos del laboratorio son sinteticos y se marcan como tales en el
  inventario; aqui no se generan datos, solo se leen.
* Ninguna credencial aparece en la evidencia: las lecturas del administrador
  de Keycloak usan el cliente de confianza de ``backend/identity_admin.py``
  y solo devuelven representaciones publicas (roles, atributos, tipos de
  credencial), nunca el valor de un secreto.

Los comprobadores que hablan con el backend propio NO hacen una peticion
HTTP contra el servicio que los ejecuta: ``http.server`` es de un solo hilo
y una peticion a si mismo durante una peticion en curso se bloquearia para
siempre. En su lugar se lee el codigo efectivo y la configuracion que el
proceso tiene cargada en memoria, que es la misma configuracion con la que
el servicio responderia.

El ``evidence_command`` de cada hallazgo describe la OPERACION REAL que
produjo la evidencia: la peticion HTTP concreta a la API de administracion
de Keycloak con su ruta, la lectura del fichero concreto con su ruta, la
consulta SQL concreta o el ``docker inspect`` que si se ejecuta. No se cita
un comando que no llega a ejecutarse.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(CURRENT_DIR)
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from database import F11_ENVIRONMENT
from identity_admin import IdentityAdminClient, IdentityAdminError, PROTECTED_ROLES
from jwt_validator import CLINICAL_PERMISSIONS, HUMAN_ONLY_ACTIONS, ROLE_MAPPING

# Evidencia acotada: se guarda la salida real recortada a un maximo legible.
MAX_EVIDENCE_CHARS = 4000

# Contenedores del entorno F11 (compose.yaml) usados como fuente de verdad
# del estado efectivo en ejecucion.
F11_FRONTEND_CONTAINER = "sgsi-zta-f11-frontend"
F11_KEYCLOAK_CONTAINER = "sgsi-zta-f11-keycloak"

# Cliente publico de la plataforma frente al backend. Su configuracion PKCE
# es la que aplica la proteccion del Authorization Code con PKCE.
PUBLIC_CLIENT_ID = os.environ.get("KEYCLOAK_PUBLIC_CLIENT_ID", "clinical-poc")

# Patron de campo de contrasena en un bundle Angular compilado. No basta con
# la palabra "password": Angular y los componentes de tabla la usan para
# enumerar tipos de input. Se busca un campo de contrasena de verdad.
PASSWORD_FIELD_PATTERNS = (
    r"""type\s*=\s*["']password["']""",
    r"""type\s*:\s*["']password["']""",
    r"""formControlName\s*:\s*["']password["']""",
    r"""ng-reflect-type\s*=\s*["']password["']""",
    r"""current-password""",
    r"""new-password""",
)
PASSWORD_FIELD_REGEX = re.compile("|".join("(?:%s)" % p for p in PASSWORD_FIELD_PATTERNS))


@dataclass
class CheckResult:
    """Resultado de un comprobador ejecutable con su evidencia real."""

    checker_id: str
    title: str
    objective: str
    severity: str
    status: str
    asset_ref: str
    evidence_command: str
    evidence_output: str
    remediation: str
    # Mecanismo real que produjo la evidencia (API de Keycloak, sistema de
    # ficheros, SQLite, docker inspect o el propio proceso). Permite
    # reconstruir de donde salio el hallazgo sin leer el codigo.
    evidence_source: str = ""


# Origen real de la evidencia de cada comprobador. Solo se declara aqui lo que
# tiene un mecanismo unico y fijo. Los comprobadores con mas de un mecanismo
# (por ejemplo, el del bundle Angular: sistema de ficheros o contenedor) lo
# emiten desde la rama que produjo la evidencia final, para no declarar un
# origen que no se ejecuto.
#
# Un comprobador que no figure aqui recibe el origen ``undeclared``, que NO es
# un origen valido: la omision se ve en la evidencia y en la prueba, en lugar de
# etiquetarse por defecto como ``in_process`` y pasar desapercibida.
EVIDENCE_SOURCES: Dict[str, str] = {
    "KC_PKCE_S256": "keycloak_admin_api",
    "KC_REGISTRATION_DISABLED": "keycloak_admin_api",
    "KC_PASSWORD_RESET_DISABLED": "keycloak_admin_api",
    "KC_MFA_ON_ADMIN_IDENTITIES": "keycloak_admin_api",
    "KC_PROTECTED_ROLE_NOT_GRANTABLE": "keycloak_admin_api",
    "BACKEND_AUTH_DELEGATED_TO_KEYCLOAK": "filesystem",
    "BACKEND_ADMIN_REQUIRES_MFA": "in_process",
    "BACKEND_AUDIT_CHAIN_VALID": "sqlite",
    "BACKEND_AUDIT_CHECKPOINT_CONSISTENT": "sqlite",
    "CONTAINER_HARDENING": "docker_inspect",
    "DATA_FILES_OWNER_ONLY": "filesystem",
}


# --------------------------------------------------------------------------
# Catalogo de comprobadores
# --------------------------------------------------------------------------
# Descripcion de cada comprobador: que mira, con que fuente de evidencia
# real y bajo que objetivo de tesis se publica.
CHECKER_CATALOG: List[Dict[str, str]] = [
    {
        "id": "KC_PKCE_S256",
        "title": "El cliente publico exige PKCE S256",
        "objective": "O1",
        "severity": "high",
        "description": (
            "Verifica en la representacion real del cliente publico del realm F11 que "
            "el atributo pkce.code.challenge.method vale S256, de modo que el codigo de "
            "autorizacion no pueda ser intercambiado sin prueba de posesion."
        ),
        "asset_ref": "keycloak-iam",
    },
    {
        "id": "KC_REGISTRATION_DISABLED",
        "title": "El realm no permite autorregistro",
        "objective": "O1",
        "severity": "high",
        "description": (
            "Verifica en la representacion real del realm que registrationAllowed esta "
            "deshabilitado: el alta de identidades solo puede venir de un administrador."
        ),
        "asset_ref": "keycloak-realm-hospital-lab",
    },
    {
        "id": "KC_PASSWORD_RESET_DISABLED",
        "title": "El realm no permite restablecer contrasena",
        "objective": "O1",
        "severity": "medium",
        "description": (
            "Verifica en la representacion real del realm que resetPasswordAllowed esta "
            "deshabilitado, para que la rotacion de credenciales sea siempre una operacion "
            "administrativa auditada."
        ),
        "asset_ref": "keycloak-realm-hospital-lab",
    },
    {
        "id": "KC_MFA_ON_ADMIN_IDENTITIES",
        "title": "Las identidades de plataforma tienen credencial OTP",
        "objective": "O1",
        "severity": "high",
        "description": (
            "Recorre las identidades que tienen rol de plataforma en el realm y comprueba "
            "en sus credenciales reales que existe una credencial OTP (TOTP)."
        ),
        "asset_ref": "keycloak-realm-hospital-lab",
    },
    {
        "id": "KC_PROTECTED_ROLE_NOT_GRANTABLE",
        "title": "El rol de plataforma no se puede conceder desde la aplicacion",
        "objective": "O1",
        "severity": "high",
        "description": (
            "Comprueba que el rol de plataforma existe en el realm, que la aplicacion lo "
            "declara protegido y que la funcion real de asignacion lo rechaza antes de "
            "emitir el mapeo de escritura (la sonda solo ejecuta lecturas)."
        ),
        "asset_ref": "keycloak-iam",
    },
    {
        "id": "BACKEND_AUTH_DELEGATED_TO_KEYCLOAK",
        "title": "El backend rechaza el login local con 410 AUTH_DELEGATED_TO_KEYCLOAK",
        "objective": "O1",
        "severity": "medium",
        "description": (
            "Comprueba en el codigo efectivo del backend que existe la rama de "
            "POST /api/v1/auth/login que responde 410 con el codigo "
            "AUTH_DELEGATED_TO_KEYCLOAK, y que la configuracion cargada en el proceso "
            "tiene ENABLE_LEGACY_AUTH distinto de 1."
        ),
        "asset_ref": "backend-api",
    },
    {
        "id": "BACKEND_ADMIN_REQUIRES_MFA",
        "title": "Las acciones sensibles exigen MFA y son solo de persona",
        "objective": "O1",
        "severity": "high",
        "description": (
            "Comprueba en la tabla de permisos real del backend que MANAGE_IDENTITIES, "
            "RUN_DIAGNOSTICS y MANAGE_ASSETS exigen MFA acreditada (require_mfa=true), "
            "que las tres estan en HUMAN_ONLY_ACTIONS para que una cuenta de servicio no "
            "pueda ejecutarlas, y que toda accion declarada en HUMAN_ONLY_ACTIONS exige MFA."
        ),
        "asset_ref": "backend-api",
    },
    {
        "id": "BACKEND_AUDIT_CHAIN_VALID",
        "title": "La cadena de auditoria verifica su encadenamiento",
        "objective": "O1",
        "severity": "high",
        "description": (
            "Recalcula el hash SHA-256 de cada evento real de auditoria y comprueba que "
            "prev_hash y event_hash encadenan sin rupturas."
        ),
        "asset_ref": "audit-chain",
    },
    {
        "id": "BACKEND_AUDIT_CHECKPOINT_CONSISTENT",
        "title": "El checkpoint de auditoria es consistente con la cadena",
        "objective": "O1",
        "severity": "medium",
        "description": (
            "Compara el checkpoint real con el conteo y el ultimo hash de la cadena, y "
            "recalcula la firma de anclaje del checkpoint con la misma regla que aplica "
            "la capa de persistencia (SHA-256 sobre la clave y el par last_hash:total_events)."
        ),
        "asset_ref": "audit-chain",
    },
    {
        "id": "FRONTEND_BUNDLE_HAS_NO_PASSWORD_FIELD",
        "title": "El bundle Angular no captura contrasenas",
        "objective": "O1",
        "severity": "high",
        "description": (
            "Busca en el bundle Angular servido un campo de contrasena real; el formulario "
            "de credenciales vive en Keycloak y la aplicacion solo hace traspaso."
        ),
        "asset_ref": "frontend-angular-bundle",
    },
    {
        "id": "CONTAINER_HARDENING",
        "title": "Los contenedores no estan en modo privilegiado",
        "objective": "O1",
        "severity": "medium",
        "description": (
            "Comprueba en el compose del F11 y en el estado real de los contenedores que "
            "no hay modo privilegiado, que se descartan todas las capacidades y que "
            "no-new-privileges esta activo."
        ),
        "asset_ref": "compose-f11",
    },
    {
        "id": "DATA_FILES_OWNER_ONLY",
        "title": "Los ficheros de datos son de solo propietario",
        "objective": "O2",
        "severity": "medium",
        "description": (
            "Comprueba los permisos reales de la base SQLite, su WAL y la clave de anclaje "
            "de auditoria: solo el propietario puede leerlos y escribirlos."
        ),
        "asset_ref": "clinical-sqlite-db",
    },
]

CHECKER_META: Dict[str, Dict[str, str]] = {entry["id"]: entry for entry in CHECKER_CATALOG}


def checker_catalog() -> List[Dict[str, str]]:
    """Devuelve el catalogo de comprobadores: id, titulo, objetivo, severidad y descripcion."""
    return [
        {
            "id": entry["id"],
            "title": entry["title"],
            "objective": entry["objective"],
            "severity": entry["severity"],
            "description": entry["description"],
        }
        for entry in CHECKER_CATALOG
    ]


# --------------------------------------------------------------------------
# Utilidades de evidencia
# --------------------------------------------------------------------------
def _truncate(text: str) -> str:
    """Acota la salida de evidencia a un maximo legible sin alterarla."""
    if len(text) <= MAX_EVIDENCE_CHARS:
        return text
    omitted = len(text) - MAX_EVIDENCE_CHARS
    return text[:MAX_EVIDENCE_CHARS] + "\n... [salida recortada: %d caracteres omitidos]" % omitted


def _json_evidence(payload: Any) -> str:
    """Serializa una representacion real como JSON legible para la evidencia."""
    if isinstance(payload, dict):
        payload = dict(payload)
        # Toda la evidencia lleva el entorno al que pertenece: la evidencia
        # real de la plataforma es solo la del F11.
        payload.setdefault("environment", F11_ENVIRONMENT)
    try:
        return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False, default=str)
    except Exception as exc:  # pragma: no cover - defensivo
        return json.dumps({"serialization_error": str(exc)})


def _build(
    checker_id: str,
    status: str,
    evidence_command: str,
    evidence_output: str,
    remediation: str,
    evidence_source: str = "",
) -> CheckResult:
    """Construye el resultado de un comprobador con los metadatos del catalogo.

    ``evidence_source`` solo se pasa cuando el mecanismo real varia entre
    ramas del propio comprobador: en ese caso no se puede declarar de antemano
    en el mapa estatico sin mentir en alguna de las ramas.
    """
    meta = CHECKER_META[checker_id]
    return CheckResult(
        checker_id=checker_id,
        title=meta["title"],
        objective=meta["objective"],
        severity=meta["severity"],
        status=status,
        asset_ref=meta["asset_ref"],
        evidence_command=evidence_command,
        evidence_output=_truncate(evidence_output),
        remediation=remediation,
        evidence_source=evidence_source,
    )


def _run_command(command: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    """Ejecuta un comando local y devuelve (codigo, salida, error) reales."""
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=REPO_ROOT,
        )
        return completed.returncode, completed.stdout.strip(), completed.stderr.strip()
    except FileNotFoundError as exc:
        return 127, "", "binario no disponible: %s" % exc
    except subprocess.TimeoutExpired:
        return 124, "", "el comando supero el limite de %d segundos" % timeout
    except Exception as exc:
        return 1, "", "fallo al ejecutar el comando: %s: %s" % (type(exc).__name__, exc)


# --------------------------------------------------------------------------
# Fuente de verdad de Keycloak (cliente de administrador ya existente)
# --------------------------------------------------------------------------
class F11AdminReader(IdentityAdminClient):
    """
    Cliente de administracion de Keycloak con lecturas de configuracion efectiva.

    Reutiliza el cliente de confianza de ``backend/identity_admin.py``: misma
    autenticacion, misma credencial de administrador que ya vive en el entorno
    del servidor. No se guarda ninguna credencial en disco por este modulo y
    no se implementa un cliente HTTP nuevo.
    """

    def get_realm(self) -> Dict[str, Any]:
        """Devuelve la representacion real del realm configurado."""
        status, payload = self._request("GET", "/admin/realms/%s" % self.realm)
        if status != 200 or not isinstance(payload, dict):
            raise IdentityAdminError(
                "no se pudo leer la representacion del realm %s" % self.realm,
                status=status if status >= 400 else 502,
            )
        return payload

    def get_client_by_client_id(self, client_id: str) -> Optional[Dict[str, Any]]:
        """Devuelve la representacion real del cliente publico solicitado."""
        status, payload = self._request(
            "GET", "/admin/realms/%s/clients" % self.realm,
        )
        if status != 200 or not isinstance(payload, list):
            raise IdentityAdminError("no se pudieron leer los clientes del realm")
        for client in payload:
            if str(client.get("clientId")) == client_id:
                return client
        return None

    def list_user_credentials(self, user_id: str) -> List[Dict[str, Any]]:
        """Devuelve los tipos de credencial real de una identidad (sin valores de secreto)."""
        status, payload = self._request(
            "GET", "/admin/realms/%s/users/%s/credentials" % (self.realm, user_id)
        )
        if status != 200 or not isinstance(payload, list):
            raise IdentityAdminError("no se pudieron leer las credenciales de la identidad")
        return [
            {
                "type": str(credential.get("type")),
                "created_date": credential.get("createdDate"),
                "user_label": credential.get("userLabel"),
            }
            for credential in payload
        ]

    def list_user_realm_roles(self, user_id: str) -> List[str]:
        """Devuelve los nombres de rol de realm asignados a una identidad."""
        status, payload = self._request(
            "GET", "/admin/realms/%s/users/%s/role-mappings/realm" % (self.realm, user_id)
        )
        if status != 200 or not isinstance(payload, list):
            raise IdentityAdminError("no se pudieron leer los roles de la identidad")
        return sorted(str(role.get("name")) for role in payload if role.get("name"))


def _admin_reader() -> F11AdminReader:
    """Construye el cliente de administracion con la configuracion del entorno."""
    base_url = os.environ.get("KEYCLOAK_ADMIN_URL", "http://127.0.0.1:8085")
    realm = os.environ.get("KEYCLOAK_REALM", "hospital-lab-local")
    username = os.environ.get("KEYCLOAK_ADMIN_USERNAME", "")
    password = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "")
    if not username or not password:
        raise IdentityAdminError(
            "la administracion de identidades no esta configurada en el servidor",
            status=503,
            code="IDENTITY_ADMIN_NOT_CONFIGURED",
        )
    return F11AdminReader(base_url, realm, username, password)


def _admin_base_url() -> str:
    """Base URL real de la API de administracion de Keycloak del entorno F11."""
    return os.environ.get("KEYCLOAK_ADMIN_URL", "http://127.0.0.1:8085").rstrip("/")


def _realm_name() -> str:
    """Nombre real del realm F11."""
    return os.environ.get("KEYCLOAK_REALM", "hospital-lab-local")


def _platform_realm_roles() -> List[str]:
    """Devuelve los nombres de rol del realm que equivalen al rol de plataforma del PEP."""
    return sorted(
        name for name, mapped in ROLE_MAPPING.items() if mapped == "ROLE_PLATFORM_ADMIN"
    )


# --------------------------------------------------------------------------
# Comprobadores de Keycloak
# --------------------------------------------------------------------------
def check_kc_pkce_s256() -> CheckResult:
    """Comprueba que el cliente publico exige PKCE S256."""
    command = (
        "GET %s/admin/realms/%s/clients y filtrado local por clientId=%s "
        "(API de administracion de Keycloak)"
        % (_admin_base_url(), _realm_name(), PUBLIC_CLIENT_ID)
    )
    reader = _admin_reader()
    client = reader.get_client_by_client_id(PUBLIC_CLIENT_ID)
    if client is None:
        return _build(
            "KC_PKCE_S256", "failed", command,
            "El realm no expone ningun cliente con clientId '%s'." % PUBLIC_CLIENT_ID,
            "Registra el cliente publico '%s' en el realm F11 con PKCE S256 habilitado." % PUBLIC_CLIENT_ID,
        )
    attributes = client.get("attributes") or {}
    method = attributes.get("pkce.code.challenge.method")
    evidence = {
        "clientId": client.get("clientId"),
        "publicClient": client.get("publicClient"),
        "enabled": client.get("enabled"),
        "attributes": attributes,
    }
    output = _json_evidence(evidence)
    if client.get("publicClient") and str(method) == "S256":
        return _build(
            "KC_PKCE_S256", "passed", command, output,
            "Ninguna: el cliente publico '%s' ya exige PKCE S256." % PUBLIC_CLIENT_ID,
        )
    return _build(
        "KC_PKCE_S256", "failed", command, output,
        "Configura el cliente publico '%s' con el atributo pkce.code.challenge.method=S256 "
        "en la consola de administracion de Keycloak." % PUBLIC_CLIENT_ID,
    )


def check_kc_registration_disabled() -> CheckResult:
    """Comprueba que el realm no permite autorregistro."""
    realm_name = _realm_name()
    command = "GET %s/admin/realms/%s (API de administracion de Keycloak)" % (
        _admin_base_url(), realm_name,
    )
    reader = _admin_reader()
    realm = reader.get_realm()
    if "registrationAllowed" not in realm:
        return _build(
            "KC_REGISTRATION_DISABLED", "warning", command,
            _json_evidence({"realm": realm_name, "campos_presentes": sorted(realm.keys())}),
            "Verifica en la consola de Keycloak que el realm no expone autorregistro; "
            "la representacion devuelta no incluye el campo registrationAllowed.",
        )
    allowed = bool(realm.get("registrationAllowed"))
    output = _json_evidence({
        "realm": realm.get("realm"),
        "registrationAllowed": allowed,
        "registrationEmailAsUsername": realm.get("registrationEmailAsUsername"),
    })
    if not allowed:
        return _build(
            "KC_REGISTRATION_DISABLED", "passed", command, output,
            "Ninguna: el realm F11 no permite el autorregistro.",
        )
    return _build(
        "KC_REGISTRATION_DISABLED", "failed", command, output,
        "Deshabilita el autorregistro del realm %s (registrationAllowed=false): el alta de "
        "identidades debe ser una operacion administrativa auditada." % realm_name,
    )


def check_kc_password_reset_disabled() -> CheckResult:
    """Comprueba que el realm no permite el restablecimiento de contrasena."""
    realm_name = _realm_name()
    command = "GET %s/admin/realms/%s (API de administracion de Keycloak)" % (
        _admin_base_url(), realm_name,
    )
    reader = _admin_reader()
    realm = reader.get_realm()
    if "resetPasswordAllowed" not in realm:
        return _build(
            "KC_PASSWORD_RESET_DISABLED", "warning", command,
            _json_evidence({"realm": realm_name, "campos_presentes": sorted(realm.keys())}),
            "Verifica en la consola de Keycloak que el restablecimiento de contrasena esta "
            "deshabilitado; la representacion devuelta no incluye resetPasswordAllowed.",
        )
    allowed = bool(realm.get("resetPasswordAllowed"))
    output = _json_evidence({
        "realm": realm.get("realm"),
        "resetPasswordAllowed": allowed,
    })
    if not allowed:
        return _build(
            "KC_PASSWORD_RESET_DISABLED", "passed", command, output,
            "Ninguna: el restablecimiento de contrasena solo se hace por la administracion "
            "de identidades, que queda auditada.",
        )
    return _build(
        "KC_PASSWORD_RESET_DISABLED", "failed", command, output,
        "Deshabilita resetPasswordAllowed en el realm %s: la rotacion de credenciales debe "
        "pasar por la administracion de identidades con MFA." % realm_name,
    )


def check_kc_mfa_on_admin_identities() -> CheckResult:
    """Comprueba que las identidades con rol de plataforma tienen credencial OTP."""
    realm_name = _realm_name()
    base = _admin_base_url()
    command = (
        "GET %s/admin/realms/%s/users + GET %s/admin/realms/%s/users/{id}/role-mappings/realm "
        "+ GET %s/admin/realms/%s/users/{id}/credentials (API de administracion de Keycloak)"
        % (base, realm_name, base, realm_name, base, realm_name)
    )
    reader = _admin_reader()
    platform_roles = _platform_realm_roles()
    users = reader.list_users()
    report: List[Dict[str, Any]] = []
    without_otp: List[str] = []
    for user in users:
        if not user.get("enabled"):
            continue
        roles = reader.list_user_realm_roles(user["id"])
        granted_platform = [role for role in roles if role in platform_roles]
        if not granted_platform:
            continue
        credentials = reader.list_user_credentials(user["id"])
        credential_types = sorted({credential["type"] for credential in credentials})
        report.append({
            "username": user["username"],
            "synthetic": user.get("synthetic"),
            "enabled": user.get("enabled"),
            "platform_roles": granted_platform,
            "credential_types": credential_types,
            "otp_credential": "otp" in credential_types,
        })
        if "otp" not in credential_types:
            without_otp.append(user["username"])
    output = _json_evidence({
        "platform_realm_roles": platform_roles,
        "identidades_de_plataforma": report,
    })
    if not report:
        return _build(
            "KC_MFA_ON_ADMIN_IDENTITIES", "warning", command, output,
            "No se encontraron identidades con rol de plataforma en el realm %s: no hay nada "
            "que verificar sobre credenciales OTP de administrador." % realm_name,
        )
    if without_otp:
        return _build(
            "KC_MFA_ON_ADMIN_IDENTITIES", "failed", command, output,
            "Enrolla la credencial OTP (TOTP) de las identidades de plataforma sin OTP "
            "(%s) en Keycloak antes de permitirles acciones administrativas."
            % ", ".join(sorted(without_otp)),
        )
    return _build(
        "KC_MFA_ON_ADMIN_IDENTITIES", "passed", command, output,
        "Ninguna: todas las identidades de plataforma del realm F11 tienen credencial OTP.",
    )


def check_kc_protected_role_not_grantable() -> CheckResult:
    """Comprueba que el rol de plataforma existe y la aplicacion no puede concederlo."""
    realm_name = _realm_name()
    command = (
        "GET %s/admin/realms/%s/roles + llamada real a set_user_roles(<id sintetico>, "
        "[rol-de-plataforma]) de backend/identity_admin.py con un transporte "
        "instrumentado que solo permite GET: se comprueba que el rechazo se dispara "
        "antes de emitir el mapeo de asignacion (ningun POST role-mappings/realm)"
        % (_admin_base_url(), realm_name)
    )
    reader = _admin_reader()
    realm_roles = reader.list_roles()
    realm_role_names = sorted(role["name"] for role in realm_roles)
    platform_roles = [name for name in _platform_realm_roles() if name in realm_role_names]
    if not platform_roles:
        return _build(
            "KC_PROTECTED_ROLE_NOT_GRANTABLE", "failed", command,
            _json_evidence({
                "roles_del_realm": realm_role_names,
                "roles_de_plataforma_esperados": _platform_realm_roles(),
            }),
            "Crea en el realm %s el rol de plataforma declarado por la aplicacion (%s)."
            % (realm_name, ", ".join(_platform_realm_roles())),
        )
    protected_in_app = sorted(set(platform_roles) & set(PROTECTED_ROLES))
    # La sonda no escribe: se instrumenta el transporte del cliente para que
    # cualquier metodo distinto de GET se registre y falle cerrado. Asi la
    # comprobacion demuestra que el rechazo ocurre antes del mapeo sin enviar
    # nunca un POST de asignacion al realm.
    write_attempts: List[str] = []
    original_request = reader._request

    def _read_only_request(method, path, payload=None, form=None, authenticated=True):
        if str(method).upper() != "GET":
            write_attempts.append("%s %s" % (method, path))
            raise IdentityAdminError(
                "la sonda de comprobacion es de solo lectura", status=403,
                code="IDENTITY_PROTECTED_ROLE",
            )
        return original_request(
            method, path, payload=payload, form=form, authenticated=authenticated,
        )

    denial: Optional[str] = None
    reader._request = _read_only_request
    try:
        reader.set_user_roles("00000000-0000-0000-0000-000000000000", platform_roles)
    except IdentityAdminError as exc:
        denial = str(exc)
    except Exception as exc:  # pragma: no cover - defensivo
        denial = "%s: %s" % (type(exc).__name__, exc)
    finally:
        reader._request = original_request
    output = _json_evidence({
        "roles_del_realm": realm_role_names,
        "roles_de_plataforma_en_el_realm": platform_roles,
        "roles_protegidos_por_la_aplicacion": sorted(PROTECTED_ROLES),
        "intento_de_concesion": denial or "la llamada NO fue rechazada",
        "mapeos_de_asignacion_emitidos": write_attempts,
    })
    if (
        protected_in_app
        and denial
        and "no se puede conceder" in denial
        and not write_attempts
    ):
        return _build(
            "KC_PROTECTED_ROLE_NOT_GRANTABLE", "passed", command, output,
            "Ninguna: la aplicacion rechaza conceder el rol de plataforma y lo declara "
            "protegido.",
        )
    if not protected_in_app:
        return _build(
            "KC_PROTECTED_ROLE_NOT_GRANTABLE", "failed", command, output,
            "Anade el rol de plataforma (%s) a PROTECTED_ROLES en backend/identity_admin.py "
            "para que la aplicacion no pueda concederlo."
            % ", ".join(_platform_realm_roles()),
        )
    return _build(
        "KC_PROTECTED_ROLE_NOT_GRANTABLE", "failed", command, output,
        "Haz que backend/identity_admin.py rechace la concesion del rol de plataforma (%s) "
        "antes de emitir el mapeo de asignacion: la lectura de roles si se ejecuta, la "
        "escritura no debe llegar nunca." % ", ".join(platform_roles),
    )


# --------------------------------------------------------------------------
# Comprobadores del backend
# --------------------------------------------------------------------------
# La rama de rechazo del login local: el estado 410 y el codigo de error van
# juntos en la misma llamada. Se busca la llamada completa y no la aparicion
# suelta del literal, que tambien casa con el detalle de un evento de
# auditoria o con un comentario del fuente.
DELEGATION_BRANCH_REGEX = re.compile(
    r"send_json\(\s*410\s*,\s*\{[^{}]*?\"code\"\s*:\s*\"AUTH_DELEGATED_TO_KEYCLOAK\"",
    re.DOTALL,
)


def _backend_source_text(relative_path: str) -> str:
    """Lee el codigo fuente efectivo del backend como texto."""
    path = os.path.join(REPO_ROOT, relative_path)
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


def check_backend_auth_delegated_to_keycloak() -> CheckResult:
    """
    Comprueba la rama de rechazo 410 del login local y la configuracion efectiva.

    Lo que se comprueba es exactamente esto: que en el codigo efectivo del
    backend existe la rama de POST /api/v1/auth/login que responde 410 con el
    codigo AUTH_DELEGATED_TO_KEYCLOAK, y que la configuracion cargada en el
    proceso no habilita el login local. No se comprueba "que el login local
    esta deshabilitado" en general: eso lo decidiria una peticion HTTP contra
    el propio backend, que el servidor de un solo hilo no puede servicing.
    """
    command = (
        "lectura de backend/server.py (rama de POST /api/v1/auth/login que responde 410 "
        "con el codigo AUTH_DELEGATED_TO_KEYCLOAK) y lectura de la variable "
        "ENABLE_LEGACY_AUTH del entorno del proceso"
    )
    try:
        source = _backend_source_text("backend/server.py")
    except OSError as exc:
        return _build(
            "BACKEND_AUTH_DELEGATED_TO_KEYCLOAK", "warning", command,
            _json_evidence({"error": str(exc), "fichero": "backend/server.py"}),
            "Restaura backend/server.py: sin el codigo efectivo no se puede comprobar "
            "la rama de rechazo del login local.",
        )
    match = DELEGATION_BRANCH_REGEX.search(source)
    branch = ""
    if match is not None:
        line_number = source.count("\n", 0, match.start()) + 1
        branch = "%d: %s" % (line_number, " ".join(match.group(0).split()))
    legacy_flag = os.environ.get("ENABLE_LEGACY_AUTH", "0")
    legacy_enabled = legacy_flag == "1"
    evidence = {
        "fichero": "backend/server.py",
        "rama_de_rechazo_410_encontrada": match is not None,
        "rama_de_rechazo_410": branch,
        "ENABLE_LEGACY_AUTH": legacy_flag,
        "nota": (
            "No se ejecuta una peticion HTTP contra el propio backend: el servidor es "
            "http.server de un solo hilo y una peticion a si mismo durante una peticion en "
            "curso se bloquearia para siempre."
        ),
    }
    output = _json_evidence(evidence)
    if match is None:
        return _build(
            "BACKEND_AUTH_DELEGATED_TO_KEYCLOAK", "failed", command, output,
            "Devuelve 410 con el codigo AUTH_DELEGATED_TO_KEYCLOAK en el endpoint local "
            "POST /api/v1/auth/login de backend/server.py.",
        )
    if legacy_enabled:
        return _build(
            "BACKEND_AUTH_DELEGATED_TO_KEYCLOAK", "failed", command, output,
            "Puesta ENABLE_LEGACY_AUTH=0 en la configuracion del backend: la autenticacion "
            "local debe estar delegada formalmente a Keycloak.",
        )
    return _build(
        "BACKEND_AUTH_DELEGATED_TO_KEYCLOAK", "passed", command, output,
        "Ninguna: la rama de rechazo 410 AUTH_DELEGATED_TO_KEYCLOAK existe en el codigo "
        "efectivo y el proceso no habilita el login local.",
    )


def check_backend_admin_requires_mfa() -> CheckResult:
    """
    Comprueba que las acciones sensibles exigen MFA y son solo de persona.

    Lo que se comprueba es exactamente esto:

    * Las tres acciones sensibles de la plataforma (MANAGE_IDENTITIES,
      RUN_DIAGNOSTICS y MANAGE_ASSETS) existen en la tabla de permisos y
      declaran ``require_mfa: true``.
    * Las tres estan en HUMAN_ONLY_ACTIONS, de modo que una cuenta de servicio
      no pueda ejecutarlas.
    * Toda accion declarada en HUMAN_ONLY_ACTIONS exige MFA: si alguien
      anade una accion de escritura nueva, esta comprobacion lo detecta.
    """
    command = (
        "lectura de la tabla CLINICAL_PERMISSIONS y del conjunto HUMAN_ONLY_ACTIONS "
        "del modulo backend/jwt_validator.py cargado en el proceso"
    )
    sensitive_actions = ("MANAGE_IDENTITIES", "RUN_DIAGNOSTICS", "MANAGE_ASSETS")
    policies: Dict[str, Any] = {}
    missing_policy: List[str] = []
    without_mfa: List[str] = []
    for action in sensitive_actions:
        policy = CLINICAL_PERMISSIONS.get(action)
        if policy is None:
            missing_policy.append(action)
            continue
        policies[action] = {
            "required_roles": sorted(policy.get("required_roles") or []),
            "require_mfa": bool(policy.get("require_mfa")),
            "description": policy.get("description"),
        }
        if not policy.get("require_mfa"):
            without_mfa.append(action)
    human_only = sorted(HUMAN_ONLY_ACTIONS)
    not_human_only = [action for action in sensitive_actions if action not in HUMAN_ONLY_ACTIONS]
    human_only_without_mfa = sorted(
        action for action in HUMAN_ONLY_ACTIONS
        if not bool((CLINICAL_PERMISSIONS.get(action) or {}).get("require_mfa"))
    )
    output = _json_evidence({
        "acciones_sensibles": list(sensitive_actions),
        "politicas": policies,
        "acciones_sin_politica": missing_policy,
        "acciones_sin_mfa": without_mfa,
        "acciones_sensibles_fuera_de_HUMAN_ONLY_ACTIONS": not_human_only,
        "HUMAN_ONLY_ACTIONS": human_only,
        "acciones_de_HUMAN_ONLY_ACTIONS_sin_mfa": human_only_without_mfa,
    })
    if missing_policy:
        return _build(
            "BACKEND_ADMIN_REQUIRES_MFA", "failed", command, output,
            "Declara las acciones %s en CLINICAL_PERMISSIONS de backend/jwt_validator.py "
            "con require_mfa=true." % ", ".join(missing_policy),
        )
    if without_mfa:
        return _build(
            "BACKEND_ADMIN_REQUIRES_MFA", "failed", command, output,
            "Marca require_mfa=true en la politica de las acciones %s de "
            "backend/jwt_validator.py: son operaciones sensibles." % ", ".join(without_mfa),
        )
    if not_human_only:
        return _build(
            "BACKEND_ADMIN_REQUIRES_MFA", "failed", command, output,
            "Anade %s a HUMAN_ONLY_ACTIONS en backend/jwt_validator.py: las cuentas de "
            "servicio no pueden ejecutar esas acciones." % ", ".join(not_human_only),
        )
    if human_only_without_mfa:
        return _build(
            "BACKEND_ADMIN_REQUIRES_MFA", "failed", command, output,
            "Marca require_mfa=true en las acciones %s de HUMAN_ONLY_ACTIONS: una accion "
            "reservada a personas tiene que exigir MFA."
            % ", ".join(human_only_without_mfa),
        )
    return _build(
        "BACKEND_ADMIN_REQUIRES_MFA", "passed", command, output,
        "Ninguna: las tres acciones sensibles exigen MFA acreditada y quedan reservadas "
        "a personas.",
    )


# --------------------------------------------------------------------------
# Comprobadores de la cadena de auditoria
# --------------------------------------------------------------------------
def _db_path() -> str:
    """Resuelve la ruta de la base de datos clinica del entorno F11."""
    return os.environ.get("LIS_DB_PATH", os.path.join(REPO_ROOT, "backend", "data", "lis.db"))


def _open_query_only(path: str) -> sqlite3.Connection:
    """Abre la base de datos en modo solo lectura logica (PRAGMA query_only)."""
    connection = sqlite3.connect(path, timeout=10.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON;")
    return connection


def _anchor_key(path: str) -> Optional[bytes]:
    """Resuelve la clave de anclaje de auditoria sin mostrarla nunca."""
    raw_env = os.environ.get("AUDIT_HMAC_KEY", "")
    if raw_env:
        try:
            return bytes.fromhex(raw_env)
        except ValueError:
            return raw_env.encode("utf-8")
    sidecar = path + ".anchor-key"
    if os.path.exists(sidecar):
        try:
            with open(sidecar, "r", encoding="ascii") as handle:
                return bytes.fromhex(handle.read().strip())
        except Exception:
            return None
    return None


def check_backend_audit_chain_valid() -> CheckResult:
    """Recalcula el encadenamiento por hash de los eventos reales de auditoria."""
    path = _db_path()
    command = (
        "SELECT id, raw_json, prev_hash, event_hash FROM audit_events ORDER BY id ASC "
        "sobre %s (recalculo SHA-256 de cada evento)" % path
    )
    if not os.path.exists(path):
        return _build(
            "BACKEND_AUDIT_CHAIN_VALID", "warning", command,
            "La base de datos de auditoria no existe en la ruta configurada: %s" % path,
            "Arranca el stack F11 para que exista la base de datos con la cadena de auditoria.",
        )
    connection = _open_query_only(path)
    try:
        rows = connection.execute(
            "SELECT id, raw_json, prev_hash, event_hash FROM audit_events ORDER BY id ASC;"
        ).fetchall()
    finally:
        connection.close()
    expected_prev = "0" * 64
    broken: List[Dict[str, Any]] = []
    for row in rows:
        record = json.loads(row["raw_json"])
        record_without_hash = {key: value for key, value in record.items() if key != "hash"}
        computed = hashlib.sha256(
            json.dumps(record_without_hash, sort_keys=True).encode("utf-8")
        ).hexdigest()
        if row["prev_hash"] != expected_prev:
            broken.append({
                "id": row["id"], "problema": "prev_hash no coincide",
                "esperado": expected_prev, "encontrado": row["prev_hash"],
            })
        if computed != row["event_hash"]:
            broken.append({
                "id": row["id"], "problema": "event_hash no coincide con el recalculo",
                "esperado": computed, "encontrado": row["event_hash"],
            })
        expected_prev = row["event_hash"]
    output = _json_evidence({
        "base_de_datos": path,
        "eventos_analizados": len(rows),
        "hash_final": expected_prev,
        "rupturas": broken[:10],
        "rupturas_totales": len(broken),
    })
    if not rows:
        return _build(
            "BACKEND_AUDIT_CHAIN_VALID", "warning", command, output,
            "La cadena de auditoria esta vacia: no hay eventos reales que verificar.",
        )
    if broken:
        return _build(
            "BACKEND_AUDIT_CHAIN_VALID", "failed", command, output,
            "Investiga los eventos alterados de la cadena de auditoria: el hash encadenado "
            "no se puede reescribir sin romper la continuidad.",
        )
    return _build(
        "BACKEND_AUDIT_CHAIN_VALID", "passed", command, output,
        "Ninguna: los %d eventos reales encadenan por hash sin rupturas." % len(rows),
    )


def check_backend_audit_checkpoint_consistent() -> CheckResult:
    """Compara el checkpoint real con la cadena y recalcula su firma de anclaje."""
    path = _db_path()
    command = (
        "SELECT checkpoint_id, last_hash, total_events, updated_at, anchor_signature "
        "FROM audit_checkpoints + SELECT count(*) FROM audit_events sobre %s" % path
    )
    if not os.path.exists(path):
        return _build(
            "BACKEND_AUDIT_CHECKPOINT_CONSISTENT", "warning", command,
            "La base de datos de auditoria no existe en la ruta configurada: %s" % path,
            "Arranca el stack F11 para que exista el checkpoint de auditoria.",
        )
    connection = _open_query_only(path)
    try:
        checkpoint = connection.execute(
            "SELECT checkpoint_id, last_hash, total_events, updated_at, anchor_signature "
            "FROM audit_checkpoints WHERE checkpoint_id = 1;"
        ).fetchone()
        total_events = int(connection.execute("SELECT count(*) FROM audit_events;").fetchone()[0])
        last_event = connection.execute(
            "SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1;"
        ).fetchone()
    finally:
        connection.close()
    if checkpoint is None:
        return _build(
            "BACKEND_AUDIT_CHECKPOINT_CONSISTENT", "failed", command,
            _json_evidence({"checkpoint": None, "eventos": total_events}),
            "Restaura el checkpoint de auditoria: su ausencia deja la cadena sin punto de "
            "control verificable.",
        )
    chain_last_hash = last_event["event_hash"] if last_event is not None else "0" * 64
    key = _anchor_key(path)
    computed_anchor = None
    if key is not None:
        # Misma regla que aplica la capa de persistencia: SHA-256 sobre la
        # concatenacion de la clave de anclaje y el par last_hash:total_events.
        message = ("%s:%s" % (checkpoint["last_hash"], checkpoint["total_events"])).encode("utf-8")
        computed_anchor = hashlib.sha256(key + message).hexdigest()
    problems: List[str] = []
    if int(checkpoint["total_events"]) != total_events:
        problems.append(
            "conteo del checkpoint (%s) distinto del conteo real (%d)"
            % (checkpoint["total_events"], total_events)
        )
    if checkpoint["last_hash"] != chain_last_hash:
        problems.append("hash del checkpoint distinto del ultimo evento real")
    if computed_anchor is None:
        problems.append("no se pudo resolver la clave de anclaje para recalcular la firma")
    elif checkpoint["anchor_signature"] != computed_anchor:
        problems.append("la firma de anclaje del checkpoint no coincide con el recalculo")
    output = _json_evidence({
        "base_de_datos": path,
        "checkpoint": {
            "last_hash": checkpoint["last_hash"],
            "total_events": checkpoint["total_events"],
            "updated_at": checkpoint["updated_at"],
            "anchor_signature": checkpoint["anchor_signature"],
        },
        "cadena_real": {
            "eventos": total_events,
            "ultimo_event_hash": chain_last_hash,
        },
        "firma_recalculada": computed_anchor,
        "problemas": problems,
    })
    if problems:
        return _build(
            "BACKEND_AUDIT_CHECKPOINT_CONSISTENT", "failed", command, output,
            "Reconstruye el checkpoint de auditoria a partir de la cadena real: %s."
            % "; ".join(problems),
        )
    return _build(
        "BACKEND_AUDIT_CHECKPOINT_CONSISTENT", "passed", command, output,
        "Ninguna: el checkpoint coincide con la cadena y su firma de anclaje es coherente.",
    )


# --------------------------------------------------------------------------
# Comprobadores del frontend y de la infraestructura
# --------------------------------------------------------------------------
def _frontend_bundle_dir() -> str:
    """Ruta del bundle Angular construido para el entorno F11."""
    return os.path.join(REPO_ROOT, "frontend", ".f11-dist", "browser")


def _scan_bundle_content(content: str, origin: str) -> List[Dict[str, str]]:
    """Busca campos de contrasena reales en un bundle y devuelve las coincidencias."""
    matches: List[Dict[str, str]] = []
    for match in PASSWORD_FIELD_REGEX.finditer(content):
        start = max(0, match.start() - 60)
        end = min(len(content), match.end() + 60)
        matches.append({
            "origen": origin,
            "patron": match.group(0),
            "contexto": content[start:end].replace("\n", " "),
        })
    return matches


def check_frontend_bundle_has_no_password_field() -> CheckResult:
    """Comprueba que el bundle Angular servido no contiene campos de contrasena."""
    bundle_dir = _frontend_bundle_dir()
    pattern_literal = "|".join(PASSWORD_FIELD_PATTERNS)
    command = (
        "lectura de los ficheros .js de frontend/.f11-dist/browser y busqueda del patron "
        "'%s' en su contenido" % pattern_literal
    )
    if os.path.isdir(bundle_dir):
        origin = "frontend/.f11-dist/browser"
        files = sorted(
            os.path.join(bundle_dir, name) for name in os.listdir(bundle_dir)
            if name.endswith(".js")
        )
        if not files:
            return _build(
                "FRONTEND_BUNDLE_HAS_NO_PASSWORD_FIELD", "warning", command,
                _json_evidence({"directorio": origin, "ficheros_js": 0}),
                "Reconstruye el bundle Angular del F11: no hay ficheros JavaScript que revisar.",
                evidence_source="filesystem",
            )
        matches: List[Dict[str, str]] = []
        for path in files:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                content = handle.read()
            matches.extend(_scan_bundle_content(content, os.path.basename(path)))
        output = _json_evidence({
            "origen": origin,
            "ficheros_js_revisados": len(files),
            "coincidencias_de_campo_de_contrasena": matches[:10],
            "coincidencias_totales": len(matches),
        })
        if matches:
            return _build(
                "FRONTEND_BUNDLE_HAS_NO_PASSWORD_FIELD", "failed", command, output,
                "Elimina del bundle Angular el campo de contrasena: el formulario de "
                "credenciales vive en Keycloak y la aplicacion solo hace traspaso.",
                evidence_source="filesystem",
            )
        return _build(
            "FRONTEND_BUNDLE_HAS_NO_PASSWORD_FIELD", "passed", command, output,
            "Ninguna: los %d ficheros JavaScript publicados no contienen ningun campo de "
            "contrasena." % len(files),
            evidence_source="filesystem",
        )
    # El bundle no esta en el arbol: se mira el contenedor que lo sirve.
    fallback_command = (
        "docker exec %s sh -c 'cat /usr/share/caddy/*.js' y busqueda del patron '%s' "
        "en el contenido leido" % (F11_FRONTEND_CONTAINER, pattern_literal)
    )
    code, stdout, stderr = _run_command(
        ["docker", "exec", F11_FRONTEND_CONTAINER, "sh", "-c", "cat /usr/share/caddy/*.js"],
        timeout=60,
    )
    if code != 0:
        return _build(
            "FRONTEND_BUNDLE_HAS_NO_PASSWORD_FIELD", "warning", fallback_command,
            _json_evidence({
                "error": stderr or stdout,
                "codigo": code,
                "nota": "No existe frontend/.f11-dist/browser y el contenedor no respondio.",
            }),
            "Publica el bundle Angular del F11 o levanta el contenedor %s para poder "
            "comprobarlo." % F11_FRONTEND_CONTAINER,
            evidence_source="docker_exec",
        )
    matches = _scan_bundle_content(stdout, F11_FRONTEND_CONTAINER)
    output = _json_evidence({
        "origen": "contenedor %s:/usr/share/caddy" % F11_FRONTEND_CONTAINER,
        "bytes_leidos": len(stdout),
        "coincidencias_de_campo_de_contrasena": matches[:10],
        "coincidencias_totales": len(matches),
    })
    if matches:
        return _build(
            "FRONTEND_BUNDLE_HAS_NO_PASSWORD_FIELD", "failed", fallback_command, output,
            "Elimina del bundle Angular el campo de contrasena: el formulario de "
            "credenciales vive en Keycloak y la aplicacion solo hace traspaso.",
            evidence_source="docker_exec",
        )
    return _build(
        "FRONTEND_BUNDLE_HAS_NO_PASSWORD_FIELD", "passed", fallback_command, output,
        "Ninguna: el bundle servido por el contenedor no contiene ningun campo de contrasena.",
        evidence_source="docker_exec",
    )


def _parse_compose_services(path: str) -> Dict[str, Dict[str, Any]]:
    """
    Lee los servicios de un compose.yaml sin dependencias externas.

    Solo se extraen las claves de endurecimiento que el comprobador necesita:
    privileged, cap_drop, cap_add y security_opt. Es un lector deliberadamente
    pequeño: no pretende ser un parser YAML completo.
    """
    services: Dict[str, Dict[str, Any]] = {}
    current: Optional[str] = None
    current_list_key: Optional[str] = None
    in_services = False
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.rstrip("\n")
            if not line.strip() or line.strip().startswith("#"):
                continue
            indent = len(line) - len(line.lstrip(" "))
            stripped = line.strip()
            if indent == 0:
                in_services = stripped.startswith("services:")
                current = None
                current_list_key = None
                continue
            if not in_services:
                continue
            if indent == 2 and stripped.endswith(":"):
                current = stripped[:-1].strip()
                services[current] = {
                    "privileged": False,
                    "cap_drop": [],
                    "cap_add": [],
                    "security_opt": [],
                }
                current_list_key = None
                continue
            if current is None:
                continue
            if indent == 4:
                key, _, value = stripped.partition(":")
                key = key.strip()
                value = value.strip()
                current_list_key = None
                if key == "privileged":
                    services[current]["privileged"] = value.lower() in ("true", "yes")
                elif key in ("cap_drop", "cap_add", "security_opt"):
                    current_list_key = key
                    services[current][key] = []
                    if value and value != "[]":
                        services[current][key] = [value]
                continue
            if indent >= 6 and stripped.startswith("- ") and current_list_key:
                services[current][current_list_key].append(stripped[2:].strip())
    return services


def _normalise_list(values: List[str]) -> List[str]:
    """Normaliza una lista de scalars YAML a mayusculas sin comillas."""
    result: List[str] = []
    for value in values:
        cleaned = str(value).strip().strip("'\"").strip("[]").strip()
        if cleaned and cleaned.upper() != "NONE":
            result.append(cleaned.upper())
    return result


def check_container_hardening() -> CheckResult:
    """Comprueba el endurecimiento de contenedores declarado y en ejecucion."""
    compose_path = os.path.join(REPO_ROOT, "infra", "f11", "compose.yaml")
    command = (
        "lectura de la seccion services de infra/f11/compose.yaml y "
        "docker inspect %s %s --format '{{.Name}} privileged={{.HostConfig.Privileged}} "
        "cap_drop={{.HostConfig.CapDrop}} cap_add={{.HostConfig.CapAdd}} "
        "security_opt={{.HostConfig.SecurityOpt}}'"
        % (F11_KEYCLOAK_CONTAINER, F11_FRONTEND_CONTAINER)
    )
    if not os.path.exists(compose_path):
        return _build(
            "CONTAINER_HARDENING", "warning", command,
            "No se encuentra el compose del entorno F11 en %s" % compose_path,
            "Restaura infra/f11/compose.yaml: es la declaracion de los servicios del F11.",
        )
    services = _parse_compose_services(compose_path)
    problems: List[str] = []
    report: Dict[str, Any] = {}
    for name, spec in services.items():
        cap_drop = _normalise_list(spec["cap_drop"])
        security_opt = _normalise_list(spec["security_opt"])
        entry = {
            "privileged": spec["privileged"],
            "cap_drop": cap_drop,
            "cap_add": _normalise_list(spec["cap_add"]),
            "security_opt": security_opt,
        }
        if spec["privileged"]:
            problems.append("el servicio %s declara privileged: true" % name)
        if "ALL" not in cap_drop:
            problems.append("el servicio %s no declara cap_drop: ALL" % name)
        if not any("NO-NEW-PRIVILEGES" in opt for opt in security_opt):
            problems.append("el servicio %s no declara no-new-privileges" % name)
        report[name] = entry
    inspect_code, inspect_stdout, inspect_stderr = _run_command([
        "docker", "inspect", F11_KEYCLOAK_CONTAINER, F11_FRONTEND_CONTAINER,
        "--format", "{{.Name}} privileged={{.HostConfig.Privileged}} "
                    "cap_drop={{.HostConfig.CapDrop}} cap_add={{.HostConfig.CapAdd}} "
                    "security_opt={{.HostConfig.SecurityOpt}}",
    ])
    runtime = {
        "codigo": inspect_code,
        "salida": inspect_stdout,
        "error": inspect_stderr,
    }
    runtime_available = inspect_code == 0 and bool(inspect_stdout)
    if runtime_available:
        for line in inspect_stdout.splitlines():
            compact = line.replace(" ", "").lower()
            if "privileged=true" in compact:
                problems.append("en ejecucion: %s esta en modo privilegiado" % line.strip())
            if "cap_drop=[]" in compact:
                problems.append(
                    "en ejecucion: %s no descarta capacidades (cap_drop vacio)" % line.strip()
                )
            if "security_opt=[]" in compact:
                problems.append(
                    "en ejecucion: %s no declara no-new-privileges" % line.strip()
                )
    else:
        problems.append(
            "no se pudo consultar el estado real de los contenedores: %s"
            % (inspect_stderr or inspect_stdout or "sin salida")
        )
    output = _json_evidence({
        "compose": os.path.relpath(compose_path, REPO_ROOT).replace("\\", "/"),
        "servicios_declarados": report,
        "estado_real_de_los_contenedores": runtime,
        "problemas": problems,
    })
    if not services:
        return _build(
            "CONTAINER_HARDENING", "warning", command, output,
            "No se pudo leer la seccion services del compose del F11.",
        )
    if problems:
        return _build(
            "CONTAINER_HARDENING", "failed", command, output,
            "Endurece los servicios del F11 en infra/f11/compose.yaml: sin privileged, con "
            "cap_drop: ALL y con no-new-privileges:true. Problemas: %s."
            % "; ".join(problems),
        )
    return _build(
        "CONTAINER_HARDENING", "passed", command, output,
        "Ninguna: los servicios del F11 no estan en modo privilegiado y descartan capacidades.",
    )


def check_data_files_owner_only() -> CheckResult:
    """Comprueba los permisos reales de la base de datos y de su WAL."""
    path = _db_path()
    artifacts = [
        path,
        path + "-wal",
        path + "-shm",
        path + ".anchor-key",
    ]
    command = (
        "consulta de los permisos de los ficheros %s con os.stat (modo esperado 0600)"
        % " ".join(artifacts)
    )
    existing = [artifact for artifact in artifacts if os.path.exists(artifact)]
    if not existing:
        return _build(
            "DATA_FILES_OWNER_ONLY", "warning", command,
            "No existe ningun fichero de datos en la ruta configurada: %s" % path,
            "Arranca el backend del F11 para que existan la base de datos y su WAL.",
        )
    report: List[Dict[str, Any]] = []
    problems: List[str] = []
    for artifact in existing:
        mode = os.stat(artifact).st_mode & 0o777
        report.append({
            "fichero": artifact,
            "modo": "%04o" % mode,
            "solo_propietario": mode == 0o600,
        })
        if mode != 0o600:
            problems.append("%s tiene modo %04o" % (artifact, mode))
    output = _json_evidence({
        "base_de_datos": path,
        "ficheros": report,
        "problemas": problems,
    })
    if problems:
        return _build(
            "DATA_FILES_OWNER_ONLY", "failed", command, output,
            "Restringe a 0600 el modo de la base de datos, su WAL y la clave de anclaje "
            "(chmod 600): solo el propietario del proceso debe poder leerlos.",
        )
    return _build(
        "DATA_FILES_OWNER_ONLY", "passed", command, output,
        "Ninguna: los %d ficheros de datos son de solo propietario (0600)." % len(existing),
    )


# --------------------------------------------------------------------------
# Ejecucion
# --------------------------------------------------------------------------
CHECKERS: List[Callable[[], CheckResult]] = [
    check_kc_pkce_s256,
    check_kc_registration_disabled,
    check_kc_password_reset_disabled,
    check_kc_mfa_on_admin_identities,
    check_kc_protected_role_not_grantable,
    check_backend_auth_delegated_to_keycloak,
    check_backend_admin_requires_mfa,
    check_backend_audit_chain_valid,
    check_backend_audit_checkpoint_consistent,
    check_frontend_bundle_has_no_password_field,
    check_container_hardening,
    check_data_files_owner_only,
]

# Correspondencia entre cada funcion de comprobador y su identificador de
# catalogo. La funcion se llama check_<id en minusculas>: la correspondencia se
# deriva del propio catalogo para que no haya dos listas que se desincronicen.
CHECKER_BY_FUNCTION: Dict[str, str] = {
    "check_" + entry["id"].lower(): entry["id"] for entry in CHECKER_CATALOG
}


def run_checks(checker_ids: Optional[List[str]] = None) -> List[CheckResult]:
    """
    Ejecuta los comprobadores y devuelve sus resultados con la evidencia real.

    ``checker_ids`` distingue tres casos, porque en Python una lista vacia es
    *falsy* y no puede usarse como sinonimo de "todos":

    * ``None`` (o ausente): se ejecuta el catalogo completo.
    * ``[]``: no se ejecuta ningun comprobador (una ejecucion con cero).
    * Una lista no vacia: se ejecutan solo esos comprobadores.

    Una excepcion en un comprobador se convierte en un resultado ``warning``
    con el detalle real de la excepcion: nunca se convierte en un ``passed``.
    """
    wanted = set(checker_ids) if checker_ids is not None else None
    results: List[CheckResult] = []
    for checker in CHECKERS:
        checker_id = CHECKER_BY_FUNCTION.get(checker.__name__)
        if checker_id is None:
            raise RuntimeError(
                "El comprobador '%s' no esta registrado en el catalogo." % checker.__name__
            )
        if wanted is not None and checker_id not in wanted:
            continue
        try:
            result = checker()
            if not result.evidence_source:
                result.evidence_source = EVIDENCE_SOURCES.get(result.checker_id, "undeclared")
            results.append(result)
        except Exception as exc:
            meta = CHECKER_META[checker_id]
            results.append(CheckResult(
                checker_id=checker_id,
                title=meta["title"],
                objective=meta["objective"],
                severity=meta["severity"],
                status="warning",
                asset_ref=meta["asset_ref"],
                evidence_source=EVIDENCE_SOURCES.get(checker_id, "undeclared"),
                evidence_command=(
                    "llamada a la funcion check_%s() del modulo backend/security_diagnostics.py "
                    "en el proceso" % checker_id.lower()
                ),
                evidence_output=_truncate(
                    "El comprobador %s no pudo obtener evidencia: %s: %s"
                    % (checker_id, type(exc).__name__, exc)
                ),
                remediation=(
                    "Revisa la causa real de la excepcion y vuelve a ejecutar el comprobador "
                    "antes de darlo por verificado."
                ),
            ))
    return results
