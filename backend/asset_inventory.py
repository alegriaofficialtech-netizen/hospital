#!/usr/bin/env python3
"""Modulo M3 de inventario de activos del laboratorio SGSI-ZTA (F11).

Catalogo de los componentes REALES del laboratorio F11: emisor de identidades,
API clinica, bundle Angular, base de datos, cadena de auditoria, realm,
cliente OIDC, tema de Keycloak, compose y suite de pruebas.

Reglas del modulo:

* El inventario describe lo que existe, no lo que deberia existir. Cada activo
  declara su origen (``compose``, ``runtime`` o ``manual``) para que se pueda
  distinguir lo observado de lo declarado.
* ``owner`` es siempre un rol o un equipo, nunca el nombre de una persona.
* ``version`` se lee del entorno real cuando se puede y se deja en ``None``
  cuando no: no se inventa una version.
* Los activos que guardan datos del laboratorio son sinteticos y se marcan con
  ``synthetic=1``. El resto es infraestructura (``synthetic=0``).
* La siembra es idempotente y queda auditada: se ejecuta una sola vez, los
  activos y su evento ``ASSET_SEED`` se escriben en la misma transaccion y el
  backend no arranca si la siembra falla (fail-closed).
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import sqlite3
import subprocess
import sys
from typing import Any, Callable, Dict, List, Optional

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(CURRENT_DIR)
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from database import (
    ASSET_CLASSIFICATIONS,
    ASSET_CRITICALITIES,
    ASSET_SOURCES,
    F11_ENVIRONMENT,
    validate_asset_name,
)

F11_FRONTEND_CONTAINER = "sgsi-zta-f11-frontend"
F11_KEYCLOAK_CONTAINER = "sgsi-zta-f11-keycloak"

# Accion de auditoria que deja constancia de la siembra del inventario.
SEED_AUDIT_ACTION = "ASSET_SEED"


# --------------------------------------------------------------------------
# Vocabulario y reglas de decision
# --------------------------------------------------------------------------
def classifications() -> List[str]:
    """Devuelve las clasificaciones admitidas para un activo."""
    return list(ASSET_CLASSIFICATIONS)


def criticalities() -> List[str]:
    """Devuelve las criticidades admitidas para un activo."""
    return list(ASSET_CRITICALITIES)


def sources() -> List[str]:
    """Devuelve los origenes admitidos para un activo."""
    return list(ASSET_SOURCES)


# Regla de decision de la clasificacion: que hace que un activo sea de un tipo
# y no de otro. Se escribe para que la clasificacion sea reproducible.
CLASSIFICATION_RULES: Dict[str, str] = {
    "container": (
        "Regla: es container si la unidad se ejecuta como imagen de contenedor, con su "
        "propio sistema de ficheros y su propio ciclo de vida. No se confunde con service: "
        "el contenedor es la empaquetacion, el servicio es la funcion que expone."
    ),
    "service": (
        "Regla: es service si la unidad expone una funcion de red o de proceso que "
        "responde a peticiones, con su propia politica de autorizacion. Un servicio puede "
        "correr sin contenedor."
    ),
    "dataset": (
        "Regla: es dataset si la unidad es un conjunto de datos persistido cuyo contenido "
        "es el activo: ordenes clinicas, eventos de auditoria, registros. Se marca como "
        "sintetico cuando guarda datos del laboratorio de prueba."
    ),
    "identity_store": (
        "Regla: es identity_store si la unidad custodia identidades, roles, credenciales o "
        "politicas de acceso. Es el componente donde el compromiso significa escalamiento."
    ),
    "code": (
        "Regla: es code si la unidad es el codigo fuente o un artefacto de compilacion que "
        "se ejecuta dentro de otro componente. El binario no es infraestructura: es codigo."
    ),
    "configuration": (
        "Regla: es configuration si la unidad declara como funciona el sistema (compose, "
        "cliente OIDC, plantillas) y no guarda datos por si misma."
    ),
}

# Regla de decision de la criticidad: como se decide el nivel de un activo a
# partir de su clasificacion y del papel que juega en la plataforma.
CRITICALITY_RULES: Dict[str, str] = {
    "critical": (
        "Regla: es critical si el activo custodia credenciales o material de identidad, "
        "contiene los datos clinicos o la cadena de auditoria, o aplica las decisiones de "
        "autorizacion del PEP. Su compromiso permite el escalamiento o destroy la "
        "trazabilidad, que es lo que el resto de controles no puede recuperar."
    ),
    "high": (
        "Regla: es high si el activo es una condicion necesaria para la seguridad pero su "
        "compromiso degrada la defensa sin romper la trazabilidad: una puerta de entrada, un "
        "contenedor que aloja el emisor, la declaracion de despliegue del entorno."
    ),
    "medium": (
        "Regla: es medium si el activo no custodia secretos ni decisiones de autorizacion y "
        "su compromiso solo afecta a la usabilidad, la presentacion o la calidad de la "
        "evidencia: codigo de cliente, tema, suite de pruebas."
    ),
    "low": (
        "Regla: es low si el activo es auxiliar, no interviene en la autorizacion ni en la "
        "conservacion de la evidencia, y su compromiso no degrada ninguna funcion de "
        "seguridad de la plataforma."
    ),
}

# Criticidad de partida por clasificacion antes de considerar el papel.
CRITICALITY_BY_CLASSIFICATION: Dict[str, str] = {
    "container": "high",
    "service": "critical",
    "dataset": "critical",
    "identity_store": "critical",
    "code": "medium",
    "configuration": "high",
}

# Papeles que elevan la criticidad a critical con independencia de la
# clasificacion, porque tocan identidades, autorizacion o evidencia.
CRITICALITY_ESCALATION_ROLES = ("identity", "authorization", "audit", "credentials")


def criticality_for(classification: str, role: str) -> str:
    """
    Decide la criticidad de un activo a partir de su clasificacion y de su papel.

    Regla: se parte de la criticidad base de la clasificacion
    (CRITICALITY_BY_CLASSIFICATION) y se eleva a ``critical`` cuando el papel del
    activo es identity, authorization, audit o credentials, porque en ese caso
    el activo custodia material de identidad, decide el acceso o sostiene la
    evidencia de auditoria.
    """
    base = CRITICALITY_BY_CLASSIFICATION.get(classification, "low")
    if role in CRITICALITY_ESCALATION_ROLES:
        return "critical"
    return base


# --------------------------------------------------------------------------
# Lectura de versiones reales
# --------------------------------------------------------------------------
def _run(command: List[str], timeout: int = 25) -> Optional[str]:
    """Ejecuta un comando y devuelve su salida limpia, o None si no se pudo leer."""
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, cwd=REPO_ROOT
        )
    except Exception:
        return None
    if completed.returncode != 0:
        return None
    output = (completed.stdout or "").strip()
    return output or None


def _keycloak_version() -> Optional[str]:
    """Lee la version real de la imagen de Keycloak del F11."""
    output = _run([
        "docker", "inspect", F11_KEYCLOAK_CONTAINER, "--format",
        '{{index .Config.Labels "org.opencontainers.image.version"}}',
    ])
    if output and output not in ("<no value>", "null", "None"):
        return output
    output = _run([
        "docker", "exec", F11_KEYCLOAK_CONTAINER, "sh", "-c",
        "cat /opt/keycloak/version.txt 2>/dev/null",
    ])
    if output:
        return output.split()[-1]
    return None


def _caddy_version() -> Optional[str]:
    """Lee la version real de Caddy en el contenedor del frontend."""
    output = _run(["docker", "exec", F11_FRONTEND_CONTAINER, "caddy", "version"])
    if output:
        return output.split()[0]
    return None


def _git_revision() -> Optional[str]:
    """Lee la revision real del repositorio del entorno F11."""
    output = _run(["git", "-C", REPO_ROOT, "rev-parse", "--short", "HEAD"])
    return output


def _sqlite_version() -> Optional[str]:
    """Version real de la biblioteca SQLite con la que se escribe la base."""
    return sqlite3.sqlite_version


def _python_version() -> Optional[str]:
    """Version real del interprete que ejecuta el backend."""
    return platform.python_version()


def _angular_version() -> Optional[str]:
    """Version real de Angular declarada en el proyecto del frontend."""
    path = os.path.join(REPO_ROOT, "frontend", "package.json")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            package = json.load(handle)
    except Exception:
        return None
    dependencies = package.get("dependencies") or {}
    declared = dependencies.get("@angular/core")
    if not declared:
        return None
    return str(declared).lstrip("^~")


VERSION_RESOLVERS: Dict[str, Callable[[], Optional[str]]] = {
    "keycloak": _keycloak_version,
    "caddy": _caddy_version,
    "git": _git_revision,
    "sqlite": _sqlite_version,
    "python": _python_version,
    "angular": _angular_version,
}


# --------------------------------------------------------------------------
# Catalogo semilla del laboratorio F11
# --------------------------------------------------------------------------
# Cada activo declara su clasificacion, su papel (que decide la criticidad),
# su propietario como equipo, su origen y una descripcion que justifica la
# clasificacion y la criticidad elegidas.
SEED_CATALOG: List[Dict[str, Any]] = [
    {
        "name": "keycloak-iam",
        "classification": "container",
        "role": "identity",
        "owner": "Equipo de Identidad y Acceso SGSI-ZTA",
        "source": "compose",
        "version": "keycloak",
        "synthetic": 0,
        "description": (
            "Contenedor que ejecuta el emisor OIDC del laboratorio F11 y donde viven las "
            "identidades sinteticas, los roles del realm, el tema de acceso y la "
            "autenticacion TOTP. Se clasifica como container porque se despliega y ejecuta "
            "como imagen aislada de Docker, y es critical porque su compromiso equivale al "
            "del sistema completo: permite emitir tokens y conceder roles."
        ),
    },
    {
        "name": "keycloak-realm-hospital-lab",
        "classification": "identity_store",
        "role": "identity",
        "owner": "Equipo de Identidad y Acceso SGSI-ZTA",
        "source": "runtime",
        "version": None,
        "synthetic": 1,
        "description": (
            "Realm hospital-lab-local de Keycloak: guarda las identidades sinteticas "
            "(sufijo .test), sus roles de realm y la politica de autorregistro y "
            "restablecimiento de contrasena. Se clasifica como identity_store porque "
            "custodia identidades y roles, y es critical porque un realm alterado "
            "concede privilegios sin pasar por la aplicacion."
        ),
    },
    {
        "name": "oidc-client-clinical-poc",
        "classification": "configuration",
        "role": "identity",
        "owner": "Equipo de Identidad y Acceso SGSI-ZTA",
        "source": "runtime",
        "version": None,
        "synthetic": 0,
        "description": (
            "Cliente publico OIDC clinical-poc registrado en el realm, con la configuracion "
            "de PKCE S256, las URIs de retorno y la audiencia clinical-poc-api que exige el "
            "backend. Se clasifica como configuration porque declara el acceso sin guardar "
            "datos, y es critical porque de sus atributos depende la proteccion del codigo "
            "de autorizacion contra la interceptacion."
        ),
    },
    {
        "name": "keycloak-theme-hospital-lab",
        "classification": "code",
        "role": "presentation",
        "owner": "Equipo de Experiencia Clinica SGSI-ZTA",
        "source": "manual",
        "version": "git",
        "synthetic": 0,
        "description": (
            "Tema de acceso propio que se compila dentro de la imagen de Keycloak y dibuja "
            "el formulario de credenciales del hospital. Se clasifica como code porque es "
            "codigo que se ejecuta dentro del emisor, y es medium porque no custodia "
            "secretos ni decide el acceso: su compromiso degrada la presentacion, no la "
            "autorizacion."
        ),
    },
    {
        "name": "backend-api",
        "classification": "service",
        "role": "authorization",
        "owner": "Equipo de Plataforma SGSI-ZTA",
        "source": "runtime",
        "version": "git",
        "synthetic": 0,
        "description": (
            "API clinica en Python que valida los tokens RS256 de Keycloak, aplica el RBAC "
            "con MFA, expone el laboratorio y, desde F2, el diagnostico y el inventario. Se "
            "clasifica como service porque expone una funcion de red con su propia politica "
            "de autorizacion, y es critical porque es el punto de aplicacion de permisos: su "
            "compromiso permite ejecutar acciones sin el control previsto."
        ),
    },
    {
        "name": "frontend-caddy",
        "classification": "container",
        "role": "presentation",
        "owner": "Equipo de Experiencia Clinica SGSI-ZTA",
        "source": "compose",
        "version": "caddy",
        "synthetic": 0,
        "description": (
            "Contenedor de Caddy que sirve el bundle Angular del laboratorio en el puerto "
            "4200 de la interfaz local. Se clasifica como container porque se ejecuta como "
            "imagen de Docker con su propio ciclo de vida, y es high porque es la puerta de "
            "entrada del navegador: su compromiso expone la interfaz, aunque no las "
            "identidades, que viven en Keycloak."
        ),
    },
    {
        "name": "frontend-angular-bundle",
        "classification": "code",
        "role": "presentation",
        "owner": "Equipo de Experiencia Clinica SGSI-ZTA",
        "source": "runtime",
        "version": "angular",
        "synthetic": 0,
        "description": (
            "Artefacto compilado de la aplicacion Angular que el navegador descarga; desde el "
            "corte de acceso unico no contiene ningun campo de contrasena y solo hace "
            "traspaso al formulario de Keycloak. Se clasifica como code porque es un "
            "artefacto ejecutable, y es medium porque no custodia secretos ni decide el "
            "acceso, pero es la superficie que ve el usuario."
        ),
    },
    {
        "name": "clinical-sqlite-db",
        "classification": "dataset",
        "role": "clinical_data",
        "owner": "Equipo de Plataforma SGSI-ZTA",
        "source": "runtime",
        "version": "sqlite",
        "synthetic": 1,
        "description": (
            "Base de datos SQLite en modo WAL con las ordenes clinicas sinteticas del "
            "laboratorio y sus metadatos. Se clasifica como dataset porque su contenido es "
            "el activo, y es critical porque es el deposito de datos clinicos: aunque sean "
            "sinteticos, su compromiso expone el modelo de datos y las relaciones del "
            "laboratorio."
        ),
    },
    {
        "name": "audit-chain",
        "classification": "dataset",
        "role": "audit",
        "owner": "Equipo de Seguridad de la Informacion SGSI-ZTA",
        "source": "runtime",
        "version": "sqlite",
        "synthetic": 1,
        "description": (
            "Cadena de auditoria encadenada por hash y su checkpoint, almacenados en la misma "
            "base SQLite con la clave de anclaje al lado. Se clasifica como dataset porque "
            "son datos, y es critical porque es la evidencia de trazabilidad: si la cadena "
            "deja de verificar, ninguna otra afirmacion de la plataforma es demostrable."
        ),
    },
    {
        "name": "compose-f11",
        "classification": "configuration",
        "role": "deployment",
        "owner": "Equipo de Infraestructura F11 SGSI-ZTA",
        "source": "compose",
        "version": "git",
        "synthetic": 0,
        "description": (
            "Declaracion de despliegue del entorno F11 en infra/f11/compose.yaml: servicios, "
            "puertos, volumen, red y opciones de endurecimiento de contenedores. Se clasifica "
            "como configuration porque no guarda datos y es high porque de ella depende el "
            "aislamiento real de los contenedores que ejecutan la plataforma."
        ),
    },
    {
        "name": "api-test-suite",
        "classification": "code",
        "role": "assurance",
        "owner": "Equipo de Seguridad de la Informacion SGSI-ZTA",
        "source": "manual",
        "version": "git",
        "synthetic": 0,
        "description": (
            "Suite de pruebas de API que ejercita el stack real (autenticacion, RBAC, MFA y "
            "cadena de auditoria) sobre la interfaz de bucle local. Se clasifica como code "
            "porque es codigo de verificacion y es medium porque no forma parte del camino "
            "de ejecucion: su valor es la evidencia que produce, no el servicio que da."
        ),
    },
]


# --------------------------------------------------------------------------
# Siembra idempotente, atomica y auditada
# --------------------------------------------------------------------------
def build_asset_payload(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Construye el registro persistible de un activo del catalogo semilla."""
    classification = entry["classification"]
    version_resolver = entry.get("version")
    version: Optional[str] = None
    if isinstance(version_resolver, str) and version_resolver in VERSION_RESOLVERS:
        version = VERSION_RESOLVERS[version_resolver]()
    elif isinstance(version_resolver, str):
        version = version_resolver
    return {
        "name": entry["name"],
        "classification": classification,
        "criticality": criticality_for(classification, entry.get("role", "")),
        "owner": entry["owner"],
        "source": entry["source"],
        "version": version,
        "environment": F11_ENVIRONMENT,
        "synthetic": 1 if int(entry.get("synthetic") or 0) else 0,
        "description": entry["description"],
    }


def seed_asset_id(name: str) -> str:
    """
    Identificador estable de un activo del catalogo semilla.

    Es determinista a proposito: la identidad del activo sembrado no depende
    del arranque. Si un administrador renombra un activo por la API, su
    identificador no cambia y la siembra no lo vuelve a insertar con el
    nombre original.
    """
    digest = hashlib.sha256(("f11-seed:" + name).encode("utf-8")).hexdigest()[:8].upper()
    return "AST-" + digest


def seed_catalog(db: Any) -> Dict[str, Any]:
    """
    Inserta el catalogo semilla del F11 de forma idempotente, atomica y auditada.

    Reglas de la siembra:

    * Idempotencia por identidad, no solo por nombre: cada activo del
      catalogo tiene un identificador estable (``seed_asset_id``), de modo que
      un activo renombrado por la API no se reinserta con el nombre original
      en el siguiente arranque.
    * La siembra se ejecuta UNA sola vez: cuando la cadena de auditoria ya
      tiene un evento ``ASSET_SEED``, el arranque no vuelve a tocar el
      inventario. Un activo renombrado o corregido despues se queda como
      esta: el inventario refleja lo que hay y su correccion se hace por la
      API, que queda auditada.
    * Atomicidad: los activos y el evento ``ASSET_SEED`` se escriben en la
      misma transaccion. Si la siembra falla no queda ni un activo a medias ni
      un evento que diga lo contrario, y el backend no arranca (fail-closed).
    """
    existing = db.list_assets()
    existing_names = {str(asset.get("name") or "") for asset in existing}
    existing_ids = {str(asset.get("id") or "") for asset in existing}

    if db.count_audit_events_by_action(SEED_AUDIT_ACTION) > 0:
        # La siembra ya se hizo y quedo auditada: el arranque no vuelve a
        # tocar el inventario. Es lo que evita que un activo renombrado por la
        # API reaparezca con su nombre original.
        return {
            "created": [],
            "skipped": sorted(existing_names),
            "total_catalog": len(SEED_CATALOG),
            "environment": F11_ENVIRONMENT,
            "already_seeded": True,
        }

    pending: List[Dict[str, Any]] = []
    skipped: List[str] = []
    for entry in SEED_CATALOG:
        asset_id = seed_asset_id(entry["name"])
        if entry["name"] in existing_names or asset_id in existing_ids:
            # El activo ya esta (con su nombre o renombrado): no se duplica ni
            # se sobrescribe.
            skipped.append(entry["name"])
            continue
        pending.append(entry)

    payloads: List[Dict[str, Any]] = []
    for entry in pending:
        payload = build_asset_payload(entry)
        payload["id"] = seed_asset_id(entry["name"])
        payload["revision"] = 1
        payloads.append(payload)

    audit_event = {
        "action": SEED_AUDIT_ACTION,
        "actor": "SYSTEM",
        "role": "NONE",
        "status": "ALLOWED",
        "details": (
            "Siembra del inventario de activos del entorno %s: %d activos creados, "
            "%d ya existentes (catalogo de %d activos)"
            % (F11_ENVIRONMENT, len(payloads), len(skipped), len(SEED_CATALOG))
        ),
        "ip": "127.0.0.1",
        "mfa_verified": False,
    }
    created, _record = db.insert_assets_with_audit_event(payloads, audit_event)
    return {
        "created": created,
        "skipped": skipped,
        "total_catalog": len(SEED_CATALOG),
        "environment": F11_ENVIRONMENT,
        "already_seeded": False,
    }


# --------------------------------------------------------------------------
# Validacion de los cuerpos de escritura
# --------------------------------------------------------------------------
def validate_asset(payload: Dict[str, Any], partial: bool = False) -> List[str]:
    """
    Valida el cuerpo de un activo y devuelve la lista de errores por campo.

    Cada error tiene el formato ``campo: mensaje`` para que la API pueda
    construir el mapa ``fields`` de la respuesta 400.

    En modo parcial (actualizacion) solo se validan los campos presentes en el
    cuerpo; en modo completo todos los campos son obligatorios.
    """
    errors: List[str] = []

    def present(field: str) -> bool:
        return partial and field not in payload

    if not present("name"):
        name = str(payload.get("name") or "").strip()
        # Misma regla y mismo mensaje que aplica la capa de persistencia:
        # la regla vive en backend/database.py y aqui solo se reutiliza.
        name_error = validate_asset_name(name)
        if name_error:
            errors.append("name: %s" % name_error)

    if not present("classification"):
        classification = str(payload.get("classification") or "").strip()
        if classification not in ASSET_CLASSIFICATIONS:
            errors.append(
                "classification: la clasificacion debe ser una de: %s"
                % ", ".join(ASSET_CLASSIFICATIONS)
            )

    if not present("criticality"):
        criticality = str(payload.get("criticality") or "").strip()
        if criticality not in ASSET_CRITICALITIES:
            errors.append(
                "criticality: la criticidad debe ser una de: %s"
                % ", ".join(ASSET_CRITICALITIES)
            )

    if not present("owner"):
        owner = str(payload.get("owner") or "").strip()
        if not owner:
            errors.append("owner: el propietario es obligatorio y debe ser un rol o un equipo")
        elif not 3 <= len(owner) <= 80:
            errors.append("owner: el propietario debe tener entre 3 y 80 caracteres")

    if not present("source"):
        source = str(payload.get("source") or "").strip()
        if source not in ASSET_SOURCES:
            errors.append(
                "source: el origen debe ser uno de: %s" % ", ".join(ASSET_SOURCES)
            )

    if not present("version"):
        version = payload.get("version")
        if version is not None:
            if not isinstance(version, str):
                errors.append("version: la version debe ser una cadena de texto")
            elif len(version) > 64:
                errors.append("version: la version no puede superar los 64 caracteres")

    if not present("environment"):
        environment = payload.get("environment")
        if environment is not None:
            if not isinstance(environment, str):
                errors.append("environment: el entorno debe ser una cadena de texto")
            elif environment != F11_ENVIRONMENT:
                errors.append(
                    "environment: el entorno del inventario es '%s' y no admite otros valores"
                    % F11_ENVIRONMENT
                )

    if not present("synthetic"):
        synthetic = payload.get("synthetic")
        if synthetic is not None and synthetic not in (0, 1, True, False):
            errors.append("synthetic: el valor sintetico debe ser 0 o 1")

    if not present("description"):
        description = str(payload.get("description") or "").strip()
        if not description:
            errors.append("description: la descripcion es obligatoria")
        elif not 10 <= len(description) <= 600:
            errors.append("description: la descripcion debe tener entre 10 y 600 caracteres")

    return errors
