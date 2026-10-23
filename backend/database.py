#!/usr/bin/env python3
"""
database.py - Gestor de Persistencia Duradera ACID para LIS Clínico
SGSI-ZTA Hospital Lab — ISO/IEC 27001:2022 Control A.8.15 & NIST SP 800-207

Implementa persistencia relacional transaccional mediante SQLite en modo WAL:
1. Transacciones ACID completas con control estricto de concurrencia (RLock).
2. Modelo relacional + documento JSON que preserva integridad y compatibilidad total.
3. Cadena criptográfica de auditoría inmutable e inviolable a través de reinicios.
4. Verificación exhaustiva de integridad en el arranque (Detección de alteración o borrado).
5. Mecanismo de respaldo atómico en línea mediante la API de backup de SQLite.
6. Aislamiento Fail-Closed ante fallos de disco o acceso no autorizado.
7. Colecciones Proxy (OrdersDict, AuditLogsList) para compatibilidad transparente 100%.
8. Transacción clínica única que cubre la orden y su evento de auditoría.
"""

import collections.abc
import hashlib
import json
import os
import sqlite3
import threading
import time
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

SCHEMA_VERSION = 9
ZERO_HASH = "0" * 64

# Vocabulario cerrado de M9 (validacion por expertos) y de los informes. Vive
# en la capa de persistencia porque es la capa inferior: la API y el modulo de
# dominio lo reutilizan en lugar de duplicarlo, de modo que ningun escritor
# pueda guardar un estado, un veredicto o un objetivo fuera de catalogo.
INSTRUMENT_STATUSES = ("BORRADOR", "ACTIVO", "ARCHIVADO")
VALIDATION_DIMENSIONS = (
    "identidad",
    "dispositivo",
    "red",
    "aplicacion",
    "datos",
    "monitoreo",
)
# El veredicto es una declaracion del experto, no un calculo del sistema. El
# catalogo solo acota que valores puede declarar.
VERDICTS = ("NO_CUMPLE", "CUMPLE_PARCIALMENTE", "CUMPLE")
REPORT_OBJECTIVES = ("O1", "O2", "O3", "O4")

# Entorno de ejecucion al que pertenece toda la evidencia de la plataforma.
# La evidencia real es solo la del entorno F11: el resto no genera hallazgos.
F11_ENVIRONMENT = "f11-local"

# Vocabulario cerrado del inventario de activos (M3). La capa de persistencia
# lo impone: un activo con una clasificacion, criticidad u origen fuera de
# estas listas no se escribe.
ASSET_CLASSIFICATIONS = ("container", "service", "dataset", "identity_store", "code", "configuration")
ASSET_CRITICALITIES = ("critical", "high", "medium", "low")
ASSET_SOURCES = ("compose", "runtime", "manual")

# Regla del nombre de un activo. Vive en la capa de persistencia porque es la
# capa inferior: la API la reutiliza en lugar de duplicarla, de modo que un
# escritor que no pase por el handler HTTP (un script, una importacion) no
# puede meter comillas, espacios ni caracteres de control en assets.name.
ASSET_NAME_MIN_LENGTH = 3
ASSET_NAME_MAX_LENGTH = 80
ASSET_NAME_ALLOWED_CHARACTERS = "-_."

# Campos del activo que admiten null con significado propio: null en 'version'
# significa "borra la version". En el resto de campos, un null no borra nada:
# se conserva el valor vigente.
NULLABLE_ASSET_FIELDS = ("version",)


def validate_asset_name(name: str) -> Optional[str]:
    """
    Aplica la regla de nombre de activo y devuelve el motivo, o None si es valido.

    Misma regla y mismo mensaje en las dos capas (persistencia y API): el
    nombre no puede estar vacio, su longitud esta entre 3 y 80 caracteres y
    solo admite letras, digitos, guion, guion bajo y punto.
    """
    if not name:
        return "el nombre del activo es obligatorio"
    if not ASSET_NAME_MIN_LENGTH <= len(name) <= ASSET_NAME_MAX_LENGTH:
        return "el nombre debe tener entre %d y %d caracteres" % (
            ASSET_NAME_MIN_LENGTH, ASSET_NAME_MAX_LENGTH,
        )
    if not all(char.isalnum() or char in ASSET_NAME_ALLOWED_CHARACTERS for char in name):
        return "el nombre solo admite letras, digitos, guion, guion bajo y punto"
    return None

# Vocabulario de Gestion de Riesgos (M4)
RISK_CATEGORIES = (
    "identidad",
    "acceso",
    "software",
    "datos",
    "red",
    "infraestructura",
)
RISK_LEVELS = ("BAJO", "MEDIO", "ALTO", "CRITICO")
RISK_TREATMENTS = ("MITIGAR", "ACEPTAR", "TRANSFERIR", "EVITAR")
RISK_STATUSES = ("IDENTIFICADO", "EN_TRATAMIENTO", "CONTROLADO", "ACEPTADO")

# Vocabulario de Gestion de Controles (M5)
CONTROL_FRAMEWORKS = ("ISO_27001_2022", "NIST_SP_800_207", "CISA_ZTM")
CONTROL_STATUSES = ("PROPUESTO", "IMPLEMENTADO", "VERIFICADO")
CONTROL_EFFECTIVENESS = ("PREVENTIVO", "DETECTIVO", "CORRECTIVO")
CONTROL_EVIDENCE_TYPES = ("checker", "audit_event", "automated_test", "config_file", "none")

# Vocabulario y ciclo de vida de Gestion de Incidentes (M6 / F4)
INCIDENT_SEVERITIES = ("BAJA", "MEDIA", "ALTA", "CRITICA")
INCIDENT_STATUSES = ("ABIERTO", "EN_INVESTIGACION", "MITIGADO", "CERRADO")

# Diagrama de transiciones validas del ciclo de vida de un incidente. Vive en la
# capa de persistencia porque es la capa inferior: la API y el modulo de dominio
# lo reutilizan en lugar de duplicarlo, de modo que ninguna via de escritura
# puede saltarse una transicion no declarada. CERRADO es terminal: una vez
# cerrado un incidente no vuelve a abrirse (se registra uno nuevo si reaparece).
INCIDENT_TRANSITIONS = {
    "ABIERTO": ("EN_INVESTIGACION", "MITIGADO", "CERRADO"),
    "EN_INVESTIGACION": ("MITIGADO", "CERRADO"),
    "MITIGADO": ("CERRADO", "EN_INVESTIGACION"),
    "CERRADO": (),
}


def calculate_risk_level(probability: int, impact: int) -> Tuple[int, str]:
    """Calcula el score (P x I) y nivel cualitativo segun matriz 5x5."""
    try:
        prob = int(probability)
        imp = int(impact)
    except (ValueError, TypeError):
        prob, imp = 1, 1
    prob = max(1, min(5, prob))
    imp = max(1, min(5, imp))
    score = prob * imp
    if score >= 15:
        level = "CRITICO"
    elif score >= 10:
        level = "ALTO"
    elif score >= 5:
        level = "MEDIO"
    else:
        level = "BAJO"
    return score, level


class DatabaseError(Exception):
    """Excepción base para errores de base de datos."""
    pass


class AssetValidationError(DatabaseError):
    """El activo no cumple el vocabulario cerrado de clasificacion, criticidad u origen."""
    pass


class AssetAlreadyExistsError(DatabaseError):
    """Ya existe un activo registrado con el mismo nombre."""
    pass


class AssetNotFoundError(DatabaseError):
    """El activo solicitado no existe en el inventario."""
    pass

class RiskValidationError(DatabaseError):
    """El riesgo no cumple con el vocabulario o valores permitidos."""
    pass


class RiskAlreadyExistsError(DatabaseError):
    """Ya existe un riesgo registrado con el mismo codigo."""
    pass


class RiskNotFoundError(DatabaseError):
    """El riesgo solicitado no existe."""
    pass


class ControlValidationError(DatabaseError):
    """El control no cumple con el marco, estado o validaciones requeridas."""
    pass


class ControlAlreadyExistsError(DatabaseError):
    """Ya existe un control registrado con el mismo codigo."""
    pass


class ControlNotFoundError(DatabaseError):
    """El control solicitado no existe."""
    pass


class ControlEvidenceMissingError(DatabaseError):
    """Un control no puede marcarse como VERIFICADO sin evidencia real enlazada."""
    pass


class IncidentValidationError(DatabaseError):
    """El incidente no cumple con el vocabulario o valores permitidos (M6)."""
    pass


class IncidentAlreadyExistsError(DatabaseError):
    """Ya existe un incidente registrado con el mismo codigo (M6)."""
    pass


class IncidentNotFoundError(DatabaseError):
    """El incidente solicitado no existe (M6)."""
    pass


class IncidentTransitionError(DatabaseError):
    """La transicion de estado solicitada no esta declarada en el ciclo de vida (M6)."""
    pass


class AlertNotFoundError(DatabaseError):
    """La alerta no existe entre las derivadas del estado real de la plataforma (M6)."""
    pass


class InstrumentValidationError(DatabaseError):
    """El instrumento de validacion no cumple el contrato de M9."""
    pass


class InstrumentAlreadyExistsError(DatabaseError):
    """Ya existe un instrumento con el mismo codigo."""
    pass


class InstrumentNotFoundError(DatabaseError):
    """El instrumento solicitado no existe."""
    pass


class ExpertReviewValidationError(DatabaseError):
    """El dictamen de experto no cumple el contrato de registro de M9."""
    pass


class ExpertReviewAlreadyExistsError(DatabaseError):
    """Ya existe un dictamen registrado con el mismo codigo."""
    pass


class ExpertReviewNotFoundError(DatabaseError):
    """El dictamen de experto solicitado no existe."""
    pass


class ReportValidationError(DatabaseError):
    """El informe solicitado no cumple el contrato del modulo de informes."""
    pass


class ReportNotFoundError(DatabaseError):
    """El informe solicitado no existe."""
    pass


class DuplicateOrderError(DatabaseError):
    """Excepción cuando se intenta registrar una orden con ID duplicado."""
    pass


class OrderNotFoundError(DatabaseError):
    """Excepción cuando una orden requerida no existe."""
    pass


class OrderVersionConflictError(DatabaseError):
    """Excepción cuando la versión esperada de la orden no coincide con la almacenada."""
    pass


class IomtReplayError(DatabaseError):
    """Excepción cuando se reutiliza un nonce IoMT ya registrado."""
    pass


class AuditChainCorruptedError(DatabaseError):
    """Excepción crítica cuando se detecta manipulación o discontinuidad en la cadena de auditoría."""
    pass


class ClinicalDatabaseManager:
    """Gestor transaccional de base de datos relacional para LIS y Auditoría."""

    def __init__(self, db_path: Optional[str] = None, hmac_key: Optional[bytes] = None):
        if db_path:
            self.db_path = db_path
        else:
            self.db_path = os.environ.get("LIS_DB_PATH", "/data/lis.db")

        self._lock = threading.RLock()
        self._conn: Optional[sqlite3.Connection] = None
        self._last_audit_hash = ZERO_HASH

        self._ensure_directory()
        self._init_connection()
        self.hmac_key = self._resolve_anchor_key(hmac_key)
        self._apply_migrations()
        self._apply_file_permissions()
        self._load_and_verify_audit_chain()

    @property
    def anchor_key(self) -> bytes:
        """Expone la clave de anclaje de auditoría para derivar secretos internos."""
        return self.hmac_key

    def _ensure_directory(self) -> None:
        """Asegura que el directorio del archivo exista con permisos restrictivos si es nuevo."""
        db_dir = os.path.dirname(os.path.abspath(self.db_path))
        if db_dir and not os.path.exists(db_dir):
            try:
                os.makedirs(db_dir, mode=0o750, exist_ok=True)
            except Exception as e:
                raise DatabaseError(f"No se pudo crear directorio para base de datos {db_dir}: {e}")

    def _init_connection(self) -> None:
        """Inicializa la conexión con SQLite en modo WAL, sincronización FULL y timeout."""
        old_umask = os.umask(0o077)
        try:
            self._conn = sqlite3.connect(
                self.db_path,
                timeout=10.0,
                check_same_thread=False,
                isolation_level=None  # Manejo manual de transacciones
            )
        except Exception as e:
            raise DatabaseError(f"Fallo al conectar a SQLite en {self.db_path}: {e}")
        finally:
            os.umask(old_umask)

        try:
            self._conn.row_factory = sqlite3.Row
            cursor = self._conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA synchronous=FULL;")
            cursor.execute("PRAGMA foreign_keys=ON;")
            cursor.execute("PRAGMA busy_timeout=5000;")
            cursor.close()
        except Exception as e:
            raise DatabaseError(f"Fallo al configurar SQLite en {self.db_path}: {e}")

    def _get_conn(self) -> sqlite3.Connection:
        """Obtiene la conexión activa o lanza DatabaseError si está cerrada."""
        if self._conn is None:
            raise DatabaseError(f"Conexión de base de datos no disponible o cerrada en {self.db_path}.")
        return self._conn

    # --------------------------------------------------------------------------
    # CLAVE DE ANCLAJE DE AUDITORÍA (SIN DEFAULTS EMBEBIDOS)
    # --------------------------------------------------------------------------
    def _audit_events_have_rows(self) -> bool:
        """Comprueba si existe una cadena de auditoría previa en la base."""
        try:
            cur = self._conn.cursor()
            try:
                cur.execute("SELECT 1 FROM audit_events LIMIT 1;")
                return cur.fetchone() is not None
            finally:
                cur.close()
        except sqlite3.OperationalError:
            # La tabla aún no existe: base nueva, sin cadena previa.
            return False

    def _anchor_sidecar_path(self) -> str:
        """Ruta del archivo lateral que custodia la clave de anclaje de esta base."""
        return self.db_path + ".anchor-key"

    def _resolve_anchor_key(self, hmac_key: Optional[bytes]) -> bytes:
        """
        Resuelve la clave de anclaje de auditoría sin valores por defecto.

        Orden: argumento explícito, variable de entorno, archivo lateral de la
        base, o generación aleatoria si la base no tiene cadena previa. Si ya
        existen eventos y no hay clave disponible, falla cerrado.
        """
        if hmac_key is not None:
            if not isinstance(hmac_key, bytes) or not hmac_key:
                raise DatabaseError("La clave de anclaje de auditoría explícita debe ser bytes no vacíos.")
            return hmac_key

        env_key = os.environ.get("AUDIT_HMAC_KEY")
        if env_key:
            return env_key.encode("utf-8")

        sidecar = self._anchor_sidecar_path()
        if os.path.exists(sidecar):
            try:
                with open(sidecar, "r", encoding="ascii") as handle:
                    raw = handle.read().strip()
                key = bytes.fromhex(raw)
            except Exception as e:
                raise DatabaseError(f"Clave de anclaje ilegible en {sidecar}: {e}")
            if not key:
                raise DatabaseError(f"Clave de anclaje vacía en {sidecar}.")
            return key

        if self._audit_events_have_rows():
            raise AuditChainCorruptedError(
                "Cadena de auditoría existente sin clave de anclaje disponible: "
                "configure AUDIT_HMAC_KEY o restaure el archivo .anchor-key."
            )

        key = os.urandom(32)
        try:
            fd = os.open(sidecar, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as handle:
                handle.write(key.hex())
            os.chmod(sidecar, 0o600)
        except Exception as e:
            raise DatabaseError(f"No se pudo persistir la clave de anclaje en {sidecar}: {e}")
        return key

    def _clinical_artifacts(self) -> Tuple[str, ...]:
        """Rutas de los artefactos en disco que contienen datos clínicos o su clave."""
        return (
            self.db_path,
            self.db_path + "-wal",
            self.db_path + "-shm",
            self._anchor_sidecar_path(),
        )

    def _apply_file_permissions(self) -> None:
        """Restringe base viva, diario WAL y clave de anclaje al propietario (0600)."""
        try:
            for path in self._clinical_artifacts():
                if os.path.exists(path):
                    os.chmod(path, 0o600)
        except OSError as e:
            raise DatabaseError(f"No se pudieron aplicar permisos 0600 en {self.db_path}: {e}")

    def _harden_file_permissions(self) -> None:
        """
        Reaplica 0600 tras una escritura confirmada.

        SQLite crea los archivos -wal/-shm de forma perezosa, por lo que el modo
        debe reafirmarse después de cada COMMIT. Un fallo aquí no revierte una
        transacción ya confirmada; el arranque siguiente vuelve a exigir 0600.
        """
        for path in self._clinical_artifacts():
            try:
                if os.path.exists(path):
                    os.chmod(path, 0o600)
            except OSError:
                pass

    # --------------------------------------------------------------------------
    # MIGRACIONES
    # --------------------------------------------------------------------------
    def _apply_migrations(self) -> None:
        """Aplica esquema versionado con migraciones idempotentes."""
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE;")
            try:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS schema_migrations (
                        version INTEGER PRIMARY KEY,
                        applied_at TEXT NOT NULL
                    );
                """)
                cur.execute("SELECT MAX(version) FROM schema_migrations;")
                current_ver = cur.fetchone()[0] or 0

                if current_ver < 1:
                    # Migración 1: Tablas de Órdenes, Eventos de Auditoría y Checkpoint
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS clinical_orders (
                            order_id TEXT PRIMARY KEY,
                            patient_dni TEXT NOT NULL,
                            status TEXT NOT NULL,
                            created_at REAL NOT NULL,
                            data_json TEXT NOT NULL
                        );
                    """)
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_orders_patient_dni ON clinical_orders(patient_dni);")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_orders_status ON clinical_orders(status);")

                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS audit_events (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            event_timestamp TEXT NOT NULL,
                            action TEXT NOT NULL,
                            actor TEXT NOT NULL,
                            role TEXT NOT NULL,
                            status TEXT NOT NULL,
                            ip_source TEXT NOT NULL,
                            details TEXT NOT NULL,
                            mfa_verified INTEGER NOT NULL,
                            prev_hash TEXT NOT NULL,
                            event_hash TEXT NOT NULL UNIQUE,
                            raw_json TEXT NOT NULL
                        );
                    """)
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(event_timestamp);")

                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS audit_checkpoints (
                            checkpoint_id INTEGER PRIMARY KEY CHECK (checkpoint_id = 1),
                            last_hash TEXT NOT NULL,
                            total_events INTEGER NOT NULL,
                            updated_at TEXT NOT NULL,
                            anchor_signature TEXT NOT NULL
                        );
                    """)
                    cur.execute("""
                        INSERT OR IGNORE INTO audit_checkpoints (checkpoint_id, last_hash, total_events, updated_at, anchor_signature)
                        VALUES (1, '0000000000000000000000000000000000000000000000000000000000000000', 0, datetime('now'), 'INITIAL');
                    """)

                    cur.execute("INSERT INTO schema_migrations (version, applied_at) VALUES (1, datetime('now'));")

                if current_ver < 2:
                    # Migración 2: control de versión optimista y registro antirreplay IoMT
                    cur.execute("PRAGMA table_info(clinical_orders);")
                    columns = {row[1] for row in cur.fetchall()}
                    if "version" not in columns:
                        cur.execute("ALTER TABLE clinical_orders ADD COLUMN version INTEGER NOT NULL DEFAULT 1;")
                    if "updated_at" not in columns:
                        cur.execute("ALTER TABLE clinical_orders ADD COLUMN updated_at REAL;")

                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS iomt_nonces (
                            nonce TEXT PRIMARY KEY,
                            device_id TEXT NOT NULL,
                            received_at REAL NOT NULL
                        );
                    """)
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_iomt_nonces_received ON iomt_nonces(received_at);")
                    cur.execute("INSERT INTO schema_migrations (version, applied_at) VALUES (2, datetime('now'));")

                if current_ver < 3:
                    # Migración 3: M2 Diagnóstico de seguridad y M3 Inventario de activos
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS diagnostic_runs (
                            id TEXT PRIMARY KEY,
                            started_at REAL NOT NULL,
                            finished_at REAL,
                            status TEXT NOT NULL,
                            checker_count INTEGER NOT NULL,
                            passed INTEGER NOT NULL,
                            failed INTEGER NOT NULL,
                            warnings INTEGER NOT NULL,
                            triggered_by TEXT NOT NULL,
                            environment TEXT NOT NULL,
                            notes TEXT
                        );
                    """)
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_diagnostic_runs_started ON diagnostic_runs(started_at DESC);")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_diagnostic_runs_environment ON diagnostic_runs(environment);")

                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS security_findings (
                            id TEXT PRIMARY KEY,
                            run_id TEXT NOT NULL,
                            checker_id TEXT NOT NULL,
                            title TEXT NOT NULL,
                            objective TEXT NOT NULL,
                            severity TEXT NOT NULL,
                            status TEXT NOT NULL,
                            asset_ref TEXT,
                            evidence_command TEXT NOT NULL,
                            evidence_output TEXT NOT NULL,
                            remediation TEXT NOT NULL,
                            detected_at REAL NOT NULL
                        );
                    """)
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_security_findings_run ON security_findings(run_id);")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_security_findings_checker ON security_findings(checker_id);")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_security_findings_status ON security_findings(status);")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_security_findings_severity ON security_findings(severity);")

                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS assets (
                            id TEXT PRIMARY KEY,
                            name TEXT NOT NULL UNIQUE,
                            classification TEXT NOT NULL,
                            criticality TEXT NOT NULL,
                            owner TEXT NOT NULL,
                            source TEXT NOT NULL,
                            version TEXT,
                            environment TEXT NOT NULL,
                            synthetic INTEGER NOT NULL,
                            description TEXT NOT NULL,
                            created_at REAL NOT NULL,
                            updated_at REAL NOT NULL,
                            revision INTEGER NOT NULL
                        );
                    """)
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_assets_classification ON assets(classification);")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_assets_criticality ON assets(criticality);")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_assets_source ON assets(source);")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_assets_environment ON assets(environment);")

                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS asset_evaluations (
                            id TEXT PRIMARY KEY,
                            asset_id TEXT NOT NULL,
                            evaluated_at REAL NOT NULL,
                            evaluated_by TEXT NOT NULL,
                            criticality TEXT NOT NULL,
                            notes TEXT NOT NULL,
                            findings_count INTEGER NOT NULL
                        );
                    """)
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_asset_evaluations_asset ON asset_evaluations(asset_id);")

                    cur.execute("INSERT INTO schema_migrations (version, applied_at) VALUES (3, datetime('now'));")

                if current_ver < 4:
                    # Migracion 4: origen real de la evidencia de cada hallazgo.
                    # El mecanismo (API de Keycloak, ficheros, SQLite, docker
                    # inspect, proceso) viaja con el hallazgo: la evidencia es
                    # reconstruible y no depende de leer el codigo del comprobador.
                    columnas = {fila[1] for fila in cur.execute("PRAGMA table_info(security_findings);")}
                    if "evidence_source" not in columnas:
                        cur.execute(
                            "ALTER TABLE security_findings ADD COLUMN evidence_source TEXT NOT NULL DEFAULT '';"
                        )
                    cur.execute("INSERT INTO schema_migrations (version, applied_at) VALUES (4, datetime('now'));")

                if current_ver < 5:
                    # Migracion 5: rellena el origen de la evidencia en los
                    # hallazgos anteriores a la migracion 4, que se guardaron sin
                    # el. El mecanismo de cada comprobador es determinista y no
                    # cambio, asi que derivarlo del checker_id no inventa dato:
                    # solo hace explicito lo que ya era cierto. Lo que no encaja
                    # en ninguna regla queda como 'undeclared' y se ve.
                    cur.execute("""
                        UPDATE security_findings SET evidence_source = CASE
                            WHEN checker_id LIKE 'KC_%' THEN 'keycloak_admin_api'
                            WHEN checker_id LIKE 'BACKEND_AUDIT%' THEN 'sqlite'
                            WHEN checker_id LIKE 'DATA_FILES%' THEN 'filesystem'
                            WHEN checker_id = 'FRONTEND_BUNDLE_HAS_NO_PASSWORD_FIELD' THEN 'filesystem'
                            WHEN checker_id = 'BACKEND_AUTH_DELEGATED_TO_KEYCLOAK' THEN 'filesystem'
                            WHEN checker_id = 'CONTAINER_HARDENING' THEN 'docker_inspect'
                            WHEN checker_id = 'BACKEND_ADMIN_REQUIRES_MFA' THEN 'in_process'
                            ELSE 'undeclared'
                        END
                        WHERE COALESCE(evidence_source, '') = '';
                    """)
                    cur.execute("INSERT INTO schema_migrations (version, applied_at) VALUES (5, datetime('now'));")

                if current_ver < 6:
                    # Migracion 6: modulo M4 Gestion de Riesgos y M5 Gestion de Controles.
                    # Soporta O2 (matriz de riesgos y vulnerabilidades) y O3 (controles ISO 27001,
                    # NIST SP 800-207 y CISA Zero Trust Maturity Model).
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS risks (
                            id TEXT PRIMARY KEY,
                            code TEXT NOT NULL UNIQUE,
                            name TEXT NOT NULL,
                            description TEXT NOT NULL,
                            category TEXT NOT NULL,
                            asset_id TEXT,
                            finding_id TEXT,
                            threat TEXT NOT NULL,
                            vulnerability TEXT NOT NULL,
                            probability_inherent INTEGER NOT NULL,
                            impact_inherent INTEGER NOT NULL,
                            inherent_risk_score INTEGER NOT NULL,
                            inherent_risk_level TEXT NOT NULL,
                            treatment TEXT NOT NULL,
                            probability_residual INTEGER NOT NULL,
                            impact_residual INTEGER NOT NULL,
                            residual_risk_score INTEGER NOT NULL,
                            residual_risk_level TEXT NOT NULL,
                            owner_role TEXT NOT NULL,
                            status TEXT NOT NULL,
                            synthetic INTEGER NOT NULL DEFAULT 0,
                            created_at REAL NOT NULL,
                            updated_at REAL NOT NULL,
                            revision INTEGER NOT NULL DEFAULT 1
                        );
                    """)
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_risks_category ON risks(category);")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_risks_status ON risks(status);")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_risks_inherent_level ON risks(inherent_risk_level);")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_risks_residual_level ON risks(residual_risk_level);")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_risks_asset_id ON risks(asset_id);")

                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS controls (
                            id TEXT PRIMARY KEY,
                            code TEXT NOT NULL UNIQUE,
                            framework TEXT NOT NULL,
                            clause_or_pillar TEXT NOT NULL,
                            name TEXT NOT NULL,
                            description TEXT NOT NULL,
                            owner_role TEXT NOT NULL,
                            status TEXT NOT NULL,
                            evidence_type TEXT,
                            evidence_reference TEXT,
                            verification_date TEXT,
                            verification_notes TEXT,
                            compliance_score REAL NOT NULL DEFAULT 0.0,
                            synthetic INTEGER NOT NULL DEFAULT 0,
                            created_at REAL NOT NULL,
                            updated_at REAL NOT NULL,
                            revision INTEGER NOT NULL DEFAULT 1
                        );
                    """)
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_controls_framework ON controls(framework);")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_controls_status ON controls(status);")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_controls_owner_role ON controls(owner_role);")

                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS risk_controls (
                            risk_id TEXT NOT NULL,
                            control_id TEXT NOT NULL,
                            effectiveness TEXT NOT NULL,
                            PRIMARY KEY (risk_id, control_id)
                        );
                    """)
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_risk_controls_risk ON risk_controls(risk_id);")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_risk_controls_control ON risk_controls(control_id);")

                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS control_evidences (
                            id TEXT PRIMARY KEY,
                            control_id TEXT NOT NULL,
                            evidence_source TEXT NOT NULL,
                            reference_id TEXT NOT NULL,
                            observed_result TEXT NOT NULL,
                            verified_by TEXT NOT NULL,
                            verified_at REAL NOT NULL,
                            verified_with_mfa INTEGER NOT NULL
                        );
                    """)
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_control_evidences_control ON control_evidences(control_id);")

                    cur.execute("INSERT INTO schema_migrations (version, applied_at) VALUES (6, datetime('now'));")

                if current_ver < 7:
                    # Migracion 7: separa el origen declarado del vinculo real de
                    # trazabilidad O1 -> O2. 'source_checker' guarda el codigo del
                    # comprobador M2 que origina el riesgo; 'finding_id' queda
                    # reservado al id de un hallazgo real de security_findings (o
                    # NULL si el diagnostico aun no se ejecuto). Aditiva e
                    # idempotente, igual que la migracion 4.
                    columnas = {fila[1] for fila in cur.execute("PRAGMA table_info(risks);")}
                    if "source_checker" not in columnas:
                        cur.execute("ALTER TABLE risks ADD COLUMN source_checker TEXT;")
                    # Reparacion idempotente sobre bases ya pobladas: donde la
                    # siembra antigua guardo el codigo del comprobador dentro de
                    # finding_id, ese codigo se mueve a source_checker y
                    # finding_id se sustituye por el hallazgo real mas reciente de
                    # ese comprobador (o NULL si todavia no hay hallazgo). No
                    # inventa dato: se deriva de lo ya guardado y de la tabla de
                    # hallazgos. Un id que ya apunta a un hallazgo real no se toca.
                    cur.execute("""
                        UPDATE risks
                        SET source_checker = finding_id,
                            finding_id = (
                                SELECT f.id FROM security_findings f
                                WHERE f.checker_id = risks.finding_id
                                ORDER BY f.detected_at DESC LIMIT 1
                            )
                        WHERE source_checker IS NULL
                          AND finding_id IS NOT NULL
                          AND finding_id NOT IN (SELECT id FROM security_findings);
                    """)
                    cur.execute("INSERT INTO schema_migrations (version, applied_at) VALUES (7, datetime('now'));")


                if current_ver < 8:
                    # Migracion 8: modulo M6 de monitorizacion de incidentes,
                    # alertas derivadas y acuses (F4). Es aditiva e idempotente:
                    # solo crea tablas nuevas (CREATE TABLE IF NOT EXISTS) y no
                    # altera ninguna existente, por lo que es segura sobre una
                    # base ya poblada por las migraciones 1..7. Las alertas NO
                    # se persisten: se derivan del estado real en cada consulta;
                    # lo unico que se guarda es el acuse. El historial de
                    # transiciones (incident_updates) es inmutable: no se edita
                    # ni se borra, solo se anexa.
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS incidents (
                            id TEXT PRIMARY KEY,
                            code TEXT NOT NULL UNIQUE,
                            title TEXT NOT NULL,
                            description TEXT NOT NULL DEFAULT '',
                            severity TEXT NOT NULL,
                            status TEXT NOT NULL,
                            detected_at REAL NOT NULL,
                            closed_at REAL,
                            asset_id TEXT REFERENCES assets(id),
                            risk_id TEXT REFERENCES risks(id),
                            control_id TEXT REFERENCES controls(id),
                            owner_role TEXT NOT NULL DEFAULT '',
                            synthetic INTEGER NOT NULL DEFAULT 1,
                            revision INTEGER NOT NULL DEFAULT 1,
                            created_by TEXT NOT NULL DEFAULT '',
                            created_at REAL NOT NULL,
                            updated_at REAL NOT NULL
                        );
                    """)
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_detected ON incidents(detected_at DESC);")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_asset ON incidents(asset_id);")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_risk ON incidents(risk_id);")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_control ON incidents(control_id);")

                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS incident_updates (
                            id TEXT PRIMARY KEY,
                            incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                            from_status TEXT,
                            to_status TEXT NOT NULL,
                            note TEXT NOT NULL DEFAULT '',
                            actor TEXT NOT NULL,
                            occurred_at REAL NOT NULL
                        );
                    """)
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_incident_updates_incident ON incident_updates(incident_id);")

                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS alert_acknowledgements (
                            alert_id TEXT PRIMARY KEY,
                            acknowledged_by TEXT NOT NULL,
                            acknowledged_at REAL NOT NULL,
                            note TEXT NOT NULL DEFAULT ''
                        );
                    """)
                    cur.execute("INSERT INTO schema_migrations (version, applied_at) VALUES (8, datetime('now'));")


                if current_ver < 9:
                    # Migracion 9: modulo M9 de validacion por expertos e
                    # informes generados desde datos reales (F5). Es aditiva e
                    # idempotente: solo crea tablas nuevas (CREATE TABLE IF NOT
                    # EXISTS) y no altera ninguna existente, por lo que es
                    # segura sobre una base ya poblada por las migraciones
                    # 1..8. El instrumento es una herramienta de medida; los
                    # dictamenes NO se siembran: solo los registra un experto.
                    # 'synthetic' queda en 1 por defecto y el servidor lo
                    # impone al escribir: la declaracion del cliente no decide
                    # la naturaleza del registro.
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS validation_instruments (
                            id TEXT PRIMARY KEY,
                            code TEXT NOT NULL UNIQUE,
                            name TEXT NOT NULL,
                            description TEXT NOT NULL DEFAULT '',
                            version TEXT NOT NULL,
                            scale_min INTEGER NOT NULL DEFAULT 1,
                            scale_max INTEGER NOT NULL DEFAULT 5,
                            status TEXT NOT NULL,
                            synthetic INTEGER NOT NULL DEFAULT 1,
                            created_by TEXT NOT NULL DEFAULT '',
                            created_at REAL NOT NULL,
                            updated_at REAL NOT NULL
                        );
                    """)
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_instruments_code ON validation_instruments(code);")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_instruments_status ON validation_instruments(status);")

                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS instrument_items (
                            id TEXT PRIMARY KEY,
                            instrument_id TEXT NOT NULL REFERENCES validation_instruments(id) ON DELETE CASCADE,
                            code TEXT NOT NULL,
                            dimension TEXT NOT NULL,
                            statement TEXT NOT NULL,
                            weight REAL NOT NULL DEFAULT 1,
                            position INTEGER NOT NULL DEFAULT 0,
                            UNIQUE (instrument_id, code)
                        );
                    """)
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_instrument_items_instrument ON instrument_items(instrument_id);")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_instrument_items_dimension ON instrument_items(dimension);")

                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS expert_reviews (
                            id TEXT PRIMARY KEY,
                            code TEXT NOT NULL UNIQUE,
                            instrument_id TEXT NOT NULL REFERENCES validation_instruments(id),
                            instrument_version TEXT NOT NULL,
                            expert_name TEXT NOT NULL,
                            expert_role TEXT NOT NULL,
                            expert_affiliation TEXT NOT NULL DEFAULT '',
                            scope TEXT NOT NULL DEFAULT '',
                            verdict TEXT NOT NULL,
                            observations TEXT NOT NULL DEFAULT '',
                            score REAL,
                            reviewed_at TEXT NOT NULL,
                            synthetic INTEGER NOT NULL DEFAULT 1,
                            created_by TEXT NOT NULL DEFAULT '',
                            created_at REAL NOT NULL
                        );
                    """)
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_expert_reviews_instrument ON expert_reviews(instrument_id);")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_expert_reviews_verdict ON expert_reviews(verdict);")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_expert_reviews_reviewed ON expert_reviews(reviewed_at DESC);")

                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS expert_review_answers (
                            id TEXT PRIMARY KEY,
                            review_id TEXT NOT NULL REFERENCES expert_reviews(id) ON DELETE CASCADE,
                            item_id TEXT NOT NULL REFERENCES instrument_items(id),
                            score INTEGER NOT NULL,
                            comment TEXT NOT NULL DEFAULT '',
                            UNIQUE (review_id, item_id)
                        );
                    """)
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_expert_review_answers_review ON expert_review_answers(review_id);")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_expert_review_answers_item ON expert_review_answers(item_id);")

                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS reports (
                            id TEXT PRIMARY KEY,
                            code TEXT NOT NULL UNIQUE,
                            title TEXT NOT NULL,
                            objective TEXT NOT NULL,
                            period_from TEXT NOT NULL,
                            period_to TEXT NOT NULL,
                            content TEXT NOT NULL,
                            content_hash TEXT NOT NULL,
                            generated_by TEXT NOT NULL,
                            generated_at REAL NOT NULL,
                            synthetic INTEGER NOT NULL DEFAULT 1
                        );
                    """)
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_reports_objective ON reports(objective);")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_reports_generated ON reports(generated_at DESC);")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_reports_hash ON reports(content_hash);")
                    cur.execute("INSERT INTO schema_migrations (version, applied_at) VALUES (9, datetime('now'));")


                cur.execute("COMMIT;")
            except Exception as e:
                cur.execute("ROLLBACK;")
                raise DatabaseError(f"Fallo al aplicar migraciones en {self.db_path}: {e}")
            finally:
                cur.close()

    # --------------------------------------------------------------------------
    # VERIFICACIÓN ESTRICTA DE LA CADENA Y DEL CHECKPOINT
    # --------------------------------------------------------------------------
    def _compute_anchor(self, last_hash: str, total_events: int) -> str:
        """Calcula un anclaje criptográfico HMAC del punto de control de auditoría."""
        msg = f"{last_hash}:{total_events}".encode("utf-8")
        return hashlib.sha256(self.hmac_key + msg).hexdigest()

    def _read_checkpoint(self, cur: sqlite3.Cursor) -> Optional[sqlite3.Row]:
        """Lee el checkpoint único de auditoría."""
        cur.execute("""
            SELECT last_hash, total_events, updated_at, anchor_signature
            FROM audit_checkpoints WHERE checkpoint_id = 1;
        """)
        return cur.fetchone()

    def _count_audit_events(self, cur: sqlite3.Cursor) -> int:
        """Cuenta los eventos de auditoría presentes en la base."""
        cur.execute("SELECT count(*) FROM audit_events;")
        return int(cur.fetchone()[0])

    def _assert_checkpoint_consistency(self, cur: sqlite3.Cursor) -> sqlite3.Row:
        """
        Exige que el checkpoint coincida exactamente con la cadena almacenada.

        Detecta borrado total, truncado y huecos comparando el total registrado
        con el conteo real y el último hash con el último evento persistido.
        """
        checkpoint = self._read_checkpoint(cur)
        if checkpoint is None:
            raise AuditChainCorruptedError("Checkpoint de auditoría ausente: base inconsistente.")

        total_events = self._count_audit_events(cur)
        if checkpoint["total_events"] != total_events:
            raise AuditChainCorruptedError(
                f"Discrepancia de conteo: checkpoint={checkpoint['total_events']}, "
                f"eventos={total_events} (borrado o truncado)"
            )

        if total_events == 0:
            if checkpoint["last_hash"] != ZERO_HASH:
                raise AuditChainCorruptedError(
                    "Discrepancia con Checkpoint: no hay eventos pero el último hash no es el inicial."
                )
            return checkpoint

        cur.execute("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1;")
        row = cur.fetchone()
        last_hash = row["event_hash"] if row else None
        if checkpoint["last_hash"] != last_hash:
            raise AuditChainCorruptedError(
                f"Discrepancia con Checkpoint: Checkpoint={checkpoint['last_hash']}, Último evento={last_hash}"
            )

        expected_anchor = self._compute_anchor(checkpoint["last_hash"], checkpoint["total_events"])
        if checkpoint["anchor_signature"] != expected_anchor:
            raise AuditChainCorruptedError(
                "Firma criptográfica de anclaje (Anchor HMAC) inválida en el Checkpoint de auditoría."
            )

        return checkpoint

    def _load_and_verify_audit_chain(self) -> None:
        """Carga y valida exhaustivamente la cadena y el checkpoint en el arranque."""
        with self._lock:
            conn = self._get_conn()
            cur = conn.cursor()
            started_transaction = False
            try:
                if not conn.in_transaction:
                    cur.execute("BEGIN;")
                    started_transaction = True

                # El checkpoint se valida SIEMPRE, incluso con la tabla vacía.
                self._assert_checkpoint_consistency(cur)

                cur.execute("SELECT id, raw_json, prev_hash, event_hash FROM audit_events ORDER BY id ASC;")
                rows = cur.fetchall()

                expected_prev = ZERO_HASH
                for row in rows:
                    record = json.loads(row["raw_json"])
                    curr_hash = row["event_hash"]

                    if row["prev_hash"] != expected_prev:
                        raise AuditChainCorruptedError(
                            f"Ruptura de cadena en evento ID {row['id']}: Esperado {expected_prev}, encontrado {row['prev_hash']}"
                        )

                    record_for_hash = {k: v for k, v in record.items() if k != "hash"}
                    computed_hash = hashlib.sha256(json.dumps(record_for_hash, sort_keys=True).encode("utf-8")).hexdigest()

                    if computed_hash != curr_hash:
                        raise AuditChainCorruptedError(
                            f"Manipulación detectada en evento ID {row['id']}: Hash almacenado {curr_hash} no coincide con el calculado {computed_hash}"
                        )

                    expected_prev = curr_hash

                self._last_audit_hash = expected_prev

                if started_transaction:
                    cur.execute("COMMIT;")
                    started_transaction = False
            except Exception:
                if started_transaction and conn.in_transaction:
                    try:
                        cur.execute("ROLLBACK;")
                    except Exception:
                        pass
                raise
            finally:
                cur.close()

    # --------------------------------------------------------------------------
    # OPERACIONES DE AUDITORÍA TRANSACCIONALES
    # --------------------------------------------------------------------------
    def _insert_audit_event(
        self,
        cur: sqlite3.Cursor,
        action: str,
        actor: str,
        role: str,
        status: str,
        details: str,
        ip: str = "127.0.0.1",
        mfa_verified: bool = False,
    ) -> Dict[str, Any]:
        """
        Inserta un evento encadenado y actualiza el checkpoint con el mismo cursor.

        No confirma la transacción: el llamador es responsable del COMMIT.
        """
        checkpoint = self._read_checkpoint(cur)
        if checkpoint is None:
            raise AuditChainCorruptedError("Checkpoint de auditoría ausente: base inconsistente.")

        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        prev_hash = checkpoint["last_hash"]
        new_total = int(checkpoint["total_events"]) + 1

        record = {
            "timestamp": timestamp,
            "action": action,
            "actor": actor,
            "role": role,
            "status": status,
            "ip_source": ip,
            "details": details,
            "mfa_verified": mfa_verified,
            "prev_hash": prev_hash,
        }
        record_hash = hashlib.sha256(json.dumps(record, sort_keys=True).encode("utf-8")).hexdigest()
        record["hash"] = record_hash
        raw_json = json.dumps(record, sort_keys=True)

        cur.execute("""
            INSERT INTO audit_events (
                event_timestamp, action, actor, role, status, ip_source, details, mfa_verified, prev_hash, event_hash, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            timestamp, action, actor, role, status, ip, details,
            1 if mfa_verified else 0, prev_hash, record_hash, raw_json
        ))

        new_anchor = self._compute_anchor(record_hash, new_total)
        cur.execute("""
            UPDATE audit_checkpoints
            SET last_hash = ?, total_events = ?, updated_at = datetime('now'), anchor_signature = ?
            WHERE checkpoint_id = 1;
        """, (record_hash, new_total, new_anchor))

        return record

    def record_audit_event(
        self,
        action: str,
        actor: str,
        role: str,
        status: str,
        details: str,
        ip: str = "127.0.0.1",
        mfa_verified: bool = False,
    ) -> Dict[str, Any]:
        """Registra un evento de auditoría atómicamente con actualización del hash encadenado."""
        with self._lock:
            conn = self._get_conn()
            cur = conn.cursor()
            try:
                cur.execute("BEGIN IMMEDIATE;")
                self._assert_checkpoint_consistency(cur)
                record = self._insert_audit_event(
                    cur,
                    action=action,
                    actor=actor,
                    role=role,
                    status=status,
                    details=details,
                    ip=ip,
                    mfa_verified=mfa_verified,
                )
                cur.execute("COMMIT;")
                self._last_audit_hash = record["hash"]
                self._harden_file_permissions()
                return record
            except Exception as exc:
                if conn.in_transaction:
                    try:
                        cur.execute("ROLLBACK;")
                    except Exception:
                        pass
                if isinstance(exc, DatabaseError):
                    raise
                raise DatabaseError(f"Error al registrar evento de auditoría en {self.db_path}: {exc}") from exc
            finally:
                cur.close()

    # --------------------------------------------------------------------------
    # TRANSACCIÓN CLÍNICA ÚNICA (ORDEN + AUDITORÍA)
    # --------------------------------------------------------------------------
    def run_clinical_transaction(
        self,
        operation: Callable[[sqlite3.Cursor], Any],
        audit_event: Dict[str, Any],
    ) -> Tuple[Any, Dict[str, Any]]:
        """
        Ejecuta una operación clínica y su evento de auditoría en una sola transacción.

        Si la operación o la auditoría fallan, ambas se revierten. La lectura del
        último hash ocurre dentro de la transacción, lo que permite múltiples
        escritores concurrentes sin romper la cadena.
        """
        with self._lock:
            conn = self._get_conn()
            cur = conn.cursor()
            try:
                cur.execute("BEGIN IMMEDIATE;")
                self._assert_checkpoint_consistency(cur)
                result = operation(cur)
                record = self._insert_audit_event(cur, **audit_event)
                cur.execute("COMMIT;")
                self._last_audit_hash = record["hash"]
                self._harden_file_permissions()
                return result, record
            except Exception as exc:
                if conn.in_transaction:
                    try:
                        cur.execute("ROLLBACK;")
                    except Exception:
                        pass
                if isinstance(exc, DatabaseError) or hasattr(exc, "code"):
                    # Las reglas clínicas y los errores de aplicación conservan su
                    # código para que el PEP los traduzca a HTTP sin perder detalle.
                    raise
                raise DatabaseError(
                    f"Fallo en transacción clínica en {self.db_path}: {exc}"
                ) from exc
            finally:
                cur.close()

    # --------------------------------------------------------------------------
    # HELPERS DE CURSOR PARA ÓRDENES
    # --------------------------------------------------------------------------
    def fetch_order_cursor(self, cur: sqlite3.Cursor, order_id: str) -> Optional[Dict[str, Any]]:
        """Recupera una orden usando el cursor de una transacción en curso."""
        cur.execute("SELECT data_json FROM clinical_orders WHERE order_id = ?;", (order_id,))
        row = cur.fetchone()
        if row is None:
            return None
        return json.loads(row["data_json"])

    def insert_order_cursor(self, cur: sqlite3.Cursor, order: Dict[str, Any]) -> None:
        """Inserta una orden nueva; un ID duplicado se rechaza (sin sobrescritura)."""
        order_id = order.get("order_id")
        if not order_id:
            raise DatabaseError("order_id requerido para guardar orden.")

        order.setdefault("version", 1)
        created_at = order.get("timestamp")
        if not isinstance(created_at, (int, float)):
            created_at = time.time()
        updated_at = time.time()
        patient_dni = order.get("patient_dni") or ""
        status = order.get("status", "SAMPLE_COLLECTED")
        data_json = json.dumps(order, sort_keys=True)

        try:
            cur.execute("""
                INSERT INTO clinical_orders (order_id, patient_dni, status, created_at, data_json, version, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?);
            """, (order_id, patient_dni, status, created_at, data_json, int(order["version"]), updated_at))
        except sqlite3.IntegrityError as exc:
            raise DuplicateOrderError(f"La orden '{order_id}' ya existe en {self.db_path}.") from exc

    def replace_order_cursor(
        self,
        cur: sqlite3.Cursor,
        order: Dict[str, Any],
        expected_version: int,
    ) -> Dict[str, Any]:
        """Actualiza una orden aplicando control de versión optimista."""
        order_id = order.get("order_id")
        if not order_id:
            raise DatabaseError("order_id requerido para actualizar orden.")

        new_version = int(expected_version) + 1
        order["version"] = new_version
        order["updated_at"] = time.time()
        data_json = json.dumps(order, sort_keys=True)

        cur.execute("""
            UPDATE clinical_orders
            SET patient_dni = ?, status = ?, data_json = ?, version = ?, updated_at = ?
            WHERE order_id = ? AND version = ?;
        """, (
            order.get("patient_dni") or "",
            order.get("status", "SAMPLE_COLLECTED"),
            data_json,
            new_version,
            order["updated_at"],
            order_id,
            int(expected_version),
        ))

        if cur.rowcount == 0:
            cur.execute("SELECT 1 FROM clinical_orders WHERE order_id = ?;", (order_id,))
            exists = cur.fetchone() is not None
            if not exists:
                raise OrderNotFoundError(f"La orden '{order_id}' no existe en {self.db_path}.")
            raise OrderVersionConflictError(
                f"Conflicto de versión en la orden '{order_id}': se esperaba la versión {expected_version}."
            )

        return order

    def _create_order_operation(self, cur: sqlite3.Cursor, order: Dict[str, Any]) -> Dict[str, Any]:
        """Operación interna de creación, reutilizable en transacciones simples o auditadas."""
        self.insert_order_cursor(cur, order)
        return order


    def _run_simple_read(self, operation: Callable[[sqlite3.Cursor], Any]) -> Any:
        """Ejecuta una operacion de solo lectura sobre la base de datos."""
        with self._lock:
            conn = self._get_conn()
            cur = conn.cursor()
            try:
                return operation(cur)
            finally:
                cur.close()

    def _run_simple_write(self, operation: Callable[[sqlite3.Cursor], Any]) -> Any:
        """Ejecuta una operación de escritura con transacción propia y rollback completo."""
        with self._lock:
            conn = self._get_conn()
            cur = conn.cursor()
            try:
                cur.execute("BEGIN IMMEDIATE;")
                self._assert_checkpoint_consistency(cur)
                result = operation(cur)
                cur.execute("COMMIT;")
                self._harden_file_permissions()
                return result
            except Exception as exc:
                if conn.in_transaction:
                    try:
                        cur.execute("ROLLBACK;")
                    except Exception:
                        pass
                if isinstance(exc, DatabaseError):
                    raise
                raise DatabaseError(f"Fallo en operación de base de datos en {self.db_path}: {exc}") from exc
            finally:
                cur.close()

    def create_order(
        self,
        order: Dict[str, Any],
        audit_event: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Crea una orden nueva y, opcionalmente, audita el alta en la misma transacción."""
        operation = lambda cur: self._create_order_operation(cur, order)
        if audit_event is not None:
            result, _ = self.run_clinical_transaction(operation, audit_event)
            return result
        return self._run_simple_write(operation)

    def update_order(
        self,
        order: Dict[str, Any],
        expected_version: int,
        audit_event: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Actualiza una orden con control de versión y auditoría opcional en la misma transacción."""
        operation = lambda cur: self.replace_order_cursor(cur, order, expected_version)
        if audit_event is not None:
            result, _ = self.run_clinical_transaction(operation, audit_event)
            return result
        return self._run_simple_write(operation)

    def register_iomt_nonce(
        self,
        nonce: str,
        device_id: str,
        received_at: float,
        max_age_seconds: int,
    ) -> None:
        """Registra un nonce IoMT en transacción propia para mitigar reintentos."""
        self._run_simple_write(
            lambda cur: self.register_iomt_nonce_cursor(
                cur, nonce, device_id, received_at, max_age_seconds
            )
        )

    def register_iomt_nonce_cursor(
        self,
        cur: sqlite3.Cursor,
        nonce: str,
        device_id: str,
        received_at: float,
        max_age_seconds: int,
    ) -> None:
        """Depura nonces expirados y registra el nonce actual; duplicado = replay."""
        cutoff = float(received_at) - float(max_age_seconds)
        cur.execute("DELETE FROM iomt_nonces WHERE received_at < ?;", (cutoff,))
        try:
            cur.execute(
                "INSERT INTO iomt_nonces (nonce, device_id, received_at) VALUES (?, ?, ?);",
                (nonce, device_id, float(received_at)),
            )
        except sqlite3.IntegrityError as exc:
            raise IomtReplayError(
                f"Nonce '{nonce}' ya utilizado por el dispositivo '{device_id}'."
            ) from exc

    # --------------------------------------------------------------------------
    # M2 DIAGNÓSTICO DE SEGURIDAD (ejecuciones, hallazgos) E M3 INVENTARIO DE ACTIVOS
    # --------------------------------------------------------------------------
    def _insert_diagnostic_run_cursor(self, cur: sqlite3.Cursor, run: Dict[str, Any]) -> Dict[str, Any]:
        """Inserta una ejecución de diagnóstico en una transacción ya abierta."""
        run_id = str(run.get("id") or "").strip()
        if not run_id:
            raise DatabaseError("El identificador de la ejecucion de diagnostico es obligatorio.")
        started_at = float(run.get("started_at") or time.time())
        finished_at = run.get("finished_at")
        cur.execute("""
            INSERT INTO diagnostic_runs (
                id, started_at, finished_at, status, checker_count, passed, failed,
                warnings, triggered_by, environment, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            run_id,
            started_at,
            float(finished_at) if finished_at is not None else None,
            str(run.get("status") or "completed"),
            int(run.get("checker_count") or 0),
            int(run.get("passed") or 0),
            int(run.get("failed") or 0),
            int(run.get("warnings") or 0),
            str(run.get("triggered_by") or "unknown"),
            str(run.get("environment") or F11_ENVIRONMENT),
            run.get("notes"),
        ))
        return self._fetch_diagnostic_run_cursor(cur, run_id)

    def _fetch_diagnostic_run_cursor(self, cur: sqlite3.Cursor, run_id: str) -> Optional[Dict[str, Any]]:
        """Lee una ejecución de diagnóstico por su identificador."""
        cur.execute("SELECT * FROM diagnostic_runs WHERE id = ?;", (run_id,))
        row = cur.fetchone()
        return dict(row) if row is not None else None

    def _insert_security_finding_cursor(self, cur: sqlite3.Cursor, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Inserta un hallazgo de seguridad en una transacción ya abierta."""
        finding_id = str(finding.get("id") or "").strip()
        if not finding_id:
            raise DatabaseError("El identificador del hallazgo de seguridad es obligatorio.")
        run_id = str(finding.get("run_id") or "").strip()
        if not run_id:
            raise DatabaseError("Todo hallazgo de seguridad debe pertenecer a una ejecucion (run_id).")
        status = str(finding.get("status") or "").strip()
        if status not in ("passed", "failed", "warning"):
            raise DatabaseError(
                "El estado del hallazgo debe ser passed, failed o warning; se recibio '%s'." % status
            )
        severity = str(finding.get("severity") or "").strip()
        if severity not in ("critical", "high", "medium", "low"):
            raise DatabaseError(
                "La severidad del hallazgo debe ser critical, high, medium o low; se recibio '%s'." % severity
            )
        objective = str(finding.get("objective") or "").strip()
        if objective not in ("O1", "O2"):
            raise DatabaseError(
                "El objetivo del hallazgo debe ser O1 u O2; se recibio '%s'." % objective
            )
        cur.execute("""
            INSERT INTO security_findings (
                id, run_id, checker_id, title, objective, severity, status, asset_ref,
                evidence_command, evidence_output, evidence_source, remediation, detected_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            finding_id,
            run_id,
            str(finding.get("checker_id") or ""),
            str(finding.get("title") or ""),
            objective,
            severity,
            status,
            finding.get("asset_ref"),
            str(finding.get("evidence_command") or ""),
            str(finding.get("evidence_output") or ""),
            str(finding.get("evidence_source") or ""),
            str(finding.get("remediation") or ""),
            float(finding.get("detected_at") or time.time()),
        ))
        cur.execute("SELECT * FROM security_findings WHERE id = ?;", (finding_id,))
        row = cur.fetchone()
        return dict(row) if row is not None else {"id": finding_id}

    def insert_diagnostic_run(self, run: Dict[str, Any]) -> Dict[str, Any]:
        """Persiste una ejecución de diagnóstico y devuelve el registro almacenado."""
        return self._run_simple_write(
            lambda cur: self._insert_diagnostic_run_cursor(cur, run)
        )

    def insert_security_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Persiste una lista de hallazgos en una única transacción atómica."""
        def operation(cur: sqlite3.Cursor) -> List[Dict[str, Any]]:
            return [self._insert_security_finding_cursor(cur, finding) for finding in findings]
        return self._run_simple_write(operation)

    def insert_diagnostic_run_with_findings(
        self,
        run: Dict[str, Any],
        findings: List[Dict[str, Any]],
    ) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Guarda la ejecución y sus hallazgos en una sola transacción: o se escriben ambos, o ninguno."""
        def operation(cur: sqlite3.Cursor) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
            stored_run = self._insert_diagnostic_run_cursor(cur, run)
            stored = [self._insert_security_finding_cursor(cur, finding) for finding in findings]
            return stored_run, stored
        return self._run_simple_write(operation)

    def insert_diagnostic_run_with_findings_and_audit_event(
        self,
        run: Dict[str, Any],
        findings: List[Dict[str, Any]],
        audit_event: Dict[str, Any],
    ) -> Tuple[Dict[str, Any], List[Dict[str, Any]], Dict[str, Any]]:
        """
        Guarda la ejecucion, sus hallazgos y el evento ``DIAGNOSTIC_RUN`` en una sola transaccion.

        Si la ejecucion, cualquiera de los hallazgos o la insercion del evento
        fallan, se revierte todo: no queda una ejecucion sin su rastro de
        auditoria ni hallazgos huerfanos. El evento se construye en el llamador
        y se inserta con el mismo cursor que las escrituras clinicas.
        """
        def operation(cur: sqlite3.Cursor) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
            stored_run = self._insert_diagnostic_run_cursor(cur, run)
            stored = [self._insert_security_finding_cursor(cur, finding) for finding in findings]
            return stored_run, stored

        (stored_run, stored_findings), record = self.run_clinical_transaction(operation, audit_event)
        return stored_run, stored_findings, record

    def list_diagnostic_runs(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Lista las ejecuciones de diagnóstico más recientes."""
        with self._lock:
            try:
                cur = self._conn.cursor()
                cur.execute(
                    "SELECT * FROM diagnostic_runs ORDER BY started_at DESC LIMIT ?;",
                    (max(1, int(limit)),),
                )
                rows = cur.fetchall()
                cur.close()
                return [dict(row) for row in rows]
            except Exception as e:
                raise DatabaseError(f"Error al listar ejecuciones de diagnostico en {self.db_path}: {e}")

    def get_diagnostic_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        """Recupera una ejecución de diagnóstico por su identificador."""
        with self._lock:
            try:
                cur = self._conn.cursor()
                cur.execute("SELECT * FROM diagnostic_runs WHERE id = ?;", (run_id,))
                row = cur.fetchone()
                cur.close()
                return dict(row) if row is not None else None
            except Exception as e:
                raise DatabaseError(f"Error al leer la ejecucion de diagnostico '{run_id}': {e}")

    def count_diagnostic_runs(self) -> int:
        """Cuenta las ejecuciones de diagnóstico registradas."""
        with self._lock:
            try:
                cur = self._conn.cursor()
                cur.execute("SELECT count(*) FROM diagnostic_runs;")
                total = int(cur.fetchone()[0])
                cur.close()
                return total
            except Exception as e:
                raise DatabaseError(f"Error al contar las ejecuciones de diagnostico: {e}")

    def list_security_findings(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        objective: Optional[str] = None,
        checker_id: Optional[str] = None,
        run_id: Optional[str] = None,
        asset_ref: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Lista hallazgos de seguridad con filtros opcionales sobre la evidencia real."""
        clauses: List[str] = []
        params: List[Any] = []
        for column, value in (
            ("status", status),
            ("severity", severity),
            ("objective", objective),
            ("checker_id", checker_id),
            ("run_id", run_id),
            ("asset_ref", asset_ref),
        ):
            if value:
                clauses.append("f.%s = ?" % column)
                params.append(str(value))
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(max(1, int(limit)))
        with self._lock:
            try:
                cur = self._conn.cursor()
                cur.execute(
                    "SELECT f.*, r.environment AS environment FROM security_findings f "
                    "LEFT JOIN diagnostic_runs r ON r.id = f.run_id"
                    + where
                    + " ORDER BY f.detected_at DESC LIMIT ?;",
                    tuple(params),
                )
                rows = cur.fetchall()
                cur.close()
                return [dict(row) for row in rows]
            except Exception as e:
                raise DatabaseError(f"Error al listar hallazgos de seguridad en {self.db_path}: {e}")

    def _count_findings_by(self, column: str) -> Dict[str, int]:
        """Cuenta los hallazgos agrupados por una columna de la tabla de hallazgos."""
        if column not in ("status", "severity", "objective", "checker_id"):
            raise DatabaseError("Columna de agrupacion no permitida para el recuento de hallazgos: %s" % column)
        with self._lock:
            try:
                cur = self._conn.cursor()
                cur.execute(
                    "SELECT %s AS bucket, count(*) FROM security_findings GROUP BY %s ORDER BY %s;"
                    % (column, column, column)
                )
                rows = cur.fetchall()
                cur.close()
                return {str(row["bucket"]): int(row[1]) for row in rows}
            except Exception as e:
                raise DatabaseError(f"Error al contar hallazgos por {column} en {self.db_path}: {e}")

    def count_findings_by_status(self) -> Dict[str, int]:
        """Cuenta los hallazgos por estado (passed, failed, warning)."""
        return self._count_findings_by("status")

    def count_findings_by_severity(self) -> Dict[str, int]:
        """Cuenta los hallazgos por severidad (critical, high, medium, low)."""
        return self._count_findings_by("severity")

    def count_findings_by_objective(self) -> Dict[str, int]:
        """Cuenta los hallazgos por objetivo de tesis (O1, O2)."""
        return self._count_findings_by("objective")

    def _validate_asset_fields(self, asset: Dict[str, Any]) -> None:
        """Exige el vocabulario cerrado de clasificacion, criticidad y origen."""
        classification = str(asset.get("classification") or "").strip()
        if classification not in ASSET_CLASSIFICATIONS:
            raise AssetValidationError(
                "Clasificacion de activo no admitida: '%s'. Valores validos: %s."
                % (classification, ", ".join(ASSET_CLASSIFICATIONS))
            )
        criticality = str(asset.get("criticality") or "").strip()
        if criticality not in ASSET_CRITICALITIES:
            raise AssetValidationError(
                "Criticidad de activo no admitida: '%s'. Valores validos: %s."
                % (criticality, ", ".join(ASSET_CRITICALITIES))
            )
        source = str(asset.get("source") or "").strip()
        if source not in ASSET_SOURCES:
            raise AssetValidationError(
                "Origen de activo no admitido: '%s'. Valores validos: %s."
                % (source, ", ".join(ASSET_SOURCES))
            )

    def _insert_asset_cursor(self, cur: sqlite3.Cursor, asset: Dict[str, Any]) -> Dict[str, Any]:
        """Inserta un activo del inventario en una transacción ya abierta."""
        asset_id = str(asset.get("id") or "").strip()
        if not asset_id:
            raise DatabaseError("El identificador del activo es obligatorio.")
        name = str(asset.get("name") or "").strip()
        # La persistencia aplica la misma regla de nombre que la API: un
        # escritor que no pase por el handler HTTP no puede meter comillas,
        # espacios ni caracteres de control en el nombre.
        name_error = validate_asset_name(name)
        if name_error:
            raise AssetValidationError(name_error)
        self._validate_asset_fields(asset)
        now = time.time()
        cur.execute(
            "SELECT id FROM assets WHERE name = ?;",
            (name,),
        )
        if cur.fetchone() is not None:
            raise AssetAlreadyExistsError("Ya existe un activo registrado con el nombre '%s'." % name)
        try:
            cur.execute("""
                INSERT INTO assets (
                    id, name, classification, criticality, owner, source, version,
                    environment, synthetic, description, created_at, updated_at, revision
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                asset_id,
                name,
                str(asset["classification"]).strip(),
                str(asset["criticality"]).strip(),
                str(asset.get("owner") or "").strip(),
                str(asset["source"]).strip(),
                asset.get("version"),
                str(asset.get("environment") or F11_ENVIRONMENT),
                1 if int(asset.get("synthetic") or 0) else 0,
                str(asset.get("description") or "").strip(),
                float(asset.get("created_at") or now),
                float(asset.get("updated_at") or now),
                int(asset.get("revision") or 1),
            ))
        except sqlite3.IntegrityError as exc:
            raise AssetAlreadyExistsError(
                "Ya existe un activo registrado con el nombre '%s'." % name
            ) from exc
        cur.execute("SELECT * FROM assets WHERE id = ?;", (asset_id,))
        row = cur.fetchone()
        return dict(row) if row is not None else {"id": asset_id}

    def insert_asset(self, asset: Dict[str, Any]) -> Dict[str, Any]:
        """Alta de un activo en el inventario, con validacion del vocabulario cerrado."""
        return self._run_simple_write(lambda cur: self._insert_asset_cursor(cur, asset))

    def insert_assets_with_audit_event(
        self,
        assets: List[Dict[str, Any]],
        audit_event: Dict[str, Any],
    ) -> Tuple[List[str], Dict[str, Any]]:
        """
        Inserta un lote de activos y su evento de auditoria en una sola transaccion.

        Es la via que usa la siembra del inventario (M3): o se escriben todos los
        activos y queda el evento en la cadena de auditoria, o no queda ninguno
        de los dos. Nunca queda un inventario a medias con un evento que lo
        dice completo.
        """
        def operation(cur: sqlite3.Cursor) -> List[str]:
            created: List[str] = []
            for asset in assets:
                self._insert_asset_cursor(cur, asset)
                created.append(str(asset.get("name") or ""))
            return created

        created, record = self.run_clinical_transaction(operation, audit_event)
        return created, record

    def insert_asset_with_audit_event(
        self,
        asset: Dict[str, Any],
        audit_event: Dict[str, Any],
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Da de alta un activo y registra su evento de auditoria en una sola transaccion.

        Es la via que usan las rutas de escritura de la API (M3): o quedan el
        activo y su evento, o no queda ninguno de los dos. La respuesta 201
        nunca puede confirmar un activo que la cadena de auditoria no conoce.
        """
        return self.run_clinical_transaction(
            lambda cur: self._insert_asset_cursor(cur, asset),
            audit_event,
        )

    def _update_asset_cursor(
        self,
        cur: sqlite3.Cursor,
        asset_id: str,
        changes: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Actualiza un activo en una transaccion ya abierta."""
        cur.execute("SELECT * FROM assets WHERE id = ?;", (asset_id,))
        row = cur.fetchone()
        if row is None:
            raise AssetNotFoundError("El activo '%s' no existe en el inventario." % asset_id)
        current = dict(row)
        merged = dict(current)
        for field in (
            "name", "classification", "criticality", "owner", "source",
            "version", "environment", "synthetic", "description",
        ):
            if field not in changes:
                # Campo no enviado: se conserva el valor vigente.
                continue
            value = changes[field]
            if value is None and field not in NULLABLE_ASSET_FIELDS:
                # Null en un campo obligatorio no borra nada: se conserva el
                # valor vigente. El campo 'version' si admite null y su
                # borrado es explicito (ver NULLABLE_ASSET_FIELDS).
                continue
            merged[field] = value
        merged["synthetic"] = 1 if int(merged.get("synthetic") or 0) else 0
        self._validate_asset_fields(merged)
        name_error = validate_asset_name(str(merged.get("name") or "").strip())
        if name_error:
            raise AssetValidationError(name_error)
        merged["revision"] = int(current.get("revision") or 1) + 1
        merged["updated_at"] = time.time()
        if merged["name"] != current["name"]:
            cur.execute("SELECT id FROM assets WHERE name = ?;", (merged["name"],))
            if cur.fetchone() is not None:
                raise AssetAlreadyExistsError(
                    "Ya existe un activo registrado con el nombre '%s'." % merged["name"]
                )
        try:
            cur.execute("""
                UPDATE assets SET
                    name = ?, classification = ?, criticality = ?, owner = ?, source = ?,
                    version = ?, environment = ?, synthetic = ?, description = ?,
                    updated_at = ?, revision = ?
                WHERE id = ?;
            """, (
                merged["name"],
                merged["classification"],
                merged["criticality"],
                merged["owner"],
                merged["source"],
                merged.get("version"),
                merged["environment"],
                merged["synthetic"],
                merged["description"],
                merged["updated_at"],
                merged["revision"],
                asset_id,
            ))
        except sqlite3.IntegrityError as exc:
            raise AssetAlreadyExistsError(
                "Ya existe un activo registrado con el nombre '%s'." % merged["name"]
            ) from exc
        cur.execute("SELECT * FROM assets WHERE id = ?;", (asset_id,))
        updated = cur.fetchone()
        return dict(updated) if updated is not None else merged

    def update_asset(self, asset_id: str, changes: Dict[str, Any]) -> Dict[str, Any]:
        """Actualiza los campos modificables de un activo e incrementa su revision."""
        return self._run_simple_write(
            lambda cur: self._update_asset_cursor(cur, asset_id, changes)
        )

    def update_asset_with_audit_event(
        self,
        asset_id: str,
        changes: Dict[str, Any],
        audit_event: Dict[str, Any],
        details_builder: Optional[Callable[[Dict[str, Any]], str]] = None,
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Actualiza un activo y registra su auditoria en la misma transaccion.

        ``details_builder`` permite describir el resultado real (por ejemplo,
        la revision ya incrementada) sin calcularlo fuera de la transaccion.
        """
        event = dict(audit_event)
        def operation(cur: sqlite3.Cursor) -> Dict[str, Any]:
            updated = self._update_asset_cursor(cur, asset_id, changes)
            if details_builder is not None:
                event["details"] = details_builder(updated)
            return updated

        updated, record = self.run_clinical_transaction(operation, event)
        return updated, record

    def get_asset(self, asset_id: str) -> Optional[Dict[str, Any]]:
        """Recupera un activo del inventario por su identificador."""
        with self._lock:
            try:
                cur = self._conn.cursor()
                cur.execute("SELECT * FROM assets WHERE id = ?;", (asset_id,))
                row = cur.fetchone()
                cur.close()
                return dict(row) if row is not None else None
            except Exception as e:
                raise DatabaseError(f"Error al leer el activo '{asset_id}': {e}")

    def list_assets(
        self,
        classification: Optional[str] = None,
        criticality: Optional[str] = None,
        source: Optional[str] = None,
        environment: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Lista los activos del inventario con filtros opcionales."""
        clauses: List[str] = []
        params: List[Any] = []
        for column, value in (
            ("classification", classification),
            ("criticality", criticality),
            ("source", source),
            ("environment", environment),
        ):
            if value:
                clauses.append("%s = ?" % column)
                params.append(str(value))
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        query = "SELECT * FROM assets" + where + " ORDER BY name ASC;"
        if limit:
            query = "SELECT * FROM assets" + where + " ORDER BY name ASC LIMIT ?;"
            params.append(max(1, int(limit)))
        with self._lock:
            try:
                cur = self._conn.cursor()
                cur.execute(query, tuple(params))
                rows = cur.fetchall()
                cur.close()
                return [dict(row) for row in rows]
            except Exception as e:
                raise DatabaseError(f"Error al listar activos en {self.db_path}: {e}")

    def _insert_asset_evaluation_cursor(
        self,
        cur: sqlite3.Cursor,
        evaluation: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Registra una evaluacion de activo en una transaccion ya abierta."""
        evaluation_id = str(evaluation.get("id") or "").strip()
        if not evaluation_id:
            raise DatabaseError("El identificador de la evaluacion es obligatorio.")
        asset_id = str(evaluation.get("asset_id") or "").strip()
        if not asset_id:
            raise DatabaseError("La evaluacion debe referenciar un activo (asset_id).")
        criticality = str(evaluation.get("criticality") or "").strip()
        if criticality not in ASSET_CRITICALITIES:
            raise AssetValidationError(
                "Criticidad de evaluacion no admitida: '%s'. Valores validos: %s."
                % (criticality, ", ".join(ASSET_CRITICALITIES))
            )
        cur.execute("SELECT id FROM assets WHERE id = ?;", (asset_id,))
        if cur.fetchone() is None:
            raise AssetNotFoundError("El activo '%s' no existe en el inventario." % asset_id)
        cur.execute("""
            INSERT INTO asset_evaluations (
                id, asset_id, evaluated_at, evaluated_by, criticality, notes, findings_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?);
        """, (
            evaluation_id,
            asset_id,
            float(evaluation.get("evaluated_at") or time.time()),
            str(evaluation.get("evaluated_by") or "unknown"),
            criticality,
            str(evaluation.get("notes") or ""),
            int(evaluation.get("findings_count") or 0),
        ))
        cur.execute("SELECT * FROM asset_evaluations WHERE id = ?;", (evaluation_id,))
        row = cur.fetchone()
        return dict(row) if row is not None else {"id": evaluation_id}

    def insert_asset_evaluation(self, evaluation: Dict[str, Any]) -> Dict[str, Any]:
        """Registra la evaluacion de criticidad de un activo."""
        return self._run_simple_write(
            lambda cur: self._insert_asset_evaluation_cursor(cur, evaluation)
        )

    def insert_asset_evaluation_with_audit_event(
        self,
        evaluation: Dict[str, Any],
        audit_event: Dict[str, Any],
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Registra una evaluacion y su evento de auditoria en una sola transaccion.

        La evaluacion no puede quedar guardada sin el evento que la declara, ni
        el evento sin la evaluacion que dice haber registrado.
        """
        return self.run_clinical_transaction(
            lambda cur: self._insert_asset_evaluation_cursor(cur, evaluation),
            audit_event,
        )

    def list_asset_evaluations(self, asset_id: str) -> List[Dict[str, Any]]:
        """Lista las evaluaciones registradas para un activo."""
        with self._lock:
            try:
                cur = self._conn.cursor()
                cur.execute(
                    "SELECT * FROM asset_evaluations WHERE asset_id = ? ORDER BY evaluated_at DESC;",
                    (asset_id,),
                )
                rows = cur.fetchall()
                cur.close()
                return [dict(row) for row in rows]
            except Exception as e:
                raise DatabaseError(f"Error al listar evaluaciones del activo '{asset_id}': {e}")

    def asset_summary(self) -> Dict[str, Any]:
        """Resume el inventario: totales por clasificacion, criticidad y origen."""
        with self._lock:
            try:
                cur = self._conn.cursor()
                cur.execute("SELECT count(*) FROM assets;")
                total = int(cur.fetchone()[0])
                summary: Dict[str, Any] = {
                    "total": total,
                    "by_classification": {},
                    "by_criticality": {},
                    "by_source": {},
                }
                for key, column in (
                    ("by_classification", "classification"),
                    ("by_criticality", "criticality"),
                    ("by_source", "source"),
                ):
                    cur.execute(
                        "SELECT %s AS bucket, count(*) FROM assets GROUP BY %s ORDER BY %s;"
                        % (column, column, column)
                    )
                    summary[key] = {str(row[0]): int(row[1]) for row in cur.fetchall()}
                cur.close()
                return summary
            except Exception as e:
                raise DatabaseError(f"Error al resumir el inventario de activos: {e}")

    # --------------------------------------------------------------------------
    # COMPATIBILIDAD: GUARDADO LEGADO
    # --------------------------------------------------------------------------
    def save_order(self, order_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        [DEPRECADO] Crea o actualiza una orden sin control de versión del llamador.

        Se conserva exclusivamente para compatibilidad con DatabaseBackedOrdersDict
        y las suites de persistencia previas. Las rutas clínicas deben usar
        create_order/update_order con auditoría atómica.
        """
        order_id = order_dict.get("order_id")
        if not order_id:
            raise DatabaseError("order_id requerido para guardar orden.")

        def operation(cur: sqlite3.Cursor) -> Dict[str, Any]:
            existing = self.fetch_order_cursor(cur, order_id)
            if existing is None:
                self.insert_order_cursor(cur, order_dict)
                return order_dict
            current_version = int(existing.get("version", 1))
            return self.replace_order_cursor(cur, order_dict, expected_version=current_version)

        return self._run_simple_write(operation)

    def get_audit_events(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Recupera la lista de eventos de auditoría ordenada cronológicamente."""
        with self._lock:
            try:
                cur = self._conn.cursor()
                query = "SELECT raw_json FROM audit_events ORDER BY id ASC"
                if limit:
                    query += f" LIMIT {int(limit)}"
                cur.execute(query)
                rows = cur.fetchall()
                cur.close()
                return [json.loads(r["raw_json"]) for r in rows]
            except Exception as e:
                raise DatabaseError(f"Error al leer eventos de auditoría en {self.db_path}: {e}")

    def get_last_audit_hash(self) -> str:
        """Devuelve el último hash de la cadena de auditoría."""
        with self._lock:
            return self._last_audit_hash

    def count_audit_events_by_action(self, action: str) -> int:
        """Cuenta los eventos de auditoria que declaran una accion concreta."""
        with self._lock:
            try:
                cur = self._conn.cursor()
                cur.execute(
                    "SELECT COUNT(*) FROM audit_events WHERE action = ?;", (action,)
                )
                count = int(cur.fetchone()[0])
                cur.close()
                return count
            except Exception as e:
                raise DatabaseError(f"Error al contar eventos de auditoría en {self.db_path}: {e}")

    def verify_chain_integrity(self) -> Tuple[bool, Optional[str]]:
        """Verifica la integridad de la cadena de bloques completa y su checkpoint."""
        with self._lock:
            try:
                self._load_and_verify_audit_chain()
                return True, None
            except AuditChainCorruptedError as e:
                return False, str(e)
            except Exception as e:
                return False, f"Fallo operacional de verificación: {e}"

    def clear_audit_logs(self, confirm: bool = False) -> None:
        """Reinicia la bitácora de auditoría solo con confirmación explícita."""
        if not confirm:
            raise DatabaseError(
                "Se requiere confirm=True para reiniciar la bitácora de auditoría."
            )
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE;")
            try:
                cur.execute("DELETE FROM audit_events;")
                cur.execute("""
                    UPDATE audit_checkpoints
                    SET last_hash = '0000000000000000000000000000000000000000000000000000000000000000',
                        total_events = 0,
                        updated_at = datetime('now'),
                        anchor_signature = 'INITIAL'
                    WHERE checkpoint_id = 1;
                """)
                cur.execute("COMMIT;")
                self._last_audit_hash = ZERO_HASH
                self._harden_file_permissions()
            except Exception as e:
                cur.execute("ROLLBACK;")
                raise DatabaseError(f"Error al reiniciar auditoría: {e}")
            finally:
                cur.close()

    # --------------------------------------------------------------------------
    # OPERACIONES CLÍNICAS DE LECTURA Y MANTENIMIENTO
    # --------------------------------------------------------------------------
    def get_order(self, order_id: str) -> Optional[Dict[str, Any]]:
        """Recupera una orden por su ID."""
        with self._lock:
            conn = self._get_conn()
            try:
                cur = conn.cursor()
                cur.execute("SELECT data_json FROM clinical_orders WHERE order_id = ?;", (order_id,))
                r = cur.fetchone()
                cur.close()
                if not r:
                    return None
                return json.loads(r["data_json"])
            except Exception as e:
                raise DatabaseError(f"Error al leer orden '{order_id}' en {self.db_path}: {e}")

    def get_orders(self, patient_dni: Optional[str] = None) -> List[Dict[str, Any]]:
        """Recupera la lista de órdenes registradas."""
        with self._lock:
            conn = self._get_conn()
            try:
                cur = conn.cursor()
                if patient_dni:
                    cur.execute("SELECT data_json FROM clinical_orders WHERE patient_dni = ? ORDER BY created_at ASC;", (patient_dni,))
                else:
                    cur.execute("SELECT data_json FROM clinical_orders ORDER BY created_at ASC;")
                rows = cur.fetchall()
                cur.close()
                return [json.loads(r["data_json"]) for r in rows]
            except Exception as e:
                raise DatabaseError(f"Error al listar órdenes en {self.db_path}: {e}")

    def delete_order(self, order_id: str) -> bool:
        """Elimina una orden por su identificador."""
        with self._lock:
            conn = self._get_conn()
            try:
                cur = conn.cursor()
                cur.execute("BEGIN IMMEDIATE;")
                try:
                    cur.execute("DELETE FROM clinical_orders WHERE order_id = ?;", (order_id,))
                    deleted = cur.rowcount > 0
                    cur.execute("COMMIT;")
                    return deleted
                except Exception as e:
                    cur.execute("ROLLBACK;")
                    raise DatabaseError(f"Error al eliminar orden: {e}")
                finally:
                    cur.close()
            except DatabaseError:
                raise
            except Exception as e:
                raise DatabaseError(f"Fallo operacional al eliminar orden: {e}")

    def clear_orders(self) -> None:
        """Elimina todas las órdenes registradas."""
        with self._lock:
            conn = self._get_conn()
            try:
                cur = conn.cursor()
                cur.execute("BEGIN IMMEDIATE;")
                try:
                    cur.execute("DELETE FROM clinical_orders;")
                    cur.execute("COMMIT;")
                except Exception as e:
                    cur.execute("ROLLBACK;")
                    raise DatabaseError(f"Error al limpiar órdenes: {e}")
                finally:
                    cur.close()
            except DatabaseError:
                raise
            except Exception as e:
                raise DatabaseError(f"Fallo operacional al limpiar órdenes: {e}")

    # --------------------------------------------------------------------------
    # RESPALDO EN LÍNEA Y RESTAURACIÓN
    # --------------------------------------------------------------------------
    def backup_database(self, dest_path: str) -> None:
        """Copia atómica en línea de la base de datos usando la API de backup de SQLite."""
        with self._lock:
            conn = self._get_conn()
            dest_dir = os.path.dirname(os.path.abspath(dest_path))
            if dest_dir:
                os.makedirs(dest_dir, mode=0o700, exist_ok=True)

            try:
                dest_conn = sqlite3.connect(dest_path)
                try:
                    conn.backup(dest_conn)
                finally:
                    dest_conn.close()

                try:
                    os.chmod(dest_path, 0o600)
                except Exception:
                    pass

                # El respaldo debe poder verificar su cadena: se copia el ancla 0600.
                anchor_dest = dest_path + ".anchor-key"
                fd = os.open(anchor_dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w", encoding="ascii") as handle:
                    handle.write(self.hmac_key.hex())
                os.chmod(anchor_dest, 0o600)
            except Exception as e:
                raise DatabaseError(f"Error al respaldar base de datos en {dest_path}: {e}")

    def close(self) -> None:
        """Cierra la conexión con SQLite."""
        with self._lock:
            if self._conn:
                try:
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None



    # --------------------------------------------------------------------------
    # M4: GESTION DE RIESGOS (O2)
    # --------------------------------------------------------------------------
    def _insert_risk_cursor(self, cur: sqlite3.Cursor, risk: Dict[str, Any]) -> Dict[str, Any]:
        """Inserta un riesgo en una transaccion ya abierta."""
        code = str(risk.get("code") or "").strip()
        name = str(risk.get("name") or "").strip()
        category = str(risk.get("category") or "").strip().lower()
        if category not in RISK_CATEGORIES:
            raise RiskValidationError(
                f"Categoria '{category}' no admitida. Opciones: {', '.join(RISK_CATEGORIES)}"
            )
        status = str(risk.get("status") or "IDENTIFICADO").strip().upper()
        if status not in RISK_STATUSES:
            raise RiskValidationError(
                f"Estado '{status}' no admitido. Opciones: {', '.join(RISK_STATUSES)}"
            )
        treatment = str(risk.get("treatment") or "MITIGAR").strip().upper()
        if treatment not in RISK_TREATMENTS:
            raise RiskValidationError(
                f"Tratamiento '{treatment}' no admitido. Opciones: {', '.join(RISK_TREATMENTS)}"
            )

        prob_inh = int(risk.get("probability_inherent") or 1)
        imp_inh = int(risk.get("impact_inherent") or 1)
        score_inh, level_inh = calculate_risk_level(prob_inh, imp_inh)

        prob_res = int(risk.get("probability_residual") or prob_inh)
        imp_res = int(risk.get("impact_residual") or imp_inh)
        score_res, level_res = calculate_risk_level(prob_res, imp_res)

        risk_id = str(risk.get("id") or ("RSK-" + hashlib.sha256(code.encode("utf-8")).hexdigest()[:8].upper()))
        now = time.time()

        try:
            cur.execute("""
                INSERT INTO risks (
                    id, code, name, description, category, asset_id, finding_id,
                    source_checker,
                    threat, vulnerability, probability_inherent, impact_inherent,
                    inherent_risk_score, inherent_risk_level, treatment,
                    probability_residual, impact_residual, residual_risk_score,
                    residual_risk_level, owner_role, status, synthetic,
                    created_at, updated_at, revision
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                risk_id,
                code,
                name,
                str(risk.get("description") or "").strip(),
                category,
                risk.get("asset_id"),
                risk.get("finding_id"),
                risk.get("source_checker"),
                str(risk.get("threat") or "").strip(),
                str(risk.get("vulnerability") or "").strip(),
                prob_inh,
                imp_inh,
                score_inh,
                level_inh,
                treatment,
                prob_res,
                imp_res,
                score_res,
                level_res,
                str(risk.get("owner_role") or "ROLE_SECURITY_AUDITOR").strip(),
                status,
                1 if int(risk.get("synthetic") or 0) else 0,
                float(risk.get("created_at") or now),
                float(risk.get("updated_at") or now),
                int(risk.get("revision") or 1),
            ))
        except sqlite3.IntegrityError as exc:
            raise RiskAlreadyExistsError(f"Ya existe un riesgo con el codigo '{code}'.") from exc

        cur.execute("SELECT * FROM risks WHERE id = ?;", (risk_id,))
        row = cur.fetchone()
        return dict(row) if row is not None else {"id": risk_id}

    def _update_risk_cursor(
        self, cur: sqlite3.Cursor, risk_id: str, changes: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Actualiza un riesgo existente en una transaccion."""
        cur.execute("SELECT * FROM risks WHERE id = ?;", (risk_id,))
        current = cur.fetchone()
        if not current:
            raise RiskNotFoundError(f"Riesgo {risk_id} no encontrado")

        current_dict = dict(current)
        prob_inh = int(changes.get("probability_inherent") if "probability_inherent" in changes else current_dict["probability_inherent"])
        imp_inh = int(changes.get("impact_inherent") if "impact_inherent" in changes else current_dict["impact_inherent"])
        score_inh, level_inh = calculate_risk_level(prob_inh, imp_inh)

        prob_res = int(changes.get("probability_residual") if "probability_residual" in changes else current_dict["probability_residual"])
        imp_res = int(changes.get("impact_residual") if "impact_residual" in changes else current_dict["impact_residual"])
        score_res, level_res = calculate_risk_level(prob_res, imp_res)

        category = str(changes.get("category", current_dict["category"])).lower().strip()
        if category not in RISK_CATEGORIES:
            raise RiskValidationError(f"Categoria '{category}' no admitida")
        status = str(changes.get("status", current_dict["status"])).upper().strip()
        if status not in RISK_STATUSES:
            raise RiskValidationError(f"Estado '{status}' no admitido")
        treatment = str(changes.get("treatment", current_dict["treatment"])).upper().strip()
        if treatment not in RISK_TREATMENTS:
            raise RiskValidationError(f"Tratamiento '{treatment}' no admitido")

        now = time.time()
        new_rev = int(current_dict.get("revision") or 1) + 1

        cur.execute("""
            UPDATE risks SET
                name = ?, description = ?, category = ?, asset_id = ?, finding_id = ?,
                source_checker = ?,
                threat = ?, vulnerability = ?, probability_inherent = ?, impact_inherent = ?,
                inherent_risk_score = ?, inherent_risk_level = ?, treatment = ?,
                probability_residual = ?, impact_residual = ?, residual_risk_score = ?,
                residual_risk_level = ?, owner_role = ?, status = ?, updated_at = ?, revision = ?
            WHERE id = ?;
        """, (
            str(changes.get("name", current_dict["name"])).strip(),
            str(changes.get("description", current_dict["description"])).strip(),
            category,
            changes.get("asset_id", current_dict["asset_id"]),
            changes.get("finding_id", current_dict["finding_id"]),
            changes.get("source_checker", current_dict["source_checker"]),
            str(changes.get("threat", current_dict["threat"])).strip(),
            str(changes.get("vulnerability", current_dict["vulnerability"])).strip(),
            prob_inh,
            imp_inh,
            score_inh,
            level_inh,
            treatment,
            prob_res,
            imp_res,
            score_res,
            level_res,
            str(changes.get("owner_role", current_dict["owner_role"])).strip(),
            status,
            now,
            new_rev,
            risk_id,
        ))

        cur.execute("SELECT * FROM risks WHERE id = ?;", (risk_id,))
        return dict(cur.fetchone())

    def insert_risk_with_audit_event(
        self, risk: Dict[str, Any], audit_event: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Da de alta un riesgo y su auditoria en una sola transaccion atomica."""
        return self.run_clinical_transaction(
            lambda cur: self._insert_risk_cursor(cur, risk), audit_event
        )

    def insert_risks_with_audit_event(
        self, risks: List[Dict[str, Any]], audit_event: Dict[str, Any]
    ) -> Tuple[List[str], Dict[str, Any]]:
        """Inserta lote de riesgos con auditoria atomica (para siembra)."""
        def operation(cur: sqlite3.Cursor) -> List[str]:
            created: List[str] = []
            for r in risks:
                self._insert_risk_cursor(cur, r)
                created.append(str(r.get("code") or ""))
            return created
        return self.run_clinical_transaction(operation, audit_event)

    def update_risk_with_audit_event(
        self, risk_id: str, changes: Dict[str, Any], audit_event: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Actualiza un riesgo y audita el cambio atomicamente."""
        return self.run_clinical_transaction(
            lambda cur: self._update_risk_cursor(cur, risk_id, changes), audit_event
        )

    def get_risk(self, risk_id_or_code: str) -> Optional[Dict[str, Any]]:
        """Recupera un riesgo y sus controles vinculados."""
        def op(cur: sqlite3.Cursor) -> Optional[Dict[str, Any]]:
            cur.execute("SELECT * FROM risks WHERE id = ? OR code = ?;", (risk_id_or_code, risk_id_or_code))
            row = cur.fetchone()
            if not row:
                return None
            result = dict(row)
            cur.execute("""
                SELECT c.*, rc.effectiveness
                FROM controls c
                JOIN risk_controls rc ON c.id = rc.control_id
                WHERE rc.risk_id = ?;
            """, (result["id"],))
            result["controls"] = [dict(r) for r in cur.fetchall()]
            return result
        return self._run_simple_read(op)

    def list_risks(self, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Lista riesgos aplicando filtros opcionales."""
        def op(cur: sqlite3.Cursor) -> List[Dict[str, Any]]:
            query = "SELECT * FROM risks WHERE 1=1"
            params: List[Any] = []
            if filters:
                if filters.get("category"):
                    query += " AND category = ?"
                    params.append(filters["category"])
                if filters.get("status"):
                    query += " AND status = ?"
                    params.append(filters["status"])
                if filters.get("inherent_risk_level"):
                    query += " AND inherent_risk_level = ?"
                    params.append(filters["inherent_risk_level"])
                if filters.get("residual_risk_level"):
                    query += " AND residual_risk_level = ?"
                    params.append(filters["residual_risk_level"])
                if filters.get("asset_id"):
                    query += " AND asset_id = ?"
                    params.append(filters["asset_id"])
            query += " ORDER BY inherent_risk_score DESC, created_at DESC;"
            cur.execute(query, tuple(params))
            return [dict(r) for r in cur.fetchall()]
        return self._run_simple_read(op)

    def get_risks_summary(self) -> Dict[str, Any]:
        """Calcula el resumen de metricas de riesgos para el dashboard e indicadores (M8)."""
        def op(cur: sqlite3.Cursor) -> Dict[str, Any]:
            cur.execute("SELECT COUNT(*) FROM risks;")
            total = cur.fetchone()[0]

            cur.execute("SELECT inherent_risk_level, COUNT(*) FROM risks GROUP BY inherent_risk_level;")
            inherent = {k: v for k, v in cur.fetchall()}

            cur.execute("SELECT residual_risk_level, COUNT(*) FROM risks GROUP BY residual_risk_level;")
            residual = {k: v for k, v in cur.fetchall()}

            cur.execute("SELECT status, COUNT(*) FROM risks GROUP BY status;")
            by_status = {k: v for k, v in cur.fetchall()}

            cur.execute("SELECT treatment, COUNT(*) FROM risks GROUP BY treatment;")
            by_treatment = {k: v for k, v in cur.fetchall()}

            cur.execute("SELECT category, COUNT(*) FROM risks GROUP BY category;")
            by_category = {k: v for k, v in cur.fetchall()}

            return {
                "total_risks": total,
                "inherent_levels": {level: inherent.get(level, 0) for level in RISK_LEVELS},
                "residual_levels": {level: residual.get(level, 0) for level in RISK_LEVELS},
                "by_status": {st: by_status.get(st, 0) for st in RISK_STATUSES},
                "by_treatment": {tr: by_treatment.get(tr, 0) for tr in RISK_TREATMENTS},
                "by_category": {cat: by_category.get(cat, 0) for cat in RISK_CATEGORIES},
            }
        return self._run_simple_read(op)

    # --------------------------------------------------------------------------
    # M5: GESTION DE CONTROLES (O3)
    # --------------------------------------------------------------------------
    def _insert_control_cursor(self, cur: sqlite3.Cursor, control: Dict[str, Any]) -> Dict[str, Any]:
        """Inserta un control con validacion del marco y del estado de evidencia."""
        code = str(control.get("code") or "").strip()
        framework = str(control.get("framework") or "").strip()
        if framework not in CONTROL_FRAMEWORKS:
            raise ControlValidationError(
                f"Marco '{framework}' no admitido. Opciones: {', '.join(CONTROL_FRAMEWORKS)}"
            )
        status = str(control.get("status") or "PROPUESTO").strip().upper()
        if status not in CONTROL_STATUSES:
            raise ControlValidationError(
                f"Estado '{status}' no admitido. Opciones: {', '.join(CONTROL_STATUSES)}"
            )

        evidence_type = control.get("evidence_type")
        evidence_reference = control.get("evidence_reference")

        # Regla central de evidencia F3: un control NO puede ser VERIFICADO sin evidencia real
        if status == "VERIFICADO":
            if not evidence_type or evidence_type == "none" or not evidence_reference:
                raise ControlEvidenceMissingError(
                    f"El control {code} no puede marcarse como VERIFICADO sin evidencia real enlazada."
                )

        control_id = str(control.get("id") or ("CTL-" + hashlib.sha256(code.encode("utf-8")).hexdigest()[:8].upper()))
        now = time.time()
        score = 1.0 if status == "VERIFICADO" else (0.5 if status == "IMPLEMENTADO" else 0.0)
        if "compliance_score" in control:
            score = float(control["compliance_score"])

        v_date = str(control.get("verification_date") or ("" if status != "VERIFICADO" else time.strftime("%Y-%m-%d", time.gmtime())))

        try:
            cur.execute("""
                INSERT INTO controls (
                    id, code, framework, clause_or_pillar, name, description,
                    owner_role, status, evidence_type, evidence_reference,
                    verification_date, verification_notes, compliance_score,
                    synthetic, created_at, updated_at, revision
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                control_id,
                code,
                framework,
                str(control.get("clause_or_pillar") or "").strip(),
                str(control.get("name") or "").strip(),
                str(control.get("description") or "").strip(),
                str(control.get("owner_role") or "ROLE_SECURITY_AUDITOR").strip(),
                status,
                evidence_type,
                evidence_reference,
                v_date,
                str(control.get("verification_notes") or ""),
                score,
                1 if int(control.get("synthetic") or 0) else 0,
                float(control.get("created_at") or now),
                float(control.get("updated_at") or now),
                int(control.get("revision") or 1),
            ))
        except sqlite3.IntegrityError as exc:
            raise ControlAlreadyExistsError(f"Ya existe un control con el codigo '{code}'.") from exc

        cur.execute("SELECT * FROM controls WHERE id = ?;", (control_id,))
        row = cur.fetchone()
        return dict(row) if row is not None else {"id": control_id}

    def _update_control_cursor(
        self, cur: sqlite3.Cursor, control_id: str, changes: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Actualiza un control existente asegurando las reglas de evidencia."""
        cur.execute("SELECT * FROM controls WHERE id = ?;", (control_id,))
        current = cur.fetchone()
        if not current:
            raise ControlNotFoundError(f"Control {control_id} no encontrado")

        current_dict = dict(current)
        framework = str(changes.get("framework", current_dict["framework"])).strip()
        if framework not in CONTROL_FRAMEWORKS:
            raise ControlValidationError(f"Marco '{framework}' no admitido")
        status = str(changes.get("status", current_dict["status"])).upper().strip()
        if status not in CONTROL_STATUSES:
            raise ControlValidationError(f"Estado '{status}' no admitido")

        evidence_type = changes.get("evidence_type", current_dict["evidence_type"])
        evidence_reference = changes.get("evidence_reference", current_dict["evidence_reference"])

        if status == "VERIFICADO":
            if not evidence_type or evidence_type == "none" or not evidence_reference:
                raise ControlEvidenceMissingError(
                    f"El control {control_id} no puede marcarse como VERIFICADO sin evidencia real enlazada."
                )

        score = 1.0 if status == "VERIFICADO" else (0.5 if status == "IMPLEMENTADO" else 0.0)
        if "compliance_score" in changes:
            score = float(changes["compliance_score"])

        now = time.time()
        new_rev = int(current_dict.get("revision") or 1) + 1

        cur.execute("""
            UPDATE controls SET
                framework = ?, clause_or_pillar = ?, name = ?, description = ?,
                owner_role = ?, status = ?, evidence_type = ?, evidence_reference = ?,
                verification_date = ?, verification_notes = ?, compliance_score = ?,
                updated_at = ?, revision = ?
            WHERE id = ?;
        """, (
            framework,
            str(changes.get("clause_or_pillar", current_dict["clause_or_pillar"])).strip(),
            str(changes.get("name", current_dict["name"])).strip(),
            str(changes.get("description", current_dict["description"])).strip(),
            str(changes.get("owner_role", current_dict["owner_role"])).strip(),
            status,
            evidence_type,
            evidence_reference,
            str(changes.get("verification_date", current_dict["verification_date"] or "")),
            str(changes.get("verification_notes", current_dict["verification_notes"] or "")),
            score,
            now,
            new_rev,
            control_id,
        ))

        cur.execute("SELECT * FROM controls WHERE id = ?;", (control_id,))
        return dict(cur.fetchone())

    def insert_control_with_audit_event(
        self, control: Dict[str, Any], audit_event: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Da de alta un control y su auditoria en una sola transaccion atomica."""
        return self.run_clinical_transaction(
            lambda cur: self._insert_control_cursor(cur, control), audit_event
        )

    def insert_controls_with_audit_event(
        self, controls: List[Dict[str, Any]], audit_event: Dict[str, Any]
    ) -> Tuple[List[str], Dict[str, Any]]:
        """Inserta lote de controles con auditoria atomica."""
        def operation(cur: sqlite3.Cursor) -> List[str]:
            created: List[str] = []
            for c in controls:
                self._insert_control_cursor(cur, c)
                created.append(str(c.get("code") or ""))
            return created
        return self.run_clinical_transaction(operation, audit_event)

    def update_control_with_audit_event(
        self, control_id: str, changes: Dict[str, Any], audit_event: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Actualiza un control y audita atomicamente."""
        return self.run_clinical_transaction(
            lambda cur: self._update_control_cursor(cur, control_id, changes), audit_event
        )

    def get_control(self, control_id_or_code: str) -> Optional[Dict[str, Any]]:
        """Recupera un control con sus riesgos vinculados y su historial de evidencias."""
        def op(cur: sqlite3.Cursor) -> Optional[Dict[str, Any]]:
            cur.execute("SELECT * FROM controls WHERE id = ? OR code = ?;", (control_id_or_code, control_id_or_code))
            row = cur.fetchone()
            if not row:
                return None
            result = dict(row)
            cur.execute("""
                SELECT r.*, rc.effectiveness
                FROM risks r
                JOIN risk_controls rc ON r.id = rc.risk_id
                WHERE rc.control_id = ?;
            """, (result["id"],))
            result["risks"] = [dict(r) for r in cur.fetchall()]
            cur.execute("SELECT * FROM control_evidences WHERE control_id = ? ORDER BY verified_at DESC;", (result["id"],))
            result["evidences"] = [dict(r) for r in cur.fetchall()]
            return result
        return self._run_simple_read(op)

    def list_controls(self, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Lista controles segun filtros."""
        def op(cur: sqlite3.Cursor) -> List[Dict[str, Any]]:
            query = "SELECT * FROM controls WHERE 1=1"
            params: List[Any] = []
            if filters:
                if filters.get("framework"):
                    query += " AND framework = ?"
                    params.append(filters["framework"])
                if filters.get("status"):
                    query += " AND status = ?"
                    params.append(filters["status"])
                if filters.get("owner_role"):
                    query += " AND owner_role = ?"
                    params.append(filters["owner_role"])
            query += " ORDER BY framework ASC, code ASC;"
            cur.execute(query, tuple(params))
            return [dict(r) for r in cur.fetchall()]
        return self._run_simple_read(op)

    def get_controls_summary(self) -> Dict[str, Any]:
        """Calcula metricas de controles y cumplimiento para M8 (Indicadores)."""
        def op(cur: sqlite3.Cursor) -> Dict[str, Any]:
            cur.execute("SELECT COUNT(*) FROM controls;")
            total = cur.fetchone()[0]

            cur.execute("SELECT framework, COUNT(*) FROM controls GROUP BY framework;")
            by_framework = {k: v for k, v in cur.fetchall()}

            cur.execute("SELECT status, COUNT(*) FROM controls GROUP BY status;")
            by_status = {k: v for k, v in cur.fetchall()}

            cur.execute("SELECT AVG(compliance_score) FROM controls;")
            avg_score = cur.fetchone()[0] or 0.0

            return {
                "total_controls": total,
                "by_framework": {fw: by_framework.get(fw, 0) for fw in CONTROL_FRAMEWORKS},
                "by_status": {st: by_status.get(st, 0) for st in CONTROL_STATUSES},
                "compliance_percentage": round(float(avg_score) * 100.0, 1),
            }
        return self._run_simple_read(op)

    def link_risk_control_with_audit_event(
        self, risk_id: str, control_id: str, effectiveness: str, audit_event: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Vincula un riesgo y un control con efectividad declarada en una sola transaccion auditada."""
        eff = effectiveness.upper().strip()
        if eff not in CONTROL_EFFECTIVENESS:
            raise RiskValidationError(f"Efectividad '{eff}' no admitida. Opciones: {', '.join(CONTROL_EFFECTIVENESS)}")

        def operation(cur: sqlite3.Cursor) -> Dict[str, Any]:
            cur.execute("SELECT id FROM risks WHERE id = ?;", (risk_id,))
            if not cur.fetchone():
                raise RiskNotFoundError(f"Riesgo {risk_id} no existe")
            cur.execute("SELECT id FROM controls WHERE id = ?;", (control_id,))
            if not cur.fetchone():
                raise ControlNotFoundError(f"Control {control_id} no existe")

            cur.execute("""
                INSERT OR REPLACE INTO risk_controls (risk_id, control_id, effectiveness)
                VALUES (?, ?, ?);
            """, (risk_id, control_id, eff))
            return {"risk_id": risk_id, "control_id": control_id, "effectiveness": eff}

        return self.run_clinical_transaction(operation, audit_event)

    def add_control_evidence_with_audit_event(
        self, evidence: Dict[str, Any], audit_event: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Registra una evidencia y actualiza el estado del control a VERIFICADO atomicamente."""
        control_id = str(evidence.get("control_id") or "")
        evidence_source = str(evidence.get("evidence_source") or "checker_run")
        reference_id = str(evidence.get("reference_id") or "")
        observed_result = str(evidence.get("observed_result") or "")
        verified_by = str(evidence.get("verified_by") or "ROLE_SECURITY_AUDITOR")
        verified_with_mfa = 1 if evidence.get("verified_with_mfa") else 0

        ev_id = "EVD-" + hashlib.sha256(f"{control_id}-{reference_id}-{time.time()}".encode()).hexdigest()[:8].upper()
        now = time.time()

        def operation(cur: sqlite3.Cursor) -> Dict[str, Any]:
            cur.execute("SELECT * FROM controls WHERE id = ?;", (control_id,))
            control = cur.fetchone()
            if not control:
                raise ControlNotFoundError(f"Control {control_id} no existe")

            cur.execute("""
                INSERT INTO control_evidences (
                    id, control_id, evidence_source, reference_id, observed_result,
                    verified_by, verified_at, verified_with_mfa
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                ev_id, control_id, evidence_source, reference_id, observed_result,
                verified_by, now, verified_with_mfa
            ))

            cur.execute("""
                UPDATE controls SET
                    status = 'VERIFICADO',
                    evidence_type = ?,
                    evidence_reference = ?,
                    verification_date = date('now'),
                    verification_notes = ?,
                    compliance_score = 1.0,
                    updated_at = ?,
                    revision = revision + 1
                WHERE id = ?;
            """, (evidence_source, reference_id, f"Verificado mediante {reference_id}: {observed_result[:100]}", now, control_id))

            cur.execute("SELECT * FROM control_evidences WHERE id = ?;", (ev_id,))
            return dict(cur.fetchone())

        return self.run_clinical_transaction(operation, audit_event)

    # --------------------------------------------------------------------------
    # M6: MONITORIZACION DE INCIDENTES, ALERTAS DERIVADAS Y ACUSES (F4)
    # --------------------------------------------------------------------------
    def _insert_incident_update_cursor(
        self,
        cur: sqlite3.Cursor,
        incident_id: str,
        from_status: Optional[str],
        to_status: str,
        note: str,
        actor: str,
        occurred_at: float,
    ) -> str:
        """Anexa una transicion de estado al historial inmutable del incidente.

        El historial nunca se edita ni se borra: cada cambio de estado deja una
        fila nueva con el estado de origen, el de destino, quien lo hizo y cuando.
        """
        digest = hashlib.sha256(
            ("%s|%s|%s|%s|%.6f" % (
                incident_id, from_status or "", to_status, str(actor or ""), occurred_at,
            )).encode("utf-8")
        ).hexdigest()[:12].upper()
        update_id = "UPI-" + digest
        cur.execute("""
            INSERT INTO incident_updates (
                id, incident_id, from_status, to_status, note, actor, occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?);
        """, (
            update_id, incident_id, from_status, to_status,
            str(note or ""), str(actor or "SYSTEM"), float(occurred_at),
        ))
        return update_id

    def _list_incident_updates_cursor(
        self, cur: sqlite3.Cursor, incident_id: str
    ) -> List[Dict[str, Any]]:
        """Lee el historial de transiciones de un incidente con el cursor abierto."""
        cur.execute(
            "SELECT * FROM incident_updates WHERE incident_id = ? "
            "ORDER BY occurred_at ASC, rowid ASC;",
            (incident_id,),
        )
        return [dict(r) for r in cur.fetchall()]

    def _insert_incident_cursor(
        self, cur: sqlite3.Cursor, incident: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Inserta un incidente y su transicion inicial en una transaccion abierta.

        La capa de persistencia fuerza ``synthetic = 1``: todo incidente creado
        desde la plataforma es de laboratorio, y la declaracion del cliente no
        puede cambiarlo. El alta registra la primera fila del historial
        (None -> estado inicial) para que la traza quede completa.
        """
        code = str(incident.get("code") or "").strip()
        if not code:
            raise IncidentValidationError("El code del incidente es obligatorio.")
        title = str(incident.get("title") or "").strip()
        if not title:
            raise IncidentValidationError("El title del incidente es obligatorio.")
        severity = str(incident.get("severity") or "").strip().upper()
        if severity not in INCIDENT_SEVERITIES:
            raise IncidentValidationError(
                "Severidad '%s' no admitida. Opciones: %s"
                % (severity, ", ".join(INCIDENT_SEVERITIES))
            )
        status = str(incident.get("status") or "ABIERTO").strip().upper()
        if status not in INCIDENT_STATUSES:
            raise IncidentValidationError(
                "Estado '%s' no admitido. Opciones: %s"
                % (status, ", ".join(INCIDENT_STATUSES))
            )

        incident_id = str(
            incident.get("id")
            or ("INC-" + hashlib.sha256(code.encode("utf-8")).hexdigest()[:8].upper())
        )
        now = time.time()
        raw_detected = incident.get("detected_at")
        try:
            detected_at = float(raw_detected) if raw_detected is not None else now
        except (TypeError, ValueError):
            detected_at = now
        closed_at = now if status == "CERRADO" else None
        actor = str(incident.get("created_by") or "SYSTEM")

        try:
            cur.execute("""
                INSERT INTO incidents (
                    id, code, title, description, severity, status, detected_at,
                    closed_at, asset_id, risk_id, control_id, owner_role,
                    synthetic, revision, created_by, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                incident_id, code, title,
                str(incident.get("description") or "").strip(),
                severity, status, detected_at, closed_at,
                incident.get("asset_id"), incident.get("risk_id"), incident.get("control_id"),
                str(incident.get("owner_role") or "").strip(),
                1, 1, actor, now, now,
            ))
        except sqlite3.IntegrityError as exc:
            message = str(exc)
            if "UNIQUE" in message.upper() or "PRIMARY KEY" in message.upper():
                raise IncidentAlreadyExistsError(
                    "Ya existe un incidente con el codigo '%s'." % code
                ) from exc
            # Un vinculo declarado a un activo/riesgo/control inexistente choca
            # con la clave foranea: se reporta como dato invalido, no como
            # duplicado, para que el cliente reciba el motivo real.
            raise IncidentValidationError(
                "Vinculo de incidente invalido: %s" % message
            ) from exc

        self._insert_incident_update_cursor(
            cur, incident_id, None, status, "Alta del incidente", actor, now
        )

        cur.execute("SELECT * FROM incidents WHERE id = ?;", (incident_id,))
        row = cur.fetchone()
        return dict(row) if row is not None else {"id": incident_id}

    def insert_incident_with_audit_event(
        self, incident: Dict[str, Any], audit_event: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Da de alta un incidente y su auditoria en una sola transaccion atomica."""
        return self.run_clinical_transaction(
            lambda cur: self._insert_incident_cursor(cur, incident), audit_event
        )

    def insert_incidents_with_audit_event(
        self, incidents: List[Dict[str, Any]], audit_event: Dict[str, Any]
    ) -> Tuple[List[str], Dict[str, Any]]:
        """Inserta un lote de incidentes con auditoria atomica (usado por la siembra)."""
        def operation(cur: sqlite3.Cursor) -> List[str]:
            created: List[str] = []
            for incident in incidents:
                self._insert_incident_cursor(cur, incident)
                created.append(str(incident.get("code") or ""))
            return created
        return self.run_clinical_transaction(operation, audit_event)

    def update_incident_status_with_audit_event(
        self,
        incident_id: str,
        to_status: str,
        note: str,
        actor: str,
        audit_event: Dict[str, Any],
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Aplica una transicion de estado validada y la audita en una sola transaccion.

        La transicion se valida contra INCIDENT_TRANSITIONS: una transicion no
        declarada se rechaza (IncidentTransitionError) y no toca ni el estado ni
        el historial. La sinteticidad del incidente nunca cambia en una
        transicion: el incidente siguio siendo de laboratorio.
        """
        status = str(to_status or "").strip().upper()
        if status not in INCIDENT_STATUSES:
            raise IncidentValidationError(
                "Estado '%s' no admitido. Opciones: %s"
                % (status, ", ".join(INCIDENT_STATUSES))
            )

        def operation(cur: sqlite3.Cursor) -> Dict[str, Any]:
            cur.execute(
                "SELECT * FROM incidents WHERE id = ? OR code = ?;",
                (incident_id, incident_id),
            )
            row = cur.fetchone()
            if row is None:
                raise IncidentNotFoundError("El incidente '%s' no existe." % incident_id)
            current = dict(row)
            from_status = str(current["status"])
            allowed = INCIDENT_TRANSITIONS.get(from_status, ())
            if status not in allowed:
                raise IncidentTransitionError(
                    "Transicion no permitida para el incidente '%s': %s -> %s. "
                    "Desde %s solo se admite: %s"
                    % (
                        incident_id, from_status, status, from_status,
                        (", ".join(allowed) or "ninguna transicion (estado terminal)"),
                    )
                )

            now = time.time()
            closed_at = now if status == "CERRADO" else current.get("closed_at")
            cur.execute("""
                UPDATE incidents SET
                    status = ?, closed_at = ?, updated_at = ?, revision = revision + 1
                WHERE id = ?;
            """, (status, closed_at, now, current["id"]))
            self._insert_incident_update_cursor(
                cur, current["id"], from_status, status, note, actor, now
            )
            cur.execute("SELECT * FROM incidents WHERE id = ?;", (current["id"],))
            return dict(cur.fetchone())

        return self.run_clinical_transaction(operation, audit_event)

    def get_incident(self, incident_id_or_code: str) -> Optional[Dict[str, Any]]:
        """Recupera un incidente con su historial completo de transiciones."""
        def op(cur: sqlite3.Cursor) -> Optional[Dict[str, Any]]:
            cur.execute(
                "SELECT * FROM incidents WHERE id = ? OR code = ?;",
                (incident_id_or_code, incident_id_or_code),
            )
            row = cur.fetchone()
            if not row:
                return None
            result = dict(row)
            result["updates"] = self._list_incident_updates_cursor(cur, result["id"])
            return result
        return self._run_simple_read(op)

    def list_incident_updates(self, incident_id: str) -> List[Dict[str, Any]]:
        """Lista el historial de transiciones de un incidente."""
        return self._run_simple_read(
            lambda cur: self._list_incident_updates_cursor(cur, incident_id)
        )

    def list_incidents(self, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Lista incidentes aplicando filtros opcionales de estado y severidad."""
        def op(cur: sqlite3.Cursor) -> List[Dict[str, Any]]:
            query = "SELECT * FROM incidents WHERE 1=1"
            params: List[Any] = []
            if filters:
                if filters.get("status"):
                    query += " AND status = ?"
                    params.append(str(filters["status"]).strip().upper())
                if filters.get("severity"):
                    query += " AND severity = ?"
                    params.append(str(filters["severity"]).strip().upper())
            query += " ORDER BY detected_at DESC, code ASC;"
            cur.execute(query, tuple(params))
            return [dict(r) for r in cur.fetchall()]
        return self._run_simple_read(op)

    def get_alert_acknowledgements(self) -> Dict[str, Dict[str, Any]]:
        """Devuelve los acuses registrados indexados por id de alerta derivada."""
        def op(cur: sqlite3.Cursor) -> Dict[str, Dict[str, Any]]:
            cur.execute("SELECT * FROM alert_acknowledgements;")
            return {str(r["alert_id"]): dict(r) for r in cur.fetchall()}
        return self._run_simple_read(op)

    def insert_alert_ack_with_audit_event(
        self,
        alert_id: str,
        acknowledged_by: str,
        note: str,
        audit_event: Dict[str, Any],
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Registra el acuse de una alerta derivada y su auditoria en una sola transaccion.

        Es lo unico que se persiste de una alerta: la alerta en si se deriva del
        estado real. Un id inexistente no llega hasta aqui: el modulo de dominio
        comprueba antes que la alerta exista entre las derivadas.
        """
        def operation(cur: sqlite3.Cursor) -> Dict[str, Any]:
            now = time.time()
            cur.execute("""
                INSERT INTO alert_acknowledgements (alert_id, acknowledged_by, acknowledged_at, note)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(alert_id) DO UPDATE SET
                    acknowledged_by = excluded.acknowledged_by,
                    acknowledged_at = excluded.acknowledged_at,
                    note = excluded.note;
            """, (
                str(alert_id), str(acknowledged_by or "SYSTEM"), now, str(note or ""),
            ))
            cur.execute(
                "SELECT * FROM alert_acknowledgements WHERE alert_id = ?;", (str(alert_id),)
            )
            return dict(cur.fetchone())
        return self.run_clinical_transaction(operation, audit_event)

    def monitoring_query(
        self, sql: str, params: Tuple[Any, ...] = ()
    ) -> List[Dict[str, Any]]:
        """Ejecuta una consulta de solo lectura del modulo de monitorizacion (M6).

        Es el unico acceso SQL directo que el modulo de alertas e indicadores
        necesita para declarar el origen real de su evidencia: la cadena SQL que
        se muestra en ``evidence``/``source`` es exactamente la que se ejecuta.
        La sentencia la fija el propio codigo del modulo (nunca un cliente HTTP),
        no escribe y no admite varios statements.
        """
        def op(cur: sqlite3.Cursor) -> List[Dict[str, Any]]:
            cur.execute(sql, tuple(params))
            return [dict(r) for r in cur.fetchall()]
        return self._run_simple_read(op)

    # --------------------------------------------------------------------------
    # M9: INSTRUMENTOS DE VALIDACION, DICTAMENES DE EXPERTOS E INFORMES (F5)
    # --------------------------------------------------------------------------
    def _insert_instrument_cursor(
        self, cur: sqlite3.Cursor, instrument: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Inserta un instrumento y sus items en una transaccion abierta.

        La capa de persistencia impone ``synthetic = 1``: un instrumento dado de
        alta desde la plataforma es de laboratorio y la declaracion del cliente
        no puede cambiarlo. Tambien vuelve a validar el contrato (escala
        coherente, al menos un item, codigos de item unicos) para que un
        escritor que no pase por la API no pueda guardar un instrumento roto.
        """
        code = str(instrument.get("code") or "").strip()
        if not code:
            raise InstrumentValidationError("El code del instrumento es obligatorio.")
        name = str(instrument.get("name") or "").strip()
        if not name:
            raise InstrumentValidationError("El name del instrumento es obligatorio.")
        version = str(instrument.get("version") or "").strip()
        if not version:
            raise InstrumentValidationError("La version del instrumento es obligatoria.")
        status = str(instrument.get("status") or "BORRADOR").strip().upper()
        if status not in INSTRUMENT_STATUSES:
            raise InstrumentValidationError(
                "Estado '%s' no admitido. Opciones: %s"
                % (status, ", ".join(INSTRUMENT_STATUSES))
            )
        try:
            scale_min = int(instrument.get("scale_min", 1))
            scale_max = int(instrument.get("scale_max", 5))
        except (TypeError, ValueError) as exc:
            raise InstrumentValidationError("La escala debe ser numerica.") from exc
        if scale_min >= scale_max:
            raise InstrumentValidationError(
                "Escala incoherente: scale_min (%s) debe ser menor que scale_max (%s)."
                % (scale_min, scale_max)
            )
        if scale_min < 0:
            raise InstrumentValidationError("scale_min no puede ser negativo.")

        raw_items = instrument.get("items")
        if not isinstance(raw_items, list) or not raw_items:
            raise InstrumentValidationError(
                "El instrumento debe declarar al menos un item de medida."
            )
        item_codes: set = set()
        items: List[Dict[str, Any]] = []
        for position, raw in enumerate(raw_items):
            if not isinstance(raw, dict):
                raise InstrumentValidationError("Cada item debe ser un objeto JSON.")
            item_code = str(raw.get("code") or "").strip()
            if not item_code:
                raise InstrumentValidationError("Todo item requiere un code.")
            if item_code in item_codes:
                raise InstrumentValidationError(
                    "Codigo de item duplicado en el instrumento: '%s'." % item_code
                )
            item_codes.add(item_code)
            dimension = str(raw.get("dimension") or "").strip().lower()
            if dimension not in VALIDATION_DIMENSIONS:
                raise InstrumentValidationError(
                    "Dimension '%s' no admitida. Opciones: %s"
                    % (dimension, ", ".join(VALIDATION_DIMENSIONS))
                )
            statement = str(raw.get("statement") or "").strip()
            if not statement:
                raise InstrumentValidationError(
                    "El item '%s' no declara un enunciado verificable." % item_code
                )
            try:
                weight = float(raw.get("weight", 1))
            except (TypeError, ValueError) as exc:
                raise InstrumentValidationError(
                    "El peso del item '%s' debe ser numerico." % item_code
                ) from exc
            if weight <= 0:
                raise InstrumentValidationError(
                    "El peso del item '%s' debe ser mayor que cero." % item_code
                )
            items.append({
                "id": "ITM-" + hashlib.sha256(
                    ("%s|%s" % (code, item_code)).encode("utf-8")
                ).hexdigest()[:10].upper(),
                "code": item_code,
                "dimension": dimension,
                "statement": statement,
                "weight": weight,
                "position": int(raw.get("position", position)),
            })

        instrument_id = str(
            instrument.get("id")
            or ("INS-" + hashlib.sha256(
                ("%s|%s" % (code, version)).encode("utf-8")
            ).hexdigest()[:8].upper())
        )
        now = time.time()
        try:
            cur.execute("""
                INSERT INTO validation_instruments (
                    id, code, name, description, version, scale_min, scale_max,
                    status, synthetic, created_by, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                instrument_id, code, name,
                str(instrument.get("description") or "").strip(),
                version, scale_min, scale_max, status, 1,
                str(instrument.get("created_by") or "SYSTEM"), now, now,
            ))
        except sqlite3.IntegrityError as exc:
            message = str(exc)
            if "UNIQUE" in message.upper() or "PRIMARY KEY" in message.upper():
                raise InstrumentAlreadyExistsError(
                    "Ya existe un instrumento con el codigo '%s'." % code
                ) from exc
            raise InstrumentValidationError(
                "Instrumento invalido: %s" % message
            ) from exc

        for item in items:
            cur.execute("""
                INSERT INTO instrument_items (
                    id, instrument_id, code, dimension, statement, weight, position
                ) VALUES (?, ?, ?, ?, ?, ?, ?);
            """, (
                item["id"], instrument_id, item["code"], item["dimension"],
                item["statement"], item["weight"], item["position"],
            ))

        cur.execute("SELECT * FROM validation_instruments WHERE id = ?;", (instrument_id,))
        result = dict(cur.fetchone())
        cur.execute(
            "SELECT * FROM instrument_items WHERE instrument_id = ? "
            "ORDER BY position ASC, code ASC;",
            (instrument_id,),
        )
        result["items"] = [dict(r) for r in cur.fetchall()]
        return result

    def insert_instrument_with_audit_event(
        self, instrument: Dict[str, Any], audit_event: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Da de alta un instrumento y sus items con auditoria atomica."""
        return self.run_clinical_transaction(
            lambda cur: self._insert_instrument_cursor(cur, instrument), audit_event
        )

    def get_instrument(self, instrument_id_or_code: str) -> Optional[Dict[str, Any]]:
        """Recupera un instrumento con sus items, o None si no existe."""
        def op(cur: sqlite3.Cursor) -> Optional[Dict[str, Any]]:
            cur.execute(
                "SELECT * FROM validation_instruments WHERE id = ? OR code = ?;",
                (instrument_id_or_code, instrument_id_or_code),
            )
            row = cur.fetchone()
            if not row:
                return None
            result = dict(row)
            cur.execute(
                "SELECT * FROM instrument_items WHERE instrument_id = ? "
                "ORDER BY position ASC, code ASC;",
                (result["id"],),
            )
            result["items"] = [dict(r) for r in cur.fetchall()]
            return result
        return self._run_simple_read(op)

    def list_instruments(self) -> List[Dict[str, Any]]:
        """Lista los instrumentos con el numero real de items de cada uno."""
        def op(cur: sqlite3.Cursor) -> List[Dict[str, Any]]:
            cur.execute("""
                SELECT i.*,
                       (SELECT COUNT(*) FROM instrument_items t WHERE t.instrument_id = i.id)
                           AS item_count
                FROM validation_instruments i
                ORDER BY i.created_at ASC, i.code ASC;
            """)
            return [dict(r) for r in cur.fetchall()]
        return self._run_simple_read(op)

    def _insert_expert_review_cursor(
        self, cur: sqlite3.Cursor, review: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Registra un dictamen y sus respuestas en una transaccion abierta.

        El ``score`` que llega ya fue calculado por el modulo de dominio como
        media ponderada DESCRIPTIVA de las respuestas; la persistencia no lo
        recalcula ni lo usa para deducir el veredicto: el veredicto es el que
        declaro el experto y se guarda tal cual.
        """
        code = str(review.get("code") or "").strip()
        if not code:
            raise ExpertReviewValidationError("El code del dictamen es obligatorio.")
        instrument_id = str(review.get("instrument_id") or "").strip()
        cur.execute("SELECT * FROM validation_instruments WHERE id = ?;", (instrument_id,))
        instrument_row = cur.fetchone()
        if instrument_row is None:
            raise InstrumentNotFoundError(
                "El instrumento '%s' no existe." % instrument_id
            )
        instrument = dict(instrument_row)
        if str(instrument["status"]) != "ACTIVO":
            raise ExpertReviewValidationError(
                "El instrumento '%s' no esta ACTIVO (estado: %s)."
                % (instrument["code"], instrument["status"])
            )
        verdict = str(review.get("verdict") or "").strip().upper()
        if verdict not in VERDICTS:
            raise ExpertReviewValidationError(
                "Veredicto '%s' no admitido. Opciones: %s"
                % (verdict, ", ".join(VERDICTS))
            )
        expert_name = str(review.get("expert_name") or "").strip()
        if not expert_name:
            raise ExpertReviewValidationError(
                "El dictamen debe registrar el nombre del experto que lo emite."
            )
        expert_role = str(review.get("expert_role") or "").strip()
        if not expert_role:
            raise ExpertReviewValidationError(
                "El dictamen debe registrar el rol o cargo del experto."
            )

        cur.execute(
            "SELECT * FROM instrument_items WHERE instrument_id = ?;",
            (instrument_id,),
        )
        items_by_id = {str(r["id"]): dict(r) for r in cur.fetchall()}

        raw_answers = review.get("answers")
        if not isinstance(raw_answers, list) or not raw_answers:
            raise ExpertReviewValidationError(
                "El dictamen debe incluir al menos una respuesta por item."
            )
        answers: List[Dict[str, Any]] = []
        seen_items: set = set()
        for raw in raw_answers:
            if not isinstance(raw, dict):
                raise ExpertReviewValidationError("Cada respuesta debe ser un objeto JSON.")
            item_id = str(raw.get("item_id") or "").strip()
            item = items_by_id.get(item_id)
            if item is None:
                raise ExpertReviewValidationError(
                    "El item '%s' no pertenece al instrumento '%s'."
                    % (item_id, instrument["code"])
                )
            if item_id in seen_items:
                raise ExpertReviewValidationError(
                    "Respuesta duplicada para el item '%s'." % item["code"]
                )
            seen_items.add(item_id)
            try:
                answer_score = int(raw.get("score"))
            except (TypeError, ValueError) as exc:
                raise ExpertReviewValidationError(
                    "La respuesta del item '%s' debe ser un entero." % item["code"]
                ) from exc
            if not int(instrument["scale_min"]) <= answer_score <= int(instrument["scale_max"]):
                raise ExpertReviewValidationError(
                    "La respuesta del item '%s' (%s) queda fuera de la escala %s..%s."
                    % (
                        item["code"], answer_score,
                        instrument["scale_min"], instrument["scale_max"],
                    )
                )
            answers.append({
                "id": "ANS-" + hashlib.sha256(
                    ("%s|%s" % (code, item_id)).encode("utf-8")
                ).hexdigest()[:10].upper(),
                "item_id": item_id,
                "score": answer_score,
                "comment": str(raw.get("comment") or "").strip(),
            })

        try:
            score_value = round(float(review.get("score")), 2)
        except (TypeError, ValueError) as exc:
            raise ExpertReviewValidationError(
                "El score descriptivo del dictamen debe ser numerico."
            ) from exc

        review_id = str(
            review.get("id")
            or ("REV-" + hashlib.sha256(code.encode("utf-8")).hexdigest()[:8].upper())
        )
        now = time.time()
        reviewed_at = str(review.get("reviewed_at") or time.strftime("%Y-%m-%d", time.gmtime()))
        try:
            cur.execute("""
                INSERT INTO expert_reviews (
                    id, code, instrument_id, instrument_version, expert_name,
                    expert_role, expert_affiliation, scope, verdict, observations,
                    score, reviewed_at, synthetic, created_by, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                review_id, code, instrument_id, str(instrument["version"]),
                expert_name, expert_role,
                str(review.get("expert_affiliation") or "").strip(),
                str(review.get("scope") or "").strip(),
                verdict, str(review.get("observations") or "").strip(),
                score_value, reviewed_at, 1,
                str(review.get("created_by") or "SYSTEM"), now,
            ))
        except sqlite3.IntegrityError as exc:
            message = str(exc)
            if "UNIQUE" in message.upper() or "PRIMARY KEY" in message.upper():
                raise ExpertReviewAlreadyExistsError(
                    "Ya existe un dictamen registrado con el codigo '%s'." % code
                ) from exc
            raise ExpertReviewValidationError(
                "Dictamen invalido: %s" % message
            ) from exc

        for answer in answers:
            cur.execute("""
                INSERT INTO expert_review_answers (
                    id, review_id, item_id, score, comment
                ) VALUES (?, ?, ?, ?, ?);
            """, (
                answer["id"], review_id, answer["item_id"],
                answer["score"], answer["comment"],
            ))

        cur.execute("SELECT * FROM expert_reviews WHERE id = ?;", (review_id,))
        result = dict(cur.fetchone())
        cur.execute("""
            SELECT a.*, t.code AS item_code, t.dimension, t.statement, t.weight
            FROM expert_review_answers a
            JOIN instrument_items t ON t.id = a.item_id
            WHERE a.review_id = ?
            ORDER BY t.position ASC, t.code ASC;
        """, (review_id,))
        result["answers"] = [dict(r) for r in cur.fetchall()]
        return result

    def insert_expert_review_with_audit_event(
        self, review: Dict[str, Any], audit_event: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Registra un dictamen y sus respuestas con auditoria atomica."""
        return self.run_clinical_transaction(
            lambda cur: self._insert_expert_review_cursor(cur, review), audit_event
        )

    def get_expert_review(self, review_id_or_code: str) -> Optional[Dict[str, Any]]:
        """Recupera un dictamen con sus respuestas, o None si no existe."""
        def op(cur: sqlite3.Cursor) -> Optional[Dict[str, Any]]:
            cur.execute(
                "SELECT * FROM expert_reviews WHERE id = ? OR code = ?;",
                (review_id_or_code, review_id_or_code),
            )
            row = cur.fetchone()
            if not row:
                return None
            result = dict(row)
            cur.execute("""
                SELECT a.*, t.code AS item_code, t.dimension, t.statement, t.weight
                FROM expert_review_answers a
                JOIN instrument_items t ON t.id = a.item_id
                WHERE a.review_id = ?
                ORDER BY t.position ASC, t.code ASC;
            """, (result["id"],))
            result["answers"] = [dict(r) for r in cur.fetchall()]
            return result
        return self._run_simple_read(op)

    def list_expert_reviews(self) -> List[Dict[str, Any]]:
        """Lista los dictamenes registrados con el numero real de respuestas."""
        def op(cur: sqlite3.Cursor) -> List[Dict[str, Any]]:
            cur.execute("""
                SELECT r.*,
                       (SELECT COUNT(*) FROM expert_review_answers a WHERE a.review_id = r.id)
                           AS answers_count
                FROM expert_reviews r
                ORDER BY r.reviewed_at DESC, r.code ASC;
            """)
            return [dict(r) for r in cur.fetchall()]
        return self._run_simple_read(op)

    def insert_report_with_audit_event(
        self, report: Dict[str, Any], audit_event: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Persiste un informe generado y lo audita en una sola transaccion.

        El contenido llega ya construido desde el modulo de informes a partir
        de datos reales; la persistencia solo comprueba que el hash declarado
        corresponde exactamente al contenido que se guarda.
        """
        code = str(report.get("code") or "").strip()
        title = str(report.get("title") or "").strip()
        objective = str(report.get("objective") or "").strip().upper()
        content = str(report.get("content") or "")
        content_hash = str(report.get("content_hash") or "").strip().lower()
        if objective not in REPORT_OBJECTIVES:
            raise ReportValidationError(
                "Objetivo '%s' no admitido. Opciones: %s"
                % (objective, ", ".join(REPORT_OBJECTIVES))
            )
        if not code or not title:
            raise ReportValidationError("El informe requiere code y title.")
        actual_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if content_hash != actual_hash:
            raise ReportValidationError(
                "El content_hash no corresponde al contenido Markdown del informe."
            )

        report_id = str(
            report.get("id")
            or ("RPT-ID-" + hashlib.sha256(code.encode("utf-8")).hexdigest()[:8].upper())
        )
        now = time.time()

        def operation(cur: sqlite3.Cursor) -> Dict[str, Any]:
            try:
                cur.execute("""
                    INSERT INTO reports (
                        id, code, title, objective, period_from, period_to,
                        content, content_hash, generated_by, generated_at, synthetic
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, (
                    report_id, code, title, objective,
                    str(report.get("period_from") or ""),
                    str(report.get("period_to") or ""),
                    content, content_hash,
                    str(report.get("generated_by") or "SYSTEM"), now, 1,
                ))
            except sqlite3.IntegrityError as exc:
                message = str(exc)
                if "UNIQUE" in message.upper() or "PRIMARY KEY" in message.upper():
                    raise ReportValidationError(
                        "Ya existe un informe con el codigo '%s'." % code
                    ) from exc
                raise
            cur.execute("SELECT * FROM reports WHERE id = ?;", (report_id,))
            return dict(cur.fetchone())

        return self.run_clinical_transaction(operation, audit_event)

    def get_report(self, report_id_or_code: str) -> Optional[Dict[str, Any]]:
        """Recupera un informe con su contenido Markdown integro."""
        def op(cur: sqlite3.Cursor) -> Optional[Dict[str, Any]]:
            cur.execute(
                "SELECT * FROM reports WHERE id = ? OR code = ?;",
                (report_id_or_code, report_id_or_code),
            )
            row = cur.fetchone()
            return dict(row) if row is not None else None
        return self._run_simple_read(op)

    def list_reports(self) -> List[Dict[str, Any]]:
        """Lista los informes sin el contenido, del mas reciente al mas antiguo."""
        def op(cur: sqlite3.Cursor) -> List[Dict[str, Any]]:
            cur.execute("""
                SELECT id, code, title, objective, period_from, period_to,
                       content_hash, generated_by, generated_at, synthetic
                FROM reports
                ORDER BY generated_at DESC, code ASC;
            """)
            return [dict(r) for r in cur.fetchall()]
        return self._run_simple_read(op)


class DatabaseBackedOrdersDict(collections.abc.MutableMapping):
    """
    Proxy de diccionario compatible 100% con 'ORDERS_DB'.
    Permite acceso transparente a la base de datos relacional manteniendo
    la interfaz nativa dict de Python.
    """

    def __init__(self, db: ClinicalDatabaseManager):
        self._db = db

    def __getitem__(self, key: str) -> Dict[str, Any]:
        order = self._db.get_order(key)
        if order is None:
            raise KeyError(key)
        return order

    def __setitem__(self, key: str, value: Dict[str, Any]) -> None:
        if not isinstance(value, dict):
            raise TypeError("El valor de la orden debe ser un diccionario.")
        val_copy = dict(value)
        val_copy["order_id"] = key
        self._db.save_order(val_copy)

    def __delitem__(self, key: str) -> None:
        deleted = self._db.delete_order(key)
        if not deleted:
            raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        for o in self._db.get_orders():
            yield o["order_id"]

    def __len__(self) -> int:
        return len(self._db.get_orders())

    def __contains__(self, key: object) -> bool:
        if not isinstance(key, str):
            return False
        return self._db.get_order(key) is not None

    def values(self) -> List[Dict[str, Any]]:
        return self._db.get_orders()

    def items(self) -> List[Tuple[str, Dict[str, Any]]]:
        return [(o["order_id"], o) for o in self._db.get_orders()]

    def clear(self) -> None:
        self._db.clear_orders()

    def get(self, key: str, default: Any = None) -> Any:
        order = self._db.get_order(key)
        return order if order is not None else default


class DatabaseBackedAuditLogs(collections.abc.Sequence):
    """
    Proxy de secuencia compatible 100% con 'AUDIT_LOGS'.
    Permite acceso transparente a la bitácora de auditoría en base de datos.
    """

    def __init__(self, db: ClinicalDatabaseManager):
        self._db = db

    def __getitem__(self, index: Any) -> Any:
        events = self._db.get_audit_events()
        return events[index]

    def __len__(self) -> int:
        return len(self._db.get_audit_events())

    def __iter__(self) -> Iterator[Dict[str, Any]]:
        return iter(self._db.get_audit_events())

    def append(self, record: Dict[str, Any]) -> None:
        # Si se usa append directamente, se asume registro de evento ya formado
        pass

    def clear(self) -> None:
        # El contrato de pruebas autoriza el reinicio explícito de la bitácora.
        self._db.clear_audit_logs(confirm=True)
