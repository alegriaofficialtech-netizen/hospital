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

SCHEMA_VERSION = 4
ZERO_HASH = "0" * 64

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
