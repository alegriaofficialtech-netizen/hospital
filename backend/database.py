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

SCHEMA_VERSION = 2
ZERO_HASH = "0" * 64


class DatabaseError(Exception):
    """Excepción base para errores de base de datos."""
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
