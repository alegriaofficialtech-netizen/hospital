# Endurecimiento clínico, de integridad y de menor privilegio

**Ámbito:** `candidate_release/` del sandbox `~/sandbox-jwt-validator`
**Rama:** `stage4-lis-candidate-release`
**Origen:** hallazgos P0 de `OPENCODE_CUTOVER_AUDIT.md` filtrados por
`OPENCODE_CLINICAL_HARDENING_PROMPT.txt`.

Este trabajo **no** toca `/opt/sgsi-zta-hospital-lab`, no ejecuta el cutover ni
`--apply`, no reinicia contenedores, no modifica Keycloak y no publica nada.

---

## 1. Alcance ejecutado

Numeración tomada literalmente de `OPENCODE_CUTOVER_AUDIT.md`.

| ID | Hallazgo del informe | Estado |
|----|----------------------|--------|
| C-03 | Reutilizar un `order_id` sobrescribe la orden | Corregido |
| C-04 | IoMT degrada órdenes liberadas y crea órdenes sin admisión | Corregido |
| C-05 | La validación no exige estado ni mediciones; `digital_signature` no cubre el contenido | Corregido |
| C-06 | La escritura clínica y el evento de auditoría no son atómicos | Corregido |
| C-07 | El borrado total de la auditoría no se detecta | Corregido |
| C-08 | Dos escritores pueden romper la cadena de auditoría | Corregido |
| C-09 | El token M2M del auditor puede leer todas las órdenes clínicas | Corregido |
| A-01 | Secretos por defecto hardcodeados | Corregido |
| A-02 | El canal IoMT no tiene antirreplay ni separación por dispositivo | Corregido |
| A-04 | El audit-monitor no falla visiblemente ni detecta listas vacías | Corregido |
| A-05 | `synchronous=NORMAL` y permisos de base 0644 | Corregido |

Fuera de alcance por instrucción explícita: C-01, C-02, C-10, C-11, C-12, A-03,
A-06…A-09, Docker, Keycloak y los scripts de cutover.

---

## 2. Cambios por archivo

### `clinical_domain.py` (nuevo)

Dominio clínico puro, sin E/S ni variables de entorno:

- Máquina de estados explícita `CREATED → SAMPLE_COLLECTED → ANALYZED →
  VALIDATED_AND_RELEASED` (terminal). `assert_transition()` rechaza saltos,
  estados desconocidos y cualquier transición desde un estado terminal.
- `validate_measurements()`: esquema cerrado de analitos, valores numéricos
  finitos y rangos fisiológicos. Rechaza booleanos, cadenas, `NaN`/`inf` y
  diccionarios vacíos.
- `compute_integrity_seal()` / `verify_integrity_seal()`: HMAC-SHA256 sobre el
  contenido canónico completo de la orden (paciente, estado, mediciones,
  validador, observaciones, versión). **Es un sello de integridad, no una firma
  digital**: no aporta no repudio; para eso hace falta clave asimétrica.
  Sustituye a `digital_signature`, que era `sha256(order_id::actor::timestamp)`.
- `patient_reference()`: pseudonimización estable (`ref:<12 hex>`) para que la
  auditoría no almacene PHI en claro.

### `database.py`

- `SCHEMA_VERSION = 2`, migración idempotente que añade `version` y
  `updated_at` a `clinical_orders` y la tabla `iomt_nonces` con índice por
  `received_at`.
- `run_clinical_transaction(operation, audit_event)`: una sola transacción
  `BEGIN IMMEDIATE` que ejecuta la operación clínica **y** el evento de
  auditoría, con `ROLLBACK` conjunto. La lectura del último hash ocurre dentro
  de la transacción, no desde estado en memoria.
- `insert_order_cursor()`: `INSERT` puro. Un `order_id` duplicado lanza
  `DuplicateOrderError`; se elimina el `ON CONFLICT DO UPDATE`.
- `replace_order_cursor()`: control de versión optimista (`WHERE version = ?`)
  con `OrderVersionConflictError` / `OrderNotFoundError`.
- `register_iomt_nonce_cursor()`: depuración por TTL e inserción del nonce en la
  misma transacción; un duplicado lanza `IomtReplayError`.
- `_resolve_anchor_key()`: sin valores por defecto. Prioridad: argumento
  explícito → `AUDIT_HMAC_KEY` → archivo lateral `<db>.anchor-key` (0600) →
  generación aleatoria de 32 bytes **solo si la base no tiene eventos**. Si hay
  cadena previa y no hay clave, falla cerrado con `AuditChainCorruptedError`.
- `_assert_checkpoint_consistency()`: compara siempre `total_events` con el
  conteo real y `last_hash` con el último evento, incluso con la tabla vacía.
- `_apply_file_permissions()` / `_harden_file_permissions()`: `0600` sobre la
  base, `-wal`, `-shm` y la clave de anclaje, reafirmado tras cada `COMMIT`
  (SQLite crea `-wal`/`-shm` de forma perezosa).
- `PRAGMA synchronous=FULL` (antes `NORMAL`), `journal_mode=WAL`,
  `busy_timeout=5000`.
- `backup_database()`: escribe `<backup>.anchor-key` junto al respaldo para que
  la cadena restaurada siga siendo verificable.
- `clear_audit_logs(confirm=True)`: el reseteo de bitácora exige confirmación
  explícita.

### `server.py` (PEP)

- **Alta de orden**: `create_order(order, audit_event=...)` atómico; duplicado →
  `409 ORDER_ALREADY_EXISTS` sin sobrescribir.
- **Validación**: solo desde `ANALYZED` → `VALIDATED_AND_RELEASED`; revalidación
  → `409 ORDER_ALREADY_VALIDATED`; estado insuficiente →
  `409 INVALID_ORDER_TRANSITION`; mediciones inválidas → `422`. El sello se
  calcula sobre el contenido final con `get_seal_key()`.
- **IoMT**: canal fail-closed. Sin `IOMT_DEVICE_KEYS_JSON` responde
  `503 IOMT_NOT_CONFIGURED`. Exige `X-Device-Id`, `X-Device-Signature`,
  `X-Device-Timestamp` y `X-Device-Nonce`; firma
  `device_id\ntimestamp\nnonce\nbody`; ventana de ±300 s; nonce durable
  anti-replay. No crea órdenes (`404 ORDER_NOT_FOUND`), no toca órdenes
  liberadas (`409 ORDER_LOCKED`) y no permite cambiar de dispositivo analizador.
- **Auditoría**: `audit_chain_valid` ya no se recalcula sobre la copia que envía
  el servidor; se consulta `db_manager.verify_chain_integrity()` (checkpoint +
  conteo + anclaje) y se añade `chain_error`.
- **Listado de órdenes**: `VIEW_ORDERS` mediante `enforce_clinical_action`;
  se elimina `ROLE_SECURITY_AUDITOR` de la lista embebida. Cada orden incluye
  `integrity_verified` calculado en lectura.
- `run_server()` fija `os.umask(0o077)`.

### `jwt_validator.py`

- `ClinicalAuthContext.is_service_account` derivado de
  `preferred_username == service-account-*`.
- `CLINICAL_ACTIONS = {CREATE_ORDER, VALIDATE_ORDER, VIEW_ORDERS}`:
  `enforce_clinical_action()` rechaza cuentas de servicio en acciones clínicas,
  incluidas las que hoy tendrían rol suficiente. Las cuentas M2M quedan
  limitadas a `VIEW_AUDIT_LOGS`.

### `audit_monitor/monitor.py`

- `verify_audit_chain([])` devuelve `False` y alerta: una cadena vacía no es una
  cadena válida.
- `run_audit_cycle()` exige además `audit_chain_valid is True` del servidor
  (veredicto de checkpoint). Un prefijo de cadena sigue siendo autoconsistente
  por diseño, así que el truncado por la cola solo es detectable con el
  checkpoint.
- `audit_exit_code()` y `sys.exit(...)`: el proceso devuelve 0 solo si el ciclo
  fue `SUCCESS` y la cadena se reportó íntegra; en cualquier otro caso devuelve
  1 para que el supervisor lo marque como no saludable.

---

## 3. Evidencia

### 3.1 Reproducción independiente (`/tmp/repro_findings.py`)

Mismo script ejecutado contra el código de `HEAD` y contra el endurecido.

**Antes — `/tmp/old_tree` (HEAD `182564c`):**

```text
[VULNERABLE] C-03 alta no sobrescribe orden existente :: http=201 dni_almacenado=DNI-ATACANTE
[VULNERABLE] C-04 IoMT no crea ordenes :: http=200 order_created=True
[VULNERABLE] C-04 IoMT no modifica orden liberada :: liberada=200 reingesta=200 valor=17.0
[VULNERABLE] C-05 validacion exige estado ANALYZED :: http=200 code=None
[VULNERABLE] C-05 orden liberada no se revalida :: primera=200 segunda=200 code=None
[VULNERABLE] C-05 sello cubre contenido clinico :: sin integrity_seal (digital_signature=True)
[VULNERABLE] check_c06 :: error: AttributeError: 'ClinicalDatabaseManager' object has no attribute 'create_order'
[VULNERABLE] C-07 borrado de la cadena detectado :: valid=True reason=None
[VULNERABLE] C-08 dos escritores conservan la cadena :: valid=False reason=Ruptura de cadena en evento ID 2
[VULNERABLE] C-09 VIEW_ORDERS aplicado por politica :: http=200
[VULNERABLE] A-01 sin clave de anclaje por defecto :: longitud=34 es_default=True
[VULNERABLE] A-02 antirreplay de nonce IoMT :: primera=200 reenvio=200 code=None
[VULNERABLE] A-04 monitor rechaza cadena vacia y falla visiblemente :: cadena_vacia_valida=True exit_code=0
[VULNERABLE] A-05 synchronous=FULL y base 0600 :: synchronous=1 modo=0o644
== TOTAL: 0/14 SAFE, 14 VULNERABLE ==
```

**Después — `candidate_release`:**

```text
[SAFE] C-03 alta no sobrescribe orden existente :: http=409 dni_almacenado=DNI-ORIGINAL
[SAFE] C-04 IoMT no crea ordenes :: http=404 order_created=False
[SAFE] C-04 IoMT no modifica orden liberada :: liberada=200 reingesta=409 valor=13.0
[SAFE] C-05 validacion exige estado ANALYZED :: http=409 code=INVALID_ORDER_TRANSITION
[SAFE] C-05 orden liberada no se revalida :: primera=200 segunda=409 code=ORDER_ALREADY_VALIDATED
[SAFE] C-05 sello cubre contenido clinico :: original=True adulterado=False
[SAFE] C-06 orden y auditoria atomicas :: orden_persistida=False eventos_antes=16 eventos_despues=16
[SAFE] C-07 borrado de la cadena detectado :: valid=False reason=Discrepancia de conteo: checkpoint=2, eventos=0 (borrado o truncado)
[SAFE] C-08 dos escritores conservan la cadena :: valid=True reason=None
[SAFE] C-09 VIEW_ORDERS aplicado por politica :: http=403
[SAFE] A-01 sin clave de anclaje por defecto :: longitud=32 es_default=False
[SAFE] A-02 antirreplay de nonce IoMT :: primera=200 reenvio=409 code=IOMT_REPLAY_DETECTED
[SAFE] A-04 monitor rechaza cadena vacia y falla visiblemente :: cadena_vacia_valida=False exit_code=1
[SAFE] A-05 synchronous=FULL y base 0600 :: synchronous=2 modo=0o600
== TOTAL: 14/14 SAFE, 0 VULNERABLE ==
```

### 3.2 Suites de regresión (servidor, Python 3.13.5)

| Suite | Resultado |
|-------|-----------|
| `candidate_release/test_database.py` | 8/8 OK |
| `candidate_release/test_phase2_persistence_audit_integrity.py` | 10/10 OK |
| `candidate_release/test_candidate_lis.py` | 10/10 OK |
| `candidate_release/test_persistence_durability.py` | 5/5 OK |
| `candidate_release/test_clinical_hardening.py` (nueva) | 14/14 OK |
| raíz `test_jwt_validator.py` + `test_lis_jwt_adapter.py` | 54/54 OK |
| `candidate_release/test_audit_monitor.py` | 9/15 OK — 6 bloqueadas por entorno |

**Total ejecutado y en verde: 110 pruebas.**

### 3.3 Pruebas no ejecutadas (limitación de entorno, no del cambio)

`test_audit_monitor.py` requiere el realm de pruebas de Keycloak en
`http://127.0.0.1:8085/realms/hospital-lab-oidc-test`, que **no estaba
levantado**: `curl` devuelve `Connection refused` (`Errno 111`).

Bloqueadas por eso, sin evidencia de resultado:
`test_01`, `test_02`, `test_03`, `test_04`, `test_14`, `test_15`.

Las 9 restantes pasan, incluida la prueba IoMT endurecida (replay, firma ajena,
dispositivo desconocido, marca temporal vencida).

No se inició ni modificó Keycloak para no alterar el entorno.

### 3.4 Pruebas ajustadas y por qué

| Archivo | Ajuste | Motivo |
|---------|--------|--------|
| `test_phase2_persistence_audit_integrity.py` | espera `synchronous == 2` (FULL) en vez de 1 | El valor anterior codificaba la política que A-05 marca como hallazgo |
| `test_candidate_lis.py` | firma IoMT con clave por dispositivo + timestamp/nonce; `integrity_seal` en vez de `digital_signature` | Nuevo contrato de A-02 y C-05 |
| `test_audit_monitor.py` | igual que la anterior en `test_10`, más casos de replay/firma/ventana | Igual |
| `test_persistence_durability.py` | firma IoMT nueva; analito `leucocitos_mm3`; el respaldo restaurado copia `.anchor-key` | A-02, C-05 y el nuevo requisito operativo de anclaje |

No se relajó ninguna aserción: los criterios de aceptación se endurecieron.

---

## 4. Cambios de contrato operativo

1. **IoMT**
   - `IOMT_DEVICE_KEYS_JSON='{"<device-id>": "<secreto-de-16+-caracteres>"}'`
   - Opcional: `IOMT_MAX_CLOCK_SKEW_SECONDS` (300), `IOMT_NONCE_TTL_SECONDS` (900).
   - Sin configuración el canal responde 503 (fail-closed).
   - El cliente debe enviar `X-Device-Timestamp` y `X-Device-Nonce` y firmar
     `device_id\ntimestamp\nnonce\nbody`.

2. **Clave de anclaje de auditoría**
   - Se elimina `SGSI-ZTA-Default-Audit-Anchor-2026`.
   - Orden de resolución: argumento → `AUDIT_HMAC_KEY` → `<db>.anchor-key` →
     clave aleatoria (solo base sin cadena).
   - Una cadena existente sin clave **no arranca**. Es intencional: sin clave no
     hay verificación posible.

3. **Respaldos y restauración**
   - `backup_database()` escribe `<backup>.anchor-key`.
   - Un respaldo restaurado manualmente **debe** incluir el archivo lateral, o el
     operador debe definir `AUDIT_HMAC_KEY`.

4. **Sello de integridad clínico**
   - `CLINICAL_SIGNING_KEY` (hex o UTF-8, ≥16 bytes) es opcional; si falta se
     deriva del anclaje de auditoría.
   - El campo es `integrity_seal`; `digital_signature` desaparece.
   - Es HMAC, **no** firma digital: no hay no repudio.

5. **Base de datos del sandbox reiniciada**
   - `candidate_release/data/lis.db` se generó con la clave por defecto eliminada
     y no era verificable. Se respaldó en
     `/tmp/pre_hardening_backup/lis.db.pre-hardening` y se regeneró vacía.
   - No afecta a producción: es el archivo de pruebas del sandbox.

6. **Migración de esquema v1 → v2**
   - Automática e idempotente al abrir la base: columnas `version`/`updated_at`
     y tabla `iomt_nonces`.

---

## 5. Pendiente y riesgos residuales

- Docker, Keycloak, `--apply`, cutover y scripts de despliegue: intactos.
- C-01, C-02, C-10, C-11, C-12, A-03, A-06…A-09: no abordados.
- `cutover_prep/post_cutover_verify.py` sigue usando la clave IoMT por defecto y
  el flujo de `digital_signature`; debe actualizarse antes del cutover (fuera de
  alcance autorizado).
- Las 6 pruebas de `test_audit_monitor.py` dependientes de Keycloak siguen sin
  evidencia de ejecución en este entorno.
- El sello es simétrico (HMAC): la clave la conoce el servidor, así que no hay
  no repudio. Si el requisito clínico lo exige, hace falta firma asimétrica y
  custodia de clave privada; hoy no existe esa infraestructura.
- La clave de anclaje vive junto a la base (0600). No sustituye a un KMS/HSM ni
  a un almacén WORM para el checkpoint.
