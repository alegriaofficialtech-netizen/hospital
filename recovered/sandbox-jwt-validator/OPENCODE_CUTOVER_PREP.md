# Compatibilidad de `cutover_prep/` con el backend clínico endurecido

**Proyecto:** SGSI-ZTA Hospital Lab — `/home/elcra/sandbox-jwt-validator` (servidor-1)
**Rama:** `stage4-lis-candidate-release`
**Base revisada:** `64ac4f5` — *fix(clinical): enforce state machine, atomic audit and least privilege*
**Fecha:** 2026-10-20
**Dictamen:** **GO para los scripts** · **NO-GO para ejecutar el cutover hoy**

---

## 1. Verificación del commit `64ac4f5`

Revisión read-only, sin modificar nada:

| Comprobación | Resultado |
| --- | --- |
| Archivos del commit | 13 (2.333 inserciones, 238 borrados) |
| `PRAGMA integrity_check` de `candidate_release/data/lis.db` | `ok` |
| `journal_mode` | `wal` |
| Esquema | v2 (`schema_migrations`) |
| Permisos de la base | `0600` |
| Ancla de auditoría | `lis.db.anchor-key`, 32 bytes, `0600` |
| Clave predeterminada retirada | sí (`anchor key is default: False`) |
| Checkpoint vs. eventos | 16/16, hash final coincidente |
| Verificación criptográfica con el manager | `chain valid: True` |
| Respaldo pre-endurecimiento | íntegro, 8 eventos, esquema v1, checkpoint coherente |

La base reiniciada es consistente y el respaldo previo
(`/tmp/pre_hardening_backup/lis.db.pre-hardening`) es íntegro y conserva su checkpoint.
Las 16 entradas de auditoría y la única orden son residuo de las pruebas, no datos reales.

---

## 2. Diagnóstico: por qué los scripts no servían

Los siete scripts se escribieron contra el backend anterior. Contra `64ac4f5`:

| Script | Defecto bloqueante |
| --- | --- |
| `post_cutover_verify.py` | Clave IoMT embebida; firma solo el cuerpo (sin dispositivo, timestamp ni nonce); espera que IoMT cree órdenes (ahora 404); **crea una orden clínica real durante la verificación**; no verifica el ancla ni el checkpoint |
| `preflight_check.py` | Manifiesto sin `clinical_domain.py`; no detecta secretos embebidos; no comprueba el contrato de entorno ni la compatibilidad de la base |
| `backup_production.sh` | **No copia `<db>.anchor-key`**: la base restaurada no arranca; `cp -r .../*` omite dotfiles; no verifica la cadena del respaldo |
| `cutover_deploy.sh` | **No copia `clinical_domain.py`** (el backend no importa); `json.load` sobre YAML; no inyecta `IOMT_DEVICE_KEYS_JSON` ni el ancla; sin espera de health ni verificación |
| `prepare_volume.sh` | Ajusta permisos sobre datos existentes sin confirmación; no verifica esquema ni ancla |
| `recover_database.sh` | **No restaura el ancla**; sobrescribe sin snapshot previo; inspección que puede crear WAL |
| `rollback.sh` | Detiene servicios y **nunca los vuelve a levantar**; declara "cero pérdida de datos" sin verificar la base; no detecta la incompatibilidad código/base |

---

## 3. Qué se cambió

### 3.1 Nuevo `cutover_prep/cutover_common.py`

Utilidades compartidas, solo stdlib, sin secretos:

- resolución de credenciales M2M por entorno o `--creds`, **sin valores por defecto**;
- cliente HTTP tolerante a cuerpos de error no JSON;
- firma IoMT `device_id\ntimestamp\nnonce\ncuerpo`;
- apertura SQLite `mode=ro` (lee WAL sin escribir);
- **verificación independiente de la cadena**: recalcula
  `sha256(json.dumps(record, sort_keys=True))` por evento y el anclaje
  `sha256(anchor_key + f"{last_hash}:{total}")`, sin instanciar el manager sobre la base viva
  (eso ejecutaría migraciones);
- veredicto con estados `GO` / `NO-GO` / `INCOMPLETE` (los SKIP bloqueantes no cuentan como aprobado);
- CLI `inspect` y `durability` para que los scripts de shell no dupliquen criptografía.

### 3.2 `post_cutover_verify.py` (prioridad)

**Modo por defecto: solo lectura estricta.**

- No crea órdenes, no valida órdenes, no ingesta resultados clínicos.
- Las pruebas IoMT son **negativas**: sin cabeceras (401), dispositivo desconocido (403),
  timestamp vencido (401), firma inválida (403) y orden inexistente (404, lo que prueba C-04).
  Todas usan un `order_id` con prefijo `CANARY-` inexistente, de modo que ningún dato real
  pueda ser alcanzado.
- Comprueba menor privilegio del token M2M: `GET /orders`, `POST /orders` y
  `POST /orders/validate` deben devolver 403 (C-09).
- Verifica `integrity_check`, esquema ≥ v2, `journal_mode`, permisos `0600` de base y ancla,
  y la cadena recalculada.
- La prueba positiva existe pero es explícita: `--write-probe --canary-order-id=CANARY-*`;
  el script se niega a usar cualquier identificador que no empiece con `CANARY-`.
- Códigos de salida: `0` GO, `1` NO-GO, `2` INCOMPLETO.

> Las pruebas negativas generan eventos `DENIED` en la auditoría append-only. Es el
> comportamiento correcto de un sistema auditado, no una mutación clínica.

### 3.3 `preflight_check.py`

Añade: manifiesto que cubre los cinco módulos del runtime, compilación en memoria,
detección de secretos por defecto, contrato de entorno que el despliegue debe inyectar
(`LIS_DB_PATH`, `ENABLE_LEGACY_AUTH`, `IOMT_DEVICE_KEYS_JSON`,
`IOMT_MAX_CLOCK_SKEW_SECONDS`, `IOMT_NONCE_TTL_SECONDS`, `AUDIT_HMAC_KEY`), validación del
archivo de claves por dispositivo, inspección opcional de la base existente y escritura real en el destino de respaldo (8c), que es un bloqueo de cutover independiente del código.

### 3.4 `backup_production.sh`

- Copia **base + ancla** y falla cerrado si hay base sin ancla (un respaldo así no restaura).
- `cp -a` con dotfiles.
- `BACKUP_METADATA.json`: commit, rama, hashes, esquema, checkpoint, huella del ancla
  (nunca la clave).
- Verificación criptográfica del respaldo tras generarlo.
- `--verify-only=DIR` para re-auditar un respaldo.
- `--source-db` / `--skip-code` para respaldos de base y ensayos sin Docker.

### 3.5 `cutover_deploy.sh`

- Copia los cinco módulos, incluido `clinical_domain.py`.
- Verifica el manifiesto antes y **hashes después** de copiar.
- Escritura atómica (`.tmp` + `mv`) y snapshot de lo reemplazado.
- `docker-compose.yml` con **PyYAML**; aborta si falta la librería.
- Inyecta el contrato de entorno en `.env` (`0600`, escritura atómica) y referencias en compose.
- Garantiza el ancla en el volumen sin pasar secretos por línea de comandos.
- Espera `/health` real y ejecuta la verificación post-cutover.
- Si el health falla, ejecuta rollback automático.
- `--no-restart` corta antes de cualquier operación con Docker (útil para ensayos).

### 3.6 `prepare_volume.sh`

Detecta datos existentes y exige `--allow-existing`; nunca borra; aplica `0600` solo a
`lis.db`, `-wal`, `-shm` y al ancla; verifica escritura real como UID 65534, esquema y ancla.

### 3.7 `recover_database.sh`

- Restaura **base + ancla**; aborta si el respaldo tiene eventos y no hay ancla.
- Snapshot obligatorio del destino antes de sobrescribir; si falla, no restaura.
- Exige `--force` para sobrescribir datos existentes.
- Verifica cadena y anclaje del respaldo y del destino, y compara recuentos de órdenes y eventos.
- Modo `--target-db` para restauración en rutas del host (ensayos sin Docker).

### 3.8 `rollback.sh`

- Snapshot del estado candidato antes de sobrescribir.
- Verifica el manifiesto del respaldo.
- Restaura con `cp -a`, compara byte a byte y elimina `clinical_domain.py` si el respaldo no lo tenía.
- **Compuerta de compatibilidad código/base** (ver hallazgo 1).
- `--with-database` restaura la base emparejada de forma explícita.
- Rearranca y espera `/health` (antes dejaba el servicio detenido).
- Solo afirma "datos preservados" tras verificar integridad y cadena.

### 3.9 `test_cutover_full_rehearsal.py`

Adaptado al contrato nuevo: claves por dispositivo desde `IOMT_DEVICE_KEYS_JSON`, firma con
timestamp y nonce, verificación de `integrity_seal`, comprobación de que IoMT no crea
órdenes, replay rechazado, y Keycloak reportado como **PENDIENTE** en lugar de romper el ensayo.

---

## 4. Hallazgos operativos nuevos

### 4.1 El rollback de solo código es inválido tras el cutover — **crítico**

Probado empíricamente con el `database.py` anterior sobre una base v2:

```
AuditChainCorruptedError: Firma criptográfica de anclaje (Anchor HMAC) inválida
                        en el Checkpoint de auditoría.
```

El código previo usa la clave por defecto retirada y no puede abrir la base migrada.
Revertir solo el código deja el servicio caído en el arranque. `rollback.sh` ahora:

- detecta la incompatibilidad **antes de tocar nada** y aborta con instrucciones;
- ofrece `--with-database`, que restaura la base emparejada del respaldo
  (pierde los datos escritos desde el cutover: decisión explícita, no automática).

### 4.2 `/home/elcra/backups` no es escribible por el operador

```
drwxr-xr-x 3 root root /home/elcra/backups
```

Las rutas por defecto `pre_cutover/` y `pre_restore/` fallaban con `Permission denied`.
Los scripts ahora fallan cerrado con el comando exacto:

```
sudo install -d -o elcra -g users -m 700 /home/elcra/backups/pre_cutover
```

y admiten `--dest` / `--safety-dir`. **Acción pendiente del operador antes del cutover.**

### 4.3 `PRAGMA synchronous` no es verificable desde fuera

Es un ajuste por conexión con valor por defecto FULL: una conexión nueva siempre lee `2`,
incluso contra una base generada por el backend anterior. El verificador no lo usa como
prueba; comprueba `journal_mode` en la base y la directiva `PRAGMA synchronous=FULL` en el
`database.py` desplegado.

### 4.4 Otros

- `docker-compose.yml` se parseaba con `json.load` (es YAML): el despliegue habría abortado.
- El despliegue no copiaba `clinical_domain.py`: el backend no habría importado.
- La verificación post-cutover creaba una orden clínica real en el sistema auditado.

---

## 5. Evidencia de ejecución

Todo se ejecutó en el sandbox. **No se usó `--apply` contra `/opt`, no se tocó el volumen,
no se reiniciaron servicios, no se modificó Keycloak y no se hizo push.**

| Prueba | Resultado |
| --- | --- |
| `bash -n` sobre los 5 scripts | OK |
| `python3 -m py_compile` sobre los 4 módulos | OK |
| Batería segura (inspección, respaldo, verificación, restauración) | **11/11 PASS** |
| Rechazo de sobrescritura sin `--force` | PASS (aborta) |
| Rechazo de respaldo de base sin ancla | PASS (aborta) |
| Servidor efímero + `post_cutover_verify --read-only` | **PASS=18 FAIL=0 SKIP=2** (INCOMPLETE) |
| Ensayo integral | **12 PASS, 2 PENDIENTES** |
| Rollback v1 sobre base v2 | aborta con instrucciones |
| Rollback v1 + `--with-database` sin base en respaldo | aborta |
| Rollback v2 sobre base v2 | continúa y verifica la cadena |
| `test_candidate_lis` | 10/10 OK |
| `test_clinical_hardening` | 14/14 OK |
| `test_persistence_durability` | 5/5 OK |
| `test_phase2_persistence_audit_integrity` | 10/10 OK |
| `test_audit_monitor` | 9/15 OK, **6 pendientes por Keycloak** |

### Pendientes por Keycloak (realm `hospital-lab`, `127.0.0.1:8085`)

`test_01`, `test_02`, `test_03`, `test_04`, `test_14`, `test_15` de `test_audit_monitor.py`,
y los puntos 08 y 09 del ensayo. El realm responde `Connection refused`. No se inició ni se
modificó Keycloak.

---

## 6. Contrato operativo que cambia

1. **El ancla viaja con la base.** Respaldo, restauración y rollback copian
   `<db>.anchor-key`. Sin ella, la base no arranca.
2. **La verificación post-cutover es no destructiva por defecto.** Solo `--write-probe`
   escribe, y solo sobre órdenes `CANARY-`.
3. **El rollback requiere decisión sobre los datos.** Con esquema v2 y código anterior,
   `--with-database` es obligatorio y pierde lo escrito tras el cutover.
4. **El despliegue exige claves IoMT explícitas.** Sin `--device-keys-file` o
   `IOMT_DEVICE_KEYS_JSON`, aborta: el canal quedaría en 503.
5. **El snapshot necesita una ruta escribible.** `--safety-dir` o `sudo install -d` previo.

---

## 7. Riesgos residuales

- **La verificación de cadena es simétrica (HMAC).** Detecta alteración, no da
  no repudiación: quien tenga el ancla puede re-firmar. El ancla vive junto a la base
  (`0600`), no en un KMS/HSM.
- **El ancla en `.env` es texto plano.** El despliegue la escribe con `0600`; un operador
  con acceso al archivo puede leerla.
- **`post_cutover_verify` no prueba la validación médica con MFA.** Requiere un token
  humano real; esa ruta la cubre el ensayo con JWT sintéticos y debe probarse manualmente
  tras el cutover.
- **La restauración desde el respaldo pre-cutover pierde datos posteriores.** Es inherente
  al rollback con cambio de esquema; queda explícito en `--with-database`.
- **Los scripts de volumen usan `docker run`.** Es de solo lectura (`--network none`), pero
  requiere que el usuario esté en el grupo `docker`.

---

## 8. Dictamen

**GO** — los siete scripts y el arnés son compatibles con el backend endurecido, no usan
secretos embebidos, no escriben datos clínicos en la verificación por defecto, preservan el
ancla de auditoría y fallan cerrado ante estados inseguros. Evidencia reproducible en el
sandbox.

**NO-GO para ejecutar el cutover hoy**, por dos condiciones externas al código:

1. **Keycloak `hospital-lab` no responde** (`Connection refused`). El LIS delega la
   autenticación: sin realm, el cutover deja el acceso roto y 6 pruebas quedan sin verificar.
2. **`/home/elcra/backups` no es escribible por `elcra`.** Hay que provisionarlo antes de
   respaldar:
   `sudo install -d -o elcra -g users -m 700 /home/elcra/backups/pre_cutover /home/elcra/backups/pre_restore`

Cumplidas ambas, el procedimiento es: `preflight_check.py` → `backup_production.sh --apply`
→ `prepare_volume.sh --apply` → `cutover_deploy.sh --apply` → `post_cutover_verify.py --read-only`.
