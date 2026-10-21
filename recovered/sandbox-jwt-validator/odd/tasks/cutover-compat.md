# ODD — Compatibilidad de cutover_prep con el backend clínico endurecido

**Feature:** `cutover-compat`
**Repositorio:** `/home/elcra/sandbox-jwt-validator` (servidor-1)
**Rama:** `stage4-lis-candidate-release`
**Base:** `64ac4f5`
**Fecha:** 2026-10-20
**Estado:** implementado y verificado

## Objetivo

Alinear los siete scripts de `cutover_prep/` con el backend endurecido en `64ac4f5`, de modo
que el cutover sea ejecutable sin romper la cadena de auditoría, sin escribir datos clínicos
reales durante la verificación y sin depender de secretos embebidos.

## Problema

`cutover_prep/` quedó escrito contra el backend anterior. Hoy:

- usa `DEVICE_KEY = b"Secret_IoMT_Key_Hematology_2026"` (hallazgo A-01),
- firma solo el cuerpo, sin `device_id`, timestamp ni nonce (A-02),
- espera que IoMT cree órdenes, que ahora responde 404 (C-04),
- escribe una orden clínica real durante la verificación post-cutover,
- no copia `clinical_domain.py`, así que el despliegue fallaría al importar,
- respalda y restaura `lis.db` sin `<db>.anchor-key`, por lo que la base restaurada no
  arranca (fail-closed de A-01),
- hace `json.load()` sobre un `docker-compose.yml` (YAML), lo que revienta el despliegue,
- declara "cero pérdida de datos" en el rollback sin verificar la base,
- `rollback.sh` detiene los servicios y nunca los vuelve a levantar.

## Por qué

Un cutover con estos scripts produciría, en el mejor caso, un NO-GO tardío; en el peor, una
base restaurada que no arranca o un rollback que deja el servicio caído. La verificación
post-cutover, además, no puede ser destructiva: hoy crea una orden con DNI ficticio en el
sistema que se supone está verificando.

## Alcance autorizado

**Dentro:** los siete scripts de `cutover_prep/`, el arnés `test_cutover_full_rehearsal.py`
y un nuevo `cutover_prep/cutover_common.py` de utilidades compartidas.
**Fuera:** `/opt`, Keycloak, Docker principal, servicios, `--apply`, `push`.

## Decisiones de diseño

1. **Verificación post-cutover no destructiva por defecto.** El modo por defecto es
   `--read-only`: no crea órdenes, no ingesta resultados, no valida. Solo lee y prueba
   rechazos. Las pruebas IoMT positivas requieren `--write-probe --canary-order-id=CANARY-*`,
   y el script se niega a usar cualquier `order_id` que no empiece con `CANARY-`.
2. **Verificación criptográfica independiente.** El verificador recalcula la cadena de
   auditoría en Python puro a partir de `audit_events` y el anclaje
   `sha256(anchor_key + f"{last_hash}:{total}")`, sin instanciar
   `ClinicalDatabaseManager` sobre la base viva (eso ejecutaría migraciones y escribiría).
3. **`PRAGMA synchronous` no es verificable desde fuera.** Es un ajuste por conexión con
   valor por defecto FULL: leerlo en una conexión nueva siempre devuelve 2. El verificador
   comprueba `journal_mode` en la base y la política `PRAGMA synchronous=FULL` en el
   `database.py` desplegado.
4. **El ancla viaja con la base.** Respaldo, restauración y rollback copian
   `<db>.anchor-key` y fallan cerrado si falta con una cadena existente.
5. **Credenciales sin valores por defecto.** Solo `AUDIT_MONITOR_CLIENT_ID`/`_SECRET` desde
   entorno o un archivo indicado con `--creds`; sin candidatos embebidos ni secretos.
   Los secretos se redactan en toda salida.
6. **Snapshot antes de toda destrucción.** Restauración y rollback copian el estado actual
   (base + ancla + config) a un directorio de seguridad antes de sobrescribir; si el
   snapshot falla, no se continúa.
7. **Despliegue atómico y verificado.** Copia a temporal + `mv`, respalda lo reemplazado,
   valida el manifiesto antes y después, espera `/health` real y ejecuta la verificación
   post-cutover. Si el health falla, ejecuta rollback.
8. **YAML real.** `docker-compose.yml` se edita con PyYAML, no con `json.load`.

## Checklist

- [x] T1 — `cutover_common.py`: credenciales, HTTP, inspección SQLite read-only,
      verificación de cadena y anclaje, firma IoMT, redacción de secretos, veredicto.
- [x] T2 — `post_cutover_verify.py`: modo read-only estricto, pruebas negativas IoMT,
      menor privilegio, integridad y cadena; `--write-probe` con canario.
- [x] T3 — `preflight_check.py`: manifiesto con `clinical_domain.py`, compilación del
      candidato, secretos embebidos, contrato de entorno, compatibilidad de base y ancla.
- [x] T4 — `backup_production.sh`: copia código con dotfiles, base + ancla, metadatos,
      verificación criptográfica del respaldo.
- [x] T5 — `cutover_deploy.sh`: `clinical_domain.py`, manifiesto, escritura atómica,
      YAML, contrato de entorno, ancla en volumen, espera de health, verificación y
      rollback automático.
- [x] T6 — `prepare_volume.sh`: detección de datos existentes, permisos por archivo
      (0600 en base y ancla), verificación de esquema.
- [x] T7 — `recover_database.sh`: restauración con ancla, snapshot previo, verificación
      de cadena y checkpoint posterior.
- [x] T8 — `rollback.sh`: snapshot, restauración verificada, limpieza de archivos
      exclusivos del candidato, reinicio y health.
- [x] T9 — Arnés de ensayo adaptado al contrato nuevo.
- [x] T10 — Pruebas seguras (sin `--apply`), informe, commit y dictamen GO/NO-GO.

## Criterios de aceptación

1. Ningún script contiene secretos embebidos.
2. La verificación post-cutover no modifica datos clínicos en modo por defecto.
3. Respaldo → restauración → verificación de cadena funciona de punta a punta en el sandbox.
4. El despliegue copia todos los módulos que el backend importa.
5. `bash -n` y `python3 -m py_compile` limpios en los ocho archivos.
6. Ensayo completo sin `--apply` con resultado reproducible.

## Verificación

- `bash -n cutover_prep/*.sh`
- `python3 -m py_compile cutover_prep/*.py`
- `python3 cutover_prep/preflight_check.py --json`
- `python3 cutover_prep/post_cutover_verify.py --read-only --db-path ... --creds ...`
- `cutover_prep/backup_production.sh --dry-run` y `--apply --dest=/tmp/...`
- `cutover_prep/recover_database.sh --dry-run`
- `cutover_prep/rollback.sh --dry-run`
- `python3 cutover_prep/test_cutover_full_rehearsal.py`

## Ruta de implementación

`delegated direct` planificada; ejecutada **inline** porque el juego de scripts es acoplado,
comparte un módulo nuevo y cada archivo depende del contrato exacto del backend leído en esta
sesión. Un escritor delegado requeriría transferir ese contrato completo sin beneficio.

## Estrategia de entrega

`local-commit` en `stage4-lis-candidate-release`. Sin push, sin `--apply`.

## Progreso

- 2026-10-20: verificación de `64ac4f5` — base 0600, `integrity_check=ok`, WAL, esquema v2,
  checkpoint 16/16 coherente, cadena válida, ancla de 32 bytes no predeterminada, ancla 0600.
  Respaldo pre-endurecimiento íntegro (8 eventos, checkpoint coherente, esquema v1).
- 2026-10-20: lectura y diagnóstico de los siete scripts; todos incompatibles con `64ac4f5`.
- 2026-10-20: reescritura completa de los siete scripts y del arnés, más `cutover_common.py`.
- 2026-10-20: batería segura 11/11 PASS (inspección, respaldo, verificación, restauración,
  rechazo sin `--force`, rechazo de base sin ancla, servidor efímero + verificación).
- 2026-10-20: ensayo integral 12 PASS + 2 PENDIENTES (Keycloak).
- 2026-10-20: suites del backend 39/39 verdes; `test_audit_monitor` 9/15 con los 6
  dependientes de Keycloak en ERROR/FAIL por realm inaccesible.

## Hallazgos operativos nuevos

1. **El rollback de solo código es inválido tras el cutover.** Probado empíricamente:
   el `database.py` anterior abre la base v2 y lanza `AuditChainCorruptedError`
   ("Firma criptográfica de anclaje (Anchor HMAC) inválida") porque usa la clave por
   defecto retirada. `rollback.sh` ahora detecta la incompatibilidad y aborta, salvo
   `--with-database` (restauración de la base emparejada, con pérdida explícita de los
   datos posteriores al cutover).
2. **`/home/elcra/backups` pertenece a `root:root` (0755).** El operador `elcra` no puede
   crear `pre_cutover/` ni `pre_restore/` con las rutas por defecto: los scripts fallan
   cerrado con el comando `sudo install -d ...` necesario. Se añadió `--safety-dir`.
3. **`PRAGMA synchronous` no es verificable desde fuera.** Es un ajuste por conexión con
   valor por defecto FULL; una conexión nueva siempre lee 2. El verificador comprueba
   `journal_mode` en la base y la directiva `PRAGMA synchronous=FULL` en el `database.py`
   desplegado.
4. **`docker-compose.yml` se parseaba con `json.load`.** Es YAML: el despliegue habría
   abortado. Ahora usa PyYAML (6.0.2 presente en el servidor) y falla cerrado si falta.
5. **El despliegue no copiaba `clinical_domain.py`.** El backend habría fallado al importar.
6. **La verificación post-cutover creaba una orden clínica real.** Ahora el modo por
   defecto es solo lectura y las pruebas IoMT son negativas contra un `order_id` `CANARY-`
   inexistente; la prueba positiva exige `--write-probe --canary-order-id`.

## Evidencia

| Prueba | Resultado |
| --- | --- |
| `bash -n` (5 scripts) | OK |
| `python3 -m py_compile` (4 módulos) | OK |
| Batería segura | 11/11 PASS |
| Ensayo integral | 12 PASS, 2 PENDIENTES |
| `post_cutover_verify` sobre servidor efímero | PASS=18 FAIL=0 SKIP=2 (INCOMPLETE) |
| Rollback v1 sobre base v2 | aborta con instrucciones |
| Rollback v1 + `--with-database` sin base | aborta |
| Rollback v2 sobre base v2 | continúa y verifica cadena |
| `test_candidate_lis` / `test_clinical_hardening` / `test_persistence_durability` / `test_phase2...` | 10+14+5+10 OK |
| `test_audit_monitor` | 9 OK, 6 pendientes por Keycloak |

