# ODD — Endurecimiento clínico del LIS candidato (sandbox)

**Feature:** `clinical-hardening`
**Repositorio:** `/home/elcra/sandbox-jwt-validator` (servidor-1)
**Rama:** `stage4-lis-candidate-release`
**Base:** `182564c`
**Fecha de apertura:** 2026-10-19
**Estado:** implementado y verificado

## Objetivo

Corregir en el sandbox los hallazgos P0 de **lógica clínica, integridad, auditoría y mínimo
privilegio** identificados en `OPENCODE_CUTOVER_AUDIT.md`, con pruebas negativas que
demuestren el fallo anterior y el éxito posterior. Entregar informe
`OPENCODE_CLINICAL_HARDENING.md` y commit local en la rama del sandbox.

## Problema

El LIS candidato (SQLite WAL + validación RS256) reproduce defectos que impiden un cutover
seguro: sobrescritura de órdenes por `order_id` repetido, degradación de órdenes liberadas
por el canal IoMT, validación médica sin resultados ni vínculo criptográfico real, escritura
clínica y auditoría no atómicas, borrado de auditoría no detectado, cadena rompible con dos
escritores, y un token M2M de auditor capaz de leer órdenes clínicas.

## Por qué

Sin estas correcciones no existe no repudio ni trazabilidad clínica verificable, y el
principio de menor privilegio se rompe entre el servicio de auditoría y la lectura clínica.
Son condiciones de dictamen NO-GO medidas en sandbox.

## Alcance autorizado

**Dentro:** `candidate_release/server.py`, `database.py`, `jwt_validator.py`,
`audit_monitor/monitor.py`, nuevo `clinical_domain.py`, suites de prueba del sandbox,
`MANIFEST.sha256`, informe `OPENCODE_CLINICAL_HARDENING.md`.

**Fuera (tareas posteriores, prohibido tocar):** `cutover_prep/*`, `docker-compose.yml`,
Keycloak, Docker, `/opt/sgsi-zta-hospital-lab`, `candidate_release/deploy_runbook.sh`.

**Restricciones absolutas:** no `--apply`, no desplegar, no reiniciar ni modificar
contenedores/Keycloak, no hacer push, no crear Angular, no modificar el realm principal.

## Hallazgos cubiertos

| ID | Hallazgo | Estado objetivo | Estado |
|---|---|---|---|
| C-03 | `order_id` repetido sobrescribe la orden | HTTP 409 + `INSERT` puro | Hecho |
| C-04 | IoMT degrada órdenes liberadas y crea órdenes | sin creación, bloqueo de órdenes liberadas, esquema validado | Hecho |
| C-05 | Validación médica sin resultados ni firma del contenido | estado `ANALYZED` + mediciones válidas + sello de integridad real | Hecho |
| C-06 | Orden y auditoría no atómicas | una única transacción SQLite | Hecho |
| C-07 | Borrado total de auditoría no detectado | comparación obligatoria contra checkpoint + fail-closed | Hecho |
| C-08 | Dos escritores rompen la cadena | lectura del último hash dentro de la transacción de escritura | Hecho |
| C-09 | Auditor M2M lee órdenes clínicas | `VIEW_ORDERS` por política + 403 para M2M; PHI pseudonimizada | Hecho |
| A-01 | Secretos por defecto hardcodeados | sin defaults; fail-closed | Hecho |
| A-02 | IoMT sin antirreplay ni separación por dispositivo | firma con device+timestamp+nonce, ventana temporal, registro de nonces | Hecho |
| A-04 | Monitor no falla visiblemente; lista vacía válida | lista vacía inválida, código de salida distinto de cero | Hecho |
| A-05 | `synchronous=NORMAL` y base 0644 | `synchronous=FULL`, base 0600, `umask 077` | Hecho |

## Decisiones de diseño

1. **Máquina de estados explícita** en `clinical_domain.py`:
   `CREATED → SAMPLE_COLLECTED → ANALYZED → VALIDATED_AND_RELEASED`.
   `VALIDATED_AND_RELEASED` es terminal. Transición ilegal → 409.
2. **Sello de integridad, no firma digital plena.** No existe gestión de claves asimétricas
   ni custodia de clave privada de médico, por lo que NO se declara firma digital. Se
   implementa `integrity_seal` = HMAC-SHA256 sobre el contenido canónico de la orden
   (incluye mediciones, paciente, actor, versión y sello temporal). El campo se llama
   `integrity_seal` y se acompaña de `seal_algorithm` y `seal_scope`; el nombre
   `digital_signature` se elimina para no inducir a error.
3. **Clave de anclaje de auditoría:** `AUDIT_HMAC_KEY` (entorno) o argumento explícito. Si
   no hay ninguno, se genera una clave aleatoria por base y se persiste en
   `<db>.anchor-key` con modo 0600. Si existe cadena previa y falta la clave, se falla el
   arranque. Se documenta el riesgo residual: clave junto a la base ≠ KMS/HSM.
4. **Transacción clínica única:** `run_clinical_transaction(operation, audit_event)` abre
   `BEGIN IMMEDIATE`, ejecuta la operación sobre la orden e inserta el evento de auditoría
   con el mismo cursor; cualquier error revierte ambos.
5. **Antirreplay IoMT:** nonce persistido en tabla `iomt_nonces` (durable), ventana de reloj
   configurable, clave por dispositivo desde `IOMT_DEVICE_KEYS_JSON`. Sin configuración de
   claves → 503 fail-closed (nunca clave por defecto).
6. **PHI:** los `details` de auditoría usan referencia pseudonimizada
   (`patient_ref` = sha256 truncado), nunca el DNI en claro.
7. **Mínimo privilegio:** el PEP usa `enforce_clinical_action` para `VIEW_ORDERS`
   (elimina la lista de roles duplicada en `server.py`, causa raíz de C-09). Las cuentas de
   servicio (`preferred_username` con prefijo `service-account-`) quedan restringidas a
   `VIEW_AUDIT_LOGS`.
8. **A-05:** se aplica `synchronous=FULL` porque el informe lo exige para el LIS clínico;
   la prueba que fijaba `NORMAL` se actualiza al nuevo requisito (no se relaja ninguna
   aserción, se cambia el valor esperado a la política auditada).

## Checklist de tareas

- [x] T1 — `clinical_domain.py`: estados, transiciones, esquema de mediciones, sello de
      integridad, pseudonimización de paciente.
- [x] T2 — `database.py`: migración v2 (`version`, `updated_at`, `iomt_nonces`),
      `synchronous=FULL`, permisos 0600, `umask`, clave de anclaje sin defaults,
      verificación estricta de checkpoint, cadena multi-escritor,
      `run_clinical_transaction`, `create_order`/`update_order` con versión,
      registro de nonces, `clear_audit_logs(confirm=True)`.
- [x] T3 — `server.py`: `POST /orders` atómico con 409; IoMT endurecido (sin creación,
      antirreplay, esquema, asociación de dispositivo); validación con estado/mediciones/
      sello; `GET /orders` por política; PHI pseudonimizada.
- [x] T4 — `jwt_validator.py`: detección de cuenta de servicio y denegación de acciones
      clínicas para M2M; política `VIEW_ORDERS` como única fuente de verdad.
- [x] T5 — `audit_monitor/monitor.py`: cadena vacía inválida, comparación con
      `audit_chain_valid` del servidor, código de salida distinto de cero.
- [x] T6 — Pruebas: actualizar las existentes afectadas y añadir
      `test_clinical_hardening.py` (14 casos) con casos negativos de cada hallazgo.
- [x] T7 — Ejecutar suites en el servidor y registrar cifras reales PASS/FAIL/SKIPPED.
- [x] T8 — Actualizar `MANIFEST.sha256`, escribir `OPENCODE_CLINICAL_HARDENING.md`.
- [x] T9 — Commit local en `stage4-lis-candidate-release`.

## Criterios de aceptación

1. Reproducción negativa de cada hallazgo C-03…C-09 y A-01/A-02/A-04/A-05 con prueba.
   → `/tmp/repro_findings.py`: 14/14 SAFE en el código nuevo, 14/14 VULNERABLE en `HEAD`.
2. Suites del sandbox en verde (salvo SKIPPED justificados y no atribuibles al cambio).
   → 110 pruebas en verde; 6 de `test_audit_monitor.py` bloqueadas por Keycloak ausente.
3. Sin regresión en `test_jwt_validator.py` y `test_lis_jwt_adapter.py`.
   → 54/54 OK.
4. Informe con cifras reales y riesgos pendientes declarados.
   → `OPENCODE_CLINICAL_HARDENING.md`.
5. Ningún archivo fuera del alcance autorizado modificado.

## Verificación

- `cd /home/elcra/sandbox-jwt-validator/candidate_release && python3 test_database.py`
- `python3 test_phase2_persistence_audit_integrity.py`
- `python3 test_candidate_lis.py`
- `python3 test_persistence_durability.py`
- `python3 test_clinical_hardening.py`
- `cd /home/elcra/sandbox-jwt-validator && python3 -m unittest test_jwt_validator test_lis_jwt_adapter`
- `python3 test_audit_monitor.py` (requiere Keycloak de pruebas en 127.0.0.1:8085; no se modifica)
- `python3 /tmp/repro_findings.py <directorio>` (comparativa RED/GREEN)

## Ruta de implementación

`delegated direct` — un único escritor acotado sobre el espejo local del sandbox
`candidate_release/` (disparador: el cambio toca 4+ archivos no triviales acoplados).
El escritor delegado se interrumpió a mitad de `server.py`; el orquestador completó los
endpoints restantes y asumió la verificación e iteración sobre el servidor.

## Estrategia de entrega

`local-commit` — la rama del sandbox recibe commits locales; push, PR y merge quedan
prohibidos por el alcance autorizado. El presupuesto de ~400 líneas es orientativo: la
corrección es un cambio coherente acoplado entre módulos, no una suma de cambios sueltos.

## Progreso

- 2026-10-19: conexión SSH verificada; rama `stage4-lis-candidate-release` @ `182564c`;
  sin cambios tracked; `candidate_release/data/lis.db` consistente (8 eventos, checkpoint
  conciliado, `integrity_check=ok`); base con modo 0644 confirmando A-05.
- 2026-10-19: línea base RED capturada (hallazgos reproducidos en el código original).
- 2026-10-20: implementación completada en `clinical_domain.py`, `database.py`,
  `jwt_validator.py`, `server.py`, `audit_monitor/monitor.py`.
- 2026-10-20: `data/lis.db` del sandbox respaldado en
  `/tmp/pre_hardening_backup/lis.db.pre-hardening` y regenerado: su ancla usaba la clave
  por defecto eliminada y ya no era verificable.
- 2026-10-20: `test_phase2_persistence_audit_integrity.py` ajustado a `synchronous=FULL`;
  `test_candidate_lis.py`, `test_audit_monitor.py` y `test_persistence_durability.py`
  adaptados al nuevo contrato IoMT y a `integrity_seal`.
- 2026-10-20: verificación final — 8+10+10+5+14 pruebas de `candidate_release` en verde,
  54 de la raíz en verde, 9/15 de `test_audit_monitor.py` en verde (6 bloqueadas por
  Keycloak ausente), y `repro_findings.py` 14/14 SAFE contra 14/14 VULNERABLE en `HEAD`.
- 2026-10-20: `MANIFEST.sha256` regenerado (11 archivos) y verificado con `sha256sum -c`.
