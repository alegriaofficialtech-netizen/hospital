# Plataforma SGSI-ZTA — objetivos de tesis, modulos y fases

Rama: `feat/f11-preflight-gate` (commits locales, sin push, sin cutover).
Servidor: `servidor-1` (`/home/elcra/sgsi-zta-integration`).

## 1. Que cambia

El laboratorio clinico deja de ser el producto. Pasa a ser **el modulo
demostrativo de Zero Trust**: un dominio real (admision, paciente,
validacion, auditoria) con el mismo modelo de identidades, permisos, MFA y
cadena de auditoria que usa el resto de la plataforma. Lo que se demuestra
aqui es el mecanismo, no el dominio clinico.

La plataforma cubre los cuatro objetivos de la tesis:

| # | Objetivo | Modulos que lo atienden |
|---|---|---|
| O1 | Diagnostico de seguridad | M2 Diagnostico |
| O2 | Inventario de activos, matriz de riesgos y vulnerabilidades | M3 Inventario, M4 Riesgos |
| O3 | Controles ISO 27001 y Zero Trust | M5 Controles |
| O4 | Gestion administrativa, monitoreo de incidentes, auditoria, indicadores de seguridad y validacion por expertos | M1 Identidad, M6 Incidentes, M7 Auditoria, M8 Indicadores, M9 Validacion |

## 2. Reglas de evidencia (no negociables)

1. **Sintetico y real son worlds distintos.** Los datos de la plataforma
   (identidades, ordenes, assets, hallazgos, incidentes) son sinteticos y se
   marcan como tales en la propia base y en la interfaz.
2. **La evidencia real es solo la del entorno F11**: la configuracion
   efectiva, los codigos, los eventos de auditoria encadenados por hash, las
   verificaciones ejecutadas y su salida. Un hallazgo de seguridad se cita con
   el comando que lo produjo.
3. **El sistema no diagnostica por opinion.** M2 solo publica hallazgos que
  yum ha ejecutado un comprobador y ha obtenido. Un juicio de un tercero se
   registra como opinion: autor, fecha, alcance y texto, nunca generado por
   la plataforma.
4. **Los controles se declaran con evidencia.** M5 no marca un control como
   implantado sin una evidencia enlazada (fichero, prueba o evento de
   auditoria). El estado por defecto de un control es "no evaluado".
5. **Trazabilidad biunívoca.** Cada modulo declara a que objetivo sirve y
   que evidencia produce. La matriz de la seccion 5 es la que se entrega.

## 3. Modulos

| Modulo | Que hace | Permisos | Persistencia | Pruebas |
|---|---|---|---|---|
| M0 Laboratorio (demostrativo Zero Trust) | ordenes clinicas, admision, validacion con MFA, auditoria | `ROLE_RECEPTION`, `ROLE_LAB_TECH`, `ROLE_PATHOLOGIST`, `ROLE_SECURITY_AUDITOR` | SQLite `clinical_orders`, `audit_events` (cadena por hash) | 12/12 API + login real con TOTP |
| M1 Identidad y acceso | alta, baja logica, roles y rotacion de identidades sinteticas | `ROLE_PLATFORM_ADMIN` + MFA obligatorio | Keycloak (identidades) + cadena de auditoria (gestion) | admin con MFA, admin sin MFA, sin rol |
| M2 Diagnostico de seguridad | comprobadores ejecutados que emiten hallazgos con su comando y su salida | `ROLE_PLATFORM_ADMIN`, `ROLE_SECURITY_AUDITOR` | SQLite `findings` | comprobadores con resultado esperado |
| M3 Inventario de activos | catalogo de software, servicios, contenedores e identidades | lectura para todos los autenticados | SQLite `assets` | alta, consulta, version |
| M4 Matriz de riesgos y vulnerabilidades | riesgos con probabilidad, impacto y severidad, y su relacion con activos y hallazgos | `ROLE_SECURITY_AUDITOR` (lectura), `ROLE_PLATFORM_ADMIN` (escritura) | SQLite `risks` | severidad calculada, traza |
| M5 Controles ISO 27001 y Zero Trust | catalogo de controles con estado y evidencia enlazada | `ROLE_SECURITY_AUDITOR` (consulta), `ROLE_PLATFORM_ADMIN` (evaluacion) | SQLite `controls`, `control_evidence` | estado por defecto "no evaluado" |
| M6 Monitoreo de incidentes | incidentes con deteccion, clasificacion, accion y cierre | `ROLE_SECURITY_AUDITOR` (gestiona), lectura para los demas | SQLite `incidents` | ciclo de vida completo |
| M7 Auditoria | ya existe: cadena inmutable y encadenada | `ROLE_SECURITY_AUDITOR` | SQLite `audit_events` + `audit_checkpoints` | verificacion de integridad de cadena |
| M8 Indicadores de seguridad | indicadores calculados sobre datos reales de la plataforma (KRI) | lectura para todos los autenticados | derivado, sin copia | valor calculado y su origen |
| M9 Validacion por expertos | registro de dictamenes externos: autor, fecha, alcance, veredicto, observaciones | `ROLE_SECURITY_AUDITOR` (consulta), `ROLE_PLATFORM_ADMIN` (captura) | SQLite `expert_reviews` | el sistema no genera dictamenes |

## 4. Fases

| Fase | Contenido | Estado |
|---|---|---|
| F0 | Base del laboratorio como modulo demostrativo: login real con OIDC/PKCE, permisos, MFA TOTP, auditoria encadenada, suite de 12 pruebas | **hecha** |
| F1 | M1 Identidad y acceso: API de administracion, permisos con MFA, baja logica, rotacion, auditoria de la gestion | **en curso** |
| F1b | M1 pantalla Angular de administracion de identidades, con el patron visual del login | pendiente |
| F2 | M2 Diagnostico + M3 Inventario: comprobadores reales y catalogo de activos | **cerrada** |
| F3 | M4 Matriz de riesgos + M5 Controles, derivados de lo que M2 y M3 hayan encontrado | **cerrada** |
| F4 | M6 Incidentes + M8 Indicadores sobre datos reales de la plataforma | pendiente |
| F5 | M9 Validacion por expertos y consolidacion de la evidencia por objetivo | pendiente |

## 5. Matriz de trazabilidad: modulo, objetivo, evidencia

| Modulo | O1 | O2 | O3 | O4 | Evidencia que produce | Estado |
|---|---|---|---|---|---|---|
| M0 | | | x | x | Flujo clinico completo con rol minimo, MFA obligatorio en la validacion y auditoria encadenada | real, verificado |
| M1 | | | x | x | Identidades sinteticas, roles del realm, denegaciones reales por rol y por MFA, eventos de gestion en la cadena | real, verificado (F1) |
| M2 | x | | | | 12 comprobadores ejecutables; cada hallazgo guarda la operacion real, su resultado, la fecha, el estado y el origen del mecanismo (API de Keycloak, ficheros, SQLite, docker inspect). RBAC de lectura y escritura con MFA, e historial de ejecuciones | real, verificado (F2) |
| M3 | | x | | | Inventario de los componentes reales con clasificacion, criticidad, responsable, origen, version y marca de sintetico; alta y edicion con MFA, e historial de evaluaciones por activo | real, verificado (F2) |
| M4 | | x | x | | Riesgos con probabilidad, impacto y severidad calculada, enlazados a activos reales de M3 y a hallazgos reales de M2: `finding_id` apunta al hallazgo y `source_checker` guarda el comprobador de origen. Historial de revisiones y matriz 5x5 | real, verificado (F3) |
| M5 | | | x | | Estado de cada control con su evidencia enlazada; nunca "cumple" sin evidencia (HTTP 400 `CONTROL_EVIDENCE_MISSING`). Controles alineados a ISO/IEC 27001:2022, NIST SP 800-207 y CISA ZTM | real, verificado (F3) |
| M6 | | | | x | Incidentes con deteccion, accion, cierre y su registro en auditoria | pendiente |
| M7 | | | x | x | Cadena de hash verificada y su checkpoint | real, verificado |
| M8 | | | | x | Indicadores con la consulta que los produce. Parcial: ya son reales los del diagnostico y el inventario (reparto por estado, severidad, objetivo, clasificacion y criticidad, cada uno con su campo de origen) | parcial, verificado (F2) |
| M9 | | | | x | Dictamenes de terceros con autor, fecha y alcance; generados por la plataforma: ninguno | pendiente |

## 6. Lo que ya esta resuelto y sirve de base

- Identidad real en Keycloak con PKCE S256, JWT RS256, roles mapeados y MFA
  TOTP. El formulario de acceso es de Keycloak, con tema propio del hospital.
- La cadena de auditoria es inmutable y encadenada por hash, con checkpoint.
- El gate de preflight con evidencia termica real, y el supervisor con corte a
  88 C sostenidos.
- La suite de 12 pruebas de API sobre el stack real.

## 7. Reglas operativas heredadas

- Nada de Push ni cutover. Un solo repositorio, rama declarada.
- Los datos sinteticos se marcan como sinteticos en la base y en la pantalla.
- Ninguna credencial se devuelve al navegador mas de una vez y nunca entra en
  la auditoria.
- El build solo se ejecuta con preflight favorable y monitor a 88 C.

## Acceso unico en Keycloak (2026-10-22)

### Objetivo
Una sola experiencia visual de inicio de sesion: el formulario de credenciales
vive en Keycloak con el diseno del hospital, y Angular deja de capturar
credenciales.

### Cambios
- [x] Diseno del hospital volcado al tema de Keycloak
      (`infra/f11/keycloak-theme/sgsi-zta/login/`): mismo CSS del usuario, iconos
      en SVG en linea, imagen `frontend/public/lab-background.jpg` como recurso
      del tema, textos nuevos en `messages_es.properties`.
- [x] `login.component.*` de Angular convertido en traspaso: sin formulario, sin
      `ngModel`, sin contrasena de ejemplo (`demo.reception` / `Clinica2026!`).
- [x] `AuthService.homeRoute()`: cada rol entra en su panel
      (recepcion -> admision, patologo -> medico, auditor -> auditoria,
      administrador -> administracion, tecnico -> dashboard). El retorno OIDC
      apunta a `/login` para que la decision de panel este en un solo sitio.
- [x] Canal publico de solicitud de cuenta `POST /api/v1/identity-requests`:
      valida, acota por origen (5/hora) y registra `IDENTITY_REQUEST` en la
      cadena de auditoria. No concede acceso ni habilita autorregistro.
- [x] Pantalla publica `/solicitud-cuenta` en Angular, enlazada desde el tema.
- [x] Dockerfile del tema: una sola fuente de verdad (antes copiaba un
      directorio duplicado y servia la version vieja del CSS).
- [x] `client.baseUrl` definido (`http://localhost:4200/`) para el enlace de
      solicitud, y `baseUrl`/`rootUrl` tambien en el bootstrap del realm.

### Evidencia
- Suite de API: **27/27** (`infra/f11/run-api-tests.sh`): 22 previas + 5 nuevas
  (`test_f11_identity_request.py`).
- Navegador real (Chrome headless via CDP, tunel del operador):
  `/login` redirige al tema de Keycloak, login real de `recepcion.test` ->
  `/admision`, 0 campos de contrasena en la aplicacion, envio real de solicitud
  con referencia `REQ-...`, cierre de sesion que vuelve al formulario de
  Keycloak sin bucle.
- Capturas: `/home/elcra/sgsi-zta-runtime/f11/capturas/` (01 a 05).
- Auditoria: 416 eventos, con `IDENTITY_REQUEST` en `REQUESTED`, `REJECTED` y
  `RATE_LIMITED`.

### Pendiente
- `admin.test` sigue sin TOTP enrolled: no hay administrador independiente, por
  lo que `sgsi-admin` permanece en `medico.test`.
- F2 (diagnostico + inventario) sin iniciar: tablas `security_findings`,
  `diagnostic_runs` y `assets`, 12 comprobadores ejecutables, O1/O2.

## F2: M2 Diagnostico + M3 Inventario (2026-10-22)

### Objetivo
O1 (diagnostico de seguridad) y O2 (inventario de activos, base de la matriz de
riesgos). La evidencia es la configuracion efectiva del laboratorio F11: cada
hallazgo conserva el comando que lo produjo y su salida.

### M2 Diagnostico de seguridad
- [x] 12 comprobadores ejecutables (`backend/security_diagnostics.py`) sobre la
      configuracion real: PKCE S256 del cliente, autorregistro y reset de
      contrasena deshabilitados, MFA en las identidades con rol de plataforma,
      rol protegido no concedible, login local delegado a Keycloak, MFA
      obligatoria para administrar, cadena y checkpoint de auditoria, bundle
      Angular sin campos de contrasena, endurecimiento de contenedores y
      permisos 0600 de los ficheros de datos.
- [x] Persistencia de `diagnostic_runs` y `security_findings` (migracion 3).
- [x] Historial de ejecuciones, hallazgos con evidencia y resumen de indicadores.
- [x] RBAC: `VIEW_DIAGNOSTICS` (auditor y plataforma) y `RUN_DIAGNOSTICS`
      (plataforma **con MFA**, solo humano). Denegaciones reales comprobadas.
- [x] Auditoria: `DIAGNOSTIC_RUN` en la cadena por hash.

### M3 Inventario de activos
- [x] Catalogo de los 11 componentes reales del laboratorio, con clasificacion
      (`container`, `service`, `dataset`, `identity_store`, `code`,
      `configuration`), criticidad, responsable (rol, nunca una persona), origen
      (`compose`, `runtime`, `manual`), version y marca de sintetico.
- [x] Persistencia de `assets` y `asset_evaluations` (migracion 3).
- [x] Alta, actualizacion con `revision` incremental y **historial de
      evaluaciones** por activo.
- [x] RBAC: `VIEW_ASSETS` para cualquier identidad autenticada y
      `MANAGE_ASSETS` para la plataforma **con MFA**.
- [x] Auditoria: `ASSET_CREATE`, `ASSET_UPDATE` y `ASSET_EVALUATE`.

### Hallazgos reales sobre el propio laboratorio (O1)
El diagnostico no es decorativo: sobre la configuracion viva del F11 produce
cuatro hallazgos abiertos, entre ellos dos que son整改 pendientes y dos que son
fixtures deliberados de la propia suite:
- `KC_MFA_ON_ADMIN_IDENTITIES` (failed): `medico.sinmfa` y `admin.sinmfa.test`
  tienen el rol `sgsi-admin` **sin credencial OTP**. Son las identidades que la
  suite usa para demostrar la denegacion por MFA; el hallazgo es real y explica
  por que la puerta de administracion exige MFA.
- `CONTAINER_HARDENING` (failed): el servicio `keycloak` del compose no declara
  `cap_drop: ALL` (el de `frontend` si lo cumple).

### Evidencia
- Suite de API: **45/45** (27 previas + 18 de F2), `infra/f11/run-api-tests.sh`.
- Navegador real (Chrome headless por CDP): `/diagnostico` ejecuta los
  comprobadores con el administrador con MFA y muestra 24 hallazgos con su
  comando y su salida; `/inventario` lista 13 activos con sus indicadores y su
  historial; el auditor ve los hallazgos pero no puede ejecutar ni dar de alta.
- Correccion de un fallo previo discovered durante la verificacion: el frontend
  no mapeaba `sgsi-admin` a `ROLE_PLATFORM_ADMIN`, de modo que
  `/administracion` era inalcanzable en la aplicacion.

### Pendiente
- `admin.test` sigue sin TOTP enrolled y **sin ningun rol del realm**: cuando se
  enrolle hay que asignarle `sgsi-admin` y `mfa-required`, verificar el acceso
  real a `/administracion`, y solo despues retirar `sgsi-admin` de `medico.test`
  conservando su rol medico.
- F3 (M4 Matriz de riesgos + M5 Controles) puede apoyarse en los hallazgos y el
  inventario ya reales.

## Cierre formal de F2 (2026-10-22)

F2 queda cerrada sobre tres revisiones independientes y una suite de 55 casos.
Lo que sigue es el estado real, sin presentar como resuelto lo que no lo esta.

### Que hace F2

**M2 Diagnostico de seguridad (O1).** Doce comprobadores ejecutables contra la
configuracion efectiva del laboratorio F11: PKCE S256, autorregistro y reset de
contrasena deshabilitados, MFA en las identidades con rol de plataforma, rol
protegido no concedible, login local delegado a Keycloak, MFA obligatoria en las
acciones sensibles, cadena y checkpoint de auditoria, bundle Angular sin campos
de contrasena, endurecimiento de contenedores y permisos 0600 de los datos.
Cada hallazgo guarda la operacion real, su resultado, la fecha, el estado y el
origen del mecanismo; no se cita ningun comando que no se haya ejecutado.

**M3 Inventario de activos (O2).** Once componentes reales con clasificacion,
criticidad, responsable (rol, nunca una persona), origen, version y marca de
sintetico, mas alta, edicion e historial de evaluaciones. Es la base de la
matriz de riesgos de M4.

### Hallazgos de las revisiones y su estado

| # | Defecto | Estado |
|---|---|---|
| C1 | La siembra del inventario no dejaba evento de auditoria | corregido: siembra y evento en una transaccion; fallo de siembra detiene el arranque |
| C2 | `checker_ids: []` ejecutaba los 12 comprobadores | corregido: `null` = catalogo, `[]` = ninguno, lista = esos |
| C3 | Ocho rechazos F2 sin evento en la cadena | corregido: `DENIED_*` en los ocho caminos, sin filtrar el cuerpo |
| C4 | `evidence_command` citaba comandos que no se ejecutaban | corregido: se guarda la operacion real |
| C5 | El comprobador de MFA solo vigilaba `MANAGE_IDENTITIES` | corregido: las tres acciones y su pertenencia a `HUMAN_ONLY_ACTIONS` |
| C6 | Un titulo afirmaba mas de lo que comprobaba | corregido: titulo y descripcion describen la comprobacion real |
| C7 | Un cuerpo JSON invalido disparaba la ejecucion completa | corregido: 400 sin ejecutar nada |
| C8 | La validacion del nombre vivia solo en la capa HTTP | corregido: misma regla en persistencia |
| C9 | El frontend aceptaba una MFA que el backend rechaza | corregido: mismo criterio (`amr` lista, sin `acr`); la API sigue siendo la autoridad |
| C10 | El campo `version` no se podia borrar | corregido: "no enviado" y "null" son distinguibles |
| N1 | El run de diagnostico no era atomico con su evento | corregido: run, hallazgos y `DIAGNOSTIC_RUN` en una transaccion (`test_28`) |
| N2 | La siembra comprueba el evento fuera de su transaccion (TOCTOU) | documentado como limitacion: fail-closed con un unico proceso |
| N3 | El fallback de origen disfrazaba omisiones | corregido: centinela `undeclared`, que la prueba rechaza |
| N4 | El arnes de pruebas era mas laxo que el backend con `amr` | corregido: mismo criterio, solo puede dar falsos negativos |

### Verificacion

- **55/55 pruebas de API** (27 previas + 28 de F2) contra la pila desplegada.
- **Migraciones 4 y 5** aplicadas: `security_findings.evidence_source` existe y la API lo publica; 252 hallazgos historicos regularizados con su origen determinista.
- **Atomicidad probada por mutacion**, no por lectura: `test_27` fuerza el fallo
  de auditoria y exige que no quede el activo; `test_28` hace lo mismo con la
  ejecucion y sus hallazgos. Se rompio la implementacion a proposito y ambas
  pruebas fallaron, luego se restauro.
- **Navegador real**: el administrador con MFA ejecuta el diagnostico y ve la
  evidencia con su origen; el auditor ve los hallazgos y no puede ejecutar ni
  dar de alta; cero campos de contrasena en la aplicacion.
- **Diagnostico en vivo**: 10 comprobadores en verde y 2 en rojo legitimos
  (`CONTAINER_HARDENING` por el `cap_drop` de keycloak y
  `KC_MFA_ON_ADMIN_IDENTITIES` por el fixture). Un diagnostico que nunca falla
  no demuestra nada.

### Minimo privilegio en el realm

- `admin.sinmfa.test` tenia `sgsi-admin` sin OTP y no lo usaba ninguna prueba:
  se le retiro el rol y se deshabilito la cuenta. Se conserva como evidencia.
- `medico.sinmfa` conserva el rol **exclusivamente como fixture sintetico** de
  la denegacion por MFA. No es un acceso administrativo efectivo: sin segundo
  factor la API le responde 403 y la interfaz no le habilita la accion.
- `medico.test` es el administrador provisional con TOTP hasta que `admin.test`
  se enrolle y se verifique.

### Limitaciones declaradas

- La siembra del inventario comprueba su evento en una transaccion distinta de
  la insercion (TOCTOU). Con un unico proceso es correcta y fail-closed; con dos
  arranques concurrentes el segundo aborta. Decidido y documentado, no oculto.
- El servidor HTTP sigue siendo de un solo hilo: una ejecucion de diagnostico
  bloquea la API durante su duracion.
- `CONTAINER_HARDENING` queda abierto: cerrarlo exige recrear keycloak con
  `cap_drop: ALL` y verificar el SSO, fuera del alcance de F2.
- `insert_asset`, `update_asset` e `insert_asset_evaluation` siguen siendo
  llamables sin auditoria; hoy solo los usan las pruebas. Es una trampa para un
  llamador futuro y esta anotado.
- El inventario acumula activos `prueba-f2-*` de las ejecuciones de la suite;
  no se borran porque no hay endpoint de borrado y borrarlos ocultaria el
  historial de evaluacion.

## Procedimiento pendiente: habilitar admin.test (manual, no ejecutado)

Ver `odd/tasks/procedimiento-enrolamiento-admin.md`. No se retira `sgsi-admin`
de `medico.test` hasta que `admin.test` se autentique con MFA y administre
usuarios de verdad.


## Cierre de F3: M4 Gestion de Riesgos y M5 Gestion de Controles (2026-10-22)

F3 queda implementada y verificada sobre la rama `feat/f11-f3-risks-controls`, cubriendo los Objetivos O2 y O3 de la tesis doctoral.

### Que hace F3

**M4 Matriz de Riesgos y Vulnerabilidades (O2)**:
- Modelo de evaluacion formal 5x5: calculo automatico y determinista de nivel inherente y residual (`BAJO`, `MEDIO`, `ALTO`, `CRITICO`).
- Siembra automatica, idempotente y auditada de riesgos semilla asociados a los activos reales de M3 y hallazgos reales de M2 (`RSK-SEED`).
- Trazabilidad biunivoca con controles de mitigacion y registro de revisiones incrementales.
- Endpoints REST `/api/v1/risks`, `/api/v1/risks/summary`, `/api/v1/risks/{id}`, `/api/v1/risks/{id}/controls` con soporte para filtrado por categoria, estado, nivel de riesgo y activo.
- RBAC estricto: lectura permitida para `ROLE_SECURITY_AUDITOR` y `ROLE_PLATFORM_ADMIN`; mutaciones y vinculaciones restringidas exclusivamente a `ROLE_PLATFORM_ADMIN` con MFA verificado (`MANAGE_RISKS`).

**M5 Catalogo de Controles de Seguridad (O3)**:
- Catalogo de controles alineado a marcos normativos internacionales: ISO/IEC 27001:2022, NIST SP 800-207 (Zero Trust) y CISA Zero Trust Maturity Model.
- Regla de oro de evidencia: un control jamas puede pasar al estado `VERIFICADO` sin referencia real a evidencia observada (`test_suite`, `checker_run`, `audit_event`, etc.). Los intentos de transicion sin evidencia son rechazados con HTTP 400 (`CONTROL_EVIDENCE_MISSING`).
- Verificacion formal de controles via `/api/v1/controls/{id}/verify` registrando evidencia fechada, fuente, resultado y operador con MFA.
- Persistencia atomica de transacciones y auditoria (`run_clinical_transaction`): ante cualquier anomalia en el registro del evento criptografico SHA-256, la mutacion del control o riesgo es revertida integramente.
- Endpoints REST `/api/v1/controls`, `/api/v1/controls/summary`, `/api/v1/controls/{id}`, `/api/v1/controls/{id}/verify` con soporte para filtrado por marco normativo, estado y rol responsable.

**Aislamiento de Rate-Limiting entre Ejecuciones**:
- Soporte para cabecera `X-Forwarded-For` en peticiones de loopback local para desacoplar suites de pruebas sinteticas (`test_f11_identity_request.py`).
- Endpoint administrativo `/api/v1/admin/rate-limits/reset` protegido por rol de administracion de plataforma y MFA verificado para reinicio higienico de contadores en memoria.
- Validacion consecutiva back-to-back: 5/5 pruebas aprobadas en dos ejecuciones sucesivas sin contaminacion por codigo 429.

### Verificacion

- **89/89 pruebas de API aprobadas** (55 de F2 + 34 de F3) en `infra/f11/run-api-tests.sh` ejecutadas contra la pila real en Debian (`servidor-1`).
- **Migraciones 6 y 7 aplicadas**: tablas `risks`, `controls`, `risk_controls` y `control_evidences` con indices y claves foraneas consistentes. La migracion 7 anade `risks.source_checker`, aditiva e idempotente, con reparacion de los datos ya sembrados.
- **Atomicidad y rollback verificados por prueba destructiva**: `test_14` (riesgos), `test_16` (controles) y `test_17` (evidencias de verificacion) fuerzan fallos de auditoria demostrando reversion total sin registros huerfanos.
- **Cadena criptografica SHA-256 integra**: `test_15` valida el encadenamiento de hashes `prev_hash` -> `hash` para la totalidad de eventos de auditoria emitidos durante las operaciones de F3.
- **Integracion Frontend**:
  - Rutas y componentes independientes para `/riesgos` y `/controles` con vistas de lista, filtros, matrices y dialogos de verificacion.
  - Tarjetas de resumen en el dashboard de indicadores (`/indicadores`) consumiendo M4 y M5.
  - Navegacion lateral en `shell.component.ts` con control de visibilidad por rol.

### Correcciones aplicadas tras la revision de F3

La primera entrega de F3 aprobaba las pruebas pero tenia nueve defectos reales, todos corregidos y con prueba:

| Defecto | Que estaba mal | Correccion |
|---|---|---|
| D1 | la siembra de enlaces riesgo-control tragaba excepciones y podia terminar con la matriz de trazabilidad cortada sin dejar rastro | `ControlSeedError`: un enlace que falla, o un extremo inexistente, aborta la siembra nombrando el par y la causa (fail-closed) |
| D2 | el alta manual de un riesgo enviaba `asset_name`/`finding_checker`, que el backend solo resuelve durante la siembra: todo riesgo creado desde la interfaz quedaba sin vinculo con M3 ni con M2 | el formulario usa selectores de activo y hallazgo y envia `asset_id`/`finding_id` reales |
| D3 | el auditor veia botones de gestion de controles que la API le rechazaba con 403 | el criterio de la interfaz es el mismo que el del backend: rol de plataforma **y** MFA acreditada |
| D4 | el cliente declaraba `synthetic: 1` como si fuera su decision | la sinteticidad la impone el servidor y el cliente no la envia |
| D5 | la siembra guardaba el **codigo del comprobador** en la columna `finding_id` de `risks`: la trazabilidad O1->O2 apuntaba a un texto que no era un hallazgo | `finding_id` guarda el id de un hallazgo real de la ultima ejecucion, o `null`; el comprobador pasa a la columna nueva `source_checker` |
| D6 | el contrato de TypeScript declaraba campos que la API nunca devuelve | el contrato es la copia fiel de lo que la API acepta y devuelve |
| D7 | el alta de controles tampoco forzaba la sinteticidad en el servidor | el servidor la impone en el alta y la ignora en la edicion |
| D8 | los KPI de resumen de M4 y M5 se renderizaban vacios: el tipo del servicio y las plantillas usaban nombres historicos que la API no devuelve | tipo y plantillas alineados con la respuesta real, con prueba que contrasta la forma y los totales |
| D9 | el contrato de controles declaraba `synthetic` y `timestamp` inexistentes | contrato limpio |

### Verificacion en navegador real (F3)

Verificacion con Chrome real sobre la pila desplegada, con capturas en `/home/elcra/sgsi-zta-runtime/f11/capturas/shots-f3/` (series 20 a 28).

- **M4 como administrador**: 14 riesgos listados, KPI de total coincidente con las filas listadas (14), KPI de severidad inherente y residual presentes, distribucion por categoria con datos, matriz 5x5 visible, alta accesible con selectores de activo y hallazgo, y detalle con el hallazgo o el comprobador de origen.
- **M5 como administrador**: 31 controles listados, 62.9 por ciento de cumplimiento verificado (16 de 31), reparto por estado y marcos normativos (ISO/IEC 27001:2022 26, NIST SP 800-207 2, CISA ZTM 3), alta accesible.
- **Como Oficial de Seguridad (auditor)**: lee la matriz y el catalogo con sus KPI, y **no** ve ninguna accion de gestion ni de verificacion. La interfaz coincide por fin con lo que la API ya imponia con 403.
- **Login unico**: cero campos de contrasena en la aplicacion en todas las pantallas recorridas.

### Limitaciones de F3

- **TOCTOU en la verificacion de controles** (anotada en `control_management.py`): entre la comprobacion de que el control no esta verificado y la escritura existe una ventana teorica. Ambas operaciones comparten transaccion (`run_clinical_transaction`) y la unicidad de la evidencia la cierra en la practica.
- La comprobacion automatica del dialogo de verificacion no logro seleccionar el estado "PROPUESTO" en el componente `mat-select`, porque el guion de verificacion solo pulsa botones del DOM. Es una limitacion del guion, no de la aplicacion: la regla de evidencia esta cubierta por las pruebas de API y por las 16 verificaciones reales visibles en el catalogo.

### Estado de Cuentas y Privilegios

- `medico.test` conserva privilegios provisionales de administracion con TOTP (`sgsi-admin` + `mfa-required`) hasta la inscripcion formal de MFA para `admin.test`.