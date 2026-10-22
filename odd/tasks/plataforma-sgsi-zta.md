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
| F2 | M2 Diagnostico + M3 Inventario: comprobadores reales y catalogo de activos | pendiente |
| F3 | M4 Matriz de riesgos + M5 Controles, derivados de lo que M2 y M3 hayan encontrado | pendiente |
| F4 | M6 Incidentes + M8 Indicadores sobre datos reales de la plataforma | pendiente |
| F5 | M9 Validacion por expertos y consolidacion de la evidencia por objetivo | pendiente |

## 5. Matriz de trazabilidad: modulo, objetivo, evidencia

| Modulo | O1 | O2 | O3 | O4 | Evidencia que produce | Estado |
|---|---|---|---|---|---|---|
| M0 | | | x | x | Flujo clinico completo con rol minimo, MFA obligatorio en la validacion y auditoria encadenada | real, verificado |
| M1 | | | x | x | Identidades sinteticas, roles del realm, denegaciones reales por rol y por MFA, eventos de gestion en la cadena | real, verificado (F1) |
| M2 | x | | | | Hallazgos con el comando que los produjo y su salida, sin juicio propio | pendiente |
| M3 | | x | | | Activos con su origen (contenedor, servicio, fichero) y su version | pendiente |
| M4 | | x | x | | Riesgos con probabilidad, impacto y severidad calculada, enlazados a activos y hallazgos | pendiente |
| M5 | | | x | | Estado de cada control con su evidencia enlazada; nunca "cumple" sin evidencia | pendiente |
| M6 | | | | x | Incidentes con deteccion, accion, cierre y su registro en auditoria | pendiente |
| M7 | | | x | x | Cadena de hash verificada y su checkpoint | real, verificado |
| M8 | | | | x | Indicadores con la consulta que los produce | pendiente |
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

## Cierre de la revision independiente de F2 (2026-10-22)

Dos revisiones independientes se hicieron sobre el rango `add81d6..HEAD`. La
primera encontro 13 defectos; la segunda verifico las correcciones y encontro
un bloqueante de fondo. Estado final:

### Corregido y verificado
- **Evidencia verificable**. Cada hallazgo guarda la operacion real que lo
  produjo, su resultado, la fecha, el estado y el **origen** del mecanismo
  (`keycloak_admin_api`, `filesystem`, `sqlite`, `docker_inspect`, `docker_exec`,
  `in_process`). El origen se emite desde la rama que se ejecuto, no desde una
  tabla estatica. Migracion 4. Ningun comprobador cita un comando que no corre.
- **Auditoria completa y atomica**. La siembra, el alta, la actualizacion y la
  evaluacion de activos escriben el dato y su evento en la **misma transaccion**
  (`run_clinical_transaction`): si la auditoria falla, no queda dato ni evento.
  Los ocho caminos de rechazo dejan evento `DENIED_*` sin filtrar el cuerpo.
- **`checker_ids`**: `null` ejecuta el catalogo, `[]` no ejecuta ninguno y una
  lista ejecuta exactamente esos. Probado en los tres casos, punta a punta.
- **Comprobador de MFA** ampliado a `MANAGE_IDENTITIES`, `RUN_DIAGNOSTICS` y
  `MANAGE_ASSETS`, incluyendo su pertenencia a `HUMAN_ONLY_ACTIONS`. Tiene prueba
  negativa: si una accion pierde la exigencia, el comprobador pasa a `failed`.
- **Angular** usa el mismo criterio de MFA que el backend (`amr` lista con
  `otp`/`totp`/`mfa-otp`, sin `acr`); la interfaz queda restrictiva ante la duda
  y la API sigue siendo la autoridad. Cuerpo JSON invalido responde 400 y no
  dispara la ejecucion completa.
- **Comprobadores sin efectos secundarios**: el del rol protegido ya no hace un
  `POST` de sonda; instrumenta el transporte y verifica el rechazo sin escribir.
- **Higiene**: las pruebas reutilizan nombres fijos (`prueba-f2-*`) y son
  idempotentes; la siembra se prueba en una base temporal con 11 activos y un
  unico `ASSET_SEED`.

### Minimo privilegio en el realm (sin debilitar MFA)
- `admin.sinmfa.test` tenia `sgsi-admin` sin OTP y no lo usaba ninguna prueba:
  se le retiro el rol y se **deshabilito** la cuenta. Se conserva como evidencia,
  sin acceso.
- `medico.sinmfa` conserva el rol **a proposito**: es el fixture que demuestra la
  denegacion por MFA en tres pruebas. Su hallazgo sigue abierto y documentado.
- `medico.test` sigue siendo el unico administrador funcional con TOTP.

### Evidencia
- Suite de API: **54/54** (27 previas + 27 de F2) contra la pila desplegada.
- Navegador real: el administrador con MFA ejecuta el diagnostico y ve la
  evidencia con su origen; el auditor ve los hallazgos y no puede ejecutar ni
  dar de alta; cero campos de contrasena en la aplicacion.
- Diagnostico en vivo: 10 comprobadores en verde y 2 en rojo legitimos
  (`CONTAINER_HARDENING` por el `cap_drop` de keycloak y
  `KC_MFA_ON_ADMIN_IDENTITIES` por el fixture). Un diagnostico que nunca falla
  no demuestra nada.

### Residual aceptado
- Las escrituras de ordenes clinicas previas siguen con su patron original; la
  atomicidad se aplico a todo el camino de F2.
- El servidor HTTP sigue siendo de un solo hilo (documentado, no cambiado).
- `CONTAINER_HARDENING` queda como hallazgo abierto: cerrarlo exige recrear
  keycloak con `cap_drop: ALL` y verificar el SSO, fuera del alcance de F2.

## Procedimiento pendiente: habilitar admin.test (manual, no ejecutado)

Ver `odd/tasks/procedimiento-enrolamiento-admin.md`. No se retira `sgsi-admin`
de `medico.test` hasta que `admin.test` se autentique con MFA y administre
usuarios de verdad.

