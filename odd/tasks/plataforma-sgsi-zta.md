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
