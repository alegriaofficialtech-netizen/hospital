# Feature: Frontend Angular + Material para SGSI-ZTA Hospital Lab

**Estado:** en progreso
**Fecha:** 2026-10-20
**Workspace:** `C:\Users\elcra\Desktop\SGSI-ZTA-Integration`
**Origen backend:** `/home/elcra/sandbox-jwt-validator` @ `9910290` (`stage4-lis-candidate-release`)
**Archivo recuperado:** `recovered/sandbox-jwt-validator` (solo archivos versionados; sin secretos ni datos clínicos)
**SHA-256 del archivo git:** `afba8a675e5dc15945499b870f50cb2bdd5f155152565199661b03f71ef134ac`

---

## 1. Objetivo

Completar el software del laboratorio con un frontend Angular + TypeScript + Angular Material que cubra login, dashboard, admisión, médico, auditoría e indicadores, primero con APIs simuladas y luego con las APIs reales del backend Python/SQLite/Keycloak.

## 2. Alcance

- **Sí:** frontend Angular, modelos, servicios, guards, mocks, tests, documentación y commits locales.
- **No:** producción, cutover, push, cambios en `/opt`, secretos, datos clínicos reales.
- **Backend:** se conserva el código versionado recuperado; no se reescribe la arquitectura Zero Trust. Los cambios de backend, si hacen falta endpoints de solo lectura, se hacen mínimos y con tests.

## 3. Inventario inicial

### Local (antes de recuperar)

- `jwt_validator.py`, `lis_server_adapter.py`, tests y scripts `scratch_*`.
- `candidate_release/` parcial (4 archivos), `OPENCODE_*.md`.
- Sin Angular, sin `package.json`, sin repositorio git propio (el home `C:\Users\elcra` es un repo enorme; no se usa para commits).

### Servidor (recuperado)

- Rama `stage4-lis-candidate-release`, HEAD `9910290`.
- `candidate_release/`: `server.py`, `database.py`, `clinical_domain.py`, `jwt_validator.py`, `audit_monitor/`, tests.
- `cutover_prep/`, `main_realm_prep/`, `migration_rehearsal/`, docs.
- Sin frontend.
- Sin archivos `.env`, claves privadas ni datos clínicos en `git ls-files`.

### API backend observada

| Método | Ruta | Rol / condición |
|---|---|---|
| GET | `/health` | público |
| GET | `/api/v1/orders` | `VIEW_ORDERS`: admisión, laboratorio, médico |
| POST | `/api/v1/orders` | `CREATE_ORDER`: admisión |
| POST | `/api/v1/orders/validate` | `VALIDATE_ORDER`: médico + MFA |
| GET | `/api/v1/audit/events` | `VIEW_AUDIT_LOGS`: auditor |
| POST | `/api/v1/iomt/results` | dispositivo IoMT (HMAC) |

Estados: `CREATED` → `SAMPLE_COLLECTED` → `ANALYZED` → `VALIDATED_AND_RELEASED`.
Roles: `admision`/`ROLE_RECEPTION`, `laboratorio`/`ROLE_LAB_TECH`, `medico`/`ROLE_PATHOLOGIST`, `auditor`/`ROLE_SECURITY_AUDITOR`.

## 4. Decisiones de arquitectura

- **Angular 22 standalone** + TypeScript estricto + SCSS + Angular Material.
- **Mock-first:** `environment.useMockApi = true`; un interceptor HTTP responde con datos sintéticos y aplica RBAC. La UI no cambia al conectar el backend real.
- **Auth:** `AuthService` con dos modos: demo (roles seleccionables, sin secretos) y Keycloak OIDC (`keycloak-js`, cliente público `clinical-poc`, sin client secret). En producción se apunta al issuer canónico.
- **API real:** `ApiService` contra `/health`, `/api/v1/orders`, `/api/v1/orders/validate`, `/api/v1/audit/events`; proxy de desarrollo a `http://127.0.0.1:8000`.
- **Dominio:** modelos TypeScript espejo del backend; estados y roles centralizados; sin lógica clínica duplicada más allá de presentación/validación de formulario.
- **Indicadores:** calculados en el cliente a partir de órdenes/auditoría; sin dependencia de charting pesada en la primera fase.
- **Datos:** solo sintéticos (`DNI-DEMO-*`, `ORD-DEMO-*`). Nunca datos reales.

## 5. Tareas

- [x] **F1 — Inventario y recuperación.** Verificar repo servidor, recuperar `git archive` versionado, comparar, no sobrescribir.
- [x] **F2 — Repo y entorno.** `git init` local, `.gitignore`, `backend/` desde `candidate_release`, venv Python, README de ejecución.
- [x] **F3 — Scaffold Angular.** `ng new` Angular 22, Material, routing, SCSS, proxy, entornos.
- [x] **F4 — Shell y navegación.** Layout Material, toolbar/sidenav, rutas lazy, guards de auth/rol, tema.
- [x] **F5 — Login.** Demo por rol + botón Keycloak; sesión, logout, persistencia segura en memoria/sessionStorage.
- [x] **F6 — Dashboard.** KPIs, órdenes recientes, estado de cadena de auditoría, accesos rápidos.
- [x] **F7 — Admisión.** Formulario reactivo, alta de orden, listado/filtros, estados y errores.
- [x] **F8 — Médico.** Bandeja de `ANALYZED`, detalle de mediciones, observaciones, validación con confirmación MFA demo.
- [x] **F9 — Auditoría.** Eventos, filtros, chip de cadena válida/inválida, detalle.
- [x] **F10 — Indicadores.** Órdenes por estado, volumen diario, tasa de validación, eventos de auditoría.
- [ ] **F11 — Integración real.** `ApiService` y proxy implementados; falta probar contra backend/Keycloak reales cuando estén disponibles. El modo mock sigue siendo el fallback.
  - [ ] **F11.1 — Entorno local aislado.** Keycloak de pruebas en WSL2/Docker, realm `hospital-lab-local`, puerto `8085`, sin reutilizar contenedores ni secretos de producción.
  - [ ] **F11.2 — Realm sintético y MFA real.** Roles, cliente público PKCE S256, mapper de audiencia, `oidc-amr-mapper`, flujo condicional TOTP para `mfa-required`, usuarios sintéticos.
  - [ ] **F11.3 — Backend real.** Arranque con discovery local, audiencia `clinical-poc-api`, `azp=clinical-poc`, SQLite aislada y claves sintéticas de IoMT.
  - [ ] **F11.4 — Modo real separado.** Configuración Angular `local-real` con `useMockApi=false` y `useMockAuth=false`; el modo mock sigue siendo el default.
  - [ ] **F11.5 — UI real.** Ocultar bypass demo en modo Keycloak; MFA derivada del token; no permitir “simular MFA” con OIDC real.
  - [ ] **F11.6 — E2E de backend.** Pruebas directas de tokens reales: admisión, laboratorio, médico con TOTP, auditoría y denegaciones RBAC/MFA.
  - [ ] **F11.7 — E2E de navegador.** Playwright con Authorization Code + PKCE, TOTP, admisión, liberación y auditoría.
  - [ ] **F11.8 — Evidencia y límites.** Documentar comandos, resultados observados, fallos de entorno y pendientes; commits locales.
- [x] **F12 — Tests, build y commits.** Unit tests de servicios/mocks/guards y componentes clave; `npm run build`; commits por unidad.

## 8. Progreso y evidencia (2026-10-21)

- Repo local inicializado; commit base `1a55ad9` con backend recuperado y scaffold Angular.
- Frontend implementado y comprometido en `90caef5`; 7 archivos de test, 21 tests; `npm test -- --watch=false` pasa.
- `npm run build` pasa; bundle inicial 678.90 kB raw / 148.53 kB transfer; warning budget ajustado a 750 kB, error 1 MB.
- `backend/test_candidate_lis.py`: 10 tests OK (proceso devuelve código 1 por advertencias de recursos SQLite en Windows; no hay fallos de aserción).
- Suite backend completa en Windows: 5 fallos/6 errores por permisos POSIX, Docker y Keycloak ausentes; documentado en `backend/README.md`. No se modificó el backend para ocultar esas diferencias.
- El dashboard y los indicadores ahora respetan el rol auditor: no solicitan `/api/v1/orders` (que el backend niega a auditoría); muestran solo auditoría.
- F11 pendiente de ejecución real, no de código.

## 6. Criterios de aceptación

- `npm run build` pasa sin errores.
- `npm test -- --watch=false` (runner que genere el scaffold) pasa.
- En modo mock: login por rol, dashboard, alta de orden, validación médica, auditoría e indicadores funcionan sin backend.
- RBAC de UI: admisión no valida, médico no crea, auditor no ve órdenes clínicas; el backend real sigue siendo la autoridad.
- No hay secretos, claves ni datos clínicos en el repo.
- `git log` local con commits por fase; sin push.
- README con pasos Windows: Node/npm, venv Python, backend, frontend, mock/real.

## 7. Riesgos

- Angular 22 + Node 22 puede requerir ajustes de test runner; se valida con el scaffold real.
- Keycloak local puede no estar disponible; el modo demo permite avanzar; la integración real se prueba cuando el backend/Keycloak estén arriba.
- El backend usa `http.server` y CORS no configurado; el proxy de Angular evita CORS en desarrollo.
- El repo home `C:\Users\elcra` es enorme; **no** ejecutar `git status` desde el home. Usar el repo anidado del workspace.
- No copiar `tls/`, `.env`, `candidate_release/data/` ni volúmenes; solo `git archive` versionado.
