# SGSI-ZTA Hospital Lab — Frontend

Angular 22 standalone application with Angular Material 22 for the hospital laboratory
Zero Trust workflow. The first frontend phase runs entirely on synthetic mock data and can be
switched to the real Python/Keycloak backend through environment flags.

> **Synthetic data only.** Orders, patients, DNIs and audit events are fictional
> (`DEMO-0001`, `ORD-2026-0001`). Do not load real clinical data into this phase.

## Requirements

- Node.js 22.22+ (or 24.15+)
- npm 10+
- Windows PowerShell (commands below)

## Run in mock mode (default)

```powershell
cd C:\Users\elcra\Desktop\SGSI-ZTA-Integration\frontend
npm install
npm start
```

Open `http://localhost:4200`. The login screen offers four demo roles:

| Role | Access |
| --- | --- |
| Reception | Admission and order creation |
| Laboratory | Dashboard and indicators |
| Pathologist | Medical validation with simulated MFA |
| Security Auditor | Audit chain and indicators |

Demo authentication is stored in `sessionStorage` only. No tokens, passwords or real identities
are persisted. Clinical validation in demo mode requires pressing **Simulate MFA verification**
on the Medical validation screen.

Mock mode is controlled by `src/environments/environment.ts`:

```ts
useMockApi: true,
useMockAuth: true,
```

The mock API interceptor answers `/api/v1/orders`, `/api/v1/orders/validate`,
`/api/v1/audit/events` and `/health` with a 250 ms delay, the same paths and payloads as the
backend, and simulated `401/403/404/409` errors.

## Run against the real backend

1. Start the backend on `http://127.0.0.1:8000`.
2. Start Keycloak and import/configure the `hospital-lab` realm with the public client
   `clinical-poc` (no client secret).
3. Edit `src/environments/environment.ts`:

```ts
useMockApi: false,
useMockAuth: false,
apiBaseUrl: '',
```

4. Run `npm start`. The dev server proxies `/api` and `/health` to `http://127.0.0.1:8000`
   using `proxy.conf.json`, so no CORS configuration is required.
5. Use **Sign in with Keycloak**. The client uses authorization code flow with PKCE
   (`S256`), `check-sso`, and no login iframe.

Keycloak settings live in `src/environments/environment.ts` and
`src/environments/environment.prod.ts`. The production file contains the placeholder issuer
`https://servidor-1.tailb0f78a.ts.net:8443`; replace it with the deployed public issuer before
building. Production builds replace `environment.ts` automatically through `fileReplacements`
in `angular.json`.

## Backend contract used

| Method | Path | Roles |
| --- | --- | --- |
| GET | `/health` | Public |
| GET | `/api/v1/orders` | Reception, Lab, Pathologist |
| POST | `/api/v1/orders` | Reception |
| POST | `/api/v1/orders/validate` | Pathologist + MFA |
| GET | `/api/v1/audit/events` | Security Auditor |

Workflow: `CREATED` → `SAMPLE_COLLECTED` → `ANALYZED` → `VALIDATED_AND_RELEASED`.
The backend creates orders directly as `SAMPLE_COLLECTED`.

## Tests and build

```powershell
npm test -- --watch=false
npm run build
```

Tests use Vitest with jsdom, configured by Angular 22 through `@angular/build:unit-test`.
The suite covers auth state, mock API rules, status badges, dashboard role behavior, the app
root and functional guards.

The initial production bundle is approximately 679 kB raw / 149 kB transfer. The scaffold
budget is raised to 750 kB warning because Angular Material is part of the initial shell;
the error budget remains 1 MB. Keycloak is lazy-loaded in its own chunk.

## Project layout

```
src/app/
  core/            models, auth (signals, guards, interceptor), API + mock API
  layout/          responsive toolbar/sidenav shell
  features/        login, dashboard, admission, doctor, audit, indicators
  shared/          status badge and status label pipe
src/environments/  dev and production flags
proxy.conf.json    /api and /health -> 127.0.0.1:8000
```
