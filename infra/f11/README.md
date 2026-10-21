# F11 isolated runtime

Status: **prepared, not started**.

F11 is an isolated SGSI-ZTA Hospital Lab runtime for `servidor-1`. It does not
reuse the existing `sgsi-zta-*` containers, networks, or volumes, and it does not
use port `8000`.

## Topology

| Component | Runtime | Bind | Notes |
| --- | --- | --- | --- |
| Keycloak 26.8.0 | Docker Compose | `127.0.0.1:8085` | `start-dev`, realm `hospital-lab-local` |
| Frontend (Angular 22) | Docker Compose + Caddy (host network) | `127.0.0.1:4200` | Multi-stage build; static files served by Caddy |
| Backend (Python 3.13) | Host venv + optional systemd unit | `127.0.0.1:8010` | No backend container; avoids a Python image pull |
| SQLite | Host filesystem | `/home/elcra/sgsi-zta-runtime/f11/lis.db` | Outside the repository, mode `0700` directory |

The Caddy container uses host networking so it can reach the loopback-only
backend at `127.0.0.1:8010`. It binds only `127.0.0.1:4200` and disables Caddy's
admin API. This keeps the backend off the network and avoids Docker DNS/issuer
mismatch with Keycloak at `127.0.0.1:8085`.

## Isolation

- Compose project: `sgsi-zta-f11`.
- Containers: `sgsi-zta-f11-keycloak`, `sgsi-zta-f11-frontend`.
- Network: `sgsi-zta-f11-net` (explicit name) for Keycloak. The frontend uses
  host networking to reach the loopback-only backend; it does not join
  `sgsi-zta-f11-net`.
- Volume: `sgsi-zta-f11-keycloak-data` (explicit name).
- `restart: "no"` on both services; F11 never auto-starts after a reboot.
- No changes to `/opt`, the main Keycloak, existing containers, or other projects.
- No push and no cutover.

## Resource limits

| Component | CPU limit | Memory limit | CPU reservation | Memory reservation |
| --- | ---: | ---: | ---: | ---: |
| Keycloak | 1.00 | 1024 MiB | 0.25 | 256 MiB |
| Caddy frontend | 0.25 | 128 MiB | 0.05 | 32 MiB |
| Backend systemd unit | 50% of one CPU | 512 MiB | n/a | n/a |

Total configured limits: about **1.75 CPU** and **1664 MiB**. The limits are
ceilings, not a guarantee that the host has free memory.

### Conditions to start F11

Do not start F11 until all of these are true:

1. `MemAvailable` is at least **3 GiB** (`free -h`).
2. Load average is below **2.0**. If it is above **2.5**, wait for a quieter
   window.
3. There is no swap thrashing and no active maintenance or other heavy job.
4. Ports `8085`, `4200`, and `8010` are free.
5. The existing `sgsi-zta-*` containers remain healthy and untouched.

The current server state is **not** a safe start window: it has been heavily
loaded, with roughly 0.9 GiB free and load above 4.

## Secrets and local state

Generated locally on `servidor-1`, never transferred from Windows:

- `infra/f11/.env`: Keycloak bootstrap admin credentials.
- `infra/f11/backend.env`: backend discovery URL, audience, signing key, and
  synthetic IoMT device key.
- `/home/elcra/sgsi-zta-runtime/f11/`: SQLite database, credentials from realm
  provisioning, and other runtime state.

Both environment files are mode `0600` and ignored by Git. The runtime directory
is mode `0700`. The committed examples are `infra/f11/.env.example` and
`infra/f11/backend.env.example`; they contain placeholders only.

Do not print or commit the generated values. Do not copy them back to Windows.

## Python environment

`backend/.venv` is a local virtual environment. Debian's system Python does not
provide `ensurepip`, so `pip` was bootstrapped **inside the venv** with
`get-pip.py`. No global Python package was installed.

Installed state:

- Python `3.13.5`
- pip `26.2.2`
- `cryptography` `47.0.0`
- `pip check`: clean
- Backend AST parse: 11 files, 0 syntax errors

The backend entrypoint is `backend/server.py`; it uses only the standard library
plus `cryptography`. The host command is:

```bash
cd /home/elcra/sgsi-zta-integration/backend
set -a
. /home/elcra/sgsi-zta-integration/infra/f11/backend.env
set +a
./.venv/bin/python server.py
```

The process reads `HOST`, `PORT`, `LIS_DB_PATH`, and the OIDC/IoMT settings from
`infra/f11/backend.env`. The systemd unit loads that file directly.

## Images and build

Images already present on the server:

- `quay.io/keycloak/keycloak:26.8.0`
- `node:22-bookworm-slim` (frontend build stage)
- `caddy:2.11-alpine` (frontend runtime)

No image pull is expected for the prepared F11 stack. If a tag is missing, do
not pull it without explicit approval.

The frontend build is deferred. The first build will run `npm ci`, which
downloads npm packages; no global Node installation is used. The build command
is:

```bash
docker compose -f infra/f11/compose.yaml build frontend
```

The Dockerfile builds with `--configuration local-real` and
`--output-path=dist/f11`, then copies `dist/f11/browser` into Caddy.

## Start sequence (not executed)

Run only after the conditions above are met.

1. Validate the Compose model without starting containers:

   ```bash
   docker compose --env-file infra/f11/.env -f infra/f11/compose.yaml config --quiet
   ```

2. Start Keycloak only:

   ```bash
   docker compose --env-file infra/f11/.env -f infra/f11/compose.yaml up -d keycloak
   curl -fsS http://127.0.0.1:8085/realms/master >/dev/null
   ```

3. Provision the synthetic realm and users:

   ```bash
   set -a
   . infra/f11/.env
   set +a
   backend/.venv/bin/python infra/local-test/setup_realm.py \
     --keycloak-url http://127.0.0.1:8085 \
     --realm hospital-lab-local \
     --client-id clinical-poc \
     --redirect-uri http://127.0.0.1:4200/ \
     --admin-user "$KEYCLOAK_ADMIN_USERNAME" \
     --admin-password "$KEYCLOAK_ADMIN_PASSWORD" \
     --credentials-file /home/elcra/sgsi-zta-runtime/f11/credentials.json
   ```

4. Install and start the backend unit **only with explicit authorization**:

   ```bash
   sudo cp infra/f11/systemd/sgsi-zta-f11-backend.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl start sgsi-zta-f11-backend.service
   curl -fsS http://127.0.0.1:8010/health
   ```

   The unit is not installed or enabled by this preparation. It uses
   `MemoryMax=512M`, `CPUQuota=50%`, and a restricted systemd sandbox. If systemd
   installation is not authorized, the backend can be run manually, but it will
   not have cgroup CPU/RAM limits.

5. Build and start the static frontend:

   ```bash
   docker compose --env-file infra/f11/.env -f infra/f11/compose.yaml build frontend
   docker compose --env-file infra/f11/.env -f infra/f11/compose.yaml up -d frontend
   curl -fsS http://127.0.0.1:4200/ >/dev/null
   ```

6. Verify discovery and the UI, then run the real-stack E2E in a low-load window.

## Stop and cleanup

```bash
docker compose --env-file infra/f11/.env -f infra/f11/compose.yaml down
sudo systemctl stop sgsi-zta-f11-backend.service
```

`down` without `-v` preserves the Keycloak volume. Do not delete
`sgsi-zta-f11-keycloak-data` during normal operation. Do not remove the existing
`sgsi-zta-*` stack.

## Static checks

```bash
./infra/f11/static-check.sh
```

The script checks Python syntax without writing bytecode, `pip check`, the
Compose model, the systemd unit, whitespace, and the absence of
`silent-check-sso` references. It does not start containers, build images, or
start the backend.

## `silent-check-sso.html`

The file is **not required** for the current Keycloak Authorization Code + PKCE
flow. The codebase has no reference to it, and it remains only in the Windows
working copy as an untracked file. It is only useful for an iframe-based
`check-sso` optimization; it did not fix the intermittent AMR issue and is not
part of F11.

## Known limitations

- The intermittent Keycloak AMR behavior is unresolved. Do not claim full
  real-stack validation until the remote E2E is re-run and the evidence is
  captured.
- The first frontend build downloads npm packages; it is deferred.
- The backend systemd unit is prepared but not installed or enabled.
- The remote E2E paths and ports must be adapted to F11 before the full suite is
  considered valid.
