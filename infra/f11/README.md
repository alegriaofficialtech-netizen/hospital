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

## E2E preparation

The E2E suite has two real checks. Neither uses simulated MFA:

1. Python direct API E2E (`tests/e2e/test_real_stack.py`) obtains tokens through
   Keycloak Authorization Code + PKCE, completes the real TOTP challenge, checks
   JWT `alg`, `iss`, `aud`, and `azp`, then exercises RBAC and the full clinical
   release flow.
2. Playwright UI E2E (`frontend/e2e/real-stack.spec.ts`) signs in through Angular,
   completes the real TOTP challenge, and verifies route guards, admission,
   IoMT ingestion, medical release, audit, and denied access.

Prepare the E2E device secret from the ignored backend environment:

```bash
./infra/f11/prepare-e2e-secrets.sh
```

This writes `/home/elcra/sgsi-zta-runtime/f11/e2e-secrets.json` with mode `0600`.
Realm provisioning writes `/home/elcra/sgsi-zta-runtime/f11/credentials.json`.

After F11 is running and healthy:

```bash
./infra/f11/health-check.sh
./infra/f11/run-e2e.sh
```

`run-e2e.sh` delegates admission control to `infra/f11/preflight-gate.sh
--stage e2e` (see "Preflight gate"): CPU pressure, load normalised by core
count, memory, swap, temperature, host stability and stack state. It then runs
the Python E2E with the host venv, and runs the prebuilt Playwright container
`sgsi-zta-f11-e2e:local` with `--network host` and CPU/RAM/PID limits. Build and
test are separate stages: `infra/f11/build-images.sh` produces that image once,
so a test run never compiles anything. No global Node is installed.
`F11_CHROMIUM_NO_SANDBOX=1` is used only for the isolated root test container.

E2E inputs:

- `F11_BASE_URL` default `http://127.0.0.1:4200`
- `F11_API_BASE_URL` default `http://127.0.0.1:8010`
- `F11_CREDENTIALS_FILE` default `$F11_RUNTIME_DIR/credentials.json`
- `F11_SECRETS_FILE` default `$F11_RUNTIME_DIR/e2e-secrets.json`
- `F11_RUNTIME_DIR` default `/home/elcra/sgsi-zta-runtime/f11`

The first Playwright image build downloads npm dependencies and Chromium. It is
a one-time Stage B step (`build-images.sh`), gated and skippable when the image
is already present.

## Preflight gate

`infra/f11/preflight-gate.sh` is the single admission control for every F11
stage. It replaced the previous `load1 < 2.0` check in `run-e2e.sh`.

### Why the old gate was miscalibrated

`load1` counts runnable and uninterruptible tasks and is **not normalised by the
number of CPUs**. servidor-1 is an Intel i7-6500U (2 physical cores, 4 threads,
15 W TDP) that also runs roughly 600 tasks and 95 containers. Measured over a
3 h window:

| Signal | Measured |
|---|---|
| `load1` | min **2.29** · p10 3.30 · avg 4.76 · p90 6.26 · max 8.10 |
| samples with `load1 < 2.0` | **0 of 181 (0 %)** |
| CPU busy | avg 58.1 % (p10 51.3 %, p90 62.6 %) |
| PSI cpu `some avg60` | 20.6 % |
| PSI memory `some avg60` | 0.0 % |
| MemAvailable | 4.5–4.7 GiB |

The old gate refused **every** run while the host still had measurable CPU and
memory headroom, and it would have refused forever: a 4-thread host doing real
work has a structural load floor above 2.0. A fixed load number is not portable
across machines and cannot distinguish "busy because 95 containers have a
heartbeat" from "saturated".

### Signals and thresholds

Blocking signals are marked **B**, advisory ones **A**.

| Signal | Source | build | up | e2e |
|---|---|---|---|---|
| **B** CPU pressure `some avg60` | `/proc/pressure/cpu` | fail > 55 % · warn > 35 % | fail > 45 % · warn > 30 % | fail > 45 % · warn > 30 % |
| **B** load15 / nproc | `/proc/loadavg` | fail > 1.5× · warn > 1.0× | fail > 1.5× · warn > 1.0× | fail > 1.5× · warn > 1.0× |
| **B** load trend | `load1` vs `load15` | fail if `load1 > 1.8×load15` **and** `load1 > nproc` | same | same |
| **B** MemAvailable | `/proc/meminfo` | fail < 4096 MiB · warn < 5120 MiB | fail < 3584 MiB | fail < 3072 MiB (same 3 GiB floor as before) |
| **B** swap used | `/proc/meminfo` | fail > 25 % · warn > 10 % | same | same |
| **B** swap activity | `pswpout` delta / 5 s | fail > 1024 pg · warn > 128 pg | same | same |
| **B** temperature | `/sys/class/thermal` | fail > 92 °C · warn > 84 °C | fail > 90 °C · warn > 82 °C | fail > 90 °C · warn > 82 °C |
| **B** I/O pressure | `/proc/pressure/io` | fail > 25 % | fail > 20 % | fail > 20 % |
| **B** uptime | `/proc/uptime` | fail < 600 s | same | same |
| **B** reboot continuity | `boot_id` vs state | fail on change unless `--allow-reboot`; **always fails** if a run was marked active | same | same |
| **B** OOM continuity | `oom_kill` vs state | fail on any new kill | same | same |
| **B** ports | `ss -ltn` | 8085/8010/4200 must be **free** | must be **free** | must be **listening** |
| **B** stack state | docker labels | must be **down** | must be **down** | keycloak + frontend + backend **up** |
| **B** container restarts | `RestartCount` | — | — | fail if any F11 container restarted |
| **B** inputs | credentials/secrets | — | — | readable + schema-valid |
| **B** images | `docker image inspect` | — | — | keycloak + frontend + e2e present |
| **B** disk free | `statfs` | fail < 10 GiB | fail < 8 GiB | fail < 5 GiB |
| **A** CPU busy (5 s) | `/proc/stat` | warn > 75 % · never blocks | warn > 70 % | warn > 70 % |

Raw CPU utilisation never blocks. A 5 s sample catches legitimate bursts and
says nothing about whether tasks actually stalled; PSI and the normalised load15
are the signals that answer that question. The first implementation *did* block
on utilisation and produced a false refusal at 91 % busy while PSI sat at 20 %,
which is exactly the failure mode this gate must not have.

### Stages and usage

```bash
# collect evidence without blocking (always exits 0)
infra/f11/preflight-gate.sh --stage up --report

# machine readable
infra/f11/preflight-gate.sh --stage e2e --json

# enforce
infra/f11/preflight-gate.sh --stage build
```

Exit codes: `0` allowed (warnings permitted), `1` refused, `2` usage error.
State is kept in `$F11_RUNTIME_DIR/state/preflight.env` (boot id, OOM counter,
last result) and `run-active` (written during an E2E run, removed on exit).
A leftover `run-active` from a run that died without cleanup is reported as
`run_marker FAIL`; inspect the run, then delete the file deliberately.

### Staged build

Compilation and testing are separate, and the compiler runs under real cgroup
limits because `docker build` cannot be limited through the stable CLI.

| Stage | Command | What runs | Limits |
|---|---|---|---|
| A — compile | `infra/f11/build-artifacts.sh` | `npm ci` + `ng build` in a container | `--cpus 2.0 --memory 3g --memory-swap 3g --pids-limit 512`, `NODE_OPTIONS=--max-old-space-size=2048` |
| B — package | `infra/f11/build-images.sh` | runtime image from `.f11-dist/browser`; e2e image only if missing | runtime build is seconds; e2e build is one-time and cached |
| C — start | `preflight-gate.sh --stage up` then `docker compose up -d` + `systemctl start` | keycloak + frontend + backend | compose limits: 1.0/1024M, 0.25/128M, systemd `CPUQuota=50%` / `MemoryMax=512M` |
| D — test | `infra/f11/run-e2e.sh` | Python API E2E, then Playwright | Playwright `--cpus 1.0 --memory 1g --pids-limit 256` |

Stage A writes `frontend/.f11-dist/browser` (gitignored, and **not** excluded by
`frontend/.dockerignore`, unlike `dist/`). `frontend/Dockerfile.prebuilt` only
copies it; `frontend/Dockerfile` remains the reference multi-stage build for CI.

For the one unlimit-able step (Playwright image build), opt into a dedicated
BuildKit daemon that runs inside a limited container:

```bash
infra/f11/build-images.sh --rebuild-e2e --limited-e2e-builder
docker buildx rm sgsi-zta-f11-builder   # when done
```

The builder is created under a fixed name and is **not** made the default, so
other projects keep their builder.

### Thermal note

`x86_pkg_temp` sits at 80–86 °C with the host at ~47 % CPU busy. That is a
15 W laptop-class package with little thermal headroom, which is why the gate
warns at 82 °C and refuses at 90 °C. Expect the temperature warning during any
build; it is not a failure by itself, but a sustained rise above 90 °C must stop
the run.

Four supervised attempts measured the same wall, each with a different workload:

| Attempt | Workload | Duration | Peak | Samples >= 88 C |
| --- | --- | --- | --- | --- |
| 1 | buildkitd 2 cores, node base + apt + Chromium download | 113 s | 93 C | 8 |
| 2 | buildkitd 1 core, same Dockerfile | 78 s | 90 C | 4 |
| 3 | buildkitd 1 core, official Playwright base (pull + export) | 129 s | 93 C | 6 |
| 4 | plain `docker pull` of the official image, no build at all | 71 s | 93 C | 4 |

The variable is the host, not the workload. Attempt 4 is the decisive one: merely
transferring the official image, with no compiler and no apt, breaches the
ceiling. Ingesting roughly 2 GB is itself a thermal event on this package.

Consequently B2 cannot complete under an 88 C abort ceiling and the Playwright
image does not exist. The alternatives are operator decisions, not build-script
tuning:

- raise the ceiling to about 95 C for the one-time transfer (Tjmax is 100 C);
- generate the image on a cooler machine and move it as an uncompressed
  `docker save` stream, which avoids gzip decompression here but is slower;
- free thermal headroom by stopping the other stacks this host runs.

### Safe procedure (Angular + Python + Keycloak)

```bash
cd /home/elcra/sgsi-zta-integration

# 0. host must be acceptable for compilation
infra/f11/preflight-gate.sh --stage build

# 1. compile (Stage A) -- no docker build involved
infra/f11/build-artifacts.sh

# 2. package (Stage B)
infra/f11/build-images.sh

# 3. prepare E2E inputs
infra/f11/prepare-e2e-secrets.sh          # writes $F11_RUNTIME_DIR/e2e-secrets.json
#    credentials.json is produced by the realm bootstrap; verify its schema with
#    the gate (--stage e2e) before starting anything.

# 4. host must accept the stack
infra/f11/preflight-gate.sh --stage up

# 5. start the stack (explicit, never automatic)
docker compose --env-file infra/f11/.env -f infra/f11/compose.yaml up -d
sudo systemctl start sgsi-zta-f11-backend

# 6. verify and test
infra/f11/health-check.sh
infra/f11/run-e2e.sh

# 7. stop
sudo systemctl stop sgsi-zta-f11-backend
docker compose --env-file infra/f11/.env -f infra/f11/compose.yaml down
```
## Known limitations

- The intermittent Keycloak AMR behavior is unresolved. Do not claim full
  real-stack validation until the remote E2E is re-run and the evidence is
  captured.
- The Angular build is staged and cgroup-limited; see "Staged build".
- The backend systemd unit is prepared but not installed or enabled.
- The remote E2E paths and ports must be adapted to F11 before the full suite is
  considered valid.
