# Stage C ligera — Angular + Python + Keycloak without Playwright

Branch: `feat/f11-preflight-gate` (local commits only, no push, no cutover).

## Objective

Bring the F11 real-mode stack up on `servidor-1` — Keycloak, the Python
backend and the static Angular frontend — and verify it with an automated API
suite plus a manual browser session from Windows. The Playwright image is not
required and is not produced.

## Problem

Stage B2 (the Playwright image) cannot be built on this host. Four supervised
attempts, four different workloads, all of them aborted at the 88 C ceiling:

| Attempt | Workload | Duration | Peak |
|---|---|---|---|
| 1 | buildkitd 2 cores, node base + apt + Chromium download | 113 s | 93 C |
| 2 | buildkitd 1 core, same Dockerfile | 78 s | 90 C |
| 3 | buildkitd 1 core, official Playwright base (pull + export) | 129 s | 93 C |
| 4 | plain `docker pull` of the official image, no build at all | 71 s | 93 C |

Attempt 4 is decisive: transferring the image, with no compiler and no apt,
already breaches the ceiling. Ingesting roughly 2 GB is itself a thermal event
on this package. No Dockerfile change can fix it, so the operator suspended B2
and asked for Stage C to be decoupled from Playwright.

## Scope

In scope:

- Preflight gate: a new `api` stage that admits a running stack without the
  Playwright image, and an 88 C thermal ceiling on the start stages.
- Component lifecycle: independent start and stop for keycloak, frontend and
  backend, with resource limits, without installing the systemd unit.
- API suite covering JWT validation, RBAC, MFA/TOTP and the audit trail,
  using only the dependencies already present in the repository.
- Manual UI procedure: a Windows browser over an SSH tunnel.

Out of scope:

- The Playwright image and the E2E suite. `run-e2e.sh` and the `e2e` gate
  stage stay in place, suspended, not deleted.
- Installing the systemd unit, which still needs explicit authorization.
- Any change to `/opt`, to another project, or to production.

## Constraints

- Thermal ceiling 88 C, unchanged. The gate refuses at 88 C and warns at 82 C.
- Preflight is mandatory before any component starts.
- All hospital software runs on Debian. Windows only runs a browser.
- No new image downloads and no new large builds.
- The existing `sgsi-zta-*` stacks and Coolify's builder are never touched.

## Tasks

| ID | Task | Status |
|---|---|---|
| T1 | Add the `api` stage to the preflight gate | done |
| T2 | Independent component lifecycle without systemd | done |
| T3 | API suite: JWT, RBAC, MFA TOTP, audit | done, not yet executed |
| T4 | Manual UI procedure over the SSH tunnel | done |
| T5 | Document the lightweight Stage C | done |

## Route declaration

| Task | Route | Trigger evidence |
|---|---|---|
| T1 | inline | one file, already mapped end to end, mechanical edit |
| T2, T3, T4 | inline (subagent unavailable) | the provider rate-limited the delegated explorer; the authoritative repository is remote, so a subagent would also have to drive SSH for every write. The contracts were already fixed by direct inspection, so the writer was executed by the parent. |
| T5 | inline | documentation derived from the implemented behaviour |

## Design notes

- **Gate decoupling.** The `e2e` stage required the Playwright image. The new
  `api` stage keeps the "the stack must be up" semantics but requires only
  `credentials.json` and the keycloak and frontend images. The backend is
  detected by its listening port, not by the systemd unit, because the unit is
  not installed.
- **Backend without systemd.** `systemd-run --scope` answers "Access denied"
  for this account and `cgexec` is absent, so no cgroup can be created. The
  backend runs as a host process bounded by `taskset` (one core), `ulimit -v`
  (address space) and `nice`. Those approximate the unit's `MemoryMax=512M`
  and `CPUQuota=50%`; they do not reproduce them, and the documentation says
  so.
- **Token acquisition.** The Keycloak client has
  `directAccessGrantsEnabled: false`, so a password grant is not available.
  `infra/local-test/setup_realm.py` already drives the real authorization
  code + PKCE flow and answers the TOTP challenge, so the API suite reuses it
  instead of weakening the realm configuration.
- **Test matrix.** Five synthetic users cover the policies: reception creates
  orders, laboratory reads them, the pathologist validates with TOTP evidence,
  the pathologist without MFA is refused with `MFA_AUTHENTICATION_REQUIRED`,
  and the auditor reads the immutable trail where every denial must appear.

## Acceptance criteria

- [ ] `--stage up` admits the host and `--stage api` refuses while the stack
      is down, without ever mentioning the Playwright image.
- [ ] Each component starts and stops on its own, and the gate runs before
      every start.
- [ ] The API suite covers the matrix above and the audit trail shows every
      denial.
- [ ] The Windows browser reaches the frontend and the issuer through the
      tunnel and completes a login.
- [ ] Nothing outside the F11 project was modified.

## Verification evidence

Observed on `servidor-1` while preparing this change:

- `bash -n` clean on `stack-ctl.sh` and `run-api-tests.sh`.
- `ast.parse` clean on `api-tests/test_f11_api.py`; the module imports and
  exposes 12 test methods.
- No CRLF in any new file.
- `--stage up` returns ALLOWED; `--stage api` returns REFUSED with `stack
  not up` and `inputs missing`, and reports the images check as PASS with
  only keycloak and frontend, proving the Playwright image is not required.
- Zero F11 containers and zero listeners on 8085, 8010 and 4200: nothing was
  started.

## Next step

Awaiting authorization to run Stage C:

1. `infra/f11/stack-ctl.sh start keycloak`
2. provision the realm with `infra/local-test/setup_realm.py`
3. `infra/f11/stack-ctl.sh start backend`
4. `infra/f11/stack-ctl.sh start frontend`
5. `infra/f11/run-api-tests.sh`
6. manual UI from Windows over `infra/f11/tunnel.ps1`
