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
| T3 | API suite: JWT, RBAC, MFA TOTP, audit | done, passing 12/12 against the live stack |
| T4 | Manual UI procedure over the SSH tunnel | done |
| T5 | Document the lightweight Stage C | done |
| T6 | Stage C1: Keycloak plus the synthetic realm | done |
| T7 | Stage C2: the Python backend under supervision | done |

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

## Stage C1 and C2 evidence

C1, Keycloak alone, supervised at the 88 C ceiling: the preflight allowed the
host, the container started with real limits (1.0 CPU, 1 GiB, 512 pids), the
JVM took 63.5 s to boot, the realm was recreated with its five synthetic
users, and `medico.test` obtained an `otp` AMR while `medico.sinmfa` did not.
A fresh token carried `alg=RS256`, its `kid` was in the JWKS and its signature
was verified against the published RSA key. `credentials.json` was written
with mode 0600 outside the repository.

C2, the Python backend alone: the host was cooled to 82 C before the
preflight, the gate admitted it with `--component backend`, and the process
started in 10 s with 34 MiB RSS, one thread, CPU affinity to core 0 and a
2 GiB address-space limit. The API suite passed 12/12 against the live stack,
the audit chain reported `audit_chain_valid: true` with the MFA denial and
the MFA-backed validation both present, and the backend's own validator
accepted the real token and rejected a tampered signature, a tampered
payload, a truncated token and plain garbage.

Two defects were found and fixed during C2 rather than worked around:

- the Keycloak readiness wait was 120 s while the JVM needs about 65 s plus
  the realm bootstrap, so the first start reported failure five seconds
  before the service answered (commit 5f19511);
- the API suite stored the shared order id on the instance, and unittest
  builds a fresh instance per test method, so the MFA tests raised
  AttributeError (commit b5e8384).

Two design corrections were also required: the `up` stage had to become
component-aware so a running Keycloak does not block the backend, and the
`api` stage had to stop requiring the frontend, which the API suite never
uses (commit 857e7a7).

## The Windows tunnel depends on the server sshd policy

The server does not allow TCP forwarding in general. `/etc/ssh/sshd_config`
sets `AllowTcpForwarding no`, and `/etc/ssh/sshd_config.d/90-evaluacion-tunnel.conf`
opens it only for `Match User elcra Address 192.168.1.7` with
`AllowTcpForwarding local` and a fixed `PermitOpen` list.

Measured from the Windows machine (192.168.1.7 on Wi-Fi):

| Origin | Destination | Result |
|---|---|---|
| LAN 192.168.1.36 | 127.0.0.1:8085 | HTTP 200 |
| LAN 192.168.1.36 | 127.0.0.1:4200 | refused, "administratively prohibited" |
| Tailscale 100.78.61.51 | any | refused, "administratively prohibited" |

Two consequences: the tunnel must be opened against the LAN address, not the
Tailscale alias, and 127.0.0.1:4200 had to be added to the permitted
destinations for the browser to reach the frontend. The prepared rule adds
that single destination, keeps every other destination and restriction, and
is installed with `sshd -t` plus `sshd -T -C` validation before an `sshd`
reload that never restarts the service and never closes open sessions.

The browser only needs 4200 and 8085. The API is reached through the Caddy
proxy on 4200, so the backend port 8010 does not have to be forwarded.

## The host rebooted under load

During the thermal work the host rebooted on its own: the boot id changed,
the uptime dropped to 514 s and there were 13 minutes of downtime between the
end of the previous boot (15:25:55) and the start of the new one (15:38:58).
It took the whole F11 stack down with it, because the compose file uses
`restart: "no"` while the other stacks on this machine carry an always
policy and came back on their own.

Measured facts about the reboots: the last five boots ended with **no**
orderly shutdown events at all, and boots -2 and -1 contain no panic,
watchdog, thermal, MCE, hardware error or oom-kill entry. The shutdowns left
no kernel trace, so the logs alone cannot establish the cause.

The operator then stated that the shutdown was **manual**. That is the
explanation, and it downgrades the earlier reading: these were human power
cycles, not thermal resets, so they are not evidence of a thermally unstable
machine. What survives is only that the boots leave no kernel trace, which
means a future automatic reboot would be hard to explain.

Two consequences for the F11 work:

- the preflight gate correctly refused the restart until the host had been up
  for its 600 s stability window, and `F11_ALLOW_REBOOT=1` is needed to
  acknowledge a reboot the host caused itself;
- an unclean reset while the package is hot is a further reason to insist on
  a real quiet window before compiling, and not on three isolated samples.

## Stage A rebuilt with the lighter path

With the F11 stack stopped so the preflight could admit the host, Stage A ran
with the new mode:

```bash
F11_BUILD_CPUS=0.5 infra/f11/build-artifacts.sh --reuse-node-modules
```

It compiled in **50 s** with the preflight allowing it and the supervisor
cutting at 88 C. The peak was 88 C, reached but not sustained, so there was
no breach. The host started at 86 C and ended at 88 C: the build's own
contribution was about **+2 C**, against the +8 C measured for the original
method at two cores with `npm ci`. That is a measurement, not an assumption,
and it is the reason the lighter path is worth keeping.

The Caddy image was then rebuilt with a COPY only, in 1 s, and only the F11
frontend container was recreated.

One defect surfaced only at runtime: Caddy served the site as
`http://127.0.0.1:4200`, so a request arriving through the SSH tunnel with
`Host: localhost:4200` matched no site and came back as an empty body. The
Keycloak client registers both names, so the Caddyfile now serves both
`http://127.0.0.1:4200` and `http://localhost:4200`.

Two operational notes for the manual session: a TOTP code can only be used
once per 30 s window, so a second login with the same code is refused by
Keycloak; and the Angular compiler escapes non-ASCII characters as `\xNN`,
so a literal search for "Panel clínico" in the bundle finds nothing even
though the text is Spanish.

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
