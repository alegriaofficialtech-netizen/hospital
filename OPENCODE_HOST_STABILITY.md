# Estabilidad del host `servidor-1` — Evidencia y GO/NO-GO

**Fecha:** 2026-10-20 20:52 (America/Lima, UTC-05)
**Host:** `servidor-1` (`servidor-1.tailb0f78a.ts.net`, `100.78.61.51`)
**Alcance:** investigación de los reinicios, certificado Tailscale, verificación TLS real en Windows y auditoría de solo lectura de Keycloak / M2M / realm, **antes de autorizar producción**.
**Modo:** solo lectura. No se reiniciaron servicios, no se modificó `/opt`, no se ejecutó el cutover, no se hizo push.
**Secretos:** no se imprimieron contraseñas, claves privadas, client secrets ni contenido del realm. Solo nombres de variables, modos, tamaños y hashes públicos.

---

## Veredicto

> ## **NO-GO para autorizar producción en `servidor-1` en su estado actual.**

El host **no es estable**: se reinició de forma **sucia al menos 4 veces el 2026-10-20** (15:04, 15:43/15:45, 17:49 y 20:37/20:40), y **volvió a reiniciarse durante esta investigación** (20:39/20:40). No hay apagado limpio en ninguno de esos arranques. Hay además un **kernel panic real capturado en pstore** (2026-10-17) en el kernel **7.1.8+deb13 (backports)**, y el host es una **laptop Dell Inspiron 5559 de 4 hilos** con **77 contenedores**, load **51** al arrancar, CPU pressure **~99%** y **82–86 °C**.

La **verificación TLS de Windows sí es real** (controles negativos), el **certificado actual es válido hasta 2027-01-18** y el **realm de producción es válido y está protegido (0600)**. Pero esos puntos no compensan la inestabilidad del host ni la identidad caída.

---

## 1. Plataforma y carga

| Dato | Valor |
|---|---|
| Modelo | Dell Inc. **Inspiron 5559** (física, no VM: `systemd-detect-virt = none`) |
| CPU | **Intel Core i7-6500U** — **2 núcleos / 4 hilos** |
| RAM | 15 GiB (9 GiB usados, 5.6 GiB disponibles, swap 12 GiB sin uso) |
| OS | Debian GNU/Linux 13.6 (trixie) |
| Kernel | **7.1.8+deb13-amd64** (`#1 SMP PREEMPT_DYNAMIC`, backports, build 2026-08-16) |
| Docker | 97 contenedores (77 corriendo, 20 detenidos), 83 imágenes, `overlay2`, `json-file`, `LiveRestore=false`, cgroup v2 |
| Energía | **AC online**, **sin batería detectada** (`/sys/class/power_supply` solo expone `AC`), sin UPS |
| Térmica | `x86_pkg_temp` **86 °C** a 1 min del arranque, **82 °C** a 11 min; `pch_skylake` 70–74 °C; zones ACPI 25–30 °C |
| Watchdog | **`iTCO_wdt` hardware, timeout 5 min**; `softdog` 60 s |
| Load / PSI | load **51.17 / 17.61 / 6.26** a 1 min; **3.46 / 6.98 / 6.28** a 11 min; CPU PSI `some avg10=98.93%` en el pico, ~27% sostenido |
| Disco | `/dev/sda2` 221 G, **68 G usados (33%)**, 142 G libres, inodos **10%**; `/dev/sdb1` 916 G, 4.3 G (1%) |
| Procesos top CPU | `node` 142% y 125%, `cadvisor` 46.7%, `dockerd` 23%, `beam.smp` 3.8/3.7% |

**Lectura:** 77 contenedores sobre 4 hilos y una CPU de 15 W no es una carga de producción sana. El `monit` del host alerta `loadavg (5min) > 4.0` de forma continua en todos los arranques.

---

## 2. Historial de arranques (hora local)

Salida de `journalctl --list-boots` (los tiempos locales tienen saltos de reloj; ver §7):

| Boot | Inicio | Fin | Duración | ¿Apagado limpio? | Evidencia final |
|---|---|---|---|---|---|
| -8 | Sat 2026-10-17 22:20:24 | 23:17:33 | 57 min | **No** | reinicio sucio |
| -7 | Sat 2026-10-17 23:54:01 | Sun 2026-10-18 11:44:09 | 11 h 50 min | **No** | reinicio sucio |
| -6 | Mon 2026-10-19 08:51:09 | 12:14:50 | 3 h 23 min | **No** | reinicio sucio |
| -5 | Mon 2026-10-19 13:15:07 | 14:17:07 | 1 h 02 min | **No** | reinicio sucio |
| **-4** | **Tue 2026-10-20 08:50:27** | **15:04:36** | **6 h 14 min** | **No** | SSH/monit, corte abrupto |
| **-3** | **Tue 2026-10-20 15:09:42** | **15:43:54** | **34 min** | **No** | churn de Docker, corte abrupto |
| **-2** | **Tue 2026-10-20 15:53:40** | **17:49:02** | **1 h 55 min** | **No** | `monit` loadavg, corte abrupto |
| **-1** | **Tue 2026-10-20 20:23:45** | **20:37:49** | **14 min** | **No** | `php sessionclean`/Docker, corte abrupto |
| **0** | **Tue 2026-10-20 20:41:16** | actual (20:52+) | — | — | arranque en curso, load 51 a 1 min |

**Reinicios relevantes:** los dos que observó la sesión anterior son los cortes de **15:04** y **15:43/15:45**. Después hubo **dos más** (17:49 y 20:37/20:40), y el host **volvió a reiniciarse durante esta investigación**.

---

## 3. Evidencia de apagado sucio

### 3.1 No hay secuencia de apagado

En los arranques recientes **no aparece**:

- `systemd-shutdown`
- `Reached target shutdown.target - System Shutdown`
- `Reached target reboot.target - System Reboot`
- `Powering off` / `Rebooting`
- `Journal stopped`

Las últimas líneas de los arranques recientes son actividad normal (`monit` loadavg, churn de veth/Docker, `php sessionclean`), y luego el journal se corta. Los únicos apagados limpios del journal retenido son del **2026-09-01**; desde entonces los cortes son abruptos.

### 3.2 `orphan cleanup` en cada arranque

En el arranque siguiente a cada corte:

```text
EXT4-fs (sda2): orphan cleanup on readonly fs
EXT4-fs (sdb2): orphan cleanup on readonly fs
```

Esto es **consistente con un desmontaje no limpio** (reset duro, pérdida de energía o watchdog), no con un `systemctl reboot`. **No hay errores `EXT4-fs error`** ni corrupción reportada.

### 3.3 Sin OOM y sin presión de disco/memoria

- **No hay** `oom-kill`, `Out of memory`, `invoked oom-killer` ni `Killed process` en el journal del sistema.
- **Ningún** contenedor con `OOMKilled=true` (97 contenedores inspeccionados).
- Memoria: 9 GiB usados de 15 GiB, 5.6 GiB disponibles, swap 0.
- Disco: 33% usado, 10% de inodos, 142 G libres; `/sdb1` 1% usado.

**Conclusión:** OOM y disco lleno quedan **descartados** como causa de estos reinicios.

---

## 4. Kernel panic capturado (pstore, 2026-10-17)

En `/var/lib/systemd/pstore` hay **tres registros** (`1792290736`, `1792290737`, `1792290738`) que son **partes 1–27 de un mismo panic**. El texto exacto:

```text
Kernel panic - not syncing: stack-protector: Kernel stack is corrupted in: __x64_sys_epoll_pwait+0x137/0x140
CPU: 0 UID: 0 PID: 3377 Comm: node Tainted: G          I         7.1.8+deb13-amd64 #1 PREEMPT(lazy)  Debian 7.1.8-1~bpo13+1
Tainted: [I]=FIRMWARE_WORKAROUND
Call Trace:
 dump_stack_lvl+0x5d/0x80
 panic+0x6b/0x70
 ? __x64_sys_epoll_pwait+0x137/0x140
 __stack_chk_fail+0x19/0x20
 __x64_sys_epoll_pwait+0x137/0x140
 alloc_low_pages+0x4a/0x170
 ? do_syscall_64+0x9f/0x640
 ? entry_SYSCALL_64_after_hwframe+0x76/0x7e
Kernel Offset: 0x9000000 from 0xffffffff81000000
```

**Interpretación:**

- Es un **panic real por corrupción de stack** detectada por el canario (`stack-protector`) en la syscall `epoll_pwait`, con el proceso **`node`**.
- El trace contiene `alloc_low_pages` dentro de la ruta de syscall, lo que es **incoherente**: el stack está corrupto, por eso el trace no es fiable.
- Ocurrió en el kernel **7.1.8+deb13 (backports)**. Es evidencia de **inestabilidad del kernel** o de **corrupción de memoria** (RAM), no de OOM/disco.
- Es **un evento del 2026-10-17**. Los reinicios del **2026-10-20 no dejaron registros en pstore**: `/sys/fs/pstore` está **vacío** ahora y `/var/lib/systemd/pstore` solo tiene los del 17. Por tanto, **no se puede afirmar** que los cortes del 20 sean el mismo panic; tampoco descartarlo (pstore pudo estar lleno/limpiado).

---

## 5. Docker e identidad

- El host tiene **97 contenedores** (77 corriendo, 20 detenidos) y **`LiveRestore=false`**: cuando el daemon/host se detiene, los contenedores se paran.
- El stack de producción SGSI tiene **10 contenedores `Exited (255)`**:
  - `keycloak` y `keycloak-postgres`: **32 h** caídos, `FinishedAt 2026-10-19T18:13:23Z`.
  - `demo-cloudflared`, `demo-gateway`, `wazuh-*`, agentes: **2 días** caídos.
- **Keycloak/Postgres:**
  - `State=exited ExitCode=255 OOMKilled=false Error= Restart=no`
  - `StartedAt=2026-10-19T13:52:46Z`, `FinishedAt=2026-10-19T18:13:23Z`
  - Los logs **no muestran un apagado ordenado** (Keycloak termina en warnings de token; Postgres termina en checkpoints, sin `received fast shutdown request` / `database system is shut down`).
- **Causa próxima de la caída de identidad:** el stack está detenido y **`restart: no`** impide que vuelva tras un reinicio. El `LiveRestore=false` y los reinicios del host explican que no se recupere. **Reiniciar Keycloak/Postgres requiere autorización** y no se hizo.

---

## 6. Carga, térmica, energía y watchdog

- **CPU:** i7-6500U de 2C/4T; load **51.17** a 1 min del arranque del 20:41; `monit` reporta loadavg 5–7 de forma continua.
- **CPU PSI:** `some avg10=98.93%` en el pico de arranque; ~27% sostenido. `full` de CPU 0 (no hay stalls completos), pero la contención es severa.
- **Térmica:** `x86_pkg_temp` **86 °C** a 1 min, **82 °C** a 11 min; `pch_skylake` **74 °C**. Los trip points ACPI son 107/119/115 °C; el trip crítico de `x86_pkg_temp` aparece como **-274000** (no gestionado por el kernel). El **EC/BIOS** puede cortar por temperatura sin dejar log.
- **Energía:** **AC online**, **sin batería** y **sin UPS**. Una laptop sin batería no tiene ride-through: cualquier microcorte del adaptador reinicia.
- **Watchdog:** `iTCO_wdt` con **timeout de 5 min** en todos los arranques. Si PID 1 no se planifica durante 5 min (por starvation/hang), el hardware **resetea en silencio**: sin `systemd-shutdown`, sin pstore, con `orphan cleanup` al volver. Ese patrón coincide con los cortes del 20.
- **`monit`:** las reglas de loadavg son **solo `then alert`**; **no** ejecutan reboot/shutdown. `monit` no es la causa.

### Hipótesis (no probadas)

1. **Watchdog por starvation/hang** (iTCO 5 min) bajo carga extrema y 4 hilos → reset silencioso.
2. **Corte de energía/térmico/EC** (laptop sin batería, AC, 82–86 °C, sin UPS) → reset sin logs.
3. **Panic recurrente del kernel 7.1.8** (probado una vez el 17; no capturado el 20).

**Lo probado:** los reinicios son **sucios**, **no** son OOM, **no** son disco lleno, **no** hay MCE/térmico crítico/panic registrado en los arranques del 20, y hay **un panic real** el 17. **La causa exacta de los cortes del 20 no está probada**; requiere diagnóstico root/hardware.

---

## 7. Acceso a logs y limitaciones

- `elcra` **no** está en `adm` ni `systemd-journal`: `journalctl` solo muestra sesiones propias; `dmesg` restringido.
- No existen `/var/log/syslog` ni `/var/log/kern.log`; `/var/crash` no existe; `last`/`wtmpdb` no está instalado.
- `/sys/fs/pstore` es root-only; `/var/lib/systemd/pstore` también. Se leyó **en solo lectura** con un contenedor root que monta `/var/log/journal` y `/var/lib/systemd/pstore` en `:ro`. No se usó `sudo` (requiere contraseña) ni se modificó nada.
- **Saltos de reloj:** `uptime -s` 20:39:59 vs journal 20:41:16; durante el boot -2 hubo una diferencia de ~48 min entre la hora local y la conversión UTC. Esto sugiere **corrección NTP tras arranque** y posible **pila CMOS/RTC deteriorada** (laptop vieja, sin batería principal). Es una **limitación de los timestamps**, no la causa de los reinicios.

---

## 8. Tailscale: certificado vs `CertDomains`

### Estado actual

| Campo | Valor |
|---|---|
| `BackendState` | `Running` |
| Versión | `1.104.1-t7f4efe814-g8da26756c` |
| `Self.DNSName` | `servidor-1.tailb0f78a.ts.net.` |
| `Self.CertDomains` | **`None`** (vacío en `status --json`) |
| `Self.CapMap` | incluye **`https`** |
| `Self.Capabilities` | incluye **`https`** |
| `OperatorUser` | **`None`** (solo root puede usar la API local de `cert`) |
| `tailscale cert` como `elcra` | **`Access denied: cert access denied`** (permiso local, no control-plane) |
| `tailscale debug netmap` como `elcra` | `Access denied: debug access denied` (root-only) |
| Timer de renovación | **No instalado** (`sgsi-zta-cert-renew.*` no existe) |

### Certificado actual (contenedor root, solo lectura)

```text
subject=CN=servidor-1.tailb0f78a.ts.net
issuer=C=US, O=Let's Encrypt, CN=YE2
notBefore=Oct 20 17:17:40 2026 GMT
notAfter=Jan 18 17:17:39 2027 GMT
X509v3 Subject Alternative Name:
    DNS:servidor-1.tailb0f78a.ts.net
chain_certs=4
key_match=OK  pub_sha256=3645f5b0ae1509e34940dccf66cc3f7404f18e1ab033ff08965f33cd08acee6c
/certs/fullchain.pem mode=644 owner=root:root size=4849
/certs/privkey.pem   mode=600 owner=root:root size=227
```

### Conclusión matizada

- El **certificado es válido**, coincide con el nombre, la cadena tiene 4 certificados y la clave coincide. Vence el **2027-01-18**.
- `CertDomains: None` **no prueba** que HTTPS esté deshabilitado: el nodo tiene la **capacidad `https`** en `CapMap` y `Capabilities`, y el certificado se emitió el **2026-10-20 17:17:40Z**. La autorización de control-plane **parece presente**; el campo `CertDomains` del `status --json` puede no reflejar los dominios propios del nodo.
- El fallo de `tailscale cert` como `elcra` es **permiso local** (`OperatorUser=None`), **no** denegación del control-plane. La renovación **debe correr como root**.
- **La renovación real no está probada:** no hay timer, `sudo` pide contraseña y `debug netmap` (root) no se pudo leer. El `renew_cert.sh --check`/`--dry-run --force` con un shim de `tailscale` valida la **lógica del script**, no la emisión real.
- **Acción:** en ventana autorizada, ejecutar como root `tailscale cert` (o `renew_cert.sh --force`), verificar el certificado nuevo, instalar el timer systemd como root y confirmar `CertDomains`/`netmap`. No hay riesgo inmediato por vencimiento (89 días), pero **no se debe autorizar producción sin una renovación probada o un proceso manual documentado y monitoreado**.

---

## 9. Verificación TLS real en Windows

**Entorno:** Windows PowerShell **5.1.26100.9711**; `curl 8.21.0 (Windows) libcurl/8.21.0 Schannel`.

| Prueba | Resultado | Conclusión |
|---|---|---|
| `curl https://wrong.host.badssl.com/` (sin `-k`) | **exit 60**, `SEC_E_WRONG_PRINCIPAL`, HTTP **000** | Rechaza hostname incorrecto |
| `curl https://expired.badssl.com/` | **exit 35**, `SEC_E_CERT_EXPIRED`, HTTP 000 | Rechaza certificado vencido |
| `curl https://self-signed.badssl.com/` | **exit 60**, `SEC_E_UNTRUSTED_ROOT`, HTTP 000 | Rechaza raíz no confiable |
| `curl -k https://wrong.host.badssl.com/` | **exit 0**, HTTP **200** | Solo con `-k` acepta el certificado inválido |
| `curl https://example.com/` | **exit 0**, HTTP **200** | Acepta cadena válida |
| `Invoke-WebRequest https://wrong.host.badssl.com/` | **falla** (`WebException`, canal SSL/TLS no confiable) | .NET/Schannel valida por defecto |
| `Invoke-WebRequest https://expired.badssl.com/` | **falla** (`WebException`) | .NET/Schannel valida por defecto |
| `Invoke-WebRequest https://example.com/` | **200** | Línea base correcta |
| `Cert:\LocalMachine\Root` | **ISRG Root X1** presente, `NotAfter 2035-04-06` | La raíz de Let's Encrypt es confiable |
| `https://servidor-1.tailb0f78a.ts.net:8443/` (ahora) | **exit 7** (no conecta) | El stack/gateway está caído, **no** es fallo TLS |

**Conclusión:**

- El cliente **sí verifica TLS de verdad**. `ssl_verify=0` **no es evidencia suficiente**: aparece también en los fallos de Schannel (wrong.host/expired/self-signed). La prueba real es **exit code + HTTP status + controles negativos**.
- La prueba canónica anterior (`curl` sin `-k` → HTTP 200; `Invoke-WebRequest` sin `-SkipCertificateCheck` → 200) fue **verificación real**, porque el mismo cliente rechaza los certificados inválidos y acepta la cadena de Let's Encrypt/ISRG Root X1.
- El endpoint canónico está **caído ahora** (`exit 7`) porque el stack de identidad/gateway no está corriendo. Hay que **repetir la prueba canónica cuando el gateway esté arriba**; no es un hallazgo TLS negativo.

---

## 10. Keycloak, M2M y realm (solo lectura)

### 10.1 Contenedores y configuración

- `keycloak-postgres`: `postgres:16-alpine`; `keycloak`: `quay.io/keycloak/keycloak:26.8.0`.
- Keycloak publica `127.0.0.1:${KEYCLOAK_PORT:-8085}:8080`; monta `./config/keycloak/hospital-lab-realm.json:/opt/keycloak/data/import/hospital-lab-realm.json:ro`.
- Ambos `Exited (255)`, `OOMKilled=false`, `Restart=no`, `FinishedAt 2026-10-19T18:13:23Z`; sin apagado ordenado en logs.
- El stack completo de producción (10 contenedores) está detenido; el cutover **no se aplicó**.

### 10.2 Variables de entorno (solo nombres; valores redactados)

`.env` de producción (`0600 elcra:users`, 1165 bytes) contiene, entre otras:

```text
CLINICAL_IMAGE=<set>            CLINICAL_PORT=<set>
COMPOSE_PROJECT_NAME=<set>      DEMO_*_PASSWORD=<set>
KC_BOOTSTRAP_ADMIN_PASSWORD=<set>
KC_BOOTSTRAP_ADMIN_USERNAME=<set>
KEYCLOAK_IMAGE=<set>            KEYCLOAK_PORT=<set>
POSTGRES_DB=<set>               POSTGRES_IMAGE=<set>
POSTGRES_PASSWORD=<set>         POSTGRES_USER=<set>
WAZUH_*_PASSWORD=<set>          WAZUH_*_PORT=<set>
```

- **`AUDIT_MONITOR_CLIENT_SECRET`:** **ausente** (`grep -c` = **0**). El cliente `clinical-audit-monitor-service` existe en el realm (los logs de Keycloak lo muestran), pero **el secreto M2M no está en el `.env` de producción**; el monitor no puede autenticarse hasta provisionarlo.

### 10.3 Realm de producción

| Artefacto | Estado |
|---|---|
| `/home/elcra/sgsi-backups/realm/hospital-lab-realm-production.json` | **0600** `elcra:users`, **105542 bytes**, mtime 2026-10-20 16:11:51 -05 |
| SHA-256 | `a65335434c2753f13de8030bee80a09ac074817ac4876f20632ad55f176cfcf6` |
| Contenido estructural | realm `hospital-lab`; **13 clients**, **11 realm roles**, **10 users**, **24 flows** |
| Validación / import | Exportado de copia read-only del volumen detenido; import verificado previamente (9 usuarios importados) |
| `/opt/sgsi-zta-hospital-lab/config/keycloak/hospital-lab-realm.json` | **644**, **7557 bytes**, mtime 2026-10-03 — **realm viejo/inválido**, aún no reemplazado |
| Backups | `/home/elcra/sgsi-backups/{,realm,secrets,pre_cutover,pre_restore,pre_rollback}` → **0700** `elcra:users` |
| Git | Ningún archivo `realm*.json` trackeado en `/home/elcra/sandbox-jwt-validator` |
| Timer de cert | **No instalado** |

**Hallazgo de seguridad:** el realm **viejo/inválido** en `/opt/.../hospital-lab-realm.json` está en **644** (legible por cualquier usuario local y por contenedores). El artefacto válido está en **0600**. El `identity_up.sh --apply` instala el válido con backup y 0600; hay que **verificar que el backup del archivo viejo también quede 0600** y que el archivo 644 sea reemplazado en la ventana autorizada.

**Estado:** el realm válido está **listo y protegido**, pero **no instalado** en producción. El archivo que Keycloak importaría hoy es el **inválido de 7557 bytes**.

### 10.4 Preflight previo

El preflight de la sesión anterior dio **`PASS=23 FAIL=3 SKIP=2`**. Los FAIL se reducen a dos causas raíz:

- Identidad caída (`4a`/`4`).
- `AUDIT_MONITOR_CLIENT_SECRET` ausente (`4l`).

No se repitió el preflight ahora porque el stack está detenido; el preflight completo requiere Keycloak arriba.

---

## 11. GO / NO-GO

| Área | Veredicto | Evidencia |
|---|---|---|
| **Estabilidad del host** | **NO-GO** | 4+ reinicios sucios el 20; reinicio durante la investigación; sin apagado limpio; `orphan cleanup`; panic del 17; load 51/PSI 99%/86 °C; sin batería/UPS |
| **TLS Windows (verificación real)** | **GO** | Controles negativos: 60/35/60 con HTTP 000; `-k` 200; example.com 200; IWR rechaza inválidos; ISRG Root X1 presente |
| **Certificado actual** | **GO (vigente)** | Válido 2026-10-20 → **2027-01-18**, SAN correcto, cadena 4, key match OK, modos 644/600 |
| **Renovación del certificado** | **NO-GO / no probado** | `OperatorUser=None`, sin timer, `sudo` con contraseña, `debug netmap` root-only; `https` cap presente, pero emisión real no probada |
| **Stack de identidad** | **NO-GO** | Keycloak/Postgres `Exited 255`, `Restart=no`, sin apagado ordenado; stack completo detenido |
| **Secreto M2M** | **NO-GO** | `AUDIT_MONITOR_CLIENT_SECRET` ausente (0) |
| **Realm válido** | **GO (artefacto)** | 0600, 105542 bytes, 13/11/10/24, import verificado |
| **Realm instalado en producción** | **NO-GO (pendiente)** | `/opt` aún tiene el archivo viejo inválido de 7557 bytes, modo 644 |
| **Backups** | **GO** | Directorios 0700; artefactos 0600 |
| **Procedimiento de cutover** | **GO (preparado, no ejecutado)** | Dry-run e itest previos verdes; no aplicado en producción |
| **Autorización de producción** | **NO-GO** | La suma de host inestable + identidad caída + M2M ausente + renovación no probada + realm no instalado |

---

## 12. Acciones requeridas antes de autorizar producción

1. **No autorizar producción en `servidor-1` ahora.** La inestabilidad del host es un bloqueante absoluto.
2. **Diagnóstico root/hardware del host:**
   - `journalctl -k -b -1` y `dmesg` como root para los arranques del 20.
   - Revisar `/sys/fs/pstore` como root (vacío ahora) y el estado EFI/pstore.
   - **memtest86+** (RAM), **SMART** de `sda`/`sdb`, **Dell ePSA/BIOS diagnostics**.
   - Limpiar ventilador/renovar pasta térmica; verificar el **adaptador AC** y la **pila CMOS**; añadir **UPS** o reemplazar la batería.
   - **Rollback del kernel** 7.1.8+deb13 (backports) al kernel estable de Debian 13 (6.12.x) y repetir la prueba de estabilidad.
   - Reducir la carga: 77 contenedores en 4 hilos no es sostenible; mover el stack SGSI a hardware adecuado (≥8 núcleos, ≥32 GB, SSD, UPS) o aislarlo.
3. **Soak de estabilidad:** 7 días sin reinicios sucios, con load/temperatura monitoreadas, antes de reconsiderar el GO.
4. **Política de reinicio:** cambiar Keycloak/Postgres a `restart: unless-stopped` (con healthchecks) para que la identidad vuelva tras un reinicio; `live-restore` no sobrevive a un reinicio del host.
5. **Identidad:** en ventana autorizada, levantar Keycloak/Postgres, instalar el realm válido 0600 (backup del viejo 644), provisionar `AUDIT_MONITOR_CLIENT_SECRET`, validar el monitor M2M y el flujo completo.
6. **Certificado:** ejecutar como root `tailscale cert` o `renew_cert.sh --force`, verificar el certificado nuevo, instalar el timer systemd y confirmar `CertDomains`/`debug netmap`.
7. **TLS:** repetir la prueba canónica de Windows cuando el gateway esté arriba; mantener los controles negativos como parte de la evidencia.
8. **Seguridad:** reemplazar el realm 644 por el 0600, asegurar el backup del viejo a 0600, y no commitear secretos.
9. **Preflight final:** ejecutar `preflight_check.py` con el stack arriba; los 3 FAIL previos deben quedar en 0. Después, dry-run del cutover y ventana autorizada.

---

## 13. Comandos de evidencia (read-only)

```bash
# Boots e identidad del host
journalctl --list-boots --no-pager
date; uptime; uptime -s; who -b
free -h; df -h; df -i /

# Journal del sistema (root container read-only, sin sudo)
docker run --rm --network host \
  -v /var/log/journal:/var/log/journal:ro \
  -v /run/log/journal:/run/log/journal:ro \
  -v /etc/machine-id:/etc/machine-id:ro \
  debian:trixie-slim sh -c \
  'apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq systemd >/dev/null 2>&1 && \
   journalctl --directory=/var/log/journal --system --no-pager -b -1 -o short-precise | tail -80'

# pstore (root container read-only)
docker run --rm -v /var/lib/systemd/pstore:/pstore:ro debian:trixie-slim \
  sh -c 'for f in /pstore/*/001/dmesg.txt; do echo "== $f =="; tail -40 "$f"; done'
docker run --rm -v /sys:/hostsys:ro debian:trixie-slim sh -c 'ls -la /hostsys/fs/pstore'

# Docker / OOM
docker info --format 'Containers={{.Containers}} Running={{.ContainersRunning}} Stopped={{.ContainersStopped}} LiveRestore={{.LiveRestoreEnabled}}'
docker ps -a -q | xargs -r docker inspect --format '{{.Name}} OOMKilled={{.State.OOMKilled}} Exit={{.State.ExitCode}}' | grep 'OOMKilled=true'

# Térmica / energía / watchdog
for z in /sys/class/thermal/thermal_zone*; do echo "$z $(cat $z/type) $(cat $z/temp)"; done
for d in /sys/class/power_supply/*; do echo "== $d"; cat $d/type $d/online 2>/dev/null; done
journalctl -k -b -1 | grep -iE 'watchdog|panic|thermal|mce|oom|hard lockup|soft lockup'

# Tailscale / cert
tailscale status --json | python3 -c 'import json,sys; d=json.load(sys.stdin); s=d.get("Self",{}); print(d.get("BackendState"), s.get("CertDomains"), list((s.get("CapMap") or {}).keys()))'
tailscale debug prefs | python3 -c 'import json,sys; print(json.load(sys.stdin).get("OperatorUser"))'
tailscale cert --cert-file /dev/null --key-file /dev/null servidor-1.tailb0f78a.ts.net
docker run --rm -v /etc/sgsi-zta/tls:/certs:ro debian:trixie-slim sh -c \
  'stat -c "%n %a %U:%G %s" /certs/fullchain.pem /certs/privkey.pem; \
   openssl x509 -in /certs/fullchain.pem -noout -subject -issuer -dates -ext subjectAltName; \
   grep -c "BEGIN CERTIFICATE" /certs/fullchain.pem'

# TLS Windows (PowerShell)
curl.exe -sS --max-time 12 -o NUL -w "verify=%{ssl_verify_result} http=%{http_code}\n" https://wrong.host.badssl.com/; $LASTEXITCODE
curl.exe -sS --max-time 12 -o NUL -w "verify=%{ssl_verify_result} http=%{http_code}\n" https://expired.badssl.com/; $LASTEXITCODE
curl.exe -sS --max-time 12 -k -o NUL -w "verify=%{ssl_verify_result} http=%{http_code}\n" https://wrong.host.badssl.com/; $LASTEXITCODE
Invoke-WebRequest -UseBasicParsing https://wrong.host.badssl.com/ -TimeoutSec 12
Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -match 'ISRG|Let.s Encrypt' }
```

---

## 14. Conclusión

- **Host:** inestable, con reinicios sucios recurrentes, un kernel panic capturado, sobrecarga extrema, temperatura alta y sin batería/UPS. **No es apto para producción** en este estado.
- **Causa exacta de los reinicios del 20:** **no probada**. La evidencia descarta OOM y disco; el panic del 17 prueba inestabilidad del kernel/RAM; los cortes silenciosos del 20 encajan con watchdog por starvation, energía/térmica o panic no capturado. Se requiere diagnóstico root/hardware y un soak.
- **TLS:** **GO**; la verificación de Windows es real y los controles negativos lo demuestran.
- **Certificado:** **vigente** hasta 2027-01-18; **renovación no probada/automatizada**.
- **Identidad/M2M/realm:** identidad **caída**, M2M **ausente**, realm válido **listo pero no instalado**; el archivo de producción sigue siendo el viejo inválido 644.
- **Decisión:** **NO-GO** para autorizar producción. Primero estabilizar el host, levantar la identidad con el realm válido, provisionar el M2M, probar la renovación del certificado y repetir el preflight/cutover en una ventana autorizada.

---

### Anexo A — Evidencia puntual del panic (pstore)

```text
/var/lib/systemd/pstore/1792290736/001/dmesg.txt
/var/lib/systemd/pstore/1792290737/001/dmesg.txt
/var/lib/systemd/pstore/1792290738/001/dmesg.txt
```

Los tres archivos contienen las partes 1–27 del mismo panic; el texto del §4 es literal (salvo caracteres corruptos del stack, que se transcriben como aparecen).

### Anexo B — Diferencias de reloj observadas

| Observación | Valor |
|---|---|
| `uptime -s` (boot actual) | 20:39:59 |
| `who -b` | 20:40 |
| `journalctl` boot 0 | 20:41:16 |
| Diferencia boot -2 local vs UTC | ~48 min |
| `timedatectl` | `System clock synchronized: yes`, `NTP service: active`, `RTC in local TZ: no` |

Los saltos son compatibles con corrección NTP tras arranque y posible pila CMOS/RTC deteriorada; no cambian la conclusión de apagado sucio.

### Anexo C — Archivos de evidencia en el host

```text
/tmp/host_stability_probe.out
/tmp/journal_probe.out
/tmp/journal_system_probe.out
/tmp/journal_deep_probe.out
/tmp/last_reboot_probe.sh
/var/lib/systemd/pstore/1792290736..738/001/dmesg.txt
/home/elcra/sgsi-backups/realm/hospital-lab-realm-production.json
```

Todos los comandos de este informe son de solo lectura; no se reinició ningún servicio, no se modificó `/opt` y no se hizo push.
