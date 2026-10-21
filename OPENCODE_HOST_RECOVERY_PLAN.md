# Plan de recuperación de `servidor-1` — Diagnóstico, estabilización y decisión

**Fecha:** 2026-10-20 21:05 (America/Lima, UTC-05)
**Host:** `servidor-1` (`servidor-1.tailb0f78a.ts.net`, `100.78.61.51`)
**Base:** `OPENCODE_HOST_STABILITY.md` (2026-10-20 20:52) + snapshot read-only de las 21:05.
**Alcance:** plan de diagnóstico y recuperación. **No** se reinició nada, **no** se cambió el kernel, **no** se desplegó nada y **no** se modificó producción.
**Regla:** todo lo que implique instalar, reiniciar, cambiar kernel, parar contenedores o tocar `/opt` requiere **ventana autorizada**, acceso root y, para el kernel, **acceso físico**.

---

## 0. Resumen ejecutivo

El host sigue **NO-GO** para producción. El snapshot de las 21:05 muestra **25 minutos de uptime**, load **4.6**, CPU pressure **~25%**, **80 °C** de CPU, **77 contenedores corriendo** y el stack SGSI de producción **detenido**. No alcanza para declarar estabilidad: el patrón de reinicios sucios sigue vigente y el host ya se reinició cuatro veces el 20/10.

**Orden de recuperación:**

1. **P0 — Backups verificables fuera del host.** Hoy el backup real es solo el realm y las claves IoMT; los directorios `pre_cutover`, `pre_restore` y `pre_rollback` están **vacíos**. No hay DB, Wazuh, compose, `.env`, TLS de producción, `/etc` ni `/boot` respaldados. Esto es lo primero: si el host muere o se corrompe, no hay recuperación completa.
2. **P1 — Causa de los reinicios.** Journal root por arranque, pstore/EFI, watchdog, energía, térmica, reloj/CMOS, ePSA/BIOS. La causa exacta del 20/10 **no está probada**; hay que acotarla antes de tocar el kernel.
3. **P1 — Kernel panic y RAM.** Preservar el pstore del 17/10, correr **memtest86+**, SMART y, si RAM/hardware están sanos, probar el **6.12 estable ya instalado** como arranque alternativo.
4. **P1 — Térmica, SMART y alimentación.** 80 °C en reposo relativo, laptop sin batería, sin UPS, HDD Toshiba de 1 TB sin SMART medido.
5. **P2 — Carga real y aislamiento.** El host no es un lab dedicado: corre Supabase (27 contenedores), Nextcloud, fancypets, yape y otros; el SGSI compite por 4 hilos. Hay que medir, limitar y **migrar o aislar**.
6. **P2 — Decisión Debian vs migrar.** Debian 13 es adecuado; **este hardware no**. Recomendación: migrar el laboratorio a un host dedicado y dejar la laptop como lab/PoC, o estabilizarla solo como lab con el stack mínimo.
7. **P2 — Kernel 6.12 como prueba controlada.** Ya está instalado (`6.12.107`); no hace falta instalar. El riesgo es el arranque: requiere respaldo, entrada alternativa en GRUB, acceso físico y recuperación con USB live.
8. **P3 — Producción.** Solo después de un soak de 7–14 días con criterios medibles, backups restaurados y, para producción, hardware adecuado.

**Recomendación de fondo:** no autorizar producción en esta laptop. Estabilizarla como laboratorio/PoC después de P0–P2; para producción, migrar a un host dedicado con ECC, UPS, RAID y acceso remoto. El detalle está en §10.

---

## 1. Snapshot read-only de las 21:05

| Dato | Valor actual | Lectura |
|---|---|---|
| Uptime | 25 min (boot 20:41) | Sigue dentro del patrón; 25 min no es soak |
| Load / CPU PSI | 4.60 / 5.09 / 5.56; `some` 26.56 / 24.87 / 25.09 % | 4 hilos, carga alta sostenida |
| Memoria | 10 GiB usados / 15 GiB; 5.2 GiB disponibles; swap 0 | Sin OOM; no es la causa |
| Temperatura | `x86_pkg_temp` 80 °C; `pch` 70.5 °C | Alta para la carga; riesgo térmico |
| Discos | `sda`: Kingston SKC600256G SSD 238.5 G (EFI 976 M, root 225.2 G, swap 12.3 G); `sdb`: Toshiba MQ01ABD100 HDD 931.5 G (data ext4 916 G, 1 % usado) | Root en SSD SATA; data en HDD 5400 rpm |
| Contenedores | 97 totales, 77 corriendo | Host multiproyecto, no lab dedicado |
| Top CPU | cadvisor 32.9 %; Supabase Kong 17.1/9.7 %; Supabase Meta 16.1 %; Studio 14.1 %; Minio 12.5 % | El consumo principal **no** es el SGSI |
| SGSI producción | 10 contenedores `Exited (255)`; `restart: no` | Sigue detenido |
| Kernel | `7.1.8+deb13-amd64` corriendo; `6.12.107+deb13-amd64` **instalado** | El kernel estable ya está en disco |
| Meta kernel | `linux-image-amd64` 7.1.8-1~bpo13+1; candidato 7.2.9 backports; 6.12.113 security disponible | Riesgo de upgrade automático a 7.2.9 |
| GRUB | `GRUB_DEFAULT=0`, `GRUB_TIMEOUT=5`; `grub.cfg` 0600 root; EFI=yes | Menú de 5 s; no se pudo leer `grub.cfg` como `elcra` |
| Watchdog / panic | `panic=90`, `panic_on_oops=0`, `watchdog=1`, `watchdog_thresh=10`; iTCO 300 s activo; softdog 60 s inactivo | Un panic reinicia a los 90 s; el iTCO corta a los 5 min |
| SMART / sensores | `smartctl`, `sensors`, `efibootmgr`, `dkms` **no instalados** | SMART y fan/voltajes sin medir |
| Backups | `realm` 196 K, `secrets` 8 K, `issuer-test` 100 K; `pre_*` 4 K vacíos | **No hay backup de recuperación completo** |
| Herramientas backup | `borg`, `rsync`, `zstd`, `gpg` OK; `restic`, `age` no | Borg es la opción recomendada |
| Tailscale | `CertDomains=None`, pero `https=True`; sin timer | Renovación no automatizada |
| Red/almacenamiento | `fstab` con montaje CIFS a la estación Windows; data en HDD local | El CIFS puede ser copia secundaria, no la única |

**Hallazgos nuevos que cambian el plan:**

- **El kernel 6.12 ya está instalado.** La vuelta al estable no requiere instalar paquetes: requiere **seleccionar la entrada correcta en GRUB**, con respaldo y recuperación. Eso reduce el riesgo, pero no lo elimina: si el arranque falla, la laptop no tiene IPMI ni consola remota.
- **El backup actual es insuficiente.** Solo hay realm y secretos IoMT; no hay DB de Keycloak/Postgres, Wazuh, compose, `.env`, TLS de producción, `/etc`, `/boot` ni imagen del sistema. Los `pre_*` están vacíos. **P0 real.**
- **El host es multiproyecto.** 27 contenedores de Supabase, Nextcloud, fancypets, yape, etc.; el SGSI es una fracción. No se puede estabilizar el lab sin aislar o migrar la carga conviviente.
- **La temperatura sigue alta.** 80 °C de CPU con load 4.6 y 25 min de uptime; el disipador/pasta/ventilación y el dGPU `amdgpu` son candidatos.
- **El HDD de datos no tiene SMART medido.** Es un Toshiba 1 TB de 2.5"; si falla, se pierde `/srv` y possiblemente backups locales.
- **El `panic=90` explica reinicios tras panic, no los resets silenciosos.** Los resets del 20/10 no dejaron pstore: apuntan a watchdog, energía o térmica, no a un panic registrado.

## 2. Prioridades P0–P3

| Prioridad | Objetivo | Depende de | Criterio de salida |
|---|---|---|---|
| **P0** | Backup completo y verificable **fuera del host** | Nada | Restore probado; checksums; copia off-host; RPO/RTO definidos |
| **P1** | Acotar causa de reinicios sucios | P0 (evidencia preservada) | Hipótesis descartadas o confirmadas con evidencia root/pstore/energía/térmica |
| **P1** | Analizar kernel panic y descartar RAM | P0 | Pstore preservado; memtest 0 errores; SMART sano |
| **P1** | Bajar temperatura y medir fan/voltajes | P0/P1 | CPU p95 < 80 °C; sin throttling; fan estable |
| **P1** | Medir SMART de SSD y HDD | P0 | 0 reasignados/pendientes/uncorrectables; self-test OK |
| **P1** | Asegurar energía (batería/UPS/adaptador/CMOS) | P0 | 0 eventos de corte; UPS online; reloj estable |
| **P2** | Medir y reducir carga real; aislar SGSI | P1 | Load p95 < 4; PSI < 10 %; contenedores con límites |
| **P2** | Decidir Debian vs migrar | P1/P2 | Decisión documentada con costo/riesgo |
| **P2** | Probar 6.12 con arranque alternativo | P0, P1, acceso físico | 7 días estable en 6.12; fallback probado |
| **P3** | Autorizar producción | Todo lo anterior + hardware adecuado | Gates de §12 cumplidos |

**Regla de orden:** no se toca el kernel ni se para producción antes de P0. El host se reinicia en intervalos irregulares (a veces < 30 min); un cambio de kernel ahora, remoto y sin acceso físico, es un riesgo de dejar la laptop sin arranque.

---

## 3. P0 — Backups verificables fuera del host

### 3.1 Diagnóstico del backup actual

| Ubicación | Tamaño | Contenido | Veredicto |
|---|---|---|---|
| `/home/elcra/sgsi-backups/realm/` | 196 K | `hospital-lab-realm-production.json` (105542 B, 0600) + versión anterior | **Válido como backup lógico de Keycloak** |
| `/home/elcra/sgsi-backups/secrets/` | 8 K | Claves IoMT / secretos locales | Parcial; no incluye `.env` de producción |
| `/home/elcra/sgsi-backups/issuer-test/` | 100 K | `ca.key`, `tls.key` de **prueba**, `probe.py`, compose | Solo test; no es producción |
| `/home/elcra/sgsi-backups/pre_cutover/` | 4 K | **Vacío** | No cuenta como backup |
| `/home/elcra/sgsi-backups/pre_restore/` | 4 K | **Vacío** | No cuenta como backup |
| `/home/elcra/sgsi-backups/pre_rollback/` | 4 K | **Vacío** | No cuenta como backup |

**Gaps críticos:**

- No hay backup de la **DB de Keycloak/Postgres** (volumen Docker), ni de **Wazuh**, ni de los volúmenes de `clinical-poc`.
- No hay backup del **`.env` de producción** (`/opt/sgsi-zta-hospital-lab/.env`, 0600).
- No hay backup del **TLS de producción** (`/etc/sgsi-zta/tls/fullchain.pem` y `privkey.pem`).
- No hay backup de **`/opt/sgsi-zta-hospital-lab`** (compose, config, Caddyfile) ni de **`/etc`**, **`/boot`**, **EFI**, lista de paquetes, `fstab`, estado de Tailscale.
- Todo está **en el mismo host**, en el SSD root. Si el SSD falla o el host se pierde, no hay recuperación.

### 3.2 Qué respaldar y con qué método

| Activo | Método | Frecuencia | Retención | Verificación |
|---|---|---|---|---|
| Realm Keycloak | `kc.sh export` + validación JSON | Diario / tras cambios | 30 días | Import en Keycloak aislado |
| Postgres Keycloak | `pg_dump -Fc` (DB arriba) o copia consistente con DB detenida | Diario | 7 diarios / 4 semanales / 3 mensuales | `pg_restore --list` + restore en test |
| `.env`, TLS prod, claves IoMT | `borg` con patrón explícito; nunca imprimir | Diario / tras cambios | 30 días | Hash + restore controlado |
| Volúmenes Docker | `tar`/`borg` con contenedor detenido o volumen `:ro` | Diario/semanal | 4 semanales | Restore en host aislado |
| Compose/config/repo | Git + `borg` | Diario | 30 días | `docker compose config` |
| `/etc`, `/boot`, EFI, `dpkg --get-selections`, `lsmod` | `borg`/`tar` | Semanal | 3 mensuales | Arranque en VM/USB de prueba |
| Imágenes Docker críticas | `docker save` o registry | Semanal | 2 versiones | `docker load` en test |
| Evidencia pstore/journal | Copia + hash | Antes de limpiar | Permanente | SHA-256 |

### 3.3 Destino y arquitectura 3-2-1

- **3 copias, 2 medios, 1 fuera de sitio.** Como mínimo: (a) repo `borg` en SSD externo cifrado, (b) copia en NAS/segundo host, (c) copia off-site (nube cifrada o sede distinta).
- **Cifrado en reposo y en tránsito.** `borg` con `repokey-blake2`; el disco externo además con LUKS; la passphrase en un gestor de contraseñas, **nunca** en el host ni en el repo.
- **El montaje CIFS a la estación Windows** que ya está en `fstab` puede servir como copia secundaria temporal, pero **no** como único destino: CIFS no es ideal para un repo `borg` (locking/permisos). Si se usa, guardar un archivo `tar.zst.gpg` verificado, no un repo vivo.
- **La clave privada TLS de producción** la copia un operador autorizado, cifrada y con permisos 0600; no se imprime, no se pega en chats y no se deja en el repo.

### 3.4 Procedimiento recomendado (ventana autorizada)

1. **Preservar evidencia:** copiar pstore, journal de los boots `-1..-4`, `dmesg` actual y `journalctl --list-boots` a un archivo con hash. No limpiar pstore.
2. **Backup lógico de Keycloak:** exportar realm desde una copia consistente; validar JSON; comparar counts (clients, roles, users, flows). El artefacto de 105542 B ya está validado; usarlo como referencia.
3. **Backup de DB:** con Keycloak/Postgres detenidos, copiar el volumen; o levantar Postgres en ventana controlada y `pg_dump -Fc`. No copiar un volumen Postgres “en caliente” y llamarlo backup.
4. **Backup de archivos críticos:** `.env`, `/etc/sgsi-zta/tls`, `/opt/sgsi-zta-hospital-lab`, `/home/elcra/sgsi-backups`, `/etc`, `/boot`, EFI, `fstab`, `dpkg --get-selections`, `lsmod`, estado de Tailscale.
5. **Backup de volúmenes:** Wazuh, clinical-poc y demás; documentar cuáles son reconstruibles y cuáles no.
6. **Crear repo `borg` cifrado** en el destino externo; `borg create` con `--stats --compression zstd --numeric-ids --acl --xattrs`; excluir cachés y basura.
7. **Copiar off-host** y verificar SHA-256 de los artefactos; `borg check --verify-data`.
8. **Restore test** en un host/VM aislado: importar realm, `pg_restore`, verificar key/cert, `docker compose config`. No restaurar sobre producción.
9. **Documentar RPO/RTO** y programar el backup diario/semanal con alerta.

**Plantilla de comandos (sin secretos):**

```bash
# Destino externo cifrado, montado en /mnt/backup
export BORG_REPO=/mnt/backup/sgsi-borg
# La passphrase se ingresa interactivamente o desde el gestor; NO en el host.
borg init --encryption=repokey-blake2 "$BORG_REPO"
borg create --stats --compression zstd --numeric-ids --acl --xattrs \
  "$BORG_REPO::sgsi-{now}" \
  /etc /boot /opt/sgsi-zta-hospital-lab /home/elcra/sgsi-backups \
  /etc/sgsi-zta/tls
borg check --verify-data "$BORG_REPO"
borg list "$BORG_REPO"
```

Para DB: `pg_dump -Fc -f /backup/keycloak.dump <db>` y luego `borg create` del dump. Para volúmenes: detener el contenedor, `tar -C /var/lib/docker/volumes/<vol> -czf` o `borg` del path; nunca con la DB escribiendo.

### 3.5 RPO/RTO propuestos

| Activo | RPO | RTO |
|---|---|---|
| Realm / configuración Keycloak | 24 h (1 h si hay cambios) | 4 h |
| DB Keycloak/Postgres | 24 h | 4 h |
| `.env` / TLS / IoMT | 24 h / tras cambio | 4 h |
| Host completo | 24 h | 8 h |
| Wazuh / datos clínicos | Definir con el negocio | Definir |

### 3.6 Checklist P0

- [ ] Inventario completo de volúmenes y archivos críticos.
- [ ] Backup lógico de realm validado e importado en test.
- [ ] `pg_dump` verificado con `pg_restore --list`.
- [ ] `.env`, TLS, IoMT y compose en repo cifrado.
- [ ] `/etc`, `/boot`, EFI y lista de paquetes respaldados.
- [ ] Copia off-host con checksum.
- [ ] Restore test pasado.
- [ ] RPO/RTO documentados y alerta de backup activa.

**Riesgo si se posterga:** el host puede morir o corromper el SSD; hoy no hay forma de reconstruir Keycloak/Postgres, Wazuh ni el TLS de producción. Es el riesgo más alto y el más barato de mitigar.

---

## 4. P1 — Causa de los reinicios

### 4.1 Evidencia que ya tenemos

- Reinicios sucios el 20/10: 15:04, 15:43/15:45, 17:49, 20:37/20:40; el host se reinició **durante** la investigación.
- Sin `systemd-shutdown`, sin `Reached target Shutdown/Reboot`, sin `Journal stopped` en los boots recientes; corte abrupto.
- `EXT4-fs (sda2): orphan cleanup on readonly fs` en boots `-1` y `-3`; `sdb2` en `-2`. El filesystem no se desmontó limpio.
- Sin OOM, sin `oom-kill`, sin `OOMKilled=true`; memoria 10/15 GiB, 5.2 GiB disponibles, swap 0.
- Sin agotamiento de disco: root 68 G usados de 221 G (33 %), inodos 10 %; `sdb` 1 %.
- Sin `EXT4-fs error`, `I/O error` ni remount read-only en el journal reciente.
- Pstore del 17/10: panic real `stack-protector: Kernel stack is corrupted in: __x64_sys_epoll_pwait`, kernel `7.1.8+deb13`, `Tainted: G I`, `__stack_chk_fail`.
- Sin MCE/térmica crítica/panic en el journal del 20/10; solo watchdog init, `i915`/`amdgpu`.
- iTCO_wdt 5 min activo; softdog 60 s inactivo; `panic=90`.
- Load 51 al boot; CPU PSI 98.9 %; 86 °C; luego 4.6–7 y 80 °C. 77 contenedores en 4 hilos.
- Sin batería; solo AC; sin UPS. Reloj con saltos de hasta ~48 min; NTP sincronizado; posible CMOS/RTC.

### 4.2 Matriz de hipótesis

| Hipótesis | Evidencia a favor | Evidencia en contra | Prueba | Decisión |
|---|---|---|---|---|
| **Watchdog / PID1 starvation** | Load 51, PSI 99 %, 4 hilos, 77 contenedores, iTCO 300 s, sin shutdown limpio | No hay log de watchdog reset | Journal root del boot anterior, `systemd` watchdog, `/sys/class/watchdog`, reducir carga y soak | Si desaparece a baja carga, es la causa principal |
| **Energía / adaptador / VRM** | Sin batería, sin UPS, resets bajo carga, reloj salta | AC online; no hay evento ACPI | UPS/batería, power meter, adaptador conocido, `upower`/`acpi`, `dmidecode -t 39` | Si los resets coinciden con carga/corte, es energía |
| **Térmica / EC** | 80–86 °C, laptop consumer, dGPU, sin limpieza | No hay `critical` ACPI en journal | `sensors`, fan RPM, limpieza/pasta, ePSA, correlación temp/reset | Si baja la temp y no reinicia, es térmica |
| **Kernel panic (7.1.8 backports)** | Pstore 17/10, stack-protector, `Tainted: G I` | Los resets del 20/10 no dejaron pstore | 6.12 controlado, memtest, kdump/netconsole | Si 6.12 no paniquea en 7 días, el kernel es candidato |
| **RAM / hardware** | Stack corruption, sin ECC, laptop 2016 | Memtest no ejecutado | memtest86+ 4+ pasadas; ePSA; SMART | Si hay errores, reemplazar RAM/equipo |
| **Disco / I/O** | HDD Toshiba sin SMART; SSD SATA | Sin errores EXT4/ATA en journal | `smartctl -a`, self-test, `dmesg` root | Si SMART falla, reemplazar y restaurar |
| **Reinicio forzado por software** | Podría ser `reboot -f`, `sysrq`, cron | No hay evidencia; `monit` solo alerta | Auth logs, `wtmp`, timers, cron, `journalctl` root | Descartar antes de concluir hardware |

### 4.3 Pruebas concretas (solo lectura o ventana root)

**Ahora, sin cambios (root read-only):**

```bash
# Journal por arranque, kernel y shutdown
for b in -1 -2 -3 -4; do
  journalctl -b "$b" -k --no-pager | tail -200
  journalctl -b "$b" --no-pager | grep -Ei 'shutdown|reboot|power|thermal|mce|watchdog|panic|oops|hung|lockup' | tail -100
done
journalctl --list-boots --no-pager
cat /proc/sys/kernel/panic /proc/sys/kernel/panic_on_oops
cat /proc/sys/kernel/watchdog /proc/sys/kernel/watchdog_thresh
for w in /sys/class/watchdog/watchdog*; do echo "$w"; cat "$w/identity" "$w/timeout" "$w/state"; done
systemctl show -p RuntimeWatchdogUSec -p RebootWatchdogUSec
```

**Pstore/EFI:**

```bash
ls -l /sys/fs/pstore /var/lib/systemd/pstore 2>/dev/null
# Copiar y hashear antes de limpiar; no borrar.
```

**Energía/térmica/reloj:**

```bash
for d in /sys/class/power_supply/*; do echo "$d"; cat "$d/type" "$d/online" 2>/dev/null; done
for z in /sys/class/thermal/thermal_zone*; do printf '%s %s %s\n' "$z" "$(cat "$z/type")" "$(cat "$z/temp")"; done
timedatectl; hwclock --show 2>&1 || true
journalctl -k --no-pager | grep -Ei 'ACPI|thermal|power|battery|mce|throttl' | tail -100
```

**ePSA/BIOS/firmware:** requiere acceso físico. Dell ePSA (F12) para RAM, disco, fan, batería; `dmidecode -t 1,3,4,39` para BIOS/sistema/procesador/power supply. Un update de BIOS solo después de P0 y con UPS.

### 4.4 Cómo cerrar la causa (o la incertidumbre)

- **Si a baja carga (solo SGSI mínimo, < 10 contenedores) no hay reinicios en 72 h:** la hipótesis principal es watchdog/starvation por carga; el problema es de capacidad, no solo de kernel.
- **Si los reinicios coinciden con picos térmicos o de consumo:** térmica/energía; resolver cooling/UPS/adaptador antes de cualquier kernel.
- **Si hay panic/oops en pstore o journal:** kernel/RAM; memtest y 6.12.
- **Si no hay evidencia concluyente:** tratar el host como **no confiable**; no autorizar producción; migrar. La ausencia de causa no es un aprobado.

**Riesgo:** cada prueba que reinicia o estresa el host puede corromper el filesystem. Por eso P0 primero y, para memtest, ventana con backup verificado.

## 5. P1 — Kernel panic y RAM

### 5.1 Preservar y analizar el panic

- El pstore del 17/10 es la **única evidencia directa de panic**. Copiarlo con hash antes de cualquier limpieza; no borrar `/var/lib/systemd/pstore` ni `/sys/fs/pstore`.
- DATOS: `Kernel panic - not syncing: stack-protector: Kernel stack is corrupted in: __x64_sys_epoll_pwait+0x137/0x140`; `CPU: 0 UID: 0 PID: 3377 Comm: node Tainted: G I 7.1.8+deb13-amd64`; `Tainted: [I]=FIRMWARE_WORKAROUND`; `__stack_chk_fail`; traza con `alloc_low_pages` incoherente.
- El kernel es **7.1.8 backports**, no el estable 6.12. Un panic por stack corruption puede ser bug de kernel, RAM, firmware o driver; no se puede atribuir solo al kernel sin memtest y sin reproducir en 6.12.
- `panic=90` hace que un panic reinicie a los 90 s; eso explica un reinicio con pstore, pero **no** los resets silenciosos del 20/10. Si no hay pstore, la hipótesis principal no es panic.

### 5.2 memtest86+ (obligatorio antes de culpar al kernel)

- Requiere **downtime** y acceso físico. Arrancar desde USB con memtest86+; mínimo **4 pasadas completas**, ideal 8; 0 errores.
- La laptop Inspiron 5559 tiene 2 slots SODIMM; si hay errores, probar módulo por módulo para identificar el fallo. Sin ECC, memtest es la única defensa.
- Si memtest falla: reemplazar RAM; no perder tiempo cambiando kernels. Si memtest pasa y 6.12 sigue paniqueando, el problema es kernel/driver/firmware o placa; recolectar pstore/kdump y evaluar reemplazo/migración.

### 5.3 Probar 6.12 (sin instalar)

- `6.12.107+deb13-amd64` **ya está instalado**; el arranque alternativo existe. El runbook completo está en §11.
- No ejecutarlo ahora: el host se reinicia en intervalos irregulares (a veces < 30 min) y no hay IPMI. Un fallo de arranque deja la laptop inaccesible hasta ir físicamente.
- Prerrequisitos: P0 backup verificado, memtest/SMART/térmica/energía diagnosticados, acceso físico, USB live, ventana estable, `7.1.8` conservado como fallback.
- Si 6.12 es estable 7 días: mantenerlo; congelar backports para que un `apt upgrade` no instale 7.2.9; conservar 7.1.8 30 días.
- Si 6.12 también falla: no seguir cambiando kernels; el problema es hardware/firmware; migrar o reemplazar.

### 5.4 Evidencia para el futuro

- `kdump`/`pstore`/`netconsole`: opcionales; la laptop no tiene serial. `netconsole` a un host de logs puede capturar panics si la red está estable. No configurar ahora; planificar en la ventana.
- Mantener `pstore` habilitado y con espacio; `systemd-pstore` copia y limpia; revisar que no se pierdan registros.
- Documentar el panic con hash, fecha, kernel, carga y temperatura; adjuntar a la incidencia de hardware.

**Riesgo:** memtest y 6.12 requieren reinicios; sin backup off-host, un corte durante la prueba puede dejar el sistema sin recuperación. P0 primero.

---

## 6. P1 — Temperaturas

### 6.1 Situación

- `x86_pkg_temp` **80 °C** a los 25 min con load 4.6; `pch` **70.5 °C**; en el boot anterior llegó a **86 °C** con load 51.
- El kernel no reporta `critical` ACPI; el `x86_pkg_temp` trip está inválido (`-274000`). El EC puede cortar por su cuenta, sin log.
- Laptop consumer de 2016, disipador compacto, posible polvo/pasta seca, dGPU `amdgpu` presente, 77 contenedores. La carga y la refrigeración están al límite.

### 6.2 Acciones (ventana autorizada)

1. **Instalar `lm-sensors`** y ejecutar `sensors-detect`; medir CPU, PCH, fan RPM y voltajes si el hardware los expone. `dell-smm-hwmon`/`i8k` puede dar fan; verificar.
2. **Limpieza física:** polvo en ventilador/radiador; reemplazo de pasta térmica CPU/GPU; revisar que el ventilador gire libre y que las salidas no estén bloqueadas.
3. **Ventilación:** lid abierta, base elevada, cooling pad temporal; ambiente < 27 °C; no bloquear rejillas.
4. **Reducir carga:** mover contenedores convivientes; limitar CPU; bajar el scrape de cadvisor; apagar dGPU si no se usa (BIOS o blacklist `amdgpu`, solo en prueba; verificar que la salida gráfica use `i915`).
5. **Monitoreo:** exportar temperatura/fan a Prometheus/node_exporter; alerta a 85 °C; registrar throttling (`turbostat`/`cpupower`).
6. **Umbral de seguridad:** si sostiene > 95 °C o el EC corta, apagar y migrar; no esperar a que el hardware se dañe.

### 6.3 Criterios medibles

| Métrica | Umbral | Ventana | Herramienta |
|---|---|---|---|
| `x86_pkg_temp` p95 | < 80 °C | 7 días | `sensors`/node_exporter |
| `x86_pkg_temp` máx | < 90 °C | 7 días | idem |
| `pch` p95 | < 85 °C | 7 días | idem |
| Throttling | 0 eventos | 7 días | `turbostat`/journal |
| Fan | RPM estable, sin paradas | 7 días | `sensors`/EC |
| Ambiente | < 27 °C | 7 días | sensor externo |

**Riesgo:** la limpieza/pasta puede dañar el equipo si no se hace con ESD y experiencia; hacer backup y usar técnico. Un reset térmico durante el backup puede corromper datos.

---

## 7. P1 — SMART

### 7.1 Discos y herramienta

- `sda`: **Kingston SKC600256G** SSD SATA 238.5 G (EFI, root, swap).
- `sdb`: **Toshiba MQ01ABD100** HDD SATA 931.5 G, 5400 rpm (data ext4, 1 % usado).
- `smartctl` **no está instalado**; `smartd` tampoco. Sin SMART no se puede descartar degradación del SSD/HDD.

### 7.2 Acciones

1. Instalar `smartmontools` en ventana autorizada (o usar USB live con smartctl). No instalar ahora.
2. Ejecutar:

```bash
smartctl -i -A -l error -l selftest /dev/sda
smartctl -i -A -l error -l selftest /dev/sdb
smartctl -t short /dev/sda
smartctl -t short /dev/sdb
# Esperar y leer:
smartctl -l selftest /dev/sda
smartctl -l selftest /dev/sdb
```

3. Long self-test en ventana de mantenimiento (puede tardar horas; carga el disco). No en producción.
4. Revisar atributos: `Reallocated_Sector_Ct`, `Current_Pending_Sector`, `Offline_Uncorrectable`, `UDMA_CRC_Error_Count`, `Temperature_Celsius`, `Power_On_Hours`, `Wear_Leveling_Count`/`Percentage_Used` (SSD).
5. Configurar `smartd` con alertas; incluir temperatura y fallos de self-test.

### 7.3 Umbrales y decisión

| Métrica | Sano | Alerta | Crítico |
|---|---|---|---|
| Reallocated / Pending / Uncorrectable | 0 | > 0 estable | > 0 creciente |
| CRC errors | 0 | 1–10 | > 10 o creciente |
| Self-test | Pass | — | Fail |
| Temperatura disco | < 45 °C | 45–50 °C | > 50 °C |
| SSD wear | < 80 % | 80–90 % | > 90 % |
| HDD power-on | < 30k h | 30–50k h | > 50k h + errores |

Si falla: **reemplazar el disco y restaurar desde el backup off-host**; no seguir usando el disco para producción. El HDD de datos es vulnerable (2.5", 5400 rpm); si contiene backups locales, no es un backup off-host.

**Riesgo:** un long self-test o una copia intensiva puede precipitar el fallo de un disco ya degradado. Hacer P0 y copiar los datos críticos primero.

---

## 8. P1 — Alimentación

### 8.1 Situación

- Solo `AC` online; **no hay batería**; **no hay UPS**. La laptop no tiene protección ante corte.
- El adaptador puede ser de 65 W; con i7-6500U, dGPU, HDD y 77 contenedores, el consumo puede acercarse al límite; un adaptador/VRM degradado puede resetear bajo carga.
- Reloj con saltos de hasta ~48 min; NTP sincronizado; posible **pila CMOS** agotada. No causa reinicios por sí sola, pero corrompe la correlación temporal.
- Sin eventos ACPI de corte en el journal; el reset puede ser eléctrico y no dejar log.

### 8.2 Acciones

1. **Reemplazar la batería** de la laptop si es posible (actúa como UPS integrado) y la **pila CMOS CR2032**; verificar `hwclock`/`timedatectl`.
2. **UPS line-interactive con USB** (NUT/apcupsd): runtime ≥ 15 min; apagado ordenado; alerta. Dimensionar para laptop + switch + disco externo.
3. **Adaptador conocido y certificado**: mismo voltaje, wattage igual o mayor; revisar conector/cable; evitar alargadores y regletas baratas; medir consumo con power meter.
4. **Monitoreo**: `upower -d`, `acpi -V`, `dmidecode -t 39`, eventos de AC; alerta de pérdida de energía y de batería.
5. **Prueba de corte controlada**: con UPS, simular corte y verificar apagado/encendido; no en producción.

### 8.3 Criterios medibles

| Métrica | Umbral | Ventana |
|---|---|---|
| Cortes de energía no planificados | 0 | 7 días |
| UPS online / batería | 100 %; salud ≥ 80 % | 7 días |
| Adaptador/voltaje | estable, sin caídas | 7 días |
| Reloj/NTP | offset < 1 s; sin saltos | 7 días |
| Apagado ordenado | 100 % de los reinicios planificados | 7 días |

**Riesgo:** una UPS mal dimensionada o una batería inflada es peligrosa; usar equipo certificado. El adaptador incorrecto puede dañar la laptop.

## 9. P2 — Carga real de contenedores

### 9.1 Snapshot

- **97 contenedores, 77 corriendo**, 83 imágenes; 37.44 GB imágenes, 14.11 GB contenedores, 9.2 GB volúmenes.
- **No es un lab dedicado.** Proyectos observados: Supabase (14 + 13 contenedores), SGSI (10), native (6), fancypets (6), itest (5), stream (5), monitoring (4), yape (3), source (3), nextcloud (3), entre otros.
- Top CPU: **cadvisor 32.9 %**, Supabase Kong 17.1/9.7 %, Supabase Meta 16.1 %, Studio 14.1 %, Minio 12.5 %, Kong 9.7 %; el SGSI `val-postgres` 5.5 %. El stack SGSI de producción está detenido.
- **El consumo principal no es el SGSI.** El laboratorio compite con cargas ajenas; no se puede garantizar latencia/estabilidad del lab sin aislar o migrar.

### 9.2 Medición read-only (antes de cambiar nada)

```bash
# Baseline de 5 minutos, sin cambios
for i in $(seq 1 30); do
  date +%s
  docker stats --no-stream --format '{{.Name}} {{.CPUPerc}} {{.MemPerc}}' \
    | sort -k2 -rn | head -20
  sleep 10
done > /tmp/docker_baseline.txt
```

Complementar con `systemd-cgtop`, `docker events --since 24h`, `docker ps -a --format` por proyecto, `docker inspect` de healthchecks/restart policies. No parar contenedores en esta fase.

### 9.3 Reducción y aislamiento (ventana autorizada)

1. **Mapa de dependencias:** qué proyecto depende de qué; quién es dueño; qué se puede mover/parar. No asumir que “es de prueba”.
2. **Stack SGSI mínimo:** Keycloak, Postgres, clinical-poc, gateway, monitor. Wazuh/demo solo si el cutover lo exige. El resto, apagado o en otro host.
3. **Mover convivientes:** Supabase, Nextcloud, fancypets, yape, etc. a otro host o a un entorno externo. La laptop no debe ser el host de producción de varios proyectos.
4. **Límites:** `cpus`, `mem_limit`, `pids_limit`, `restart: unless-stopped` solo para críticos; healthchecks reales; backoff.
5. **cadvisor:** bajar frecuencia de scrape o moverlo; 32.9 % de CPU en monitoreo es desproporcionado para un host de 4 hilos.
6. **Docker:** `LiveRestore=false`; tras un reset, los contenedores no vuelven solos. Para el lab, `unless-stopped`; para producción, orquestación adecuada.
7. **Medir el efecto:** mismo baseline tras cada cambio; no cambiar varias variables a la vez.

### 9.4 Criterios medibles

| Métrica | Umbral | Ventana |
|---|---|---|
| Load p95 | < 4 (1× vCPU) | 7 días |
| CPU PSI `some` p95 | < 10 % | 7 días |
| CPU PSI `full` | < 1 % | 7 días |
| Memoria disponible | > 20 % | 7 días |
| Swap | < 1 GiB | 7 días |
| OOM | 0 | 7 días |
| Top contenedor | < 50 % CPU | 7 días |
| Reinicios de contenedores | 0 | 7 días |
| Contenedores de producción | healthy | 7 días |

**Riesgo:** parar contenedores ajenos puede tumbar servicios de otras personas; requiere autorización y ventana. Mover cargas puede romper dependencias de red/volúmenes; documentar.

---

## 10. ¿Mantener Debian en este equipo o migrar el laboratorio?

### 10.1 Respuesta corta

- **Debian 13 como sistema operativo: sí.** Es estable, conocido, con Docker/Tailscale; el problema no es Debian.
- **Este hardware para producción: no.** Es una laptop consumer de 2016, 2 núcleos/4 hilos, 15 GiB sin ECC, SSD SATA + HDD 2.5", sin UPS, sin IPMI, sin PSU redundante, con térmica limitada y 77 contenedores de varios proyectos.
- **Recomendación:** **migrar el laboratorio a un host dedicado** y dejar la laptop como lab/PoC o nodo de respaldo, después de estabilizarla. Si el laboratorio es solo PoC/training, la laptop puede quedarse como lab, pero **no** como producción hospitalaria.

### 10.2 Comparación

| Criterio | Laptop actual | Host dedicado recomendado |
|---|---|---|
| CPU | i7-6500U 2C/4T | ≥ 8C/16T (Xeon/EPYC/Core moderno) |
| RAM | 15 GiB, no ECC | 32–64 GiB ECC |
| Almacenamiento | SSD 256 G + HDD 1 Tb, sin RAID | NVMe/SSD + RAID1; backups off-host |
| Energía | Sin batería, sin UPS | UPS + fuente redundante si es servidor |
| Térmica | Limitada, 80–86 °C | Disipación adecuada, sala ventilada |
| Gestión remota | Sin IPMI; solo SSH | IPMI/iDRAC/iLO o consola remota |
| Carga | 77 contenedores de varios proyectos | Solo SGSI, con límites |
| Disponibilidad | Reinicios sucios; sin HA | Soak 7–14 días; monitorización |
| Costo | Hundido | Inversión única + UPS |

### 10.3 Opciones

**A. Migrar a host dedicado (recomendado para producción).**
- Mini-server/SFF: Dell OptiPlex/Lenovo ThinkCentre/HP EliteDesk con 8–16 hilos, 32–64 GiB, NVMe + SSD SATA para backups locales, NIC Intel, UPS USB.
- Servidor usado con IPMI (Dell R630/R730xd, HPE DL380 Gen9) si hay sala/ruido/power; más consumo.
- Instalar Debian 13 estable (kernel 6.12), Docker, Tailscale; replicar compose; copiar datos; probar; cutover; dejar la laptop como fallback.
- Ventaja: ECC, UPS, IPMI, RAID, térmica, aislamiento. Desventaja: costo/tiempo.

**B. Quedarse en la laptop como lab/PoC (táctico).**
- Stack mínimo SGSI; mover los otros proyectos; UPS/batería; limpieza/pasta; 6.12; 7–14 días de soak.
- Aun así: sin ECC, sin redundancia, sin IPMI; **no** autorizar producción hospitalaria.
- Útil para validar el cutover y como entorno de pruebas.

**C. Nube/VM gestionada.**
- Si la latencia/red lo permite; menos control sobre Tailscale/LAN clínica; costo recurrente; evaluar requisitos hospitalarios y residencia de datos.

### 10.4 Decisión

- **Producción:** A. Migrar.
- **Lab/PoC:** B, después de P0–P2.
- **Si no hay presupuesto:** B con aceptación formal de riesgo, sin datos reales de pacientes; no llamarlo producción.
- **Criterio de decisión:** si el sistema va a manejar datos clínicos reales, disponibilidad y auditoría, la laptop no cumple; migrar es más barato que una caída.

---

## 11. Kernel 6.12 — Runbook con respaldo, arranque alternativo y recuperación

> **No ejecutar ahora.** El host se reinicia en intervalos irregulares (a veces < 30 min), no tiene IPMI y el arranque alternativo puede fallar. Este runbook es para una ventana autorizada, con acceso físico, USB live y P0 completado.

### 11.1 Estado actual

- Corriendo: `7.1.8+deb13-amd64` (backports).
- Instalado: `6.12.107+deb13-amd64` (estable) — **no hace falta instalar**.
- Meta `linux-image-amd64`: 7.1.8 backports; candidato 7.2.9 backports; 6.12.113 security disponible.
- `GRUB_DEFAULT=0`, `GRUB_TIMEOUT=5`; `grub.cfg` 0600 root; EFI=yes; `efibootmgr` no instalado; `dkms` no instalado (sin módulos externos).
- `panic=90`, `panic_on_oops=0`; iTCO 300 s.

### 11.2 Prerrequisitos (todos)

- [ ] P0 backup off-host verificado y restore test pasado.
- [ ] Acceso físico a la laptop, teclado/pantalla, USB live Debian 13.
- [ ] Ventana de mantenimiento; host estable el tiempo suficiente; si se reinicia en menos de 30 min, **postergar**.
- [ ] Root/sudo disponible; contraseña en mano.
- [ ] `7.1.8` y su initrd conservados; no remove.
- [ ] `update-grub` y `update-initramfs` funcionando; `/boot` con espacio (142 G libres).
- [ ] Backports congelados para que un `apt upgrade` no instale 7.2.9.
- [ ] Documento de recuperación impreso/accesible desde otro dispositivo.

### 11.3 Respaldo previo (ventana)

```bash
# Como root
mkdir -p /root/kernel-backup-$(date +%F)
cp -a /boot /root/kernel-backup-$(date +%F)/
cp -a /etc/default/grub /etc/grub.d /root/kernel-backup-$(date +%F)/
cp -a /boot/efi /root/kernel-backup-$(date +%F)/efi
dpkg --get-selections > /root/kernel-backup-$(date +%F)/packages.txt
apt-mark showhold > /root/kernel-backup-$(date +%F)/holds.txt
lsmod > /root/kernel-backup-$(date +%F)/lsmod.txt
efibootmgr -v > /root/kernel-backup-$(date +%F)/efibootmgr.txt 2>&1 || true
```

Además: `borg`/`tar` del backup a destino externo; verificar hash; el backup debe incluir `/boot`, `/boot/efi`, `/etc/default/grub`, `/etc/grub.d`, y la lista de paquetes.

### 11.4 Arranque alternativo (sin cambiar el default)

1. Verificar que la entrada 6.12 existe:

```bash
grep -i '6.12' /boot/grub/grub.cfg
```

2. Si no aparece, regenerar:

```bash
update-initramfs -u -k 6.12.107+deb13-amd64
update-grub
```

3. Aumentar temporalmente el timeout para poder elegir a mano:

```bash
# /etc/default/grub: GRUB_TIMEOUT=10 (o 15)
update-grub
```

4. Arranque **one-time** a 6.12, dejando 7.1.8 como default:

```bash
grub-reboot 'Debian GNU/Linux, with Linux 6.12.107+deb13-amd64'
grub-editenv list   # debe mostrar next_entry
```

Si el título exacto no coincide, usar el índice de la entrada (`grep -n` en `grub.cfg`) o `grub-set-default`; pero `grub-reboot` es más seguro porque el siguiente arranque vuelve al default.

5. Reiniciar en ventana; verificar `uname -r`.

**Por qué así:** si 6.12 no arranca, el próximo boot vuelve a 7.1.8 por default. Si se cambia `GRUB_DEFAULT` directo a 6.12 y falla, el host puede quedar en loop de fallo.

### 11.5 Validación y soak

- `uname -r` = 6.12.107.
- `dmesg`/`journalctl -k` sin oops/panic/stack-protector; pstore vacío.
- `systemctl --failed`; Docker; Tailscale; red; discos.
- No arrancar producción; probar el stack SGSI en lab.
- Soak **72 h mínimo, 7 días recomendado**; monitorear temperatura, load, PSI, SMART, pstore.
- Si estable: `GRUB_DEFAULT` a 6.12 (o `saved` + `grub-set-default`), conservar 7.1.8 30 días; congelar backports.
- Si falla: volver a 7.1.8 y no insistir; el problema es hardware/firmware.

### 11.6 Recuperación ante fallo de arranque

| Fallo | Acción |
|---|---|
| 6.12 panic/hang, GRUB visible | Esperar reboot/watchdog; seleccionar 7.1.8; arrancar |
| GRUB no aparece / no responde | USB live Debian; montar root; `chroot`; `grub-editenv`/`grub-set-default` a 7.1.8; `update-grub` |
| `/boot` corrupto | Restaurar `/boot` desde backup; `update-initramfs -u -k all`; `update-grub` |
| EFI/bootloader roto | USB live; `efibootmgr`/`grub-install --target=x86_64-efi --efi-directory=/boot/efi`; verificar orden de arranque |
| Disco/FS dañado | `fsck` desde live; si no, restaurar imagen/backup; reemplazar disco |
| 6.12 sin driver crítico | Volver a 7.1.8; revisar `dmesg`; no forzar |

**No hay IPMI.** Si el arranque falla y no hay acceso físico, el host queda fuera. Por eso el runbook exige presencia física y USB live.

### 11.7 Riesgos y “no hacer”

- **No** cambiar el kernel ahora, con el host reiniciándose en intervalos irregulares (a veces < 30 min).
- **No** hacerlo remoto sin acceso físico.
- **No** instalar 7.2.9 backports; usar 6.12 estable.
- **No** eliminar 7.1.8 antes de 7 días de soak.
- **No** dejar que `apt upgrade` cambie el default: `apt-mark hold linux-image-amd64 linux-image-7.1.8+deb13-amd64` o deshabilitar backports.
- **No** asumir que 6.12 arregla el panic: puede ser RAM/placa; memtest primero.

### 11.8 Si 6.12 no estabiliza

- Recolectar pstore/kdump; memtest; SMART; ePSA; BIOS/firmware.
- Si hay errores de RAM: reemplazar módulos.
- Si no hay errores: el hardware/placa es sospechoso; migrar a otro host. No seguir cambiando kernels.

## 12. Criterios medibles de estabilidad (GO/NO-GO)

### 12.1 Tabla de criterios

| Dimensión | Métrica | Umbral | Ventana | Herramienta / evidencia |
|---|---|---|---|---|
| Reinicios | Reinicios sucios | **0** | 7 días (14 recomendado) | `journalctl --list-boots`, boot ID, uptime |
| Reinicios | `orphan cleanup` al boot | **0** | 7 días | journal del boot |
| Kernel | Panic/oops/stack-protector/lockup | **0** | 7 días | pstore, `dmesg`, journal |
| Kernel | `pstore` | Vacío | 7 días | `/sys/fs/pstore` |
| Memoria | memtest86+ | ≥ 4 pasadas, **0 errores** | Una vez | USB memtest |
| Memoria | MCE / `rasdaemon` | **0** | 7 días | journal, `rasdaemon` |
| Térmica | CPU p95 / máx | **< 80 / < 90 °C** | 7 días | `sensors`/node_exporter |
| Térmica | PCH p95 | **< 85 °C** | 7 días | idem |
| Térmica | Throttling | **0 eventos** | 7 días | `turbostat`/journal |
| SMART | Reallocated / pending / uncorrectable | **0** | 7 días | `smartctl -A` |
| SMART | Self-test | **Pass** | Semanal | `smartctl -l selftest` |
| SMART | CRC / ATA errors | **0 / sin crecimiento** | 7 días | `smartctl`, journal |
| Energía | Cortes no planificados | **0** | 7 días | UPS/NUT, journal |
| Energía | UPS / batería | Online; salud ≥ 80 % | 7 días | NUT/upower |
| Reloj | Offset NTP / saltos | **< 1 s / 0** | 7 días | `timedatectl` |
| Carga | Load p95 | **< 4** (1× vCPU) | 7 días | uptime/node_exporter |
| Carga | CPU PSI `some` p95 | **< 10 %** | 7 días | `/proc/pressure/cpu` |
| Carga | CPU PSI `full` | **< 1 %** | 7 días | idem |
| Carga | Memoria disponible | **> 20 %** | 7 días | `free`/node_exporter |
| Carga | Swap | **< 1 GiB** | 7 días | `free` |
| Carga | OOM | **0** | 7 días | journal, `OOMKilled` |
| Contenedores | Reinicios | **0** | 7 días | `docker events`, inspect |
| Contenedores | Salud | **healthy** | 7 días | healthchecks |
| Contenedores | Top CPU | **< 50 %** | 7 días | `docker stats` |
| Backups | Éxito diario | **7/7** | 7 días | borg/restic logs |
| Backups | Checksum / `borg check` | **7/7 / semanal Pass** | 7 días | `borg check --verify-data` |
| Backups | Restore test | **Pass** | Mensual | VM/host aislado |
| Backups | RPO / RTO | ≤ 24 h / ≤ 4 h (crítico ≤ 1 h) | Continuo | Documento |
| Identidad | Keycloak/Postgres up | **7/7** | 7 días | healthchecks |
| Identidad | M2M / realm / preflight | OK / instalado / **0 FAIL** | 7 días | `preflight_check.py` |
| Certificado | Timer renovación | Activo | 7 días | `systemctl list-timers` |
| Certificado | Validez | **> 30 días** | 7 días | `openssl x509` |
| Operación | Alertas probadas | reboot/temp/SMART/load/backup/cert/pstore | Una vez | Simulación |
| Recuperación | Fallback kernel / restore | **Probados** | Una vez | Runbook §11 |

### 12.2 Gates

- **Gate A — Backup:** off-host verificado, restore test pasado, RPO/RTO definidos.
- **Gate B — Hardware:** memtest 0 errores, SMART sano, térmica dentro de umbral, energía/UPS, sin MCE.
- **Gate C — Kernel:** 7 días en 6.12 sin panic/oops/lockup; pstore vacío; fallback probado.
- **Gate D — Carga:** 7 días con load/PSI/memoria/contenedores dentro de umbral; sin OOM.
- **Gate E — Operación:** identidad/M2M/realm/cert/preflight; backups automáticos; alertas.
- **Gate F — Producción:** host dedicado adecuado (ECC, UPS, RAID/IPMI) o aceptación formal de riesgo **solo para lab**; para datos clínicos reales, F es obligatorio.

### 12.3 Regla de soak

- **7 días consecutivos** mínimos; **14 recomendados** para producción.
- Cualquier evento de la lista de fallo **reinicia el contador**.
- El soak debe correr con la **carga representativa** del lab/producción, no con el host vacío.
- El uptime actual (25 min) **no cuenta**.

### 12.4 Fallos que reinician el soak

- Cualquier reinicio sucio, panic, oops, stack-protector, lockup o `orphan cleanup`.
- Temperatura > 95 °C, throttling sostenido o corte térmico.
- SMART crítico, error ATA, self-test fail.
- Corte de energía no planificado, UPS fallida.
- OOM, swap > 1 GiB, memoria disponible < 10 %.
- Pérdida de datos, backup fallido, restore fallido.
- Keycloak/Postgres caídos > 15 min o preflight con FAIL.
- Certificado < 30 días o renovación fallida.

### 12.5 Estado actual frente a los criterios

| Gate | Estado |
|---|---|
| A — Backup | **NO** (solo realm/secrets; sin DB/Wazuh/TLS/.env; sin restore test) |
| B — Hardware | **NO** (memtest/SMART pendientes; 80 °C; sin UPS) |
| C — Kernel | **NO** (7.1.8 inestable; 6.12 sin probar) |
| D — Carga | **NO** (load 4.6; PSI 25 %; 77 contenedores) |
| E — Operación | **NO** (identidad detenida; M2M ausente; cert sin timer) |
| F — Producción | **NO** (hardware inadecuado) |

**Veredicto:** **NO-GO** para producción. La laptop puede aspirar a **lab GO** si A–E se cumplen; para producción, F es obligatorio.

---

## 13. Riesgos y mitigaciones

| Riesgo | Prob. | Impacto | Mitigación |
|---|---|---|---|
| Pérdida de datos antes del backup | Alta | Crítico | P0 inmediato; copiar realm/secrets/DB/config; off-host; checksums |
| Reinicio durante backup/diagnóstico | Alta | Alto | Comandos cortos; copiar primero lo crítico; repetir; no estresar |
| Fallo de arranque al probar 6.12 | Media | Alto | Acceso físico, USB live, `grub-reboot` one-time, 7.1.8 conservado, backup |
| Lockout remoto sin IPMI | Media | Alto | No hacer kernel remoto; ventana presencial; consola |
| RAM/hardware defectuoso | Media | Alto | memtest, ePSA, SMART; reemplazar/migrar |
| Daño térmico | Alta | Alto | Limpieza/pasta, ventilación, reducir carga, umbral 95 °C |
| Corte de energía | Alta | Alto | Batería/UPS, adaptador conocido, power meter |
| SMART falla en SSD/HDD | Media | Alto | Backup, self-test, reemplazo, restore |
| Parar contenedores ajenos | Media | Medio | Autorización, mapa de dependencias, ventana |
| Exposición de secretos | Media | Alto | Cifrado, 0600, gestor de passphrase, no imprimir |
| `apt upgrade` instala 7.2.9 backports | Media | Medio | `apt-mark hold`/deshabilitar backports; 6.12 fijo |
| Migración con downtime | Media | Medio | Plan de copia/cutover, ventana, rollback |
| Backup CIFS no confiable | Media | Medio | Repo local + copia off-site; no único destino |
| Error humano | Media | Medio | Runbooks, peer review, checklist, ventana |
| BIOS/firmware update | Baja | Alto | Solo con backup/UPS, instrucciones Dell, post-soak |

---

## 14. Orden de ejecución

### Etapa 0 — Hoy (sin cambios)
- Preservar evidencia pstore/journal; documentar.
- Inventario de activos/volúmenes; clasificar crítico/importante.
- Definir destino off-host y passphrase (gestor).
- **No** tocar kernel, servicios ni `/opt`.

### Etapa 1 — 0–72 h (P0 + diagnóstico)
- Ejecutar backup off-host y restore test (P0).
- Journal root por boot; pstore; watchdog; energía/térmica/reloj.
- Instalar `smartmontools`/`lm-sensors` en ventana; SMART corto; sensores.
- Baseline de contenedores.
- Agendar memtest/ePSA con acceso físico.

### Etapa 2 — Semana 1 (estabilización)
- UPS/batería/CMOS/adaptador; limpieza/pasta/ventilación.
- Mover/limitar contenedores; stack SGSI mínimo.
- Congelar backports; preparar GRUB/6.12 con backup y USB live.
- Prueba 6.12 one-time; soak 72 h.

### Etapa 3 — Semana 2 (soak y decisión)
- Soak 7–14 días con criterios de §12.
- Si pasa: lab GO; decidir migración.
- Si falla: no insistir; migrar/reemplazar.

### Etapa 4 — Migración/producción
- Host dedicado; Debian 13/6.12; Docker/Tailscale; copia; pruebas; cutover.
- Identidad/M2M/realm/cert/preflight; backups; alertas.
- Go/no-go de producción con Gates A–F.

---

## 15. Qué NO hacer

- **No** cambiar el kernel ahora, menos remoto, con el host reiniciándose y sin IPMI.
- **No** desactivar el watchdog para “evitar reinicios”: enmascara el síntoma y puede dejar el host colgado.
- **No** instalar 7.2.9 backports ni dejar que `apt upgrade` cambie el default.
- **No** borrar pstore/journal antes de copiarlos y hashearlos.
- **No** copiar la clave privada TLS sin cifrado, ni imprimirla, ni subirla al repo.
- **No** llamar “backup” a los directorios `pre_*` vacíos.
- **No** parar contenedores ajenos sin autorización y mapa de dependencias.
- **No** autorizar producción con la laptop; el hardware no cumple.
- **No** hacer memtest/SMART long sin backup off-host.
- **No** restaurar sobre producción durante las pruebas; usar host/VM aislado.

---

## 16. Evidencia y comandos read-only

Los comandos de diagnóstico usados están en:

- `C:\Users\elcra\AppData\Local\Temp\opencode\sgsi-cutover\recovery_diag.sh`
- `C:\Users\elcra\AppData\Local\Temp\opencode\sgsi-cutover\host_stability_probe.sh`
- `C:\Users\elcra\AppData\Local\Temp\opencode\sgsi-cutover\journal_deep_probe.sh`
- `C:\Users\elcra\AppData\Local\Temp\opencode\sgsi-cutover\pstore_read.sh`
- `C:\Users\elcra\AppData\Local\Temp\opencode\sgsi-cutover\hw_probe.sh`
- `C:\Users\elcra\AppData\Local\Temp\opencode\sgsi-cutover\tailscale_check.sh`

En el host: `/tmp/host_stability_probe.out`, `/tmp/journal_system_probe.out`, `/tmp/journal_deep_probe.out`.

**Este plan no ejecutó** reinicios, instalaciones, cambios de kernel, paradas de contenedores ni modificaciones de producción. El único cambio es este documento local.

---

## 17. Conclusión

- **Producción:** **NO-GO**. La laptop no es estable ni adecuada; el backup actual no permite recuperación completa.
- **P0:** backup off-host verificable, con restore test. Es lo único urgente e independiente de la causa de los reinicios.
- **P1:** acotar reinicios con evidencia root (watchdog/energía/térmica/kernel), memtest, SMART y sensores; no cambiar el kernel antes.
- **P2:** reducir carga/aislar el SGSI; decidir migración. La recomendación estratégica es **migrar el laboratorio a un host dedicado** y dejar la laptop como lab/PoC.
- **6.12:** ya está instalado; se puede probar con `grub-reboot` one-time, conservando 7.1.8, con backup, USB live y recuperación documentada. No es un experimento remoto.
- **Criterio de aprobación:** Gates A–F de §12, soak de 7–14 días, backups restaurados y, para producción, hardware adecuado. Sin eso, el veredicto sigue siendo **NO-GO**.




