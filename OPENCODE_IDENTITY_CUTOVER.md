# Integración de emisor canónico y cierre del preflight — SGSI-ZTA Hospital Lab

**Fecha:** 2026-10-20
**Rama:** `stage4-lis-candidate-release`
**Commit de tooling:** `a823d7b`
**Dictamen:** **NO-GO condicional** — el tooling está validado; faltan la ventana autorizada de identidad y el secreto M2M de producción.

---

## 1. Resultado en una línea

El emisor canónico `https://servidor-1.tailb0f78a.ts.net:8443/realms/hospital-lab` funciona con el certificado real de Let's Encrypt, el gateway Caddy y el LIS dentro de la red interna; el realm de producción se exportó sin detener Keycloak y se verificó su importación en limpio. El corte sigue bloqueado porque el Keycloak de producción está detenido y su secreto M2M no existe todavía.

---

## 2. Evidencia del emisor canónico y TLS

| Comprobación | Resultado |
|---|---|
| Certificado | `CN=servidor-1.tailb0f78a.ts.net`, emisor `Let's Encrypt CN=YE2` |
| Vigencia | `2026-10-20 17:17:40Z` → `2027-01-18 17:17:39Z` (89 días) |
| SAN | cubre `servidor-1.tailb0f78a.ts.net` |
| Cadena | 4 certificados; clave y certificado coinciden |
| Permisos | `fullchain.pem 0644 root:root`, `privkey.pem 0600 root:root` |
| Gateway | Caddy `identity-gateway`, bind `100.78.61.51:8443`, alias canónico en `clinical` |
| Windows | `curl.exe` `ssl_verify=0`, HTTP 200; `Invoke-WebRequest` 200 |
| Keycloak | fuera de `clinical`; solo `identity-db` + `identity-ui` |
| LIS | sin puerto publicado al host; solo red `internal: true` |

Prueba desde Windows (sin `-k`):

```text
ssl_verify=0
http=200
iwr_status=200
issuer=https://servidor-1.tailb0f78a.ts.net:8443/realms/hospital-lab
```

---

## 3. Hallazgo crítico: Docker no publica puertos en redes `internal`

El compose de producción declaraba:

```yaml
clinical-poc:
  ports: ["127.0.0.1:${CLINICAL_PORT:-8000}:8000"]
  networks: [clinical]
networks:
  clinical:
    internal: true
```

Con Docker **29.7.2**, un contenedor en una red `internal: true` **no recibe mapeo de puertos** (`NetworkSettings.Ports` queda en `null`, `docker port` vacío). Consecuencia: el health check del deploy y la verificación post-cutover contra `http://127.0.0.1:8086` habrían fallado y disparado **rollback automático**.

Corrección aplicada:

- Se retira el `ports` de `clinical-poc` en el compose generado (el mapeo era inefectivo).
- El health check del deploy se ejecuta **dentro** del contenedor (`docker compose exec -T clinical-poc python -c ...`).
- La verificación post-cutover corre en un contenedor sonda sobre la red `clinical`, con `--url http://clinical-poc:8000`.
- El gateway y el monitor alcanzan el LIS por la red interna; el LIS deja de estar expuesto al host (mejora ZTA).

Esto se validó en el ensayo aislado: el LIS quedó `healthy` sin puerto publicado y el monitor autenticó y leyó la auditoría por la red interna.

---

## 4. Ensayo integral aislado (`zta-itest`)

| Paso | Resultado |
|---|---|
| Keycloak 26.8.0 + Postgres + Caddy con certificado real | OK |
| Realm `hospital-lab`, roles, cliente `clinical-poc`, usuarios | OK |
| Discovery canónico (issuer/jwks/token) | OK |
| Cliente M2M `clinical-audit-monitor-service` | creado; rol `auditor`; `aud=clinical-poc-api` |
| Token M2M verificado | OK |
| Orden clínica con token de usuario (`itest-cli`, password grant) | HTTP 201 |
| Audit monitor | **2 eventos**, cadena **INTACTA**, **0 anomalías** |
| LIS sin puerto host | OK; health por `exec` |

El cliente M2M es confidencial, con service accounts, rol de reino `auditor` (mapea a `ROLE_SECURITY_AUDITOR`) y mapper de audiencia `clinical-poc-api`. El script es idempotente y escribe el secreto en un archivo `0600`, mostrando solo la huella SHA-256.

---

## 5. Exportación del realm de producción sin downtime

Se exportó el realm **real de producción** desde una **copia del volumen detenido**, sin arrancar Keycloak ni montar el volumen original en escritura:

1. `pg_dump` desde la copia de la DB.
2. Restauración en un Postgres efímero.
3. `kc.sh export --users same_file` (Keycloak 26.x: `realm_file` solo aplica al export a directorio).
4. Validación estructural y artefacto `0600`.
5. Importación en un Keycloak limpio y verificación.

Resultado:

```text
realm=hospital-lab clients=13 roles=11 flujos=24 usuarios=10
importación limpia: clinical-poc presente, rol auditor presente, usuarios=9
artefacto: /home/elcra/sgsi-backups/realm/hospital-lab-realm-production.json (0600)
```

El archivo antiguo `config/keycloak/hospital-lab-realm.json` (import inválido: flujo sin `id`/`executions`) queda reemplazado por `identity_up.sh` con backup, previa validación.

---

## 6. Estrategia de renovación

- El certificado es Let's Encrypt para un nombre `ts.net`; solo Tailscale completa el desafío DNS-01.
- `tailscale cert` **requiere root**; como `elcra` falla con `Access denied: cert access denied`.
- No existe `--dry-run` en `tailscale cert`; el dry-run es del script.
- `renew_cert.sh`:
  - emite la hoja y la clave;
  - reconstruye la cadena completa reutilizando los intermedios del `fullchain` vigente;
  - valida SAN, clave, vigencia y cadena;
  - instala atómicamente (`0644` cert / `0600` clave);
  - recarga Caddy y verifica TLS de extremo a extremo;
  - si falla, restaura el material anterior y recarga.
- Probado con un shim de `tailscale`: `--check` (89 días, cadena 2, SAN, clave) y `--dry-run` (emisión, reconstrucción, validación, sin instalar).
- Unidades listas en `cutover_prep/systemd/sgsi-zta-cert-renew.{service,timer}`.

Pendiente para que la renovación real funcione:

1. Habilitar **HTTPS Certificates** en el admin console de Tailscale (`CertDomains` está vacío).
2. Instalar el timer como root (requiere `sudo`).
3. Probar una emisión real como root en la ventana autorizada.

---

## 7. Estado de los cinco bloqueadores

| # | Bloqueador | Estado |
|---|---|---|
| 1 | Keycloak detenido | **Pendiente**: contenedores de producción `Exited (255)` desde `2026-10-19T18:13:23Z`, `restart: no`; no se reinició por falta de autorización. `identity_up.sh` listo. |
| 2 | Secreto OAuth M2M | **Tooling validado** en el ensayo; el secreto de producción se genera al arrancar Keycloak. |
| 3 | Dependencias Python | **Resuelto**: imagen `sgsi-zta-clinical:2026.10` (`cryptography 43.0.0`, CA certs, uid 65534). 42 tests del subconjunto OK; 62 completos con 7 fallos por dependencias externas. |
| 4 | Claves IoMT | **Resuelto**: 3 claves generadas (`0600`), el deploy las inyecta; secretos cortos fallan cerrado. |
| 5 | Export del realm | **Resuelto**: artefacto de producción exportado e importado en limpio. |

Diagnóstico del `127.0.0.1:8085` sin respuesta: el contenedor de Keycloak está detenido; el puerto publicado desaparece con él. El `Exited (255)` es consistente con un apagado del host/daemon, y `restart: no` impidió que volviera. El disparador exacto no es demostrable sin acceso root a `journalctl`.

---

## 8. Preflight final (estado real de producción)

```text
[DICTAMEN: NO-GO] PASS=23 FAIL=3 SKIP=2
```

- **PASS** `2a` árbol limpio en `a823d7b`.
- **PASS** `4c`–`4g` material TLS: cadena 4, SAN, clave, 89 días, clave 600.
- **PASS** `4j` artefacto de producción: 24 flujos, 13 clientes.
- **FAIL** `4a`/`4` gateway/Keycloak canónicos: `Connection refused` (identidad abajo).
- **FAIL** `4l` secreto M2M ausente en producción.
- **SKIP** `8` base existente (sin `--db-path`), `8d` red `clinical` (la crea el cutover).
- **INFO** timer de renovación no instalado; `CertDomains` vacío.

Los 3 FAIL tienen **dos causas raíz**: identidad detenida y secreto M2M dependiente de ella. Ninguna es un defecto del tooling.

---

## 9. Runbook para pasar a GO (ventana autorizada)

```bash
cd /home/elcra/sandbox-jwt-validator

# 1. Identidad: Keycloak + Postgres + gateway, con el realm válido instalado
./cutover_prep/identity_up.sh --apply \
  --realm-export-file=/home/elcra/sgsi-backups/realm/hospital-lab-realm-production.json

# 2. Secreto M2M (la contraseña admin se toma del .env de producción; no se imprime)
set -a; . /opt/sgsi-zta-hospital-lab/.env; set +a
KC_ADMIN_PASSWORD="$KC_BOOTSTRAP_ADMIN_PASSWORD" python3 cutover_prep/provision_monitor_client.py \
  --server http://127.0.0.1:8085 \
  --admin-user "$KC_BOOTSTRAP_ADMIN_USERNAME" \
  --realm hospital-lab \
  --out /home/elcra/sgsi-backups/secrets/monitor.env \
  --token-url https://servidor-1.tailb0f78a.ts.net:8443/realms/hospital-lab/protocol/openid-connect/token

# 3. Preflight (debe dar GO)
python3 cutover_prep/preflight_check.py \
  --device-keys-file=/home/elcra/sgsi-backups/secrets/iomt-device-keys.json \
  --monitor-secret-file=/home/elcra/sgsi-backups/secrets/monitor.env \
  --clinical-image=sgsi-zta-clinical:2026.10 \
  --realm-export-file=/home/elcra/sgsi-backups/realm/hospital-lab-realm-production.json

# 4. Cutover
./cutover_prep/cutover_deploy.sh --apply \
  --tls-dir=/etc/sgsi-zta/tls \
  --clinical-image=sgsi-zta-clinical:2026.10 \
  --monitor-secret-file=/home/elcra/sgsi-backups/secrets/monitor.env \
  --realm-export-file=/home/elcra/sgsi-backups/realm/hospital-lab-realm-production.json \
  --device-keys-file=/home/elcra/sgsi-backups/secrets/iomt-device-keys.json

# 5. Renovación (root)
sudo install -m 0644 cutover_prep/systemd/sgsi-zta-cert-renew.service /etc/systemd/system/
sudo install -m 0644 cutover_prep/systemd/sgsi-zta-cert-renew.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sgsi-zta-cert-renew.timer
sudo ./cutover_prep/renew_cert.sh --check
```

---

## 10. Riesgos abiertos

1. **Host inestable:** se observaron **dos reinicios** del host durante la sesión (uptime 4 min y luego 14 min). No ejecutar el cutover hasta tener una ventana estable; los reinicios explican por qué los contenedores `restart: no` no vuelven.
2. **`CertDomains: None`:** sin HTTPS Certificates habilitado, `tailscale cert` como root podría fallar. La renovación real no está probada como root.
3. **`sudo` con contraseña:** las unidades systemd no se pudieron instalar; quedan como archivos.
4. **Secreto M2M de producción:** no existe hasta arrancar Keycloak; el ensayo solo prueba el tooling.
5. **Artefacto de realm:** contiene hashes de credenciales y secretos de clientes; debe permanecer `0600` y no copiarse al repositorio.
6. **Clave TLS:** `privkey.pem` es `0600 root`; no se imprimió, copió ni cambió de permisos.

---

## 11. Archivos relevantes

- `cutover_prep/cutover_deploy.sh` — deploy, TLS, compose, health in-network, sonda de verificación.
- `cutover_prep/preflight_check.py` — preflight, TLS, realm, M2M, filtro por proyecto de Compose.
- `cutover_prep/identity_up.sh` — arranque de identidad + instalación del realm válido.
- `cutover_prep/export_realm.sh` / `verify_realm_import.sh` — export sin downtime y verificación en limpio.
- `cutover_prep/provision_monitor_client.py` / `kc_admin.py` — cliente M2M idempotente.
- `cutover_prep/renew_cert.sh` + `systemd/` — renovación y timer.
- `cutover_prep/generate_iomt_keys.py` — claves IoMT.
- `cutover_prep/lis_image/` — imagen con `cryptography`.
- `/home/elcra/sgsi-backups/realm/hospital-lab-realm-production.json` — artefacto de producción (`0600`).
- `/home/elcra/sgsi-backups/secrets/iomt-device-keys.json` — claves IoMT (`0600`).
- `/etc/sgsi-zta/tls/{fullchain.pem,privkey.pem}` — certificado real y clave.

---

**Dictamen final:** **NO-GO** hasta ejecutar el runbook en una ventana autorizada y estable. Con la identidad arriba y el secreto M2M provisionado, el preflight pasa a GO y el cutover queda listo; el ensayo integral ya demostró el flujo completo.
