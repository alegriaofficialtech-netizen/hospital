# Identidad canónica del laboratorio — propuesta y pruebas

**Fecha:** 2026-10-20
**Alcance:** identidad OIDC del LIS, red clínica, respaldos y verificación de issuer.
**Modo:** correcciones en sandbox, pruebas aisladas. Sin `--apply`, sin cutover, sin push.

---

## 1. Veredicto

| Dimensión | Resultado |
| --- | --- |
| Diseño de identidad | **GO** — mecanismo probado extremo a extremo |
| Ejecución del cutover hoy | **NO-GO** — 4 bloqueantes externos al diseño |
| `/opt`, Keycloak principal, Docker existente | **intactos** |

**URL canónica propuesta:**

```
https://servidor-1.tailb0f78a.ts.net:8443
```

Issuer resultante:

```
https://servidor-1.tailb0f78a.ts.net:8443/realms/hospital-lab
```

---

## 2. Por qué esa URL (infraestructura real, no inventada)

| Elemento | Hallazgo verificado |
| --- | --- |
| Tailscale | 1.104.1, nodo `servidor-1`, IP `100.78.61.51` |
| MagicDNS | habilitado; sufijo `tailb0f78a.ts.net`; nombre `servidor-1.tailb0f78a.ts.net` |
| Certificados HTTPS del tailnet | **`CertDomains: None`** → HTTPS deshabilitado en la consola de Tailscale |
| `tailscale serve` / `funnel` | sin configuración |
| 80 / 443 / 8080 | `coolify-proxy` (Traefik v3.6) |
| 9443 | Portainer |
| 81 | nginx de OpenMediaVault |
| 8089 | `demo-gateway` (Caddy), solo `127.0.0.1` |
| 8443 | **libre** |
| Windows (`iacrismo`, 100.72.28.100) | resuelve el nombre a `100.78.61.51`; TCP 443 y TCP 8443 alcanzables |

**Decisión:** 8443 porque 443 pertenece a Traefik y modificarlo está fuera del alcance autorizado.
El puerto se publica **solo en la IP de Tailscale** (`100.78.61.51:8443`), no en `0.0.0.0`: no queda expuesto a la LAN.

### Alternativas descartadas

| Alternativa | Motivo |
| --- | --- |
| `http://keycloak:8080` | Irresoluble desde Windows/Angular |
| `https://servidor-1.tailb0f78a.ts.net` (443) | Traefik ya ocupa 443; cambiarlo modifica Docker existente |
| `lis.alegriatecn.com` | Dominio real con Let's Encrypt en este host, pero exige registro DNS público y router de Coolify/Traefik; fase pública posterior |
| `vidasana.192.168.1.36.sslip.io` | Atado a IP privada y a Coolify; mismo problema |
| Solo `tailscale serve` | Termina TLS en el host, pero **no es alcanzable desde una red Docker `internal: true`** |
| TLS nativo en Keycloak | Expone `/admin` en el borde y cambia el comando del Keycloak principal |
| `network_mode: host` para el LIS | Rompe el DNS `clinical-poc:8000` del monitor y la aislación clínica |

---

## 3. Arquitectura

```
Windows (Angular)
   │  Tailscale (WireGuard)
   ▼
100.78.61.51:8443
   │
   ▼
identity-gateway (Caddy, TLS)
   │  red identity-ui
   ▼
keycloak:8080 ── keycloak-postgres (identity-db)

clinical-poc (red clinical, internal: true)
   │  alias DNS: servidor-1.tailb0f78a.ts.net → identity-gateway
   ▼
https://servidor-1.tailb0f78a.ts.net:8443/realms/hospital-lab
   └── mismo issuer que Windows
```

Decisiones deliberadas:

- **El LIS no habla con Keycloak directamente.** El gateway es el único ingreso; Keycloak permanece en `identity-db` + `identity-ui`.
- El nombre canónico se resuelve dentro de `clinical` mediante un **alias de red** de Docker (`aliases: [servidor-1.tailb0f78a.ts.net]`), sin tocar `/etc/hosts` ni abrir la red interna.
- Se conserva el bloqueo de `/admin` y `/realms/master` que ya usaba el gateway de demo.
- El gateway no reutiliza el `demo-gateway` porque ese servicio arrastra `wazuh-dashboard` y su perfil `demo`.

---

## 4. Cambios aplicados en sandbox

Commits locales (sin push) sobre `stage4-lis-candidate-release`:

| Commit | Contenido |
| --- | --- |
| `be388ee` | Issuer canónico, gateway, volumen externo, OAuth del monitor, respaldos y checks |
| `33a272c` | Propietario del volumen para uid 65534 |
| `e136417` | Sonda de issuer reproducible (`cutover_prep/issuer_probe.py`) |

### `cutover_prep/cutover_common.py`

- `CANONICAL_BASE_URL`, `CANONICAL_REALM`, `BACKUP_BASE_DIR`.
- `canonical_issuer()`, `canonical_discovery_url()`, `canonical_token_url()`.
- `issuer_document_problems()`: valida issuer y que `jwks_uri`, `token_endpoint` y `authorization_endpoint` compartan origen; rechaza `127.0.0.1`, `localhost`, `keycloak:8080` y `http://`.
- `tls_peer_certificate()` para verificar SAN.

### `cutover_prep/cutover_deploy.sh`

- Volumen `clinical-data` declarado **`external: true`** (falla cerrado si no existe).
- `KC_HOSTNAME` fijado al origen canónico.
- `KEYCLOAK_DISCOVERY_URL` y `KEYCLOAK_AUDIENCE` inyectados en `clinical-poc`.
- `AUDIT_MONITOR_TOKEN_URL`, `AUDIT_MONITOR_CLIENT_ID` y `AUDIT_MONITOR_CLIENT_SECRET` inyectados en el monitor; `AUDIT_MONITOR_USE_LEGACY=0`.
- Nuevo servicio `identity-gateway` (perfil `identidad`) en `identity-ui` + `clinical` con alias canónico.
- Escritura del `Caddyfile` del gateway y verificación del material TLS.
- `PASO 8a`: `chown 65534:65534` del volumen y sonda de escritura.
- Arranque conjunto `--profile clinical --profile identidad`.
- Espera del discovery canónico antes de la verificación post-cutover.

### `cutover_prep/preflight_check.py`

Nuevos controles: TLS canónico, issuer canónico, secreto M2M, token endpoint del monitor, red `clinical`, volumen externo, imagen del LIS con `cryptography`, y aviso de escritura del volumen.

### `cutover_prep/post_cutover_verify.py`

- Comprobación 11: discovery canónico, endpoints coherentes y compose con el issuer fijado.
- `--skip-identity` solo para pruebas aisladas sin Keycloak.
- `--canonical-base`, `--compose-path`.

### Respaldos

`/home/elcra/backups` es `root:root 0755` y no es escribible por `elcra`. Los valores por defecto pasan a:

```
/home/elcra/sgsi-backups/{pre_cutover,pre_restore,pre_rollback}
```

---

## 5. Pruebas de issuer consistente

Laboratorio aislado: red `internal: true`, Keycloak 26.8.0 efímero, Postgres efímero, Caddy con certificado de prueba, nombres `zta-issuer-test-*`. **Sin tocar `/opt` ni el Keycloak principal.**

### 5.1 Resultados

| Ejecución | Resultado |
| --- | --- |
| Sonda dentro de la red interna (contenedor) | **21/21 PASS** |
| Sonda desde el host | **21/21 PASS** |
| Sonda CLI del repo (`issuer_probe.py`) | **12/12 PASS** |
| Windows → Tailscale → HTTPS canónico | **PASS** (discovery y token) |
| Desmontaje | sin contenedores ni redes; 8443 libre |

### 5.2 Afirmaciones verificadas

| Afirmación | Evidencia observada |
| --- | --- |
| DNS del nombre canónico | `100.78.61.51` desde Windows y host; `192.168.208.5` (gateway) dentro de la red interna |
| TLS | `subject=CN=servidor-1.tailb0f78a.ts.net`, SAN correcto, `Verify return code: 0 (ok)` |
| Issuer | `https://servidor-1.tailb0f78a.ts.net:8443/realms/hospital-lab` en los tres caminos |
| JWKS | mismo origen canónico, 2 claves |
| Token | `iss` canónico, `aud=[clinical-poc-api, account]`, `typ=Bearer` |
| Validador del LIS | acepta el token; `context.issuer` canónico; rol `ROLE_SECURITY_AUDITOR` |
| Issuer distinto | rechazado con `UntrustedIssuerError` |
| Monitor M2M | `client_credentials` OK; `iss` canónico; `aud` incluye `clinical-poc-api` |
| Fugas | discovery sin `127.0.0.1`, `localhost`, `keycloak:8080` ni `http://` |

### 5.3 Reproducción

```bash
cd /home/elcra/sandbox-jwt-validator
SSL_CERT_FILE=/ruta/ca.crt \
TEST_USER_PASSWORD=... TEST_MONITOR_SECRET=... \
python3 cutover_prep/issuer_probe.py \
  --base-url https://servidor-1.tailb0f78a.ts.net:8443
```

---

## 6. Bloqueantes para el cutover

| # | Bloqueante | Evidencia | Acción |
| --- | --- | --- | --- |
| 1 | HTTPS de Tailscale deshabilitado | `CertDomains: None` | Habilitar *HTTPS Certificates* en la consola y emitir el certificado |
| 2 | Keycloak y Postgres detenidos | `Exited (255)` desde `2026-10-19T18:13:23Z`, `restart: no` | `docker compose --profile identidad up -d keycloak-postgres keycloak` |
| 3 | Secreto M2M del monitor ausente | preflight `4b` | Provisión del cliente en el realm y export de `AUDIT_MONITOR_CLIENT_SECRET` |
| 4 | Imagen del LIS sin dependencias | `python:3.12-slim-bookworm` no importa `cryptography` | Construir imagen con `requirements.txt` y fijar `CLINICAL_IMAGE` |
| 5 | Claves IoMT ausentes | preflight `7a` | `--device-keys-file` o `IOMT_DEVICE_KEYS_JSON` |
| 6 | Realm no importable en frío | `--import-realm` falla con `AuthenticationFlowModel ... flow is null` | Exportar el realm completo desde la instancia viva |
| 7 | Volumen `clinical-data` no escribible por 65534 | sonda `NOT-WRITABLE` | **Resuelto por el despliegue** (`PASO 8a`), probado en volumen temporal |

### Preflight actual

```
[DICTAMEN: NO-GO] PASS=14 FAIL=6 SKIP=2
```

Los 6 FAIL son los bloqueantes 1–5 más el árbol sin confirmar (se resuelve con el commit).

### Corrección de un hallazgo previo

El informe anterior afirmaba que `cutover_deploy.sh` abortaría por un volumen no declarado. **Era incorrecto:** el script ya añadía `{"name": "clinical-data"}`. Lo que faltaba era el modo estricto. Ahora se declara `external: true`, que falla cerrado si el volumen no existe en lugar de crear uno vacío en silencio.

---

## 7. Prerrequisitos, en orden

```bash
# 1. Consola de Tailscale: DNS -> HTTPS Certificates -> Enable
#    Luego, en servidor-1:
tailscale cert \
  --cert-file /opt/sgsi-zta-hospital-lab/config/keycloak/tls/servidor-1.tailb0f78a.ts.net.crt \
  --key-file  /opt/sgsi-zta-hospital-lab/config/keycloak/tls/servidor-1.tailb0f78a.ts.net.key \
  servidor-1.tailb0f78a.ts.net

# 2. Levantar solo identidad (no toca el LIS)
cd /opt/sgsi-zta-hospital-lab
docker compose --profile identidad up -d keycloak-postgres keycloak

# 3. Exportar el realm completo desde la instancia viva y guardarlo como artefacto de import

# 4. Provisionar el cliente M2M del monitor y exportar el secreto (sin imprimirlo)

# 5. Construir la imagen del LIS con cryptography y fijar CLINICAL_IMAGE

# 6. Preflight y sonda
python3 cutover_prep/preflight_check.py --port=8086 --device-keys-file=<keys.json>
SSL_CERT_FILE=<ca> python3 cutover_prep/issuer_probe.py
```

El endpoint canónico se materializa cuando se aplique el parche de compose. Antes de eso el preflight seguirá en NO-GO por diseño.

---

## 8. Qué no se tocó

- `/opt/sgsi-zta-hospital-lab` y su `docker-compose.yml`.
- Keycloak principal y su base.
- Contenedores, redes y volúmenes existentes (salvo el volumen temporal de prueba, eliminado).
- Cutover, push y despliegue.

Artefactos de prueba en `/home/elcra/sgsi-backups/issuer-test/` (certificados de prueba, realm de laboratorio, secretos efímeros 0600).
