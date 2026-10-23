# Manual Técnico de la Plataforma SGSI-ZTA Hospital Lab

**Fase:** F6 — Cierre Técnico y Consolidación  
**Entorno:** Debian 13 (`servidor-1`), Runtime F11 (`/home/elcra/sgsi-zta-runtime/f11`)  
**Repositorio:** `/home/elcra/sgsi-zta-integration`  

---

## 1. Arquitectura General del Sistema

La plataforma SGSI-ZTA Hospital Lab implementa un Sistema de Gestión de Seguridad de la Información (SGSI) alineado con los principios de Arquitectura Zero Trust (ZTA) según las directrices de NIST SP 800-207 y el Modelo de Madurez Zero Trust de CISA.

El sistema se estructura en tres capas desacopladas:

1. **Plano de Control y Punto de Decisión de Políticas (PDP)**:
   - **Keycloak (OIDC / OAuth 2.0)**: Emisor central de identidades y proveedor de tokens de seguridad firmados (JWT). Implementa autenticación multifactor obligatoria (TOTP RFC 6238) y control de flujo mediante PKCE (S256).
2. **Plano de Aplicación y Punto de Aplicación de Políticas (PEP)**:
   - **Backend API (Python / HTTP Server)**: Motor transaccional y ejecutor estricto de políticas Zero Trust. Cada solicitud entrante valida la firma del token, la presencia de roles mínimos requeridos y la verificación de MFA para operaciones críticas (`HUMAN_ONLY_ACTIONS`).
3. **Plano de Datos y Registro de Evidencias**:
   - **SQLite en modo WAL (Write-Ahead Logging)**: Persistencia relacional atómica con sellado criptográfico.
   - **Cadena de Auditoría Encadenada (SHA-256)**: Registro inmutable de eventos con custodia de ancla lateral (`.anchor-key`).
   - **Frontend (Angular 22)**: Interfaz de usuario SPA con componentes standalone, detección de cambios OnPush y observancia estricta de políticas RBAC.

---

## 2. Tecnologías y Versiones

| Componente | Tecnología | Versión | Rol en la Arquitectura |
|---|---|---|---|
| Sistema Operativo | Debian GNU/Linux | 13 (Trixie) | Servidor anfitrión seguro (`servidor-1`) |
| Proveedor de Identidad | Keycloak | 26.x (Docker) | OIDC, PKCE S256, RBAC, TOTP RFC 6238 |
| Backend API | Python | 3.13.5 | Servidor REST, PEP, lógica de negocio y auditoría |
| Base de Datos | SQLite | 3.x (WAL) | Persistencia transaccional con control de concurrencia |
| Frontend | Angular | 22.x (Docker/NGINX) | SPA Zero Trust, Material Design, Signals |
| Protocolo de Sesión | OIDC + JWT | RS256 | Tokens firmados criptográficamente |
| Segundo Factor | TOTP | RFC 6238 (SHA-1, 30s) | MFA para acciones humanas privilegiadas |

---

## 3. Catálogo de Módulos (M0 a M9)

| Módulo | Denominación | Objetivo de Tesis | Función Técnica | Acciones Sensibles |
|---|---|---|---|---|
| **M0** | Laboratorio Clínico | Demostrativo ZTA | Órdenes clínicas, admisión, validación patológica y sellado. | `CREATE_ORDER`, `VALIDATE_ORDER` |
| **M1** | Identidad y Acceso | O1 / O3 | Gestión de identidades sintéticas y solicitud de cuentas. | `CREATE_IDENTITY`, `DEACTIVATE_IDENTITY` |
| **M2** | Diagnóstico de Seguridad | O1 | 12 comprobadores ejecutables que producen hallazgos con evidencia. | `RUN_DIAGNOSTICS` |
| **M3** | Inventario de Activos | O2 | Catálogo de componentes, servicios, software y contenedores. | `MANAGE_ASSETS` |
| **M4** | Matriz de Riesgos | O2 | Evaluación 5x5 de riesgos inherentes y residuales vinculados a activos. | `MANAGE_RISKS` |
| **M5** | Catálogo de Controles | O3 | Controles ISO 27001, NIST y CISA con verificación basada en evidencia. | `MANAGE_CONTROLS` |
| **M6** | Incidentes y Alertas | O4 | Registro de incidentes, transiciones y alertas derivadas en tiempo real. | `MANAGE_INCIDENTS`, `ACK_ALERT` |
| **M7** | Auditoría Criptográfica | O1–O4 | Cadena inmutable SHA-256 encadenada por bloques con ancla HMAC. | `VIEW_AUDIT_EVENTS` |
| **M8** | Indicadores de Seguridad | O4 | Dashboard de postura de seguridad, cumplimiento normativo y riesgos. | `VIEW_INDICATORS` |
| **M9** | Validación por Expertos | O4 | Instrumento de medición (14 ítems), dictámenes e informes auditados. | `MANAGE_VALIDATION` |

---

## 4. Esquema de Base de Datos y Migraciones

La base de datos SQLite opera en modo WAL con `PRAGMA synchronous = NORMAL` y custodia de permisos `0600`. El esquema evoluciona mediante 9 migraciones idempotentes:

### Migraciones Implementadas

1. **v1**: Tablas base clínicas (`clinical_orders`, `iomt_nonces`).
2. **v2**: Cadena de auditoría criptográfica (`audit_events`, `audit_checkpoints`).
3. **v3**: M2 Diagnóstico y M3 Inventario (`diagnostic_runs`, `security_findings`, `assets`, `asset_evaluations`).
4. **v4**: Adición de campo de origen de evidencia en hallazgos.
5. **v5**: Consolidación determinista de `evidence_source` en hallazgos históricos.
6. **v6**: M4 Riesgos y M5 Controles (`risks`, `controls`, `risk_controls`, `control_evidences`).
7. **v7**: M6 Incidentes y Alertas (`incidents`, `incident_updates`, `alert_acknowledgements`).
8. **v8**: Normalización de estados de alertas y tiempos de mitigación.
9. **v9**: M9 Validación por Expertos (`validation_instruments`, `instrument_items`, `expert_reviews`, `expert_review_answers`, `reports`).

### Catálogo de las 21 Tablas del Sistema

- `alert_acknowledgements`: Acuses de recibo de alertas derivadas por operadores autorizados.
- `asset_evaluations`: Evaluaciones de postura de seguridad por activo.
- `assets`: Inventario consolidado de activos de información y componentes del laboratorio.
- `audit_checkpoints`: Punto de control único de auditoría con último hash y ancla criptográfica.
- `audit_events`: Libro mayor inmutable de eventos de auditoría encadenados por hash SHA-256.
- `clinical_orders`: Órdenes médicas del laboratorio con estados y sellos de integridad.
- `control_evidences`: Registro formal de evidencias reales vinculadas a la verificación de controles.
- `controls`: Catálogo de controles de seguridad de la información (ISO 27001 / NIST / CISA).
- `diagnostic_runs`: Registro de ejecuciones de la batería de 12 comprobadores técnicos.
- `expert_review_answers`: Respuestas individuales por ítem en dictámenes de expertos.
- `expert_reviews`: Dictámenes emitidos por evaluadores externos sobre el instrumento de validación.
- `incident_updates`: Historial de transiciones de estado y comentarios en incidentes.
- `incidents`: Registro de incidentes de seguridad de la información clasificados por severidad.
- `instrument_items`: Enunciados específicos (14 ítems en 6 dimensiones) del instrumento de medición.
- `iomt_nonces`: Control anti-repetición para dispositivos médicos e IoMT.
- `reports`: Informes consolidados de cumplimiento e investigación con hash SHA-256 determinista.
- `risk_controls`: Matriz de vinculación biunívoca entre riesgos y controles de mitigación.
- `risks`: Matriz de riesgos de seguridad con cálculo 5x5 de severidad inherente y residual.
- `schema_migrations`: Registro histórico de versiones de esquema aplicadas con marca temporal.
- `security_findings`: Hallazgos de seguridad emitidos por comprobadores con salida literal.
- `validation_instruments`: Instrumentos de validación metodológica (ej. INSTR-F11-ZTA-01).

---

## 5. Modelo de Autenticación y Autorización (Zero Trust)

### Flujo de Autenticación
- **Inicio de sesión único (SSO)**: Delegado exclusivamente en Keycloak.
- **Flujo OIDC**: Authorization Code Flow con PKCE (S256). Ninguna credencial de usuario o contraseña transita por la aplicación frontend o backend.
- **Segundo Factor (MFA)**: Autenticación TOTP mediante RFC 6238. La presencia del segundo factor se acredita en el token JWT a través del claim `amr` conteniendo `otp` y/o claim `acr`.

### Política de Mínimo Privilegio (RBAC)

Las operaciones sensibles clasificadas como `HUMAN_ONLY_ACTIONS` rechazan de forma estricta cualquier llamada efectuada por cuentas de servicio o sesiones sin MFA verificado:

```python
HUMAN_ONLY_ACTIONS = frozenset({
    "MANAGE_IDENTITIES",
    "RUN_DIAGNOSTICS",
    "MANAGE_ASSETS",
    "MANAGE_RISKS",
    "MANAGE_CONTROLS",
    "MANAGE_INCIDENTS",
    "MANAGE_VALIDATION",
    "GENERATE_REPORTS",
})
```

| Rol del Realm | Acciones Permitidas | Acceso a Rutas Frontend |
|---|---|---|
| `ROLE_PLATFORM_ADMIN` | Gestión de identidades, activos, riesgos, controles, incidentes y reportes (con MFA). | `/administracion`, `/inventario`, `/riesgos`, `/controles`, `/incidentes`, `/informes` |
| `ROLE_SECURITY_AUDITOR` | Lectura integral de auditoría, diagnóstico, inventario, riesgos, controles e incidentes. | `/auditoria`, `/diagnostico`, `/inventario`, `/riesgos`, `/controles`, `/incidentes`, `/evidencias` |
| `ROLE_PATHOLOGIST` | Validación clínica y liberación de resultados diagnósticos (con MFA). | `/laboratorio`, `/ordenes` |
| `ROLE_LAB_TECH` | Carga de resultados analíticos de laboratorio. | `/laboratorio` |
| `ROLE_RECEPTION` | Admisión de pacientes y creación de órdenes médicas. | `/recepcion`, `/solicitud-cuenta` |

---

## 6. Cadena Criptográfica de Auditoría y Trazabilidad

### Algoritmo de Encadenamiento SHA-256
Cada evento registrado en `audit_events` calcula su digest SHA-256 a partir del contenido ordenado canónicamente (`sort_keys=True`) incorporando el hash del evento inmediatamente anterior (`prev_hash`):

$$\text{hash}_n = \text{SHA256}(\text{JSON}(\text{payload}_n \cup \{\text{prev\_hash}: \text{hash}_{n-1}\}))$$

El evento inicial se ancla en `0000000000000000000000000000000000000000000000000000000000000000` (64 ceros).

### Custodia del Ancla Criptográfica
Para impedir ataques de reescritura retroactiva de la base SQLite, la tabla `audit_checkpoints` mantiene una firma HMAC calculada con una clave secreta simétrica custodiada en el archivo lateral `lis.db.anchor-key` con permisos `0600`. Cualquier alteración, truncamiento o reemplazo de la base sin la clave lateral provoca una detención en modo fallo-cerrado (`AuditChainCorruptedError`).

---

## 7. Procedimiento de Respaldo y Restauración

### Generación de Respaldo Seguro
Ejecutar el script automatizado que garantiza consistencia transaccional SQLite, captura de ramas Git con stash y custodia de secretos:

```bash
cd /home/elcra/sgsi-zta-integration
./infra/f11/backup-secure.sh
```

El respaldo se almacena en `/home/elcra/sgsi-zta-runtime/f11/backups/f6_backup_<timestamp>` con permisos `0700` y contiene:
- `lis.db`: Snapshot atómico obtenido vía `sqlite3.backup()`.
- `git_repo.bundle`: Bundle completo con todas las ramas locales y la referencia de stash.
- `metadata.json`: Versión de esquema, lista de migraciones, tabla de conteos y metadatos Git.
- `SHA256SUMS`: Sumas de comprobación criptográficas de todos los artefactos.
- `secrets/`: Directorio protegido (`0700`) con `lis.db.anchor-key` y archivos de credenciales (`0600`).

### Procedimiento de Restauración
1. Detener el backend: `./infra/f11/stack-ctl.sh stop backend`.
2. Verificar la integridad de los archivos de respaldo:
   ```bash
   cd /home/elcra/sgsi-zta-runtime/f11/backups/f6_backup_<timestamp>
   sha256sum -c SHA256SUMS
   ```
3. Restaurar la base y su ancla lateral al directorio de runtime:
   ```bash
   cp lis.db /home/elcra/sgsi-zta-runtime/f11/lis.db
   cp secrets/lis.db.anchor-key /home/elcra/sgsi-zta-runtime/f11/lis.db.anchor-key
   chmod 600 /home/elcra/sgsi-zta-runtime/f11/lis.db*
   ```
4. Restaurar el repositorio Git (si fuera necesario):
   ```bash
   git clone git_repo.bundle /home/elcra/sgsi-zta-restored
   ```
5. Iniciar el servicio: `./infra/f11/stack-ctl.sh start backend`.

---

## 8. Seguridad y Limitaciones Técnicas Declaradas

1. **Entorno Experimental F11**: La plataforma opera en un entorno de laboratorio acotado en `servidor-1`. La evaluación de seguridad se circunscribe exclusivamente a los contenedores, servicios y bases de datos del banco de pruebas F11, sin acceso ni escaneo sobre redes de producción del hospital.
2. **Servidor HTTP Monohilo**: El backend opera sobre un despachador síncrono monohilo. Las operaciones computacionalmente intensivas (ej. escaneo completo de comprobadores de diagnóstico) introducen latencia transitoria en la atención de otras peticiones concurrentes.
3. **Carácter Sintético de los Datos de Prueba**: Las identidades clínicas, pacientes, muestras de laboratorio e incidentes de prueba están explícitamente etiquetados como sintéticos (`synthetic = 1`, prefijos `SINT`).
4. **Validación de Expertos Auténtica**: El sistema provee el instrumento metodológico INSTR-F11-ZTA-01, pero no genera ni simula dictámenes automáticos. Los dictámenes reales quedan reservados a evaluadores humanos independientes.