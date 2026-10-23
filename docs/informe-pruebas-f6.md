# Informe de Pruebas y Verificación Integral — Fase F6

**Fecha de Ejecución:** 2026-10-23  
**Entorno de Pruebas:** Debian 13 (`servidor-1`), Runtime F11  
**Línea Base Exigida:** 166/166 pruebas de API aprobadas (cero regresiones permitidas)  
**Resultado Obtenido:** 166/166 pruebas de API aprobadas (100% de éxito en 376.259s)  

---

## 1. Resumen Ejecutivo

La Fase F6 concluye la verificación técnica exhaustiva de la plataforma SGSI-ZTA Hospital Lab. La totalidad de los casos de prueba de API, pruebas estáticas, comprobaciones en navegador real y validaciones criptográficas se completaron satisfactoriamente sin registrar ninguna falla ni regresión.

| Categoría de Prueba | Casos Ejecutados | Casos Aprobados | Fallas | Resultado |
|---|---|---|---|---|
| Comprobaciones Estáticas (AST, Shell, Compose) | 22 archivos | 22 | 0 | **APROBADO** |
| Suite de API Automatizada (F0–F5) | 166 | 166 | 0 | **APROBADO** |
| Comprobaciones en Navegador F4 (Incidentes/Alertas) | 24 | 24 | 0 | **APROBADO** |
| Comprobaciones en Navegador F5 (Validación/Evidencias) | 34 | 34 | 0 | **APROBADO** |
| Verificación Criptográfica de Auditoría | 2885 eventos | 2885 | 0 | **APROBADO** |
| Detección de Fugas de Secretos en Auditoría | 2885 eventos | 2885 | 0 | **APROBADO (0 fugas)** |
| Pruebas Destructivas de Rollback Transaccional | 9 casos | 9 | 0 | **APROBADO** |

---

## 2. Detalle de Suites de Pruebas de API Ejecutadas

### 2.1. `test_f11_admin.py` (10 pruebas)
- `test_01_admin_with_mfa_lists_identities`: Administrador con MFA consulta identidades en Keycloak (200).
- `test_02_admin_with_mfa_lists_roles`: Consulta autorizada de roles del realm.
- `test_03_admin_without_mfa_is_denied`: Administrador con rol pero sin OTP es denegado estrictamente (403).
- `test_04_identity_without_admin_role_is_denied`: Cuenta sin rol administrativo es rechazada (403).
- `test_05_admin_creates_and_deactivates_a_synthetic_identity`: Ciclo de vida de identidad sintética.
- `test_06_non_synthetic_username_is_rejected`: Rechazo de nombres que no cumplan el formato sintético.
- `test_07_platform_role_cannot_be_granted_from_the_application`: La interfaz no puede auto-asignarse roles protegidos.
- `test_07b_protected_role_creates_nothing`: Intentos de escalamiento de privilegios no dejan cuentas huérfanas.
- `test_08_password_never_travels_to_the_browser`: Credenciales generadas se entregan en fichero local `0600`.
- `test_09_admin_actions_are_audited`: Toda acción administrativa queda registrada en auditoría con detalle.

### 2.2. `test_f11_api.py` (12 pruebas)
- Verificación del dominio clínico demostrativo (M0): rechazo de peticiones sin token (401), tokens malformados (401), flujo de admisión por recepción, restricciones para laboratoristas y patólogos, validación médica con MFA obligatorio y rechazo de logins locales deprecados.

### 2.3. `test_f11_f2.py` (28 pruebas)
- M2 Diagnóstico de Seguridad y M3 Inventario de Activos: ejecución de los 12 comprobadores técnicos, persistencia de hallazgos con evidencia literal y comando de origen, catálogo de activos, actualizaciones con revisión incremental y auditoría atómica.

### 2.4. `test_f11_f3.py` (34 pruebas)
- M4 Gestión de Riesgos y M5 Catálogo de Controles: cálculo formal en matriz 5x5 de severidad inherente y residual, vinculación biunívoca riesgo-control, obligatoriedad de evidencia real para certificar estado `VERIFICADO`, filtrado dinámico y transacciones atómicas.

### 2.5. `test_f11_f4.py` (38 pruebas)
- M6 Gestión de Incidentes y Alertas Derivadas: ciclo de vida de incidentes de seguridad, cálculo determinista de alertas a partir del estado real del sistema, acuse de recibo de alertas e indicadores de postura M8 con especificación de origen de datos.

### 2.6. `test_f11_f5.py` (39 pruebas)
- M9 Validación por Expertos, Evidencias e Informes: persistencia del instrumento INSTR-F11-ZTA-01 (14 ítems en 6 dimensiones), registro de dictámenes con cálculo descriptivo no vinculante, inventario de evidencias trazables O1 a O4 (749 elementos) y generación de informes Markdown con hash determinista.

### 2.7. `test_f11_identity_request.py` (5 pruebas)
- Canal público de solicitud de cuentas: registro de solicitudes pendientes de autorización administrativa, rechazo de formatos inválidos, aislamiento estricto de tasa límite de peticiones (`rate-limiting`) y verificación de que el código Angular no contiene campos de contraseñas.

---

## 3. Pruebas de Seguridad Negativas y Resiliencia

### 3.1. Pruebas Destructivas de Atomicidad (Rollback Transaccional)
Se verificó empíricamente que ante fallos forzados en la inserción del evento de auditoría criptográfico, la mutación operativa se revierte íntegramente sin dejar registros huérfanos:
- **Activos (`test_27` F2)**: Si la auditoría falla, el activo no existe en `assets`.
- **Diagnóstico (`test_28` F2)**: Si la auditoría falla, ni la ejecución ni los hallazgos persisten en `diagnostic_runs`/`security_findings`.
- **Riesgos (`test_14` F3)**: Si la auditoría falla, el riesgo no existe en `risks`.
- **Controles (`test_16` F3)**: Si la auditoría falla, el control no persiste en `controls`.
- **Evidencias de Control (`test_17` F3)**: Si la auditoría falla, el control conserva su estado previo y la evidencia no se almacena.
- **Incidentes (`test_21` F4)**: Si la auditoría falla, el incidente no se almacena.
- **Transición de Incidentes (`test_22` F4)**: Si la auditoría falla, el estado no muta.
- **Instrumentos (`test_14` F5)**: Si la auditoría falla, ni el instrumento ni sus ítems persisten.
- **Dictámenes de Expertos (`test_15` F5)**: Si la auditoría falla, ni la revisión ni las respuestas persisten.

### 3.2. Aislamiento y Tasa Límite (Rate-Limiting)
- Se comprobó que el canal público rechaza peticiones abusivas respondiendo HTTP 429 (`IDENTITY_REQUEST_RATE_LIMITED`).
- La suite implementa resolución de `X-Forwarded-For` en loopback (`127.0.0.1`) para garantizar aislamiento entre pruebas y el endpoint administrativo `/api/v1/admin/rate-limits/reset` para pruebas consecutivas sin interferencia.

---

## 4. Auditoría de la Cadena Criptográfica

- **Integridad de Hash**: Se verificaron de forma automatizada los **2885 eventos** que componen la tabla `audit_events`. El enlace `prev_hash` contra el hash del registro anterior se cumple al 100%, iniciando en los 64 ceros iniciales.
- **Consistencia de Checkpoint**: La tabla `audit_checkpoints` refleja fielmente `total_events = 2885`, y su firma `anchor_signature` coincide exactamente con el HMAC calculado mediante la clave custodiada en `lis.db.anchor-key`.
- **Fugas de Información**: Búsqueda por patrones regulares descartó la existencia de tokens JWT expuestos (`eyJ...`), contraseñas en claro (`password=`) o secretos base32 de TOTP en los 2885 registros de auditoría.

---

## 5. Defectos Técnicos Corregidos en el Proceso de Consolidación

1. **Aislamiento de Rate-Limiting entre Ejecuciones**: Se corrigió la fuga de contadores de IP de loopback agregando soporte de proxy sintético en pruebas y endpoint de reinicio administrativo.
2. **Determinismo en `evidence_source`**: Se migraron e indexaron 252 hallazgos históricos asegurando trazabilidad formal a sus comprobadores respectivos (Migración 5).
3. **Persistencia de `revision` en Controles y Riesgos**: Se aseguró que cualquier mutación incremente estrictamente el campo `revision` para auditoría forense.
4. **Validación Estricta de Evidencias en M5**: Se bloqueó la posibilidad de que un control transicione a `VERIFICADO` sin especificar `reference_id` y `observed_result`.