# Matriz de Trazabilidad de Objetivos de Tesis — SGSI-ZTA

**Proyecto:** Implementación Demostrativa de SGSI alineado con Arquitectura Zero Trust para Laboratorio Clínico Hospitalario  
**Fase:** F6 — Cierre Técnico y Consolidación  
**Versión de Matriz:** 1.0 (Consolidada)  

---

## 1. Declaración de Alcance y Rigor Metodológico

Para garantizar la honestidad académica y la reproducibilidad científica de la investigación doctoral, se establecen las siguientes distinciones obligatorias:

1. **Resultados Técnicos Reales del Laboratorio**: Corresponden a mediciones empíricas sobre el banco de pruebas F11 (`servidor-1`): comprobaciones de hardening de contenedores, políticas de Keycloak, tiempos de respuesta, firmas de tokens JWT, encadenamiento criptográfico de auditoría (SHA-256) y validación de permisos en código.
2. **Datos Sintéticos de Prueba y Demostración**: Identidades de usuario (`medico.test`, `auditor.test`, etc.), registros clínicos de muestra, órdenes de laboratorio, incidentes y alertas creadas por las suites de prueba. Todos ellos están explícitamente etiquetados (`synthetic = 1`, prefijos `SINT` o `prueba-*`).
3. **Límites de Evaluación Institucional**: El sistema ha sido probado y auditado técnica y funcionalmente en el entorno controlado de laboratorio F11. **No se ha ejecutado escaneo intrusivo ni pruebas de penetración sobre la infraestructura de producción hospitalaria**, respetando las normativas de seguridad del paciente y continuidad operativa.
4. **Validaciones Humanas Pendientes**: El instrumento de validación metodológica INSTR-F11-ZTA-01 está completamente desarrollado, sembrado e integrado en la plataforma. Sin embargo, la asignación de puntajes por expertos independientes constituye un proceso humano externo que debe realizarse formalmente mediante el procedimiento descrito en la Guía de Evaluación.

---

## 2. Matriz de Mapeo: Objetivos vs Módulos, Funciones y Evidencias

| Objetivo de Tesis | Módulos Relacionados | Funcionalidades Técnicas Implementadas | Indicadores / Métricas Asociadas | Elementos de Evidencia Verificables |
|---|---|---|---|---|
| **O1: Diagnóstico de Seguridad** | **M2** Diagnóstico Técnico<br>**M1** Identidad (F1b) | - 12 comprobadores automatizados de postura técnica.<br>- Evaluación de PKCE, MFA, permisos de archivos, hardening.<br>- Registro literal de salida de comandos. | - Comprobadores superados vs fallidos.<br>- Severidad de hallazgos abiertos.<br>- Cumplimiento de hardening de servicios. | **594 hallazgos** técnicos reales persistidos en `security_findings` con comando exacto y código de retorno. |
| **O2: Inventario de Activos y Riesgos** | **M3** Inventario de Activos<br>**M4** Matriz de Riesgos | - Catálogo de 11 componentes reales del laboratorio.<br>- Matriz de riesgos 5x5 (inherente y residual).<br>- Trazabilidad biunívoca riesgo -> activo -> vulnerabilidad.<br>- Revisiones incrementales de activos. | - Porcentaje de activos evaluados.<br>- Cantidad de riesgos críticos/altos residuales.<br>- Nivel de riesgo promedio del laboratorio. | **42 elementos** derivados en `assets`, `asset_evaluations` y matriz `risks`. |
| **O3: Controles Zero Trust e ISO 27001** | **M5** Gestión de Controles<br>**M0** Laboratorio Clínico | - Catálogo de controles mapeado a ISO 27001, NIST SP 800-207 y CISA ZTM.<br>- Transición a `VERIFICADO` condicionada a evidencia obligatoria.<br>- Persistencia y auditoría atómica mediante `run_clinical_transaction`. | - Porcentaje de controles implementados y verificados.<br>- Tasa de cobertura de controles por marco normativo. | **61 elementos** en `controls`, `control_evidences` y enlaces `risk_controls`. |
| **O4: Incidentes, Auditoría, Indicadores y Validación** | **M6** Incidentes y Alertas<br>**M7** Auditoría Criptográfica<br>**M8** Indicadores en Tiempo Real<br>**M9** Validación por Expertos | - Ciclo de vida de incidentes con transiciones auditadas.<br>- Detección de alertas deterministas derivadas.<br>- Cadena de auditoría SHA-256 (2885 eventos) con ancla HMAC lateral.<br>- Dashboard de postura de seguridad.<br>- Instrumento INSTR-F11-ZTA-01 (14 ítems en 6 dimensiones).<br>- Generación de informes con firma hash SHA-256. | - MTTR (tiempo medio de mitigación de incidentes).<br>- Cantidad de alertas activas.<br>- Score descriptivo de validación (media ponderada).<br>- Tasa de eventos auditados íntegros (100%). | **52 elementos** en `incidents`, `alert_acknowledgements`, `reports` y `validation_instruments`. |

**Total de elementos de evidencia derivados y trazables:** **749 elementos** clasificados bajo el endpoint unificado `/api/v1/evidence`.

---

## 3. Desglose de Evidencias Técnicas por Objetivo

### Objetivo O1 — Diagnóstico de Seguridad
- **Fuente de Verdad**: Ejecución en vivo de la batería de 12 comprobadores técnicos (`backend/security_diagnostics.py`).
- **Naturaleza de la Evidencia**: Salida estándar y código de retorno de comandos sobre el sistema anfitrión Debian y los contenedores de Keycloak y Frontend.
- **Hallazgos Notables**:
  - `KC_MFA_ON_ADMIN_IDENTITIES` (Failed legítimo): Detecta que las identidades sintéticas de prueba `medico.sinmfa` y `admin.sinmfa.test` carecen de segundo factor configurado, sustentando la regla de denegación por MFA.
  - `CONTAINER_HARDENING` (Failed legítimo): Detecta que el contenedor Keycloak omite la directiva `cap_drop: ALL` (presente en el frontend), demostrando que el diagnóstico no es condescendiente ni prefabricado.

### Objetivo O2 — Inventario de Activos y Matriz de Riesgos
- **Fuente de Verdad**: Registros en tablas `assets` y `risks`.
- **Naturaleza de la Evidencia**: Los activos corresponden a los contenedores, bases de datos y servicios reales del banco de pruebas (ej. `AST-KC-01` para Keycloak, `AST-DB-01` para SQLite, `AST-BE-01` para el servidor Python).
- **Riesgos Evaluados**: Vinculados directamente a los hallazgos de O1 (ej. `RSK-F11-IAM-01` evalúa el riesgo de compromiso de credenciales privilegiadas si se omitiese el factor OTP).

### Objetivo O3 — Controles Zero Trust e ISO 27001
- **Fuente de Verdad**: Tablas `controls` y `control_evidences`.
- **Naturaleza de la Evidencia**: Referencias explícitas a ejecuciones de comprobadores (`checker_run`), suites de pruebas automatizadas (`test_suite`) o eventos de auditoría (`audit_event`).
- **Mecanismo Anti-Fraude**: La API y la capa de datos impiden marcar un control como `VERIFICADO` si no existe una evidencia previa registrada con sello temporal, operador con MFA y resultado observado (`CONTROL_EVIDENCE_MISSING`).

### Objetivo O4 — Validación Metodológica, Auditoría e Incidentes
- **Fuente de Verdad**: Tablas `audit_events`, `audit_checkpoints`, `incidents`, `reports` y `validation_instruments`.
- **Naturaleza de la Evidencia**:
  - Cadena criptográfica SHA-256 con 2885 eventos encadenados sin alteraciones.
  - Firma HMAC de control de checkpoint verificada mediante archivo lateral `lis.db.anchor-key` (0600).
  - Informes Markdown generados bajo demanda cuyo hash coincide exactamente con el contenido textual descargado.
  - Instrumento metodológico INSTR-F11-ZTA-01 listo para recepción de dictámenes de evaluadores externos.