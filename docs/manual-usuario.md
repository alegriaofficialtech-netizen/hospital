# Manual de Usuario de la Plataforma SGSI-ZTA Hospital Lab

**Fase:** F6 — Cierre Técnico y Consolidación  
**Público Objetivo:** Administradores de Plataforma, Oficiales de Seguridad de la Información, Personal Clínico y Evaluadores Expertos.  

---

## 1. Acceso a la Plataforma e Inicio de Sesión Único

El acceso a la plataforma SGSI-ZTA se realiza a través del navegador web accediendo a la URL del frontend:
`http://localhost:4200` (o mediante el túnel SSH correspondiente).

### Procedimiento de Autenticación
1. Al acceder a cualquier ruta protegida, la aplicación redirige automáticamente a la pantalla institucional de inicio de sesión de Keycloak.
2. Ingrese su identificador de usuario corporativo (ej. `medico.test`, `auditor.test`, `laboratorio.test`) y su contraseña.
3. Si la cuenta tiene configurado el segundo factor (obligatorio para administradores y patólogos), el sistema solicitará el código numérico de 6 dígitos generado por la aplicación de autenticación TOTP (Google Authenticator, FreeOTP o similar).
4. Una vez validado, Keycloak emite el token de seguridad firmado y redirige al usuario a la interfaz principal de la plataforma (`/dashboard` o la vista permitida según su rol).

*(Referencia de captura: `capturas/01-login-keycloak.png`)*

---

## 2. Administración de Identidades y Acceso (M1)

**Ruta:** `/administracion`  
**Rol Requerido:** Administrador de Plataforma (`ROLE_PLATFORM_ADMIN`) con MFA.

### Funcionalidades
- **Listado de Identidades**: Visualización de los usuarios registrados, estado de la cuenta (activo/inactivo), roles asignados y obligatoriedad de MFA.
- **Alta de Identidad Sintética**: Formulario para registrar nuevas cuentas de prueba. Toda cuenta creada a través de la interfaz se etiqueta automáticamente con el prefijo sintético para evitar colisiones con cuentas institucionales.
- **Baja Lógica / Desactivación**: Permite inhabilitar el acceso de una cuenta sin purgar sus registros de auditoría históricos.
- **Canal de Solicitud de Cuentas**: Los usuarios sin credenciales pueden solicitar acceso desde la pantalla de bienvenida (`/solicitud-cuenta`). Dicha solicitud se almacena en el registro de auditoría (`PENDING_ADMIN_AUTHORIZATION`) para su revisión administrativa.

*(Referencia de captura: `capturas/10-admin-panel.png`, `capturas/03-solicitud-cuenta.png`)*

---

## 3. Diagnóstico de Seguridad Técnico (M2)

**Ruta:** `/diagnostico`  
**Roles Requeridos:** Oficial de Seguridad (`ROLE_SECURITY_AUDITOR`) o Administrador de Plataforma (`ROLE_PLATFORM_ADMIN`).

### Funcionalidades
- **Ejecución de Comprobadores**: El administrador con MFA puede disparar la ejecución de los 12 comprobadores técnicos automatizados.
- **Inspección de Hallazgos**: Visualización de hallazgos clasificados por severidad (`CRITICO`, `ALTO`, `MEDIO`, `BAJO`, `INFORMATIVO`).
- **Trazabilidad de Evidencia Real**: Cada hallazgo detalla el comando exacto ejecutado, el código de salida y la porción relevante de la configuración analizada (ej. políticas de contraseñas de Keycloak, cabeceras HTTP, permisos de archivos en disco).

*(Referencia de capturas: `capturas/11-diagnostico-inicial.png`, `capturas/12-diagnostico-ejecutado.png`, `capturas/13-diagnostico-hallazgos.png`)*

---

## 4. Inventario de Activos de Información (M3)

**Ruta:** `/inventario`  
**Roles Requeridos:** Todos los usuarios autenticados (lectura); modificación restringida a Administrador con MFA.

### Funcionalidades
- **Catálogo de Activos**: Registro de los 11 componentes de software, contenedores Docker, bases de datos y servicios que componen el banco de pruebas F11.
- **Clasificación y Criticidad**: Atributos de tipo (`container`, `service`, `dataset`, `identity_store`), rol custodio y nivel de criticidad.
- **Historial de Evaluaciones**: Cada activo registra su evolución temporal mediante evaluaciones de postura de seguridad vinculadas a revisiones incrementales.

*(Referencia de capturas: `capturas/14-inventario.png`, `capturas/15-inventario-detalle.png`)*

---

## 5. Matriz de Gestión de Riesgos (M4)

**Ruta:** `/riesgos`  
**Roles Requeridos:** Oficial de Seguridad (`ROLE_SECURITY_AUDITOR`) o Administrador con MFA (`ROLE_PLATFORM_ADMIN`).

### Funcionalidades
- **Matriz 5x5 de Probabilidad e Impacto**: Cálculo determinista del nivel de riesgo inherente y residual.
- **Vinculación con Activos y Amenazas**: Cada riesgo identifica el activo afectado, la vulnerabilidad explotable y la amenaza correspondiente.
- **Controles de Mitigación**: Visualización de los controles de seguridad asignados para reducir el riesgo residual.
- **Filtros Dinámicos**: Búsqueda por categoría (`software`, `infrastructure`, `iam`, `data`), estado (`IDENTIFICADO`, `EVALUADO`, `TRATADO`) y nivel de severidad.

*(Referencia de capturas: `capturas/shots-f3/20-riesgos-matriz.png`, `capturas/shots-f3/22-riesgo-detalle.png`)*

---

## 6. Catálogo de Controles de Seguridad (M5)

**Ruta:** `/controles`  
**Roles Requeridos:** Oficial de Seguridad o Administrador de Plataforma.

### Funcionalidades
- **Alineación Normativa**: Controles clasificados según ISO/IEC 27001:2022, NIST SP 800-207 y CISA Zero Trust Maturity Model.
- **Estados del Control**: `PROPUESTO`, `EN_PROCESO`, `IMPLEMENTADO`, `VERIFICADO`.
- **Regla Estricta de Verificación**: Para transicionar un control a estado `VERIFICADO`, el administrador con MFA debe suministrar obligatoriamente una referencia de evidencia real (`reference_id`, fuente de verificación y resultado observado). El sistema rechaza cualquier intento de verificación testimonial sin respaldo.

*(Referencia de capturas: `capturas/shots-f3/23-controles.png`, `capturas/shots-f3/25-control-verificar.png`)*

---

## 7. Gestión de Incidentes y Alertas Derivadas (M6)

**Ruta:** `/incidentes` y `/alertas`  
**Roles Requeridos:** Oficial de Seguridad o Administrador de Plataforma.

### Funcionalidades
- **Gestión del Ciclo de Vida de Incidentes**: Registro de incidentes de seguridad, asignación de responsable, clasificación de severidad y seguimiento de transiciones (`ABIERTO` -> `EN_INVESTIGACION` -> `CONTENIDO` -> `RESUELTO` -> `CERRADO`).
- **Alertas Derivadas del Estado Real**: Sistema de detección automática que correlaciona hallazgos abiertos, riesgos sin controles o cuentas sin MFA, generando alertas con identificadores deterministas.
- **Acuse de Recibo (Acknowledgment)**: Mecanismo para registrar la atención formal de una alerta sin eliminar la evidencia que la causó.

*(Referencia de capturas: `capturas/shots-f4/30-incidentes.png`, `capturas/shots-f4/32-alertas.png`, `capturas/shots-f4/33-alerta-evidencia.png`)*

---

## 8. Dashboard y Monitorización de Seguridad (M8)

**Ruta:** `/indicadores`  
**Roles Requeridos:** Accesible para todos los usuarios autenticados (solo lectura).

### Funcionalidades
- **Panel de Postura Zero Trust**: Vista consolidada en tiempo real que refleja el porcentaje de controles verificados, distribución de riesgos residuales, incidentes activos y estado de comprobadores de diagnóstico.
- **Trazabilidad de Fuentes**: Cada indicador numérico detalla el endpoint o tabla de persistencia de donde fue derivado, garantizando reproducibilidad analítica.

*(Referencia de capturas: `capturas/shots-f3/28-indicadores.png`, `capturas/shots-f4/34-indicadores.png`)*

---

## 9. Validación por Expertos, Evidencias e Informes (M9)

**Rutas:** `/instrumentos`, `/validacion-expertos`, `/evidencias`, `/informes`  
**Roles Requeridos:** Oficial de Seguridad y Administrador de Plataforma.

### Funcionalidades
1. **Instrumento Metodológico (`/instrumentos`)**:
   - Muestra el instrumento INSTR-F11-ZTA-01 v1.0, compuesto por 14 ítems verificables estructurados en las seis dimensiones Zero Trust (Identidad, Dispositivo, Red, Aplicación, Datos, Monitoreo).
2. **Registro de Dictamen (`/validacion-expertos`)**:
   - Formulario para que evaluadores externos califiquen los 14 ítems en escala Likert de 1 a 5.
   - El sistema calcula una media ponderada descriptiva que sirve de apoyo, pero **no condiciona ni coacciona el veredicto cualitativo** (`FAVORABLE`, `FAVORABLE_CON_OBSERVACIONES`, `DESFAVORABLE`), el cual es declarado con plena autonomía por el experto humano.
3. **Catálogo Unificado de Evidencias (`/evidencias`)**:
   - Inventario trazable de los 749 elementos de evidencia clasificados por objetivo de tesis (O1 a O4) con su origen y referencia técnica.
4. **Emisión de Informes con Firma Hash (`/informes`)**:
   - Generación de informes ejecutivos en formato Markdown que integran métricas en vivo, advertencia explícita sobre datos sintéticos, limitaciones metodológicas y referencias directas a evidencias.
   - Cada informe generado calcula su hash criptográfico SHA-256 único e inmutable.