# Guía Metodológica para la Validación por Expertos — SGSI-ZTA

**Instrumento de Referencia:** `INSTR-F11-ZTA-01` (Versión 1.0)  
**Proyecto:** Sistema de Gestión de Seguridad de la Información alineado a Zero Trust para Laboratorio Clínico  
**Objetivo Académico:** Evaluación metodológica independiente de la propuesta doctoral (Objetivo O4)  

---

## 1. Presentación y Propósito de la Evaluación

La presente guía tiene como propósito orientar a los profesionales expertos en ciberseguridad, auditores de sistemas de gestión (ISO/IEC 27001) y especialistas en informática en salud durante el proceso de evaluación y juicio de expertos sobre la arquitectura y controles del modelo SGSI-ZTA aplicado al laboratorio clínico.

El sistema somete a consideración un banco de pruebas demostrativo (`servidor-1` / F11) donde se implementan controles reales de autenticación multifactor, autorización basada en roles (RBAC), encadenamiento criptográfico de auditoría, gestión de riesgos 5x5 y verificación de controles basada estrictamente en evidencias.

---

## 2. Descripción del Instrumento `INSTR-F11-ZTA-01`

El instrumento de evaluación consta de **14 enunciados técnicos verificables** distribuidos en las seis dimensiones fundamentales de la Arquitectura Zero Trust (NIST SP 800-207 y CISA Zero Trust Maturity Model):

### Dimensión 1: Identidad (3 ítems)
- **ID-01**: Toda identidad con privilegios administrativos tiene una credencial configurada con segundo factor (TOTP) obligatorio.
- **ID-02**: El rol administrativo de la plataforma no puede auto-asignarse desde la interfaz de la aplicación y requiere validación del emisor OIDC.
- **ID-03**: El token de acceso de una sesión administrativa acredita fehacientemente segundo factor de autenticación mediante claims estándar (`amr` con `otp`).

### Dimensión 2: Dispositivo / Contenedores (2 ítems)
- **DIS-01**: Los contenedores de la plataforma declaran restricciones de privilegios (`no-new-privileges: true` y perfiles de seguridad).
- **DIS-02**: Los servicios publicados escuchan estrictamente en interfaces locales o controladas, sin exposición innecesaria de puertos.

### Dimensión 3: Red y Canal Seguro (2 ítems)
- **RED-01**: El flujo de autenticación OIDC utiliza PKCE con S256 en el intercambio del código de autorización para prevenir intercepción de credenciales.
- **RED-02**: Las llamadas a la API clínica y administrativa exigen un token Bearer firmado digitalmente (JWT RS256).

### Dimensión 4: Aplicación y Carga de Trabajo (2 ítems)
- **APP-01**: El bundle del cliente web (Angular) no contiene formularios ni captura contraseñas de usuarios, delegando la captura al IdP.
- **APP-02**: La API delega la verificación de credenciales en el emisor OIDC y no implementa almacenes de contraseñas locales sin auditar.

### Dimensión 5: Datos y Almacenamiento (2 ítems)
- **DAT-01**: Los ficheros de base de datos relacional, credenciales y claves tienen permisos restrictivos (`0600`/`0700`) en el sistema operativo anfitrión.
- **DAT-02**: La base de datos clínica registra un sello de integridad verificable sobre las órdenes y resultados médicos emitidos.

### Dimensión 6: Monitoreo, Auditoría e Incidentes (3 ítems)
- **MON-01**: Toda acción administrativa, clínica o de seguridad genera un evento encadenado por hash SHA-256 (`prev_hash` -> `hash`).
- **MON-02**: El arranque del servicio verifica la continuidad de la cadena de auditoría y su anclaje criptográfico HMAC lateral.
- **MON-03**: El diagnóstico técnico de seguridad registra, por cada hallazgo detectado, la evidencia literal y el comando real que lo produjo.

---

## 3. Escala de Calificación y Reglas Metodológicas

Cada ítem se evalúa en una escala cuantitativa Likert de 1 a 5:

| Puntuación | Criterio de Cumplimiento | Descripción Operativa |
|---|---|---|
| **1** | Totalmente en desacuerdo | La plataforma no evidencia el control o su implementación es nula. |
| **2** | En desacuerdo | El control existe de forma incipiente pero carece de garantías técnicas o presenta vulnerabilidades graves. |
| **3** | Neutral / Cumplimiento Parcial | El control opera parcialmente; se identifican observaciones de diseño que requieren subsanación. |
| **4** | De acuerdo | El control se encuentra implementado y respaldado por evidencia sólida, con observaciones menores. |
| **5** | Totalmente de acuerdo | El control se cumple de manera plena, verificable, atómica y alineada con las mejores prácticas Zero Trust. |

### Principio de Autonomía y No Coacción del Veredicto
El sistema calcula automáticamente una **media ponderada descriptiva** de las respuestas asignadas a los 14 ítems:

$$\text{Puntaje Descriptivo} = \frac{\sum_{i=1}^{14} w_i \cdot x_i}{\sum_{i=1}^{14} w_i}$$

> **IMPORTANTE**: La media ponderada es exclusivamente un indicador de apoyo analítico. El sistema **NO automatiza, NO sugiere y NO condiciona el veredicto cualitativo final**.
> El evaluador humano experto debe seleccionar con total independencia su juicio profesional entre las tres opciones disponibles:
> - `FAVORABLE`: La arquitectura es sólida y apta para su validación académica.
> - `FAVORABLE_CON_OBSERVACIONES`: La arquitectura es viable pero requiere atender recomendaciones puntuales.
> - `DESFAVORABLE`: La arquitectura presenta deficiencias conceptuales o técnicas significativas.

---

## 4. Procedimiento de Evaluación Paso a Paso

1. **Ingreso y Consulta de Evidencias**:
   - Inicie sesión en la plataforma con una cuenta autorizada (`auditor.test` o cuenta asignada al experto).
   - Acceda a `/evidencias` para examinar el inventario de 749 evidencias derivadas categorizadas por los objetivos O1, O2, O3 y O4.
   - Revise en `/diagnostico` los hallazgos técnicos reales y en `/controles` las pruebas que certifican la verificación de controles.
2. **Registro de la Evaluación**:
   - Diríjase a la sección `/validacion-expertos`.
   - Seleccione el instrumento activo `INSTR-F11-ZTA-01`.
   - Ingrese sus datos profesionales (Nombre del experto, especialidad o filiación institucional).
   - Califique cada uno de los 14 enunciados en la escala 1 a 5.
   - Redacte sus observaciones cualitativas, fortalezas identificadas y recomendaciones en el campo de texto libre.
   - Seleccione de forma autónoma su veredicto cualitativo.
3. **Consolidación y Emisión de Informe**:
   - Guarde el dictamen. La operación se registra atómicamente en la base de datos y se audita en la cadena SHA-256.
   - Diríjase a `/informes` para generar el informe formal con las métricas consolidadas, advertencia de datos sintéticos y hash SHA-256 inmutable de certificación.