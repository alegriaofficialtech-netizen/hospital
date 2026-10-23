# SGSI-ZTA Hospital Lab ? Gu?a de Acceso Web Permanente y Manual Operativo

Bienvenido a la plataforma **SGSI-ZTA Hospital Lab** (Sistema de Gesti?n de Seguridad de la Informaci?n y Arquitectura Zero Trust para Laboratorio Cl?nico Hospitalario).

Esta gu?a te permite encender tu computadora Windows, abrir Chrome y utilizar el sistema de inmediato, **sin abrir CMD, sin PowerShell y sin t?neles SSH manuales**.

---

## 1. Direcci?n de Acceso Permanente

- **URL de Acceso Directo:** [https://servidor-1.tailb0f78a.ts.net:8443](https://servidor-1.tailb0f78a.ts.net:8443)
- **Seguridad:** Certificado SSL/TLS oficial emitido por Let's Encrypt mediante la red privada segura de Tailscale (sin advertencias de certificado ni excepciones de seguridad).
- **Requisitos:** Tener la aplicaci?n Tailscale activa en tu barra de tareas de Windows con tu cuenta autorizada. No necesitas abrir ninguna consola ni ejecutar comandos.

---

## 2. C?mo Iniciar Sesi?n

1. Abre Google Chrome y navega a [https://servidor-1.tailb0f78a.ts.net:8443](https://servidor-1.tailb0f78a.ts.net:8443).
2. Haz clic en el bot?n principal **"Iniciar sesi?n con Keycloak"**.
3. El sistema te redirigir? a la pantalla corporativa institucional de acceso Zero Trust.
4. Introduce tu usuario y contrase?a institucional.
5. Si tu perfil cuenta con doble factor obligatorio (MFA), introduce el c?digo num?rico de 6 d?gitos de tu aplicaci?n autenticadora (Google Authenticator / FreeOTP).
6. Al autenticarte, ser?s redirigido autom?ticamente a tu panel de trabajo correspondiente seg?n tu rol.

---

## 3. Perfiles del Sistema y Responsabilidades

| Perfil | Rol RBAC | Acceso Principal | MFA Obligatorio | Responsabilidades |
| :--- | :--- | :--- | :---: | :--- |
| **Admisi?n / Recepci?n** | `ROLE_RECEPTION` | `/admision` | No | Registro y creaci?n de ?rdenes cl?nicas de pacientes sint?ticos. |
| **T?cnico de Laboratorio** | `ROLE_LAB_TECH` | `/dashboard` | No | Procesamiento de muestras y registro de mediciones anal?ticas. |
| **M?dico Pat?logo** | `ROLE_PATHOLOGIST` | `/medico` | **S? (TOTP)** | Validaci?n m?dica y liberaci?n de resultados cr?ticos con firma y doble factor. |
| **Auditor de Seguridad** | `ROLE_SECURITY_AUDITOR` | `/auditoria` | No | Inspecci?n de la cadena criptogr?fica de eventos, diagn?sticos e indicadores. |
| **Administrador de Plataforma** | `ROLE_PLATFORM_ADMIN` | `/administracion` | **S? (TOTP)** | Gesti?n de identidades, inventario de activos, riesgos y controles. |

> **Nota sobre el Administrador:** La identidad `admin.test` tiene pendiente la configuraci?n de su autenticador TOTP personal. El usuario `medico.test` conserva los privilegios administrativos provisionales con MFA activo para que puedas realizar todas las funciones de administraci?n sin bloqueos.

---

## 4. Gu?a Operativa por M?dulo

### M?dulo 0: ?rdenes y Proceso Cl?nico Zero Trust
- **Ruta:** Men? superior ? **?rdenes Cl?nicas** / **Atenci?n M?dica**.
- **Flujo de Trabajo:**
  1. El personal de **Recepci?n** crea la orden del paciente con las pruebas solicitadas (ej. hemograma, glucosa).
  2. El **Laboratorio** registra los resultados de los analizadores biom?dicos (IoMT).
  3. El **M?dico Pat?logo** ingresa con su segundo factor MFA, revisa las mediciones, valida los rangos de referencia y emite la liberaci?n formal del informe.

### M?dulo 1: Administraci?n de Identidades y Cuentas
- **Ruta:** Men? superior ? **Administraci?n**.
- **Operaciones:**
  - Consulta del censo institucional de cuentas de usuario.
  - Alta de identidades sint?ticas con asignaci?n estricta de roles de menor privilegio.
  - Activaci?n, suspensi?n y desactivaci?n de credenciales.
  - Protecci?n de menor privilegio: La interfaz proh?be la auto-asignaci?n de roles privilegiados de infraestructura.

### M?dulo 2: Comprobadores y Diagn?stico de Seguridad
- **Ruta:** Men? lateral ? **Diagn?stico**.
- **Operaciones:**
  - Ejecuci?n de diagn?sticos automatizados sobre el cat?logo de 12 comprobadores Zero Trust.
  - Verificaci?n del estado de cifrado en reposo, firmas de token JWT, auditor?a inmutable y aislamiento de red.

### M?dulo 3: Inventario de Activos de Informaci?n
- **Ruta:** Men? lateral ? **Activos**.
- **C?mo Registrar un Activo:**
  1. Haz clic en **"Registrar Activo"**.
  2. Selecciona la categor?a ISO 27001 (Hardware, Software, Informaci?n, Red o Personas).
  3. Asigna la clasificaci?n de criticidad (Confidencialidad, Integridad y Disponibilidad: Baja, Media, Alta o Cr?tica).
  4. Ingresa el propietario responsable y guarda el registro. La operaci?n genera un evento de auditor?a firmado.

### M?dulo 4: Matriz de Gesti?n de Riesgos
- **Ruta:** Men? lateral ? **Riesgos**.
- **C?mo Evaluar un Riesgo:**
  1. Accede a la matriz de riesgos y pulsa **"Evaluar Riesgo"**.
  2. Asocia el riesgo a un activo inventariado del M?dulo 3.
  3. Define la amenaza (ej. acceso no autorizado, interrupci?n de suministro) y la vulnerabilidad identificada.
  4. Califica la Probabilidad (1 a 5) y el Impacto (1 a 5). El sistema calcula autom?ticamente el Nivel de Riesgo Inherente y propone el tratamiento correspondiente (Mitigar, Transferir, Evitar o Aceptar).

### M?dulo 5: Controles de Seguridad (ISO 27001 & Zero Trust)
- **Ruta:** Men? lateral ? **Controles**.
- **C?mo Gestionar Controles:**
  1. Visualiza los controles mapeados con los objetivos del Anexo A de ISO 27001:2022 y los pilares de NIST SP 800-207.
  2. Actualiza el estado de implementaci?n (No Implementado, Planificado, En Proceso o Implementado).
  3. Vincula el control al riesgo que mitiga para recalcular el Riesgo Residual.

### M?dulo 6: Gesti?n de Incidentes y Alertas
- **Ruta:** Men? lateral ? **Incidentes** / **Alertas**.
- **C?mo Registrar un Incidente:**
  1. Pulsa **"Reportar Incidente"**.
  2. Clasifica la severidad (P1 Cr?tico, P2 Alto, P3 Medio, P4 Bajo).
  3. Describe los s?ntomas observados y el activo comprometido.
  4. Reconoce y atiende las alertas autom?ticas de anomal?as de red o intentos de autenticaci?n fallidos.

### M?dulo 7: Pista de Auditor?a Criptogr?fica Inmutable
- **Ruta:** Men? lateral ? **Auditor?a**.
- **C?mo Interpretar la Auditor?a:**
  - Cada acci?n realizada en la plataforma queda registrada como un bloque encadenado con hash **SHA-256**.
  - El sistema muestra el estado de la cadena: un indicador verde confirma que la cadena est? ?ntegra y no ha sido alterada.
  - La clave de anclaje HMAC reside en el servidor con permisos restringidos (0600), garantizando no repudio.

### M?dulo 8: Indicadores y Postura de Ciberseguridad
- **Ruta:** Men? lateral ? **Indicadores**.
- **M?tricas Clave:**
  - **Posture Score:** ?ndice global de madurez de seguridad (0 a 100).
  - **Radar de Cumplimiento:** Porcentaje de efectividad por dimensi?n de seguridad.
  - **M?tricas Operativas:** Tiempo medio de detecci?n (MTTD) y resoluci?n (MTTR) de eventos e incidentes.

### M?dulo 9: Instrumento de Expertos, Dict?menes e Informes
- **Ruta:** Men? lateral ? **Validaci?n e Informes**.
- **Uso:**
  - Consulta del instrumento t?cnico formal **INSTR-F11-ZTA-01** (14 ?tems de validaci?n).
  - Emisi?n de dict?menes t?cnicos por evaluadores autorizados.
  - Generaci?n de informes ejecutivos consolidables con trazabilidad total de evidencias O1 a O4.

---

## 5. Persistencia, Respaldo y Recuperaci?n

- **Base de Datos:** La instancia web persistente opera sobre `/home/elcra/sgsi-zta-runtime/f11/demo/lis.db`, totalmente aislada de la base operativa de pruebas de desarrollo.
- **Respaldos Autom?ticos:** Se ejecutan de manera desatendida cada hora mediante un proceso programado en el servidor Debian, generando copias at?micas verificadas con `PRAGMA integrity_check`, firma de anclaje y archivo `SHA256SUMS`.
- **Arranque Autom?tico:** Tras un reinicio del servidor, el script `autostart.sh` levanta autom?ticamente Keycloak, el backend y el gateway Caddy, restaurando el acceso HTTPS sin necesidad de intervenci?n manual.
