# Guión de Sustentación y Demostración en Vivo — SGSI-ZTA

**Proyecto Doctoral:** Sistema de Gestión de Seguridad de la Información alineado con Arquitectura Zero Trust para Laboratorio Clínico Hospitalario  
**Entorno de Demostración:** Banco de Pruebas Experimental F11 (`servidor-1`), Debian 13  
**Destinatarios:** Tribunal Evaluador, Directores de Tesis y Comité de Evaluación Académica  

---

## 1. Introducción y Propósito de la Demostración

### Contexto del Problema
Los entornos hospitalarios y laboratorios clínicos procesan datos altamente sensibles (categoría especial bajo GDPR y normativas de salud). Tradicionalmente, la seguridad perimetral confía implícitamente en el tráfico que se encuentra dentro de la red corporativa. Esta suposición se desmorona ante amenazas avanzadas, dispositivos médicos (IoMT) comprometidos y movimientos laterales.

### Propuesta de la Tesis
La investigación diseña, implementa y valida experimentalmente un modelo de Sistema de Gestión de Seguridad de la Información (SGSI) gobernado por los principios rectores de la Arquitectura Zero Trust (ZTA, NIST SP 800-207 y CISA Zero Trust Maturity Model):
1. **Nunca confiar, verificar siempre.**
2. **Acceso con mínimo privilegio (RBAC dinámico).**
3. **Asumir la brecha y garantizar auditoría inmutable e intransigente.**

---

## 2. Arquitectura General del Sistema

### Planos del Sistema
- **Punto de Decisión de Políticas (PDP)**: Keycloak gestiona identidades, flujos OIDC con PKCE S256, emisión de JWT RS256 y desafío obligatorio de segundo factor (TOTP).
- **Punto de Aplicación de Políticas (PEP)**: Backend Python valida criptográficamente cada token, exige MFA para operaciones sensibles (`HUMAN_ONLY_ACTIONS`) y encadena eventos de auditoría atómicamente antes de persistir cualquier cambio.
- **Plano de Aplicación y Datos**: Frontend Angular 22 (SPA Zero Trust sin contraseñas) y SQLite 3 en modo WAL con sellado criptográfico y custodia de ancla lateral (`.anchor-key`).

```
  [ Usuario / Navegador ]
             │  (Flujo OIDC + PKCE S256 + TOTP)
             ▼
      [ Keycloak PDP ] ──────► Emite JWT (RS256 con claims 'amr': ['otp'])
             │
             ▼
   [ Frontend Angular 22 ]
             │  (Petición HTTP con Header Authorization: Bearer <JWT>)
             ▼
    [ Backend API (PEP) ] ────► Valida Token + RBAC + MFA
             │
      ┌──────┴─────────────────────────┐
      ▼                                ▼
[ Base SQLite (WAL) ]       [ Cadena de Auditoría ]
(Persistencia Atómica)      (SHA-256 encadenado + Ancla HMAC 0600)
```

---

## 3. Guión Paso a Paso para la Demostración en Vivo

---

### Paso 1: Autenticación, Roles y Segundo Factor (Keycloak PDP)
- **Pantalla**: `http://localhost:4200/login` -> Redirección a Keycloak.
- **Qué Demostrar**:
  1. Intentar acceder a `/administracion` sin sesión: la aplicación redirige al portal OIDC de Keycloak.
  2. Demostrar inicio de sesión con `medico.test`:
     - Paso 1: Ingreso de usuario y contraseña.
     - Paso 2: Desafío de segundo factor TOTP (código temporal de 6 dígitos).
  3. Demostrar denegación por falta de MFA con `medico.sinmfa`:
     - La cuenta posee el rol pero carece de TOTP registrado.
     - La API rechaza cualquier mutación administrativa con **HTTP 403 Forbidden** (`MFA_REQUIRED`).
- **Punto Clave para el Tribunal**:
  *"La aplicación cliente jamás captura ni almacena contraseñas; el flujo delega la autenticación en el emisor de identidades con PKCE S256, y la API exige segundo factor para toda acción sensible."*

---

### Paso 2: Diagnóstico de Seguridad e Inventario de Activos (Objetivo O1)
- **Pantallas**: `/diagnostico` e `/inventario`.
- **Qué Demostrar**:
  1. En `/diagnostico`, ejecutar la batería de 12 comprobadores automatizados como administrador con MFA.
  2. Inspeccionar la salida literal de un hallazgo:
     - Mostrar que el sistema no emite juicios declarativos vacíos: se exhibe el comando ejecutado, el código de retorno y la evidencia técnica en bruto.
     - Mostrar los dos hallazgos legítimamente abiertos (`CONTAINER_HARDENING` por omisión de `cap_drop: ALL` en Keycloak, y `KC_MFA_ON_ADMIN_IDENTITIES` por las identidades de prueba sin OTP).
  3. En `/inventario`, navegar por los 11 activos reales del laboratorio (contenedores, base de datos, servicios, datasets).
  4. Mostrar el historial de evaluaciones de postura y cómo cada activo avanza en su número de revisión incremental.
- **Punto Clave para el Tribunal**:
  *"El diagnóstico no es condescendiente ni prefabricado: demuestra que el sistema identifica brechas reales sobre su propia configuración y las registra como evidencia trazable."*

---

### Paso 3: Identificación y Gestión de Riesgos (Objetivo O2)
- **Pantalla**: `/riesgos`.
- **Qué Demostrar**:
  1. Visualizar la matriz de riesgos 5x5 (Probabilidad vs Impacto).
  2. Seleccionar un riesgo crítico (ej. `RSK-F11-IAM-01`: Riesgo de compromiso de cuenta administrativa).
  3. Explicar el cálculo determinista:
     - **Riesgo Inherente**: 5 x 5 = 25 (`CRITICO`).
     - **Controles de Mitigación Vinculados**: Control ISO A.5.15 y NIST AC-2.
     - **Riesgo Residual**: Reducción calculada a 2 x 2 = 4 (`BAJO`).
  4. Demostrar que un auditor (`auditor.test`) puede consultar toda la matriz, pero solo el administrador con MFA puede registrar o modificar riesgos.
- **Punto Clave para el Tribunal**:
  *"Se cierra la trazabilidad O1 -> O2: un hallazgo técnico del diagnóstico fundamenta la existencia de un riesgo en la matriz, y su mitigación está matemáticamente ligada a controles verificables."*

---

### Paso 4: Catálogo y Verificación de Controles Zero Trust (Objetivo O3)
- **Pantalla**: `/controles`.
- **Qué Demostrar**:
  1. Navegar por los controles alineados a ISO/IEC 27001:2022, NIST SP 800-207 y CISA Zero Trust Maturity Model.
  2. Abrir el modal de detalle de un control en estado `IMPLEMENTADO`.
  3. **Demostración de la Regla Anti-Fraude**:
     - Intentar marcar el control como `VERIFICADO` sin aportar evidencia: el sistema bloquea la acción con HTTP 400 (`CONTROL_EVIDENCE_MISSING`).
     - Completar el formulario de verificación formal aportando la referencia real (`test_suite`, `checker_run` o `audit_event`) y el resultado observado.
     - El control transiciona a `VERIFICADO` con sello temporal y operador auditado.
- **Punto Clave para el Tribunal**:
  *"Un control en este modelo jamás es una casilla de verificación autodeclarativa. La transición a verificado exige respaldo empírico documentado y operador con segundo factor."*

---

### Paso 5: Incidentes, Alertas, Indicadores y Validación Metodológica (Objetivo O4)
- **Pantallas**: `/incidentes`, `/alertas`, `/indicadores`, `/validacion-expertos`, `/evidencias` e `/informes`.
- **Qué Demostrar**:
  1. **Incidentes y Alertas (`/incidentes`, `/alertas`)**:
     - Mostrar el registro de incidentes y las alertas derivadas del estado real del sistema (ej. alerta por activo crítico sin evaluación reciente).
     - Acusar recibo de una alerta (`Acknowledge`) y mostrar que la evidencia subyacente no se altera.
  2. **Dashboard de Postura (`/indicadores`)**:
     - Visualizar el puntaje general de postura Zero Trust, el porcentaje de controles verificados y la distribución de riesgos residuales.
     - Destacar que cada tarjeta indica la fuente de donde se derivó el dato.
  3. **Instrumento Metodológico (`/instrumentos`)**:
     - Presentar el instrumento `INSTR-F11-ZTA-01` con sus 14 ítems distribuidos en las 6 dimensiones Zero Trust.
  4. **Formulario de Evaluación por Expertos (`/validacion-expertos`)**:
     - Demostrar la pantalla de evaluación.
     - Mostrar cómo el sistema calcula una media ponderada descriptiva que **no preselecciona ni condiciona el veredicto del evaluador**.
     - El veredicto cualitativo (`FAVORABLE`, `FAVORABLE_CON_OBSERVACIONES`, `DESFAVORABLE`) lo declara el experto con total autonomía.
  5. **Inventario Unificado de Evidencias (`/evidencias`)**:
     - Mostrar los **749 elementos de evidencia derivados** clasificados en O1, O2, O3 y O4.
  6. **Generación de Informes Criptográficos (`/informes`)**:
     - Generar un informe ejecutivo Markdown.
     - Mostrar sus cuatro secciones obligatorias: Métricas en vivo, Declaración explícita de datos sintéticos, Limitaciones metodológicas y Referencias.
     - Exhibir el hash SHA-256 único e inmutable del informe generado.
- **Punto Clave para el Tribunal**:
  *"El Objetivo O4 proporciona una metodología formal y reproducible para someter el modelo al juicio de expertos independientes, cerrando la cadena con informes inmutables y trazables."*

---

### Paso 6: Demostración de Auditoría Criptográfica e Inmutabilidad
- **Pantalla**: `/auditoria` (o terminal con verificación automatizada).
- **Qué Demostrar**:
  1. En `/auditoria`, mostrar los registros encadenados por bloque SHA-256.
  2. Demostrar la relación de enlace: el campo `prev_hash` de cada fila coincide estrictamente con el `event_hash` de la fila anterior.
  3. Explicar el mecanismo del ancla HMAC lateral (`lis.db.anchor-key`): si un atacante modificara la base de datos SQLite directamente en disco, la firma del checkpoint fallaría y el sistema se detendría en modo fallo-cerrado.
- **Punto Clave para el Tribunal**:
  *"La auditoría no es un log convencional de texto; es una cadena criptográficamente ligada protegida por secretos laterales que garantizan la integridad forense."*

---

## 4. Resumen de Pruebas y Rigor Técnico

- **Pruebas Automatizadas de API**: **166/166 aprobadas** al 100% contra la pila real (376 segundos de ejecución sin simulaciones en memoria).
- **Comprobaciones en Navegador**: 24 comprobaciones en F4 y 34 en F5 verificadas con capturas de pantalla auténticas (`capturas/shots-f4`, `capturas/shots-f5`).
- **Pruebas Destructivas de Rollback**: 9 casos de prueba donde se forzó el fallo del evento de auditoría para comprobar que SQLite ejecuta reversión total sin dejar datos huérfanos.
- **Respaldo Seguro y Recuperación Verificada**: Scripts automatizados `backup-secure.sh` y ensayo de restauración en sandbox temporal superado con `PRAGMA integrity_check` exitoso.

---

## 5. Declaración de Limitaciones Reales de la Investigación

Es fundamental declarar ante el tribunal con honestidad académica lo que la investigación abordó y lo que constituye trabajo futuro:

1. **Alcance del Banco de Pruebas**: La evaluación experimental se realizó sobre el entorno controlado F11 en `servidor-1`. **No se realizaron pruebas intrusivas ni escaneos sobre la red de producción hospitalaria ni sobre equipos médicos en uso con pacientes reales.**
2. **Datos Sintéticos**: Las órdenes de laboratorio, pacientes y ciertos incidentes de prueba son sintéticos y están debidamente rotulados (`synthetic = 1`).
3. **Servidor Monohilo**: El backend opera sobre un servidor síncrono monohilo, adecuado para el laboratorio demostrativo, requiriendo un balanceador asíncrono (ej. Gunicorn/Uvicorn) para un escalamiento masivo hospitalario.
4. **Juicio de Expertos Pendiente de Recolección de Campo**: El instrumento de validación está sembrado y listo en el sistema, pero la obtención de dictámenes firmados por evaluadores externos constituye una etapa humana que no debe falsearse algorítmicamente.

---

## 6. Conclusiones Técnicas para el Cierre de la Sustentación

1. **Factibilidad Demostrada**: Es técnicamente viable y operativo implementar un SGSI bajo principios Zero Trust en el contexto de un laboratorio clínico hospitalario.
2. **Eliminación de la Confianza Implícita**: Se demostró que la separación estricta de planos PDP (Keycloak) y PEP (Backend API) con MFA obligatorio mitiga eficazmente el riesgo de compromiso de credenciales y escalamiento de privilegios.
3. **Evidencia sobre Opinión**: Al condicionar la gestión de controles y riesgos a comprobadores ejecutables y evidencias vinculadas, la seguridad de la información pasa de ser una auditoría declarativa a una disciplina empíricamente comprobable.