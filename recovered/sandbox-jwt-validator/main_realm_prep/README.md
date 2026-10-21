# Preparación Declarativa del Realm Principal `hospital-lab` (Keycloak 26.8)

Módulo declarativo e idempotente para alinear el realm de producción `hospital-lab` con la Arquitectura Zero Trust (NIST SP 800-207) del SGSI-ZTA Hospital Lab.

---

## 1. Alcance y Objetivos

1. **Cliente Frontend (`clinical-poc`):**
   - Habilita el cliente preservando el 100% de la configuración preexistente (`redirectUris`, `webOrigins`, `attributes`).
   - Valida el flujo seguro Authorization Code con PKCE S256 mandatorio. Deshabilita Direct Access Grants.
   - Configura el mapper de audiencia `clinical-poc-api-audience` (`oidc-audience-mapper`).
   - Configura el mapper de métodos de autenticación `amr` (`oidc-amr-mapper`) para la acreditación contextual de TOTP/MFA clínico.

2. **Servicio Automatizado de Monitoreo (`clinical-audit-monitor-service`):**
   - Aprovisiona cliente confidencial M2M bajo RFC 6749 (Client Credentials).
   - Habilita Service Accounts (`serviceAccountsEnabled: true`).
   - Asigna exclusivamente el rol de mínimo privilegio `auditor`.
   - Audita roles clínicos no autorizados (`medico`, `admision`, etc.). **No los revoca automáticamente**: exige autorización explícita mediante la bandera `--allow-revocations` y verifica la respuesta real de Keycloak.
   - Sincronización inteligente: solo planifica actualización de credenciales si el archivo local está ausente o desfasado, comparando secretos en memoria (`secrets.compare_digest`) sin exponerlos en salidas.

3. **Límite de Confianza de Proxy (`KC_PROXY_HEADERS=xforwarded`):**
   - Audita que Keycloak procese cabeceras de proxy inverso.
   - Documenta que la seguridad perimetral depende de que el proxy perimetral (Nginx) sobrescriba de forma no eludible `X-Forwarded-For`, `X-Forwarded-Proto` y `X-Forwarded-Host`, manteniendo Keycloak aislado en `127.0.0.1:8085`.

4. **Preparación de MFA en Flujo Principal:**
   - Audita el flujo `hospital-browser`. Verifica que la ejecución condicional exija `auth-otp-form` para usuarios con rol `mfa-required`.
   - Comprueba que los médicos en `hospital-lab` pertenecen al grupo `medico`, adquiriendo el rol `mfa-required`, y que el mapper `amr` acredita dicho factor en el access token.

---

## 2. Invariantes de Seguridad y No Destructividad

- **Preservación Integral:** No realiza `PUT` parciales destructivos que puedan eliminar atributos, URIs o configuraciones personalizadas del cliente `clinical-poc`.
- **Idempotencia Estricta:** Las ejecuciones sucesivas validan las configuraciones reales de los mappers y atributos. Si el realm y las credenciales ya están conformes, planifica exactamente 0 cambios.
- **Fail-Safe y Resilencia:** Cada operación queda registrada en un diario de ejecución (*journal*). Si un paso intermedio falla, se interrumpe la ejecución sin eliminar clientes ni roles preexistentes.
- **Protección de Secretos:** La escritura en `.env.audit_monitor_credentials_main` utiliza descriptores temporales con `os.fsync`, permisos estrictos `0600` y respaldo `.bak` previo.
- **Aislamiento de Realm:** Rechaza taxativamente cualquier realm que no sea `hospital-lab` (protege `hospital-lab-oidc-test` y `master`).
- **Separación Categórica:** Clasifica las acciones en:
  - `ADDITIVE`: Acciones seguras sin riesgo de rotura.
  - `MODIFICATION`: Actualizaciones sobre configuraciones existentes.
  - `REVOCATION`: Acciones destructivas que requieren autorización independiente.

---

## 3. Modos de Uso

### Modo Auditoría y Verificación (`--verify`)
Inspecciona el realm sin planificar cambios:
```bash
python3 main_realm_prep/prepare_hospital_lab_realm.py --verify
```

### Modo Simulación Declarativa (`--dry-run`, por defecto)
Muestra las operaciones exactas agrupadas por categoría y los payloads que se ejecutarían:
```bash
python3 main_realm_prep/prepare_hospital_lab_realm.py --dry-run
```

### Modo con Autorización de Revocaciones (`--allow-revocations`)
Habilita la planificación y ejecución de eliminación de roles no autorizados en Service Accounts:
```bash
python3 main_realm_prep/prepare_hospital_lab_realm.py --dry-run --allow-revocations
```

### Modo Aplicación Autorizada (`--apply`)
Aplica los cambios tras confirmación manual explícita (o bandera `--confirm` para CI/CD):
```bash
python3 main_realm_prep/prepare_hospital_lab_realm.py --apply
```

---

## 4. Pruebas Automatizadas del Preparador

La suite `test_prepare_hospital_lab_realm.py` simula la API REST administrativa de Keycloak de forma determinista y sin tocar servicios reales:

```bash
python3 -m unittest -v main_realm_prep/test_prepare_hospital_lab_realm.py
```
Cubre 17 casos de prueba críticos: preservación de clientes, creación completa, corrección de mappers, sincronización inteligente de credenciales sin fuga, idempotencia, fallos HTTP, manejo de excepciones, verificación real de revocación, detección de clientes incompatibles y separación categórica de acciones.
