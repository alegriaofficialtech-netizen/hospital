# Gestión administrativa de usuarios y roles (F11)

Realm aislado: `hospital-lab-local` en el Keycloak local de F11
(`http://127.0.0.1:8085`). **Este documento no aplica al realm de producción.**

## Principios

1. **Sin registro público.** `registrationAllowed` está en `false` y
   `resetPasswordAllowed` también. Nadie puede crear su propia cuenta ni
   restablecer su contraseña por el portal: la única entrada es la
   administration del realm.
2. **Solo identidades sintéticas.** Las cuentas se crean con el prefijo
   `*.test` y referencias de paciente `DNI-DEMO-*`. Ningún dato real de
   paciente, profesional o identificador entra en este realm.
3. **Baja por desactivación, no por borrado.** Una cuenta que se desactiva
   conserva su historial en la cadena de auditoría. El borrado destruye
   evidencia y por tanto no se usa en el ciclo normal.
4. **MFA por rol, no por usuario.** La exigencia de segundo factor está
   atada al rol `mfa-required`, de modo que el patólogo siempre la tiene y
   recepción nunca. La clave del rol es `mfa-required`; el flujo condicional
   del realm la exige.
5. **Separación de responsabilidades.** Quien administra cuentas no es quien
   firma resultados, y el rol `auditor` no puede administrar usuarios. La
   administración usa la credencial de servicio del realm `master`, que no
   debe compartirse con el rol `auditor`.
6. **El realm de producción no se toca.** Cualquier herramienta debe negarse
   a operar sobre un realm distinto de `hospital-lab-local` salvo que se le
   pase un flag explícito, y ese flag debe estar fuera del uso normal.

## Matriz de roles

| Rol del realm | Rol en el LIS | Puede | MFA |
|---|---|---|---|
| `admision` | `ROLE_RECEPTION` | Crear órdenes, listar órdenes | No |
| `laboratorio` | `ROLE_LAB_TECH` | Listar órdenes y resultados | No |
| `medico` | `ROLE_PATHOLOGIST` | Validar y liberar informes | No por defecto |
| `medico` + `mfa-required` | `ROLE_PATHOLOGIST` | Validar y liberar informes | **Sí, obligatoria** |
| `auditor` | `ROLE_SECURITY_AUDITOR` | Leer la auditoría y la cadena de hashes | No |

La cuenta `medico.sinmfa` existe precisamente para comprobar que la
validación **se deniega** sin evidencia OTP en el token.

## Operaciones y llamadas de administración

Todas se ejecutan contra la API de administración del realm local, con un
token de servicio del realm `master`:

```
POST /realms/master/protocol/openid-connect/token
     grant_type=password&client_id=admin-cli&username=<admin>&password=<clave>
```

### Alta de una cuenta sintética

```
POST /admin/realms/hospital-lab-local/users
{
  "username": "residente.test",
  "enabled": true,
  "emailVerified": true,
  "firstName": "Cuenta", "lastName": "Sintetica",
  "attributes": { "f11": "sintetico" },
  "credentials": [ { "type": "password", "value": "<clave aleatoria>", "temporary": true } ]
}
```

Después se asignan los roles:

```
GET  /admin/realms/hospital-lab-local/roles/{rol}
PUT  /admin/realms/hospital-lab-local/users/{id}/role-mappings/realm
     [ ...ids de los roles... ]
```

Y, si corresponde, se exige MFA con el rol `mfa-required`, que el flujo
condicional del realm traduce a la pantalla de TOTP.

### Baja o desactivación

```
PUT /admin/realms/hospital-lab-local/users/{id}
{ "enabled": false }
```

Nunca `DELETE`: la traza de auditoría debe seguir siendo reconstruible.

### Cambio de rol

```
GET  /admin/realms/hospital-lab-local/users/{id}/role-mappings/realm
PUT  /admin/realms/hospital-lab-local/users/{id}/role-mappings/realm
     [ ...ids de los roles... ]
```

### Rotación de clave

```
PUT /admin/realms/hospital-lab-local/users/{id}/reset-password
{ "type": "password", "value": "<clave aleatoria>", "temporary": true }
```

### Verificación

```
GET /admin/realms/hospital-lab-local/users?search=residente.test
```

Y la comprobación funcional: la cuenta obtiene token con la audiencia
`clinical-poc-api` y el rol esperado en `realm_access.roles`, y el token de
`medico` + `mfa-required` llega con `amr` incluyendo `otp`.

## Reglas de la contraseña

- Generada aleatoriamente en el momento, de al menos 16 caracteres.
- `temporary: true` en Keycloak: obliga al cambio en el primer inicio de
  sesión. La cuenta nace sin contraseña utilizable hasta ese cambio.
- La contraseña **nunca** se escribe en el repositorio, en un registro del
  shell ni en la interfaz de Angular. Se entrega por un canal fuera de banda
  y solo se almacena en el fichero de credenciales sintéticas con modo
  `0600`, fuera del árbol de Git.
- El correo no se usa como vía de recuperación: `resetPasswordAllowed` está
  en `false` y el realm no tiene SMTP configurado, de modo que no existe
  ningún canal de recuperación que alguien pueda usar.

## Trazabilidad de la propia administración

Cada alta, baja, cambio de rol o rotación debe quedar registrada con:
usuario administrador, marca de tiempo, cuenta y realm afectados, operación y
motivo. El registro natural es la auditoría del Keycloak (eventos
`CREATE`/`UPDATE`/`DELETE` de la administración del realm) y, para las
operaciones sobre F11, la cadena de auditoría del backend, que ya es
inmutable y encadenada por hash.

## Propuesta de herramienta

`infra/f11/manage-users.py`, con estas garantías:

- `--realm` por defecto `hospital-lab-local`; si se indica otro realm exige
  `--i-know-this-is-not-production`.
- `--dry-run` obligatorio para cualquier operación destructiva: muestra el
  cambio y no lo aplica.
- Imprime los identificadores y los roles, **nunca** las contraseñas; las
  claves se escriben directamente en el fichero de credenciales con modo
  `0600`.
- Lee la credencial de administración del entorno (`KEYCLOAK_ADMIN_PASSWORD`)
  y falla si no está presente, en vez de aceptarla por línea de órdenes.
- Cada operación deja una línea de traza en
  `$F11_RUNTIME_DIR/user-admin.log`.

## Lo que queda fuera de alcance

- Gestión de usuarios del realm de producción: no se hace desde aquí.
- Registro autoservicio, recuperación por correo o redes sociales: no existen
  y no deben añadirse.
- Alta de cuentas de pacientes: los pacientes no tienen cuenta; el acceso
  es siempre de personal.
