# Procedimiento manual: habilitar `admin.test`

Estado: **pendiente**. No ejecutado. Requiere una persona con acceso a la app
de autenticacion (TOTP) y al tunel SSH del laboratorio.

Regla que manda: `admin.test` no sustituye a `medico.test` hasta que se
demuestre que puede autenticarse con MFA y administrar identidades de verdad.

## 1. Preparar el acceso

1. Abrir el tunel SSH que publica los puertos 8085 (Keycloak) y 4200 (frontend).
2. Entrar en la consola de administracion de Keycloak:
   `http://localhost:8085/admin` con la cuenta de administrador del realm
   `master`. Su credencial no se escribe aqui: vive en el entorno de
   `infra/local-test/setup_realm.py`.

## 2. Enrolar el segundo factor

3. Realm `hospital-lab-local` -> `Users` -> `admin.test`.
4. Pestana `Credentials` -> `Set up authenticator` (OTP/TOTP).
5. Escanear el codigo con la app y confirmar el codigo de 6 digitos.
6. Guardar el secreto (`totp_secret`) en
   `/home/elcra/sgsi-zta-runtime/f11/admin-credentials.json` con permisos 600.
   **Sin ese secreto no se puede verificar por API**, y el codigo es de un solo
   uso por ventana de 30 s.

## 3. Asignar el rol y exigir MFA

7. `Role mapping` -> asignar `sgsi-admin`.
8. Asignar tambien `mfa-required`.
9. Comprobar que la cuenta esta `enabled`.

## 4. Verificar de verdad (antes de tocar nada mas)

10. Navegador: `http://localhost:4200/login` con `admin.test` + TOTP. Debe
    aterrizar en `/administracion` sin segundo formulario.
11. API: con el token de `admin.test`, `GET /api/v1/admin/identities` debe
    responder 200 y una operacion de escritura debe aceptarse (MFA acreditada).
12. Diagnostico: ejecutar `BACKEND_ADMIN_REQUIRES_MFA` y comprobar que el
    hallazgo `KC_MFA_ON_ADMIN_IDENTITIES` ya no menciona a `admin.test`.

## 5. Retirar el privilegio redundante de `medico.test`

13. Solo si los pasos 10-12 pasan: quitar `sgsi-admin` a `medico.test` en
    Keycloak, **conservando** el rol `medico` y `mfa-required`.
14. Verificar que `medico.test` ya no entra en `/administracion` (o que la API
    le responde 403 en administracion) y que **si** sigue validando ordenes
    clinicas.
15. Si algo falla en el paso 14, restaurar `sgsi-admin` a `medico.test` antes de
    seguir. Nunca dejar la plataforma sin administrador funcional.
