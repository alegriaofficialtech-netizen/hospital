# SGSI-ZTA Hospital Lab: Standalone JWT/OIDC Validator Sandbox

Prototipo de validaci?n criptogr?fica Zero Trust para el Policy Enforcement Point (PEP) del LIS Cl?nico.
Conforme a NIST SP 800-207, RFC 7519 (JWT), RFC 7517 (JWK) y RFC 7515 (JWS).

---

## 1. Alcance y Aislamiento

- **Ubicaci?n:** `/home/elcra/sandbox-jwt-validator/` (Entorno de pruebas 100% aislado).
- **Dependencias:** Python 3.13 + `python3-cryptography` est?ndar de Debian 13.
- **Sin afectaci?n:** Cero modificaciones sobre `/opt/sgsi-zta-hospital-lab`, `/home/elcra/sgsi-zta-native-app` o los contenedores Docker en ejecuci?n.

---

## 2. Invariantes de Seguridad Zero Trust Implementados

1. **Criptograf?a Asim?trica Estricta:** Exclusivamente tokens firmados con `RS256` mediante claves p?blicas descargadas de Keycloak v?a JWKS. Rechazo de `none`, `HS256` y cualquier algoritmo sim?trico.
2. **Rechazo de Confusi?n de Tipos:** Los ID Tokens (`typ: ID` o `token_use: id`) son rechazados en el PEP; solo se aceptan Access Tokens Bearer.
3. **Validaci?n Contextual de MFA:** `acr=1` NO se acepta como evidencia de TOTP. Para operaciones cl?nicas cr?ticas (ej. `VALIDATE_ORDER`), se exige expl?citamente `amr` con indicador temporal (`otp` o `totp`).
4. **Denegaci?n por Defecto (Default Deny):** Usuarios sin roles cl?nicos autorizados o con firmas no coincidentes son bloqueados con excepciones tipadas.
5. **Mitigaci?n Anti-DoS en JWKS:** Rate-limiting de 60 segundos ante r?fagas de tokens con `kid` desconocido para evitar ataques de inundaci?n hacia Keycloak.
6. **Aislamiento IoMT:** Las transmisiones de analizadores biom?dicos se gestionan en su propio canal HMAC y nunca a trav?s de este validador.

---

## 3. Instrucciones de Ejecuci?n

Para ejecutar la suite completa de pruebas automatizadas:

```bash
cd /home/elcra/sandbox-jwt-validator
python3 -m unittest -v test_jwt_validator.py
```

Para medir el consumo de memoria y CPU durante la ejecuci?n:

```bash
/usr/bin/time -v python3 -m unittest test_jwt_validator.py
```
