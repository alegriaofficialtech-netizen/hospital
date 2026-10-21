# Backend Python — SGSI-ZTA Hospital Lab

Código versionado recuperado desde `/home/elcra/sandbox-jwt-validator`
(`stage4-lis-candidate-release`, HEAD `9910290`) usando `git archive`.
No incluye `.env`, claves privadas, certificados ni datos clínicos.

## Contenido

- `server.py`: LIS clínico con `http.server`, Zero Trust JWT/OIDC, RBAC y cadena de auditoría.
- `database.py`: persistencia SQLite WAL, transacciones ACID, checkpoints y verificación de cadena.
- `clinical_domain.py`: máquina de estados y validación de mediciones.
- `jwt_validator.py`: validación RS256/JWKS, roles y MFA.
- `audit_monitor/monitor.py`: monitor M2M de auditoría.
- `test_*.py`: suites de regresión recuperadas.

## Requisitos

- Python 3.13+ (probado con 3.14.4 en Windows).
- `cryptography` (ver `requirements.txt`).
- Keycloak 26.x para el modo real; el frontend puede usar mocks sin Keycloak.

## Ejecución local

```powershell
cd backend
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe server.py
```

El servidor escucha en `http://127.0.0.1:8000` por defecto (`HOST`, `PORT`).
`GET /health` es público. El resto requiere Bearer token de Keycloak con los
roles definidos en `jwt_validator.py`.

Variables de entorno relevantes (sin valores en el repo):

- `KEYCLOAK_DISCOVERY_URL`
- `KEYCLOAK_AUDIENCE`
- `KEYCLOAK_EXPECTED_AZP`
- `LIS_DB_PATH`
- `CLINICAL_SIGNING_KEY`
- `IOMT_DEVICE_KEYS_JSON`

## Pruebas

```powershell
cd backend
.\.venv\Scripts\python.exe -m unittest discover -v
```

No ejecutar contra producción. Los tests usan SQLite temporal y claves de prueba.

**Nota Windows:** la suite completa fue escrita para Linux y asume permisos POSIX
`0600`, Docker y un Keycloak real. En Windows fallan las aserciones de modo de archivo,
las pruebas que invocan `docker` y los flujos OAuth que requieren Keycloak. Esas fallas
son de entorno, no del frontend. Para validar la suite completa, ejecutar en Linux/WSL o
en el contenedor previsto. En Windows, el frontend funciona de forma independiente en
modo mock; el backend real debe validarse en el entorno Linux objetivo.
