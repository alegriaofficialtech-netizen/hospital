import os

ENV_FILE = "/home/elcra/sandbox-jwt-validator/.env.test_credentials"

def load_test_credentials() -> dict:
    creds = {}
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if '=' in line and not line.startswith('#'):
                    k, v = line.split('=', 1)
                    creds[k.strip()] = v.strip()
    for key in ['TEST_ADMISION_PASSWORD', 'TEST_MEDICO_PASSWORD', 'TEST_AUDITOR_PASSWORD']:
        if key in os.environ:
            creds[key] = os.environ[key]
    return creds

def get_user_password(username: str) -> str:
    creds = load_test_credentials()
    role_key = f"TEST_{username.split('.')[0].upper()}_PASSWORD"
    pwd = creds.get(role_key)
    if not pwd:
        raise RuntimeError(f"Credencial protegida para '{username}' ({role_key}) no encontrada en .env.test_credentials")
    return pwd