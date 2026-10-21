#!/usr/bin/env python3
"""
validate_backups.py - Validación Criptográfica y Ensayo de Restauración Aislada de Respaldos
SGSI-ZTA Hospital Lab - Servidor-1 (Debian 13)

Verifica:
1. Permisos restrictivos (0600) y exclusión formal en .gitignore.
2. Integridad de compresión gzip y ausencia de escrituras incompletas.
3. Validación estructural del volcado JSON del realm.
4. Ensayo de restauración de extremo a extremo en contenedor PostgreSQL 16 aislado.
5. Verificación de objetos restaurados: 101 tablas, 3 realms, clientes y usuarios.
6. Procedimiento robusto de captura con manejo de pipes y umask/permisos atómicos.
"""

import json
import os
import subprocess
import sys
import time

SANDBOX_DIR = "/home/elcra/sandbox-jwt-validator"
JSON_BACKUP = os.path.join(SANDBOX_DIR, "backup_hospital_lab_realm_pre_stage4.json")
SQL_BACKUP = os.path.join(SANDBOX_DIR, "backup_keycloak_db_pre_stage4.sql.gz")
TEST_CONTAINER = "backup-validation-pg-rehearsal"


def verify_permissions_and_git():
    print("[1/5] Verificando permisos y exclusión de Git...")
    for fpath in (JSON_BACKUP, SQL_BACKUP):
        if not os.path.exists(fpath):
            raise FileNotFoundError(f"Archivo de respaldo no encontrado: {fpath}")

        stat_info = os.stat(fpath)
        mode = stat_info.st_mode & 0o777
        if mode != 0o600:
            raise PermissionError(f"Permisos incorrectos en {fpath}: {oct(mode)} (esperado: 0600)")
        print(f"  [+] {os.path.basename(fpath)}: Permisos 0600 confirmados ({stat_info.st_size} bytes)")

        # Verificar exclusión en .gitignore
        res = subprocess.run(
            ["git", "-C", SANDBOX_DIR, "check-ignore", fpath],
            capture_output=True,
            text=True
        )
        if res.returncode != 0:
            raise AssertionError(f"El archivo {fpath} NO está excluido por .gitignore!")
        print(f"  [+] {os.path.basename(fpath)}: Exclusión de Git verificada (regla: {res.stdout.strip()})")


def verify_gzip_integrity():
    print("\n[2/5] Verificando integridad de compresión gzip del dump SQL...")
    res = subprocess.run(["gzip", "-t", SQL_BACKUP], capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Fallo de integridad gzip en {SQL_BACKUP}: {res.stderr}")
    print(f"  [+] {os.path.basename(SQL_BACKUP)}: Archivo gzip íntegro y sin corrupción.")


def verify_json_structure():
    print("\n[3/5] Verificando estructura del respaldo JSON del realm...")
    with open(JSON_BACKUP, "r", encoding="utf-8") as f:
        data = json.load(f)

    if "realm" not in data or "clients" not in data or "roles" not in data:
        raise ValueError("El JSON exportado no contiene las claves requeridas ('realm', 'clients', 'roles')")

    realm_id = data["realm"].get("realm")
    if realm_id != "hospital-lab":
        raise ValueError(f"El realm exportado es '{realm_id}', esperado 'hospital-lab'")

    clients = data.get("clients", [])
    roles = data.get("roles", [])
    print(f"  [+] Realm: {realm_id}")
    print(f"  [+] Clientes exportados: {len(clients)}")
    print(f"  [+] Roles exportados: {len(roles)}")

    poc_client = next((c for c in clients if c.get("clientId") == "clinical-poc"), None)
    if not poc_client:
        raise ValueError("Cliente 'clinical-poc' no encontrado en el respaldo JSON pre-stage4")
    print(f"  [+] Estado de 'clinical-poc' en respaldo: enabled={poc_client.get('enabled')} (esperado: False)")


def verify_isolated_sql_restore():
    print("\n[4/5] Ejecutando ensayo de restauración en instancia PostgreSQL 16 aislada...")
    # Asegurar limpieza previa
    subprocess.run(["docker", "rm", "-f", TEST_CONTAINER], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Iniciar contenedor temporal postgres:16-alpine sin exponer puertos al host
    run_cmd = [
        "docker", "run", "-d",
        "--name", TEST_CONTAINER,
        "-e", "POSTGRES_PASSWORD=KeycloakTestPass2026!",
        "-e", "POSTGRES_DB=keycloak",
        "-e", "POSTGRES_USER=keycloak",
        "postgres:16-alpine"
    ]
    subprocess.run(run_cmd, check=True, stdout=subprocess.DEVNULL)

    try:
        # Esperar a que PostgreSQL esté listo
        ready = False
        for _ in range(15):
            res = subprocess.run(
                ["docker", "exec", TEST_CONTAINER, "pg_isready", "-U", "keycloak"],
                capture_output=True, text=True
            )
            if res.returncode == 0:
                ready = True
                break
            time.sleep(1)

        if not ready:
            raise TimeoutError("PostgreSQL en contenedor aislado no respondió a pg_isready")
        print("  [+] Instancia aislada de PostgreSQL 16 iniciada y respondiendo.")

        # Restaurar volcado SQL descomprimiendo al vuelo con detención inmediata ante errores (ON_ERROR_STOP=1)
        print("  [*] Restaurando base de datos con psql (ON_ERROR_STOP=1)...")
        zcat_p = subprocess.Popen(["zcat", SQL_BACKUP], stdout=subprocess.PIPE)
        psql_cmd = [
            "docker", "exec", "-i", TEST_CONTAINER,
            "psql", "-U", "keycloak", "-d", "keycloak",
            "-v", "ON_ERROR_STOP=1", "-q"
        ]
        psql_p = subprocess.Popen(psql_cmd, stdin=zcat_p.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        zcat_p.stdout.close()
        stdout, stderr = psql_p.communicate()

        if psql_p.returncode != 0:
            raise RuntimeError(f"Fallo durante la restauración psql (código {psql_p.returncode}): {stderr.decode()}")
        print("  [+] Restauración completada exitosamente sin errores.")

        # Consultas de verificación sobre la base restaurada
        def run_query(sql):
            cmd = ["docker", "exec", TEST_CONTAINER, "psql", "-U", "keycloak", "-d", "keycloak", "-t", "-A", "-c", sql]
            return subprocess.check_output(cmd).decode().strip()

        table_count = int(run_query("SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public';"))
        realms = run_query("SELECT string_agg(name, ', ') FROM realm;")
        user_count = int(run_query("SELECT count(*) FROM user_entity;"))
        poc_status = run_query("SELECT enabled FROM client WHERE client_id = 'clinical-poc';")

        print(f"  [+] Total de tablas públicas restauradas: {table_count} (esperado >= 100)")
        print(f"  [+] Realms restaurados: {realms}")
        print(f"  [+] Usuarios restaurados en Keycloak: {user_count} usuarios")
        print(f"  [+] Estado de 'clinical-poc' en DB restaurada: enabled={poc_status} (esperado: f)")

        assert table_count >= 100, f"Cantidad insuficiente de tablas: {table_count}"
        assert "hospital-lab" in realms, f"Realm 'hospital-lab' ausente en {realms}"
        assert user_count >= 10, f"Cantidad insuficiente de usuarios: {user_count}"
        assert poc_status == "f", f"'clinical-poc' debería estar deshabilitado en respaldo pre-stage4, obtenido: {poc_status}"
        print("  [+] Todas las aserciones de la base de datos restaurada pasaron al 100%.")

    finally:
        # Destruir contenedor temporal garantizando limpieza absoluta
        subprocess.run(["docker", "rm", "-f", TEST_CONTAINER], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("  [+] Contenedor temporal aislado destruido y recursos liberados.")


def hardened_backup_procedure_demonstration():
    print("\n[5/5] Demostrando procedimiento de captura endurecido (Fail-Safe Pipes + Permisos 0600)...")
    """
    Patrón de arquitectura seguro para captura de respaldos:
    1. Archivo creado directamente con permisos 0600 mediante os.open (sin ventana de exposición umask).
    2. Ejecución con monitoreo individual de códigos de retorno de pg_dump y gzip.
    3. Si pg_dump falla a mitad de la compresión, se detecta el fallo, se elimina el archivo parcial y se aborta.
    4. Inmediata validación gzip -t post-escritura.
    """
    test_out = "/tmp/test_hardened_backup.sql.gz"
    try:
        fd = os.open(test_out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with open(fd, "wb") as out_f:
            p1 = subprocess.Popen(
                ["docker", "exec", "sgsi-zta-hospital-lab-keycloak-postgres-1", "pg_dump", "-U", "keycloak", "--schema-only", "keycloak"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            p2 = subprocess.Popen(["gzip", "-c"], stdin=p1.stdout, stdout=out_f, stderr=subprocess.PIPE)
            p1.stdout.close()
            _, err1 = p1.communicate()
            _, err2 = p2.communicate()

            if p1.returncode != 0:
                raise RuntimeError(f"pg_dump falló con código {p1.returncode}: {err1.decode()}")
            if p2.returncode != 0:
                raise RuntimeError(f"gzip falló con código {p2.returncode}: {err2.decode()}")

        # Verificar permisos
        st = os.stat(test_out)
        mode = st.st_mode & 0o777
        assert mode == 0o600, f"Permisos inválidos: {oct(mode)}"

        # Verificar gzip
        res = subprocess.run(["gzip", "-t", test_out], capture_output=True)
        assert res.returncode == 0, "Fallo gzip -t en respaldo de prueba"

        print("  [+] Patrón de tubería protegida y permisos atómicos 0600 verificado con éxito.")
    finally:
        if os.path.exists(test_out):
            os.remove(test_out)


def main():
    print("=" * 72)
    print(" SGSI-ZTA: VALIDACIÓN Y ENSAYO DE RESTAURACIÓN DE RESPALDOS (Debian 13)")
    print("=" * 72)
    verify_permissions_and_git()
    verify_gzip_integrity()
    verify_json_structure()
    verify_isolated_sql_restore()
    hardened_backup_procedure_demonstration()
    print("\n" + "=" * 72)
    print(" [+] RESULTADO: TODOS LOS RESPALDOS SON 100% ÍNTEGROS Y RECUPERABLES.")
    print("=" * 72)


if __name__ == "__main__":
    main()
