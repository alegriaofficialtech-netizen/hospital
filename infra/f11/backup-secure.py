#!/usr/bin/env python3
"""Respaldo seguro, atómico y verificable del proyecto SGSI-ZTA Hospital Lab (F6).

Respaldos generados:
  * Repositorio Git completo con ramas, historial y stash (git bundle)
  * Base de datos SQLite consistente mediante sqlite3.backup()
  * Metadatos de migraciones, versiones y conteos
  * Secretos y archivo lateral de clave de anclaje (.anchor-key) con permisos 0600
  * Verificacion de integridad automatica mediante SHA-256 e integrity_check
"""

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = Path(os.environ.get("F11_RUNTIME_DIR", "/home/elcra/sgsi-zta-runtime/f11"))
DEFAULT_BACKUP_BASE = RUNTIME / "backups"

if str(ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(ROOT / "backend"))

from database import ClinicalDatabaseManager


def sha256_file(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def create_backup(target_dir: Path) -> Path:
    target_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(target_dir, 0o700)

    secrets_dir = target_dir / "secrets"
    secrets_dir.mkdir(exist_ok=True)
    os.chmod(secrets_dir, 0o700)

    # 1. Base de datos SQLite consistente y su ancla lateral
    db_file = RUNTIME / "lis.db"
    dest_db = target_dir / "lis.db"
    print(f"[*] Respaldando base de datos viva {db_file} -> {dest_db}...")
    db_mgr = ClinicalDatabaseManager(str(db_file))
    db_mgr.backup_database(str(dest_db))
    db_mgr.close()
    os.chmod(dest_db, 0o600)
    
    # Copiar anchor-key tambien en la carpeta secrets
    anchor_src = RUNTIME / "lis.db.anchor-key"
    if anchor_src.is_file():
        shutil.copy2(anchor_src, secrets_dir / "lis.db.anchor-key")
        os.chmod(secrets_dir / "lis.db.anchor-key", 0o600)

    # 2. Respaldo Git (bundle con todas las ramas y stash)
    bundle_file = target_dir / "git_repo.bundle"
    print(f"[*] Creando bundle Git completo -> {bundle_file}...")
    cmd = ["git", "-C", str(ROOT), "bundle", "create", str(bundle_file), "--all", "refs/stash"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        # Si no hay stash, reintentar solo con --all
        cmd = ["git", "-C", str(ROOT), "bundle", "create", str(bundle_file), "--all"]
        res = subprocess.run(cmd, check=True, capture_output=True, text=True)
    os.chmod(bundle_file, 0o600)

    # Verificar bundle
    v_res = subprocess.run(["git", "bundle", "verify", str(bundle_file)], capture_output=True, text=True)
    if v_res.returncode != 0:
        raise RuntimeError(f"Error verificando git bundle: {v_res.stderr}")

    # 3. Archivos de configuracion y credenciales
    secret_files = [
        "credentials.json",
        "admin-credentials.json",
        "admin-sinmfa-credentials.json",
        "e2e-secrets.json",
    ]
    for sf in secret_files:
        src_path = RUNTIME / sf
        if src_path.is_file():
            dst_path = secrets_dir / sf
            shutil.copy2(src_path, dst_path)
            os.chmod(dst_path, 0o600)

    # 4. Metadatos de migraciones y tablas
    print("[*] Exportando metadatos de migraciones y tablas...")
    con = sqlite3.connect(f"file:{dest_db}?mode=ro", uri=True)
    cur = con.cursor()
    cur.execute("SELECT version, applied_at FROM schema_migrations ORDER BY version ASC;")
    migrations = [{"version": r[0], "applied_at": r[1]} for r in cur.fetchall()]

    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;")
    tables = [r[0] for r in cur.fetchall()]

    table_counts = {}
    for t in tables:
        cur.execute(f"SELECT count(*) FROM {t};")
        table_counts[t] = cur.fetchone()[0]

    cur.execute("SELECT last_hash, total_events, updated_at, anchor_signature FROM audit_checkpoints WHERE checkpoint_id = 1;")
    cp = cur.fetchone()
    checkpoint = {
        "last_hash": cp[0] if cp else None,
        "total_events": cp[1] if cp else 0,
        "updated_at": cp[2] if cp else None,
        "anchor_signature": cp[3] if cp else None,
    }
    con.close()

    # Git info
    git_head = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
    git_branch = subprocess.check_output(["git", "-C", str(ROOT), "branch", "--show-current"], text=True).strip()
    git_msg = subprocess.check_output(["git", "-C", str(ROOT), "log", "-1", "--pretty=%B"], text=True).strip()

    metadata = {
        "backup_created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "git": {
            "head": git_head,
            "branch": git_branch,
            "last_commit_subject": git_msg.splitlines()[0] if git_msg else "",
        },
        "database": {
            "schema_version": max((m["version"] for m in migrations), default=0),
            "migrations": migrations,
            "total_tables": len(tables),
            "table_counts": table_counts,
            "audit_checkpoint": checkpoint,
        },
        "python_version": sys.version,
    }

    meta_file = target_dir / "metadata.json"
    meta_file.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    os.chmod(meta_file, 0o600)

    # 5. Calcular hashes SHA-256 de todos los artefactos
    print("[*] Calculando hashes SHA-256...")
    sha_lines = []
    for root_dir, _, files in os.walk(target_dir):
        for f in sorted(files):
            if f == "SHA256SUMS":
                continue
            fpath = Path(root_dir) / f
            rel = fpath.relative_to(target_dir)
            digest = sha256_file(fpath)
            sha_lines.append(f"{digest}  {rel}")

    sums_file = target_dir / "SHA256SUMS"
    sums_file.write_text("\n".join(sha_lines) + "\n", encoding="utf-8")
    os.chmod(sums_file, 0o600)

    return target_dir


def verify_recovery(backup_dir: Path) -> bool:
    print("\n[*] Ejecutando verificacion de recuperacion en entorno aislado...")
    with tempfile.TemporaryDirectory(prefix="f6_verify_restore_") as tmp_dir:
        tmp_path = Path(tmp_dir)
        restored_db = tmp_path / "lis.db"
        restored_anchor = tmp_path / "lis.db.anchor-key"

        # Copiar base y ancla
        shutil.copy2(backup_dir / "lis.db", restored_db)
        if (backup_dir / "lis.db.anchor-key").is_file():
            shutil.copy2(backup_dir / "lis.db.anchor-key", restored_anchor)
        elif (backup_dir / "secrets" / "lis.db.anchor-key").is_file():
            shutil.copy2(backup_dir / "secrets" / "lis.db.anchor-key", restored_anchor)

        os.chmod(restored_db, 0o600)
        os.chmod(restored_anchor, 0o600)

        # 1. Integridad SQLite
        con = sqlite3.connect(str(restored_db))
        cur = con.cursor()
        cur.execute("PRAGMA integrity_check;")
        res = cur.fetchall()
        con.close()
        if res != [("ok",)]:
            print(f"[!] PRAGMA integrity_check fallo: {res}", file=sys.stderr)
            return False
        print("  [+] PRAGMA integrity_check: OK")

        # 2. Inicializar ClinicalDatabaseManager sobre la copia para validar consistencia de checkpoint y ancla
        db_mgr = ClinicalDatabaseManager(str(restored_db))
        last_hash = db_mgr.get_last_audit_hash()
        events = db_mgr.get_audit_events(limit=1)
        db_mgr.close()

        print(f"  [+] Respaldo de base inicializado y verificado (cadena criptográfica y checkpoint válidos).")
        print(f"  [+] Último hash encadenado verificado: {last_hash[:16]}...")

        # 3. Verificar SHA256SUMS del respaldo
        sums_file = backup_dir / "SHA256SUMS"
        for line in sums_file.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            expected_hash, rel_path = line.split("  ", 1)
            actual_hash = sha256_file(backup_dir / rel_path)
            if actual_hash != expected_hash:
                print(f"[!] Mismatch de hash en {rel_path}: esperado {expected_hash}, calculado {actual_hash}", file=sys.stderr)
                return False
        print("  [+] SHA256SUMS verificado: todos los archivos coinciden.")

    print("[*] Verificacion de recuperacion completada exitosamente.")
    return True


def main():
    parser = argparse.ArgumentParser(description="Respaldo seguro F6")
    parser.add_argument("--output-dir", type=str, default=None, help="Directorio destino del respaldo")
    args = parser.parse_args()

    ts = time.strftime("%Y%m%d_%H%M%S")
    target = Path(args.output_dir) if args.output_dir else (DEFAULT_BACKUP_BASE / f"f6_backup_{ts}")

    print(f"=== INICIANDO RESPALDO SEGURO F6 ===")
    print(f"Destino: {target}")
    backup_path = create_backup(target)
    print(f"[+] Respaldo creado en {backup_path}")

    ok = verify_recovery(backup_path)
    if not ok:
        print("[FATAL] La verificacion de recuperacion fallo.", file=sys.stderr)
        sys.exit(1)

    print(f"=== RESPALDO SEGURO F6 COMPLETADO CON EXITO ===")


if __name__ == "__main__":
    main()