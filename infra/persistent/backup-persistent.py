#!/usr/bin/env python3
# SGSI-ZTA Hospital Lab: Respaldo atomico e integridad SQLite
import os, sys, time, shutil, hashlib, sqlite3
from pathlib import Path

RUNTIME = Path(os.environ.get("F11_RUNTIME_DIR", "/home/elcra/sgsi-zta-runtime/f11"))
DEMO_DIR = RUNTIME / "demo"
DB = DEMO_DIR / "lis.db"
KEY = DEMO_DIR / "lis.db.anchor-key"
BACKUP_DIR = DEMO_DIR / "backups"

timestamp = time.strftime("%Y%m%d_%H%M%S")
dest = BACKUP_DIR / f"backup_{timestamp}"

print(f"=== RESPALDO DE INSTANCIA PERSISTENTE ({timestamp}) ===")
dest.mkdir(parents=True, exist_ok=True)
os.chmod(dest, 0o700)

if not DB.is_file():
    print(f"error: base de datos no existe en {DB}", file=sys.stderr)
    sys.exit(1)

# 1. Comprobacion de integridad SQLite
con = sqlite3.connect(str(DB))
cur = con.cursor()
cur.execute("PRAGMA integrity_check;")
res = cur.fetchone()[0]
if res != "ok":
    print(f"error: falla en PRAGMA integrity_check: {res}", file=sys.stderr)
    con.close()
    sys.exit(1)
print("[1] Integridad SQLite verificada: OK")

# 2. Copia atomica de la base
dest_db = dest / "lis.db"
bck = sqlite3.connect(str(dest_db))
con.backup(bck)
bck.close()
con.close()
os.chmod(dest_db, 0o600)
print(f"[2] Copia atomica creada en {dest_db}")

# 3. Respaldo de clave de anclaje
if KEY.is_file():
    dest_key = dest / "lis.db.anchor-key"
    shutil.copy2(KEY, dest_key)
    os.chmod(dest_key, 0o600)
    print(f"[3] Clave de anclaje respaldada en {dest_key}")

# 4. Checksums SHA-256
sums = []
for p in sorted(dest.glob("*")):
    if p.name == "SHA256SUMS":
        continue
    h = hashlib.sha256(p.read_bytes()).hexdigest()
    sums.append(h + "  " + p.name + "\n")
sums_file = dest / "SHA256SUMS"
sums_file.write_text("".join(sums), encoding="utf-8")
os.chmod(sums_file, 0o600)
print(f"[4] Checksums generados en {sums_file}")

# 5. Rotacion: conservar los ultimos 10 respaldos
backups = sorted([p for p in BACKUP_DIR.glob("backup_*") if p.is_dir()])
if len(backups) > 10:
    for old in backups[:-10]:
        shutil.rmtree(old)
print("[5] Rotacion completada (maximo 10 copias)")

print(f"[+] Respaldo finalizado con exito en {dest}")
