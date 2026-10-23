#!/usr/bin/env python3
"""Preparacion del entorno de demostracion limpia SGSI-ZTA Hospital Lab (F6).

Genera una base de datos aislada (/home/elcra/sgsi-zta-runtime/f11/demo/lis.db)
con datos sintéticos normativos limpios (sin residuos de ejecuciones de prueba):
  * Activos del laboratorio (M3)
  * Matriz de riesgos 5x5 (M4)
  * Catalogo de controles ISO 27001 / NIST / CISA (M5)
  * Incidentes iniciales de seguridad (M6)
  * Instrumento de validacion INSTR-F11-ZTA-01 v1.0 (M9, sin dictamenes falsos)
  * Cadena de auditoria criptografica propia con su ancla lateral (0600)
"""

import argparse
import os
import shutil
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = Path(os.environ.get("F11_RUNTIME_DIR", "/home/elcra/sgsi-zta-runtime/f11"))
DEFAULT_DEMO_DIR = RUNTIME / "demo"

if str(ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(ROOT / "backend"))

from database import ClinicalDatabaseManager
from asset_inventory import seed_catalog
from risk_management import seed_risk_catalog
from control_management import seed_control_catalog
from incident_management import seed_incidents
from validation_management import seed_validation_instrument


def prepare_demo_database(demo_dir: Path) -> Path:
    demo_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(demo_dir, 0o700)

    demo_db_path = demo_dir / "lis.db"
    demo_anchor_path = demo_dir / "lis.db.anchor-key"

    # Si ya existia una base demo previa, limpiarla para regenerar limpia
    for f in [demo_db_path, demo_anchor_path, demo_dir / "lis.db-wal", demo_dir / "lis.db-shm"]:
        if f.is_file():
            f.unlink()

    print(f"[*] Creando base de datos de demostracion en {demo_db_path}...")
    
    # ClinicalDatabaseManager aplica migraciones 1..9 al inicializarse
    db_mgr = ClinicalDatabaseManager(str(demo_db_path))

    # Siembra limpia de catalogos
    print("[*] Sembrando catalogo de activos (M3)...")
    res_assets = seed_catalog(db_mgr)
    print(f"    -> {len(res_assets.get('created', []))} activos creados.")

    print("[*] Sembrando matriz de riesgos 5x5 (M4)...")
    res_risks = seed_risk_catalog(db_mgr)
    print(f"    -> {len(res_risks.get('created', []))} riesgos creados.")

    print("[*] Sembrando catalogo de controles (M5)...")
    res_controls = seed_control_catalog(db_mgr)
    print(f"    -> {len(res_controls.get('created', []))} controles creados.")

    print("[*] Sembrando catalogo de incidentes iniciales (M6)...")
    res_incidents = seed_incidents(db_mgr)
    print(f"    -> {len(res_incidents.get('created', []))} incidentes creados.")

    print("[*] Sembrando instrumento de validacion INSTR-F11-ZTA-01 (M9)...")
    res_val = seed_validation_instrument(db_mgr)
    print(f"    -> Instrumento sembrado: {res_val.get('instrument_code', 'N/A')} ({res_val.get('action', 'OK')}).")

    last_hash = db_mgr.get_last_audit_hash()
    db_mgr.close()

    # Asegurar permisos restrictivos
    os.chmod(demo_db_path, 0o600)
    if demo_anchor_path.is_file():
        os.chmod(demo_anchor_path, 0o600)

    # Validar integridad
    con = sqlite3.connect(str(demo_db_path))
    cur = con.cursor()
    cur.execute("PRAGMA integrity_check;")
    check = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM audit_events;")
    events_count = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM expert_reviews;")
    reviews_count = cur.fetchone()[0]
    con.close()

    print(f"\n[+] Entorno de demostracion preparado con exito:")
    print(f"    Base de datos: {demo_db_path}")
    print(f"    PRAGMA integrity_check: {check}")
    print(f"    Eventos de auditoria iniciales: {events_count} (cadena encadenada: {last_hash[:16]}...)")
    print(f"    Dictamenes de expertos: {reviews_count} (rigurosamente cero dictamenes falsos)")
    return demo_db_path


def main():
    parser = argparse.ArgumentParser(description="Preparar base de datos para demostracion limpia (F6)")
    parser.add_argument("--demo-dir", type=str, default=None, help="Directorio para la base demo")
    args = parser.parse_args()

    target = Path(args.demo_dir) if args.demo_dir else DEFAULT_DEMO_DIR
    prepare_demo_database(target)


if __name__ == "__main__":
    main()