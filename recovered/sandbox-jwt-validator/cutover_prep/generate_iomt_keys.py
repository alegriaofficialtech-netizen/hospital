#!/usr/bin/env python3
"""
generate_iomt_keys.py - Genera claves por dispositivo para el canal IoMT.

Formato exigido por server.py: objeto JSON {device-id: secreto}, con secretos
de al menos 16 caracteres. Escribe el archivo en modo 0600 y nunca imprime los
secretos: solo los identificadores y una huella del contenido.

Uso:
  python3 cutover_prep/generate_iomt_keys.py \
    --devices pc-admision,laptop-medico,servidor-his \
    --out /home/elcra/sgsi-backups/secrets/iomt-device-keys.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sys
import tempfile


def main() -> int:
    parser = argparse.ArgumentParser(description="Genera claves IoMT (JSON, 0600)")
    parser.add_argument(
        "--devices",
        default="pc-admision,laptop-medico,servidor-his",
        help="Identificadores separados por coma",
    )
    parser.add_argument("--bytes", type=int, default=32, help="Entropía por secreto")
    parser.add_argument("--out", required=True, help="Ruta de salida (0600)")
    parser.add_argument("--force", action="store_true", help="Sobrescribe si existe")
    args = parser.parse_args()

    devices = [item.strip() for item in args.devices.split(",") if item.strip()]
    if not devices:
        raise SystemExit("sin dispositivos")
    if args.bytes < 16:
        raise SystemExit("--bytes debe ser >= 16")

    if os.path.exists(args.out) and not args.force:
        raise SystemExit(f"{args.out} ya existe; use --force para rotar")

    payload = {device: secrets.token_hex(args.bytes) for device in devices}
    blob = json.dumps(payload, indent=2, sort_keys=True) + "\n"

    directory = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(directory, mode=0o700, exist_ok=True)
    descriptor, tmp_path = tempfile.mkstemp(dir=directory, prefix=".iomt-", text=True)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(blob)
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, args.out)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

    fingerprint = hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]
    print(f"dispositivos: {', '.join(devices)}")
    print(f"archivo: {args.out} (0600)")
    print(f"huella: {fingerprint}")
    print(f"bytes por secreto: {args.bytes * 2} hex")
    return 0


if __name__ == "__main__":
    sys.exit(main())
