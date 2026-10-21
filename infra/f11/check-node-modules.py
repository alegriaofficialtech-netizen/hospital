#!/usr/bin/env python3
"""Compatibility check for reusing the host's node_modules in Stage A.

Read-only. It answers one question: is the dependency tree already on the
host exactly the tree that `npm ci` would produce, and is it usable by the
build container? If any of that is not true, Stage A must fall back to the
original method.

Checks:
  1. the tree exists and is not empty
  2. every package in package-lock.json is present with the locked version
  3. the platform specific binaries match the build platform (no win32/darwin)
  4. the Node version of the build image satisfies the Angular CLI engines

Usage:
  check-node-modules.py [--frontend DIR] [--node-version X.Y.Z] [--platform TAG]

Exit codes: 0 compatible, 1 incompatible, 2 usage error.
"""

import argparse
import json
import pathlib
import platform
import re
import sys

# The build container runs node:<version>-bookworm-slim on the same
# architecture as the host, so the native packages must be the linux ones.
PLATFORM_PACKAGES = {
    "linux-x64": ["@esbuild/linux-x64", "@parcel/watcher-linux-x64-glibc"],
    "linux-arm64": ["@esbuild/linux-arm64", "@parcel/watcher-linux-arm64-glibc"],
}
FOREIGN_MARKERS = ("win32", "darwin", "freebsd")


def fail(msg):
    print("  FALLO: %s" % msg)
    return 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--frontend", default="/home/elcra/sgsi-zta-integration/frontend")
    ap.add_argument("--node-version", default="", help="node version inside the build image")
    ap.add_argument("--platform", default="", help="platform tag, e.g. linux-x64")
    args = ap.parse_args()

    frontend = pathlib.Path(args.frontend)
    node_modules = frontend / "node_modules"
    lock_path = frontend / "package-lock.json"

    problems = 0
    print("== 1. el arbol de dependencias ==")
    if not lock_path.is_file():
        print("  FALLO: falta %s" % lock_path)
        return 1
    if not node_modules.is_dir() or not any(node_modules.iterdir()):
        print("  FALLO: %s no existe o esta vacio" % node_modules)
        return 1
    print("  %s presente (%d entradas)" % (node_modules, len(list(node_modules.iterdir()))))

    print("== 2. cobertura y versiones frente al lock ==")
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    packages = lock.get("packages", {})
    checked = missing = mismatched = foreign_optional = 0
    for key, meta in packages.items():
        if not key or meta.get("link"):
            continue
        version = meta.get("version")
        if version is None:
            continue
        # npm never installs an optional dependency whose os/cpu constraints
        # do not match the platform. Those entries are legitimately absent and
        # must not be treated as a broken tree.
        if meta.get("optional") and (meta.get("os") or meta.get("cpu")):
            if (frontend / key).is_dir():
                checked += 1
            else:
                foreign_optional += 1
            continue
        pj = frontend / key / "package.json"
        if not pj.is_file():
            missing += 1
            if missing <= 5:
                print("  FALLO: ausente %s" % key)
            continue
        try:
            got = json.loads(pj.read_text(encoding="utf-8")).get("version")
        except (OSError, ValueError):
            got = None
        if got != version:
            mismatched += 1
            if mismatched <= 5:
                print("  FALLO: %s instalado %s, lock %s" % (key, got, version))
        checked += 1
    print("  paquetes verificados: %d | ausentes: %d | version distinta: %d" % (checked, missing, mismatched))
    print("  opcionales de otra plataforma omitidas por npm: %d (ausencia correcta)" % foreign_optional)
    if missing or mismatched:
        problems += fail("el arbol no coincide con el lock: npm ci es obligatorio")

    print("== 3. binarios nativos de la plataforma ==")
    tag = args.platform or ("linux-x64" if platform.machine() in ("x86_64", "amd64") else "linux-arm64")
    print("  plataforma de compilacion: %s" % tag)
    for pkg in PLATFORM_PACKAGES.get(tag, []):
        if (node_modules / pkg).is_dir():
            print("  OK   %s" % pkg)
        else:
            problems += fail("falta el binario nativo %s para %s" % (pkg, tag))
    foreign = []
    for p in node_modules.glob("@*/*"):
        if p.is_dir() and any(m in p.name for m in FOREIGN_MARKERS):
            foreign.append(p.name)
    if foreign:
        print("  aviso: paquetes de otra plataforma presentes: %s" % ", ".join(sorted(foreign)[:6]))
    else:
        print("  OK   sin binarios win32/darwin")

    print("== 4. version de Node de la imagen de compilacion ==")
    if not args.node_version:
        print("  (no informada; se omite esta comprobacion)")
    else:
        cli = node_modules / "@angular/cli" / "package.json"
        if not cli.is_file():
            problems += fail("no se encuentra @angular/cli en el arbol")
        else:
            engines = json.loads(cli.read_text(encoding="utf-8")).get("engines", {})
            node_req = engines.get("node", "")
            print("  node de la imagen: %s | engines del CLI: %s" % (args.node_version, node_req))
            m = re.match(r"\^(\d+)\.(\d+)\.(\d+)", node_req)
            if m:
                want = tuple(int(x) for x in m.groups())
                got = tuple(int(x) for x in args.node_version.split(".")[:3])
                if got < want:
                    problems += fail("node %s no cumple %s" % (args.node_version, node_req))
                else:
                    print("  OK   node %s cumple %s" % (args.node_version, node_req))
            elif node_req and node_req not in args.node_version:
                problems += fail("node %s no cumple %s" % (args.node_version, node_req))

    print()
    if problems:
        print("RESULTADO: INCOMPATIBLE (%d problema(s)) -> usar el metodo original con npm ci" % problems)
        return 1
    print("RESULTADO: COMPATIBLE -> se puede reutilizar el arbol en solo lectura")
    return 0


if __name__ == "__main__":
    sys.exit(main())
