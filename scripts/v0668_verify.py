#!/usr/bin/env python3
"""Corre gemelos .syn seleccionados y suites Rust por crate, con salida breve.

La salida completa se guarda en un directorio temporal para investigar fallos.
Cada archivo .test.syn se invoca por separado: `test tests/` incluye probes.
"""
import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SYN = ROOT / "engine/target/debug/synsema.exe"


def run(label, command, cwd, logs):
    result = subprocess.run(command, cwd=cwd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, errors="replace")
    log = logs / (re.sub(r"[^a-zA-Z0-9_.-]", "_", label) + ".log")
    log.write_text(result.stdout, encoding="utf-8")
    summaries = [line.strip() for line in result.stdout.splitlines()
                 if "test result:" in line or re.search(r"\b\d+ passed\b", line)]
    print(f"{'OK' if result.returncode == 0 else 'FAIL'} {label} "
          f"{summaries[-1] if summaries else '(sin resumen)'}")
    if result.returncode:
        print(f"  log: {log}")
        print("  últimas líneas: " + " | ".join(result.stdout.splitlines()[-8:]))
    return result.returncode == 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("syn", nargs="*", help="rutas a archivos .test.syn")
    parser.add_argument("--glob", action="append", default=[],
                        help="patrón de archivos .test.syn dentro de tests/; repetible")
    parser.add_argument("--rust", choices=["core", "runtime"], action="append", default=[],
                        help="corre la suite it completa del crate; repetible")
    parser.add_argument("--labels", action="store_true",
                        help="ejecuta los gemelos con el mismo modo --labels que usa CI")
    args = parser.parse_args()
    paths = {Path(p).resolve() for p in args.syn}
    for pattern in args.glob:
        paths.update((ROOT / "tests").glob(pattern))
    if not paths and not args.rust:
        parser.error("indica archivos, --glob o --rust")
    for path in paths:
        if not path.is_file() or not path.name.endswith(".test.syn"):
            parser.error(f"archivo .test.syn inexistente: {path}")
    if paths and not SYN.is_file():
        parser.error(f"falta binario: {SYN}; compila con cargo build -p synsema-runtime --bin synsema")
    logs = Path(tempfile.mkdtemp(prefix="v0668-verify-"))
    print(f"logs: {logs}")
    results = []
    for path in sorted(paths):
        command = [str(SYN), "test"]
        if args.labels:
            command.append("--labels")
        command.append(str(path))
        results.append(run(path.name, command, ROOT, logs))
    for crate in dict.fromkeys(args.rust):
        results.append(run(f"rust-{crate}", ["cargo", "test", "-p", f"synsema-{crate}",
                                             "--test", "it", "-j", "2"], ROOT / "engine", logs))
    print(f"resultado: {sum(results)}/{len(results)} comandos verdes")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
