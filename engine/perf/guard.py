#!/usr/bin/env python3
"""Guardia de rendimiento por instrucciones ejecutadas, contra un ancla fija.

Cuenta las instrucciones (valgrind/cachegrind, sin simular caché) de cada programa de
`engine/perf/progs/` en los tres caminos del motor: el nivel nativo (`jit`), la VM sola (`vm`,
`--jitless`) y el tree-walker (`ref`, `--reference`, lo que corre con `--labels`). Las compara con
`engine/perf/baseline.json` y falla si alguna pasa el presupuesto.

Por qué instrucciones y no tiempo: son deterministas (no dependen de la carga de la máquina ni del
acomodo que deja PGO, que mueve filas ±3–5 % sin cambiar el trabajo), así que una suba chica que se
repite versión tras versión se acumula contra el ancla y se ve. El ancla NO es la versión anterior:
es el punto donde quedó optimizado el motor. Un costo aprobado se registra por fila en
`approved.json` con el total exacto de instrucciones aceptadas y su razón; no reescribe el ancla.

Cuando algo se pasa, imprime qué funciones crecieron (cachegrind cuenta por función).

    python3 engine/perf/guard.py --bin <run>                 # compara con el ancla
    python3 engine/perf/guard.py --bin <run> --only fib,loop # algunos programas
    python3 engine/perf/guard.py --bless-from perf.json      # sólo cambio de entorno de CI

Si cambia el entorno, el ancla se vuelve a medir con el artefacto `perf-guard` del CI,
en un PR que no cambie el motor; una medición local no sirve para ese propósito.

`<run>` es `cargo build --release -p synsema-jit --example run`. El ancla vale para un toolchain,
un runner y una versión de valgrind (están en `meta`): cambiar cualquiera de los tres es volver a
medir el ancla (en un PR que no toque el motor, para que la diferencia sea sólo del entorno).
"""
import argparse
import collections
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PROGS = os.path.join(HERE, "progs")
BASELINE = os.path.join(HERE, "baseline.json")
APPROVED = os.path.join(HERE, "approved.json")
MODES = {"jit": [], "vm": ["--jitless"], "ref": ["--reference"]}
# Funciones que se guardan por programa: las que pesan al menos esto del total.
FN_SHARE = 0.0005
FN_MAX = 80
HASH = re.compile(r"::h[0-9a-f]{16}$")


def parse_cachegrind(path):
    """Instrucciones por función de un `cachegrind.out` (con la compresión de nombres `(id)`)."""
    names = {}
    per_fn = collections.Counter()
    fn = "???"
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("fn="):
                m = re.match(r"fn=\((\d+)\)(?: (.*))?$", line.rstrip("\n"))
                if m:
                    if m.group(2) is not None:
                        names[m.group(1)] = m.group(2)
                    fn = names.get(m.group(1), "???")
                else:
                    fn = line[3:].rstrip("\n")
                fn = HASH.sub("", fn)
            elif line[:1].isdigit():
                parts = line.split()
                if len(parts) >= 2:
                    per_fn[fn] += int(parts[1])
    return per_fn


def measure_env():
    """El entorno de cada medición: fijo y mínimo, igual en toda corrida.

    El entorno va al principio de la pila del proceso, así que su largo corre la alineación de lo
    que el programa guarda ahí, y `memcmp` de glibc cuenta distinto según la alineación: con el
    mismo motor, `s_csv|ref` medía +450 000 instrucciones (todas en `__memcmp_avx2_movbe`) en una
    rama que se llama `main` frente a una que se llama `feat/v0650` (`GITHUB_REF`,
    `GITHUB_HEAD_REF`). Con el entorno del runner, la fila dependía del nombre de la rama."""
    # PATH fijo también: el del runner cambia con lo que agregan las acciones del job.
    return {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": "/tmp"}


def measure(binary, prog, mode):
    # v0.6.58 (B3 de la ronda 1): un programa también puede ser una carpeta `progs/<nombre>/` con su
    # `main.syn`, su `synsema.json` y el caché de sus paquetes (`cache/`, relativo a la raíz del
    # proyecto, así el entorno no lleva la ruta del checkout): un programa que usa paquetes.
    folder = os.path.join(PROGS, prog)
    env = measure_env()
    if os.path.isdir(folder):
        cwd, entry = folder, "main.syn"
        env["SYNSEMA_MODULE_CACHE"] = "cache"
    else:
        cwd, entry = PROGS, prog + ".syn"
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "cg.out")
        cmd = ["valgrind", "--tool=cachegrind", "--cache-sim=no", f"--cachegrind-out-file={out}",
               binary, *MODES[mode], entry]
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=env)
        if r.returncode != 0 or not os.path.exists(out):
            raise SystemExit(f"{prog} ({mode}) falló (código {r.returncode}):\n{r.stdout}\n{r.stderr}")
        # `run` escribe su tiempo (`[12.3 ms]`) por stderr; cualquier otra línea es un error.
        errors = [l for l in r.stderr.splitlines()
                  if not re.match(r"(==|--)\d+(==|--)", l) and not re.fullmatch(r"\[[\d.]+ ms\]", l)]
        if errors:
            raise SystemExit(f"{prog} ({mode}) escribió errores:\n" + "\n".join(errors))
        per_fn = parse_cachegrind(out)
    total = sum(per_fn.values())
    top = {k: v for k, v in per_fn.most_common(FN_MAX) if v >= total * FN_SHARE}
    return total, top, per_fn


def env_meta():
    def first_line(cmd):
        try:
            return subprocess.run(cmd, capture_output=True, text=True).stdout.strip().splitlines()[0]
        except Exception:
            return "?"
    return {
        "rustc": first_line(["rustc", "--version"]),
        "valgrind": first_line(["valgrind", "--version"]),
        "runner": os.environ.get("ImageOS", "") + " " + os.environ.get("ImageVersion", ""),
        "commit": first_line(["git", "rev-parse", "--short", "HEAD"]),
    }


def write_baseline(programs, meta, budget):
    doc = {
        "budget_pct": budget,
        "meta": meta,
        "note": "Ancla fija de engine/perf/guard.py. Sólo se remide por cambio del entorno de CI; costos aprobados van en approved.json.",
        "programs": programs,
    }
    with open(BASELINE, "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, indent=1, sort_keys=True)
        f.write("\n")
    print(f"ancla de entorno escrita: {BASELINE} ({len(programs)} mediciones)")


def fmt(n):
    return f"{n:,}".replace(",", " ")


def limit_for(key, anchor_total, budget, approved):
    exception = approved.get(key)
    if exception is None:
        return anchor_total * (1 + budget / 100), budget
    if not isinstance(exception, dict) or type(exception.get("accepted_total")) is not int \
            or not isinstance(exception.get("reason"), str) or not exception["reason"].strip() \
            or exception["accepted_total"] <= anchor_total * (1 + budget / 100):
        raise SystemExit(f"aprobación inválida para {key}: requiere accepted_total sobre el presupuesto y reason")
    return exception["accepted_total"], 100 * (exception["accepted_total"] - anchor_total) / anchor_total


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin")
    ap.add_argument("--bless-from", help="remide el ancla sólo por cambio de entorno de CI, desde un JSON de --out")
    ap.add_argument("--only", default="")
    ap.add_argument("--budget", type=float, default=None, help="por ciento sobre el ancla (por defecto, el del ancla)")
    ap.add_argument("--out", help="escribe las mediciones en este JSON (artefacto del CI)")
    a = ap.parse_args()
    if a.bless_from:
        with open(a.bless_from, encoding="utf-8") as f:
            measured = json.load(f)
        with open(BASELINE, encoding="utf-8") as f:
            old = json.load(f)
        fields = ("rustc", "valgrind", "runner")
        if all(measured["meta"].get(field) == old["meta"].get(field) for field in fields):
            raise SystemExit("el entorno de CI no cambió; conservar el ancla fija y registrar costos en approved.json")
        write_baseline(measured["programs"], measured["meta"], a.budget if a.budget is not None else 0.3)
        return 0
    if not a.bin:
        ap.error("--bin es obligatorio (salvo con --bless-from)")
    binary = os.path.abspath(a.bin)
    progs = sorted(
        [f[:-4] for f in os.listdir(PROGS) if f.endswith(".syn")]
        + [d for d in os.listdir(PROGS) if os.path.isfile(os.path.join(PROGS, d, "main.syn"))]
    )
    if a.only:
        wanted = set(a.only.split(","))
        progs = [p for p in progs if p in wanted]
    base = None
    if os.path.exists(BASELINE):
        with open(BASELINE, encoding="utf-8") as f:
            base = json.load(f)
    budget = a.budget if a.budget is not None else (base or {}).get("budget_pct", 0.3)
    with open(APPROVED, encoding="utf-8") as f:
        approved = json.load(f)
    if not isinstance(approved, dict):
        raise SystemExit("approved.json debe ser un objeto de filas")
    unknown = set(approved) - set((base or {}).get("programs", {}))
    if unknown:
        raise SystemExit(f"aprobaciones sin fila en el ancla: {', '.join(sorted(unknown))}")

    results = {}
    over, missing = [], []
    print(f"{'programa':<18}{'modo':<5}{'ancla fija':>16}{'hoy':>16}{'acumulado':>12}{'límite':>10}")
    for p in progs:
        for mode in MODES:
            key = f"{p}|{mode}"
            total, top, per_fn = measure(binary, p, mode)
            results[key] = {"total": total, "fns": top}
            b = (base or {}).get("programs", {}).get(key)
            if b is None:
                missing.append(key)
                print(f"{p:<18}{mode:<5}{'—':>16}{fmt(total):>16}{'nuevo':>12}{'—':>10}")
                continue
            pct = 100.0 * (total - b["total"]) / b["total"]
            limit_total, limit_pct = limit_for(key, b["total"], budget, approved)
            mark = "  <-- pasa el límite acumulado" if total > limit_total else ""
            print(f"{p:<18}{mode:<5}{fmt(b['total']):>16}{fmt(total):>16}{pct:>+11.3f}%{limit_pct:>+9.3f}%{mark}")
            if total > limit_total:
                over.append((key, pct, b, per_fn))

    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump({"meta": env_meta(), "programs": results}, f, indent=1, sort_keys=True)

    for key, pct, b, per_fn in over:
        print(f"\n== {key}: {pct:+.3f}% sobre el ancla ({fmt(b['total'])} -> {fmt(sum(per_fn.values()))})")
        print("   funciones que más crecieron (instrucciones, hoy - ancla):")
        # El ancla guarda sólo las funciones que pesaban al menos FN_SHARE del total: una que no
        # está pesaba menos que eso, así que su crecimiento es "al menos" lo de hoy menos ese umbral.
        floor = b["total"] * FN_SHARE
        deltas = []
        for n in set(b["fns"]) | set(k for k, _ in per_fn.most_common(FN_MAX)):
            if n in b["fns"]:
                deltas.append((per_fn.get(n, 0) - b["fns"][n], n, ""))
            elif per_fn.get(n, 0) > floor:
                deltas.append((per_fn[n] - floor, n, "  (al menos; en el ancla pesaba menos del umbral)"))
        deltas.sort(reverse=True)
        for d, n, note in deltas[:12]:
            if d <= 0:
                break
            print(f"   {d:>+14,}  {n}{note}".replace(",", " "))
    if missing and base is not None:
        print(f"\nsin ancla (programas o modos nuevos): {', '.join(missing)}; medir en CI y agregar sólo esas filas al ancla")
    if base is None:
        print("\nno hay ancla fija todavía; medir en CI antes de incorporarla")
        return 1
    if over:
        print(f"\n{len(over)} medición(es) pasan su límite acumulado desde el ancla fija.")
        print("Si el costo es deliberado: registrar el total exacto del CI como accepted_total y reason por fila en approved.json, antes de la release; no reescribir el ancla.")
        return 1
    if missing:
        return 1
    print(f"\nok: ninguna fila pasa su límite acumulado desde el ancla fija ({base['meta'].get('commit', '?')}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
