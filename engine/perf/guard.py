#!/usr/bin/env python3
"""Guardia de rendimiento por instrucciones ejecutadas, contra un ancla fija.

Cuenta las instrucciones (valgrind/cachegrind, sin simular caché) de cada programa de
`engine/perf/progs/` en los tres caminos del motor: el nivel nativo (`jit`), la VM sola (`vm`,
`--jitless`) y el tree-walker (`ref`, `--reference`, lo que corre con `--labels`). Las compara con
`engine/perf/baseline.json` y falla si alguna pasa el presupuesto.

Por qué instrucciones y no tiempo: son deterministas (no dependen de la carga de la máquina ni del
acomodo que deja PGO, que mueve filas ±3–5 % sin cambiar el trabajo), así que una suba chica que se
repite versión tras versión se acumula contra el ancla y se ve. El ancla NO es la versión anterior:
es el punto donde quedó optimizado el motor, y sólo se mueve a propósito (`--bless`) en el mismo PR
que trae el costo, con la razón en el CHANGELOG.

Cuando algo se pasa, imprime qué funciones crecieron (cachegrind cuenta por función).

    python3 engine/perf/guard.py --bin <run>                 # compara con el ancla
    python3 engine/perf/guard.py --bin <run> --bless         # reescribe el ancla
    python3 engine/perf/guard.py --bin <run> --only fib,loop # algunos programas
    python3 engine/perf/guard.py --bless-from perf.json      # el ancla con lo que midió el CI

El ancla se escribe con lo que mide el CI (el artefacto `perf-guard` del job), no con una medición
local: el enlazador y la libc de otra máquina cambian los números.

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
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "cg.out")
        cmd = ["valgrind", "--tool=cachegrind", "--cache-sim=no", f"--cachegrind-out-file={out}",
               binary, *MODES[mode], prog + ".syn"]
        r = subprocess.run(cmd, cwd=PROGS, capture_output=True, text=True, env=measure_env())
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
        "note": "Ancla de engine/perf/guard.py. Se reescribe sólo a propósito (--bless), con la razón en el CHANGELOG.",
        "programs": programs,
    }
    with open(BASELINE, "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, indent=1, sort_keys=True)
        f.write("\n")
    print(f"ancla escrita: {BASELINE} ({len(programs)} mediciones)")


def fmt(n):
    return f"{n:,}".replace(",", " ")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin")
    ap.add_argument("--bless-from", help="escribe el ancla con un JSON de --out (el artefacto del CI)")
    ap.add_argument("--bless", action="store_true")
    ap.add_argument("--only", default="")
    ap.add_argument("--budget", type=float, default=None, help="por ciento sobre el ancla (por defecto, el del ancla)")
    ap.add_argument("--out", help="escribe las mediciones en este JSON (artefacto del CI)")
    a = ap.parse_args()
    if a.bless_from:
        with open(a.bless_from, encoding="utf-8") as f:
            measured = json.load(f)
        write_baseline(measured["programs"], measured["meta"], a.budget if a.budget is not None else 0.2)
        return 0
    if not a.bin:
        ap.error("--bin es obligatorio (salvo con --bless-from)")
    binary = os.path.abspath(a.bin)
    progs = sorted(f[:-4] for f in os.listdir(PROGS) if f.endswith(".syn"))
    if a.only:
        wanted = set(a.only.split(","))
        progs = [p for p in progs if p in wanted]
    base = None
    if os.path.exists(BASELINE):
        with open(BASELINE, encoding="utf-8") as f:
            base = json.load(f)
    budget = a.budget if a.budget is not None else (base or {}).get("budget_pct", 0.2)

    results = {}
    over, missing = [], []
    print(f"{'programa':<18}{'modo':<5}{'ancla':>16}{'hoy':>16}{'cambio':>10}")
    for p in progs:
        for mode in MODES:
            key = f"{p}|{mode}"
            total, top, per_fn = measure(binary, p, mode)
            results[key] = {"total": total, "fns": top}
            b = (base or {}).get("programs", {}).get(key)
            if b is None:
                missing.append(key)
                print(f"{p:<18}{mode:<5}{'—':>16}{fmt(total):>16}{'nuevo':>10}")
                continue
            pct = 100.0 * (total - b["total"]) / b["total"]
            mark = "  <-- pasa el presupuesto" if pct > budget else ""
            print(f"{p:<18}{mode:<5}{fmt(b['total']):>16}{fmt(total):>16}{pct:>+9.3f}%{mark}")
            if pct > budget:
                over.append((key, pct, b, per_fn))

    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump({"meta": env_meta(), "programs": results}, f, indent=1, sort_keys=True)

    if a.bless:
        write_baseline(results, env_meta(), budget)
        return 0

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
        print(f"\nsin ancla (programas o modos nuevos): {', '.join(missing)}; correr con --bless para sumarlos")
    if base is None:
        print("\nno hay ancla todavía: correr con --bless")
        return 1
    if over:
        print(f"\n{len(over)} medición(es) pasan el presupuesto de +{budget}% sobre el ancla.")
        print("Si el costo es a propósito: --bless en el mismo PR y la razón en el CHANGELOG.")
        return 1
    print(f"\nok: nada pasa +{budget}% sobre el ancla ({base['meta'].get('commit', '?')}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
