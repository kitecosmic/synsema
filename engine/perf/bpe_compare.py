#!/usr/bin/env python3
"""Compare the external Synsema BPE library with the same algorithm in Python.

Example: python engine/perf/bpe_compare.py --bin engine/target/release/synsema.exe \
    --library C:/path/to/tokenizador --corpus CHANGELOG.md
Only the first 100,000 Unicode characters are used. Requires the `regex` Python package.
"""

import argparse
from collections import Counter
import json
from pathlib import Path
from statistics import median
import subprocess
import tempfile
from time import perf_counter

import regex

PATTERN = r" ?\p{L}+| ?\p{N}+| ?[^\s\p{L}\p{N}]+|\s+"


def python_bpe(text: str, vocab: int) -> tuple[list[list[int]], dict[str, float]]:
    start = perf_counter()
    words = [(list(piece.encode()), n) for piece, n in Counter(regex.findall(PATTERN, text)).items()]
    prep = perf_counter() - start
    count_time = fuse_time = 0.0
    merges = []
    for new in range(256, vocab):
        start = perf_counter()
        counts: dict[int, int] = {}
        for ids, n in words:
            for a, b in zip(ids, ids[1:]):
                key = a * vocab + b
                counts[key] = counts.get(key, 0) + n
        best, best_n = None, 1
        for key, n in counts.items():
            if n > best_n:
                best, best_n = key, n
        count_time += perf_counter() - start
        if best is None:
            break
        a, b = divmod(best, vocab)
        merges.append([a, b])
        start = perf_counter()
        following = []
        for ids, n in words:
            out = []
            i = 0
            while i < len(ids):
                if i + 1 < len(ids) and ids[i] == a and ids[i + 1] == b:
                    out.append(new)
                    i += 2
                else:
                    out.append(ids[i])
                    i += 1
            following.append((out, n))
        words = following
        fuse_time += perf_counter() - start
    return merges, {"prep": prep, "count_and_select": count_time, "fuse": fuse_time}


def synsema_bpe(binary: Path, library: Path, text: str, vocab: int, jitless: bool) -> tuple[list[list[int]], float]:
    source = f'use "./tokenizador.syn" as tok\nlet m be tok.entrenar({json.dumps(text, ensure_ascii=False)}, {vocab})\nprint(json_encode(m.fusiones))\n'
    with tempfile.NamedTemporaryFile("w", suffix=".syn", prefix="bpe_compare_", dir=library, encoding="utf-8", delete=False) as f:
        f.write(source)
        path = Path(f.name)
    try:
        args = [str(binary), "run"]
        if jitless:
            args.append("--jitless")
        start = perf_counter()
        result = subprocess.run(args + [str(path)], cwd=library, text=True, capture_output=True)
        elapsed = perf_counter() - start
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip())
        return json.loads(result.stdout.strip()), elapsed
    finally:
        path.unlink()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bin", type=Path, required=True)
    ap.add_argument("--library", type=Path, required=True)
    ap.add_argument("--corpus", type=Path, required=True)
    ap.add_argument("--chars", type=int, default=100_000)
    ap.add_argument("--vocab", type=int, default=512)
    ap.add_argument("--repeat", type=int, default=1, help="report the median of independent runs")
    args = ap.parse_args()
    if args.repeat < 1:
        ap.error("--repeat must be positive")
    text = args.corpus.read_text(encoding="utf-8")[:args.chars]
    measurements = []
    for _ in range(args.repeat):
        expected, phases = python_bpe(text, args.vocab)
        native, native_s = synsema_bpe(args.bin.resolve(), args.library.resolve(), text, args.vocab, False)
        vm, vm_s = synsema_bpe(args.bin.resolve(), args.library.resolve(), text, args.vocab, True)
        if native != expected or vm != expected:
            raise AssertionError(f"merges differ: Python={len(expected)} Synsema={len(native)} VM={len(vm)}")
        measurements.append((phases, native_s, vm_s))
    phases = {k: median(row[0][k] for row in measurements) for k in phases}
    native_s = median(row[1] for row in measurements)
    vm_s = median(row[2] for row in measurements)
    print(json.dumps({"chars": len(text), "merges": len(expected), "equivalent": True,
                      "repeat": args.repeat,
                      "python_s": round(sum(phases.values()), 3),
                      "python_phases_s": {k: round(v, 3) for k, v in phases.items()},
                      "synsema_s": round(native_s, 3), "jitless_s": round(vm_s, 3)}))


if __name__ == "__main__":
    main()
