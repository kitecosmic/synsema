#!/usr/bin/env python3
"""Detecta nombres de tests que siguen duplicados en Rust y .syn."""
from pathlib import Path
import re
import sys

root = Path(__file__).resolve().parents[1]
found = []
for syn in sorted((root / "tests").glob("*.test.syn")):
    module = syn.name.removesuffix(".test.syn")
    rusts = list((root / "engine/crates").glob(f"*/tests/**/{module}.rs"))
    if not rusts:
        continue
    names = set(re.findall(r'^test "([^"]+)"', syn.read_text(encoding="utf-8"), re.M))
    for rust in rusts:
        remaining = set(re.findall(r'^#\[test\]\r?\nfn (\w+)\(',
                                   rust.read_text(encoding="utf-8"), re.M))
        overlap = names & remaining
        if overlap:
            found.append((module, rust, sorted(overlap)))
for module, rust, names in found:
    print(f"{module}: {len(names)} duplicados en {rust.relative_to(root)}: {', '.join(names)}")
print(f"módulos con duplicados: {len(found)}")
sys.exit(bool(found))
