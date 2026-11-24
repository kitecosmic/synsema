#!/usr/bin/env python3
"""Cruza tests Rust de v0.6.67 con el árbol actual y gemelos .test.syn.

No decide equivalencia semántica. Produce una lista breve de casos que requieren
inspección y un TSV completo en el directorio temporal.
"""
import csv
import re
import subprocess
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = "v0.6.67"
ATTR = re.compile(
    r"(?m)^(?P<indent>[ \t]*)#\[test\][ \t]*\r?\n"
    r"(?:[ \t]*(?:#\[[^\r\n]*\]|//[^\r\n]*)[ \t]*\r?\n)*"
    r"[ \t]*(?:pub(?:\([^\r\n]*\))?\s+)?(?:async\s+)?fn\s+(?P<name>\w+)\s*\("
)
SYN_TEST = re.compile(r'(?m)^test "([^"]+)"')


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT).decode("utf-8", "replace")


def rust_files(revision=None):
    command = ("ls-tree", "-r", "--name-only", revision, "engine/crates") if revision else (
        "ls-files", "engine/crates")
    return [p for p in git(*command).splitlines() if re.search(r"/tests/.*\.rs$", p)]


def tests_in(source, path):
    crate = path.split("/")[2]
    module = Path(path).stem
    result = {}
    occurrences = Counter()
    for match in ATTR.finditer(source):
        name = match.group("name")
        occurrences[name] += 1
        indent = match.group("indent")
        close = re.search(r"(?m)^" + re.escape(indent) + r"}[ \t]*$", source[match.end():])
        body = source[match.start():match.end() + close.end()] if close else source[match.start():]
        key = (crate, module, name, occurrences[name])
        result[key] = (path, body)
    return result


def all_rust(revision=None):
    found = {}
    collisions = []
    parse_gaps = []
    for path in rust_files(revision):
        source = git("show", f"{revision}:{path}") if revision else (ROOT / path).read_text(
            encoding="utf-8", errors="replace")
        raw_attrs = len(re.findall(r"(?m)^[ \t]*#\[test\]", source))
        parsed_attrs = len(list(ATTR.finditer(source)))
        if raw_attrs != parsed_attrs:
            parse_gaps.append((path, raw_attrs, parsed_attrs))
        for key, value in tests_in(source, path).items():
            if key in found:
                collisions.append((key, found[key][0], path))
            found[key] = value
    return found, collisions, parse_gaps


def all_syn():
    found = defaultdict(list)
    for path in sorted((ROOT / "tests").glob("*.test.syn")):
        source = path.read_text(encoding="utf-8", errors="replace")
        for match in SYN_TEST.finditer(source):
            found[match.group(1)].append(path.relative_to(ROOT).as_posix())
    return found


def risk_signals(body, syn_paths):
    flags = []
    checks = [
        (r"run_source_secure|run_source_ceiled|run_source_labels", "techo especial"),
        (r"\.output\b|\.errors\b|RunResult", "salida/errores del host"),
        (r"std::fs|\bfs::|temp_dir|unique_tmp", "archivos del host"),
        (r"std::env|env::set_var|env::remove_var", "entorno del proceso"),
        (r"TcpListener|TcpStream|thread::|Instant::", "sockets/hilos/reloj"),
        (r"\.steps\b|alloc_counts|touched_private|\.diagnostic", "internos del motor"),
        (r"\bfor\s+[^\n]*\bin\b|\bwhile\s+", "bucle de casos en Rust"),
        (r"\bformat!\s*\(|\bprogram\s*\(|\brun_tests\s*\(", "fuente construido en Rust"),
    ]
    for pattern, reason in checks:
        if re.search(pattern, body):
            flags.append(reason)
    if re.search(r"assert_eq!\s*\([\s\S]{0,100}?\.errors\b", body):
        flags.append("error exacto del host")
    if not syn_paths:
        flags.append("sin gemelo por nombre")
    return "; ".join(dict.fromkeys(flags)) or "-"


def main():
    before, old_collisions, old_gaps = all_rust(BASE)
    after, new_collisions, new_gaps = all_rust()
    syn = all_syn()
    rows = []
    wrong_module = []
    for key, (path, body) in sorted(before.items()):
        crate, module, name, occurrence = key
        state = "RUST" if key in after else "SYN" if name in syn else "MISSING"
        twins = syn.get(name, []) if state != "RUST" else []
        if state == "SYN" and not any(Path(p).name.startswith(module + ".test.syn") or
                                       Path(p).name.startswith(module + "_") for p in twins):
            wrong_module.append(key)
        rows.append(dict(crate=crate, module=module, test=name, occurrence=occurrence, before=path,
                         after=after[key][0] if key in after else "-", state=state,
                         syn=",".join(twins) or "-",
                         risk=risk_signals(body, twins) if state != "RUST" else "-"))
    out = Path(tempfile.gettempdir()) / "v0668-coverage-audit.tsv"
    with out.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=rows[0].keys(), delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    counts = Counter(row["state"] for row in rows)
    risks = Counter(row["risk"] for row in rows if row["state"] == "SYN" and row["risk"] != "-")
    print(f"base={len(before)} actual={len(after)} SYN={counts['SYN']} "
          f"RUST={counts['RUST']} MISSING={counts['MISSING']}")
    print(f"colisiones de clave Rust: antes={len(old_collisions)} ahora={len(new_collisions)}; "
          f"migrados con señales para revisar={sum(risks.values())}")
    print(f"atributos sin parsear: antes={len(old_gaps)} ahora={len(new_gaps)}; "
          f"gemelos en otro módulo={len(wrong_module)}")
    print(f"nombres repetidos en módulos cfg: antes={sum(k[3] > 1 for k in before)} "
          f"ahora={sum(k[3] > 1 for k in after)}")
    for row in rows:
        if row["state"] == "MISSING":
            print(f"MISSING {row['crate']}/{row['module']}::{row['test']}")
    print(f"informe={out}")
    return 1 if counts["MISSING"] or old_collisions or new_collisions or old_gaps or new_gaps or wrong_module else 0


if __name__ == "__main__":
    raise SystemExit(main())
