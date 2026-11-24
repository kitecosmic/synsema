#!/usr/bin/env python3
"""Inventario mecánico de candidatos Rust para v0.6.68.

La clasificación es una pista para el repaso humano, nunca una orden de borrar tests.
Actualiza el TSV versionado y conserva las decisiones escritas allí.
"""
import csv, os, re, io

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS_ROOT = os.path.join(ROOT, "engine", "crates")
LEDGER = os.path.join(ROOT, "scripts", "v0668_candidates.tsv")

# marcadores que implican QUEDA (miran por dentro del host o necesitan entorno del host)
QUEDA_PATTERNS = [
    (r"set_reference_mode|set_request_mode|set_trusted\(|set_profile\(|set_program_args|set_labels\(|set_labels_detail|set_serve_log_sink|set_pc_private|set_redaction_text|set_eager|native_tier|install_infer_knobs", "muta estado global del proceso (host)"),
    (r"\.steps\b|steps_exact|steps\(\)", "afirma steps exactos (contrato del oráculo)"),
    (r"touched_private", "usa touched_private del host"),
    (r"\.diagnostic|run_source_diagnostic|explain.*json", "usa diagnostic estructurado del host"),
    (r"alloc_counts|AllocCounter|type_sizes", "allocator/size-of del host"),
    (r"\baudit\b|audit_stream|AuditLine", "lee el stream de auditoría desde el host"),
    (r"receipt|sealed|auditor_key", "recibos sellados vistos desde el host"),
    (r"env::(var|set_var|remove_var)|var_os|SYNSEMA_[A-Z_]+", "depende de variables de entorno"),
    (r"std::process::Command|Command::new", "ejecuta procesos (CLI/binarios)"),
    (r"TcpListener|TcpStream|std::net|serve::|start_serve|spawn_serve", "levanta serve/sockets reales"),
    (r"thread::spawn|thread::sleep", "hilos/tiempos del host"),
    (r"proptest|quickcheck|fuzz", "fuzz/property"),
    (r"\.exit_code|exit_code", "afirma exit_code del host"),
    (r"Instant::now|Duration::from", "mide tiempos reales"),
    (r"wasmtime|wasm", "wasm del host"),
    (r"perf_", "perf del host"),
]

RUN_SRC = re.compile(r"(?:run_source(?:_ceiled|_secure|_diagnostic|_labels|_with)?|run_program)\s*\(")

def strip_strings_and_comments(src):
    """Quita el contenido de strings y comentarios pero conserva la estructura de llaves."""
    out = []
    i, n = 0, len(src)
    mode = None  # None | 'line' | 'block' | 'str' | 'raw'
    raw_hashes = 0
    while i < n:
        c = src[i]
        if mode is None:
            if src.startswith("//", i):
                mode = "line"; i += 2; continue
            if src.startswith("/*", i):
                mode = "block"; i += 2; continue
            if src.startswith('r#"', i):
                raw_hashes = src[i:i+4].count("#"); mode = "raw"; i += 3; continue
            if src.startswith('r"', i):
                mode = "str"; i += 2; continue
            if c == '"':
                mode = "str"; i += 1; continue
            if c == "'":
                # char literal simple o lifetime: tratar como char si cierra
                if i + 2 < n and src[i+2] == "'":
                    i += 3; continue
                i += 1; continue
            out.append(c); i += 1; continue
        if mode == "line":
            if c == "\n":
                mode = None; out.append("\n")
            i += 1; continue
        if mode == "block":
            if src.startswith("*/", i):
                mode = None; i += 2; continue
            if c == "\n": out.append("\n")
            i += 1; continue
        if mode == "str":
            if c == "\\":
                i += 2; continue
            if c == '"':
                mode = None
            i += 1; continue
        if mode == "raw":
            # el cierre es `"` seguido de los mismos # del inicio: `"..."#`
            if c == '"' and src[i + 1:i + 1 + raw_hashes] == "#" * raw_hashes:
                mode = None
                i += 1 + raw_hashes
                continue
            if c == "\n": out.append("\n")
            i += 1; continue
    return "".join(out)

def extract_fns(clean):
    """Devuelve [(name, header_idx, body_clean, attrs)] para fn de nivel superior."""
    fns = []
    for m in re.finditer(r"(?m)^(@\[[^\]]*\]\s*)*fn\s+(\w+)", clean):
        # braced body
        b = clean.find("{", m.end())
        if b == -1: continue
        depth, i = 0, b
        while i < len(clean):
            if clean[i] == "{": depth += 1
            elif clean[i] == "}":
                depth -= 1
                if depth == 0: break
            i += 1
        body = clean[b:i+1]
        # atributos en las líneas previas
        start = m.start()
        # buscar hacia atrás líneas de atributos
        line_start = clean.rfind("\n", 0, start) + 1
        attrs = []
        j = line_start
        while j > 0:
            prev_start = clean.rfind("\n", 0, j - 1) + 1
            prev = clean[prev_start:j].strip()
            if prev.startswith("#[") or prev.startswith("#!["):
                attrs.insert(0, prev); j = prev_start
            else:
                break
        is_test = any("#[test]" in a for a in attrs) or "#[test]" in (m.group(1) or "")
        fns.append((m.group(2), start, body, is_test, attrs))
    return fns

def main():
    rows = []          # (crate, relfile, fn, verdict, reasons, ceiling, calls)
    helper_map = {}    # (dirroot, name) -> usa run_source-ish
    files = []
    for crate in sorted(os.listdir(TESTS_ROOT)):
        tdir = os.path.join(TESTS_ROOT, crate, "tests")
        if not os.path.isdir(tdir): continue
        for dp, _, fs in os.walk(tdir):
            for f in fs:
                if f.endswith(".rs"):
                    files.append((crate, os.path.join(dp, f)))
    parsed = []
    for crate, path in files:
        raw = io.open(path, encoding="utf-8", errors="replace").read()
        clean = strip_strings_and_comments(raw)
        fns = extract_fns(clean)
        parsed.append((crate, path, raw, clean, fns))
        for name, _, body, is_test, _ in fns:
            if not is_test:
                dirroot = os.path.dirname(path)
                is_runsrc = bool(RUN_SRC.search(body))
                ceiling = bool(re.search(r"ceiled|secure|labels|sandbox|cap_set|capset", body, re.I))
                helper_map[(dirroot, name)] = ("runsrc" if is_runsrc else "plain", ceiling, body)
    def called_helpers(body, dirroot):
        return [m.group(1) for m in re.finditer(r"\b([a-z_][a-z0-9_]*)\s*\(", body)
                if (dirroot, m.group(1)) in helper_map]
    def chain_text(body, dirroot, max_depth=3):
        """El cuerpo + los cuerpos de TODOS los helpers que llama, recursivo."""
        text = body
        seen = set()
        frontier = called_helpers(body, dirroot)
        for _ in range(max_depth):
            nxt = []
            for h in frontier:
                if h in seen: continue
                seen.add(h)
                hb = helper_map[(dirroot, h)][2]
                text += hb
                nxt += called_helpers(hb, dirroot)
            frontier = nxt
            if not frontier: break
        return text
    def call_is_runsrc(body, dirroot):
        """run_source-ness transitiva por cualquier cadena de helpers."""
        if RUN_SRC.search(body): return ("direct", bool(re.search(r"ceiled|secure|labels|sandbox|cap_set|capset", body, re.I)))
        text = chain_text(body, dirroot)
        if RUN_SRC.search(text):
            return ("helper", bool(re.search(r"ceiled|secure|labels|sandbox|cap_set|capset", text, re.I)))
        return None
    def body_markers(body, dirroot):
        """Marcadores del cuerpo + de TODOS los helpers que llama (recursivo)."""
        text = chain_text(body, dirroot)
        hits = []
        for pat, why in QUEDA_PATTERNS:
            if re.search(pat, text):
                hits.append(why)
        return hits
    for crate, path, raw, clean, fns in parsed:
        rel = os.path.relpath(path, ROOT).replace("\\", "/")
        dirroot = os.path.dirname(path)
        raw_flag = bool(re.search(r'"Runtime error:|"Capability not granted:|"SQL error:', raw))
        for name, _, body, is_test, attrs in fns:
            if not is_test: continue
            reasons = body_markers(body, dirroot)
            uses_src = call_is_runsrc(body, dirroot)
            ceiling = "default"
            if uses_src and uses_src[1]: ceiling = "especial"
            if re.search(r"ceiled|secure|labels|sandbox|cap_set|capset", body, re.I): ceiling = "especial"
            if not uses_src:
                verdict = "QUEDA"
                reasons.insert(0, "no corre un programa vía run_source/run_program")
            elif reasons:
                verdict = "QUEDA"
            else:
                verdict = "MIGRA"
                # hallazgo del piloto (2026-11-23): el texto capturable con try/recover no lleva
                # el prefijo decorado del host (`Runtime error: archivo:linea:col: …`); un test
                # que afirme el mensaje decorado completo QUEDA. El contenido de los strings se
                # vació al limpiar, así que la detección es por ARCHIVO sobre el texto crudo y
                # el repaso test por test del lote confirma.
                if raw_flag:
                    reasons.append("el archivo contiene literales de mensaje decorado (revisar test por test)")
                if re.search(r"\.errors\b", body): reasons.append("afirma errors (validar patrón)")
                if re.search(r"\.output\b|assert_output", body): reasons.append("afirma output (traduce a valores)")
            rows.append((crate, rel, name, verdict, "; ".join(reasons) or "-", ceiling))
    previous = {}
    if os.path.exists(LEDGER):
        with io.open(LEDGER, encoding="utf-8", newline="") as fh:
            for old in csv.DictReader(fh, delimiter="\t"):
                previous[(old["archivo"], old["test"])] = old
    candidates = [r for r in rows if r[3] == "MIGRA"]
    fields = ["crate", "archivo", "test", "techo", "pista", "decision", "nota"]
    with io.open(LEDGER, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        for crate, archivo, name, _, reason, ceiling in candidates:
            old = previous.get((archivo, name), {})
            writer.writerow(dict(crate=crate, archivo=archivo, test=name, techo=ceiling,
                                 pista=reason, decision=old.get("decision", "PENDIENTE"),
                                 nota=old.get("nota") or "-"))
    # resumen
    from collections import Counter
    by_v = Counter(r[3] for r in rows)
    by_crate = Counter((r[0], r[3]) for r in rows)
    files_mix = {}
    for r in rows:
        files_mix.setdefault(r[1], set()).add(r[3])
    migra_files = sum(1 for v in files_mix.values() if v == {"MIGRA"})
    decisions = Counter(previous.get((r[1], r[2]), {}).get("decision", "PENDIENTE")
                        for r in candidates)
    print(f"Rust: {len(rows)}; candidatos mecánicos: {len(candidates)}; "
          f"excluidos mecánicos: {by_v['QUEDA']}; decisiones: {dict(decisions)}")
    print(f"Lotes sin exclusiones mecánicas: {migra_files}; "
          f"manifest: {os.path.relpath(LEDGER, ROOT)}")

if __name__ == "__main__":
    main()
