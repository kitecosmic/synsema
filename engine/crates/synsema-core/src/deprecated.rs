//! Nombres que cambiaron antes de v1.0 (v0.6.29, specs/lenguaje/v1-compatibilidad.md).
//!
//! Cada fila es `(viejo, nuevo)`. El viejo SIGUE funcionando hasta el corte de v1.0 —como
//! alias del nuevo, o con su comportamiento de siempre cuando el nuevo cambió la forma del
//! resultado (`capture` → `regex_capture`)—, pero `synsema check` lo avisa y la primera
//! carga de un programa que lo usa lo dice una vez por stderr. En v1.0 el viejo se va.

use std::collections::HashSet;
use std::sync::Mutex;

use crate::ast::{Node, NodeKind, Program};

pub const DEPRECATED_NAMES: &[(&str, &str)] = &[
    // Texto y regex (V1-D1, V1-D2): una familia `regex_*`, `replace` para texto plano, y el
    // plegado de mayúsculas + acentos con un nombre que dice lo que hace.
    ("replace_text", "replace"),
    ("find_all", "regex_find_all"),
    ("capture", "regex_capture"),
    ("replace_re", "regex_replace"),
    ("fold", "fold_text"),
    // Criptografía (V1-D3): la MAC es bytes como cualquier hash (`hex(hmac(d, k))` para verla).
    ("hmac_sha256", "hmac"),
    // Álgebra (DATOS-10): un nombre por concepto.
    ("eye", "identity"),
    // Blockchain (V1-BC1): `<familia>_<acción>`; EVM es la familia, no Ethereum.
    ("eth_rpc", "evm_rpc"),
    ("eth_nonce", "evm_nonce"),
    ("eth_balance", "evm_balance"),
    ("eth_gas_price", "evm_gas_price"),
    ("eth_chain_id", "evm_chain_id"),
    ("eth_estimate_gas", "evm_estimate_gas"),
    ("eth_call", "evm_call"),
    ("eth_fee_history", "evm_fee_history"),
    ("eth_send_raw", "evm_send"),
    ("eth_receipt", "evm_receipt"),
    ("eth_wait_receipt", "evm_wait"),
    ("eth_address", "evm_address"),
    ("tx_eip1559", "evm_tx"),
    ("tx_eip1559_raw", "evm_tx_raw"),
    ("algo_address", "algorand_address"),
    ("algorand_tx_encode", "algorand_tx"),
    ("solana_message", "solana_tx"),
    ("solana_confirm", "solana_wait"),
];

/// El nombre nuevo de `old`, si está deprecado.
pub fn replacement(old: &str) -> Option<&'static str> {
    DEPRECATED_NAMES.iter().find(|(o, _)| *o == old).map(|(_, n)| *n)
}

/// Nombres deprecados que el programa LLAMA (o referencia como valor), en orden de aparición
/// y sin repetir, con la línea de la primera vez.
pub fn used_in(program: &Program) -> Vec<(String, &'static str, usize)> {
    let mut out: Vec<(String, &'static str, usize)> = Vec::new();
    let mut seen = HashSet::new();
    let mut declared = HashSet::new();
    // Un task o variable del programa con ese nombre lo sombrea: no es el builtin.
    for st in &program.statements {
        crate::ast_api::walk(st, &mut |n| match &n.kind {
            NodeKind::TaskDefinition { name, .. } => {
                declared.insert(name.clone());
            }
            NodeKind::LetBinding { name, .. } => {
                declared.insert(name.to_string());
            }
            _ => {}
        });
    }
    for st in &program.statements {
        crate::ast_api::walk(st, &mut |n| {
            if let NodeKind::Identifier { name } = &n.kind {
                if let Some(new) = replacement(name) {
                    if !declared.contains(name) && seen.insert(name.clone()) {
                        out.push((name.clone(), new, n.location.line));
                    }
                }
            }
        });
    }
    out
}

/// Builtins que CAMBIARON de comportamiento en v0.6.29 sin cambiar de nombre: `synsema check`
/// lo dice una vez por nombre usado (hasta v1.0), con lo que hay que revisar.
pub const CHANGED_IN_0629: &[(&str, &str)] = &[
    ("std", "`std` is now the SAMPLE standard deviation (ddof = 1, like pandas); the population one is std(xs, ddof = 0)"),
    ("var", "`var` is now the SAMPLE variance (ddof = 1, like pandas); the population one is var(xs, ddof = 0)"),
    ("group_by", "`group_by` now returns [{key, items}] in first-appearance order with the key's own type (it was a map keyed by text)"),
    ("dot", "`dot` is now the inner product of two vectors only; for matrices use matmul(a, b)"),
];

/// Avisos de `synsema check`.
pub fn check_warnings(program: &Program, file_path: &str, warnings: &mut Vec<String>) {
    for (old, new, line) in used_in(program) {
        warnings.push(format!(
            "warning: {}:{}: `{}` is deprecated — use `{}` (the old name goes away in v1.0)",
            file_path, line, old, new
        ));
    }
    for line in generate_joined_lines(program) {
        warnings.push(generate_joined_warning(file_path, line));
    }
    let mut seen = HashSet::new();
    for st in &program.statements {
        crate::ast_api::walk(st, &mut |n| {
            if let NodeKind::TaskCall { name, arguments } = &n.kind {
                let Some(id) = name.as_identifier() else { return };
                if let Some((_, note)) = CHANGED_IN_0629.iter().find(|(c, _)| *c == id) {
                    if seen.insert(id.to_string()) {
                        warnings.push(format!("warning: {}:{}: changed in v0.6.29: {}", file_path, n.location.line, note));
                    }
                }
                // `percentile(x, 0.5)`: el nivel va de 0 a 100; un literal en (0, 1) casi seguro
                // quería `quantile`.
                if id == "percentile" {
                    if let Some(a) = arguments.get(1) {
                        if let NodeKind::NumberLiteral { value } = &a.value.kind {
                            let p = value.to_f64();
                            if p > 0.0 && p < 1.0 {
                                warnings.push(format!(
                                    "warning: {}:{}: percentile takes p from 0 to 100 — percentile(x, {}) is the {}th percentile; for a fraction use quantile(x, {})",
                                    file_path, n.location.line, value, value, value
                                ));
                            }
                        }
                    }
                }
            }
        });
    }
    // `\u00e9` en un literal: desde v0.6.29 es un escape (antes el texto quedaba tal cual).
    let mut lines = program.escape_lines.clone();
    lines.dedup();
    for line in lines {
        warnings.push(format!(
            "warning: {}:{}: changed in v0.6.29: `\\uXXXX` in a string is now an escape (\"\\u00e9\" is \"é\") — for a literal backslash + u write `\\\\u`",
            file_path, line
        ));
    }
    // `x == ""` en un programa que lee CSV: desde v0.6.29 un campo vacío es `nothing`.
    let mut reads_csv = false;
    let mut empty_cmp: Option<usize> = None;
    let is_empty_text = |n: &Node| matches!(&n.kind, NodeKind::TextLiteral { value } if value.is_empty());
    for st in &program.statements {
        crate::ast_api::walk(st, &mut |n| match &n.kind {
            NodeKind::TaskCall { name, .. } if matches!(name.as_identifier(), Some("csv_parse" | "read_csv")) => {
                reads_csv = true;
            }
            NodeKind::BinaryOp { left, operator, right }
                if (operator == "==" || operator == "!=") && (is_empty_text(left) || is_empty_text(right)) =>
            {
                empty_cmp.get_or_insert(n.location.line);
            }
            _ => {}
        });
    }
    if let (true, Some(line)) = (reads_csv, empty_cmp) {
        warnings.push(format!(
            "warning: {}:{}: changed in v0.6.29: an empty CSV field is `nothing`, so `x == \"\"` no longer finds it — use is_missing(x) (a quoted \"\" is still empty text)",
            file_path, line
        ));
    }
    // `each r in rows` + `set r[k] to v` cuando lo escrito se pierde: con semántica de valor eso
    // cambia la copia del bucle, no la fila de `rows`. Lo escrito se usa si `r` sale entera del
    // bucle (se pasa, se agrega, se imprime, se religa) o si se lee un campo que el bucle
    // escribió; leer OTROS campos para calcular (`set r["t"] to r["p"] * 2`, `when r.p > 1`) no.
    for st in &program.statements {
        crate::ast_api::walk(st, &mut |n| {
            let NodeKind::EachStatement { variable, body, .. } = &n.kind else { return };
            let mut u = LoopUses::default();
            for b in body {
                u.scan(b, variable, false);
            }
            let read_written = u.reads.iter().any(|k| match k {
                None => true,
                Some(k) => u.written.iter().any(|w| w.as_deref().is_none_or(|w| w == k)),
            });
            if let (Some(line), false, false) = (u.set_line, u.escapes, read_written) {
                warnings.push(format!(
                    "warning: {}:{}: `set {}[…]` changes the loop's copy, not the item in the list (value semantics, v0.6.29) — build the new list: set xs to apply(xs, (r) => merge(r, {{…}})), or write by index: set xs[i][…] to …",
                    file_path, line, variable
                ));
            }
        });
    }
    // Lo mismo con un parámetro: `task touch(cfg)` + `set cfg[k] to v` escribe en la copia del
    // task. Si el task no lo devuelve, no lo pasa a otra llamada ni lee lo que escribió, la
    // escritura se pierde para cualquiera que lo llame.
    for st in &program.statements {
        crate::ast_api::walk(st, &mut |n| {
            let NodeKind::TaskDefinition { name, parameters, body, .. } = &n.kind else { return };
            for p in parameters {
                let mut u = LoopUses::default();
                for b in body.iter() {
                    u.scan(b, &p.name, false);
                }
                let read_written = u.reads.iter().any(|k| match k {
                    None => true,
                    Some(k) => u.written.iter().any(|w| w.as_deref().is_none_or(|w| w == k)),
                });
                if let (Some(line), false, false) = (u.set_line, u.escapes, read_written) {
                    warnings.push(format!(
                        "warning: {}:{}: `set {}[…]` changes task {}'s own copy of the argument, not the caller's value (value semantics, v0.6.29), and the task does not give it back — end the task with `give {}` and call it as `set x to {}(x)`",
                        file_path, line, p.name, name, p.name, name
                    ));
                }
            }
        });
    }
}

/// La variable raíz de un destino `x[i].k`.
fn set_root(n: &Node) -> Option<&str> {
    match &n.kind {
        NodeKind::Identifier { name } => Some(name),
        NodeKind::IndexAccess { object, .. } | NodeKind::PropertyAccess { object, .. } => set_root(object),
        _ => None,
    }
}

/// Cómo usa el cuerpo de un `each` a la variable del bucle.
#[derive(Default)]
struct LoopUses {
    /// La línea del primer `set var[…]` / `set var.k`.
    set_line: Option<usize>,
    /// La clave de primer nivel de cada escritura (`None`: dinámica, `set r[k]`).
    written: Vec<Option<String>>,
    /// La clave de primer nivel de cada lectura de un campo, fuera del valor de un `set var[…]`.
    reads: Vec<Option<String>>,
    /// La variable entera sale del bucle (se pasa, se agrega, se devuelve, se religa).
    escapes: bool,
}

impl LoopUses {
    /// `in_own_set`: dentro del valor de un `set var[…]` (leer la fila para calcular lo que se
    /// le escribe no usa lo escrito).
    fn scan(&mut self, n: &Node, var: &str, in_own_set: bool) {
        match &n.kind {
            NodeKind::SetMutation { target, value } => {
                let on_var = !matches!(target.kind, NodeKind::Identifier { .. }) && set_root(target) == Some(var);
                if on_var {
                    self.set_line.get_or_insert(n.location.line);
                    self.written.push(first_key(target));
                }
                match &target.kind {
                    // `set r to …` religa la variable: lo escrito antes pudo usarse.
                    NodeKind::Identifier { name } if name == var => self.escapes = true,
                    NodeKind::Identifier { .. } => {}
                    // En el destino sólo cuentan los índices (`set out[r.id] to …`), no la raíz.
                    _ => self.scan_target(target, var, in_own_set),
                }
                self.scan(value, var, in_own_set || on_var);
            }
            NodeKind::IndexAccess { .. } | NodeKind::PropertyAccess { .. } if set_root(n) == Some(var) => {
                if !in_own_set {
                    self.reads.push(first_key(n));
                }
                self.scan_target(n, var, in_own_set);
            }
            NodeKind::Identifier { name } if name == var => self.escapes = true,
            _ => {
                for c in crate::ast_api::children(n) {
                    self.scan(c, var, in_own_set);
                }
            }
        }
    }

    /// Los índices de una cadena `x[i].k[j]` (no su raíz).
    fn scan_target(&mut self, n: &Node, var: &str, in_own_set: bool) {
        match &n.kind {
            NodeKind::IndexAccess { object, index } => {
                self.scan(index, var, in_own_set);
                self.scan_target(object, var, in_own_set);
            }
            NodeKind::PropertyAccess { object, .. } => self.scan_target(object, var, in_own_set),
            NodeKind::Identifier { .. } => {}
            _ => self.scan(n, var, in_own_set),
        }
    }
}

/// La clave del primer nivel de `r["a"]["b"]` / `r.a.b` (`"a"`); `None` si es dinámica.
fn first_key(n: &Node) -> Option<String> {
    let mut cur = n;
    loop {
        let (object, key) = match &cur.kind {
            NodeKind::IndexAccess { object, index } => match &index.kind {
                NodeKind::TextLiteral { value } => (object, Some(value.clone())),
                _ => (object, None),
            },
            NodeKind::PropertyAccess { object, property_name, .. } => (object, Some(property_name.clone())),
            _ => return None,
        };
        if matches!(object.kind, NodeKind::Identifier { .. }) {
            return key;
        }
        cur = object;
    }
}

static SEEN: Mutex<Option<HashSet<String>>> = Mutex::new(None);

/// Los nombres deprecados que este proceso ya avisó al cargar (para los tests: el aviso va
/// a stderr).
pub fn warned_at_load() -> Vec<String> {
    let guard = SEEN.lock().unwrap_or_else(|e| e.into_inner());
    guard.as_ref().map(|s| s.iter().cloned().collect()).unwrap_or_default()
}

/// v0.6.49 (A9): las líneas donde un `generate` sin `given` es el lado izquierdo de un `+`.
/// `generate "x" + c` se lee `(generate "x") + c`: el modelo no ve `c`, que se pega a la respuesta.
/// Es seguro (nada privado llega al modelo sin `given`), pero engaña. `reason` y `analyze` toman la
/// expresión entera.
pub fn generate_joined_lines(program: &Program) -> Vec<usize> {
    let mut out = Vec::new();
    for st in &program.statements {
        crate::ast_api::walk(st, &mut |n| {
            if let NodeKind::BinaryOp { left, operator, .. } = &n.kind {
                if operator == "+" && matches!(&left.kind, NodeKind::GenerateExpression { given: None, .. }) {
                    out.push(n.location.line);
                }
            }
        });
    }
    out
}

fn generate_joined_warning(file_path: &str, line: usize) -> String {
    format!(
        "warning: {}:{}: `generate \"…\" + …` joins the model's answer with what follows the `+`; the model does not see it. To give it to the model: generate \"…\" given <expression>",
        file_path, line
    )
}

/// Aviso en tiempo de carga: una vez por nombre y por proceso (un `serve` con N workers
/// no lo repite N veces).
pub fn warn_once_at_load(program: &Program, file_path: &str) {
    let used = used_in(program);
    let joined = generate_joined_lines(program);
    if used.is_empty() && joined.is_empty() {
        return;
    }
    let mut guard = SEEN.lock().unwrap_or_else(|e| e.into_inner());
    let seen = guard.get_or_insert_with(HashSet::new);
    for line in joined {
        if seen.insert(format!("generate+{}:{}", file_path, line)) {
            eprintln!("{}", generate_joined_warning(file_path, line));
        }
    }
    for (old, new, line) in used {
        if seen.insert(old.clone()) {
            eprintln!(
                "warning: {}:{}: `{}` is deprecated — use `{}` (the old name goes away in v1.0)",
                file_path, line, old, new
            );
        }
    }
}

/// v0.6.50 (E-c): en una tool de confianza, los `require` de las tasks que el módulo no exporta
/// (`(task, capability, línea)`). No conceden nada: el scope lo abre la task exportada que el
/// programa llama, con lo que ésa declara. Una task exportada con `export let h be helper` cuenta
/// como exportada (`h` es `helper`).
pub fn trusted_unexported_requires(program: &Program) -> Vec<(String, String, usize)> {
    let mut exported = HashSet::new();
    for st in &program.statements {
        if let NodeKind::ExportDeclaration { declaration } = &st.kind {
            match &declaration.kind {
                NodeKind::TaskDefinition { name, .. } => {
                    exported.insert(name.clone());
                }
                NodeKind::LetBinding { value, .. } => {
                    if let NodeKind::Identifier { name } = &value.kind {
                        exported.insert(name.to_string());
                    }
                }
                _ => {}
            }
        }
    }
    let mut out = Vec::new();
    for st in &program.statements {
        crate::ast_api::walk(st, &mut |n| {
            if let NodeKind::TaskDefinition { name, body, .. } = &n.kind {
                if exported.contains(name) {
                    return;
                }
                for b in body.iter() {
                    if let NodeKind::RequireStatement { capability, .. } = &b.kind {
                        out.push((name.clone(), capability.clone(), b.location.line));
                    }
                }
            }
        });
    }
    out
}

/// v0.6.50 (E-c): el aviso de `trusted_unexported_requires` al cargar la tool, una vez por sitio y
/// por proceso (cada worker de `serve` la carga).
pub fn warn_trusted_unexported_requires(program: &Program, module: &str) {
    let dead = trusted_unexported_requires(program);
    if dead.is_empty() {
        return;
    }
    let mut guard = SEEN.lock().unwrap_or_else(|e| e.into_inner());
    let seen = guard.get_or_insert_with(HashSet::new);
    for (task, cap, line) in dead {
        if seen.insert(format!("trusted-require:{}:{}", module, line)) {
            eprintln!(
                "warning: trusted:{}:{}: `require {}` in task {} grants nothing: the module does not export {}, and a trusted task runs with what the exported task the program calls declares. Declare it in that exported task",
                module, line, cap, task, task
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(src: &str) -> Vec<usize> {
        generate_joined_lines(&crate::parser::parse_source(src, "g.syn").unwrap())
    }

    /// v0.6.49 (A9): `generate "x" + c` avisa (el modelo no ve `c`); con `given`, o con el `generate`
    /// a la derecha, no.
    #[test]
    fn a9_generate_joined_with_plus_warns_once_per_site() {
        assert_eq!(lines("let c be \"hola\"\nlet r be generate \"un saludo\" + c\n"), [2]);
        assert!(lines("let c be 1\nlet r be generate \"un saludo\" given c\n").is_empty());
        assert!(lines("let c be \"a\"\nlet r be c + (generate \"x\")\n").is_empty());
        assert!(lines("let r be generate \"x\" given 1 + 2\n").is_empty());
        let mut w = Vec::new();
        check_warnings(&crate::parser::parse_source("let c be 1\nlet r be generate \"x\" + c\n", "g.syn").unwrap(), "g.syn", &mut w);
        assert!(w.iter().any(|m| m.starts_with("warning: g.syn:2: `generate \"…\" + …`") && m.contains("generate \"…\" given <expression>")), "{:?}", w);
    }
}
