//! `archdef`: una arquitectura descrita en **datos**, no en Rust.
//!
//! Hasta I4, sumar un modelo nuevo costaba un archivo `.rs`, una recompilación y un release. Este
//! módulo lo convierte en un archivo de texto que el binario **ya compilado** puede leer. Las
//! operaciones (matmul, RMSNorm, RoPE, atención, SwiGLU) están adentro del binario desde siempre;
//! lo que faltaba era el **orden** y los **parámetros**, que son datos.
//!
//! Es a `synsema-infer` lo que un `.syn` es al intérprete: el motor no se recompila para correr un
//! programa nuevo.
//!
//! ## Cómo se lee una definición
//!
//! ```text
//! arch llama
//! kind decoder
//!
//! prologue
//!   x = embed(token_embd.weight)
//!
//! block
//!   h = rms_norm(x, blk.{i}.attn_norm.weight)
//!   q = matmul(h, blk.{i}.attn_q.weight)
//!   ...
//!   add(x, o)
//!
//! epilogue
//!   x = rms_norm(x, output_norm.weight)
//!   x = last(x)
//!   logits = matmul(x, output.weight | token_embd.weight)
//! ```
//!
//! Tres secciones. `prologue` corre una vez, `block` una vez **por capa** (con `{i}` sustituido por
//! su número), `epilogue` una vez al final. `x` es el residual y `logits` el resultado.
//!
//! Los **registros** son nombres cualesquiera: cada uno guarda un tensor. Los **tensores** se
//! nombran exactamente como los nombra el GGUF, así que escribir una definición es, literalmente,
//! mirar la lista de tensores del archivo y copiarla.
//!
//! ## Lo que la gramática NO tiene, a propósito
//!
//! **No hay condicionales, ni bucles, ni llamadas, ni acceso a disco o a red.** Un `archdef` es una
//! lista recta de pasos y nada más. No es una limitación que haya que levantar después: es la razón
//! por la que bajar una definición de arquitectura que escribió otra persona es tan seguro como
//! bajar una imagen. Lo peor que puede hacer una definición mala es no cargar, o dar números
//! equivocados con los pesos de uno — nunca ejecutar algo.
//!
//! Por eso tampoco hay banderas tipo «si el modelo lleva sesgo, sumalo»: **qwen2 lleva las líneas
//! de sesgo y llama no las lleva**. La diferencia entre dos arquitecturas se ve leyendo, no
//! siguiendo un `if` hasta el otro lado del archivo.
//!
//! ## El escape hatch
//!
//! Una definición alcanza cuando la arquitectura se arma con las operaciones que el binario ya
//! trae. Cuando el modelo estrena una operación —una atención distinta, una activación nueva—, hay
//! que escribir Rust y publicar un binario. El formato no lo esconde: el error de operación
//! desconocida enumera las que existen, y esa lista es el contrato.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

/// Qué clase de modelo describe la definición.
///
/// Hoy sólo decoders. Los encoders (ModernBERT, Laya) siguen escritos a mano en
/// `arch_modernbert.rs`: su forma —atención bidireccional, dos bases de RoPE alternadas, cabezas
/// de decisión— no comparte casi nada con un decoder, y forzarla en el mismo vocabulario habría
/// producido un formato peor para los dos.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchKind {
    Decoder,
}

impl ArchKind {
    /// La palabra que se publica —en `llm status` y en su `--json`—, que es la misma que se
    /// escribe en el `kind` de una definición.
    pub fn label(&self) -> &'static str {
        match self {
            ArchKind::Decoder => "decoder",
        }
    }
}

/// De dónde salió la definición. Va al diagnóstico y a la procedencia.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DefOrigin {
    /// Viene compilada en el binario: la publicamos nosotros con el release.
    Embedded,
    /// La puso el operador en el directorio de definiciones.
    File(PathBuf),
}

impl DefOrigin {
    pub fn describe(&self) -> String {
        match self {
            DefOrigin::Embedded => "en el binario".to_string(),
            DefOrigin::File(p) => p.display().to_string(),
        }
    }
}

/// Un valor de la configuración del modelo, que la definición nombra pero no fija.
///
/// Son los números que **el GGUF ya declara**. Repetirlos en la definición sería pedirle al que
/// escribe que los mantenga sincronizados con cada checkpoint, y sería la primera cosa que quede
/// vieja.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConfigKey {
    HeadCount,
    HeadCountKv,
    HeadDim,
    EmbeddingLength,
    FeedForwardLength,
    BlockCount,
    ContextLength,
}

impl ConfigKey {
    pub const ALL: &'static [(&'static str, ConfigKey)] = &[
        ("block_count", ConfigKey::BlockCount),
        ("context_length", ConfigKey::ContextLength),
        ("embedding_length", ConfigKey::EmbeddingLength),
        ("feed_forward_length", ConfigKey::FeedForwardLength),
        ("head_count", ConfigKey::HeadCount),
        ("head_count_kv", ConfigKey::HeadCountKv),
        ("head_dim", ConfigKey::HeadDim),
    ];

    fn parse(s: &str) -> Option<ConfigKey> {
        ConfigKey::ALL.iter().find(|(n, _)| *n == s).map(|(_, k)| *k)
    }

    pub fn name(&self) -> &'static str {
        ConfigKey::ALL.iter().find(|(_, k)| k == self).map(|(n, _)| *n).unwrap_or("?")
    }
}

/// Un número que la definición necesita y que se resuelve **al cargar**, nunca al correr.
///
/// La aritmética disponible es deliberadamente mínima: un literal, un valor de la config, o su raíz
/// cuadrada (que es lo único que pide gemma3). Un formato con expresiones generales es un lenguaje,
/// y un lenguaje hay que auditarlo.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Expr {
    Literal(f32),
    Config(ConfigKey),
    Sqrt(ConfigKey),
}

/// El nombre de un tensor del GGUF, con un alternativo por si el primero no está.
///
/// El alternativo existe por un caso real y sólo uno: los modelos con embeddings **atados** no
/// traen `output.weight` y usan la tabla de embeddings como cabeza. Se resuelve al cargar, así que
/// el programa que corre no tiene ninguna bifurcación.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TensorRef {
    pub name: String,
    pub fallback: Option<String>,
}

impl TensorRef {
    /// Sustituye `{i}` por el número de capa. Fuera de `block` no hay nada que sustituir.
    pub fn resolve(&self, layer: usize) -> (String, Option<String>) {
        let sub = |s: &str| s.replace("{i}", &layer.to_string());
        (sub(&self.name), self.fallback.as_deref().map(sub))
    }

    fn mentions_layer(&self) -> bool {
        self.name.contains("{i}") || self.fallback.as_deref().is_some_and(|f| f.contains("{i}"))
    }
}

/// Un registro: un lugar donde vive un tensor mientras corre el programa.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Reg(pub usize);

/// Las activaciones que el binario trae compiladas.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActKind {
    Silu,
    /// GELU exacta, con `erf`.
    Gelu,
    /// GELU con la aproximación tanh: `gelu_pytorch_tanh`, la que usa Gemma y la que implementa
    /// ggml. **No es intercambiable con [`ActKind::Gelu`]**: difieren en ~1e-3, y un modelo
    /// corrido con la que no es deriva en vez de fallar.
    GeluTanh,
    Relu,
}

/// Una operación. **Este enum es el contrato del formato**: lo que no está acá no se puede
/// describir, y el que escribe una definición lo ve en el mensaje de error.
#[derive(Clone, Debug, PartialEq)]
pub enum Op {
    /// `dst = embed(tabla)` — busca los ids de entrada en la tabla de embeddings.
    Embed { dst: Reg, table: TensorRef },
    /// `dst = rms_norm(src, peso)`
    RmsNorm { dst: Reg, src: Reg, weight: TensorRef },
    /// `dst = matmul(src, peso)` — el peso se queda cuantizado.
    Matmul { dst: Reg, src: Reg, weight: TensorRef },
    /// `add_bias(dst, sesgo)`
    AddBias { dst: Reg, bias: TensorRef },
    /// `norm_heads(dst, peso, cuantas_cabezas)` — RMSNorm por cabeza, antes de RoPE.
    NormHeads { dst: Reg, weight: TensorRef, heads: ConfigKey },
    /// `rope(dst, cuantas_cabezas)` — la base sale de la capa (local o global).
    Rope { dst: Reg, heads: ConfigKey },
    /// `dst = attention(q, k, v)` — GQA, cache, máscara causal y ventana, todo adentro.
    Attention { dst: Reg, q: Reg, k: Reg, v: Reg },
    /// `silu(dst)` / `gelu(dst)` / `gelu_tanh(dst)` / `relu(dst)`
    Activation { dst: Reg, kind: ActKind },
    /// `mul(dst, src)` — elemento a elemento.
    Mul { dst: Reg, src: Reg },
    /// `add(dst, src)` — el residual.
    Add { dst: Reg, src: Reg },
    /// `scale(dst, expr)`
    Scale { dst: Reg, factor: Expr },
    /// `dst = last(src)` — la última fila; los logits de los tokens anteriores no se usan.
    Last { dst: Reg, src: Reg },
    /// `dst = copy(src)`
    Copy { dst: Reg, src: Reg },
}

impl Op {
    /// Los nombres de todas las operaciones, para el mensaje de error y para la doc.
    pub const NAMES: &'static [&'static str] = &[
        "add", "add_bias", "attention", "copy", "embed", "gelu", "gelu_tanh", "last", "matmul",
        "mul", "norm_heads", "relu", "rms_norm", "rope", "scale", "silu",
    ];

    fn dst(&self) -> Reg {
        match self {
            Op::Embed { dst, .. }
            | Op::RmsNorm { dst, .. }
            | Op::Matmul { dst, .. }
            | Op::AddBias { dst, .. }
            | Op::NormHeads { dst, .. }
            | Op::Rope { dst, .. }
            | Op::Attention { dst, .. }
            | Op::Activation { dst, .. }
            | Op::Mul { dst, .. }
            | Op::Add { dst, .. }
            | Op::Scale { dst, .. }
            | Op::Last { dst, .. }
            | Op::Copy { dst, .. } => *dst,
        }
    }

    /// Los registros que la operación **lee**. Sirve para detectar un nombre mal escrito antes de
    /// correr nada, que es de dónde sale la mitad del valor de validar.
    fn reads(&self) -> Vec<Reg> {
        match self {
            Op::Embed { .. } => vec![],
            Op::RmsNorm { src, .. }
            | Op::Matmul { src, .. }
            | Op::Last { src, .. }
            | Op::Copy { src, .. } => vec![*src],
            // Las in-place leen su propio destino.
            Op::AddBias { dst, .. }
            | Op::NormHeads { dst, .. }
            | Op::Rope { dst, .. }
            | Op::Activation { dst, .. }
            | Op::Scale { dst, .. } => vec![*dst],
            Op::Mul { dst, src } | Op::Add { dst, src } => vec![*dst, *src],
            Op::Attention { q, k, v, .. } => vec![*q, *k, *v],
        }
    }

    fn tensors(&self) -> Vec<&TensorRef> {
        match self {
            Op::Embed { table, .. } => vec![table],
            Op::RmsNorm { weight, .. }
            | Op::Matmul { weight, .. }
            | Op::NormHeads { weight, .. } => vec![weight],
            Op::AddBias { bias, .. } => vec![bias],
            _ => vec![],
        }
    }

    /// `true` si la operación necesita el estado de la capa (el KV cache).
    fn needs_layer_state(&self) -> bool {
        matches!(self, Op::Attention { .. })
    }
}

/// Un paso del programa: una operación y la línea donde estaba escrita.
#[derive(Clone, Debug, PartialEq)]
pub struct Step {
    pub op: Op,
    pub line: usize,
}

/// Una arquitectura completa, ya parseada y validada.
#[derive(Clone, Debug)]
pub struct ArchDef {
    pub name: String,
    pub kind: ArchKind,
    /// Lo que el GGUF **no** declara. Hoy: `sliding_window_type`.
    pub params: BTreeMap<String, f64>,
    pub prologue: Vec<Step>,
    pub block: Vec<Step>,
    pub epilogue: Vec<Step>,
    /// Los nombres de los registros, en el orden en que aparecieron.
    pub regs: Vec<String>,
    pub origin: DefOrigin,
    /// SHA-256 del texto de la definición. Es la procedencia: dos corridas con el mismo sha
    /// corrieron la misma arquitectura.
    pub sha256: String,
}

impl ArchDef {
    pub fn reg_name(&self, r: Reg) -> &str {
        self.regs.get(r.0).map(|s| s.as_str()).unwrap_or("?")
    }

    /// El registro del residual, que es el que enlaza las capas.
    pub fn residual(&self) -> Option<Reg> {
        self.regs.iter().position(|n| n == "x").map(Reg)
    }

    /// El registro del resultado.
    pub fn logits(&self) -> Option<Reg> {
        self.regs.iter().position(|n| n == "logits").map(Reg)
    }

    /// Cuántos registros usa: el tamaño del archivo de registros en tiempo de corrida.
    pub fn reg_count(&self) -> usize {
        self.regs.len()
    }

    /// Un parámetro que el GGUF no trae, con su valor por defecto si la definición no lo fija.
    pub fn param(&self, name: &str, default: f64) -> f64 {
        self.params.get(name).copied().unwrap_or(default)
    }

    /// Una línea corta para `llm status`: qué es y de dónde salió.
    pub fn summary(&self) -> String {
        format!(
            "{} ({} pasos por capa, {}, sha {})",
            self.name,
            self.block.len(),
            self.origin.describe(),
            &self.sha256[..12.min(self.sha256.len())]
        )
    }
}

/// Un error de una definición, con la línea y —cuando se puede— el arreglo exacto.
///
/// No hay `panic` en ningún camino de este módulo: una definición es **dato ajeno**, igual que un
/// `.gguf`, y el criterio es el mismo que el de `synsema check`. Fallar temprano y decir qué
/// cambiar; nunca reventar a mitad de un forward, cuando ya se gastaron treinta segundos.
#[derive(Clone, Debug)]
pub struct DefError {
    pub line: usize,
    pub message: String,
    pub fix: Option<String>,
}

impl std::fmt::Display for DefError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.line > 0 {
            write!(f, "línea {}: {}", self.line, self.message)?;
        } else {
            write!(f, "{}", self.message)?;
        }
        if let Some(fix) = &self.fix {
            write!(f, " — {}", fix)?;
        }
        Ok(())
    }
}

fn err(line: usize, message: impl Into<String>) -> DefError {
    DefError { line, message: message.into(), fix: None }
}

fn err_fix(line: usize, message: impl Into<String>, fix: impl Into<String>) -> DefError {
    DefError { line, message: message.into(), fix: Some(fix.into()) }
}

/// Distancia de edición, para el «¿quisiste decir …?».
///
/// Un typo en el nombre de una operación es el error más común y el más barato de arreglar si el
/// mensaje lo dice. Sin esto, `rmsnorm` contra `rms_norm` cuesta una búsqueda en la doc.
fn edit_distance(a: &str, b: &str) -> usize {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            cur[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

fn did_you_mean(word: &str, candidates: &[&str]) -> Option<String> {
    candidates
        .iter()
        .map(|c| (edit_distance(word, c), *c))
        // Hasta un tercio del largo: más que eso ya no es un typo, es otra cosa.
        .filter(|(d, _)| *d <= (word.len() / 3).max(2))
        .min_by_key(|(d, _)| *d)
        .map(|(_, c)| format!("¿quisiste decir `{}`?", c))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    None,
    Prologue,
    Block,
    Epilogue,
}

impl Section {
    fn name(&self) -> &'static str {
        match self {
            Section::None => "(fuera de sección)",
            Section::Prologue => "prologue",
            Section::Block => "block",
            Section::Epilogue => "epilogue",
        }
    }
}

/// El estado que el parser va armando. Los registros se internan a medida que aparecen.
struct Parser {
    regs: Vec<String>,
}

impl Parser {
    fn reg(&mut self, name: &str) -> Reg {
        if let Some(i) = self.regs.iter().position(|n| n == name) {
            return Reg(i);
        }
        self.regs.push(name.to_string());
        Reg(self.regs.len() - 1)
    }
}

/// Parsea y **valida** una definición. Un `Ok` significa que el programa se puede correr: los
/// registros están escritos antes de leerse y las secciones tienen lo que tienen que tener.
pub fn parse(text: &str, origin: DefOrigin) -> Result<ArchDef, DefError> {
    let mut name: Option<String> = None;
    let mut kind: Option<ArchKind> = None;
    let mut params: BTreeMap<String, f64> = BTreeMap::new();
    let mut prologue = Vec::new();
    let mut block = Vec::new();
    let mut epilogue = Vec::new();
    let mut section = Section::None;
    let mut p = Parser { regs: Vec::new() };
    let mut seen_sections: BTreeSet<&'static str> = BTreeSet::new();

    for (idx, raw) in text.lines().enumerate() {
        let line = idx + 1;
        // Un `#` empieza un comentario en cualquier parte de la línea.
        let content = raw.split('#').next().unwrap_or("").trim();
        if content.is_empty() {
            continue;
        }

        // Encabezados: `arch`, `kind`, `param`, y las tres secciones.
        let mut head = content.split_whitespace();
        let first = head.next().unwrap_or("");
        match first {
            "arch" => {
                let v = head
                    .next()
                    .ok_or_else(|| err_fix(line, "`arch` sin nombre", "escribí `arch llama`"))?;
                if head.next().is_some() {
                    return Err(err(line, "`arch` lleva un solo nombre"));
                }
                if !v.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
                    return Err(err_fix(
                        line,
                        format!("'{}' no sirve como nombre de arquitectura", v),
                        "sólo letras, números, `_` y `-`; tiene que coincidir con \
                         `general.architecture` del GGUF",
                    ));
                }
                name = Some(v.to_string());
                continue;
            }
            "kind" => {
                let v = head.next().unwrap_or("");
                kind = match v {
                    "decoder" => Some(ArchKind::Decoder),
                    other => {
                        return Err(err_fix(
                            line,
                            format!("clase de modelo desconocida: '{}'", other),
                            "hoy sólo existe `kind decoder`; los encoders siguen escritos en Rust",
                        ))
                    }
                };
                continue;
            }
            "param" => {
                let key = head.next().ok_or_else(|| {
                    err_fix(line, "`param` sin nombre", "`param sliding_window_type 6`")
                })?;
                let val = head.next().ok_or_else(|| {
                    err_fix(
                        line,
                        format!("`param {}` sin valor", key),
                        "`param sliding_window_type 6`",
                    )
                })?;
                let n: f64 = val.parse().map_err(|_| {
                    err_fix(
                        line,
                        format!("'{}' no es un número", val),
                        "un `param` es siempre un número",
                    )
                })?;
                if !n.is_finite() {
                    return Err(err(line, format!("'{}' no es un número finito", val)));
                }
                params.insert(key.to_string(), n);
                continue;
            }
            "prologue" | "block" | "epilogue" => {
                if head.next().is_some() {
                    return Err(err_fix(
                        line,
                        format!("`{}` no lleva argumentos", first),
                        "los pasos van en las líneas de abajo",
                    ));
                }
                let tag = match first {
                    "prologue" => "prologue",
                    "block" => "block",
                    _ => "epilogue",
                };
                if !seen_sections.insert(tag) {
                    return Err(err_fix(
                        line,
                        format!("la sección `{}` está dos veces", first),
                        "juntá sus pasos en una sola",
                    ));
                }
                section = match first {
                    "prologue" => Section::Prologue,
                    "block" => Section::Block,
                    _ => Section::Epilogue,
                };
                continue;
            }
            _ => {}
        }

        if section == Section::None {
            return Err(err_fix(
                line,
                format!("`{}` está fuera de toda sección", first),
                "los pasos van adentro de `prologue`, `block` o `epilogue`",
            ));
        }

        let step = parse_step(content, line, &mut p)?;
        if section != Section::Block && step.op.needs_layer_state() {
            return Err(err_fix(
                line,
                "`attention` sólo va adentro de `block`",
                "necesita el cache de su capa, y fuera del bloque no hay capa",
            ));
        }
        if section != Section::Block && step.op.tensors().iter().any(|t| t.mentions_layer()) {
            return Err(err_fix(
                line,
                format!("`{{i}}` en `{}`, donde no hay número de capa", section.name()),
                "sacá el `{i}`, o mové el paso a `block`",
            ));
        }
        match section {
            Section::Prologue => prologue.push(step),
            Section::Block => block.push(step),
            Section::Epilogue => epilogue.push(step),
            Section::None => unreachable!("ya se rechazó arriba"),
        }
    }

    let name = name.ok_or_else(|| {
        err_fix(
            0,
            "la definición no dice qué arquitectura es",
            "agregá `arch <nombre>` arriba de todo",
        )
    })?;
    let kind = kind.ok_or_else(|| {
        err_fix(0, format!("'{}' no dice de qué clase es", name), "agregá `kind decoder`")
    })?;
    for s in ["prologue", "block", "epilogue"] {
        if !seen_sections.contains(s) {
            return Err(err_fix(
                0,
                format!("'{}' no tiene sección `{}`", name, s),
                "las tres son obligatorias: `prologue` corre una vez, `block` una por capa, \
                 `epilogue` una al final",
            ));
        }
    }

    let def = ArchDef {
        name,
        kind,
        params,
        prologue,
        block,
        epilogue,
        regs: p.regs,
        origin,
        sha256: sha256_hex(text.as_bytes()),
    };
    validate(&def)?;
    Ok(def)
}

/// Parsea un paso: `dst = op(args)` o `op(args)`.
fn parse_step(content: &str, line: usize, p: &mut Parser) -> Result<Step, DefError> {
    // El destino explícito, si lo hay. Ojo con `+=` y demás: no existen, y conviene decirlo.
    let (dst_name, call) = match content.split_once('=') {
        Some((lhs, rhs)) => {
            let lhs = lhs.trim();
            if lhs.ends_with('+') || lhs.ends_with('*') || lhs.ends_with('-') {
                return Err(err_fix(
                    line,
                    format!("`{}=` no existe en este formato", &lhs[lhs.len() - 1..]),
                    "para sumar usá `add(dst, src)`; para multiplicar, `mul(dst, src)`",
                ));
            }
            (Some(lhs.to_string()), rhs.trim().to_string())
        }
        None => (None, content.to_string()),
    };

    let open = call.find('(').ok_or_else(|| {
        err_fix(
            line,
            format!("`{}` no es una operación", call),
            "todo paso es `op(...)` o `dst = op(...)`",
        )
    })?;
    if !call.ends_with(')') {
        return Err(err_fix(line, "falta el paréntesis de cierre", "cerrá con `)`"));
    }
    let op_name = call[..open].trim().to_string();
    let args = split_args(&call[open + 1..call.len() - 1], line)?;

    // Cuáles producen un tensor nuevo y cuáles trabajan sobre su primer argumento.
    let produces =
        matches!(op_name.as_str(), "embed" | "rms_norm" | "matmul" | "attention" | "last" | "copy");
    if produces && dst_name.is_none() {
        return Err(err_fix(
            line,
            format!("`{}` produce un tensor y nadie lo recibe", op_name),
            format!("escribí `algo = {}(...)`", op_name),
        ));
    }
    if !produces && dst_name.is_some() && Op::NAMES.contains(&op_name.as_str()) {
        return Err(err_fix(
            line,
            format!("`{}` trabaja sobre su primer argumento y no devuelve nada", op_name),
            format!("escribí `{}(...)` sin `=`", op_name),
        ));
    }

    let arity = |n: usize| -> Result<(), DefError> {
        if args.len() == n {
            Ok(())
        } else {
            Err(err_fix(
                line,
                format!("`{}` lleva {} argumento(s) y le pasaste {}", op_name, n, args.len()),
                describe_op(&op_name),
            ))
        }
    };

    let reg_arg = |i: usize, p: &mut Parser| -> Result<Reg, DefError> {
        let a = &args[i];
        if a.contains('(') || a.contains('.') || a.contains('|') {
            return Err(err_fix(
                line,
                format!("`{}` no sirve como registro", a),
                "un registro es un nombre simple, como `x` o `q`; los tensores van en los \
                 argumentos de peso",
            ));
        }
        Ok(p.reg(a))
    };

    let op = match op_name.as_str() {
        "embed" => {
            arity(1)?;
            let table = tensor_ref(&args[0], line)?;
            Op::Embed { dst: p.reg(dst_name.as_ref().unwrap()), table }
        }
        "rms_norm" => {
            arity(2)?;
            let src = reg_arg(0, p)?;
            let weight = tensor_ref(&args[1], line)?;
            Op::RmsNorm { dst: p.reg(dst_name.as_ref().unwrap()), src, weight }
        }
        "matmul" => {
            arity(2)?;
            let src = reg_arg(0, p)?;
            let weight = tensor_ref(&args[1], line)?;
            Op::Matmul { dst: p.reg(dst_name.as_ref().unwrap()), src, weight }
        }
        "attention" => {
            arity(3)?;
            let (q, k, v) = (reg_arg(0, p)?, reg_arg(1, p)?, reg_arg(2, p)?);
            Op::Attention { dst: p.reg(dst_name.as_ref().unwrap()), q, k, v }
        }
        "last" => {
            arity(1)?;
            let src = reg_arg(0, p)?;
            Op::Last { dst: p.reg(dst_name.as_ref().unwrap()), src }
        }
        "copy" => {
            arity(1)?;
            let src = reg_arg(0, p)?;
            Op::Copy { dst: p.reg(dst_name.as_ref().unwrap()), src }
        }
        "add_bias" => {
            arity(2)?;
            Op::AddBias { dst: reg_arg(0, p)?, bias: tensor_ref(&args[1], line)? }
        }
        "norm_heads" => {
            arity(3)?;
            Op::NormHeads {
                dst: reg_arg(0, p)?,
                weight: tensor_ref(&args[1], line)?,
                heads: config_key(&args[2], line)?,
            }
        }
        "rope" => {
            arity(2)?;
            Op::Rope { dst: reg_arg(0, p)?, heads: config_key(&args[1], line)? }
        }
        "silu" | "gelu" | "gelu_tanh" | "relu" => {
            arity(1)?;
            let kind = match op_name.as_str() {
                "silu" => ActKind::Silu,
                "gelu" => ActKind::Gelu,
                "gelu_tanh" => ActKind::GeluTanh,
                _ => ActKind::Relu,
            };
            Op::Activation { dst: reg_arg(0, p)?, kind }
        }
        "mul" => {
            arity(2)?;
            let (dst, src) = (reg_arg(0, p)?, reg_arg(1, p)?);
            Op::Mul { dst, src }
        }
        "add" => {
            arity(2)?;
            let (dst, src) = (reg_arg(0, p)?, reg_arg(1, p)?);
            Op::Add { dst, src }
        }
        "scale" => {
            arity(2)?;
            Op::Scale { dst: reg_arg(0, p)?, factor: expr(&args[1], line)? }
        }
        other => {
            let hint = did_you_mean(other, Op::NAMES)
                .unwrap_or_else(|| format!("las operaciones son: {}", Op::NAMES.join(", ")));
            return Err(err_fix(line, format!("no existe la operación `{}`", other), hint));
        }
    };
    Ok(Step { op, line })
}

/// Una línea de ayuda por operación, para cuando la aridad no da.
fn describe_op(name: &str) -> String {
    let form = match name {
        "embed" => "dst = embed(tabla)",
        "rms_norm" => "dst = rms_norm(src, peso)",
        "matmul" => "dst = matmul(src, peso)",
        "attention" => "dst = attention(q, k, v)",
        "last" => "dst = last(src)",
        "copy" => "dst = copy(src)",
        "add_bias" => "add_bias(dst, sesgo)",
        "norm_heads" => "norm_heads(dst, peso, head_count)",
        "rope" => "rope(dst, head_count)",
        "silu" | "gelu" | "gelu_tanh" | "relu" => "silu(dst)",
        "mul" => "mul(dst, src)",
        "add" => "add(dst, src)",
        "scale" => "scale(dst, sqrt(embedding_length))",
        _ => return format!("las operaciones son: {}", Op::NAMES.join(", ")),
    };
    format!("la forma es `{}`", form)
}

/// Corta los argumentos por coma, respetando los paréntesis de `sqrt(...)`.
fn split_args(s: &str, line: usize) -> Result<Vec<String>, DefError> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut depth = 0i32;
    for c in s.chars() {
        match c {
            '(' => {
                depth += 1;
                cur.push(c);
            }
            ')' => {
                depth -= 1;
                if depth < 0 {
                    return Err(err(line, "hay un `)` de más"));
                }
                cur.push(c);
            }
            ',' if depth == 0 => {
                out.push(cur.trim().to_string());
                cur = String::new();
            }
            _ => cur.push(c),
        }
    }
    if depth != 0 {
        return Err(err_fix(line, "falta cerrar un paréntesis", "revisá los `(` y `)`"));
    }
    let last = cur.trim();
    if !last.is_empty() {
        out.push(last.to_string());
    }
    if out.iter().any(|a| a.is_empty()) {
        return Err(err_fix(line, "hay un argumento vacío", "sobra una coma"));
    }
    Ok(out)
}

/// `nombre.de.tensor` o `preferido | alternativo`.
fn tensor_ref(s: &str, line: usize) -> Result<TensorRef, DefError> {
    let mut parts = s.split('|').map(|p| p.trim()).filter(|p| !p.is_empty());
    let name = parts.next().ok_or_else(|| err(line, "falta el nombre del tensor"))?.to_string();
    let fallback = parts.next().map(|s| s.to_string());
    if parts.next().is_some() {
        return Err(err_fix(
            line,
            "un tensor admite un solo alternativo",
            "`output.weight | token_embd.weight` y nada más",
        ));
    }
    for n in [Some(&name), fallback.as_ref()].into_iter().flatten() {
        if n.contains('(') || n.contains(')') {
            return Err(err_fix(
                line,
                format!("`{}` no es un nombre de tensor", n),
                "los tensores se nombran igual que en el GGUF, como `blk.{i}.attn_q.weight`",
            ));
        }
    }
    Ok(TensorRef { name, fallback })
}

fn config_key(s: &str, line: usize) -> Result<ConfigKey, DefError> {
    ConfigKey::parse(s).ok_or_else(|| {
        let names: Vec<&str> = ConfigKey::ALL.iter().map(|(n, _)| *n).collect();
        let hint = did_you_mean(s, &names)
            .unwrap_or_else(|| format!("los valores del modelo son: {}", names.join(", ")));
        err_fix(line, format!("`{}` no es un valor del modelo", s), hint)
    })
}

fn expr(s: &str, line: usize) -> Result<Expr, DefError> {
    if let Some(inner) = s.strip_prefix("sqrt(").and_then(|r| r.strip_suffix(')')) {
        return Ok(Expr::Sqrt(config_key(inner.trim(), line)?));
    }
    if let Ok(n) = s.parse::<f32>() {
        if !n.is_finite() {
            return Err(err(line, format!("'{}' no es un número finito", s)));
        }
        return Ok(Expr::Literal(n));
    }
    if let Some(k) = ConfigKey::parse(s) {
        return Ok(Expr::Config(k));
    }
    Err(err_fix(
        line,
        format!("`{}` no es un número que se pueda calcular al cargar", s),
        "puede ser un literal, un valor del modelo, o `sqrt(<valor>)`",
    ))
}

/// Valida el programa entero: registros escritos antes de leerse, y las piezas obligatorias.
///
/// Esta es la parte que convierte un typo en un error con línea, en vez de en un tensor de ceros
/// que nadie nota hasta ver la salida.
fn validate(def: &ArchDef) -> Result<(), DefError> {
    let mut defined: BTreeSet<Reg> = BTreeSet::new();
    check_section(def, &def.prologue, &mut defined, "prologue")?;

    let residual = def.residual().ok_or_else(|| {
        err_fix(
            0,
            format!("'{}' nunca define el residual `x`", def.name),
            "el `prologue` tiene que dejar algo en `x`: es el tensor que atraviesa las capas",
        )
    })?;
    if !defined.contains(&residual) {
        return Err(err_fix(
            0,
            format!("'{}' no deja `x` listo al final del `prologue`", def.name),
            "empezá con `x = embed(token_embd.weight)`",
        ));
    }

    // `block` y `epilogue` arrancan de lo que dejó el prólogo: un registro que nace adentro del
    // bloque NO sobrevive a la capa siguiente ni llega al epílogo. Se valida así a propósito, para
    // que ninguna definición dependa de que el archivo de registros no se limpie.
    let after_prologue = defined.clone();
    let mut in_block = after_prologue.clone();
    check_section(def, &def.block, &mut in_block, "block")?;
    if !def.block.iter().any(|s| s.op.needs_layer_state()) {
        return Err(err_fix(
            0,
            format!("'{}' tiene un `block` sin atención", def.name),
            "un decoder sin `attention` no es un decoder; revisá si te faltó el paso",
        ));
    }
    if !in_block.contains(&residual) {
        return Err(err(0, format!("'{}' pierde `x` adentro del `block`", def.name)));
    }

    let mut in_epilogue = after_prologue;
    check_section(def, &def.epilogue, &mut in_epilogue, "epilogue")?;
    let logits = def.logits().ok_or_else(|| {
        err_fix(
            0,
            format!("'{}' nunca produce `logits`", def.name),
            "el `epilogue` tiene que terminar en `logits = matmul(...)`",
        )
    })?;
    if !in_epilogue.contains(&logits) {
        return Err(err(0, format!("'{}' no deja `logits` al final del `epilogue`", def.name)));
    }
    Ok(())
}

fn check_section(
    def: &ArchDef,
    steps: &[Step],
    defined: &mut BTreeSet<Reg>,
    section: &str,
) -> Result<(), DefError> {
    for step in steps {
        for r in step.op.reads() {
            if !defined.contains(&r) {
                let known: Vec<&str> = defined.iter().map(|d| def.reg_name(*d)).collect();
                let fix = if known.is_empty() {
                    format!(
                        "en `{}` todavía no hay ningún registro con valor; el primer paso tiene \
                         que producir uno",
                        section
                    )
                } else {
                    did_you_mean(def.reg_name(r), &known)
                        .unwrap_or_else(|| format!("con valor hay: {}", known.join(", ")))
                };
                return Err(err_fix(
                    step.line,
                    format!("se lee `{}` antes de escribirlo", def.reg_name(r)),
                    fix,
                ));
            }
        }
        defined.insert(step.op.dst());
    }
    Ok(())
}

/// SHA-256 propio, para no arrastrar una dependencia por veinte líneas.
///
/// Es la procedencia de la definición: quien publica una dice su sha, y quien la corre comprueba
/// que corrió esa y no otra. El mismo trato que le damos a los pesos (§4: el store de Ollama ya es
/// content-addressed, y el hash está en el nombre del archivo).
pub fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bits = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 =
                hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (i, v) in [a, b, c, d, e, f, g, hh].into_iter().enumerate() {
            h[i] = h[i].wrapping_add(v);
        }
    }
    h.iter().map(|w| format!("{:08x}", w)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Una definición mínima que pasa la validación, para no repetirla en cada test.
    const MINIMAL: &str = concat!(
        "arch prueba\n",
        "kind decoder\n",
        "prologue\n",
        "  x = embed(token_embd.weight)\n",
        "block\n",
        "  q = matmul(x, blk.{i}.attn_q.weight)\n",
        "  a = attention(q, q, q)\n",
        "  add(x, a)\n",
        "epilogue\n",
        "  x = last(x)\n",
        "  logits = matmul(x, output.weight)\n",
    );

    fn ok(text: &str) -> ArchDef {
        match parse(text, DefOrigin::Embedded) {
            Ok(d) => d,
            Err(e) => panic!("debía parsear y falló: {}", e),
        }
    }

    fn fails(text: &str) -> DefError {
        match parse(text, DefOrigin::Embedded) {
            Ok(_) => panic!("debía fallar y parseó"),
            Err(e) => e,
        }
    }

    /// Reemplaza una línea de la definición mínima, para probar un error por vez.
    fn with_line(old: &str, new: &str) -> String {
        assert!(MINIMAL.contains(old), "el fixture no tiene ese texto");
        MINIMAL.replace(old, new)
    }

    #[test]
    fn a_minimal_definition_parses() {
        let d = ok(MINIMAL);
        assert_eq!(d.name, "prueba");
        assert_eq!(d.kind, ArchKind::Decoder);
        assert_eq!(d.prologue.len(), 1);
        assert_eq!(d.block.len(), 3);
        assert_eq!(d.epilogue.len(), 2);
        assert!(d.residual().is_some());
        assert!(d.logits().is_some());
        assert_eq!(d.sha256.len(), 64);
    }

    // =====================================================================
    // I5-f: la gramática no admite condicionales, bucles ni efectos
    // =====================================================================

    /// **El criterio I5-f, como test.**
    ///
    /// No alcanza con decir en la doc que el formato no tiene control de flujo: hay que
    /// demostrarlo. Cada una de estas palabras es algo que un formato de configuración razonable
    /// podría haber tenido, y ninguna existe acá — así que bajar una definición que escribió otra
    /// persona no puede ejecutar nada.
    #[test]
    fn the_grammar_has_no_control_flow_and_no_effects() {
        for word in [
            "if", "unless", "while", "loop", "for", "match", "goto", "call", "exec", "eval",
            "shell", "run", "import", "include", "require", "open", "read_file", "write", "http",
            "fetch", "env",
        ] {
            let text = with_line("  add(x, a)", &format!("  add(x, a)\n  {}(x, a)", word));
            let e = fails(&text);
            assert!(
                e.message.contains("no existe la operación"),
                "`{}` tendría que ser una operación inexistente y dio: {}",
                word,
                e
            );
        }
    }

    /// Y lo que sí existe está enumerado: la lista de operaciones ES el contrato del formato.
    #[test]
    fn the_op_list_is_closed_and_sorted() {
        let mut sorted = Op::NAMES.to_vec();
        sorted.sort_unstable();
        assert_eq!(Op::NAMES, sorted.as_slice(), "la lista se lee en el error: ordenada");
        assert_eq!(Op::NAMES.len(), 16);
    }

    // =====================================================================
    // I5-d: una definición inválida falla temprano con el arreglo exacto
    // =====================================================================

    #[test]
    fn an_unknown_op_suggests_the_right_one() {
        let e = fails(&with_line("  add(x, a)", "  rmsnorm(x, a)"));
        assert!(e.message.contains("rmsnorm"), "{}", e);
        assert_eq!(e.fix.as_deref(), Some("¿quisiste decir `rms_norm`?"), "{}", e);
        assert_eq!(e.line, 8, "señala la línea del paso");
    }

    #[test]
    fn a_typo_in_a_register_is_caught_before_running_anything() {
        // `qq` no existe: sin esta validación daría un tensor vacío a mitad del forward.
        let e = fails(&with_line("  a = attention(q, q, q)", "  a = attention(qq, q, q)"));
        assert!(e.message.contains("se lee `qq` antes de escribirlo"), "{}", e);
        assert_eq!(e.fix.as_deref(), Some("¿quisiste decir `q`?"), "{}", e);
    }

    #[test]
    fn a_register_born_in_the_block_does_not_reach_the_epilogue() {
        // `a` existe adentro del bloque, pero el epílogo arranca de lo que dejó el prólogo.
        let e = fails(&with_line("  x = last(x)", "  x = last(a)"));
        assert!(e.message.contains("se lee `a` antes de escribirlo"), "{}", e);
    }

    #[test]
    fn attention_outside_the_block_is_rejected_with_the_reason() {
        let text = with_line("  x = last(x)", "  z = attention(x, x, x)\n  x = last(x)");
        let e = fails(&text);
        assert!(e.message.contains("sólo va adentro de `block`"), "{}", e);
        assert!(e.fix.unwrap().contains("cache"), "dice POR QUÉ, no sólo que no");
    }

    #[test]
    fn the_layer_placeholder_only_exists_inside_the_block() {
        let e = fails(&with_line(
            "  x = embed(token_embd.weight)",
            "  x = embed(blk.{i}.token_embd.weight)",
        ));
        assert!(e.message.contains("{i}"), "{}", e);
        assert!(e.fix.unwrap().contains("block"), "dice dónde sí va");
    }

    #[test]
    fn a_missing_section_says_which_and_what_each_one_is_for() {
        let text = MINIMAL.replace(
            "epilogue\n  x = last(x)\n  logits = matmul(x, output.weight)\n",
            "",
        );
        let e = fails(&text);
        assert!(e.message.contains("`epilogue`"), "{}", e);
        assert!(e.fix.unwrap().contains("una por capa"), "explica las tres");
    }

    #[test]
    fn a_duplicated_section_is_rejected() {
        let e = fails(&format!("{}block\n  add(x, x)\n", MINIMAL));
        assert!(e.message.contains("está dos veces"), "{}", e);
    }

    #[test]
    fn a_block_without_attention_is_not_a_decoder() {
        let e = fails(&with_line("  a = attention(q, q, q)", "  a = copy(q)"));
        assert!(e.message.contains("sin atención"), "{}", e);
    }

    #[test]
    fn a_definition_that_never_produces_logits_is_rejected() {
        let e = fails(&with_line(
            "  logits = matmul(x, output.weight)",
            "  y = matmul(x, output.weight)",
        ));
        assert!(e.message.contains("nunca produce `logits`"), "{}", e);
    }

    /// El residual se llama `x` y no es una convención de estilo: es el tensor que enlaza las
    /// capas, y sin él no hay forma de correr el programa. Los dos modos de que falte tienen su
    /// propio mensaje, porque el arreglo es distinto.
    #[test]
    fn a_definition_without_a_residual_is_rejected() {
        // 1) No existe en ninguna parte.
        let sin_x = concat!(
            "arch prueba
",
            "kind decoder
",
            "prologue
",
            "  y = embed(token_embd.weight)
",
            "block
",
            "  a = attention(y, y, y)
",
            "  add(y, a)
",
            "epilogue
",
            "  y = last(y)
",
            "  logits = matmul(y, output.weight)
",
        );
        let e = fails(sin_x);
        assert!(e.message.contains("nunca define el residual `x`"), "{}", e);
        assert!(e.fix.unwrap().contains("atraviesa las capas"), "dice para qué sirve");

        // 2) Existe más abajo, pero el prólogo no lo deja listo. Se dice así —y no «se lee `x`
        //    antes de escribirlo» en la línea del bloque— porque el arreglo está en el prólogo,
        //    que es donde el que escribe tiene que mirar.
        let e = fails(&with_line("  x = embed(token_embd.weight)", "  y = embed(token_embd.weight)"));
        assert!(e.message.contains("no deja `x` listo al final del `prologue`"), "{}", e);
        assert!(e.fix.unwrap().contains("x = embed("), "muestra la línea que falta");
    }

    #[test]
    fn wrong_arity_prints_the_shape_of_the_op() {
        let e = fails(&with_line("  a = attention(q, q, q)", "  a = attention(q, q)"));
        assert!(e.message.contains("3 argumento(s) y le pasaste 2"), "{}", e);
        assert_eq!(e.fix.as_deref(), Some("la forma es `dst = attention(q, k, v)`"));
    }

    #[test]
    fn a_producing_op_without_a_destination_is_rejected() {
        let e = fails(&with_line(
            "  q = matmul(x, blk.{i}.attn_q.weight)",
            "  matmul(x, blk.{i}.attn_q.weight)",
        ));
        assert!(e.message.contains("nadie lo recibe"), "{}", e);
    }

    #[test]
    fn an_in_place_op_with_a_destination_is_rejected() {
        let e = fails(&with_line("  add(x, a)", "  z = add(x, a)"));
        assert!(e.message.contains("no devuelve nada"), "{}", e);
        assert!(e.fix.unwrap().contains("sin `=`"));
    }

    /// `+=` es lo primero que escribe cualquiera que venga de otro lenguaje.
    #[test]
    fn compound_assignment_says_what_to_write_instead() {
        let e = fails(&with_line("  add(x, a)", "  x += a"));
        assert!(e.message.contains("no existe en este formato"), "{}", e);
        assert!(e.fix.unwrap().contains("add(dst, src)"));
    }

    #[test]
    fn a_tensor_where_a_register_goes_is_rejected() {
        let e = fails(&with_line("  add(x, a)", "  add(x, blk.0.attn_q.weight)"));
        assert!(e.message.contains("no sirve como registro"), "{}", e);
    }

    #[test]
    fn an_unknown_config_value_suggests_the_right_one() {
        let text = with_line("  add(x, a)", "  rope(x, head_conut)\n  add(x, a)");
        let e = fails(&text);
        assert_eq!(e.fix.as_deref(), Some("¿quisiste decir `head_count`?"), "{}", e);
    }

    #[test]
    fn a_step_outside_every_section_is_rejected() {
        let e = fails("arch p\nkind decoder\nadd(x, x)\n");
        assert!(e.message.contains("fuera de toda sección"), "{}", e);
    }

    #[test]
    fn an_unknown_model_kind_says_what_exists() {
        let e = fails("arch p\nkind encoder\n");
        assert!(e.message.contains("encoder"), "{}", e);
        assert!(e.fix.unwrap().contains("kind decoder"));
    }

    // =====================================================================
    // Piezas del formato
    // =====================================================================

    #[test]
    fn a_tensor_can_declare_one_fallback_and_only_one() {
        let d = ok(&with_line(
            "  logits = matmul(x, output.weight)",
            "  logits = matmul(x, output.weight | token_embd.weight)",
        ));
        let Op::Matmul { weight, .. } = &d.epilogue[1].op else { panic!("no es matmul") };
        assert_eq!(weight.name, "output.weight");
        assert_eq!(weight.fallback.as_deref(), Some("token_embd.weight"));

        let e = fails(&with_line(
            "  logits = matmul(x, output.weight)",
            "  logits = matmul(x, a.weight | b.weight | c.weight)",
        ));
        assert!(e.message.contains("un solo alternativo"), "{}", e);
    }

    #[test]
    fn the_layer_placeholder_is_substituted_on_both_names() {
        let t = TensorRef {
            name: "blk.{i}.attn_q.weight".into(),
            fallback: Some("blk.{i}.wq.weight".into()),
        };
        let (a, b) = t.resolve(7);
        assert_eq!(a, "blk.7.attn_q.weight");
        assert_eq!(b.as_deref(), Some("blk.7.wq.weight"));
    }

    #[test]
    fn params_are_numbers_and_nothing_else() {
        let d = ok(&MINIMAL.replace("kind decoder", "kind decoder\nparam sliding_window_type 6"));
        assert_eq!(d.param("sliding_window_type", 0.0), 6.0);
        assert_eq!(d.param("no_esta", 3.0), 3.0, "el default se usa si no está");

        let e = fails(&MINIMAL.replace("kind decoder", "kind decoder\nparam w tal_vez"));
        assert!(e.message.contains("no es un número"), "{}", e);
    }

    #[test]
    fn scale_accepts_a_literal_a_config_value_or_its_root() {
        for (arg, expected) in [
            ("2.5", Expr::Literal(2.5)),
            ("head_count", Expr::Config(ConfigKey::HeadCount)),
            ("sqrt(embedding_length)", Expr::Sqrt(ConfigKey::EmbeddingLength)),
        ] {
            let d = ok(&with_line(
                "  x = embed(token_embd.weight)",
                &format!("  x = embed(token_embd.weight)\n  scale(x, {})", arg),
            ));
            let Op::Scale { factor, .. } = d.prologue[1].op else { panic!("no es scale") };
            assert_eq!(factor, expected, "para `{}`", arg);
        }
        // Una expresión general no entra: el formato no es un lenguaje.
        let e = fails(&with_line(
            "  x = embed(token_embd.weight)",
            "  x = embed(token_embd.weight)\n  scale(x, head_count * 2)",
        ));
        assert!(e.message.contains("no es un número que se pueda calcular"), "{}", e);
    }

    #[test]
    fn comments_and_blank_lines_are_ignored_anywhere() {
        let text = format!(
            "# arriba\n{}\n   # al final\n",
            MINIMAL.replace("  add(x, a)", "  add(x, a)   # el residual")
        );
        let d = ok(&text);
        assert_eq!(d.block.len(), 3, "el comentario al final de línea no agrega un paso");
    }

    /// El sha es la procedencia: tiene que depender del texto y de nada más.
    #[test]
    fn the_sha_identifies_the_text() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // Más de un bloque de 64 bytes, para cubrir el segundo chunk y el relleno.
        assert_eq!(
            sha256_hex(&[b'a'; 200]),
            "c2a908d98f5df987ade41b5fce213067efbcc21ef2240212a41e54b5e7c28ae5"
        );
        let a = ok(MINIMAL);
        let b = ok(&format!("{}# un comentario más\n", MINIMAL));
        assert_ne!(a.sha256, b.sha256, "otro texto, otro sha, aunque el programa sea igual");
    }

    #[test]
    fn the_summary_says_where_it_came_from() {
        let d = ok(MINIMAL);
        let s = d.summary();
        assert!(s.contains("prueba"), "{}", s);
        assert!(s.contains("en el binario"), "{}", s);
        assert!(s.contains(&d.sha256[..12]), "{}", s);
    }

    #[test]
    fn errors_read_as_one_sentence() {
        let e = fails(&with_line("  add(x, a)", "  rmsnorm(x, a)"));
        let s = e.to_string();
        assert!(s.starts_with("línea 8: "), "{}", s);
        assert!(s.contains(" — ¿quisiste decir `rms_norm`?"), "{}", s);
    }

    #[test]
    fn edit_distance_is_the_usual_one() {
        assert_eq!(edit_distance("", "abc"), 3);
        assert_eq!(edit_distance("abc", "abc"), 0);
        assert_eq!(edit_distance("rmsnorm", "rms_norm"), 1);
        assert_eq!(edit_distance("kitten", "sitting"), 3);
    }
}
