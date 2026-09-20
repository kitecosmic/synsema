//! wasi-stub — deja un módulo `wasm32-wasip1` con SÓLO los imports de WASI que Vela v0.3.0 admite.
//!
//! Vela `dev` (v0.3.0, `pkg/wasm/guest_imports.go`) rechaza al cargar cualquier módulo que
//! DECLARE un import de `wasi_snapshot_preview1` fuera de una lista cerrada de ocho:
//! `args_get`, `args_sizes_get`, `clock_time_get`, `environ_get`, `environ_sizes_get`, `fd_write`,
//! `proc_exit`, `random_get`. El rechazo es por declarar, no por llamar. Nuestro guest declara 21:
//! los 15 sobrantes (`fd_close`, `fd_fdstat_get`, `fd_filestat_get`, `fd_prestat_get`,
//! `fd_prestat_dir_name`, `fd_read`, `fd_readdir`, `path_*` ×7, `poll_oneoff`) los enlaza `std::fs`
//! desde el motor aunque el techo `stdout` (`no_fs: true`) impida que el programa los alcance.
//!
//! Esta herramienta reemplaza cada import de función de `wasi_snapshot_preview1` que NO esté en la
//! lista permitida por una función LOCAL del mismo tipo que devuelve `ERRNO_NOSYS` (52) — salvo
//! `fd_prestat_get`, que devuelve `ERRNO_BADF` (8): es lo que hace parar limpio el escaneo de
//! preopens de std al arrancar (un `NOSYS` ahí abortaría). El resto del módulo no se toca: mismas
//! funciones, mismos data segments (el app slot de `tools/embed.syn` sigue siendo un tramo
//! contiguo), misma memoria exportada. Falla si tras el proceso queda un import fuera de la lista
//! o si el módulo importa algo de otro módulo que no sea WASI.
//!
//!   wasi-stub <in.wasm> <out.wasm> [--allow a,b,c] [--errno-nosys 52]
//!
//! `build.rs` no puede hacerlo (corre antes de compilar): va como paso posterior al build, y en
//! `ci.yml`/`release.yml` antes de sondear y publicar el asset. Dependencia `walrus`, sólo acá:
//! nunca al lock del motor ni al del guest (regla de dos ejes).
use std::collections::BTreeSet;
use std::process::ExitCode;

use walrus::{FunctionId, FunctionKind, ImportKind, Module, ModuleConfig, ValType};

/// El módulo de WASI preview1: el único que Vela define en su linker (`DefineWasi()`).
pub const WASI_MODULE: &str = "wasi_snapshot_preview1";

/// La lista cerrada de `guest_imports.go` (Vela `dev`, v0.3.0). CAMBIARLA es un cambio de ABI de
/// Vela, no nuestro: si Horizen la amplía, se amplía acá y en la sonda.
pub const DEFAULT_ALLOW: &[&str] = &[
    "args_get",
    "args_sizes_get",
    "clock_time_get",
    "environ_get",
    "environ_sizes_get",
    "fd_write",
    "proc_exit",
    "random_get",
];

/// `__WASI_ERRNO_NOSYS`: "function not supported".
pub const ERRNO_NOSYS: i32 = 52;
/// `__WASI_ERRNO_BADF`: "bad file descriptor". `fd_prestat_get(fd)` devolviéndolo es cómo std
/// (wasi-libc `__wasilibc_populate_preopens`) descubre que no hay más preopens y termina.
pub const ERRNO_BADF: i32 = 8;

/// Qué hizo el proceso, para el resumen y para los tests.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Imports reemplazados por un stub local, con el errno que devuelven.
    pub replaced: Vec<(String, i32)>,
    /// Imports de WASI que quedaron declarados (todos en la lista permitida).
    pub kept: Vec<String>,
}

/// Reemplaza los imports de función de WASI fuera de `allow` por stubs que devuelven `errno_nosys`
/// (`fd_prestat_get` → `ERRNO_BADF`). Falla ante un import que no sea de `wasi_snapshot_preview1`,
/// ante un import que no sea de función, o ante una firma que no sepa stubbear.
pub fn stub(module: &mut Module, allow: &BTreeSet<String>, errno_nosys: i32) -> Result<Report, String> {
    // Primero se recorre y se decide; después se muta (no se puede mutar `module.funcs` mientras
    // se itera `module.imports`).
    let mut to_replace: Vec<(FunctionId, String)> = Vec::new();
    let mut kept: Vec<String> = Vec::new();
    for import in module.imports.iter() {
        if import.module != WASI_MODULE {
            return Err(format!(
                "the module imports `{}.{}`: Vela's linker defines only `{}` (DefineWasi), nothing else can be provided",
                import.module, import.name, WASI_MODULE
            ));
        }
        match import.kind {
            ImportKind::Function(fid) => {
                if allow.contains(&import.name) {
                    kept.push(import.name.clone());
                } else {
                    to_replace.push((fid, import.name.clone()));
                }
            }
            _ => {
                return Err(format!(
                    "the module imports `{}.{}`, which is not a function: WASI provides functions only",
                    import.module, import.name
                ))
            }
        }
    }

    let mut replaced = Vec::with_capacity(to_replace.len());
    for (fid, name) in to_replace {
        let errno = if name == "fd_prestat_get" { ERRNO_BADF } else { errno_nosys };
        // Un stub devuelve el errno en cada resultado i32 de la firma; una firma sin resultado
        // (como `proc_exit`) queda como cuerpo vacío. Cualquier otra cosa no es una función de
        // WASI preview1 y es mejor fallar que inventar un valor.
        let results: Vec<ValType> = {
            let f = module.funcs.get(fid);
            let tid = match &f.kind {
                FunctionKind::Import(imp) => imp.ty,
                _ => return Err(format!("`{}` is not an imported function", name)),
            };
            module.types.get(tid).results().to_vec()
        };
        for r in &results {
            if *r != ValType::I32 {
                return Err(format!(
                    "`{}.{}` returns {:?}: only i32 errno results can be stubbed",
                    WASI_MODULE, name, r
                ));
            }
        }
        module
            .replace_imported_func(fid, |(body, _args)| {
                for _ in &results {
                    body.i32_const(errno);
                }
            })
            .map_err(|e| format!("replacing `{}.{}`: {}", WASI_MODULE, name, e))?;
        replaced.push((name, errno));
    }

    // Verificación final: lo que quede declarado tiene que estar TODO en la lista.
    for import in module.imports.iter() {
        let ok = import.module == WASI_MODULE
            && matches!(import.kind, ImportKind::Function(_))
            && allow.contains(&import.name);
        if !ok {
            return Err(format!(
                "after stubbing, the module still declares `{}.{}`, which is outside the allowed set",
                import.module, import.name
            ));
        }
    }
    replaced.sort();
    kept.sort();
    Ok(Report { replaced, kept })
}

/// Configuración de walrus para que la salida sea tan escueta como la entrada: sin sección
/// `producers` ni `name` (el perfil `wasm` del guest ya va con `strip = true`), así el módulo no
/// crece y los bytes son deterministas para un mismo input.
pub fn module_config() -> ModuleConfig {
    let mut config = ModuleConfig::new();
    config.generate_producers_section(false);
    config.generate_name_section(false);
    config.generate_dwarf(false);
    config
}

/// `wasi-stub <in> <out> [--allow a,b,c] [--errno-nosys N]`
#[derive(Debug, PartialEq, Eq)]
pub struct Options {
    pub input: String,
    pub output: String,
    pub allow: BTreeSet<String>,
    pub errno_nosys: i32,
}

pub fn parse_args<I: IntoIterator<Item = String>>(args: I) -> Result<Options, String> {
    let mut positional: Vec<String> = Vec::new();
    let mut allow: BTreeSet<String> = DEFAULT_ALLOW.iter().map(|s| s.to_string()).collect();
    let mut errno_nosys = ERRNO_NOSYS;
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--allow" => {
                let v = it.next().ok_or("--allow needs a comma-separated list of import names")?;
                allow = v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
                if allow.is_empty() {
                    return Err("--allow: the list is empty".to_string());
                }
            }
            "--errno-nosys" => {
                let v = it.next().ok_or("--errno-nosys needs a number")?;
                errno_nosys = v.parse::<i32>().map_err(|_| format!("--errno-nosys: `{}` is not an integer", v))?;
            }
            "-h" | "--help" => return Err(USAGE.to_string()),
            s if s.starts_with("--") => return Err(format!("unknown option `{}`\n{}", s, USAGE)),
            _ => positional.push(a),
        }
    }
    if positional.len() != 2 {
        return Err(USAGE.to_string());
    }
    let output = positional.pop().unwrap();
    let input = positional.pop().unwrap();
    Ok(Options { input, output, allow, errno_nosys })
}

const USAGE: &str = "usage: wasi-stub <in.wasm> <out.wasm> [--allow name,name,...] [--errno-nosys 52]\n\
  Replaces every wasi_snapshot_preview1 function import outside the allowed set by a local stub\n\
  returning ENOSYS (fd_prestat_get returns EBADF). Default allowed set (Vela v0.3.0):\n\
  args_get, args_sizes_get, clock_time_get, environ_get, environ_sizes_get, fd_write, proc_exit, random_get";

fn run(opts: &Options) -> Result<(), String> {
    let input = std::fs::read(&opts.input).map_err(|e| format!("{}: {}", opts.input, e))?;
    let mut module = module_config()
        .parse(&input)
        .map_err(|e| format!("{}: not a WebAssembly module walrus can parse: {}", opts.input, e))?;
    let before = module.imports.iter().count();
    let report = stub(&mut module, &opts.allow, opts.errno_nosys)?;
    let output = module.emit_wasm();
    // Re-parsear la salida es la validación más barata que hay sin runtime: walrus valida con
    // wasmparser al leer. Node y wasmtime-go instancian el módulo en las sondas.
    let check = module_config()
        .parse(&output)
        .map_err(|e| format!("internal error: the stubbed module does not validate: {}", e))?;
    let after = check.imports.iter().count();
    std::fs::write(&opts.output, &output).map_err(|e| format!("{}: {}", opts.output, e))?;

    println!("wasi-stub: {} -> {}", opts.input, opts.output);
    if report.replaced.is_empty() {
        println!("  replaced (0): nothing to do, every import was already in the allowed set");
    } else {
        let list: Vec<String> = report
            .replaced
            .iter()
            .map(|(n, e)| format!("{} -> {}({})", n, if *e == ERRNO_BADF { "EBADF" } else { "ENOSYS" }, e))
            .collect();
        println!("  replaced ({}): {}", report.replaced.len(), list.join(", "));
    }
    println!("  kept ({}): {}", report.kept.len(), report.kept.join(", "));
    println!("  imports: {} -> {}; bytes: {} -> {}", before, after, input.len(), output.len());
    Ok(())
}

fn main() -> ExitCode {
    let opts = match parse_args(std::env::args().skip(1)) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{}", e);
            return ExitCode::from(2);
        }
    };
    match run(&opts) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("wasi-stub: {}", e);
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use walrus::ir::{BinaryOp, Instr, Value};
    use walrus::{FunctionBuilder, LocalFunction};

    fn allow_default() -> BTreeSet<String> {
        DEFAULT_ALLOW.iter().map(|s| s.to_string()).collect()
    }

    /// Un módulo mínimo construido con walrus: memoria exportada, `fd_read` y `fd_write`
    /// importados de WASI con la firma real `(i32, i32, i32, i32) -> i32`, y una función exportada
    /// `run` que llama a los dos (así los imports están en uso, como en el guest).
    fn module_with(imports: &[(&str, &str)]) -> Vec<u8> {
        let mut m = Module::with_config(module_config());
        let ty = m.types.add(&[ValType::I32, ValType::I32, ValType::I32, ValType::I32], &[ValType::I32]);
        let mem = m.memories.add_local(false, false, 1, None, None);
        m.exports.add("memory", mem);
        let mut fids = Vec::new();
        for (module, name) in imports {
            let (fid, _) = m.add_import_func(module, name, ty);
            fids.push(fid);
        }
        let mut b = FunctionBuilder::new(&mut m.types, &[], &[ValType::I32]);
        {
            let mut body = b.func_body();
            body.i32_const(0);
            for fid in &fids {
                body.i32_const(0).i32_const(0).i32_const(0).i32_const(0).call(*fid).binop(BinaryOp::I32Add);
            }
        }
        let run = b.finish(vec![], &mut m.funcs);
        m.exports.add("run", run);
        m.emit_wasm()
    }

    fn import_names(wasm: &[u8]) -> Vec<String> {
        let m = module_config().parse(wasm).expect("valid module");
        let mut v: Vec<String> = m.imports.iter().map(|i| format!("{}.{}", i.module, i.name)).collect();
        v.sort();
        v
    }

    fn validate(wasm: &[u8]) {
        wasmparser::Validator::new().validate_all(wasm).expect("the stubbed module validates under wasmparser");
    }

    /// El primer instr del cuerpo de la función `name` (ya local) es `i32.const errno`.
    fn first_const_of(m: &Module, name: &str) -> Option<i32> {
        // El import ya no existe; buscamos la función local que llama `run` en la posición del
        // import original. Alcanza con recorrer todas las locales y devolver la que sea un stub.
        for f in m.funcs.iter() {
            if let FunctionKind::Local(lf) = &f.kind {
                if is_stub(lf) {
                    let block = lf.block(lf.entry_block());
                    if let Some((Instr::Const(c), _)) = block.instrs.first() {
                        if let Value::I32(v) = c.value {
                            let _ = name;
                            return Some(v);
                        }
                    }
                }
            }
        }
        None
    }

    fn is_stub(lf: &LocalFunction) -> bool {
        let block = lf.block(lf.entry_block());
        block.instrs.len() == 1 && matches!(block.instrs[0].0, Instr::Const(_))
    }

    #[test]
    fn only_the_import_outside_the_list_is_replaced() {
        let wasm = module_with(&[(WASI_MODULE, "fd_read"), (WASI_MODULE, "fd_write")]);
        assert_eq!(import_names(&wasm), vec!["wasi_snapshot_preview1.fd_read", "wasi_snapshot_preview1.fd_write"]);
        let mut m = module_config().parse(&wasm).unwrap();
        let report = stub(&mut m, &allow_default(), ERRNO_NOSYS).unwrap();
        assert_eq!(report.replaced, vec![("fd_read".to_string(), ERRNO_NOSYS)]);
        assert_eq!(report.kept, vec!["fd_write".to_string()]);
        assert_eq!(first_const_of(&m, "fd_read"), Some(ERRNO_NOSYS));
        let out = m.emit_wasm();
        validate(&out);
        assert_eq!(import_names(&out), vec!["wasi_snapshot_preview1.fd_write"]);
        // Los exports siguen ahí: la memoria y `run`.
        let check = module_config().parse(&out).unwrap();
        let names: Vec<&str> = check.exports.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"memory") && names.contains(&"run"));
    }

    #[test]
    fn fd_prestat_get_returns_ebadf_not_enosys() {
        let wasm = module_with(&[(WASI_MODULE, "fd_prestat_get"), (WASI_MODULE, "fd_write")]);
        let mut m = module_config().parse(&wasm).unwrap();
        let report = stub(&mut m, &allow_default(), ERRNO_NOSYS).unwrap();
        assert_eq!(report.replaced, vec![("fd_prestat_get".to_string(), ERRNO_BADF)]);
        assert_eq!(first_const_of(&m, "fd_prestat_get"), Some(ERRNO_BADF));
        validate(&m.emit_wasm());
    }

    #[test]
    fn a_custom_errno_and_a_custom_allow_list_are_honoured() {
        let wasm = module_with(&[(WASI_MODULE, "fd_read"), (WASI_MODULE, "fd_write")]);
        let mut m = module_config().parse(&wasm).unwrap();
        let allow: BTreeSet<String> = ["fd_read".to_string()].into_iter().collect();
        let report = stub(&mut m, &allow, 58).unwrap();
        assert_eq!(report.replaced, vec![("fd_write".to_string(), 58)]);
        assert_eq!(report.kept, vec!["fd_read".to_string()]);
        let out = m.emit_wasm();
        validate(&out);
        assert_eq!(import_names(&out), vec!["wasi_snapshot_preview1.fd_read"]);
    }

    #[test]
    fn nothing_to_do_when_every_import_is_allowed() {
        let wasm = module_with(&[(WASI_MODULE, "fd_write")]);
        let mut m = module_config().parse(&wasm).unwrap();
        let report = stub(&mut m, &allow_default(), ERRNO_NOSYS).unwrap();
        assert!(report.replaced.is_empty());
        assert_eq!(report.kept, vec!["fd_write".to_string()]);
    }

    #[test]
    fn an_import_from_another_module_is_an_error() {
        let wasm = module_with(&[(WASI_MODULE, "fd_write"), ("synsema_host", "http")]);
        let mut m = module_config().parse(&wasm).unwrap();
        let err = stub(&mut m, &allow_default(), ERRNO_NOSYS).unwrap_err();
        assert!(err.contains("synsema_host.http"), "{}", err);
    }

    #[test]
    fn a_stubbed_module_is_deterministic() {
        let wasm = module_with(&[(WASI_MODULE, "fd_read"), (WASI_MODULE, "poll_oneoff"), (WASI_MODULE, "fd_write")]);
        let mut a = module_config().parse(&wasm).unwrap();
        stub(&mut a, &allow_default(), ERRNO_NOSYS).unwrap();
        let mut b = module_config().parse(&wasm).unwrap();
        stub(&mut b, &allow_default(), ERRNO_NOSYS).unwrap();
        assert_eq!(a.emit_wasm(), b.emit_wasm());
    }

    #[test]
    fn args_parse_defaults_and_overrides() {
        let o = parse_args(["in.wasm".to_string(), "out.wasm".to_string()]).unwrap();
        assert_eq!(o.input, "in.wasm");
        assert_eq!(o.output, "out.wasm");
        assert_eq!(o.errno_nosys, ERRNO_NOSYS);
        assert_eq!(o.allow.len(), DEFAULT_ALLOW.len());
        assert!(o.allow.contains("fd_write") && !o.allow.contains("fd_read"));

        let o = parse_args(
            ["a".to_string(), "--allow".to_string(), "fd_write, fd_read".to_string(), "b".to_string(), "--errno-nosys".to_string(), "58".to_string()],
        )
        .unwrap();
        assert_eq!((o.input.as_str(), o.output.as_str(), o.errno_nosys), ("a", "b", 58));
        assert_eq!(o.allow, ["fd_read".to_string(), "fd_write".to_string()].into_iter().collect());

        assert!(parse_args(["only-one".to_string()]).is_err());
        assert!(parse_args(["a".to_string(), "b".to_string(), "--bogus".to_string()]).is_err());
        assert!(parse_args(["a".to_string(), "b".to_string(), "--errno-nosys".to_string(), "x".to_string()]).is_err());
    }
}
