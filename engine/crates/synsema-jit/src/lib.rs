//! El nivel nativo de Synsema (F4 de specs/compute-rendimiento.md): compila con Cranelift las tasks
//! calientes que la VM ya especializó y vuelve a la VM ante cualquier cosa que no pueda hacer.
//!
//! - `lower`: los análisis y la traducción a Cranelift. Sin `unsafe` (`forbid`).
//! - `abi`: el único módulo con `unsafe` (el contexto, la salida a la VM y la llamada).
//!
//! Core no depende de este crate: el binario lo instala al arrancar (`install`) y core lo usa por el
//! trait seguro `synsema_core::native_tier::NativeTier`. En wasm no existe.

#![deny(unsafe_code)]

#[allow(unsafe_code)]
mod abi;
mod lower;

use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};

use cranelift_codegen::ir::types::I64;
use cranelift_codegen::ir::AbiParam;
use cranelift_codegen::settings::{self, Configurable};
use cranelift_codegen::Context;
use cranelift_frontend::FunctionBuilderContext;
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{FuncId, Linkage, Module};
use synsema_core::native_tier::{self, NUnit, NativeCode, NativeTier};

/// Cuánto código de máquina puede generar un hilo; después, todo sigue en la VM.
const MAX_CODE_BYTES: usize = 64 << 20;

struct Jit {
    module: JITModule,
    deopt: FuncId,
    bytes: usize,
}

thread_local! {
    /// El módulo de este hilo (`None` dentro: la plataforma no dejó crearlo; todo en la VM).
    static JIT: RefCell<Option<Option<Jit>>> = const { RefCell::new(None) };
}

/// Nombres únicos para las funciones (un módulo por hilo, que no se libera).
static NEXT: AtomicU64 = AtomicU64::new(0);

fn new_jit() -> Option<Jit> {
    let mut flags = settings::builder();
    flags.set("opt_level", "speed").ok()?;
    flags.set("enable_verifier", "true").ok()?;
    // Como `JITBuilder::with_flags`: relocaciones de largo alcance y, en x86-64, PIC.
    flags.set("use_colocated_libcalls", "false").ok()?;
    flags.set("is_pic", if cfg!(target_arch = "x86_64") { "true" } else { "false" }).ok()?;
    let isa = cranelift_native::builder().ok()?.finish(settings::Flags::new(flags)).ok()?;
    let mut jb = JITBuilder::with_isa(isa, cranelift_module::default_libcall_names());
    jb.symbol("synsema_jit_deopt", abi::synsema_jit_deopt as *const u8);
    let mut module = JITModule::new(jb);
    let mut sig = module.make_signature();
    for _ in 0..5 {
        sig.params.push(AbiParam::new(I64));
    }
    let deopt = module.declare_function("synsema_jit_deopt", Linkage::Import, &sig).ok()?;
    Some(Jit { module, deopt, bytes: 0 })
}

fn compile_in(jit: &mut Jit, unit: &NUnit) -> Option<abi::Compiled> {
    if jit.bytes > MAX_CODE_BYTES {
        return None;
    }
    let mut plans = lower::plan(unit)?;
    let uid = NEXT.fetch_add(1, Ordering::Relaxed);
    let m = &mut jit.module;
    let mut ids = Vec::with_capacity(unit.funcs.len());
    let mut sigs = Vec::with_capacity(unit.funcs.len());
    for (i, f) in unit.funcs.iter().enumerate() {
        // La convención de la plataforma (`make_signature`): la misma con la que se declara, se
        // compila y se llama.
        let mut sig = m.make_signature();
        lower::signature(&mut sig, f.nparams as usize);
        ids.push(m.declare_function(&format!("synsema_f{uid}_{i}"), Linkage::Local, &sig).ok()?);
        sigs.push(sig);
    }
    let mut esig = m.make_signature();
    esig.params.push(AbiParam::new(I64));
    esig.params.push(AbiParam::new(I64));
    esig.returns.push(AbiParam::new(I64));
    let entry = m.declare_function(&format!("synsema_e{uid}"), Linkage::Local, &esig).ok()?;

    let mut ctx = Context::new();
    let mut fbctx = FunctionBuilderContext::new();
    let mut bytes = 0usize;
    for i in 0..unit.funcs.len() {
        ctx.clear();
        ctx.func.signature = sigs[i].clone();
        let callees: Vec<_> = ids.iter().map(|id| m.declare_func_in_func(*id, &mut ctx.func)).collect();
        let deopt = m.declare_func_in_func(jit.deopt, &mut ctx.func);
        lower::build(unit, i, &mut plans, &mut ctx.func, &mut fbctx, &callees, deopt, m.target_config())?;
        if !lower::check_memory(&ctx.func, false) {
            return None;
        }
        m.define_function(ids[i], &mut ctx).ok()?;
        bytes += ctx.compiled_code().map_or(0, |c| c.code_info().total_size as usize);
    }
    ctx.clear();
    ctx.func.signature = esig;
    let f0 = m.declare_func_in_func(ids[0], &mut ctx.func);
    lower::build_entry(&mut ctx.func, &mut fbctx, f0, unit.funcs[0].nparams as usize, m.target_config());
    if !lower::check_memory(&ctx.func, true) {
        return None;
    }
    m.define_function(entry, &mut ctx).ok()?;
    m.finalize_definitions().ok()?;
    jit.bytes += bytes;
    Some(abi::Compiled {
        entry: m.get_finalized_function(entry),
        nparams: unit.funcs[0].nparams as usize,
        ret: plans[0].ret,
        points: plans.into_iter().map(|p| p.points).collect(),
    })
}

/// El nivel nativo con Cranelift.
struct Tier;

impl NativeTier for Tier {
    fn compile(&self, unit: &NUnit) -> Option<Box<dyn NativeCode>> {
        JIT.with(|cell| {
            let mut slot = cell.borrow_mut();
            let jit = slot.get_or_insert_with(new_jit).as_mut()?;
            let c = compile_in(jit, unit)?;
            Some(Box::new(c) as Box<dyn NativeCode>)
        })
    }
}

static TIER: Tier = Tier;

/// Instala el nivel nativo para todo el proceso (x86-64 y aarch64; en otras plataformas, nada).
pub fn install() {
    if cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
        native_tier::install(&TIER);
    }
}
