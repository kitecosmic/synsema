//! v0.6.56 (migas §5): cada fila de la tabla de `f32` (`tests/it/v0656_f32.rs`) da lo mismo en la
//! VM, en el tree-walker de referencia y con el nivel nativo. Es un binario aparte porque el modo
//! referencia y el JIT son del proceso: acá las tres pasadas van en orden, en un solo test.

#[path = "it/v0656_f32.rs"]
mod table;

fn pass(mode: &str) {
    for (name, row) in table::ALL {
        if let Err(e) = std::panic::catch_unwind(row) {
            let msg = e
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default();
            panic!("{} en {}: {}", name, mode, msg);
        }
    }
}

#[test]
fn the_f32_table_holds_in_vm_reference_and_jit() {
    pass("vm");
    synsema_core::interpreter::set_reference_mode(true);
    pass("ref");
    synsema_core::interpreter::set_reference_mode(false);
    synsema_jit::install();
    synsema_core::native_tier::set_eager(true);
    let before = synsema_core::native_tier::stats();
    pass("jit");
    let after = synsema_core::native_tier::stats();
    assert_ne!(format!("{:?}", before), format!("{:?}", after), "el nivel nativo no compiló nada");
}
