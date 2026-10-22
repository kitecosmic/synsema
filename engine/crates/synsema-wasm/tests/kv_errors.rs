//! v0.6.46 (backlog §10): un `kv.get` del host que falla se leía como "la clave no está". En
//! `state_get` devolvía `nothing`, y al abrir una memoria declarada la cargaba vacía: la próxima
//! escritura pisaba la que estaba guardada. Ahora es un error, y la memoria no se abre.

use std::cell::RefCell;
use std::rc::Rc;

use synsema_stdlib::hostcap::{self, HostProvider};
use synsema_wasm::{run, RunOptions};

/// Un host con KV cuya lectura falla (o no, con `fail: false`) y que anota lo que se le escribe.
struct Kv {
    fail: bool,
    stored: Option<String>,
    writes: RefCell<Vec<String>>,
}

struct Host(Rc<Kv>);

impl HostProvider for Host {
    fn offers(&self, what: &str) -> bool {
        what == "kv"
    }
    fn kv_get(&self, _ns: &str, _key: &str) -> Option<Result<Option<String>, String>> {
        Some(if self.0.fail { Err("kv down".to_string()) } else { Ok(self.0.stored.clone()) })
    }
    fn kv_set(&self, ns: &str, key: &str, value: &str) -> Option<Result<(), String>> {
        self.0.writes.borrow_mut().push(format!("{}/{}={}", ns, key, value));
        Some(Ok(()))
    }
}

fn run_with(fail: bool, src: &str) -> (synsema_wasm::Report, Rc<Kv>) {
    run_stored(fail, None, src)
}

fn run_stored(fail: bool, stored: Option<&str>, src: &str) -> (synsema_wasm::Report, Rc<Kv>) {
    let kv = Rc::new(Kv { fail, stored: stored.map(str::to_string), writes: RefCell::new(Vec::new()) });
    hostcap::install(Some(Rc::new(Host(kv.clone()))));
    let report = run(src, &RunOptions::new("kv.syn"));
    hostcap::install(None);
    (report, kv)
}

#[test]
fn a_failed_kv_get_is_an_error_not_nothing() {
    let (r, _) = run_with(true, "print(state_get(\"k\", \"default\"))\n");
    assert!(!r.ok && r.errors.iter().any(|e| e.contains("state_get") && e.contains("kv down")), "{:?}", r.errors);
    // El control: la clave que no está sigue siendo el default.
    let (r, _) = run_with(false, "print(state_get(\"k\", \"default\"))\n");
    assert!(r.ok, "{:?}", r.errors);
    assert_eq!(r.output, vec!["default".to_string()]);
}

#[test]
fn a_memory_that_failed_to_load_is_not_written_over() {
    let src = "require memory(\"notas\")\nremember(\"context\", \"nota\")\n";
    let (r, kv) = run_with(true, src);
    assert!(!r.ok && r.errors.iter().any(|e| e.contains("could not be loaded") && e.contains("kv.get failed: kv down")), "{:?}", r.errors);
    assert!(kv.writes.borrow().is_empty(), "no se pisa lo guardado: {:?}", kv.writes.borrow());
    let (r, kv) = run_with(false, src);
    assert!(r.ok, "{:?}", r.errors);
    assert!(!kv.writes.borrow().is_empty(), "el control escribe la memoria");
}

/// Ronda 2 de cf1, R2-B3: un valor guardado que no es JSON (cortado, escrito por otro) no es "no
/// está". `state_incr` daba 1 y la memoria se abría vacía; las dos cosas pisaban lo guardado.
#[test]
fn a_stored_value_that_is_not_json_is_an_error() {
    let (r, kv) = run_stored(false, Some("{\"cortado"), "print(state_incr(\"k\"))\n");
    assert!(!r.ok && r.errors.iter().any(|e| e.contains("state_incr") && e.contains("not JSON")), "{:?}", r.errors);
    assert!(kv.writes.borrow().is_empty(), "{:?}", kv.writes.borrow());
    let (r, _) = run_stored(false, Some("41"), "print(state_incr(\"k\"))\n");
    assert!(r.ok, "{:?}", r.errors);
    assert_eq!(r.output, vec!["42".to_string()]);

    let src = "require memory(\"notas\")\nremember(\"context\", \"nota\")\n";
    let (r, kv) = run_stored(false, Some("{\"entries\": {"), src);
    assert!(!r.ok && r.errors.iter().any(|e| e.contains("could not be loaded (the stored memory is not readable") && !e.contains("kv.get failed")), "{:?}", r.errors);
    assert!(kv.writes.borrow().is_empty(), "{:?}", kv.writes.borrow());
}
