//! Los módulos que el cargador ya leyó para EJECUTAR, por ruta resuelta: el fuente exacto y los
//! `use` que tiene. Es lo que usa `program_sha` del recibo (`receipt()`) para no volver a leer ni
//! parsear nada: el hash sale de los mismos bytes que corrieron. Por proceso (lo comparten los
//! workers de `serve`); manda la primera carga de cada ruta.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use crate::ast::{NodeKind, Program};

type Entry = (Arc<str>, Vec<String>);

fn table() -> &'static Mutex<HashMap<String, Entry>> {
    static T: OnceLock<Mutex<HashMap<String, Entry>>> = OnceLock::new();
    T.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Las rutas de los `use` de un programa, en el orden en que aparecen (también los anidados
/// en tasks o ramas): el mismo recorrido que el chequeo estático.
pub fn use_paths(program: &Program) -> Vec<String> {
    let mut uses = Vec::new();
    for stmt in &program.statements {
        crate::ast_api::walk(stmt, &mut |n| {
            if let NodeKind::UseImport { path, .. } = &n.kind {
                uses.push(path.clone());
            }
        });
    }
    uses
}

/// Anota un módulo recién cargado (sólo la primera vez por ruta).
pub fn record(resolved: &str, source: &str, program: &Program) {
    if let Ok(mut t) = table().lock() {
        if !t.contains_key(resolved) {
            t.insert(resolved.to_string(), (Arc::from(source), use_paths(program)));
        }
    }
}

/// El fuente y los `use` de un módulo ya cargado.
pub fn get(resolved: &str) -> Option<Entry> {
    table().lock().ok()?.get(resolved).cloned()
}
