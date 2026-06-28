//! Conformidad de MongoDB (M3, backend NO-SQL) bajo la API propia `mongo_*`.
//!
//! Los tests de **capability/routing** corren SIEMPRE (sin servidor): el chequeo de
//! `db(scope)` precede a la conexión, y un connstring a un puerto muerto (con un
//! `serverSelectionTimeoutMS` corto) falla con un error de red — no de capability — lo que
//! prueba que el gate pasó y el ruteo a Mongo funciona. Los de **CRUD/tipos** necesitan un
//! Mongo real → `#[ignore]`, gated por `MONGO_URL`. Corre: `cargo test -- --ignored` con
//! `MONGO_URL=mongodb://synsema:synsema@localhost:27017/appdb?authSource=admin` seteada.

use synsema_runtime::engine::run_source;

fn mongo_url() -> Option<String> {
    std::env::var("MONGO_URL")
        .ok()
        .filter(|u| u.starts_with("mongodb://") || u.starts_with("mongodb+srv://"))
}

// =========================================================
// Capability + routing (sin servidor)
// =========================================================

/// `db_open("mongodb://…")` sin `require db` → violación con el scope canónico (sin
/// credenciales/puerto/query). Tampoco se auto-otorga en run.
#[test]
fn mongo_db_open_deny_without_require() {
    let r = run_source(
        "db_open(\"mongodb://user:pw@localhost:27017/appdb?authSource=admin\")",
        "<t>",
    );
    assert!(!r.success);
    assert_eq!(
        r.errors,
        vec!["Runtime error: Capability not granted: db(\"mongodb://localhost/appdb\")".to_string()]
    );
}

/// El scope URL es fiel: una grant a una base no cubre otra.
#[test]
fn mongo_scope_mismatch_deny() {
    let r = run_source(
        "require db(\"mongodb://localhost/appdb\")\ndb_open(\"mongodb://localhost/otra\")",
        "<t>",
    );
    assert!(!r.success);
    assert_eq!(
        r.errors,
        vec!["Runtime error: Capability not granted: db(\"mongodb://localhost/otra\")".to_string()]
    );
}

/// Con el grant adecuado el gate pasa y se rutea a Mongo; el puerto muerto (con un
/// server-selection timeout corto) da un error de RED — no de capability — → prueba "pasó el
/// gate + ruteo a Mongo" sin un servidor real.
#[test]
fn mongo_gate_passes_routing_to_mongo() {
    let r = run_source(
        "require db\ndb_open(\"mongodb://127.0.0.1:59999/nope?serverSelectionTimeoutMS=500\")",
        "<t>",
    );
    assert!(!r.success, "conectar a un puerto muerto debe fallar");
    assert!(
        !r.errors.iter().any(|e| e.contains("Capability not granted")),
        "no debe ser violación de capability (el gate pasó): {:?}",
        r.errors
    );
}

// =========================================================
// CRUD + tipos + _id (requieren Mongo real → #[ignore])
// =========================================================

/// CRUD completo + mapeo de tipos (nested, bytes↔Binary, decimal↔Decimal128, NULL) + `_id`
/// como text hex + filtrar por `_id`. Documentos/filtros = maps de Synsema ↔ BSON.
#[test]
#[ignore = "requiere un MongoDB real (MONGO_URL)"]
fn mongo_crud_and_types() {
    let url = mongo_url().expect("MONGO_URL no seteada");
    let src = format!(
        "require db(\"{url}\")\n\
         db_open(\"{url}\")\n\
         mongo_delete(\"syn_m3\", {{}})\n\
         let id be mongo_insert(\"syn_m3\", {{\"name\": \"Ana\", \"age\": 30, \"score\": 9.99d, \"tags\": [\"a\", \"b\"], \"blob\": bytes(\"hi\"), \"note\": nothing}})\n\
         print(type_of(id))\n\
         let one be mongo_find_one(\"syn_m3\", {{\"_id\": id}})\n\
         print(one[\"name\"])\n\
         print(text(one[\"age\"]))\n\
         print(type_of(one[\"score\"]))\n\
         print(text(length(one[\"tags\"])))\n\
         print(type_of(one[\"blob\"]) + \"=\" + decode(one[\"blob\"]))\n\
         print(text(one[\"note\"] == nothing))\n\
         let upd be mongo_update(\"syn_m3\", {{\"name\": \"Ana\"}}, {{\"$set\": {{\"age\": 31}}}})\n\
         print(text(upd[\"matched\"]) + \"/\" + text(upd[\"modified\"]))\n\
         let after be mongo_find_one(\"syn_m3\", {{\"name\": \"Ana\"}})\n\
         print(text(after[\"age\"]))\n\
         let n be mongo_count(\"syn_m3\", {{}})\n\
         print(text(n))\n\
         let del be mongo_delete(\"syn_m3\", {{\"name\": \"Ana\"}})\n\
         print(text(del[\"deleted\"]))\n\
         db_close()\n"
    );
    let r = run_source(&src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(
        r.output,
        vec![
            "text",       // _id es text (hex)
            "Ana",        // find_one por _id matchea
            "30",         // age int
            "decimal",    // 9.99 → decimal (Decimal128)
            "2",          // tags length
            "bytes=hi",   // blob round-trip (Binary → bytes; decode)
            "true",       // note es nothing (NULL)
            "1/1",        // update: matched 1, modified 1
            "31",         // age actualizado
            "1",          // count = 1
            "1",          // deleted = 1
        ]
        .into_iter()
        .map(String::from)
        .collect::<Vec<_>>()
    );
}

/// `mongo_find` con `opts` (filtro `$gte`, sort desc, limit) + `insert_many` + `aggregate`.
#[test]
#[ignore = "requiere un MongoDB real (MONGO_URL)"]
fn mongo_query_opts_and_aggregate() {
    let url = mongo_url().expect("MONGO_URL no seteada");
    let src = format!(
        "require db(\"{url}\")\n\
         db_open(\"{url}\")\n\
         mongo_delete(\"syn_m3q\", {{}})\n\
         let ids be mongo_insert_many(\"syn_m3q\", [{{\"v\": 5}}, {{\"v\": 25}}, {{\"v\": 15}}, {{\"v\": 10}}])\n\
         print(text(length(ids)))\n\
         let top be mongo_find(\"syn_m3q\", {{\"v\": {{\"$gte\": 10}}}}, {{\"sort\": {{\"v\": -1}}, \"limit\": 2}})\n\
         print(text(length(top)) + \":\" + text(top[0][\"v\"]) + \",\" + text(top[1][\"v\"]))\n\
         let agg be mongo_aggregate(\"syn_m3q\", [{{\"$group\": {{\"_id\": nothing, \"total\": {{\"$sum\": \"$v\"}}}}}}])\n\
         print(text(agg[0][\"total\"]))\n\
         let only be mongo_find(\"syn_m3q\", {{}}, {{\"fields\": {{\"v\": 1, \"_id\": 0}}, \"sort\": {{\"v\": 1}}, \"skip\": 1, \"limit\": 1}})\n\
         print(text(only[0][\"v\"]) + \":\" + text(contains(only[0], \"_id\")))\n\
         mongo_delete(\"syn_m3q\", {{}})\n\
         db_close()\n"
    );
    let r = run_source(&src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(
        r.output,
        vec![
            "4",       // insert_many → 4 ids
            "2:25,15", // sort desc + limit 2 → [25, 15]
            "55",      // $sum de 5+25+15+10
            "10:false" // skip 1 (orden asc: 5,10,15,25 → segundo=10), proyección quita _id
        ]
        .into_iter()
        .map(String::from)
        .collect::<Vec<_>>()
    );
}

/// `mongo_collections` lista la colección creada.
#[test]
#[ignore = "requiere un MongoDB real (MONGO_URL)"]
fn mongo_collections_lists_created() {
    let url = mongo_url().expect("MONGO_URL no seteada");
    let src = format!(
        "require db(\"{url}\")\n\
         db_open(\"{url}\")\n\
         mongo_insert(\"syn_m3_coll\", {{\"x\": 1}})\n\
         let cs be mongo_collections()\n\
         print(text(contains(cs, \"syn_m3_coll\")))\n\
         mongo_delete(\"syn_m3_coll\", {{}})\n\
         db_close()\n"
    );
    let r = run_source(&src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["true".to_string()]);
}

/// `sql()` sobre una conexión Mongo → error claro (sin sorpresas silenciosas).
#[test]
#[ignore = "requiere un MongoDB real (MONGO_URL)"]
fn sql_over_mongo_errors() {
    let url = mongo_url().expect("MONGO_URL no seteada");
    let src = format!(
        "require db(\"{url}\")\n\
         db_open(\"{url}\")\n\
         let r be sql(\"SELECT 1\")\n"
    );
    let r = run_source(&src, "<t>");
    assert!(!r.success, "sql() sobre Mongo debe fallar");
    assert!(
        r.errors.iter().any(|e| e.contains("MongoDB connection") && e.contains("mongo_")),
        "el error debe orientar a usar mongo_*: {:?}",
        r.errors
    );
}
