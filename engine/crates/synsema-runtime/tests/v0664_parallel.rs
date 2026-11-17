use synsema_runtime::engine::run_program;

fn output(source: &str) -> Vec<String> {
    let run = run_program(source, "v0664_parallel.syn");
    assert!(run.success, "{:?}", run.errors);
    run.output
}

#[test]
fn unused_global_tables_do_not_change_parallel_results() {
    assert_eq!(output(r#"
let unused be [{"k": 1}, {"k": 2}]
let parts be [[1, 2], [3, 4]]
print(parallel_map((p) => length(p), parts, 2))
"#), ["[2, 2]"]);
}

#[test]
fn direct_data_and_transitive_task_globals_still_arrive() {
    assert_eq!(output(r#"
let offset be 10
let irrelevant be [{"k": 1}]
print(parallel_map((p) => length(p) + offset, [[1], [2, 3]], 2))
task helper(p)
    give length(p) + offset
print(parallel_map((p) => helper(p), [[1], [2, 3]], 2))
"#), ["[11, 12]", "[11, 12]"]);
}

#[test]
fn numeric_leaf_rows_copy_on_worker_write() {
    assert_eq!(output(r#"
let row be {"k": 1}
task work(p)
    set p["k"] to p["k"] + 1
    give p["k"]
print(parallel_map(work, [row, row], 2))
print(row.k)
"#), ["[2, 2]", "1"]);
}

#[test]
fn callback_maps_and_local_closures_keep_the_full_snapshot() {
    assert_eq!(output(r#"
let base be 5
task helper(p)
    give p + base
let config be {"f": helper}
print(parallel_map((p) => config.f(p), [1, 2], 2))
task outer(factor)
    let work be (p) => p * factor
    give parallel_map(work, [1, 2], 2)
print(outer(3))
"#), ["[6, 7]", "[3, 6]"]);
}
