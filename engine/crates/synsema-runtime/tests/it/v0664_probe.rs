#[test]
#[ignore = "manual 1M-row performance probe; run in release with --ignored --nocapture"]
fn local_parallel_probe() {
    let source = r#"
require time
let rows be []
each i in range(0, 1000000)
    set rows to append(rows, {"k": i % 100, "v": i * 0.5})
let t0 be now()
let one be summarize(rows, "k", {"t": sum_of("v")})
let t1 be now()
let parts be []
each j in range(0, 8)
    set parts to append(parts, slice(rows, j * 125000, (j + 1) * 125000))
let t2 be now()
let many be parallel_map((p) => summarize(p, "k", {"t": sum_of("v")}), parts, 8)
let eight be summarize(flatten(many), "k", {"t": sum_of("t")})
let t3 be now()
print(one == eight, length(one), length(eight), round_to(t1 - t0, 3), round_to(t3 - t2, 3))
"#;
    let run = synsema_runtime::engine::run_program(source, "v0664_probe.syn");
    assert!(run.success, "{:?}", run.errors);
    assert!(run.output[0].starts_with("true 100 100 "), "{:?}", run.output);
    println!("PROBE {}", run.output.join(" "));
}
