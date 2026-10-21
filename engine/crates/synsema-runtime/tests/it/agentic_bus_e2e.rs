//! El bus de eventos es UNO por programa, se mire desde donde se mire: el intérprete
//! principal, un worker de `parallel_map`, un tick de cron (modo `run`) y un agente
//! `spawn`eado publican y suscriben contra el mismo bus. Un loop de agente escrito
//! como task (no como `agent`) usa exactamente las mismas primitivas.

use synsema_runtime::engine::{run_program, run_source};

fn out(src: &str, name: &str) -> Vec<String> {
    let r = run_program(src, name);
    assert!(r.success, "{:?}\n{}", r.errors, src);
    r.output
}

#[test]
fn bus_works_without_a_swarm_too() {
    // run_source (conform/test): sin swarm real, pero el bus existe in-process.
    let src = "let sub be bus_subscribe(\"t\")\nbus_publish(\"t\", 1)\nprint(bus_recv(sub, 1)[\"data\"])\n";
    let r = run_source(src, "<bus-nosw>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output[0], "1");
}

#[test]
fn parallel_map_workers_publish_on_the_program_bus() {
    let src = r#"task ping(n)
    bus_publish("work.done", n)
    give n * 2

let sub be bus_subscribe("work.*")
let results be parallel_map(ping, [1, 2, 3])
print(length(results))
let seen be 0
while seen < 3
    let ev be bus_recv(sub, 5)
    when ev == nothing
        stop
    set seen to seen + 1
print(seen)
"#;
    let o = out(src, "<bus-parallel>");
    assert_eq!(o, vec!["3", "3"], "{:?}", o);
}

#[test]
fn cron_ticks_in_run_mode_publish_on_the_program_bus() {
    let src = r#"require time

task tick()
    bus_publish("cron.tick", now())

let sub be bus_subscribe("cron.tick")
cron_every(0.2, tick)
let ev be bus_recv(sub, 5)
print(when ev == nothing then "missed" otherwise ev["topic"])
cron_cancel("tick")
"#;
    let o = out(src, "<bus-cron>");
    assert_eq!(o, vec!["cron.tick"], "{:?}", o);
}

#[test]
fn a_task_shaped_agent_loop_uses_select_and_the_bus_like_any_code() {
    // Un "agente" que es una task con su propio loop de eventos (no `agent`/`spawn`):
    // recibe trabajo por el bus, lo procesa, publica el resultado; el `spawn`eado
    // real sólo lo alimenta. Mismas primitivas, sin privilegios especiales.
    let src = r#"require time

agent Feeder
    sleep(0.1)
    bus_publish("jobs", 21)
    bus_publish("jobs", "quit")

task worker_loop()
    let jobs be bus_subscribe("jobs")
    let done be 0
    while true
        let ev be select({"jobs": jobs}, 5)
        when ev == nothing
            stop
        when ev["data"] == "quit"
            stop
        set done to done + ev["data"] * 2
    give done

spawn Feeder
print(worker_loop())
"#;
    let o = out(src, "<task-agent>");
    assert_eq!(o, vec!["42"], "{:?}", o);
}
