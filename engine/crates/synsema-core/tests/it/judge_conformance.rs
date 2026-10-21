//! Conformidad del primitivo `judge` (System One) en el intérprete de core, sin red:
//! sintaxis (bloque, verbos, preposiciones, `or nothing`, palabra blanda), forma del
//! resultado, camino OFFLINE (available: false + confianza 0 + nothing) y camino CABLEADO
//! por callback (una llamada por bloque, pedido con la forma correcta, respuestas a ids).
//! Spec: specs/system-one-judge.md §4, §10.1.

use std::cell::RefCell;
use std::rc::Rc;

use synsema_core::interpreter::{run_source, Interpreter};
use synsema_core::judge::{JudgeAnswer, JudgeKind, JudgeRequest, JudgeResponse};
use synsema_core::parser::parse_source;

const BLOCK: &str = r#"let ticket be {"subject": "Payouts failing", "text": "I want my money back NOW"}
let v be judge ticket
    refund: whether "The customer is asking for money back"
    team:   choose "Which team should handle this?" between {
                "billing":   "Payments, invoicing, refunds",
                "technical": "Bugs, outages, integrations"
            } or nothing
    anger:  rate "How frustrated is the customer?" across ["Calm", "Frustrated", "Very angry"]
"#;

fn assert_output(source: &str, expected: &[&str]) {
    let r = run_source(source, "<test>");
    assert!(r.success, "El programa falló: {:?}\nfuente:\n{}", r.errors, source);
    let exp: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
    assert_eq!(r.output, exp, "fuente:\n{}", source);
}

fn assert_error_contains(source: &str, needle: &str) {
    let r = run_source(source, "<test>");
    assert!(!r.success, "Se esperaba fallo.\nfuente:\n{}", source);
    assert!(
        r.errors.iter().any(|e| e.contains(needle)),
        "Se esperaba un error con '{}', got {:?}\nfuente:\n{}",
        needle,
        r.errors,
        source
    );
}

// ---- Offline: la degradación honesta ---------------------------------------------------

#[test]
fn offline_answers_are_unavailable_with_zero_confidence_and_nothing() {
    let src = format!(
        "{}print(v.refund.kind)\nprint(v.refund.available)\nprint(v.refund.probability)\n\
         print(v.team.kind)\nprint(v.team.choice)\nprint(v.team.confidence == 0)\n\
         print(v.anger.kind)\nprint(v.anger.score)\nprint(v.anger.level)\nprint(length(v.anger.levels))\n\
         print(v.anger.levels[2])\nprint(judge_available())\nprint(judge_usage())\nprint(judge_model())\n",
        BLOCK
    );
    assert_output(
        &src,
        &[
            "whether", "false", "nothing", "choose", "nothing", "true", "rate", "nothing", "nothing", "3",
            "Very angry", "false", "0", "nothing",
        ],
    );
}

#[test]
fn offline_confidence_gate_routes_to_the_human_by_itself() {
    // El patrón insignia: `judge` mide, el humano decide. Offline la confianza es 0, así
    // que la compuerta manda al humano sin una línea extra.
    let src = format!(
        "{}when confidence of v.team < 0.8\n    print(\"human\")\notherwise\n    print(\"auto\")\n",
        BLOCK
    );
    assert_output(&src, &["human"]);
}

#[test]
fn offline_direct_comparison_fails_loud_instead_of_branching_silently() {
    let src = format!("{}when v.refund.probability > 0.5\n    print(\"refund\")\n", BLOCK);
    assert_error_contains(&src, "Unsupported operation: nothing > number");
}

// ---- Sintaxis: preposiciones, escape, ids, verbos --------------------------------------

#[test]
fn rate_with_between_is_a_parse_error_with_the_fix() {
    assert_error_contains(
        "let v be judge \"x\"\n    a: rate \"How much?\" between [\"low\", \"high\"]\n",
        "'rate' takes ordered levels",
    );
}

#[test]
fn choose_with_across_is_a_parse_error_with_the_fix() {
    assert_error_contains(
        "let v be judge \"x\"\n    a: choose \"Which?\" across {\"a\": \"A\", \"b\": \"B\"}\n",
        "'choose' takes unordered options",
    );
}

#[test]
fn or_must_be_followed_by_nothing() {
    assert_error_contains(
        "let v be judge \"x\"\n    a: choose \"Which?\" between {\"a\": \"A\", \"b\": \"B\"} or other\n",
        "only `or nothing` is allowed",
    );
}

#[test]
fn rate_has_no_escape_level() {
    assert_error_contains(
        "let v be judge \"x\"\n    a: rate \"How much?\" across [\"low\", \"high\"] or nothing\n",
        "only applies to 'choose'",
    );
}

#[test]
fn whether_takes_no_options() {
    assert_error_contains(
        "let v be judge \"x\"\n    a: whether \"Is it?\" between {\"a\": \"A\", \"b\": \"B\"}\n",
        "'whether' takes no options",
    );
}

#[test]
fn duplicate_question_ids_are_rejected() {
    assert_error_contains(
        "let v be judge \"x\"\n    a: whether \"Is it?\"\n    a: whether \"Is it really?\"\n",
        "declared twice",
    );
}

#[test]
fn judge_without_block_is_a_parse_error() {
    assert_error_contains("let v be judge \"x\"\nprint(1)\n", "Expected an indented block of questions");
}

#[test]
fn unknown_verb_inside_judge_is_a_parse_error() {
    assert_error_contains(
        "let v be judge \"x\"\n    a: guess \"Is it?\"\n",
        "expected 'whether', 'choose' or 'rate'",
    );
}

#[test]
fn a_single_question_block_is_three_lines_and_fine() {
    assert_output(
        "let v be judge \"x\"\n    a: whether \"Is it?\"\nprint(length(keys(v)))\nprint(v.a.available)\n",
        &["1", "false"],
    );
}

// ---- Palabra blanda: `judge` y las del bloque siguen siendo nombres afuera --------------

#[test]
fn judge_is_an_ordinary_identifier_outside_its_construction() {
    assert_output("let judge be 5\nprint(judge + 1)\n", &["6"]);
    assert_output("task f(a, b)\n    give a + b\nlet judge be 1\nprint(f(judge, 2))\n", &["3"]);
    assert_output("let judge be {\"x\": 1}\nprint(judge.x)\nprint(x of judge)\n", &["1", "1"]);
    assert_output("let judge be [7]\nprint(judge[0])\nprint(judge)\n", &["7", "[7]"]);
}

#[test]
fn block_words_are_ordinary_identifiers_outside_the_block() {
    assert_output(
        "let rate be 2\nlet across be 3\nlet whether be 4\nlet between be 5\nlet choose be 6\n\
         print(rate * across + whether + between + choose)\n",
        &["21"],
    );
}

// ---- Validación en runtime (criteria dinámicas), antes de gastar la llamada --------------

#[test]
fn choose_needs_two_options_even_though_the_api_accepts_one() {
    assert_error_contains(
        "let opts be {\"only\": \"One\"}\nlet v be judge \"x\"\n    a: choose \"Which?\" between opts\n",
        "at least 2 options",
    );
}

#[test]
fn rate_accepts_at_most_ten_levels() {
    assert_error_contains(
        "let lv be [\"a\", \"b\", \"c\", \"d\", \"e\", \"f\", \"g\", \"h\", \"i\", \"j\", \"k\"]\n\
         let v be judge \"x\"\n    a: rate \"How?\" across lv\n",
        "at most 10 levels",
    );
}

#[test]
fn duplicate_levels_are_rejected() {
    assert_error_contains(
        "let v be judge \"x\"\n    a: rate \"How?\" across [\"Calm\", \"Calm\", \"Angry\"]\n",
        "declared twice",
    );
}

#[test]
fn state_must_be_text_map_or_list() {
    assert_error_contains(
        "let v be judge 42\n    a: whether \"Is it big?\"\n",
        "state must be a text, a map or a list",
    );
}

#[test]
fn an_option_named_nothing_cannot_combine_with_or_nothing() {
    assert_error_contains(
        "let v be judge \"x\"\n    a: choose \"Which?\" between {\"none\": \"n\", \"b\": \"B\"} or nothing\n",
        "rename the option",
    );
}

// ---- Cableado por callback: una llamada por bloque, pedido correcto, respuestas a ids ----

struct Wired {
    output: Vec<String>,
    error: Option<String>,
    requests: Vec<JudgeRequest>,
}

fn run_wired(
    src: &str,
    answer: fn(&JudgeRequest) -> Result<Option<JudgeResponse>, String>,
) -> Wired {
    let src = src.to_string();
    std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(move || {
            let program = parse_source(&src, "<test>").unwrap_or_else(|e| panic!("parse: {:?}", e));
            let mut interp = Interpreter::new();
            let seen: Rc<RefCell<Vec<JudgeRequest>>> = Rc::new(RefCell::new(Vec::new()));
            let seen2 = seen.clone();
            interp.set_judge_callback(Rc::new(move |req| {
                seen2.borrow_mut().push(req.clone());
                answer(req)
            }));
            interp.set_judge_model_callback(Rc::new(|| Some("jev-1.13.0".to_string())));
            interp.set_judge_usage_callback(Rc::new(|| 438));
            let error = match interp.execute(&program) {
                Ok(_) => None,
                Err(synsema_core::interpreter::Control::Error(e)) => Some(e.to_string()),
                Err(_) => Some("give/stop escaped to the top".to_string()),
            };
            let requests = seen.borrow().clone();
            Wired {
                output: std::mem::take(&mut interp.output),
                error,
                requests,
            }
        })
        .expect("thread")
        .join()
        .expect("join")
}

fn ticket_answers(req: &JudgeRequest) -> Result<Option<JudgeResponse>, String> {
    let answers = req
        .questions
        .iter()
        .map(|q| match q.kind {
            JudgeKind::Whether => JudgeAnswer::Whether { probability: 0.97 },
            JudgeKind::Choose => JudgeAnswer::Choose {
                choice: Some("billing".into()),
                probabilities: vec![("billing".into(), 0.97), ("technical".into(), 0.03), ("none".into(),0.0)],
                confidence: 0.93,
            },
            JudgeKind::Rate => JudgeAnswer::Rate {
                score: 1.98,
                level: "Very angry".into(),
                probabilities: vec![("Calm".into(), 0.0), ("Frustrated".into(), 0.02), ("Very angry".into(), 0.98)],
                confidence: 0.96,
            },
        })
        .collect();
    Ok(Some(JudgeResponse { answers, model: "jev-1.13.0".into(), input_tokens: 438, output_tokens: 61 }))
}

#[test]
fn wired_block_is_one_call_with_the_declared_shape() {
    let src = format!(
        "{}print(v.team.choice)\nprint(v.anger.level)\nprint(v.refund.available)\n\
         print(v.refund.probability > 0.9)\nprint(v.team.probabilities.none == 0)\n\
         print(confidence of v.team > 0.9)\nprint(judge_available())\nprint(judge_model())\nprint(judge_usage())\n\
         when confidence of v.team < 0.8\n    print(\"human\")\notherwise\n    print(\"auto\")\n",
        BLOCK
    );
    let w = run_wired(&src, ticket_answers);
    assert!(w.error.is_none(), "{:?}", w.error);
    assert_eq!(
        w.output,
        ["billing", "Very angry", "true", "true", "true", "true", "true", "jev-1.13.0", "438", "auto"]
    );
    assert_eq!(w.requests.len(), 1, "un bloque = una llamada");
    let req = &w.requests[0];
    assert_eq!(req.state["subject"], "Payouts failing", "el state viaja como JSON estructurado");
    let ids: Vec<&str> = req.questions.iter().map(|q| q.id.as_str()).collect();
    assert_eq!(ids, ["refund", "team", "anger"]);
    assert_eq!(req.questions[0].kind, JudgeKind::Whether);
    assert_eq!(req.questions[0].instruction, "The customer is asking for money back");
    assert_eq!(req.questions[1].kind, JudgeKind::Choose);
    assert!(req.questions[1].escape, "`or nothing` llega al provider");
    let opts: Vec<&str> = req.questions[1].options.iter().map(|o| o.id.as_str()).collect();
    assert_eq!(opts, ["billing", "technical"]);
    assert_eq!(
        req.questions[1].options[0].description.as_ref().and_then(|d| d.as_str()),
        Some("Payments, invoicing, refunds")
    );
    assert_eq!(req.questions[2].kind, JudgeKind::Rate);
    let lv: Vec<&str> = req.questions[2].options.iter().map(|o| o.id.as_str()).collect();
    assert_eq!(lv, ["Calm", "Frustrated", "Very angry"]);
    assert!(req.questions[2].options[0].description.is_none(), "forma lista: el id es la descripción");
}

#[test]
fn escape_answer_becomes_nothing_in_the_program() {
    fn escaped(req: &JudgeRequest) -> Result<Option<JudgeResponse>, String> {
        let answers = req
            .questions
            .iter()
            .map(|q| match q.kind {
                JudgeKind::Choose => JudgeAnswer::Choose {
                    choice: None,
                    probabilities: vec![("billing".into(), 0.01), ("technical".into(), 0.01), ("none".into(),0.98)],
                    confidence: 0.97,
                },
                JudgeKind::Whether => JudgeAnswer::Whether { probability: 0.1 },
                JudgeKind::Rate => JudgeAnswer::Rate {
                    score: 0.0,
                    level: "Calm".into(),
                    probabilities: vec![("Calm".into(), 1.0), ("Frustrated".into(), 0.0), ("Very angry".into(), 0.0)],
                    confidence: 1.0,
                },
            })
            .collect();
        Ok(Some(JudgeResponse { answers, model: "m".into(), input_tokens: 1, output_tokens: 1 }))
    }
    let src = format!(
        "{}print(v.team.choice == nothing)\nprint(v.team.available)\nprint(v.team.probabilities.none > 0.9)\n",
        BLOCK
    );
    let w = run_wired(&src, escaped);
    assert!(w.error.is_none(), "{:?}", w.error);
    assert_eq!(w.output, ["true", "true", "true"]);
}

#[test]
fn provider_unavailable_degrades_like_offline_but_judge_available_stays_true() {
    fn unavailable(_: &JudgeRequest) -> Result<Option<JudgeResponse>, String> {
        Ok(None)
    }
    let src = format!("{}print(v.team.available)\nprint(v.team.confidence == 0)\nprint(judge_available())\n", BLOCK);
    let w = run_wired(&src, unavailable);
    assert!(w.error.is_none(), "{:?}", w.error);
    assert_eq!(w.output, ["false", "true", "true"]);
}

#[test]
fn provider_rejection_is_a_runtime_error_with_the_vendor_message() {
    fn rejected(_: &JudgeRequest) -> Result<Option<JudgeResponse>, String> {
        Err("judge API rejected the request (400): Too many score levels. Must have at most 10 levels.".into())
    }
    let w = run_wired(BLOCK, rejected);
    let e = w.error.expect("debe fallar");
    assert!(e.contains("Too many score levels"), "{}", e);
}

#[test]
fn map_form_levels_carry_ids_and_descriptions() {
    fn by_id(req: &JudgeRequest) -> Result<Option<JudgeResponse>, String> {
        let q = &req.questions[0];
        let ids: Vec<&str> = q.options.iter().map(|o| o.id.as_str()).collect();
        assert_eq!(ids, ["calm", "upset", "furious"]);
        assert_eq!(q.options[1].description.as_ref().and_then(|d| d.as_str()), Some("Repeat contact, annoyed"));
        Ok(Some(JudgeResponse {
            answers: vec![JudgeAnswer::Rate {
                score: 1.1,
                level: "upset".into(),
                probabilities: vec![("calm".into(), 0.1), ("upset".into(), 0.7), ("furious".into(), 0.2)],
                confidence: 0.55,
            }],
            model: "m".into(),
            input_tokens: 1,
            output_tokens: 1,
        }))
    }
    let src = "let v be judge \"second time writing, annoyed\"\n    anger: rate \"How frustrated?\" across {\n        \"calm\": \"Polite\",\n        \"upset\": \"Repeat contact, annoyed\",\n        \"furious\": \"Caps, threats\"\n    }\nprint(v.anger.level)\nprint(v.anger.probabilities.upset)\nprint(v.anger.levels[1])\n";
    let w = run_wired(src, by_id);
    assert!(w.error.is_none(), "{:?}", w.error);
    assert_eq!(w.output, ["upset", "0.7", "upset"]);
}

// ---- `synsema check`: los límites antes de correr, y los avisos ---------------------------

fn check(src: &str) -> Result<Vec<String>, String> {
    let program = parse_source(src, "<test>").unwrap_or_else(|e| panic!("parse: {:?}", e));
    let load = |_resolved: &str, raw: &str| -> Result<synsema_core::ast::Program, String> {
        Err(format!("module not found: {}", raw))
    };
    synsema_core::templates::check_program_static_with_warnings(&program, "<test>", &load)
        .map(|(_counts, warnings)| warnings)
}

#[test]
fn check_fails_on_literal_limits_before_any_call() {
    let e = check("let v be judge \"x\"\n    a: choose \"Which?\" between {\"only\": \"One\"}\n").unwrap_err();
    assert!(e.contains("at least 2") && e.contains("<test>:2"), "{}", e);
    let e = check(
        "let v be judge \"x\"\n    a: rate \"How?\" across [\"a\", \"b\", \"c\", \"d\", \"e\", \"f\", \"g\", \"h\", \"i\", \"j\", \"k\"]\n",
    )
    .unwrap_err();
    assert!(e.contains("at most 10"), "{}", e);
    let e = check("let v be judge \"x\"\n    a: rate \"How?\" across [\"Calm\", \"Calm\", \"Angry\"]\n").unwrap_err();
    assert!(e.contains("declared twice"), "{}", e);
    let e = check("let v be judge 42\n    a: whether \"Is it big?\"\n").unwrap_err();
    assert!(e.contains("literal number"), "{}", e);
    let e = check("let v be judge \"x\"\n    a: whether \"   \"\n").unwrap_err();
    assert!(e.contains("instruction is empty"), "{}", e);
}

#[test]
fn check_warns_on_negation_arithmetic_empty_state_and_batchable_blocks() {
    let w = check(
        "let ticket be \"x\"\nlet a be judge ticket\n    pii: whether \"Is the message free of personal data?\"\n\
         let b be judge ticket\n    big: whether \"The order total exceeds 100 USD\"\nlet c be judge \"\"\n    q: whether \"Is it?\"\n",
    )
    .unwrap();
    assert!(w.iter().any(|m| m.contains("negative") && m.contains("'pii'")), "{:?}", w);
    assert!(w.iter().any(|m| m.contains("arithmetic") && m.contains("'big'")), "{:?}", w);
    assert!(w.iter().any(|m| m.contains("empty state")), "{:?}", w);
    assert!(w.iter().any(|m| m.contains("`judge ticket` appears 2 times")), "{:?}", w);
}

#[test]
fn check_is_quiet_on_a_clean_block_and_dynamic_criteria() {
    let w = check(&format!("{}print(1)\n", BLOCK)).unwrap();
    assert!(w.is_empty(), "{:?}", w);
    // criteria dinámicas: nada que cobrar en estático (se cobra en runtime)
    let w = check("let opts be {\"only\": \"One\"}\nlet v be judge \"x\"\n    a: choose \"Which?\" between opts\n").unwrap();
    assert!(w.is_empty(), "{:?}", w);
}

// ---- `decide` servido por el juez (SYNSEMA_JUDGE_DECIDE) ---------------------------------

#[test]
fn decide_via_judge_returns_the_chosen_option_and_asks_a_choose() {
    let src = "let d be decide between [\"alpha\", \"beta\"] given {\"speed\": \"matters\"}\nprint(d)\n";
    let out = std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(move || {
            let program = parse_source(src, "<test>").unwrap();
            let mut interp = Interpreter::new();
            let seen: Rc<RefCell<Vec<JudgeRequest>>> = Rc::new(RefCell::new(Vec::new()));
            let seen2 = seen.clone();
            interp.set_judge_callback(Rc::new(move |req| {
                seen2.borrow_mut().push(req.clone());
                Ok(Some(JudgeResponse {
                    answers: vec![JudgeAnswer::Choose {
                        choice: Some("beta".into()),
                        probabilities: vec![("alpha".into(), 0.2), ("beta".into(), 0.8)],
                        confidence: 0.6,
                    }],
                    model: "m".into(),
                    input_tokens: 1,
                    output_tokens: 1,
                }))
            }));
            interp.set_decide_via_judge(true);
            interp.execute(&program).map_err(|_| "error").unwrap();
            let reqs = seen.borrow().clone();
            (std::mem::take(&mut interp.output), reqs)
        })
        .unwrap()
        .join()
        .unwrap();
    assert_eq!(out.0, ["beta"]);
    assert_eq!(out.1.len(), 1);
    let q = &out.1[0].questions[0];
    assert_eq!(q.kind, JudgeKind::Choose);
    let ids: Vec<&str> = q.options.iter().map(|o| o.id.as_str()).collect();
    assert_eq!(ids, ["alpha", "beta"]);
    assert_eq!(out.1[0].state["speed"], "matters", "el `given` viaja como state");
}

#[test]
fn decide_via_judge_falls_back_to_the_llm_path_when_unavailable() {
    let src = "let d be decide between [\"alpha\", \"beta\"] given \"x\"\nprint(d)\n";
    let out = std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(move || {
            let program = parse_source(src, "<test>").unwrap();
            let mut interp = Interpreter::new();
            interp.set_judge_callback(Rc::new(|_| Ok(None)));
            interp.set_decide_via_judge(true);
            interp.execute(&program).map_err(|_| "error").unwrap();
            std::mem::take(&mut interp.output)
        })
        .unwrap()
        .join()
        .unwrap();
    assert_eq!(out, ["[decision pending]"], "sin juez disponible sigue el camino LLM (offline: placeholder)");
}

#[test]
fn instruction_can_be_a_structured_map() {
    fn check(req: &JudgeRequest) -> Result<Option<JudgeResponse>, String> {
        let q = &req.questions[0];
        assert!(q.instruction.is_object(), "la instrucción estructurada viaja como objeto: {}", q.instruction);
        assert_eq!(q.instruction["record"]["name"], "Ana");
        Ok(Some(JudgeResponse {
            answers: vec![JudgeAnswer::Whether { probability: 0.74 }],
            model: "m".into(),
            input_tokens: 1,
            output_tokens: 1,
        }))
    }
    let src = "let r be {\"name\": \"Ana\"}\nlet v be judge \"resume of Ana Ruiz\"\n    same: whether {\"question\": \"Is the resume for the same person as `record`?\", \"record\": r}\nprint(v.same.probability)\n";
    let w = run_wired(src, check);
    assert!(w.error.is_none(), "{:?}", w.error);
    assert_eq!(w.output, ["0.74"]);
}
