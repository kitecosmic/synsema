//! v0.6.66: tests de labels del filtro columnar; inspeccionan Interpreter y env del host.

#[test]
fn a_private_predicate_labels_both_mask_and_selected_table() {
    use synsema_core::interpreter::{env_get, Control, Interpreter};
    use synsema_core::labels::{label_deep, label_display_raw, strip_deep};
    let src = r#"let t be table([{"v": 1}, {"v": 2}, {"v": 3}])
let cutoff be private(2, "owner")
let m be column_mask(t, "v", (x) => x > cutoff)
let r be where(t, m)"#;
    let program = synsema_core::parser::parse_source(src, "<v0666>").unwrap();
    let mut interp = Interpreter::new();
    interp.set_labels(true);
    interp.set_labels_detail_to_program(true);
    if let Err(Control::Error(e)) = interp.execute(&program) {
        panic!("{}", e);
    }
    for name in ["m", "r"] {
        let v = env_get(&interp.global_env, name).unwrap();
        assert_eq!(label_display_raw(&label_deep(&v)), "owner", "{}", name);
        if name == "r" { assert_eq!(strip_deep(&v).to_string(), "[{v: 3}]"); }
    }
}

#[test]
fn direct_private_operand_labels_mask_and_selected_table() {
    use synsema_core::interpreter::{env_get, Control, Interpreter};
    use synsema_core::labels::{label_deep, label_display_raw};
    let src = r#"let t be table([{"v": 1}, {"v": 2}, {"v": 3}])
let cutoff be private(2, "owner")
let m be column_mask(t, "v", ">", cutoff)
let r be where(t, m)"#;
    let program = synsema_core::parser::parse_source(src, "<v0666>").unwrap();
    let mut interp = Interpreter::new();
    interp.set_labels(true);
    interp.set_labels_detail_to_program(true);
    if let Err(Control::Error(e)) = interp.execute(&program) { panic!("{}", e); }
    for name in ["m", "r"] {
        let v = env_get(&interp.global_env, name).unwrap();
        assert_eq!(label_display_raw(&label_deep(&v)), "owner", "{}", name);
    }
}

#[test]
fn a_captured_private_bool_returned_by_the_callback_labels_mask_and_table() {
    use synsema_core::interpreter::{env_get, Control, Interpreter};
    use synsema_core::labels::{label_deep, label_display_raw};
    let src = r#"let flag be private(true, "owner")
let t be table([{"v": 1}, {"v": 2}, {"v": 3}])
let m be column_mask(t, "v", (x) => flag)
let r be where(t, m)"#;
    let program = synsema_core::parser::parse_source(src, "<v0666>").unwrap();
    let mut interp = Interpreter::new();
    interp.set_labels(true);
    interp.set_labels_detail_to_program(true);
    if let Err(Control::Error(e)) = interp.execute(&program) {
        panic!("{}", e);
    }
    for name in ["m", "r"] {
        let v = env_get(&interp.global_env, name).unwrap();
        assert_eq!(label_display_raw(&label_deep(&v)), "owner", "{}", name);
    }
}

#[test]
fn a_captured_private_non_bool_return_does_not_name_its_type() {
    use synsema_core::interpreter::{Control, Interpreter};
    let src = r#"let flag be private(42, "owner")
let t be table([{"v": 1}])
let n be length(column_mask(t, "v", (x) => flag))"#;
    let program = synsema_core::parser::parse_source(src, "<v0666>").unwrap();
    let mut interp = Interpreter::new();
    interp.set_labels(true);
    match interp.execute(&program) {
        Err(Control::Error(e)) => {
            assert!(!e.message.contains("number"), "el mensaje publica el tipo: {}", e.message);
            assert!(
                e.message.starts_with("label_violation:") || e.message.starts_with("private("),
                "{}",
                e.message
            );
        }
        Err(_) => panic!("se esperaba un error de tipo Error"),
        Ok(_) => panic!("se esperaba error, el programa terminó bien"),
    }
}

#[test]
fn a_captured_private_where_predicate_labels_the_selection() {
    use synsema_core::interpreter::{env_get, Control, Interpreter};
    use synsema_core::labels::{label_deep, label_display_raw};
    let src = r#"let flag be private(true, "owner")
let t be table([{"v": 1}, {"v": 2}, {"v": 3}])
let r be where(t, (row) => flag)"#;
    let program = synsema_core::parser::parse_source(src, "<v0666>").unwrap();
    let mut interp = Interpreter::new();
    interp.set_labels(true);
    interp.set_labels_detail_to_program(true);
    if let Err(Control::Error(e)) = interp.execute(&program) {
        panic!("{}", e);
    }
    let v = env_get(&interp.global_env, "r").unwrap();
    assert_eq!(label_display_raw(&label_deep(&v)), "owner");
}

#[test]
fn decision_builtins_label_results_when_the_callback_returns_a_captured_private() {
    use synsema_core::interpreter::{env_get, Control, Interpreter};
    use synsema_core::labels::{label_deep, label_display_raw};
    let src = r#"let f be private(true, "owner")
let g be private(false, "owner")
let xs be [1, 2, 3]
let a be every(xs, (x) => f)
let b be some(xs, (x) => g)
let c be count_where(xs, (x) => f)
let d be find_first(xs, (x) => g)
let e be transform(xs, (x) => x * 10, (x) => f)
let h be index_of(xs, (x) => g)
let w be where(array([1, 2, 3]), (x) => f)"#;
    let program = synsema_core::parser::parse_source(src, "<v0666>").unwrap();
    let mut interp = Interpreter::new();
    interp.set_labels(true);
    interp.set_labels_detail_to_program(true);
    if let Err(Control::Error(e)) = interp.execute(&program) {
        panic!("{}", e);
    }
    for name in ["a", "b", "c", "d", "e", "h", "w"] {
        let v = env_get(&interp.global_env, name).unwrap();
        assert_eq!(label_display_raw(&label_deep(&v)), "owner", "{}", name);
    }
}

#[test]
fn sort_by_labels_the_order_when_the_keys_are_private() {
    use synsema_core::interpreter::{env_get, Control, Interpreter};
    use synsema_core::labels::{label_deep, label_display_raw};
    let src = r#"let k1 be private(2, "owner")
let k2 be private(1, "owner")
task key(x)
    when x == 1
        give k1
    give k2
let xs be [1, 2]
let s be sort_by(xs, key)"#;
    let program = synsema_core::parser::parse_source(src, "<v0666>").unwrap();
    let mut interp = Interpreter::new();
    interp.set_labels(true);
    interp.set_labels_detail_to_program(true);
    if let Err(Control::Error(e)) = interp.execute(&program) {
        panic!("{}", e);
    }
    let v = env_get(&interp.global_env, "s").unwrap();
    assert_eq!(label_display_raw(&label_deep(&v)), "owner");
}
