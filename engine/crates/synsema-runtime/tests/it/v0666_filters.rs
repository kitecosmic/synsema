//! La máscara columnar se compone con los builtins públicos de stdlib.

use synsema_runtime::engine::run_program;

#[test]
fn an_app_can_combine_masks_without_materializing_rows() {
    let src = r#"let t be table([{"id": 1, "distance": 0, "fare": 10}, {"id": 2, "distance": 3, "fare": nothing}, {"id": 3, "distance": 4, "fare": 20}, {"id": 4, "distance": 2, "fare": 1000}])
let distance_ok be column_mask(t, "distance", ">", 0)
let fare_ok be column_mask(t, "fare", "<", 500, missing = "exclude")
let selected be where(t, logical_and(distance_ok, fare_ok))
print(length(selected), selected[0].id, columns(selected))"#;
    let r = run_program(src, "v0666.syn");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, ["1 3 [\"id\", \"distance\", \"fare\"]"]);
}

#[test]
fn an_imported_library_can_filter_a_table() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../examples/table_filters/demo.syn");
    let src = std::fs::read_to_string(&path).unwrap();
    let r = run_program(&src, &path.to_string_lossy());
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, ["1 3"]);
}
