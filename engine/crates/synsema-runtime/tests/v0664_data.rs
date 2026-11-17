use synsema_runtime::engine::run_program;

fn path(name: &str) -> (std::path::PathBuf, String) {
    let p = std::env::temp_dir().join(format!("synsema-v0664-{}-{}", std::process::id(), name));
    let source = p.to_string_lossy().replace('\\', "/");
    (p, source)
}

fn output(source: &str) -> Vec<String> {
    let run = run_program(source, "v0664_data.syn");
    assert!(run.success, "{:?}", run.errors);
    run.output
}

#[test]
fn byte_ranges_are_exact_and_capability_checked() {
    let (file, name) = path("range.bin");
    std::fs::write(&file, b"abcdef").unwrap();
    let src = format!(r#"require file.read("{name}")
print(decode(read_file_bytes("{name}", {{"offset": 2, "length": 3}})))
print(length(read_file_bytes("{name}", {{"offset": 6, "length": 100}})))
print(length(read_file_bytes("{name}", {{"offset": 999, "length": 1}})))
print(length(read_file_bytes("{name}", {{"offset": 0, "length": 0}})))
print(decode(read_file_bytes("{name}")))
print(lineage()[0].what)
"#);
    let got = output(&src);
    assert_eq!(&got[..5], ["cde", "0", "0", "0", "abcdef"]);
    assert_eq!(got[5], format!("{} [offset=2 length=3]", name));
    let denied = run_program(&format!("print(read_file_bytes(\"{name}\", {{\"offset\": 0, \"length\": 1}}))"), "v0664_denied.syn");
    assert!(!denied.success);
    assert!(denied.errors.join(" ").contains("Capability not granted"));
    let invalid = run_program(&format!("require file.read(\"{name}\")\nprint(read_file_bytes(\"{name}\", {{\"offset\": 1.5, \"length\": 1}}))"), "v0664_invalid.syn");
    assert!(!invalid.success);
    assert!(invalid.errors.join(" ").contains("non-negative integer"));
    for (options, expected) in [
        ("{\"offset\": 0}", "offset and length"),
        ("{\"offset\": -1, \"length\": 1}", "non-negative integer"),
        ("{\"offset\": 0, \"length\": 1, \"bogus\": 1}", "unknown option"),
    ] {
        let source = format!("require file.read(\"{name}\")\nprint(read_file_bytes(\"{name}\", {options}))");
        let run = run_program(&source, "v0664_bad_range.syn");
        assert!(!run.success, "{options}");
        assert!(run.errors.join(" ").contains(expected), "{options}: {:?}", run.errors);
    }
    std::fs::remove_file(file).unwrap();
}

#[test]
fn a_small_range_near_the_end_of_a_large_file() {
    use std::io::{Seek, SeekFrom, Write};
    let (path, name) = path("large.bin");
    let mut file = std::fs::File::create(&path).unwrap();
    file.set_len(64 * 1024 * 1024).unwrap();
    file.seek(SeekFrom::End(-3)).unwrap();
    file.write_all(b"xyz").unwrap();
    drop(file);
    let source = format!("require file.read(\"{name}\")\nprint(decode(read_file_bytes(\"{name}\", {{\"offset\": 67108861, \"length\": 3}})))");
    assert_eq!(output(&source), ["xyz"]);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn parquet_info_from_file_matches_bytes_and_has_statistics() {
    let (file, name) = path("stats.parquet");
    let src = format!(r#"require file.read("{name}")
require file.write("{name}")
let b be parquet_write([{{"k": 1, "v": 2.0}}, {{"k": 3, "v": nothing}}, {{"k": 2, "v": 4.0}}])
write_file("{name}", b)
let a be parquet_info(b)
let d be parquet_info_file("{name}")
print(a == d)
print(a.row_groups[0].columns[0].name, a.row_groups[0].columns[0].min, a.row_groups[0].columns[0].max, a.row_groups[0].columns[0].null_count)
print(a.row_groups[0].columns[1].null_count)
print(lineage()[0].source)
"#);
    let out = output(&src);
    assert_eq!(out[0], "true");
    assert_eq!(out[1], "k 1 3 0");
    assert_eq!(out[2], "1");
    assert_eq!(out[3], "parquet_info_file");
    std::fs::remove_file(file).unwrap();
}

#[test]
fn public_hash_obeys_grouping() {
    assert_eq!(output("print(hash(true) == hash(1), hash(1) == hash(1.0), hash(1d) == hash(1), hash(-0.0) == hash(0))\nprint(hash({\"b\": 2, \"a\": 1}) == hash({\"a\": 1, \"b\": 2}))\nprint(hash(\"x\") >= 0, hash(\"x\") % 8 >= 0)"), ["true true true true", "true", "true true"]);
}
