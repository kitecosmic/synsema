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

