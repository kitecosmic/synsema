//! v0.6.46, Tanda C (C3 y C4): lo que la corrida escribe queda en el recibo (`outputs`), y
//! `parquet_scan` lee un Parquet del disco por partes, como entrada del linaje.

use synsema_runtime::engine::run_program;

fn out(src: &str) -> Vec<String> {
    let r = run_program(src, "v0646_tanda_c.syn");
    assert!(r.success, "falló: {:?}\n{}", r.errors, src);
    r.output
}

fn fails(src: &str) -> String {
    let r = run_program(src, "v0646_tanda_c.syn");
    assert!(!r.success, "tenía que fallar:\n{}\nsalida: {:?}", src, r.output);
    r.errors.join("\n")
}

fn tmp(tag: &str) -> String {
    let d = std::env::temp_dir().join(format!("syn_c34_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d.to_string_lossy().replace('\\', "/")
}

/// C3: entrenar y escribir un modelo → el recibo trae su sha256 sin meterlo a mano. También
/// `append_file` (el pedazo agregado) y `edit_file` (el archivo como quedó), en orden.
#[test]
fn c3_the_receipt_names_what_the_run_wrote() {
    let d = tmp("out");
    let src = format!(
        "require file.write(\"{d}/*\")\nrequire file.read(\"{d}/*\")\n\
         let model be json_encode({{\"coef\": polyfit([1, 2, 3], [2, 4, 6], 1)}})\n\
         write_file(\"{d}/model.json\", model)\n\
         append_file(\"{d}/log.txt\", \"uno\\n\")\n\
         edit_file(\"{d}/model.json\", \"coef\", \"w\")\n\
         let o be receipt().credentialSubject.outputs\n\
         print(length(o), o[0].source, o[1].source, o[2].source)\n\
         print(o[0].what == \"{d}/model.json\", \"0x\" + o[0].sha256 == hex(sha256(model)), o[0].bytes == length(model), o[0].encoding)\n\
         print(\"0x\" + o[1].sha256 == hex(sha256(\"uno\\n\")), o[1].bytes)\n\
         print(\"0x\" + o[2].sha256 == hex(sha256(read_file(\"{d}/model.json\"))))\n\
         print(length(receipt().credentialSubject.inputs))\n"
    );
    // Dos entradas: lo que leyó `edit_file` (v0.6.49, B11) y el `read_file` del final.
    assert_eq!(
        out(&src),
        vec!["3 write_file append_file edit_file", "true true true text", "true 4", "true", "2"]
    );
    // Bytes: `encoding` lo dice; una escritura negada no queda.
    let src = format!(
        "require file.write(\"{d}/*\")\nwrite_file(\"{d}/b.bin\", bytes([1, 2, 3]))\n\
         let o be receipt().credentialSubject.outputs\nprint(length(o), o[0].encoding, o[0].bytes)\n"
    );
    assert_eq!(out(&src), vec!["1 bytes 3"]);
    assert!(fails(&format!("write_file(\"{d}/x.txt\", \"x\")\n")).contains("file.write"));
}

/// C3: una extracción anota cada archivo que escribió.
#[test]
fn c3_an_extraction_names_each_file() {
    let d = tmp("zip");
    let src = format!(
        "require file.write(\"{d}/**\")\n\
         let z be zip_create([{{\"path\": \"a.txt\", \"bytes\": bytes(\"AA\")}}, {{\"path\": \"s/b.txt\", \"bytes\": bytes(\"BBB\")}}])\n\
         zip_extract(z, \"{d}/x/./\")\n\
         let o be receipt().credentialSubject.outputs\n\
         print(length(o), o[0].source, o[0].what == \"{d}/x/./a.txt\", o[1].bytes, \"0x\" + o[1].sha256 == hex(sha256(\"BBB\")))\n"
    );
    assert_eq!(out(&src), vec!["2 zip_extract true 3 true"]);
}

/// C4: `parquet_scan(path, opts)` da lo mismo que `parquet_read(read_file_bytes(path), opts)`,
/// pide `file.read`, y es una entrada del linaje con la ruta.
#[test]
fn c4_parquet_scan_reads_from_disk_like_parquet_read() {
    let d = tmp("pq");
    let src = format!(
        "require file.write(\"{d}/*\")\nrequire file.read(\"{d}/*\")\n\
         let rows be apply(range(0, 500), (i) => {{\"id\": i, \"name\": \"n\" + text(i), \"x\": i * 0.5}})\n\
         write_file(\"{d}/t.parquet\", parquet_write(rows))\n\
         let opts be {{\"columns\": [\"id\", \"x\"], \"limit\": 7}}\n\
         let a be parquet_scan(\"{d}/t.parquet\", opts)\n\
         let b be parquet_read(read_file_bytes(\"{d}/t.parquet\"), opts)\n\
         print(a == b, length(a), keys(a[0]))\n\
         print(parquet_scan(\"{d}/t.parquet\") == rows)\n\
         let l be lineage()\n\
         print(l[0].source, l[0].what == \"{d}/t.parquet\", \"0x\" + l[0].sha256 == hex(sha256(canonical_json(a))))\n"
    );
    assert_eq!(out(&src), vec!["true 7 [\"id\", \"x\"]", "true", "parquet_scan true true"]);
    // Un valor más grande que la ventana con la que se leen los encabezados (8 KiB). El encabezado
    // en sí, más grande que la ventana, lo prueba `a_page_header_larger_than_the_window_is_read_whole`
    // (stdlib): este crate escribe las estadísticas de página en el índice, no en el encabezado.
    let src = format!(
        "require file.write(\"{d}/*\")\nrequire file.read(\"{d}/*\")\n\
         let big be join(apply(range(0, 20000), (i) => \"x\"), \"\")\n\
         let rows be [{{\"s\": big}}, {{\"s\": \"a\"}}]\n\
         write_file(\"{d}/big.parquet\", parquet_write(rows))\n\
         print(parquet_scan(\"{d}/big.parquet\") == rows, parquet_read(read_file_bytes(\"{d}/big.parquet\")) == rows)\n"
    );
    assert_eq!(out(&src), vec!["true true"]);
    let e = fails(&format!("print(parquet_scan(\"{d}/t.parquet\"))\n"));
    assert!(e.contains("file.read"), "{}", e);
    let e = fails("print(parquet_scan(bytes([1, 2])))\n");
    assert!(e.contains("expected a path") && e.contains("parquet_read(bytes)"), "{}", e);
    let e = fails(&format!(
        "require file.write(\"{d}/*\")\nrequire file.read(\"{d}/*\")\nwrite_file(\"{d}/no.parquet\", \"hola\")\nprint(parquet_scan(\"{d}/no.parquet\"))\n"
    ));
    assert!(e.contains("not a Parquet file"), "{}", e);
}

/// Ronda 1 de cf1 (B2): lo que leen y escriben los workers de `parallel_map` entra en el recibo del
/// llamador, en el orden de los items (antes daba `outputs 0`, con los archivos en disco).
#[test]
fn c3_parallel_map_workers_reach_the_receipt() {
    let d = tmp("par");
    let src = format!(
        "require file.write(\"{d}/*\")\nrequire file.read(\"{d}/*\")\n\
         task w(n)\n    write_file(\"{d}/p\" + text(n) + \".txt\", text(n))\n    give read_file(\"{d}/p\" + text(n) + \".txt\")\n\
         print(parallel_map(w, [1, 2, 3]))\n\
         let s be receipt().credentialSubject\n\
         print(length(s.outputs), length(s.inputs), s.outputs[2].what == \"{d}/p3.txt\")\n"
    );
    assert_eq!(out(&src), vec!["[\"1\", \"2\", \"3\"]", "3 3 true"]);
}

/// Ronda 2 de cf1 (R2-B1): si un worker falla, lo que ya escribieron todos (también el que falló,
/// antes de fallar) sigue en el recibo: los archivos quedaron en disco.
#[test]
fn c3_a_failed_parallel_map_keeps_what_was_written() {
    let d = tmp("parfail");
    let src = format!(
        "require file.write(\"{d}/*\")\n\
         task f(n)\n    write_file(\"{d}/e\" + text(n) + \".txt\", text(n))\n    when n == 3\n        raise(\"falla\")\n    give n\n\
         try\n    parallel_map(f, [1, 2, 3, 4], 1)\nrecover e\n    print(\"recover\")\n\
         print(length(receipt().credentialSubject.outputs))\n"
    );
    let o = out(&src);
    assert_eq!(o[0], "recover");
    // Con un hilo, el 4 no llega a correr: el 1, el 2 y el 3 (que escribió antes del raise).
    assert_eq!(o[1], "3");
}
