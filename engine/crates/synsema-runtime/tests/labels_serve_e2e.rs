//! Etiquetas de flujo bajo `serve`: la respuesta HTTP y los streams son
//! sumideros PÚBLICOS. Con las etiquetas encendidas (`--labels`, o `serve --attested` que las
//! enciende solo), un valor `private` que llega al cable sin `declassify` es un error de la
//! request (`label_violation`, con el camino y la etiqueta, nunca el valor); el mismo valor
//! declassificado con motivo sale normal; y un handler que sólo computa con privados y publica
//! un agregado declassificado es el patrón de una clean room.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use synsema_runtime::serve::{run_serve_program_with_overrides, ServeOverrides};

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn start_bg(prog: String, port: u16) {
    thread::spawn(move || {
        let _ = run_serve_program_with_overrides(&prog, "labels_serve.syn", false, ServeOverrides::default());
    });
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            thread::sleep(Duration::from_millis(150));
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("server no quedó listo en 127.0.0.1:{}", port);
}

fn http_get(port: u16, path: &str) -> String {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let _ = sock.set_read_timeout(Some(Duration::from_secs(4)));
    let req = format!("GET {} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", path);
    sock.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    let _ = sock.read_to_string(&mut resp);
    resp
}

#[test]
fn a_private_value_never_reaches_the_wire_without_declassify() {
    // Proceso-global a propósito (es lo que hace `--labels`): este binario de test es sólo esto.
    assert!(synsema_runtime::host::set_labels(true) || synsema_runtime::host::labels());
    let port = free_port();
    let prog = format!(
        r#"require serve({p})
serve on {p}
    route "GET /leak"
        give {{"balance": private(5, "bank")}}
    route "GET /html"
        give html("<b>" + text(private(7, "bank")) + "</b>")
    route "GET /ok"
        let bank be private(5, "bank")
        let airline be private(3, "airline")
        let cross be bank + airline
        give {{"total": declassify(cross, "the aggregate is public by policy")}}
    route "GET /label-of"
        let bank be private(5, "bank")
        give {{"principals": label_of(bank)}}
    route "GET /partial"
        let cross be private(1, "bank") + private(2, "airline")
        give {{"x": declassify(cross, "to the bank only", ["bank"])}}
"#,
        p = port
    );
    start_bg(prog, port);

    // Un mapa con un privado adentro: 500 y el camino en el error; el valor jamás sale.
    let leak = http_get(port, "/leak");
    assert!(leak.starts_with("HTTP/1.1 500"), "{}", leak);
    assert!(leak.contains("label_violation") && leak.contains("response.balance") && leak.contains("bank"), "{}", leak);
    assert!(!leak.contains("\"balance\":5") && !leak.contains("\"balance\": 5"), "{}", leak);

    // Un `html()` construido con texto privado: el valor del servidor sale envuelto → 500.
    let html = http_get(port, "/html");
    assert!(html.starts_with("HTTP/1.1 500"), "{}", html);
    assert!(html.contains("label_violation") && !html.contains("<b>7</b>"), "{}", html);

    // El cruce de dos principales sale sólo declassificado.
    let ok = http_get(port, "/ok");
    assert!(ok.starts_with("HTTP/1.1 200"), "{}", ok);
    assert!(ok.contains("\"total\":8") || ok.contains("\"total\": 8"), "{}", ok);

    // `label_of` NO es metadato público: la etiqueta de un valor privado depende de ese valor
    // (era un oráculo), así que también necesita `declassify` para salir por el cable.
    let lof = http_get(port, "/label-of");
    assert!(lof.starts_with("HTTP/1.1 500"), "{}", lof);
    assert!(lof.contains("label_violation") && lof.contains("response.principals"), "{}", lof);

    // Declassificado a un subconjunto ({bank}) sigue siendo privado para el cable público.
    let partial = http_get(port, "/partial");
    assert!(partial.starts_with("HTTP/1.1 500"), "{}", partial);
    assert!(partial.contains("label_violation") && partial.contains("response.x") && !partial.contains("\"x\":3"), "{}", partial);
}
