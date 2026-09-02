//! Tanda escritorio, empaquetado (specs/build-serve-desktop.md §3.6, §3.8, §3.9) contra el
//! binario real de `synsema build`: `.exe` automático, `--no-console`, `--icon` y `--bundle`
//! sobre DONANTES SINTÉTICOS (un PE/Mach-O/ELF mínimo escrito por el test — `build` sólo exige
//! que el donante no esté ya construido), así corren en cualquier host. En Windows, además,
//! sobre el motor real: el `.exe` con ícono y sin consola sigue sirviendo y se apaga solo.

use std::path::{Path, PathBuf};
use std::process::Command;

const SVG: &str = "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 64 64\"><rect width=\"64\" height=\"64\" rx=\"12\" fill=\"#0a84ff\"/><circle cx=\"32\" cy=\"32\" r=\"14\" fill=\"#fff\"/></svg>";
const PNG_SIG: &[u8] = b"\x89PNG\r\n\x1a\n";

fn project(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("synsema-desktop-build-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("lamp.syn"), "print(\"lamp\")\n").unwrap();
    std::fs::write(dir.join("icon.svg"), SVG).unwrap();
    dir
}

fn synsema(dir: &Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_synsema"))
        .args(args)
        .current_dir(dir)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .output()
        .expect("spawn synsema");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn donor(dir: &Path, name: &str, bytes: &[u8]) -> String {
    std::fs::write(dir.join(name), bytes).unwrap();
    name.to_string()
}

/// Un PE sintético mínimo (mismo layout que `pe::tests::synthetic_pe`): DOS stub, `PE\0\0`,
/// optional header PE32/PE32+, N secciones con relleno; SizeOfHeaders = 0x400 (hay lugar).
fn synthetic_pe(plus: bool, sections: usize, subsystem: u16) -> Vec<u8> {
    let file_align = 0x200u32;
    let sect_align = 0x1000u32;
    let mut b = vec![0u8; 0x400];
    b[0] = b'M';
    b[1] = b'Z';
    let pe = 0x80usize;
    b[0x3c..0x40].copy_from_slice(&(pe as u32).to_le_bytes());
    b[pe..pe + 4].copy_from_slice(b"PE\0\0");
    b[pe + 6..pe + 8].copy_from_slice(&(sections as u16).to_le_bytes());
    let opt_size: u16 = if plus { 240 } else { 224 };
    b[pe + 20..pe + 22].copy_from_slice(&opt_size.to_le_bytes());
    let opt = pe + 24;
    b[opt..opt + 2].copy_from_slice(&(if plus { 0x20bu16 } else { 0x10bu16 }).to_le_bytes());
    b[opt + 32..opt + 36].copy_from_slice(&sect_align.to_le_bytes());
    b[opt + 36..opt + 40].copy_from_slice(&file_align.to_le_bytes());
    b[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes());
    b[opt + 68..opt + 70].copy_from_slice(&subsystem.to_le_bytes());
    let nd = opt + if plus { 108 } else { 92 };
    b[nd..nd + 4].copy_from_slice(&16u32.to_le_bytes());
    let sh = opt + opt_size as usize;
    let mut raw_ptr = 0x400u32;
    let mut va = 0x1000u32;
    for i in 0..sections {
        let at = sh + i * 40;
        let name = format!(".s{}", i);
        b[at..at + name.len()].copy_from_slice(name.as_bytes());
        b[at + 8..at + 12].copy_from_slice(&0x100u32.to_le_bytes());
        b[at + 12..at + 16].copy_from_slice(&va.to_le_bytes());
        b[at + 16..at + 20].copy_from_slice(&0x200u32.to_le_bytes());
        b[at + 20..at + 24].copy_from_slice(&raw_ptr.to_le_bytes());
        raw_ptr += 0x200;
        va += sect_align;
    }
    b[opt + 56..opt + 60].copy_from_slice(&va.to_le_bytes());
    b.resize(raw_ptr as usize, 0xcc);
    b
}

fn macho_donor() -> Vec<u8> {
    let mut b = vec![0xcf, 0xfa, 0xed, 0xfe];
    b.resize(0x200, 0x11);
    b
}

fn elf_donor() -> Vec<u8> {
    let mut b = b"\x7fELF".to_vec();
    b.resize(0x200, 0x22);
    b
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// (subsistema, nombres de sección, DataDirectory[2]) de un PE.
fn pe_header(b: &[u8]) -> (u16, Vec<String>, (u32, u32)) {
    let pe = u32_at(b, 0x3c) as usize;
    assert_eq!(&b[pe..pe + 4], b"PE\0\0");
    let n = u16_at(b, pe + 6) as usize;
    let opt_size = u16_at(b, pe + 20) as usize;
    let opt = pe + 24;
    let plus = u16_at(b, opt) == 0x20b;
    let subsystem = u16_at(b, opt + 68);
    let dd = opt + if plus { 112 } else { 96 } + 16;
    let rsrc = (u32_at(b, dd), u32_at(b, dd + 4));
    let sh = opt + opt_size;
    let names = (0..n)
        .map(|i| {
            let at = sh + i * 40;
            let raw = &b[at..at + 8];
            let end = raw.iter().position(|c| *c == 0).unwrap_or(8);
            String::from_utf8_lossy(&raw[..end]).into_owned()
        })
        .collect();
    (subsystem, names, rsrc)
}

/// Los bytes crudos de la sección `.rsrc`.
fn rsrc_bytes(b: &[u8]) -> Vec<u8> {
    let pe = u32_at(b, 0x3c) as usize;
    let n = u16_at(b, pe + 6) as usize;
    let sh = pe + 24 + u16_at(b, pe + 20) as usize;
    for i in 0..n {
        let at = sh + i * 40;
        if &b[at..at + 5] == b".rsrc" {
            let size = u32_at(b, at + 8) as usize;
            let ptr = u32_at(b, at + 20) as usize;
            return b[ptr..ptr + size].to_vec();
        }
    }
    panic!("el PE no tiene sección .rsrc");
}

fn count(hay: &[u8], needle: &[u8]) -> usize {
    hay.windows(needle.len()).filter(|w| *w == needle).count()
}

/// Un `.ico` contenedor a partir de `(lado, bytes)`.
fn ico_from(images: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&(images.len() as u16).to_le_bytes());
    let mut off = 6 + 16 * images.len() as u32;
    for (side, bytes) in images {
        let s = if *side >= 256 { 0u8 } else { *side as u8 };
        out.extend_from_slice(&[s, s, 0, 0]);
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&32u16.to_le_bytes());
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&off.to_le_bytes());
        off += bytes.len() as u32;
    }
    for (_, bytes) in images {
        out.extend_from_slice(bytes);
    }
    out
}

/// Entradas `(tipo, datos)` de un `.icns`.
fn icns_entries(icns: &[u8]) -> Vec<([u8; 4], Vec<u8>)> {
    assert_eq!(&icns[..4], b"icns");
    let total = u32::from_be_bytes(icns[4..8].try_into().unwrap()) as usize;
    assert_eq!(total, icns.len(), "longitud total del .icns");
    let mut out = Vec::new();
    let mut at = 8;
    while at + 8 <= icns.len() {
        let ty: [u8; 4] = icns[at..at + 4].try_into().unwrap();
        let len = u32::from_be_bytes(icns[at + 4..at + 8].try_into().unwrap()) as usize;
        out.push((ty, icns[at + 8..at + len].to_vec()));
        at += len;
    }
    out
}

#[test]
fn pe_donor_gets_exe_suffix_no_console_and_icon() {
    for plus in [false, true] {
        let dir = project(if plus { "pe64" } else { "pe32" });
        let engine = donor(&dir, "engine.bin", &synthetic_pe(plus, 5, 3));
        // Sin flags: `.exe` automático (mira el ARTEFACTO, no el host), subsistema intacto.
        let (code, out, err) = synsema(&dir, &["build", "lamp.syn", "-o", "app", "--engine-binary", &engine]);
        assert_eq!(code, 0, "{}", err);
        assert!(out.starts_with("built ") && out.contains("app.exe"), "{}", out);
        let exe = dir.join("app.exe");
        let built = std::fs::read(&exe).unwrap();
        assert!(synsema_core::bundle::is_built(&exe), "el bundle va al final");
        let (sub, names, rsrc) = pe_header(&built);
        assert_eq!((sub, names.len(), rsrc), (3, 5, (0, 0)));
        // Con extensión propia: tal cual.
        let (code, out, err) = synsema(&dir, &["build", "lamp.syn", "-o", "app.bin", "--engine-binary", &engine]);
        assert_eq!(code, 0, "{}", err);
        assert!(out.contains("app.bin") && !out.contains("app.bin.exe"), "{}", out);
        assert!(dir.join("app.bin").is_file());
        // --no-console + --icon: subsistema GUI y una sección .rsrc nueva con 4 PNG (16/32/48/256).
        let (code, out, err) = synsema(
            &dir,
            &["build", "lamp.syn", "-o", "desk", "--engine-binary", &engine, "--no-console", "--icon", "icon.svg"],
        );
        assert_eq!(code, 0, "{}", err);
        assert!(out.contains("desk.exe") && out.contains("no-console") && out.contains("icon 16/32/48/256"), "{}", out);
        let exe = dir.join("desk.exe");
        let built = std::fs::read(&exe).unwrap();
        let (sub, names, rsrc) = pe_header(&built);
        assert_eq!(sub, 2, "GUI");
        assert_eq!(names.len(), 6);
        assert_eq!(names.last().map(String::as_str), Some(".rsrc"));
        assert_ne!(rsrc, (0, 0));
        assert_eq!(count(&rsrc_bytes(&built), PNG_SIG), 4);
        assert!(synsema_core::bundle::is_built(&exe), "el bundle sigue al final después de la .rsrc");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn icon_accepts_svg_png_and_ico_and_rejects_the_rest() {
    let dir = project("icons");
    let engine = donor(&dir, "engine.bin", &synthetic_pe(true, 5, 3));
    std::fs::write(dir.join("icon.png"), synsema_stdlib::raster::render_svg_png(SVG, 100, 100).unwrap()).unwrap();
    let png32 = synsema_stdlib::raster::render_svg_png(SVG, 32, 32).unwrap();
    let png256 = synsema_stdlib::raster::render_svg_png(SVG, 256, 256).unwrap();
    std::fs::write(dir.join("icon.ico"), ico_from(&[(32, png32), (256, png256)])).unwrap();
    for (file, n, how) in [("icon.svg", 4, "icon 16/32/48/256"), ("icon.png", 4, "icon 16/32/48/256"), ("icon.ico", 2, "icon 32/256")] {
        let (code, out, err) = synsema(&dir, &["build", "lamp.syn", "-o", "a", "--engine-binary", &engine, "--icon", file]);
        assert_eq!(code, 0, "{}: {}", file, err);
        assert!(out.contains(how), "{}: {}", file, out);
        let built = std::fs::read(dir.join("a.exe")).unwrap();
        assert_eq!(count(&rsrc_bytes(&built), PNG_SIG), n, "{}", file);
    }
    // Otra extensión, un PNG falso, y un .ico sólo-BMP cuando hace falta rasterizar (Mach-O).
    std::fs::write(dir.join("icon.txt"), "x").unwrap();
    let (code, _, err) = synsema(&dir, &["build", "lamp.syn", "-o", "a", "--engine-binary", &engine, "--icon", "icon.txt"]);
    assert_eq!(code, 2);
    assert!(err.contains("--icon accepts .svg, .png or .ico"), "{}", err);
    std::fs::write(dir.join("fake.png"), "not a png").unwrap();
    let (code, _, err) = synsema(&dir, &["build", "lamp.syn", "-o", "a", "--engine-binary", &engine, "--icon", "fake.png"]);
    assert_eq!(code, 2);
    assert!(err.contains("is not a PNG file"), "{}", err);
    std::fs::write(dir.join("bmp.ico"), ico_from(&[(16, vec![0x28, 0, 0, 0, 1, 2, 3, 4])])).unwrap();
    let mac = donor(&dir, "mac.bin", &macho_donor());
    let (code, _, err) = synsema(&dir, &["build", "lamp.syn", "-o", "a", "--engine-binary", &mac, "--bundle", "--icon", "bmp.ico"]);
    assert_eq!(code, 2);
    assert!(err.contains("has no PNG image"), "{}", err);
    // El mismo .ico sólo-BMP sí sirve para el PE: sus entradas van tal cual.
    let (code, out, err) = synsema(&dir, &["build", "lamp.syn", "-o", "a", "--engine-binary", &engine, "--icon", "bmp.ico"]);
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("icon 16"), "{}", out);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn macho_donor_bundle_writes_an_app_with_plist_and_icns() {
    let dir = project("mac");
    let mac = donor(&dir, "mac.bin", &macho_donor());
    let (code, out, err) = synsema(
        &dir,
        &["build", "lamp.syn", "-o", "desk", "--engine-binary", &mac, "--bundle", "--icon", "icon.svg", "--name", "A & B", "--id", "com.example.desk"],
    );
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("A & B.app") && out.contains("bundle .app · id com.example.desk") && out.contains("icon icns"), "{}", out);
    let app = dir.join("A & B.app");
    let plist = std::fs::read_to_string(app.join("Contents").join("Info.plist")).unwrap();
    for needle in [
        "<string>A &amp; B</string>",
        "<key>LSUIElement</key>\n\t<true/>",
        "<string>com.example.desk</string>",
        "<key>CFBundleIconFile</key>\n\t<string>desk</string>",
        "<key>CFBundleExecutable</key>\n\t<string>desk</string>",
    ] {
        assert!(plist.contains(needle), "falta {:?} en {}", needle, plist);
    }
    assert_eq!(std::fs::read(app.join("Contents").join("PkgInfo")).unwrap(), b"APPL????");
    let bin = app.join("Contents").join("MacOS").join("desk");
    let bytes = std::fs::read(&bin).unwrap();
    assert!(bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe]));
    assert!(synsema_core::bundle::is_built(&bin));
    let icns = std::fs::read(app.join("Contents").join("Resources").join("desk.icns")).unwrap();
    let entries = icns_entries(&icns);
    assert_eq!(entries.len(), 7);
    assert!(entries.iter().all(|(_, d)| d.starts_with(PNG_SIG)));
    assert_eq!(&entries[0].0, b"icp4");
    assert_eq!(&entries[6].0, b"ic10");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert!(bin.metadata().unwrap().permissions().mode() & 0o111 != 0, "0o755");
    }
    assert!(!dir.join("desk").exists(), "sin binario suelto al lado del .app");
    // `-o desk.app` = --bundle; defaults de nombre e id; sin --icon → aviso y sin Resources.
    let (code, out, err) = synsema(&dir, &["build", "lamp.syn", "-o", "desk.app", "--engine-binary", &mac]);
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("desk.app") && out.contains("id dev.synsema.desk"), "{}", out);
    assert!(err.contains("no --icon"), "{}", err);
    assert!(dir.join("desk.app").join("Contents").join("MacOS").join("desk").is_file());
    assert!(!dir.join("desk.app").join("Contents").join("Resources").exists());
    // --icon sin --bundle sobre Mach-O: el ícono no vive en el binario.
    let (code, _, err) = synsema(&dir, &["build", "lamp.syn", "-o", "desk", "--engine-binary", &mac, "--icon", "icon.svg"]);
    assert_eq!(code, 2);
    assert!(err.contains("needs --bundle"), "{}", err);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn elf_donor_bundle_writes_dir_with_launcher_and_installer() {
    let dir = project("elf");
    let elf = donor(&dir, "elf.bin", &elf_donor());
    let (code, out, err) = synsema(&dir, &["build", "lamp.syn", "-o", "desk", "--engine-binary", &elf, "--bundle", "--icon", "icon.svg"]);
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("bundle dir + install.sh · id dev.synsema.desk") && out.contains("icon png 256/512"), "{}", out);
    let d = dir.join("desk");
    let bin = d.join("desk");
    assert!(std::fs::read(&bin).unwrap().starts_with(b"\x7fELF"));
    assert!(synsema_core::bundle::is_built(&bin));
    let entry = std::fs::read_to_string(d.join("desk.desktop")).unwrap();
    for needle in ["Terminal=false", "Exec=__INSTALL_DIR__/desk", "Name=desk", "Icon=desk"] {
        assert!(entry.contains(needle), "falta {:?} en {}", needle, entry);
    }
    assert!(std::fs::read(d.join("desk.png")).unwrap().starts_with(PNG_SIG));
    assert!(std::fs::read(d.join("desk-512.png")).unwrap().starts_with(PNG_SIG));
    let sh = std::fs::read_to_string(d.join("install.sh")).unwrap();
    assert!(sh.starts_with("#!/bin/sh\n") && sh.contains("--uninstall"), "{}", sh);
    // --no-console no es de Linux; y un donante ELF no recibe `.exe` aunque el host sea Windows.
    let (code, _, err) = synsema(&dir, &["build", "lamp.syn", "-o", "desk", "--engine-binary", &elf, "--no-console"]);
    assert_eq!(code, 2);
    assert!(err.contains("--no-console applies to Windows executables (PE); the engine is a Linux executable (ELF)"), "{}", err);
    let (code, out, err) = synsema(&dir, &["build", "lamp.syn", "-o", "plain", "--engine-binary", &elf]);
    assert_eq!(code, 0, "{}", err);
    assert!(dir.join("plain").is_file() && !dir.join("plain.exe").exists(), "{}", out);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert!(bin.metadata().unwrap().permissions().mode() & 0o111 != 0, "0o755");
        assert!(d.join("install.sh").metadata().unwrap().permissions().mode() & 0o111 != 0);
        // install.sh instala en un HOME de prueba (sin sudo) y --uninstall lo deshace.
        let home = dir.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let st = Command::new("sh").arg(d.join("install.sh")).env("HOME", &home).status().unwrap();
        assert!(st.success());
        assert!(home.join(".local/bin/desk").is_file());
        let installed = std::fs::read_to_string(home.join(".local/share/applications/desk.desktop")).unwrap();
        assert!(installed.contains(&format!("Exec={}/.local/bin/desk", home.display())), "{}", installed);
        assert!(home.join(".local/share/icons/hicolor/256x256/apps/desk.png").is_file());
        assert!(home.join(".local/share/icons/hicolor/512x512/apps/desk.png").is_file());
        let st = Command::new("sh").arg(d.join("install.sh")).arg("--uninstall").env("HOME", &home).status().unwrap();
        assert!(st.success());
        assert!(!home.join(".local/bin/desk").exists());
        assert!(!home.join(".local/share/applications/desk.desktop").exists());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bundle_and_desktop_flags_are_validated_against_the_engine_format() {
    let dir = project("flags");
    let pe = donor(&dir, "pe.bin", &synthetic_pe(true, 3, 3));
    let odd = donor(&dir, "odd.bin", b"#!/bin/sh\necho hola\n");
    // Donante desconocido: --bundle / --icon → exit 2; sin flags construye igual (es lo de hoy).
    let (code, _, err) = synsema(&dir, &["build", "lamp.syn", "-o", "x", "--engine-binary", &odd, "--bundle"]);
    assert_eq!(code, 2);
    assert!(err.contains("--bundle: the engine is not a PE, Mach-O or ELF executable"), "{}", err);
    let (code, _, err) = synsema(&dir, &["build", "lamp.syn", "-o", "x", "--engine-binary", &odd, "--icon", "icon.svg"]);
    assert_eq!(code, 2);
    assert!(err.contains("--icon: the engine is not a PE"), "{}", err);
    let (code, _, err) = synsema(&dir, &["build", "lamp.syn", "-o", "x", "--engine-binary", &odd]);
    assert_eq!(code, 0, "{}", err);
    assert!(dir.join("x").is_file());
    // PE + --bundle: no hay nada que empaquetar, y se dice en la línea `built`.
    let (code, out, err) = synsema(&dir, &["build", "lamp.syn", "-o", "app", "--engine-binary", &pe, "--bundle"]);
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("bundle: none needed on Windows"), "{}", out);
    assert!(dir.join("app.exe").is_file() && !dir.join("app").exists());
    // --name / --id sin --bundle; -o x.app sobre PE; --icon sin valor; --name con separador.
    let (code, _, err) = synsema(&dir, &["build", "lamp.syn", "-o", "app", "--engine-binary", &pe, "--name", "X"]);
    assert_eq!(code, 2);
    assert!(err.contains("--name applies to --bundle builds"), "{}", err);
    let (code, _, err) = synsema(&dir, &["build", "lamp.syn", "-o", "app", "--engine-binary", &pe, "--id", "com.x.y"]);
    assert_eq!(code, 2);
    assert!(err.contains("--id applies to --bundle builds"), "{}", err);
    let (code, _, err) = synsema(&dir, &["build", "lamp.syn", "-o", "app.app", "--engine-binary", &pe]);
    assert_eq!(code, 2);
    assert!(err.contains("ends with .app but the engine is a Windows executable (PE)"), "{}", err);
    let (code, _, err) = synsema(&dir, &["build", "lamp.syn", "-o", "app", "--engine-binary", &pe, "--icon"]);
    assert_eq!(code, 2);
    assert!(err.contains("--icon requires a value"), "{}", err);
    let mac = donor(&dir, "mac.bin", &macho_donor());
    let (code, _, err) = synsema(&dir, &["build", "lamp.syn", "-o", "app", "--engine-binary", &mac, "--bundle", "--name", "a/b"]);
    assert_eq!(code, 2);
    assert!(err.contains("--name must be a non-empty name without path separators"), "{}", err);
    let (code, _, err) = synsema(&dir, &["build", "lamp.syn", "-o", "app", "--engine-binary", &mac, "--bundle", "--id", "has space"]);
    assert_eq!(code, 2);
    assert!(err.contains("--id must be a reverse-DNS identifier"), "{}", err);
    // --icon sobre un PE que YA trae recursos (un manifest, como los motores compilados con
    // GNU): se mergea — el manifest sobrevive y los íconos quedan en una sección nueva.
    let with_rsrc = synthetic_pe_with_manifest();
    let r = donor(&dir, "rsrc.bin", &with_rsrc);
    let (code, out, err) = synsema(&dir, &["build", "lamp.syn", "-o", "app", "--engine-binary", &r, "--icon", "icon.svg"]);
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("icon 16/32/48/256"), "{}", out);
    let built = std::fs::read(dir.join("app.exe")).unwrap();
    let (_, names, rsrc) = pe_header(&built);
    assert_eq!(names.len(), 4);
    assert_eq!(names.last().map(String::as_str), Some(".rsrc"));
    assert_ne!(rsrc, (0, 0));
    assert_eq!(root_resource_ids(&built), vec![3, 14, 24], "RT_ICON, RT_GROUP_ICON y el manifest, ascendentes");
    assert!(std::fs::read(dir.join("app.exe")).unwrap().windows(11).any(|w| w == b"<assembly/>"), "el manifest sigue ahí");
    // Un árbol de recursos corrupto es un error claro, no un binario roto.
    let mut corrupt = synthetic_pe(true, 3, 3);
    let dd = 0x80 + 24 + 112 + 16;
    corrupt[dd..dd + 4].copy_from_slice(&0x3000u32.to_le_bytes());
    corrupt[dd + 4..dd + 8].copy_from_slice(&0x100u32.to_le_bytes());
    let c = donor(&dir, "corrupt.bin", &corrupt);
    let (code, _, err) = synsema(&dir, &["build", "lamp.syn", "-o", "app", "--engine-binary", &c, "--icon", "icon.svg"]);
    assert_eq!(code, 2);
    assert!(err.contains("cannot read the engine's resources"), "{}", err);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Un PE sintético (PE32+, 3 secciones) cuya última sección es un `.rsrc` real con un
/// `RT_MANIFEST` (id 24 → id 1 → 0x409 → `<assembly/>`), apuntado por DataDirectory[2].
fn synthetic_pe_with_manifest() -> Vec<u8> {
    let mut b = synthetic_pe(true, 3, 3);
    let sh = 0x80 + 24 + 240;
    let at = sh + 2 * 40;
    b[at..at + 8].copy_from_slice(b".rsrc\0\0\0");
    let va = u32_at(&b, at + 12);
    let raw = u32_at(&b, at + 20) as usize;
    // Árbol: root(1 id) → dir24(1 id) → dir1(1 id) → data entry → datos.
    let manifest = b"<assembly/>";
    let mut t: Vec<u8> = Vec::new();
    let dir = |t: &mut Vec<u8>, id: u32, off: u32, is_dir: bool| {
        t.extend_from_slice(&[0u8; 12]);
        t.extend_from_slice(&0u16.to_le_bytes());
        t.extend_from_slice(&1u16.to_le_bytes());
        t.extend_from_slice(&id.to_le_bytes());
        t.extend_from_slice(&(if is_dir { off | 0x8000_0000 } else { off }).to_le_bytes());
    };
    dir(&mut t, 24, 24, true); // root en 0 → dir24 en 24
    dir(&mut t, 1, 48, true); // dir24 en 24 → dir1 en 48
    dir(&mut t, 0x409, 72, false); // dir1 en 48 → data entry en 72
    t.extend_from_slice(&(va + 88).to_le_bytes()); // data entry en 72: RVA de los datos (88)
    t.extend_from_slice(&(manifest.len() as u32).to_le_bytes());
    t.extend_from_slice(&[0u8; 8]);
    t.extend_from_slice(manifest);
    b[raw..raw + t.len()].copy_from_slice(&t);
    let dd = 0x80 + 24 + 112 + 16;
    b[dd..dd + 4].copy_from_slice(&va.to_le_bytes());
    b[dd + 4..dd + 8].copy_from_slice(&(t.len() as u32).to_le_bytes());
    b
}

/// Los ids de las entradas raíz del árbol de recursos (sólo ids; los nombres se saltan).
fn root_resource_ids(b: &[u8]) -> Vec<u32> {
    let pe = u32_at(b, 0x3c) as usize;
    let n = u16_at(b, pe + 6) as usize;
    let opt = pe + 24;
    let plus = u16_at(b, opt) == 0x20b;
    let dd = opt + if plus { 112 } else { 96 } + 16;
    let rva = u32_at(b, dd);
    let sh = opt + u16_at(b, pe + 20) as usize;
    let mut base = None;
    for i in 0..n {
        let at = sh + i * 40;
        let va = u32_at(b, at + 12);
        let vs = u32_at(b, at + 8).max(u32_at(b, at + 16));
        if rva >= va && rva < va + vs {
            base = Some(u32_at(b, at + 20) as usize + (rva - va) as usize);
        }
    }
    let base = base.expect("DataDirectory[2] dentro de una sección");
    let named = u16_at(b, base + 12) as usize;
    let ids = u16_at(b, base + 14) as usize;
    (named..named + ids).map(|i| u32_at(b, base + 16 + i * 8)).collect()
}

/// Sobre el motor REAL (Windows): el `.exe` sin consola y con ícono sigue siendo el CLI bajo
/// `--engine`, sirve, y `shutdown()` lo apaga con 0 — la cirugía PE no rompe el binario.
#[cfg(windows)]
#[test]
fn real_engine_no_console_icon_binary_still_serves_and_shuts_down() {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let dir = project("real");
    std::fs::write(
        dir.join("app.syn"),
        format!(
            "require serve({p})\n\nserve on {p}\n    bind \"127.0.0.1\"\n    route \"GET /ping\"\n        give ok({{\"pong\": true}})\n    route \"GET /quit\"\n        shutdown(\"window closed\")\n        give ok({{\"bye\": true}})\n",
            p = port
        ),
    )
    .unwrap();
    let (code, out, err) = synsema(&dir, &["build", "app.syn", "-o", "desk", "--serve", "--no-console", "--icon", "icon.svg"]);
    assert_eq!(code, 0, "{}\n{}", out, err);
    assert!(out.contains("desk.exe") && out.contains("serve · bind 127.0.0.1 · no-console · icon 16/32/48/256"), "{}", out);
    let exe = dir.join("desk.exe");
    let built = std::fs::read(&exe).unwrap();
    let (sub, names, _) = pe_header(&built);
    assert_eq!(sub, 2);
    assert_eq!(names.last().map(String::as_str), Some(".rsrc"), "{:?}", names);
    // Los recursos que el motor traía (un manifest si es un build GNU) siguen, ordenados.
    let ids = root_resource_ids(&built);
    assert!(ids.contains(&3) && ids.contains(&14), "{:?}", ids);
    assert!(ids.windows(2).all(|w| w[0] < w[1]), "ids ascendentes para la bisección del loader: {:?}", ids);
    let v = Command::new(&exe).args(["--engine", "version"]).env("SYNSEMA_NO_UPDATE_CHECK", "1").output().unwrap();
    assert!(String::from_utf8_lossy(&v.stdout).starts_with("Synsema "), "{:?}", v);

    let mut child = Command::new(&exe)
        .current_dir(&dir)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .env("SYNSEMA_SHUTDOWN_GRACE", "5")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let http = |path: &str| -> Option<(u16, String)> {
        let mut s = TcpStream::connect_timeout(&format!("127.0.0.1:{}", port).parse().unwrap(), Duration::from_secs(3)).ok()?;
        s.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
        s.write_all(format!("GET {} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", path).as_bytes()).ok()?;
        let mut raw = String::new();
        let _ = s.read_to_string(&mut raw);
        Some((raw.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0), raw))
    };
    let t0 = Instant::now();
    loop {
        if let Some((200, _)) = http("/ping") {
            break;
        }
        if t0.elapsed() > Duration::from_secs(60) {
            let _ = child.kill();
            panic!("el .exe sin consola no levantó en 60 s");
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    let (st, _) = http("/quit").unwrap();
    assert_eq!(st, 200);
    let t0 = Instant::now();
    let status = loop {
        if let Ok(Some(st)) = child.try_wait() {
            break st;
        }
        if t0.elapsed() > Duration::from_secs(15) {
            let _ = child.kill();
            panic!("shutdown() no apagó el .exe en 15 s");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let mut stderr = String::new();
    child.stderr.take().unwrap().read_to_string(&mut stderr).unwrap();
    assert_eq!(status.code(), Some(0), "{}", stderr);
    assert!(stderr.contains("shutdown requested by the program: window closed"), "{}", stderr);
    let _ = std::fs::remove_dir_all(&dir);
}
