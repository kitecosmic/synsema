//! `synsema build --bundle` (tanda escritorio): lo mínimo que cada SO necesita para abrir la
//! app con doble clic y con ícono, escrito como archivos — sin toolchain, sin firma.
//!
//! - **Mach-O → `Name.app/`**: `Contents/Info.plist` (con `LSUIElement = true`: el proceso no
//!   es una app Cocoa, corre como agente sin Terminal ni ícono rebotando en el Dock; el ícono
//!   visible lo pone la PWA instalada), `Contents/PkgInfo`, `Contents/MacOS/<bin>` (0o755),
//!   `Contents/Resources/<bin>.icns` si hay `--icon`.
//! - **ELF → `<name>/`**: el binario, `<name>.desktop` (`Terminal=false`, `Exec` con el marcador
//!   `__INSTALL_DIR__`), los PNG del ícono y un `install.sh` POSIX de pocas líneas que copia a
//!   `~/.local`, reescribe `Exec` con la ruta absoluta y registra el `.desktop`; `--uninstall`
//!   deshace.
//! - **PE → nada**: el `.exe` con `--icon`/`--no-console` ya es la app.
//!
//! Formatos de distribución del ecosistema (`.dmg`, notarización, AppImage, `.deb`, `.msi`)
//! quedan afuera a propósito: se documentan, no se envuelven.

use std::path::{Path, PathBuf};

/// El formato del motor donante, por magic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineFormat {
    Pe,
    MachO,
    Elf,
    Unknown,
}

impl EngineFormat {
    /// Para mensajes: "a Windows executable (PE)", …
    pub fn describe(self) -> &'static str {
        match self {
            EngineFormat::Pe => "a Windows executable (PE)",
            EngineFormat::MachO => "a macOS executable (Mach-O)",
            EngineFormat::Elf => "a Linux executable (ELF)",
            EngineFormat::Unknown => "not a PE, Mach-O or ELF executable",
        }
    }
}

pub fn engine_format(bytes: &[u8]) -> EngineFormat {
    if bytes.starts_with(b"MZ") {
        EngineFormat::Pe
    } else if bytes.starts_with(&[0x7f, b'E', b'L', b'F']) {
        EngineFormat::Elf
    } else if bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xce, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
    {
        EngineFormat::MachO
    } else {
        EngineFormat::Unknown
    }
}

/// Lo que el bundle necesita saber de la app.
pub struct BundleSpec<'a> {
    /// Nombre visible (`--name`; default el stem de `-o`).
    pub display_name: &'a str,
    /// Nombre del ejecutable dentro del bundle (el stem de `-o`).
    pub bin_name: &'a str,
    /// Identificador inverso (`--id`; default `dev.synsema.<stem>`).
    pub bundle_id: &'a str,
    /// Versión (la del motor).
    pub version: &'a str,
    /// El binario ya construido (motor + bundle anexado).
    pub binary: &'a [u8],
    /// `.icns` (Mach-O) — `None` sin `--icon`.
    pub icns: Option<&'a [u8]>,
    /// PNGs `(lado, bytes)` para Linux — vacío sin `--icon`.
    pub pngs: &'a [(u32, Vec<u8>)],
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// El `Info.plist` mínimo y honesto (ver el módulo).
pub fn info_plist(spec: &BundleSpec<'_>) -> String {
    let icon = match spec.icns {
        Some(_) => format!("\t<key>CFBundleIconFile</key>\n\t<string>{}</string>\n", xml_escape(spec.bin_name)),
        None => String::new(),
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleName</key>
	<string>{name}</string>
	<key>CFBundleDisplayName</key>
	<string>{name}</string>
	<key>CFBundleIdentifier</key>
	<string>{id}</string>
	<key>CFBundleVersion</key>
	<string>{ver}</string>
	<key>CFBundleShortVersionString</key>
	<string>{ver}</string>
	<key>CFBundleExecutable</key>
	<string>{bin}</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
{icon}	<key>LSMinimumSystemVersion</key>
	<string>11.0</string>
	<key>NSHighResolutionCapable</key>
	<true/>
	<key>LSUIElement</key>
	<true/>
</dict>
</plist>
"#,
        name = xml_escape(spec.display_name),
        id = xml_escape(spec.bundle_id),
        ver = xml_escape(spec.version.trim_start_matches('v')),
        bin = xml_escape(spec.bin_name),
        icon = icon,
    )
}

/// El `.desktop` con el marcador que `install.sh` reemplaza por la ruta absoluta.
pub fn desktop_entry(spec: &BundleSpec<'_>) -> String {
    format!(
        "[Desktop Entry]\nType=Application\nName={name}\nComment={name} (Synsema)\nExec=__INSTALL_DIR__/{bin}\nIcon={bin}\nTerminal=false\nCategories=Utility;\n",
        name = spec.display_name.replace('\n', " "),
        bin = spec.bin_name,
    )
}

/// `install.sh`: diez líneas POSIX, sin sudo, sólo `~/.local`; `--uninstall` deshace.
pub fn install_sh(spec: &BundleSpec<'_>) -> String {
    format!(
        r#"#!/bin/sh
# Instala {name} para este usuario (sin root): binario en ~/.local/bin, lanzador en el menú,
# íconos en hicolor. `./install.sh --uninstall` deshace. Generado por `synsema build --bundle`.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HOME/.local/bin"; APPS="$HOME/.local/share/applications"; ICONS="$HOME/.local/share/icons/hicolor"
if [ "$1" = "--uninstall" ]; then
  rm -f "$BIN/{bin}" "$APPS/{bin}.desktop" "$ICONS/256x256/apps/{bin}.png" "$ICONS/512x512/apps/{bin}.png"
  command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APPS" || true
  echo "{name}: desinstalada"; exit 0
fi
mkdir -p "$BIN" "$APPS" "$ICONS/256x256/apps" "$ICONS/512x512/apps"
cp "$HERE/{bin}" "$BIN/{bin}" && chmod 755 "$BIN/{bin}"
[ -f "$HERE/{bin}.png" ] && cp "$HERE/{bin}.png" "$ICONS/256x256/apps/{bin}.png"
[ -f "$HERE/{bin}-512.png" ] && cp "$HERE/{bin}-512.png" "$ICONS/512x512/apps/{bin}.png"
sed "s|__INSTALL_DIR__|$BIN|" "$HERE/{bin}.desktop" > "$APPS/{bin}.desktop"
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APPS" || true
echo "{name}: instalada — buscala en el menú de aplicaciones"
"#,
        name = spec.display_name,
        bin = spec.bin_name,
    )
}

fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).map_err(|e| format!("cannot create {}: {}", p.display(), e))?;
    }
    std::fs::write(path, bytes).map_err(|e| format!("cannot write {}: {}", path.display(), e))
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<(), String> {
    Ok(())
}

/// Escribe `<parent>/<display_name>.app/` (temp + rename). Devuelve la ruta del `.app`.
pub fn write_macos_app(parent: &Path, spec: &BundleSpec<'_>) -> Result<PathBuf, String> {
    let app = parent.join(format!("{}.app", spec.display_name));
    let tmp = parent.join(format!(".{}.app.tmp-{}", spec.display_name, std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let contents = tmp.join("Contents");
    write(&contents.join("Info.plist"), info_plist(spec).as_bytes())?;
    write(&contents.join("PkgInfo"), b"APPL????")?;
    let bin = contents.join("MacOS").join(spec.bin_name);
    write(&bin, spec.binary)?;
    make_executable(&bin)?;
    if let Some(icns) = spec.icns {
        write(&contents.join("Resources").join(format!("{}.icns", spec.bin_name)), icns)?;
    }
    let _ = std::fs::remove_dir_all(&app);
    std::fs::rename(&tmp, &app).map_err(|e| format!("cannot write {}: {}", app.display(), e))?;
    Ok(app)
}

/// Escribe `<parent>/<bin_name>/` con binario, `.desktop`, PNGs e `install.sh`.
pub fn write_linux_dir(parent: &Path, spec: &BundleSpec<'_>) -> Result<PathBuf, String> {
    let dir = parent.join(spec.bin_name);
    let tmp = parent.join(format!(".{}.tmp-{}", spec.bin_name, std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let bin = tmp.join(spec.bin_name);
    write(&bin, spec.binary)?;
    make_executable(&bin)?;
    write(&tmp.join(format!("{}.desktop", spec.bin_name)), desktop_entry(spec).as_bytes())?;
    for (side, png) in spec.pngs {
        let name = match side {
            256 => format!("{}.png", spec.bin_name),
            512 => format!("{}-512.png", spec.bin_name),
            _ => continue,
        };
        write(&tmp.join(name), png)?;
    }
    let sh = tmp.join("install.sh");
    write(&sh, install_sh(spec).as_bytes())?;
    make_executable(&sh)?;
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::rename(&tmp, &dir).map_err(|e| format!("cannot write {}: {}", dir.display(), e))?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec<'a>(icns: Option<&'a [u8]>, pngs: &'a [(u32, Vec<u8>)]) -> BundleSpec<'a> {
        BundleSpec {
            display_name: "Mi & App",
            bin_name: "desk",
            bundle_id: "com.example.desk",
            version: "v0.6.18",
            binary: b"#!fake-binary",
            icns,
            pngs,
        }
    }

    #[test]
    fn engine_format_by_magic() {
        assert_eq!(engine_format(b"MZ\x90\x00"), EngineFormat::Pe);
        assert_eq!(engine_format(&[0x7f, b'E', b'L', b'F', 2]), EngineFormat::Elf);
        assert_eq!(engine_format(&[0xcf, 0xfa, 0xed, 0xfe]), EngineFormat::MachO);
        assert_eq!(engine_format(&[0xca, 0xfe, 0xba, 0xbe]), EngineFormat::MachO);
        assert_eq!(engine_format(b"hola"), EngineFormat::Unknown);
    }

    #[test]
    fn macos_app_layout_and_plist() {
        let dir = std::env::temp_dir().join(format!("synsema-bundle-mac-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let icns = b"icns\0\0\0\x08".to_vec();
        let app = write_macos_app(&dir, &spec(Some(&icns), &[])).unwrap();
        assert!(app.ends_with("Mi & App.app"));
        assert_eq!(xml_escape("A & <b> \"c\""), "A &amp; &lt;b&gt; &quot;c&quot;");
        let plist = std::fs::read_to_string(app.join("Contents/Info.plist")).unwrap();
        assert!(plist.contains("<string>Mi &amp; App</string>"), "escape XML: {}", plist);
        assert!(plist.contains("<key>LSUIElement</key>\n\t<true/>"));
        assert!(plist.contains("<key>CFBundleExecutable</key>\n\t<string>desk</string>"));
        assert!(plist.contains("<string>0.6.18</string>"), "sin la v: {}", plist);
        assert!(plist.contains("<key>CFBundleIconFile</key>\n\t<string>desk</string>"));
        assert_eq!(std::fs::read(app.join("Contents/MacOS/desk")).unwrap(), b"#!fake-binary");
        assert_eq!(std::fs::read(app.join("Contents/PkgInfo")).unwrap(), b"APPL????");
        assert_eq!(std::fs::read(app.join("Contents/Resources/desk.icns")).unwrap(), icns);
        // Sin ícono: sin CFBundleIconFile ni Resources.
        let app2 = write_macos_app(&dir, &spec(None, &[])).unwrap();
        let plist2 = std::fs::read_to_string(app2.join("Contents/Info.plist")).unwrap();
        assert!(!plist2.contains("CFBundleIconFile"));
        assert!(!app2.join("Contents/Resources").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn linux_dir_layout_desktop_and_installer() {
        let dir = std::env::temp_dir().join(format!("synsema-bundle-linux-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pngs = vec![(256, b"png256".to_vec()), (512, b"png512".to_vec()), (16, b"skip".to_vec())];
        let out = write_linux_dir(&dir, &spec(None, &pngs)).unwrap();
        assert!(out.ends_with("desk"));
        let d = std::fs::read_to_string(out.join("desk.desktop")).unwrap();
        assert!(d.contains("Terminal=false") && d.contains("Exec=__INSTALL_DIR__/desk") && d.contains("Icon=desk"), "{}", d);
        assert!(d.contains("Name=Mi & App"));
        assert_eq!(std::fs::read(out.join("desk.png")).unwrap(), b"png256");
        assert_eq!(std::fs::read(out.join("desk-512.png")).unwrap(), b"png512");
        assert!(!out.join("desk-16.png").exists());
        let sh = std::fs::read_to_string(out.join("install.sh")).unwrap();
        assert!(sh.starts_with("#!/bin/sh\n"));
        assert!(sh.contains("sed \"s|__INSTALL_DIR__|$BIN|\"") && sh.contains("--uninstall") && !sh.contains("sudo"));
        assert_eq!(std::fs::read(out.join("desk")).unwrap(), b"#!fake-binary");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
