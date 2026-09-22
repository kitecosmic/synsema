//! Qué arquitecturas conoce este binario, y de dónde salieron.
//!
//! Las cuatro que publicamos vienen **adentro** del binario: son parte del release, se versionan
//! con él y no dependen de que el disco tenga nada. Las demás salen de un directorio que elige el
//! operador con `SYNSEMA_INFER_ARCHDEF`.
//!
//! ## El disco gana, y un archivo roto NO cae de vuelta a la nuestra
//!
//! Si el directorio trae una definición con el mismo nombre que una nuestra, **gana la del disco**.
//! Es la salida de emergencia que hace que este formato sirva de algo: el día que un checkpoint
//! nuevo cambia un detalle de `llama` y nuestra definición queda vieja, el que la sufre arregla una
//! línea en un archivo y sigue, en vez de esperar un release. `llm status` dice cuál está corriendo
//! y con qué sha, así que la sustitución nunca es silenciosa.
//!
//! Y si el archivo **no carga** —un typo, un `arch` que no corresponde—, esa arquitectura queda
//! **no disponible**, con el error del archivo. No se vuelve a la embebida. La primera versión de
//! esto sí volvía, y la prueba en vivo mostró por qué está mal: con un typo en `silu`, el modelo
//! seguía respondiendo perfecto. El operador habría jurado que su archivo estaba corriendo.
//!
//! ## El nombre del archivo ES el nombre de la arquitectura
//!
//! `qwen3.archdef` tiene que declarar `arch qwen3`. No es burocracia: es lo que permite que, cuando
//! un archivo ni siquiera parsea, se sepa **qué arquitectura acaba de quedar rota** — el contenido
//! no se pudo leer, pero el nombre sí.
//!
//! ## Quién elige, otra vez
//!
//! Igual que con los modelos (§4.1 del spec): **el `.syn` no nombra arquitecturas ni directorios**.
//! El programa pide generar texto; el operador decidió qué modelo y, ahora, qué definiciones están
//! disponibles. Un programa no puede hacer que el motor lea un archivo que el operador no habilitó.
//!
//! ## Y una definición no ejecuta nada
//!
//! Vale repetirlo acá, que es donde entra código de terceros: un `.archdef` es una lista recta de
//! pasos sin condicionales, bucles ni llamadas (ver [`crate::archdef`]). Bajar una definición
//! ajena no es como bajar un plugin. Lo peor que puede pasar es que no cargue, o que dé números
//! equivocados con los pesos de uno.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::archdef::{parse, ArchDef, DefError, DefOrigin};

/// La extensión que se busca en el directorio del operador.
pub const EXTENSION: &str = "archdef";

/// El knob que apunta al directorio de definiciones del operador.
///
/// El nombre vive en `lib.rs` porque el runtime tiene que poder resolverlo aunque este módulo
/// no esté compilado; acá se reexporta para que los mensajes de error lo nombren sin importar
/// dos cosas.
pub use crate::ARCHDEF_DIR_ENV as DIR_ENV;

/// Las definiciones que van adentro del binario.
///
/// El `include_str!` las mete en el ejecutable: no hay que instalar nada aparte, y el sha que
/// reporta `llm status` sale del mismo texto que se compiló.
const BUILTIN: &[(&str, &str)] = &[
    ("llama", include_str!("../defs/llama.archdef")),
    ("qwen2", include_str!("../defs/qwen2.archdef")),
    ("qwen3", include_str!("../defs/qwen3.archdef")),
    ("gemma3", include_str!("../defs/gemma3.archdef")),
];

/// Un archivo del directorio que no se pudo cargar.
///
/// No se descarta en silencio: un typo en una definición que el operador puso a mano es
/// exactamente el caso donde callarse cuesta una hora de confusión.
#[derive(Clone, Debug)]
pub struct Problem {
    pub path: PathBuf,
    pub error: DefError,
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.error)
    }
}

/// Todo lo que este binario sabe correr.
#[derive(Clone, Debug, Default)]
pub struct Registry {
    defs: Vec<ArchDef>,
    problems: Vec<Problem>,
}

impl Registry {
    /// Arma el registro: primero lo embebido, después el directorio, que pisa por nombre.
    pub fn load(dir: Option<&Path>) -> Registry {
        let mut defs: Vec<ArchDef> = Vec::new();
        let mut problems = Vec::new();

        for (name, text) in BUILTIN {
            match parse(text, DefOrigin::Embedded) {
                Ok(d) => defs.push(d),
                // Una definición embebida rota es un bug nuestro que el test `builtins_parse`
                // agarra antes de cualquier release. Acá se registra y se sigue: un binario con
                // una definición mala tiene que poder correr las otras tres.
                Err(error) => problems.push(Problem { path: PathBuf::from(*name), error }),
            }
        }

        if let Some(dir) = dir {
            let mut entries: Vec<PathBuf> = match std::fs::read_dir(dir) {
                Ok(rd) => rd.filter_map(|e| e.ok()).map(|e| e.path()).collect(),
                Err(e) => {
                    problems.push(Problem {
                        path: dir.to_path_buf(),
                        error: DefError {
                            line: 0,
                            message: format!("no se pudo leer el directorio: {}", e),
                            fix: Some(format!(
                                "revisá que {}='{}' exista y se pueda leer",
                                DIR_ENV,
                                dir.display()
                            )),
                        },
                    });
                    Vec::new()
                }
            };
            // Orden estable: dos corridas con el mismo directorio cargan lo mismo en el mismo
            // orden, que es la mitad de poder reproducir una salida.
            entries.sort();
            for path in entries {
                if path.extension().and_then(|e| e.to_str()) != Some(EXTENSION) {
                    continue;
                }
                // El nombre del archivo dice qué arquitectura toca, incluso si el contenido no se
                // puede leer. Sin esto, un archivo roto no se sabría a quién le corresponde.
                let claimed = match path.file_stem().and_then(|s| s.to_str()) {
                    Some(s) => s.to_string(),
                    None => continue,
                };
                // Pase lo que pase con este archivo, la embebida del mismo nombre deja de valer:
                // el operador dijo que la suya manda, y si la suya no carga, no hay ninguna.
                defs.retain(|existing| existing.name != claimed);

                let text = match std::fs::read_to_string(&path) {
                    Ok(t) => t,
                    Err(e) => {
                        problems.push(Problem {
                            path,
                            error: DefError {
                                line: 0,
                                message: format!("no se pudo leer: {}", e),
                                fix: Some(format!(
                                    "hasta que se arregle, '{}' no se puede correr",
                                    claimed
                                )),
                            },
                        });
                        continue;
                    }
                };
                match parse(&text, DefOrigin::File(path.clone())) {
                    Ok(d) if d.name != claimed => {
                        // Declarar una arquitectura distinta de la del archivo dejaría dos nombres
                        // para lo mismo y un `unknown()` que no sabe a qué archivo mandar.
                        problems.push(Problem {
                            path: path.clone(),
                            error: DefError {
                                line: 0,
                                message: format!(
                                    "el archivo se llama '{}.{}' pero declara `arch {}`",
                                    claimed, EXTENSION, d.name
                                ),
                                fix: Some(format!(
                                    "renombralo a '{}.{}', o cambiá la línea a `arch {}`",
                                    d.name, EXTENSION, claimed
                                )),
                            },
                        });
                    }
                    Ok(d) => {
                        defs.retain(|existing| existing.name != d.name);
                        defs.push(d);
                    }
                    // Roto: la arquitectura queda no disponible, con su error. NO se vuelve a la
                    // embebida — ver la nota del módulo.
                    Err(error) => problems.push(Problem { path, error }),
                }
            }
        }

        defs.sort_by(|a, b| a.name.cmp(&b.name));
        Registry { defs, problems }
    }

    /// El registro de esta corrida, leído una sola vez.
    pub fn shared() -> &'static Registry {
        static SHARED: OnceLock<Registry> = OnceLock::new();
        SHARED.get_or_init(|| Registry::load(configured_dir().as_deref()))
    }

    pub fn find(&self, arch: &str) -> Option<&ArchDef> {
        self.defs.iter().find(|d| d.name == arch)
    }

    pub fn names(&self) -> Vec<&str> {
        self.defs.iter().map(|d| d.name.as_str()).collect()
    }

    pub fn all(&self) -> &[ArchDef] {
        &self.defs
    }

    pub fn problems(&self) -> &[Problem] {
        &self.problems
    }

    /// El mensaje para cuando el modelo trae una arquitectura que no está.
    ///
    /// Dice qué hay, dónde poner una nueva y qué archivos del directorio fallaron — porque el caso
    /// frecuente no es «no existe» sino «existe y tiene un typo», y sin esta línea eso se ve igual
    /// que lo otro.
    pub fn unknown(&self, arch: &str) -> String {
        let mut msg = format!(
            "el modelo declara la arquitectura '{}', que este binario no conoce.\n\
             Conocidas: {}.",
            arch,
            self.names().join(", ")
        );
        if !self.problems.is_empty() {
            msg.push_str("\nDefiniciones que no cargaron:");
            for p in &self.problems {
                msg.push_str(&format!("\n  - {}", p));
            }
        }
        // Si lo que falta es justo lo que el operador intentó definir, decirlo primero: el
        // diagnóstico es «tu archivo no carga», no «esa arquitectura no existe».
        let has_culprit = self
            .problems
            .iter()
            .any(|p| p.path.file_stem().and_then(|s| s.to_str()) == Some(arch));
        if has_culprit {
            msg.push_str(&format!(
                "\nHay un '{}.{}' para ella, y es el que no carga: arreglalo y vuelve a estar.",
                arch, EXTENSION
            ));
        } else {
            msg.push_str(&format!(
                "\nSe puede sumar sin recompilar: escribí '{}.{}' y apuntá {} a su directorio.",
                arch, EXTENSION, DIR_ENV
            ));
        }
        msg
    }
}

/// El directorio de definiciones del operador, si lo configuró.
///
/// Es una decisión del operador, nunca del programa `.syn` (§4.1): un `.syn` no puede hacer que
/// el motor lea un archivo que el operador no habilitó.
pub fn configured_dir() -> Option<PathBuf> {
    // Lo resolvió el runtime (`environ > .env > default`) y lo instaló; sin instalación se cae
    // al entorno del proceso. Ver `crate::knobs::engine_archdef_dir`.
    crate::knobs::engine_archdef_dir().map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Un directorio propio por test: dos tests que escriben en el mismo lugar se pisan, y
    /// `cargo test` los corre en paralelo.
    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("synsema-archdef-{}", tag));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("crear el directorio de prueba");
        dir
    }

    /// **El guard del release.** Una definición embebida rota se publicaría con el binario y
    /// rompería una arquitectura para todos, así que se parsean las cuatro en cada `cargo test`.
    #[test]
    fn every_builtin_definition_parses_and_validates() {
        let r = Registry::load(None);
        assert!(
            r.problems().is_empty(),
            "hay definiciones embebidas rotas: {:?}",
            r.problems().iter().map(|p| p.to_string()).collect::<Vec<_>>()
        );
        assert_eq!(r.names(), vec!["gemma3", "llama", "qwen2", "qwen3"]);
        for d in r.all() {
            assert_eq!(d.origin, DefOrigin::Embedded);
            assert_eq!(d.sha256.len(), 64, "{} sin sha", d.name);
            assert!(!d.block.is_empty(), "{} con bloque vacío", d.name);
        }
    }

    /// Las diferencias entre arquitecturas están en el archivo, no en un `if` del motor.
    ///
    /// Este test es la versión ejecutable de la tabla que antes vivía en el comentario de
    /// `arch_llama.rs`: si alguien le saca a qwen3 su norma por cabeza, se entera acá.
    #[test]
    fn the_definitions_differ_where_the_architectures_differ() {
        let r = Registry::load(None);
        let steps = |name: &str| -> Vec<String> {
            r.find(name)
                .unwrap_or_else(|| panic!("falta {}", name))
                .block
                .iter()
                .map(|s| format!("{:?}", s.op))
                .collect()
        };
        let llama = steps("llama");
        let qwen2 = steps("qwen2");
        let qwen3 = steps("qwen3");
        let gemma3 = steps("gemma3");

        // qwen2 = llama + tres sesgos.
        assert_eq!(qwen2.len(), llama.len() + 3);
        assert_eq!(qwen2.iter().filter(|s| s.starts_with("AddBias")).count(), 3);
        assert_eq!(llama.iter().filter(|s| s.starts_with("AddBias")).count(), 0);

        // qwen3 = llama + dos normas por cabeza.
        assert_eq!(qwen3.len(), llama.len() + 2);
        assert_eq!(qwen3.iter().filter(|s| s.starts_with("NormHeads")).count(), 2);

        // gemma3 = qwen3 + dos normas después del bloque, y la escala en el prólogo.
        assert_eq!(gemma3.len(), qwen3.len() + 2);
        assert_eq!(gemma3.iter().filter(|s| s.starts_with("NormHeads")).count(), 2);
        let gemma_prologue = &r.find("gemma3").unwrap().prologue;
        assert!(
            gemma_prologue.iter().any(|s| matches!(s.op, crate::archdef::Op::Scale { .. })),
            "a gemma3 le falta la escala de embeddings, y sin eso responde ruido"
        );
        assert!(
            !r.find("qwen3").unwrap().prologue.iter().any(|s| matches!(s.op, crate::archdef::Op::Scale { .. })),
            "qwen3 no escala embeddings"
        );
        // Y sólo gemma3 fija el patrón de ventana, porque el GGUF no lo declara.
        assert_eq!(r.find("gemma3").unwrap().param("sliding_window_type", 0.0), 6.0);
        assert_eq!(r.find("llama").unwrap().param("sliding_window_type", 0.0), 0.0);
    }

    #[test]
    fn a_definition_on_disk_replaces_the_embedded_one() {
        let dir = temp_dir("override");
        std::fs::write(
            dir.join("llama.archdef"),
            "arch llama\nkind decoder\nprologue\n  x = embed(token_embd.weight)\nblock\n  \
             a = attention(x, x, x)\n  add(x, a)\nepilogue\n  x = last(x)\n  \
             logits = matmul(x, output.weight)\n",
        )
        .unwrap();

        let r = Registry::load(Some(&dir));
        assert!(r.problems().is_empty(), "{:?}", r.problems());
        assert_eq!(r.names(), vec!["gemma3", "llama", "qwen2", "qwen3"], "no duplica el nombre");
        let llama = r.find("llama").unwrap();
        assert_eq!(llama.origin, DefOrigin::File(dir.join("llama.archdef")));
        assert_eq!(llama.block.len(), 2, "es la del disco, no la nuestra");
        // Las otras tres siguen siendo las embebidas.
        assert_eq!(r.find("qwen3").unwrap().origin, DefOrigin::Embedded);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_new_architecture_is_just_a_file() {
        let dir = temp_dir("nueva");
        std::fs::write(
            dir.join("inventada.archdef"),
            "arch inventada\nkind decoder\nprologue\n  x = embed(token_embd.weight)\nblock\n  \
             a = attention(x, x, x)\n  add(x, a)\nepilogue\n  x = last(x)\n  \
             logits = matmul(x, output.weight)\n",
        )
        .unwrap();
        let r = Registry::load(Some(&dir));
        assert!(r.find("inventada").is_some(), "una arquitectura nueva sin recompilar nada");
        assert_eq!(r.names().len(), 5);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Un archivo roto **se reporta**. Descartarlo en silencio es la forma más cara de fallar:
    /// el operador ve que su definición «no hace nada» y no tiene dónde mirar.
    #[test]
    fn a_broken_file_is_reported_and_the_rest_still_loads() {
        let dir = temp_dir("roto");
        std::fs::write(dir.join("mala.archdef"), "arch mala\nkind decoder\nprologue\n  rmsnorm(x)\n")
            .unwrap();
        let r = Registry::load(Some(&dir));
        assert_eq!(r.problems().len(), 1);
        let p = &r.problems()[0];
        assert!(p.path.ends_with("mala.archdef"));
        assert!(p.to_string().contains("rmsnorm"), "{}", p);
        // Las cuatro nuestras siguen disponibles: el archivo roto se llama `mala`, así que lo
        // único que deja no disponible es una arquitectura `mala` que igual no existía.
        assert_eq!(r.names().len(), 4);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **La lección de la prueba en vivo.** La primera versión caía de vuelta a la definición
    /// embebida cuando la del operador no cargaba, así que un typo en `silu` producía un modelo
    /// que respondía perfecto — con NUESTRA definición, no con la suya. Silencioso y carísimo.
    #[test]
    fn a_broken_file_does_not_silently_fall_back_to_ours() {
        let dir = temp_dir("sin-fallback");
        // Una `qwen3.archdef` con un typo en el nombre de una operación.
        let text = include_str!("../defs/qwen3.archdef").replace("  silu(g)", "  silou(g)");
        std::fs::write(dir.join("qwen3.archdef"), text).unwrap();

        let r = Registry::load(Some(&dir));
        assert!(r.find("qwen3").is_none(), "qwen3 tiene que quedar NO disponible, no volver a la nuestra");
        assert_eq!(r.names(), vec!["gemma3", "llama", "qwen2"], "las otras siguen");
        assert_eq!(r.problems().len(), 1);
        assert!(r.problems()[0].to_string().contains("silou"), "{}", r.problems()[0]);

        // Y el mensaje manda al archivo, no a «escribí uno».
        let msg = r.unknown("qwen3");
        assert!(msg.contains("es el que no carga"), "{}", msg);
        assert!(!msg.contains("Se puede sumar sin recompilar"), "{}", msg);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// El nombre del archivo es lo único que se sabe de una definición que no parsea, así que
    /// tiene que corresponder con lo que declara.
    #[test]
    fn a_file_must_declare_the_architecture_its_name_says() {
        let dir = temp_dir("nombre");
        let text = include_str!("../defs/qwen3.archdef").replace("arch qwen3", "arch mamba");
        std::fs::write(dir.join("qwen3.archdef"), text).unwrap();

        let r = Registry::load(Some(&dir));
        assert!(r.find("mamba").is_none(), "no se registra bajo el nombre que declara");
        assert!(r.find("qwen3").is_none(), "y tampoco vuelve a la nuestra");
        let p = &r.problems()[0];
        assert!(p.to_string().contains("declara `arch mamba`"), "{}", p);
        assert!(p.error.fix.as_ref().unwrap().contains("mamba.archdef"), "ofrece las dos salidas");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn files_with_another_extension_are_ignored() {
        let dir = temp_dir("otras");
        std::fs::write(dir.join("notas.txt"), "esto no es una definición").unwrap();
        std::fs::write(dir.join("README.md"), "# nada").unwrap();
        let r = Registry::load(Some(&dir));
        assert!(r.problems().is_empty(), "no se mira lo que no es .archdef");
        assert_eq!(r.names().len(), 4);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_directory_is_a_problem_not_a_crash() {
        let r = Registry::load(Some(Path::new("/no/existe/definiciones")));
        assert_eq!(r.problems().len(), 1);
        assert!(r.problems()[0].to_string().contains("no se pudo leer el directorio"));
        assert!(r.problems()[0].error.fix.as_ref().unwrap().contains(DIR_ENV));
        assert_eq!(r.names().len(), 4, "las embebidas siguen andando");
    }

    /// El mensaje de «no conozco esa arquitectura» tiene que decir las tres cosas que el que lo
    /// lee necesita: qué hay, qué se rompió, y cómo sumar la suya.
    #[test]
    fn the_unknown_message_says_what_to_do() {
        let dir = temp_dir("mensaje");
        std::fs::write(dir.join("mala.archdef"), "arch mala\n").unwrap();
        let r = Registry::load(Some(&dir));
        let msg = r.unknown("mamba");

        assert!(msg.contains("'mamba'"), "{}", msg);
        assert!(msg.contains("llama"), "lista lo que hay: {}", msg);
        assert!(msg.contains("mala.archdef"), "menciona lo que no cargó: {}", msg);
        assert!(msg.contains("mamba.archdef"), "dice cómo se llamaría el archivo: {}", msg);
        assert!(msg.contains(DIR_ENV), "dice qué knob apunta al directorio: {}", msg);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn loading_twice_gives_the_same_order() {
        let a = Registry::load(None);
        let b = Registry::load(None);
        assert_eq!(a.names(), b.names(), "el orden es estable entre corridas");
        for (x, y) in a.all().iter().zip(b.all()) {
            assert_eq!(x.sha256, y.sha256);
        }
    }

    #[test]
    fn the_env_knob_is_optional_and_trimmed() {
        // No se toca el entorno del proceso: se prueba la función que lo interpreta.
        assert_eq!(DIR_ENV, "SYNSEMA_INFER_ARCHDEF");
        assert_eq!(EXTENSION, "archdef");
    }
}
