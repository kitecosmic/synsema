//! Regex con retroceso (v0.6.60): `backtrack_matches`, `backtrack_find_all`, `backtrack_capture`,
//! `backtrack_replace`. Es el espejo de `matches` / `regex_find_all` / `regex_capture` /
//! `regex_replace` con otro motor (`fancy-regex`, el de tiktoken): tiene look-around, referencias
//! hacia atrás (`\1`), cuantificadores posesivos y grupos atómicos. Puras, sin capability;
//! compilan para wasm.
//!
//! **Por qué una familia aparte y no un motor elegido según el patrón.** Los dos motores leen
//! distinto el mismo texto: `a++a` sobre `aaaa` coincide en `regex` (repetición anidada) y no en
//! `fancy-regex` (posesivo). Si el motor dependiera de qué más trae el patrón, agregarle un
//! look-ahead le cambiaría el significado a lo que ya estaba escrito. Rust y Go hacen lo mismo:
//! el motor lineal por un lado (`regex`, `regexp`), el que retrocede por otro (`fancy-regex`,
//! `regexp2`). Las `regex_*` siguen lineales.
//!
//! **El tope de pasos es de la llamada, y cuenta trabajo.** Cada llamada tiene un presupuesto,
//! `max_steps`, que gastan todas sus búsquedas (`find_all` hace una por coincidencia):
//!
//! ```text
//! max_steps = max(1 048 576, (64 + instrucciones del patrón compilado) × bytes del texto)
//! ```
//!
//! Un paso es una instrucción de la VM de la crate, más uno por cada 16 bytes de un tramo de
//! texto que una instrucción coincidió con el motor lineal, comparó contra una referencia, caminó
//! hacia atrás (un look-behind de largo fijo; los bytes que camina, ronda 3) o salteó (`\Z`), más
//! uno por cada 16 lugares de captura al empezar cada búsqueda, más 16 por cada par de letras que
//! una referencia sin distinguir mayúsculas tiene que plegar (las que no son iguales ni ASCII).
//! Cuando una búsqueda necesita un paso y no queda, la llamada es un error. Es exacto y
//! determinista: la misma llamada gasta siempre lo mismo, en todas las plataformas, y no mira el
//! reloj.
//!
//! De dónde sale la fórmula (ronda 2, B-2): un motor que no repite trabajo ejecuta cada
//! instrucción del programa a lo sumo una vez por posición del texto, así que `instrucciones ×
//! bytes` es lo más que gasta una búsqueda que no retrocede de más; pasar de ahí es retroceso
//! redundante. Es la misma cota que tienen las `regex_*` (patrón × texto). Medido: `cl100k` gasta
//! 4,8 pasos por byte con 49 instrucciones, GPT-2 6,1 con 44, `o200k` 2,5 con 29; un lexer de 21
//! ramas con look-arounds en cada una, 89 con 288, y uno de 41 ramas, 170 con 556 (cerca de 0,3
//! por instrucción). Con el término fijo solo (64, la fórmula de la ronda 1) el lexer de 21 ramas
//! fallaba desde 12 KB. El 64 cubre los patrones chicos y el piso de un millón, los textos chicos.
//!
//! Lo que la fórmula no cubre, y es a propósito (ronda 3, M-1): un motor que retrocede prueba el
//! patrón desde cada posición del texto, y una repetición seguida de algo que falla vuelve a leer
//! la corrida entera desde cada una. `\d+(?![\d.])` sobre un número de 750 cifras seguido de un
//! punto gasta 1,4 millones de pasos (el cuadrado del largo de la corrida), y lo posesivo no lo
//! arregla: lo que se repite es el arranque, no el retroceso. Es cuadrático en todo motor de
//! retroceso; acá es un error que se puede atrapar, y el mensaje dice el remedio, que es decir
//! dónde puede empezar una coincidencia: `(?<!\d)\d+(?![\d.])` gasta 13 pasos por byte.
//! `\b`, `\B`, `\<` y `\>` van al motor lineal (desde la 0.20 de la crate; antes corrían en la
//! VM): un patrón que no tiene nada más que pida retroceso va entero, sin gastar pasos.
//!
//! **Compilar también tiene techo** (ronda 2, A-2): `MAX_COMPILED_BYTES`. La crate copia el grupo
//! en cada llamada de subrutina (`\g<1>`), hasta 19 niveles: `(a|b\g<1>\g<1>)` compilaba a 649 MB
//! y con una llamada más no terminaba (abortaba el proceso por memoria, y `max_steps` no corre al
//! compilar). El fork corta apenas el programa pasa del techo: esos patrones son un error en 20 ms
//! con 20 MB de pico. El techo acota también las instrucciones de la fórmula de arriba.
//!
//! **El techo cuenta también lo que una búsqueda necesita** (ronda 4, A-1 y A-2). Cada tramo del
//! patrón que va al motor lineal es una regex aparte con su caché de búsqueda, y un patrón que
//! va entero es una sola. Una parte de esa caché no depende del texto: la tabla con la que el
//! motor lineal sigue los grupos (la de su PikeVM: estados del tramo × lugares de captura × 16
//! bytes), que arma la primera vez que la usa. Con 60 grupos sobre `\w` son 36 MB, con 100 son
//! 99 MB, y nadie los contaba: en `backtrack_*` pasaban del presupuesto de búsqueda y la caché se
//! soltaba y se rehacía en cada búsqueda (de 19,5 ms a 100 s sobre 20 KB, sin pasar el tope de
//! pasos), y en un patrón que va entero quedaban retenidos. Ahora el fork cuenta al compilar la
//! caché de cada tramo con todo lo que va a tener, adentro del techo: esos patrones son un
//! error al compilar (en milisegundos, sin pedir la tabla), y el que compila tiene acotado lo que
//! pide al buscar. Es más estricto que las `regex_*`, que sólo acotan el compilado: 30 grupos
//! `(\w)` entran (11,9 MiB) y 40 no.
//!
//! **Por qué pasos y no retrocesos.** El tope de la crate (`backtrack_limit`) cuenta retrocesos, y
//! el trabajo entre dos retrocesos no tiene techo: con look-arounds adentro de repeticiones,
//! `(?:(?=(?:(?=[^x]*y)a)*+y)a)*+y` tardaba 9 s sobre 3 200 letras con 3 202 retrocesos (ronda 1
//! de la auditoría, A-1). Contar instrucciones hace falta adentro de la VM, así que el motor usa
//! `fancy-regex` 0.20.2 con un parche (`engine/vendor/fancy-regex`, ver su `SYNSEMA.md`): las
//! búsquedas `*_with_steps` reciben el presupuesto y lo devuelven con lo que queda. Por eso hay un
//! solo compilado por patrón: el tope no se fija al compilar.
//!
//! **Lo que el tope no acota.** El tiempo de un paso no es constante en un caso: un tramo que el
//! motor lineal lee y **no** coincide cuesta su paso solo, porque el motor lineal no dice hasta
//! dónde leyó. Un paso cuesta entonces, a lo sumo, una pasada del motor lineal por el resto del
//! texto: el tiempo de una llamada está acotado por `pasos × bytes del texto`, no por los pasos
//! solos. Un patrón que en cada posición lee el resto del texto sin encontrar lo que busca
//! (`(?:(?![^x]*z)a)*+y`) es cuadrático con pocos pasos: 3 s sobre 64 KB, y con 29 de esos
//! look-aheads por posición, 5,7 s sobre 16 KB (el tope por defecto crece con el patrón, así que
//! entran todos los que se escriban). Es el mismo residuo que tienen las `regex_*` con ciertos
//! patrones (la crate `regex` lo documenta para sus iteradores). Lo exponencial y lo polinomial
//! por anidamiento se cortan, y lo demás que una instrucción lee del texto se cobra (ronda 2,
//! B-1: caminar hacia atrás, `\Z`, los lugares de captura).
//!
//! **Cubrir todo el texto lo hace el motor, no el texto del patrón** (ronda 2). `backtrack_matches`
//! compila el patrón con `RegexBuilder::full_match` del fork: el patrón se parsea tal como está
//! escrito, y las dos aserciones (principio y fin del texto) se ponen alrededor de su árbol.
//! Envolver el texto como `^(?:…)$`, que es lo que hacía la ronda 1 (y lo que hace `matches` con
//! la crate `regex`, que no tiene subrutinas), le cambiaba el significado a `\g<0>`: «el patrón
//! entero» pasaba a incluir las anclas, y `backtrack_matches("((a)(b))", "\((?:[^()]|\g<0>)*\)")`
//! daba `false` sin error. De paso deja de hacer falta validar el patrón aparte (uno
//! desbalanceado, `a)(b`, ya no queda bien por el envoltorio) y el salto de línea para el que
//! termina en un comentario del modo verboso.
//!
//! **Lo que corre antes del tope también tiene techo** (ronda 3, M-2): `MAX_PATTERN_BYTES`.
//! Parsear y analizar un patrón no gasta pasos, y cuesta memoria (unas 160 veces el patrón) y
//! tiempo según su largo; el techo del compilado corta después. Un patrón de más de 16 KiB es un
//! error antes de parsearlo. Y el análisis de la crate que busca recursión por izquierda era
//! cuadrático en los grupos (7,6 s con 16 000): en el fork es lineal.
//!
//! **Lo que las cachés crecen al buscar tiene presupuesto** (ronda 3, A-2): `SEARCH_CACHE_BYTES`.
//! La otra parte de la caché de un tramo sí depende del texto: los estados de su DFA perezoso,
//! que se arman a medida que lee. La crate guardaba las cachés adentro de cada regex: 400 tramos
//! retenían 431 MB después de una búsqueda de 40 KB. En el fork las cachés de un patrón están
//! juntas, y después de cada búsqueda de un tramo se cuenta la suya: cuando entre todas tienen
//! más que lo contado al compilar más el presupuesto, se sueltan todas y cada una se rehace
//! cuando su tramo vuelve a buscar. Se mide el crecimiento, no el total (ronda 4, A-1): la tabla
//! de grupos, que ya está contada, no hace soltar nada cuando aparece. El resultado y los pasos
//! son los mismos; cambia el tiempo si el patrón necesita crecer más que el presupuesto (48
//! tramos distintos, de medio megabyte cada uno, las sueltan sobre un texto de 12 KB). Y al
//! terminar la llamada, un patrón que quedó con más de `KEPT_SEARCH_CACHE_BYTES` las suelta,
//! vaya o no entero al motor lineal: entre llamadas, los 32 patrones de la caché del hilo
//! retienen a lo sumo eso cada uno.
//!
//! **Una referencia escrita adentro de su grupo lee la vuelta anterior.** En `(a\1?)+` la
//! referencia corre mientras el grupo 1 todavía está coincidiendo. Lee lo que el grupo coincidió
//! la vez anterior, como PCRE, Perl y Oniguruma, y la primera vez no coincide: es lo que hace la
//! crate desde la 0.20. La 0.18.0 leía desde el comienzo de esta vuelta hasta el fin de la
//! anterior, que es otro texto (o ninguno, cuando quedaban cruzados: ahí entraba en pánico), y
//! por eso en la ronda 3 esos patrones eran un error de compilación
//! (`reject_self_backrefs`, que ya no está). Lo mismo vale para la referencia que llega a su
//! grupo por una llamada de subrutina (`(a\g<2>)(\1)`), y `(?(1)…)` adentro del grupo 1 pregunta
//! si el grupo coincidió, no si empezó (ronda 4, M-1 y B-1). Python (`re`) no compila la
//! referencia a un grupo abierto.
//!
//! **Sin distinguir mayúsculas, una referencia compara letra por letra** (ronda 4, A-3 y M-2).
//! Upstream compara un tramo del texto del mismo largo en bytes que el grupo, y dos letras que
//! son la misma pueden ocupar distinto (`ẞ` 3 bytes y `ß` 2): la referencia se comía lo que
//! sobraba o no coincidía. El fork lee una letra del texto por cada letra del grupo, con el
//! plegado simple de Unicode (el de un literal con `(?i)`), y da lo que dan Perl y el módulo
//! `regex` de Python. La 0.18.0, además, armaba una regex con el texto del grupo en cada
//! comparación: con un grupo de 140 KB esa regex no se podía construir, y era un pánico.
//!
//! **Las repeticiones se compilan como están escritas.** La 0.20 de la crate trae un optimizador
//! que reescribe repeticiones, y con grupos adentro cambia los grupos (`(a){1,3}\n??(a){2,}` sale
//! con tres grupos y los dos escritos sin coincidir: 8 patrones de 3 000 en el fuzz diferencial
//! de esta versión). El fork tiene una opción para dejarlas (`optimize_repeats(false)`); lo que
//! el optimizador hace sin tocar grupos queda: sacar del patrón el look-ahead del final, para
//! que lo demás vaya entero al motor lineal (`\w+(?=,)` no gasta pasos), y `\K`.
//!
//! **El resultado no depende de dónde corre el patrón** (rondas 5 y 6, M-1). Los dos motores
//! leen distinto una sola cosa: la vuelta que no lee nada de una repetición sin tope cuyo cuerpo
//! puede coincidir vacío (`(b?)*`, `(a*)+`, `(?:a?|b)+`). El motor lineal no la sigue nunca:
//! descarta ese camino del cuerpo y pasa al siguiente que lee texto. La VM la deja pasar una vez
//! y sale del lazo ahí, como Perl y PCRE. Entonces un grupo de adentro queda vacío en la VM y
//! con lo último que leyó en el motor lineal (`(b?)*` sobre `b`), y cuando el cuerpo prueba un
//! camino vacío antes que uno que lee, cambia la coincidencia (`(?:a?|b)+` sobre `ab`: `a` en la
//! VM, `ab` en el motor lineal). Qué motor corría la repetición dependía de lo de alrededor (un
//! look-ahead al final, que el optimizador saca; un look-behind al lado), que no cambia lo que
//! el patrón coincide: `backtrack_capture("b", "(b?)*")` daba `["b"]` y con `(?<!x)` atrás,
//! `[""]`. En el fork esa repetición corre siempre en la VM, tenga o no un grupo adentro
//! (`analyze.rs` la marca como las demás cosas que el motor lineal no resuelve), y la lectura es
//! una: la de Perl. Cuesta que esos patrones gasten pasos, y es la forma que retrocede
//! (`(?:a*)*b`). Una repetición contada (`{n,m}`) no tiene lazo, y una cuyo cuerpo siempre lee
//! no tiene vuelta vacía: dan lo mismo en los dos motores y siguen yendo al motor lineal.
//!
//! La otra cosa que leen distinto es una alternancia cuyas ramas empiezan igual (ronda 6,
//! propio). `regex-syntax` saca factor común de ese comienzo (`a?a|a?b` pasa a ser
//! `a?(?:a|b)`), y cuando el comienzo puede terminar en más de un lugar, la forma factorizada
//! prueba las maneras en otro orden: sobre `ab` da `ab`, y el patrón como está escrito da `a`
//! (en Perl, en Python y en la VM). La regla es la misma: esa alternancia corre siempre en la
//! VM. Cuál es no se deduce de la forma del patrón (se intentó en las rondas 6 y 7, copiando
//! las reglas de `regex-syntax`, y cada auditoría encontró un caso que la copia no tenía): al
//! compilar, el fork arma lo que el motor lineal recibiría y mira qué devolvió `regex-syntax`
//! para cada alternancia. Si salió con un comienzo sacado afuera que puede terminar en más de
//! un lugar, corre en la VM; las demás (ramas que empiezan distinto, `\w+|\d+`, literales, un
//! comienzo común de un solo final como en `\bfoo|\bbar+`) van al motor lineal. Cuesta
//! traducir el patrón una vez más al compilarlo (dos donde hay un `{0}`).
//!
//! **Un cuantificador sobre otro es un error** (ronda 5, B-3): `a{2}{3}`, `a*{2}`, `a+?+`, como
//! `a**`. La crate cerraba la pieza en el primer cuantificador y leía la llave que seguía como
//! texto (`a{2}{3}` coincidía con `aa{3}`); Perl y `re` lo rechazan, y las `regex_*` lo leen
//! como repetición de la repetición. Lo que se quiso escribir es `(?:a{2}){3}`.
//!
//! **Una cuenta con el mínimo mayor que el máximo es un error** (ronda 6, M-2): `a{3,2}`. La
//! crate la aceptaba y cada parte la leía a su modo (`{3}` el motor lineal, `{2}` la VM, y el
//! DFA de un look-behind no compilaba); además el análisis le daba el tamaño de la cuenta mayor,
//! y la VM daba vueltas vacías sobre ella sin el chequeo que las corta. PCRE2, Python y las
//! `regex_*` la rechazan; Perl la acepta y no coincide nunca.
//!
//! **Un posesivo es goloso también con `(?U)`** (ronda 6, B-2), como en PCRE: `(?U)a++` es
//! `a++`. La crate lo dejaba perezoso y posesivo a la vez: tomaba lo mínimo y no lo devolvía.
//!
//! **Un comentario adentro de la llave de una cuenta no se saltea** (ronda 6, N-2): `a{(?#c)2}`
//! es el texto `a{2}`, como en Perl, PCRE2 y Python. La crate lo leía como la cuenta.
//!
//! **Un nombre de grupo va en un solo grupo** (ronda 5, B-2). La crate acepta nombres repetidos
//! y `\k<n>` lee sólo el último grupo de ese nombre; los motores que los aceptan no leen lo
//! mismo entre sí, y los demás los rechazan. Acá son un error (`repeated_group_name`).
//!
//! **Un pánico de la crate es un error de la llamada** (`guarded`). La 0.18.0 tenía dos pánicos
//! alcanzables desde un patrón y la 0.20.2 publicada tiene otro; los que se conocen están
//! arreglados en el fork, con su test. Para los que no se conocen, cada llamada corre adentro de
//! `catch_unwind`: el programa recibe un error que puede atrapar («internal error in the regex
//! engine»), no termina. Y el pánico atrapado no se imprime (ronda 5, B-4): el hook de pánico
//! corre antes de que `catch_unwind` lo atrape, y su mensaje, que puede citar el texto de la
//! llamada, iba a stderr sin pasar por la redacción de etiquetas. Tampoco le saca el modo raw a
//! una terminal abierta (ronda 6, B-1): el hook de `term.rs`, que restaura la consola para el
//! pánico que termina el programa, pregunta antes si a éste lo atrapan (`panic_is_caught`). En
//! wasm un pánico sigue siendo un trap (se compila con `panic = "abort"`), y se imprime.
//!
//! **Sólo texto.** Texto, patrón y reemplazo tienen que ser texto; las `regex_*` convierten lo
//! que reciben, estas no.
//!
//! **`\G` se rechaza.** El iterador de la crate le avisa a su VM, con una bandera interna, que la
//! coincidencia anterior fue vacía; el bucle de este módulo (que hace falta para que todas las
//! búsquedas gasten del mismo presupuesto) no la pasa, y `\G` daría otro resultado. El parche de
//! la crate es mínimo a propósito y no la expone. Todo lo demás da igual que el iterador: lo fija
//! `the_loop_matches_the_crate_iterator`.

use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::rc::Rc;

use fancy_regex::{
    CompileError as FancyCompile, Error as FancyError, Expr, Regex, RegexBuilder, RuntimeError as FancyRuntime,
};
use num_bigint::Sign;
use synsema_core::interpreter::{py_repr_str, translate_replacement, Control, Interpreter, RuntimeError};
use synsema_core::pattern_cache::{
    register_cleaner, PatternCache, AS_WRITTEN, FULL_MATCH, FULL_MATCH_DOES_NOT_FIT, KEPT_SEARCH_CACHE_BYTES,
};
use synsema_core::types::{syn_bool, syn_list, syn_text, SynValue};

/// El tope por defecto de una llamada, para textos chicos.
pub const MAX_STEPS_FLOOR: u64 = 1 << 20;
/// El tope por defecto crece con el texto: tantos pasos por byte, más uno por cada instrucción
/// del patrón compilado.
pub const MAX_STEPS_PER_BYTE: u64 = 64;
/// La pila de retroceso de la VM de la crate (`MAX_STACK` en su `vm.rs`): no se configura.
const VM_STACK: usize = 1_000_000;
/// El techo del compilado de un patrón, en bytes (`RegexBuilder::program_size_limit` del fork):
/// las instrucciones del programa, lo que tienen adentro (las regex que cada tramo le pasa al
/// motor lineal) y la caché de búsqueda de cada una de esas regex con todo lo que va a tener sea
/// cual sea el texto (la tabla de grupos). Es del orden del límite de la crate `regex` para las
/// `regex_*` (10 MB de NFA): el mayor patrón de una sola pieza que ese límite acepta (`\w{209}`)
/// son 14,2 MiB, y entra. Medido: `cl100k` 0,37 MiB, GPT-2 0,22; un lexer de 21 ramas con
/// look-arounds Unicode, 0,28 (desde la 0.20 de la crate un look-around de una sola clase no
/// compila una regex).
///
/// Los tamaños son los de la plataforma (un puntero pesa distinto en wasm32): un patrón a pocos
/// por ciento del techo puede entrar en una y no en otra.
pub const MAX_COMPILED_BYTES: usize = 16 << 20;
/// El largo máximo de un patrón, en bytes. Lo que la crate hace antes de compilar (parsear el
/// patrón y analizar su árbol) no gasta pasos ni lo ve el techo del compilado, y crece con el
/// largo: unas 160 veces el patrón en memoria. Con 16 KiB son 3 MB y milisegundos. Los patrones
/// de tokenizador miden 100 a 300 bytes, y un lexer de 143 ramas con look-arounds, 2,7 KB.
pub const MAX_PATTERN_BYTES: usize = 16 * 1024;
/// Lo más que crecen las cachés de búsqueda de un patrón mientras una llamada busca, en bytes
/// (`RegexBuilder::search_cache_limit` del fork), por encima de lo que se contó para ellas al
/// compilar: pasado, se sueltan todas y se rehacen. Lo que cuenta es lo que cada motor dice que
/// tiene su caché; el proceso retiene hasta el doble de eso (la capacidad de sobra de sus tablas),
/// más lo que crece una búsqueda de un tramo antes de que se la cuente (el DFA perezoso de un
/// tramo tiene su propio límite, 2 MiB). Lo más que tienen a la vez es entonces lo contado
/// (adentro de `MAX_COMPILED_BYTES`) más esto. Medido con 200 tramos distintos que llenan cada
/// uno su DFA: 32 MB de pico en el proceso, contra 265 MB sin este límite.
pub const SEARCH_CACHE_BYTES: usize = 16 << 20;

/// `max_steps` cuando la llamada no lo pasa: depende del largo del texto y de cuántas
/// instrucciones tiene el patrón compilado (`Regex::program_len`; 0 si el motor lineal lo resuelve
/// entero, que no gasta pasos).
pub fn default_max_steps(text_len: usize, instructions: usize) -> u64 {
    let per_byte = MAX_STEPS_PER_BYTE.saturating_add(instructions as u64);
    (text_len as u64).saturating_mul(per_byte).max(MAX_STEPS_FLOOR)
}

/// El tope por defecto de una llamada con este texto y este patrón. Compila el patrón (queda en
/// la caché para la búsqueda): uno inválido es su error.
pub fn default_max_steps_for(text: &str, pattern: &str, full_match: bool) -> Result<u64, Failure> {
    guarded(|| Ok(default_max_steps(text.len(), compiled(pattern, full_match)?.program_len())))
}

/// Por qué no hubo resultado.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    /// El patrón no compila (o usa `\G`): el detalle.
    InvalidPattern(String),
    /// El patrón tiene más de `MAX_PATTERN_BYTES` bytes: cuántos.
    PatternTooLong(usize),
    /// La llamada pasó de `max_steps`.
    StepLimit,
    /// La pila de retroceso de la VM se llenó.
    VmStack,
    /// Cualquier otro error de corrida de la crate (su enum no es exhaustivo).
    Other(String),
    /// La crate entró en pánico adentro de la llamada: el texto del pánico. Es un error del
    /// motor de regex, no del programa (ver `guarded`).
    Engine(String),
}

thread_local! {
    /// Los compilados del hilo: clave = (patrón como lo escribió el programa, variante). El
    /// inicializador anota cómo se vacía (corre una vez por hilo, la primera vez que se usa):
    /// `Interpreter::reset_for_request` suelta también estos.
    static CACHE: RefCell<PatternCache<Rc<Regex>>> = {
        register_cleaner(clear_cache);
        RefCell::new(PatternCache::new())
    };
}

fn clear_cache() -> usize {
    CACHE.with(|c| c.borrow_mut().clear())
}

/// Una llamada entera a la crate (compilar, buscar, leer los grupos, armar el reemplazo). Si la
/// crate entra en pánico adentro, la llamada es un error que el programa puede atrapar con `try`,
/// y no el fin del programa (ronda 4, A-3: la versión 0.18.0 tenía dos pánicos alcanzables desde
/// un patrón, y la 0.20.2 sin el parche tiene otro). Es una defensa para la clase entera: los
/// pánicos que se conocen están arreglados en el fork y cada uno tiene su test.
///
/// El compilado que estaba en uso pudo quedar a medias: se sueltan todos los del hilo, y la
/// llamada siguiente compila de nuevo.
///
/// Donde el motor se compila con `panic = "abort"` (los artefactos wasm) un pánico no se puede
/// atrapar: ahí sigue siendo un trap.
///
/// **El pánico atrapado no se imprime** (ronda 5, B-4). `catch_unwind` no frena el hook de
/// pánico del proceso: Rust lo llama donde ocurre el pánico, antes de desenrollar, y el hook
/// escribe en stderr `thread '…' panicked at …: <mensaje>`. El mensaje de un pánico puede citar
/// el texto de la llamada (el de cortar un `str` en mitad de una letra cita hasta 256 bytes), y
/// stderr es el log de `serve`: lo que el programa ve pasa por la redacción de etiquetas, y eso
/// no. Mientras un hilo corre adentro de `guarded`, el hook no imprime (`quiet_while_guarded`);
/// anota dónde fue el pánico, que va al final del detalle del error, entre paréntesis: es lo
/// único que stderr tenía y el error no.
fn guarded<R>(call: impl FnOnce() -> Result<R, Failure>) -> Result<R, Failure> {
    #[cfg(panic = "unwind")]
    quiet_while_guarded();
    let outer = IN_GUARDED.replace(true);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(call));
    IN_GUARDED.set(outer);
    match outcome {
        Ok(result) => result,
        Err(payload) => {
            clear_cache();
            let detail = payload
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic".to_string());
            Err(Failure::Engine(match PANIC_AT.take() {
                Some(at) => format!("{} ({})", detail, at),
                None => detail,
            }))
        }
    }
}

thread_local! {
    /// `true` mientras este hilo corre una llamada adentro de `guarded`.
    static IN_GUARDED: Cell<bool> = const { Cell::new(false) };
    /// Dónde fue el pánico que `guarded` está por atrapar (`archivo:línea`): lo anota el hook.
    static PANIC_AT: Cell<Option<String>> = const { Cell::new(None) };
}

/// `true` cuando a un pánico de este hilo, ahora, lo atrapa `guarded` y el programa sigue: el
/// hilo está adentro de una llamada de `backtrack_*`, en un binario donde un pánico desenrolla
/// (donde aborta no hay quien lo atrape, aunque el hilo esté marcado).
///
/// Lo pregunta el hook de pánico de `term.rs`, que restaura la consola para el pánico que
/// termina el programa (ronda 6, B-1). Si restaurara también por uno que se atrapa, el programa
/// seguiría con su terminal abierta y la consola fuera de modo raw. Y que lo hiciera o no
/// dependía de cuál de los dos hooks se había instalado último (el último corre primero), que es
/// el orden de dos llamadas del programa sin relación entre sí: `term_open` y la primera
/// `backtrack_*`.
#[cfg(feature = "native")]
pub(crate) fn panic_is_caught() -> bool {
    cfg!(panic = "unwind") && IN_GUARDED.try_with(|g| g.get()).unwrap_or(false)
}

/// Instala, una vez por proceso, un hook de pánico que envuelve al que había: un pánico de un
/// hilo que está adentro de `guarded` no se imprime (se anota dónde fue), y cualquier otro sigue
/// al hook anterior como si éste no estuviera. Se instala en la primera llamada de `backtrack_*`
/// y no al arrancar: un programa que no las usa no cambia nada.
///
/// Sólo donde un pánico desenrolla: con `panic = "abort"` no hay nada que atrapar, y el mensaje
/// del hook es lo único que queda del pánico.
#[cfg(panic = "unwind")]
fn quiet_while_guarded() {
    static HOOK: std::sync::Once = std::sync::Once::new();
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            // `try_with`: un pánico mientras el hilo termina ya no tiene sus thread-locals.
            if IN_GUARDED.try_with(|g| g.get()).unwrap_or(false) {
                let at = info.location().map(|l| format!("{}:{}", l.file(), l.line()));
                let _ = PANIC_AT.try_with(|p| p.set(at));
            } else {
                previous(info);
            }
        }));
    });
}

#[cfg(test)]
thread_local! {
    /// Cuántas veces se compiló en este hilo (los tests miran que la caché se use).
    static BUILDS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// Con `true`, la próxima búsqueda de este hilo entra en pánico (el test de `guarded`).
    static PANIC_IN_SEARCH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

const NO_CONTINUE_ANCHOR: &str = "\\G (continue from the previous match) is not supported by backtrack_*";

fn uses_continue_anchor(pattern: &str) -> bool {
    let is = |e: &Expr| matches!(e, Expr::ContinueFromPreviousMatchEnd);
    match Expr::parse_tree(pattern) {
        Ok(tree) => is(&tree.expr) || tree.expr.has_descendant(is),
        // Si no parsea, el error lo da la compilación.
        Err(_) => false,
    }
}

/// Ronda 5, B-2: el primer nombre de grupo que el patrón usa en más de un grupo. La crate los
/// acepta, y `\k<n>` (y `(?(<n>)…)`) lee sólo el último grupo de ese nombre: en
/// `(?:(?<n>a)|(?<n>b))\k<n>` la referencia no coincide nunca cuando el que coincidió fue el
/// primero, sin error. Los motores que aceptan nombres repetidos no leen lo mismo (Perl, el de
/// más a la izquierda que coincidió; Oniguruma, del último al primero; .NET, un solo grupo), y
/// PCRE2 sin `(?J)`, `re` de Python y las `regex_*` los rechazan. Acá también son un error.
fn repeated_group_name(re: &Regex) -> Option<String> {
    let mut seen = HashSet::new();
    re.capture_names().flatten().find(|name| !seen.insert(*name)).map(str::to_string)
}

fn repeated_name(name: &str) -> String {
    format!(
        "the group name '{}' is on more than one group, and backtrack_* take one group per name (regex engines \
         disagree on what \\k<{}> reads otherwise); give each group its own name",
        name, name
    )
}

/// El detalle del error de un patrón que compila a más que el techo. Nombra las tres formas de
/// llegar: las copias de una subrutina, una repetición con cuenta de una clase Unicode (un tramo
/// grande para el motor lineal) y la tabla de grupos de un tramo.
fn too_large() -> String {
    format!(
        "the compiled pattern, with the memory its searches need, is over {} MiB: a subroutine call (\\g<1>) \
         copies its group at every call, a counted repetition of a Unicode class (\\w{{300}}) is large, and capture \
         groups multiply what a search needs (groups × size of the pattern); write it so that it repeats less, \
         capture less ((?:…) does not capture) or use ASCII classes ([0-9A-Za-z_] for \\w), or split it into \
         several patterns",
        MAX_COMPILED_BYTES >> 20
    )
}

/// Compila `pattern` con un techo de tamaño (el del módulo; los tests pasan uno chico). Con
/// `full_match`, el que sólo coincide con el texto entero (`backtrack_matches`): lo arma el motor
/// sobre el árbol del patrón (`RegexBuilder::full_match` del fork), no sobre su texto. El patrón
/// se parsea tal como está escrito, así que uno inválido da el mismo error que sin `full_match`, y
/// `\g<0>` (el patrón entero) sigue siendo lo que el programa escribió.
///
/// El tope de retrocesos de la crate queda sin efecto (`usize::MAX`): cada retroceso viene
/// después de una instrucción, así que el presupuesto de pasos se acaba antes.
fn build_one(pattern: &str, full_match: bool, limit: usize) -> Result<Rc<Regex>, Failure> {
    #[cfg(test)]
    BUILDS.with(|b| b.set(b.get() + 1));
    let re = RegexBuilder::new(pattern)
        .backtrack_limit(usize::MAX)
        .program_size_limit(limit)
        .full_match(full_match)
        .search_cache_limit(SEARCH_CACHE_BYTES)
        .optimize_repeats(false)
        .build()
        .map_err(|e| match e {
            FancyError::CompileError(c) => match *c {
                FancyCompile::ProgramTooLarge { .. } => Failure::InvalidPattern(too_large()),
                c => Failure::InvalidPattern(FancyError::CompileError(Box::new(c)).to_string()),
            },
            e => Failure::InvalidPattern(e.to_string()),
        })?;
    if uses_continue_anchor(pattern) {
        return Err(Failure::InvalidPattern(NO_CONTINUE_ANCHOR.to_string()));
    }
    if let Some(name) = repeated_group_name(&re) {
        return Err(Failure::InvalidPattern(repeated_name(&name)));
    }
    Ok(Rc::new(re))
}

/// El compilado que guarda la caché. Si el de `full_match` falla, el error es el del patrón tal
/// como está escrito; y si ése compila (el de `full_match` es otro programa: lleva además la
/// pieza que comprueba el fin del texto, y puede pasar del techo cuando el otro no), el error
/// dice que es por cubrir todo el texto.
fn build(pattern: &str, full_match: bool, limit: usize) -> Result<Rc<Regex>, Failure> {
    let failed = match build_one(pattern, full_match, limit) {
        Err(Failure::InvalidPattern(detail)) if full_match => detail,
        other => return other,
    };
    build_one(pattern, false, limit)?;
    Err(Failure::InvalidPattern(format!("{}{}", FULL_MATCH_DOES_NOT_FIT, failed)))
}

/// El compilado de `pattern` (el patrón como lo escribió el programa), de la caché del hilo o
/// recién hecho. La clave lleva la variante: el que cubre todo el texto (`backtrack_matches`) es
/// otro compilado que el de las búsquedas.
fn compiled(pattern: &str, full_match: bool) -> Result<Rc<Regex>, Failure> {
    // Antes de parsearlo: es lo que acota lo que cuesta llegar hasta el techo del compilado.
    if pattern.len() > MAX_PATTERN_BYTES {
        return Err(Failure::PatternTooLong(pattern.len()));
    }
    let variant = if full_match { FULL_MATCH } else { AS_WRITTEN };
    CACHE.with(|c| c.borrow_mut().get_or_try_insert(pattern, variant, || build(pattern, full_match, MAX_COMPILED_BYTES)))
}

/// Las búsquedas de una llamada, con su presupuesto.
pub struct Search {
    re: Rc<Regex>,
    max_steps: u64,
    left: u64,
}

impl Search {
    /// Compila el patrón: uno inválido es error aunque el texto esté vacío.
    pub fn new(pattern: &str, full_match: bool, max_steps: u64) -> Result<Self, Failure> {
        Ok(Search { re: compiled(pattern, full_match)?, max_steps, left: max_steps })
    }

    /// El compilado (para lo que no depende de la búsqueda: cuántos grupos tiene).
    pub fn regex(&self) -> &Regex {
        &self.re
    }

    /// Los pasos gastados hasta ahora.
    pub fn spent(&self) -> u64 {
        self.max_steps - self.left
    }

    /// Una búsqueda: `f` recibe el compilado y el presupuesto que queda, y lo deja con lo que
    /// sobró.
    pub fn run<R>(&mut self, f: impl FnOnce(&Regex, &mut u64) -> fancy_regex::Result<R>) -> Result<R, Failure> {
        #[cfg(test)]
        if PANIC_IN_SEARCH.with(|p| p.get()) {
            panic!("un pánico plantado por el test");
        }
        match f(&self.re, &mut self.left) {
            Ok(r) => Ok(r),
            Err(FancyError::RuntimeError(FancyRuntime::StepLimitExceeded)) => Err(Failure::StepLimit),
            Err(FancyError::RuntimeError(FancyRuntime::StackOverflow)) => Err(Failure::VmStack),
            Err(e) => Err(Failure::Other(e.to_string())),
        }
    }
}

/// Al terminar la llamada (con resultado o con error), el patrón no se queda con más caché de
/// búsqueda que `KEPT_SEARCH_CACHE_BYTES`: el compilado sigue en la caché del hilo, y lo que
/// retiene entre llamadas tiene que estar acotado por patrón.
impl Drop for Search {
    fn drop(&mut self) {
        // Con un pánico en curso el compilado no se toca: `guarded` lo suelta entero.
        if !std::thread::panicking() {
            self.re.trim_search_caches(KEPT_SEARCH_CACHE_BYTES);
        }
    }
}

/// La posición del carácter siguiente a `i` (o una más allá del final).
fn next_char(text: &str, i: usize) -> usize {
    i + text[i..].chars().next().map_or(1, char::len_utf8)
}

/// Recorre las coincidencias de izquierda a derecha, sin solaparse, como el iterador de la crate
/// (`Matches::next_with`): después de una coincidencia vacía avanza un carácter, y una vacía
/// pegada al final de la anterior no cuenta. `find` busca desde una posición, con el presupuesto,
/// y devuelve lo que encontró con su comienzo y su final.
fn each_match<R>(
    text: &str,
    search: &mut Search,
    find: impl Fn(&Regex, usize, &mut u64) -> fancy_regex::Result<Option<(R, usize, usize)>>,
    mut visit: impl FnMut(R, usize, usize),
) -> Result<(), Failure> {
    let mut pos = 0usize;
    let mut last_match: Option<usize> = None;
    while pos <= text.len() {
        let Some((found, start, end)) = search.run(|re, steps| find(re, pos, steps))? else { break };
        if start == end {
            pos = next_char(text, end);
            if Some(end) == last_match {
                continue;
            }
        } else {
            pos = end;
        }
        last_match = Some(end);
        visit(found, start, end);
    }
    Ok(())
}

fn find_span(re: &Regex, text: &str, pos: usize, steps: &mut u64) -> fancy_regex::Result<Option<((), usize, usize)>> {
    Ok(re.find_from_pos_with_steps(text, pos, steps)?.map(|m| ((), m.start(), m.end())))
}

/// `backtrack_find_all`: las coincidencias completas.
pub fn find_all<'t>(text: &'t str, pattern: &str, max_steps: u64) -> Result<Vec<&'t str>, Failure> {
    guarded(|| {
        let mut search = Search::new(pattern, false, max_steps)?;
        let mut out = Vec::new();
        each_match(text, &mut search, |re, pos, steps| find_span(re, text, pos, steps), |(), s, e| out.push(&text[s..e]))?;
        Ok(out)
    })
}

/// `backtrack_capture`: de la primera coincidencia, los grupos (uno que no participó es `None`);
/// sin grupos en el patrón, la coincidencia sola. `None` si no hay coincidencia.
pub fn capture<'t>(text: &'t str, pattern: &str, max_steps: u64) -> Result<Option<Vec<Option<&'t str>>>, Failure> {
    guarded(|| {
        let mut search = Search::new(pattern, false, max_steps)?;
        let Some(caps) = search.run(|re, steps| re.captures_from_pos_with_steps(text, 0, steps))? else {
            return Ok(None);
        };
        let groups = search.regex().captures_len() - 1;
        if groups == 0 {
            return Ok(Some(vec![caps.get(0).map(|m| m.as_str())]));
        }
        Ok(Some((1..=groups).map(|i| caps.get(i).map(|m| m.as_str())).collect()))
    })
}

/// `backtrack_replace`: el texto con todas las coincidencias reemplazadas, o `None` si no hubo
/// ninguna (el llamador devuelve el mismo valor). `replacement` es la plantilla de `regex_replace`
/// (`\1`, `\g<1>`, `$` literal).
pub fn replace(text: &str, pattern: &str, replacement: &str, max_steps: u64) -> Result<Option<String>, Failure> {
    guarded(|| {
        let mut search = Search::new(pattern, false, max_steps)?;
        let template = translate_replacement(replacement);
        let mut out = String::new();
        let mut last = 0usize;
        let mut any = false;
        each_match(
            text,
            &mut search,
            |re, pos, steps| {
                Ok(re.captures_from_pos_with_steps(text, pos, steps)?.and_then(|caps| {
                    let (s, e) = caps.get(0).map(|m| (m.start(), m.end()))?;
                    Some((caps, s, e))
                }))
            },
            |caps, s, e| {
                any = true;
                out.push_str(&text[last..s]);
                caps.expand(&template, &mut out);
                last = e;
            },
        )?;
        if !any {
            return Ok(None);
        }
        out.push_str(&text[last..]);
        Ok(Some(out))
    })
}

/// `backtrack_matches`: si el patrón cubre todo el texto (el compilado de `full_match`).
pub fn matches(text: &str, pattern: &str, max_steps: u64) -> Result<bool, Failure> {
    guarded(|| {
        let mut search = Search::new(pattern, true, max_steps)?;
        search.run(|re, steps| re.find_from_pos_with_steps(text, 0, steps).map(|m| m.is_some()))
    })
}

// ---------- los builtins ----------

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

#[cold]
#[inline(never)]
fn failure(name: &str, pattern: &str, max_steps: u64, f: Failure) -> Control {
    err(match f {
        Failure::InvalidPattern(detail) => format!("invalid regex pattern {}: {}", py_repr_str(pattern), detail),
        // No repite el patrón: es largo por definición.
        Failure::PatternTooLong(len) => format!(
            "{}: the pattern is {} bytes long, and a backtrack_* pattern may be at most {}; split it into several \
             patterns",
            name, len, MAX_PATTERN_BYTES
        ),
        Failure::StepLimit => format!(
            "{}: step limit exceeded (max_steps = {}) — the pattern did more work on this text than the limit \
             allows; if a repetition is tried again from every position of a long run (\\d+(?![\\d.]) reads a long \
             number once from each of its digits), say where a match may start ((?<!\\d)\\d+(?![\\d.])); if it \
             backtracks (nested or ambiguous repetitions, look-arounds inside repetitions), make repetitions \
             possessive (a++, a*+) or atomic ((?>…)); if the work is what the pattern needs, pass a higher max_steps",
            name, max_steps
        ),
        Failure::VmStack => format!(
            "{}: more than {} pending backtrack points — a repetition that is not possessive ran over a long \
             stretch of text, or look-behinds inside repetitions left their alternatives pending; make repetitions \
             possessive (a++, a*+) or atomic ((?>…))",
            name, VM_STACK
        ),
        Failure::Other(detail) => format!("{}: {}", name, detail),
        Failure::Engine(detail) => format!(
            "{}: internal error in the regex engine (a bug, not your program — please report it with the pattern \
             and the text): {}",
            name, detail
        ),
    })
}

/// El argumento `i` como texto. `what` lo nombra en el error.
fn text_arg<'a>(args: &'a [SynValue], i: usize, name: &str, what: &str) -> Result<&'a str, Control> {
    match args.get(i) {
        Some(SynValue::Text(t)) => Ok(t.as_str()),
        Some(SynValue::Bytes(_)) => Err(err(format!(
            "{}: the {} must be text, got bytes — decode it first with decode(b)",
            name, what
        ))),
        Some(other) => Err(err(format!("{}: the {} must be text, got {}", name, what, other.type_name()))),
        None => Err(err(format!("{}: missing the {}", name, what))),
    }
}

/// `max_steps = N` de la llamada en curso, o el valor por defecto para este texto y este patrón
/// (`default_max_steps_for`: compila el patrón, así que uno inválido es su error acá). Es un
/// entero de 1 o más; uno que no entra en 64 bits vale como el mayor que entra (a 5 ns por paso
/// son miles de años: es «sin tope», y lo eligió el programa).
fn max_steps_arg(
    interp: &mut Interpreter,
    name: &str,
    text: &str,
    pattern: &str,
    full_match: bool,
) -> Result<u64, Control> {
    let Some(v) = interp.kwarg("max_steps") else {
        return default_max_steps_for(text, pattern, full_match).map_err(|f| failure(name, pattern, 0, f));
    };
    let n = match &v {
        SynValue::Number(n) => n
            .as_bigint()
            .filter(|b| b.sign() == Sign::Plus)
            .map(|b| u64::try_from(&b).unwrap_or(u64::MAX)),
        _ => None,
    };
    n.ok_or_else(|| err(format!("{}: max_steps must be an integer of 1 or more, got {}", name, v)))
}

/// Los argumentos por posición son exactamente `n`. Si faltan, el error es el genérico que el
/// intérprete completa con el nombre y la cuenta (`backtrack_find_all() needs 2 arguments, got
/// 1`), como en el resto de los builtins; que sobren lo corta el intérprete antes de llamar, con
/// la aridad del registro.
fn check_arity(args: &[SynValue], n: usize, name: &str) -> Result<(), Control> {
    if args.len() < n {
        return Err(err("missing argument"));
    }
    if args.len() > n {
        return Err(err(format!("{}() takes at most {} arguments, got {}", name, n, args.len())));
    }
    Ok(())
}

fn b_matches(interp: &mut Interpreter, args: &[SynValue]) -> Result<SynValue, Control> {
    const NAME: &str = "backtrack_matches";
    check_arity(args, 2, NAME)?;
    let (text, pattern) = (text_arg(args, 0, NAME, "text")?, text_arg(args, 1, NAME, "pattern")?);
    let max_steps = max_steps_arg(interp, NAME, text, pattern, true)?;
    matches(text, pattern, max_steps).map(syn_bool).map_err(|f| failure(NAME, pattern, max_steps, f))
}

fn b_find_all(interp: &mut Interpreter, args: &[SynValue]) -> Result<SynValue, Control> {
    const NAME: &str = "backtrack_find_all";
    check_arity(args, 2, NAME)?;
    let (text, pattern) = (text_arg(args, 0, NAME, "text")?, text_arg(args, 1, NAME, "pattern")?);
    let max_steps = max_steps_arg(interp, NAME, text, pattern, false)?;
    let found = find_all(text, pattern, max_steps).map_err(|f| failure(NAME, pattern, max_steps, f))?;
    Ok(syn_list(found.into_iter().map(syn_text).collect()))
}

fn b_capture(interp: &mut Interpreter, args: &[SynValue]) -> Result<SynValue, Control> {
    const NAME: &str = "backtrack_capture";
    check_arity(args, 2, NAME)?;
    let (text, pattern) = (text_arg(args, 0, NAME, "text")?, text_arg(args, 1, NAME, "pattern")?);
    let max_steps = max_steps_arg(interp, NAME, text, pattern, false)?;
    let groups = capture(text, pattern, max_steps).map_err(|f| failure(NAME, pattern, max_steps, f))?;
    Ok(match groups {
        None => SynValue::Nothing,
        Some(gs) => syn_list(gs.into_iter().map(|g| g.map_or(SynValue::Nothing, syn_text)).collect()),
    })
}

fn b_replace(interp: &mut Interpreter, args: &[SynValue]) -> Result<SynValue, Control> {
    const NAME: &str = "backtrack_replace";
    check_arity(args, 3, NAME)?;
    let text = text_arg(args, 0, NAME, "text")?;
    let pattern = text_arg(args, 1, NAME, "pattern")?;
    let replacement = text_arg(args, 2, NAME, "replacement")?;
    let max_steps = max_steps_arg(interp, NAME, text, pattern, false)?;
    let out = replace(text, pattern, replacement, max_steps).map_err(|f| failure(NAME, pattern, max_steps, f))?;
    Ok(match out {
        None => args[0].clone(),
        Some(s) => syn_text(s),
    })
}

/// Registra los cuatro builtins (lo llaman `engine.rs` y `synsema-wasm`, junto a `bits`).
/// `max_steps` está en `BUILTIN_KWARGS` (core).
pub fn register_backtrack_builtins(interp: &Interpreter) {
    interp.register_builtin("backtrack_matches", 2, Rc::new(|i, a, _l| b_matches(i, a)));
    interp.register_builtin("backtrack_find_all", 2, Rc::new(|i, a, _l| b_find_all(i, a)));
    interp.register_builtin("backtrack_capture", 2, Rc::new(|i, a, _l| b_capture(i, a)));
    interp.register_builtin("backtrack_replace", 3, Rc::new(|i, a, _l| b_replace(i, a)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use synsema_core::pattern_cache::clear_thread_caches;

    const CL100K: &str = r"'(?i:[sdmt]|ll|ve|re)|[^\r\n\p{L}\p{N}]?+\p{L}++|\p{N}{1,3}+| ?[^\s\p{L}\p{N}]++[\r\n]*+|\s++$|\s*[\r\n]|\s+(?!\S)|\s";
    const GPT2: &str = r"'s|'t|'re|'ve|'m|'ll|'d| ?\p{L}+| ?\p{N}+| ?[^\s\p{L}\p{N}]+|\s+(?!\S)|\s+";
    /// Exponencial en el largo del tramo de `a` y sin coincidencia.
    const SLOW: &str = r"(a+)+$(?<!x)";
    /// Cada tramo `aaa…ab` se encuentra (segunda alternativa) después de que la primera retrocede
    /// de forma exponencial.
    const SLOW_BUT_FINDS: &str = r"(?:a|aa)+(?<!x)c|a+b";
    /// Look-arounds adentro de repeticiones, anidados (ronda 1, A-1). Con posesivos no llenan la
    /// pila, y cada nivel multiplica el trabajo por el largo del texto: n², n³, n³.
    const L1: &str = "(?:(?=[^x]*y)a)*y";
    const L2: &str = "(?:(?=(?:(?=[^x]*y)a)*y)a)*y";
    const L2A: &str = "(?:(?=(?:(?=[^x]*y)a)*+y)a)*+y";
    const L3A: &str = "(?:(?=(?:(?=(?:(?=[^x]*y)a)*+y)a)*+y)a)*+y";
    const L3B: &str = "(?:(?=(?:(?=(?:(?=a)a)*+y)a)*+y)a)*+y";

    const DEFAULT: u64 = MAX_STEPS_FLOOR;
    const NO_LIMIT: u64 = u64::MAX;

    /// El tope por defecto de `find_all(text, pattern)`.
    fn default_for(text: &str, pattern: &str) -> u64 {
        default_max_steps_for(text, pattern, false).unwrap()
    }
    fn all(text: &str, pattern: &str) -> Vec<String> {
        find_all(text, pattern, default_for(text, pattern)).unwrap().into_iter().map(String::from).collect()
    }
    /// Los pasos de una sola búsqueda desde el principio del texto, y lo que encontró.
    fn spent_once(text: &str, pattern: &str) -> (u64, Option<(usize, usize)>) {
        let mut search = Search::new(pattern, false, NO_LIMIT).unwrap();
        let found = search.run(|re, steps| find_span(re, text, 0, steps)).unwrap().map(|(_, s, e)| (s, e));
        (search.spent(), found)
    }
    /// El error de techo de la crate para `pattern` con ese techo: hasta dónde llegó al cortar.
    fn too_large_at(pattern: &str, limit: usize) -> usize {
        match RegexBuilder::new(pattern).program_size_limit(limit).build() {
            Err(FancyError::CompileError(c)) => match *c {
                FancyCompile::ProgramTooLarge { limit: l, reached } => {
                    assert_eq!(l, limit);
                    reached
                }
                other => panic!("{:?}: {}", pattern, other),
            },
            Err(e) => panic!("{:?}: {}", pattern, e),
            Ok(_) => panic!("{:?} compila con un techo de {} bytes", pattern, limit),
        }
    }
    /// El techo más chico con el que compila `pattern` (con `full`, para cubrir todo el texto):
    /// lo que el techo cuenta para él.
    fn smallest(pattern: &str, full: bool) -> usize {
        let (mut no, mut yes) = (0usize, MAX_COMPILED_BYTES);
        assert!(build_one(pattern, full, yes).is_ok() && build_one(pattern, full, no).is_err(), "{}", pattern);
        while yes - no > 1 {
            let mid = no + (yes - no) / 2;
            if build_one(pattern, full, mid).is_ok() {
                yes = mid;
            } else {
                no = mid;
            }
        }
        yes
    }
    /// `k` grupos encadenados: el primero es `first`, y cada uno de los demás llama `calls` veces
    /// al anterior. La crate copia el grupo en cada llamada: el programa crece como `calls^k`.
    fn chain(k: usize, first: &str, calls: usize) -> String {
        let mut p = format!("({})", first);
        for i in 2..=k {
            p.push('(');
            for _ in 0..calls {
                p.push_str(&format!("\\g<{}>", i - 1));
            }
            p.push(')');
        }
        p
    }
    /// Un lexer con una rama por palabra, cada una con sus look-arounds, y una para los números.
    fn lexer(words: &[&str]) -> String {
        let mut p = String::from(r"(?<![\w.])\d+(?:\.\d+)?(?![\w.])");
        for w in words {
            p.push_str(&format!(r"|(?<!\w){}(?!\w)", w));
        }
        p
    }
    const KEYWORDS: [&str; 20] = [
        "if", "else", "while", "for", "return", "break", "continue", "def", "class", "import", "from", "as", "with",
        "try", "except", "raise", "yield", "lambda", "pass", "not",
    ];
    fn builds() -> u64 {
        BUILDS.with(|b| b.get())
    }
    /// Los pasos que gasta `find_all(text, pattern)`, y cuántas coincidencias da.
    fn spent_by(text: &str, pattern: &str) -> (u64, usize) {
        let mut search = Search::new(pattern, false, NO_LIMIT).unwrap();
        let mut n = 0;
        each_match(text, &mut search, |re, pos, steps| find_span(re, text, pos, steps), |(), _, _| n += 1).unwrap();
        (search.spent(), n)
    }
    fn a_then(n: usize, tail: &str) -> String {
        format!("{}{}", "a".repeat(n), tail)
    }

    // ---------- el tope ----------

    #[test]
    fn the_default_limit() {
        // sin instrucciones (el motor lineal resuelve todo el patrón): el piso y 64 por byte
        assert_eq!(default_max_steps(0, 0), 1 << 20);
        assert_eq!(default_max_steps(16_384, 0), 1 << 20);
        assert_eq!(default_max_steps(16_385, 0), 16_385 * 64);
        assert_eq!(default_max_steps(3_000_000, 0), 192_000_000);
        // cada instrucción del patrón suma un paso por byte
        assert_eq!(default_max_steps(0, 288), 1 << 20);
        assert_eq!(default_max_steps(2_978, 288), 1 << 20);
        assert_eq!(default_max_steps(2_979, 288), 2_979 * 352);
        assert_eq!(default_max_steps(20_000, 288), 7_040_000);
        // sin techo: crece con el texto y con el patrón, y no desborda
        assert_eq!(default_max_steps(1 << 30, 0), 64 << 30);
        assert!(default_max_steps(usize::MAX, 0) >= 64 * (u32::MAX as u64));
        assert_eq!(default_max_steps(usize::MAX, usize::MAX), u64::MAX);
    }

    /// Ronda 2, B-2: el tope por defecto crece con el patrón. Un lexer de 21 ramas, cada una con
    /// sus look-arounds, es lineal y gasta 89 pasos por byte: con el término fijo solo (64, la
    /// fórmula de la ronda 1) era un error desde 12 KB, y el mensaje hablaba de retroceso.
    #[test]
    fn the_default_limit_grows_with_the_pattern() {
        let pattern = lexer(&KEYWORDS);
        let line = "El perro come 42 veces; if x == 10 else y = 20; while (a < b) return c.d(e) 3.14\n";
        let text = line.repeat(250);
        let bytes = text.len() as u64;
        let instructions = Search::new(&pattern, false, NO_LIMIT).unwrap().regex().program_len() as u64;
        // medido: 288 instrucciones
        assert!(instructions > 200 && instructions < 400, "{}", instructions);
        let (spent, found) = spent_by(&text, &pattern);
        // 42, if, 10, else, 20, while, return y 3.14 en cada línea
        assert_eq!(found, 8 * 250);
        let default = default_for(&text, &pattern);
        assert_eq!(default, (64 + instructions) * bytes);
        // gasta más que el término fijo y menos de la mitad del tope
        assert!(spent > 64 * bytes && spent < default / 2, "{} pasos sobre {} bytes", spent, bytes);
        assert_eq!(find_all(&text, &pattern, default).map(|v| v.len()), Ok(found));
        assert_eq!(find_all(&text, &pattern, default_max_steps(text.len(), 0)), Err(Failure::StepLimit));
        // el doble de ramas, el doble de instrucciones y de pasos: sigue entrando
        let double: Vec<String> = KEYWORDS.iter().map(|w| w.to_string()).chain(KEYWORDS.iter().map(|w| format!("{}x", w))).collect();
        let double = lexer(&double.iter().map(String::as_str).collect::<Vec<_>>());
        let (spent_double, found_double) = spent_by(&text, &double);
        assert_eq!(found_double, found);
        assert!(spent_double > 3 * spent / 2 && spent_double < default_for(&text, &double) / 2, "{} y {}", spent_double, spent);
        // un patrón que el motor lineal resuelve entero no tiene instrucciones
        assert_eq!(default_for(&text, r"\w+"), default_max_steps(text.len(), 0));
        // `backtrack_matches` busca con el patrón envuelto: su tope sale de ese compilado, que es
        // otro programa (medido: 287 instrucciones, una menos)
        let wrapped = Search::new(&pattern, true, NO_LIMIT).unwrap().regex().program_len() as u64;
        assert_ne!(wrapped, instructions);
        assert_eq!(default_max_steps_for(&text, &pattern, true), Ok((64 + wrapped) * bytes));
        // y uno inválido es su error, no un tope
        assert!(matches!(default_max_steps_for(&text, "(", false), Err(Failure::InvalidPattern(_))));
    }

    #[test]
    fn the_tokenizer_patterns_cut_like_tiktoken_well_inside_the_default_limit() {
        let text = "Hola,  mundo!\n\n  It's 12345 ñandú   ";
        assert_eq!(
            all(text, CL100K),
            ["Hola", ",", " ", " mundo", "!\n\n", " ", " It", "'s", " ", "123", "45", " ñandú", "   "]
        );
        assert_eq!(
            all(text, GPT2),
            ["Hola", ",", " ", " mundo", "!", "\n\n ", " It", "'s", " 12345", " ñandú", "   "]
        );
        let prose = "El perro come 42 veces; la perra ñandú duerme. Hello, world! It's fine.\n".repeat(200);
        let bytes = prose.len() as u64;
        for pattern in [CL100K, GPT2] {
            let (spent, n) = spent_by(&prose, pattern);
            assert_eq!(n, 4000);
            // medido: 4,8 y 5,9 pasos por byte; el tope por defecto da 64 más las instrucciones
            assert!(spent > bytes && spent < 16 * bytes, "{} pasos sobre {} bytes", spent, bytes);
            assert!(spent < default_for(&prose, pattern) / 4);
            assert!(spent < default_max_steps(prose.len(), 0) / 4);
        }
    }

    #[test]
    fn the_design_table_of_results() {
        assert_eq!(all("a   b", r"\s+(?!\S)|\s+"), ["  ", " "]);
        assert_eq!(all("aXb", "(?i:x)"), ["X"]);
        assert_eq!(all("aaaa", "a++a"), Vec::<String>::new());
        assert_eq!(all("aa", "(?=a)"), ["", ""]);
        assert_eq!(all("AU$10, $20", r"(?<=\$)\d+"), ["10", "20"]);
        assert_eq!(all("", "a"), Vec::<String>::new());
        assert_eq!(all("", "a*"), [""]);
        // una vacía al final cuenta si no está pegada a la coincidencia anterior
        assert_eq!(all("ñañ", "a|(?<=ñ)"), ["a", ""]);

        assert_eq!(capture("AU$10, $20", r"(?<!AU)\$(\d+)", DEFAULT), Ok(Some(vec![Some("20")])));
        assert_eq!(capture("hola", "(?<=h)ola", DEFAULT), Ok(Some(vec![Some("ola")])));
        assert_eq!(
            capture("2026-09", r"(\d+)-(\d+)(x)?(?!\d)", DEFAULT),
            Ok(Some(vec![Some("2026"), Some("09"), None]))
        );
        assert_eq!(capture("x", "y", DEFAULT), Ok(None));

        assert_eq!(
            replace("ab@xy cd@zz", r"(\w+)@(?=x)(\w+)", r"\2/\1", DEFAULT),
            Ok(Some("xy/ab cd@zz".to_string()))
        );
        assert_eq!(replace("ab", "(?=b)", "$1", DEFAULT), Ok(Some("a$1b".to_string())));
        assert_eq!(replace("ab", "a(?=b)", r"[\3]", DEFAULT), Ok(Some("[]b".to_string())));
        assert_eq!(replace("ab", r"(\w)(?!$)", r"\g<1>\g<1>", DEFAULT), Ok(Some("aab".to_string())));
        assert_eq!(replace("ab", "(?=x)x", "-", DEFAULT), Ok(None));
        assert_eq!(replace("aa", "(?=a)", "-", DEFAULT), Ok(Some("-a-a".to_string())));

        assert_eq!(matches("abab", r"(ab)\1", DEFAULT), Ok(true));
        assert_eq!(matches("xabab", r"(ab)\1", DEFAULT), Ok(false));
        assert_eq!(matches("ababx", r"(ab)\1", DEFAULT), Ok(false));
        assert_eq!(matches("a\n", "a", DEFAULT), Ok(false));
        assert_eq!(matches("b", "a|b", DEFAULT), Ok(true));
    }

    /// Lo que justifica el bucle propio: da lo mismo que el iterador de la crate (con su tope de
    /// fábrica, sin presupuesto) para todo patrón que no use `\G`.
    #[test]
    fn the_loop_matches_the_crate_iterator() {
        let patterns = [
            CL100K, GPT2, r"\s+(?!\S)|\s+", "(?=a)", "(?<=a)", "(?<=a)|b", "a*?", r"\b", r"(?<!\w)\w+", r"(\w)\1",
            r"(?i)(?<=k)\w", r"\Ka", r"a\Kb|", r"(?>a+)b", "a*+", r"(?=(\w+))\w", r"\w+(?=,)", "", "x*", r"(?<=\p{L})\p{N}+",
            r"[^\s\p{L}\p{N}]++", r"(?m)^(?=.)", r"(?s).(?=.)", r"\X?a", "é|(?<=é)", r"(?i)(é)\1", r"(?<=\w+)\d",
        ];
        let texts = [
            "", "a", "aa", "ab cd", "Hola,  mundo!\n\n  It's 12345 ñandú   ", "aab1 b22, c333,dd", "ééé\u{301}é", "k1K2kk",
            "\n\na\n", "a,b,,c", "🐕 perro 🐕🐕", "   ", "éÉ ÉÉ",
        ];
        let mut compared = 0;
        for pattern in patterns {
            let Ok(reference) = Regex::new(pattern) else {
                // un patrón que la crate rechaza: acá también es error
                assert!(Search::new(pattern, false, DEFAULT).is_err(), "{}", pattern);
                continue;
            };
            for text in texts {
                let want: Vec<&str> = reference.find_iter(text).map(|m| m.unwrap().as_str()).collect();
                assert_eq!(find_all(text, pattern, DEFAULT).unwrap(), want, "{:?} sobre {:?}", pattern, text);
                let want = reference.replace_all(text, "<$0>").into_owned();
                let got = replace(text, pattern, r"<\0>", DEFAULT).unwrap().unwrap_or_else(|| text.to_string());
                assert_eq!(got, want, "replace {:?} sobre {:?}", pattern, text);
                compared += 1;
            }
        }
        assert!(compared > 280, "{}", compared);
    }

    #[test]
    fn an_exponential_pattern_stops_at_the_limit() {
        let text = a_then(28, "b");
        assert_eq!(find_all(&text, SLOW, DEFAULT), Err(Failure::StepLimit));
        assert_eq!(matches(&text, SLOW, DEFAULT), Err(Failure::StepLimit));
        assert_eq!(capture(&text, SLOW, DEFAULT), Err(Failure::StepLimit));
        assert_eq!(replace(&text, SLOW, "x", DEFAULT), Err(Failure::StepLimit));
        // el mismo patrón con el look-around adelante: lo que sigue va entero al motor lineal
        assert_eq!(find_all(&text, r"(?!x)(a+)+$", DEFAULT), Ok(vec![]));
        // y con un texto corto termina
        assert_eq!(find_all(&a_then(8, "b"), SLOW, DEFAULT), Ok(vec![]));
    }

    /// `max_steps` es exacto: la llamada termina con lo que gasta, y con un paso menos no. Y es
    /// determinista: la misma llamada gasta siempre lo mismo.
    #[test]
    fn max_steps_is_exact() {
        let cases = [
            (a_then(8, "b"), SLOW),
            (a_then(12, "b "), SLOW_BUT_FINDS),
            (a_then(100, "y"), L2A),
            ("Hola,  mundo!\n\n  It's 12345 ñandú   ".repeat(20), CL100K),
            (a_then(2_000, "xy"), "(?=x)x"),
            // una referencia y un look-behind de largo variable: los tramos también gastan
            ("uno dos dos tres tres tres ".repeat(40), r"\b(\w+)\s+\1\b"),
            ("ab12 cd345 e6 ".repeat(40), r"(?<=\w+)\d"),
        ];
        for (text, pattern) in cases {
            let (spent, n) = spent_by(&text, pattern);
            assert_eq!(spent_by(&text, pattern), (spent, n), "{}", pattern);
            assert!(spent > 0, "{}", pattern);
            assert_eq!(find_all(&text, pattern, spent).map(|v| v.len()), Ok(n), "{}", pattern);
            assert_eq!(find_all(&text, pattern, spent - 1), Err(Failure::StepLimit), "{}", pattern);
            assert_eq!(replace(&text, pattern, "-", spent - 1), Err(Failure::StepLimit), "{}", pattern);
        }
        // lo que el motor lineal resuelve entero no gasta: anda con max_steps = 1
        assert_eq!(find_all("a b", r"\w(?=\s|$)", 1).map(|v| v.len()), Ok(2));
        assert_eq!(spent_by("a b", r"\w(?=\s|$)"), (0, 2));
        // y lo que pasa por la VM, por chico que sea, gasta
        assert_eq!(matches("abab", r"(ab)\1", 1), Err(Failure::StepLimit));
        assert_eq!(matches("abab", r"(ab)\1", 100), Ok(true));
    }

    /// El tope es de la llamada: con el de la crate, por búsqueda, estos tramos se encuentran
    /// todos (cada búsqueda queda por debajo del millón) y la llamada no termina nunca de cobrar.
    #[test]
    fn many_expensive_searches_add_up_to_the_limit_of_the_call() {
        let block = a_then(21, "b ");
        let (one, found) = spent_by(&block, SLOW_BUT_FINDS);
        assert_eq!(found, 1);
        // un tramo solo entra holgado en el tope por defecto (medido: 399 611 pasos); tres no
        assert!(one > DEFAULT / 3 && one < DEFAULT / 2, "{}", one);
        assert_eq!(find_all(&block.repeat(2), SLOW_BUT_FINDS, DEFAULT).map(|v| v.len()), Ok(2));
        assert_eq!(find_all(&block.repeat(3), SLOW_BUT_FINDS, DEFAULT), Err(Failure::StepLimit));
        assert_eq!(find_all(&block.repeat(100), SLOW_BUT_FINDS, DEFAULT), Err(Failure::StepLimit));
        assert_eq!(replace(&block.repeat(100), SLOW_BUT_FINDS, "-", DEFAULT), Err(Failure::StepLimit));
        // con un tope más alto, la misma llamada termina; lo que gasta es la suma de sus búsquedas
        let (total, found) = spent_by(&block.repeat(40), SLOW_BUT_FINDS);
        assert_eq!(found, 40);
        assert!(total > 39 * one && total < 41 * one, "{} y {}", total, one);
        assert_eq!(find_all(&block.repeat(40), SLOW_BUT_FINDS, total).map(|v| v.len()), Ok(40));
        assert_eq!(find_all(&block.repeat(40), SLOW_BUT_FINDS, total - 1), Err(Failure::StepLimit));
    }

    /// Ronda 1, A-1: el tope cuenta trabajo, no retrocesos. Estos patrones hacen pocos retrocesos
    /// (3 202 el primero) y mucho trabajo entre uno y otro: con el tope de la crate tardaban 9 s,
    /// 7 s y 7 s sin dar error.
    #[test]
    fn nested_look_arounds_in_repetitions_stop_at_the_limit() {
        for (pattern, n) in [(L2A, 3_200), (L3A, 400), (L3B, 800)] {
            let text = a_then(n, "y");
            let limit = default_for(&text, pattern);
            assert_eq!(find_all(&text, pattern, limit), Err(Failure::StepLimit), "{}", pattern);
            assert_eq!(matches(&text, pattern, limit), Err(Failure::StepLimit), "{}", pattern);
            assert_eq!(capture(&text, pattern, limit), Err(Failure::StepLimit), "{}", pattern);
            assert_eq!(replace(&text, pattern, "-", limit), Err(Failure::StepLimit), "{}", pattern);
        }
        // sobre textos cortos terminan, y un solo nivel entra con miles de letras
        assert_eq!(all(&a_then(100, "y"), L2A), [a_then(100, "y")]);
        assert_eq!(all(&a_then(30, "y"), L3A), [a_then(30, "y")]);
        assert_eq!(all(&a_then(4_000, "y"), L1), [a_then(4_000, "y")]);
        // muchas búsquedas caras con max_steps = 1: la primera ya no entra
        assert_eq!(find_all(&a_then(100, "y ").repeat(25), L2A, 1), Err(Failure::StepLimit));
    }

    /// Una búsqueda legítima gasta unos pasos por cada posición donde no arranca: con el tope
    /// fijo de la crate (un millón de retrocesos) esta falla; el tope por defecto crece con el
    /// texto.
    #[test]
    fn a_long_legitimate_search_fits_in_the_default_limit() {
        let text = a_then(4_500_000, "xy");
        let crate_default = Regex::new("(?=x)x").unwrap();
        assert!(crate_default.find(&text).is_err(), "la crate sola no llega");
        assert_eq!(find_all(&text, "(?=x)x", default_for(&text, "(?=x)x")), Ok(vec!["x"]));
        // con el piso solo (sin el término por byte) no alcanza
        assert_eq!(find_all(&text, "(?=x)x", MAX_STEPS_FLOOR), Err(Failure::StepLimit));
        assert_eq!(find_all(&text, "(?=x)x", 1000), Err(Failure::StepLimit));
    }

    /// Una instrucción que le pasa un tramo de texto al motor lineal gasta por el largo del tramo
    /// (un paso cada 16 bytes) cuando el tramo coincide. Cuando no coincide gasta su paso solo,
    /// porque el motor lineal no dice hasta dónde leyó: es lo que el tope no acota (el tiempo de
    /// la segunda búsqueda de este test es tan cuadrático como el de la primera).
    #[test]
    fn a_stretch_of_text_pays_by_its_length_when_it_matches() {
        let n = 1_600usize;
        let text = a_then(n, "y");
        // en cada `a`, el look-ahead lee hasta la `y` del final: los tramos suman n²/2 bytes
        let (matching, found) = spent_by(&text, "(?=[^x]*y)a");
        // lo mismo, pero el tramo no coincide (no hay `z`): gastan sólo las instrucciones
        let (failing, found_too) = spent_by(&text, "(?![^x]*z)a");
        assert_eq!((found, found_too), (n, n));
        let stretches = (n * n / 32) as u64;
        assert!(failing < 10 * n as u64, "{}", failing);
        let paid = matching - failing;
        assert!(paid >= stretches && paid < stretches + 2 * n as u64, "{} - {} y {}", matching, failing, stretches);
        // una referencia compara el texto de su grupo: también es un tramo
        let (short, _) = spent_by(&"a".repeat(32), r"^(a{16})\1");
        let (long, _) = spent_by(&"a".repeat(3_200), r"^(a{1600})\1");
        // 1 584 letras más en el grupo (tres instrucciones cada una) y 99 pasos más de tramo
        assert_eq!(long - short, 3 * 1_584 + 99);
    }

    /// La referencia sin distinguir mayúsculas compara carácter por carácter (ronda 4, A-3 y
    /// M-2). Un par de caracteres que no son iguales ni los dos ASCII arma la clase de
    /// equivalentes de uno de ellos: cuesta 16 pasos (medido: 10 ns por paso, como los demás).
    #[test]
    fn a_case_insensitive_backreference_outside_ascii_pays_for_its_work() {
        assert_eq!(spent_by("Aa", r"(?i)(a)\1"), (13, 1));
        assert_eq!(spent_by("Éé", r"(?i)(é)\1"), (13 + 16, 1));
        // con mayúsculas iguales (los mismos bytes) no hay recargo
        assert_eq!(spent_by("éé", r"(?i)(é)\1"), (13, 1));
    }

    /// Ronda 4, A-3: con un grupo largo de texto que no es ASCII, la versión 0.18.0 armaba una
    /// regex con el texto del grupo en cada comparación, y con 70 000 letras esa regex pasaba del
    /// límite del motor lineal: un pánico (`literal hir should get built successfully`), después
    /// de 1 493 millones de pasos. Ahora no arma nada: entra en el tope por defecto.
    #[test]
    fn a_case_insensitive_backreference_to_a_long_group_is_a_search_like_any_other() {
        let pattern = r"(?i)^(\x{e9}+)\1";
        // Primero con 1 000 letras: el grupo prueba cada largo, de 1 000 para abajo, y mientras
        // al texto le quedan menos bytes que los del grupo la referencia dice que no sin mirar
        // (ninguna letra del texto se acorta). Leyendo igual en cada largo serían 500 000
        // letras de más, a 16 pasos cada una.
        let short = format!("{}{}", "\u{e9}".repeat(1_000), "\u{c9}".repeat(1_000));
        assert_eq!(spent_once(&short, pattern), (22_383, Some((0, 4_000))));
        let n = 70_000;
        let text = format!("{}{}", "\u{e9}".repeat(n), "\u{c9}".repeat(n));
        assert_eq!(spent_once(&text, pattern), (1_566_258, Some((0, 4 * n))));
        assert!(default_for(&text, pattern) > 10 * 1_566_258);
        assert_eq!(matches(&text, pattern, default_for(&text, pattern)), Ok(true));
    }

    /// Ronda 4, M-2: dos letras que son la misma sin distinguir mayúsculas pueden ocupar distinta
    /// cantidad de bytes (`ẞ` 3 y `ß` 2; la K de Kelvin 3 y `k` 1; `ſ` 2 y `s` 1). Upstream
    /// compara un tramo del texto del mismo largo en bytes que el grupo: la referencia se comía
    /// lo que sobraba (las tres primeras filas terminaban en `!`, `x` y `€`), o no coincidía (las
    /// tres siguientes). Acá lee una letra del texto por cada letra del grupo y termina donde
    /// termina la última: las siete filas dan lo que dan Perl y el módulo `regex` de Python.
    #[test]
    fn a_case_insensitive_backreference_ends_where_its_last_letter_does() {
        for (pattern, text, found, replaced) in [
            ("(?i)(stra\u{1e9e}e)\\1", "STRA\u{1e9e}Estra\u{df}e!", "STRA\u{1e9e}Estra\u{df}e", "<STRA\u{1e9e}E>!"),
            ("(?i)(\u{1e9e})\\1", "\u{1e9e}\u{df}x", "\u{1e9e}\u{df}", "<\u{1e9e}>x"),
            ("(?i)(\u{212a}\u{17f})\\1", "\u{212a}\u{17f}ks\u{20ac}", "\u{212a}\u{17f}ks", "<\u{212a}\u{17f}>\u{20ac}"),
            ("(?i)(\u{212a}\u{17f})\\1", "\u{212a}\u{17f}ksz", "\u{212a}\u{17f}ks", "<\u{212a}\u{17f}>z"),
            ("(?i)(\u{17f})\\1", "\u{17f}s", "\u{17f}s", "<\u{17f}>"),
            ("(?i)(s)\\1", "s\u{17f}", "s\u{17f}", "<s>"),
            ("(?i)(\u{e9})\\1", "\u{e9}\u{c9}", "\u{e9}\u{c9}", "<\u{e9}>"),
        ] {
            assert_eq!(all(text, pattern), [found], "{} sobre {}", pattern, text);
            assert_eq!(replace(text, pattern, "<\\1>", DEFAULT), Ok(Some(replaced.to_string())), "{} sobre {}", pattern, text);
        }
        // cuando al texto le quedan menos bytes que los del grupo, la referencia todavía puede
        // coincidir si el texto tiene letras que se acortan (`ſſ` son 4 bytes y `ss`, 2)
        assert_eq!(all("\u{17f}\u{17f}ss", r"(?i)^(\x{17f}+)\1$"), ["\u{17f}\u{17f}ss"]);
        assert_eq!(all("ss\u{17f}", r"(?i)^(s+)\1$"), Vec::<String>::new());
        assert_eq!(all("\u{e9}\u{e9}\u{e9}", r"(?i)^(\x{e9}+)\1"), ["\u{e9}\u{e9}"]);
        // La suite de upstream fija lo contrario en `backrefs_casei_unicode_fold_orbits`
        // (`tests/matching.rs`: «cannot match through a backref because the window is sized in
        // bytes from the captured text»). Es el único de sus 780 tests que no pasa sobre el
        // fork, y es por esto. Sus seis casos, con lo que dan acá: los tres primeros como en
        // upstream (el plegado es el simple: `ß` no es `ss`), y los otros tres coinciden.
        assert_eq!(all("\u{3c3}\u{3c2}", "(\u{3c3})(?i:\\1)"), ["\u{3c3}\u{3c2}"]);
        assert_eq!(all("\u{3a3}\u{3c2}", "(\u{3a3})(?i:\\1)"), ["\u{3a3}\u{3c2}"]);
        assert_eq!(all("\u{df}ss", "(\u{df})(?i:\\1)"), Vec::<String>::new());
        assert_eq!(all("\u{17f}asab", "(\u{17f}a)(?i:\\1)"), ["\u{17f}asa"]);
        assert_eq!(all("\u{e5}\u{212b}", "(\u{e5})(?i:\\1)"), ["\u{e5}\u{212b}"]);
        assert_eq!(all("s\u{17f}", "(s)(?i:\\1)"), ["s\u{17f}"]);
    }

    /// Ronda 2, N-2 y B-1: cada sitio de la VM que lee un tramo del texto lo cobra, uno por uno.
    /// Los pares son la misma búsqueda sobre un tramo de 1 000 y sobre uno corto: la diferencia es
    /// lo que hay de más para recorrer (tres instrucciones por carácter donde hay un `.*`) más el
    /// tramo, un paso cada 16 bytes. Sin el cobro de un sitio, su número baja.
    #[test]
    fn every_place_that_reads_a_stretch_pays_for_it() {
        let spaces = |n: usize| format!("{}x", " ".repeat(n));
        // un look-behind de largo variable (el motor lineal hacia atrás): 1 000/16 = 62
        assert_eq!(spent_once(&spaces(1_000), r"\A.*(?<=\s+)x"), (3_077, Some((0, 1_001))));
        assert_eq!(spent_once(&spaces(10), r"\A.*(?<=\s+)x"), (45, Some((0, 11))));
        assert_eq!(3_077 - 45, 3 * 990 + 62);
        // un tramo delegado con grupos: 62
        assert_eq!(spent_once(&a_then(1_000, " "), r"\A(?=a)(\w+) "), (70, Some((0, 1_001))));
        assert_eq!(spent_once(&a_then(10, " "), r"\A(?=a)(\w+) "), (8, Some((0, 11))));
        // `(?~…)`: lo que coincide el patrón que no tiene que aparecer (`b` y 1 000 letras): 62
        let absent = |n: usize| format!("ddddb{}", "w".repeat(n));
        assert_eq!(spent_once(&absent(1_000), r"\A(?~b\w+)"), (71, Some((0, 4))));
        assert_eq!(spent_once(&absent(10), r"\A(?~b\w+)"), (9, Some((0, 4))));
        // un look-behind de largo fijo camina hacia atrás: lo intenta dos veces (con la `b`
        // adentro del `.*` y sin ella), 2 × 62 de más, y el tramo `a{1000}` que coincide, 62
        assert_eq!(spent_once(&a_then(1_000, "b"), r"\A.*(?<=a{1000})b"), (3_203, Some((0, 1_001))));
        assert_eq!(spent_once(&a_then(100, "b"), r"\A.*(?<=a{100})b"), (335, Some((0, 101))));
        assert_eq!(3_203 - 335, 3 * 900 + 2 * (62 - 6) + (62 - 6));
        // uno más largo que el texto no camina más que el texto: se cobra lo que hay, no el
        // número escrito (que serían 62 millones de pasos, un error)
        assert_eq!(all("ab", r"(?<=(?:(?=a)a){999999999})b|b"), ["b"]);
        // `\Z` saltea los saltos de línea del final: 62
        assert_eq!(spent_once(&"\n".repeat(1_000), r"\A(?=\Z)"), (66, Some((0, 0))));
        assert_eq!(spent_once(&"\n".repeat(10), r"\A(?=\Z)"), (4, Some((0, 0))));
        // y da lo mismo que antes: sólo con saltos de línea de ahí al final
        assert_eq!(all("a\n\n", r"a(?=\Z)"), ["a"]);
        assert_eq!(all("a\n\nb", r"a(?=\Z)"), Vec::<String>::new());
        assert_eq!(all("a\r\n", r"(?R)a(?=\Z)"), ["a"]);
        assert_eq!(all("a\r\n", r"a(?=\Z)"), Vec::<String>::new());
        // un literal compara sus bytes: 1 000/16 = 62 contra 16/16 = 1
        let literal = |n: usize| format!("(?=a){}", "a".repeat(n));
        assert_eq!(spent_once(&"a".repeat(1_000), &literal(1_000)), (70, Some((0, 1_000))));
        assert_eq!(spent_once(&"a".repeat(16), &literal(16)), (9, Some((0, 16))));
        // un look-behind de largo variable con una referencia de largo variable adentro corre
        // entero en la VM: busca hacia atrás los comienzos posibles (un paso por candidato) y
        // cobra el tramo hasta el más lejano, 1 001/16 = 62. (Con sólo un `\b` adentro la crate
        // prueba primero el autómata hacia atrás, y a la VM va si ese dice que no.) El grupo de
        // la referencia está afuera del look-behind: adentro, desde la ronda 10, es un error.
        let hard = r"\A(a).*(?<=\1*b+)x";
        let b_then = |n: usize| format!("a{}x", "b".repeat(n));
        assert_eq!(
            [spent_once(&b_then(1_000), hard), spent_once(&b_then(10), hard)],
            [(4_095, Some((0, 1_002))), (73, Some((0, 12)))]
        );
        // guardar un lugar de captura lo busca entre los guardados desde la última alternativa,
        // uno por uno: con 200 grupos seguidos son 400 lugares y 400²/2 miradas, un paso cada 16
        let saved = |n: usize| format!("(?=a){}", "(a)".repeat(n));
        assert_eq!(spent_once(&"a".repeat(200), &saved(200)), (5_132, Some((0, 200))));
        assert_eq!(spent_once(&"a".repeat(20), &saved(20)), (69, Some((0, 20))));
        // cada búsqueda arma los lugares de captura del patrón, y los del tramo que tiene los
        // grupos: con 500 grupos son 2 000 lugares, 122 pasos
        let groups = |n: usize| format!("(?=a)(?:x{})?", "()".repeat(n));
        assert_eq!(spent_once("a", &groups(500)), (132, Some((0, 0))));
        assert_eq!(spent_once("a", &groups(100)), (32, Some((0, 0))));
        assert_eq!(spent_once("a", &groups(10)), (10, Some((0, 0))));
        // con 500 grupos, una búsqueda por byte pasa del tope por defecto: antes eran 8 pasos
        // por byte y 5 µs por búsqueda que nadie contaba
        let text = "a".repeat(20_000);
        let limit = default_for(&text, &groups(500));
        assert_eq!(limit, 74 * 20_000);
        assert_eq!(find_all(&text, &groups(500), limit), Err(Failure::StepLimit));
        assert_eq!(find_all(&text, &groups(10), default_for(&text, &groups(10))).map(|v| v.len()), Ok(20_000));
        // (con 600 grupos el patrón ya no compila: la tabla de grupos de su tramo no entra en el
        // techo, ver `the_size_limit_counts_what_a_search_needs`)
        assert_eq!(invalid(&groups(600)), too_large());
    }

    #[test]
    fn the_vm_stack_is_its_own_error() {
        let spaces = " ".repeat(1_500_000);
        assert_eq!(find_all(&spaces, GPT2, default_for(&spaces, GPT2)), Err(Failure::VmStack));
        // con posesivos (`cl100k`) el mismo texto anda
        assert_eq!(find_all(&spaces, CL100K, default_for(&spaces, CL100K)).map(|v| v.len()), Ok(1));
        // Ronda 1, B-3: en la versión 0.18.0, un look-ahead adentro de una repetición no posesiva
        // dejaba sus alternativas pendientes y la llenaba con un texto corto. Desde la 0.20 un
        // look-ahead es atómico (al coincidir suelta las suyas, como en PCRE): este patrón ya no
        // la llena. Con el tope por defecto lo corta el de pasos, y con uno más alto termina.
        let text = a_then(1_600, "y");
        assert_eq!(find_all(&text, L2, default_for(&text, L2)), Err(Failure::StepLimit));
        assert_eq!(find_all(&text, L2, 100_000_000).map(|v| v.len()), Ok(1));
        // Un look-behind no es atómico: adentro de una repetición, el suyo deja una alternativa
        // pendiente por vuelta además de la de la repetición, y 600 000 vueltas la llenan. El
        // mismo patrón con look-ahead, no.
        let text = a_then(600_000, "y");
        assert_eq!(find_all(&text, r"(?:(?=(?:(?=a)a|(?=a)a))a)*y", NO_LIMIT).map(|v| v.len()), Ok(1));
        assert_eq!(find_all(&text, r"(?:(?<=(?:(?=a)a|(?=a)a))a)*y", NO_LIMIT), Err(Failure::VmStack));
        assert_eq!(find_all(&text, r"(?:(?<=(?>(?=a)a|(?=a)a))a)*y", NO_LIMIT).map(|v| v.len()), Ok(1));
    }

    // ---------- patrones que no compilan ----------

    fn invalid(pattern: &str) -> String {
        match Search::new(pattern, false, DEFAULT) {
            Err(Failure::InvalidPattern(m)) => m,
            other => panic!("{:?}: {:?}", pattern, other.map(|_| ())),
        }
    }
    fn invalid_in_full(pattern: &str) -> String {
        match Search::new(pattern, true, DEFAULT) {
            Err(Failure::InvalidPattern(m)) => m,
            other => panic!("{:?}: {:?}", pattern, other.map(|_| ())),
        }
    }

    #[test]
    fn invalid_patterns_are_errors_not_crashes() {
        assert_eq!(invalid("("), "Parsing error at position 1: Opening parenthesis without closing parenthesis");
        assert_eq!(invalid(r"(a)\2"), "Error compiling regex: Invalid back reference to group 2");
        let deep = format!("(?=x){}a{}", "(".repeat(500), ")".repeat(500));
        assert!(invalid(&deep).ends_with("Pattern too deeply nested"), "{}", invalid(&deep));
        // el límite de tamaño del motor lineal para un tramo sale del techo del compilado: es el
        // mismo error
        assert_eq!(invalid(r"(?=x)\w{1000}"), too_large());
        // el texto vacío no esconde el error
        assert!(find_all("", "(", DEFAULT).is_err());
        assert!(replace("", "(", "", DEFAULT).is_err());
        assert!(capture("", "(", DEFAULT).is_err());
    }

    /// Ronda 2, A-2: compilar tiene techo. La crate copia el grupo en cada llamada de subrutina,
    /// hasta 19 niveles: el primero de estos compilaba a 649 MB, y los otros no terminaban (el
    /// proceso abortaba por memoria). `max_steps` no los frena: corre al buscar.
    #[test]
    fn a_pattern_that_compiles_to_too_much_is_an_error() {
        assert_eq!(MAX_COMPILED_BYTES, 16 << 20);
        assert!(
            too_large().starts_with("the compiled pattern, with the memory its searches need, is over 16 MiB: "),
            "{}",
            too_large()
        );
        let chain_of_20 = chain(20, "a", 2);
        // un tramo para el motor lineal que solo ya no entra (`\w{200}` son 13,6 MiB)
        let with_a_delegate = r"(?=x)\w{400}";
        for pattern in [r"(a|b\g<1>\g<1>)", r"(a|b\g<1>\g<1>\g<1>)", chain_of_20.as_str(), with_a_delegate] {
            assert_eq!(invalid(pattern), too_large(), "{}", pattern);
            assert_eq!(invalid_in_full(pattern), too_large(), "{}", pattern);
            assert_eq!(default_max_steps_for("a", pattern, false), Err(Failure::InvalidPattern(too_large())));
            assert_eq!(find_all("a", pattern, 1), Err(Failure::InvalidPattern(too_large())));
        }
        // una subrutina que no crece sigue andando: una llamada, la recursión de un solo camino
        // y los paréntesis balanceados (19 niveles)
        assert_eq!(all("aa", r"(?=a)(a)\g<1>"), ["aa"]);
        assert_eq!(all("bba", r"(a|b\g<1>)"), ["bba"]);
        assert_eq!(all("x ((a)(b)) y", r"\((?:[^()]|\g<0>)*\)"), ["((a)(b))"]);
        // las copias de una subrutina comparten la regex de un tramo que es el mismo texto (desde
        // la 0.20 de la crate): 128 copias de `\w{100}` son una sola, y entra
        assert!(Search::new(&chain(8, r"\w{100}(?=a)", 2), false, DEFAULT).is_ok());
        // los patrones de tokenizador entran holgados (medido: 0,37 y 0,22 MiB), y también el
        // mayor de una sola pieza que acepta el motor lineal en las `regex_*` (`\w{209}`: 14,2 MiB)
        for pattern in [CL100K, GPT2, r"(?=x)\w{200}", r"\w{200}", r"\w{209}"] {
            assert!(Search::new(pattern, false, DEFAULT).is_ok(), "{}", pattern);
        }
        // el límite propio del motor lineal para un tramo sale del techo: es el mismo error
        assert_eq!(invalid(r"\w{1000}"), too_large());
        // lo mismo el autómata de un look-behind de largo variable
        assert_eq!(invalid(r"(?<=\w{1000,})x"), too_large());
    }

    /// Ronda 4, A-1: el techo cuenta también lo que una búsqueda necesita, sea cual sea el
    /// texto. La caché de búsqueda de un tramo tiene una tabla de «estados del tramo × lugares
    /// de captura» (la de la PikeVM del motor lineal, dos veces): con 60 grupos sobre clases
    /// Unicode son 36 MB, que antes no contaba nadie al compilar, pasaban del presupuesto de
    /// búsqueda (16 MiB) y hacían soltar y rehacer la caché en cada búsqueda (sobre 20 KB de
    /// texto, de 19,5 ms a 100 s, sin pasar el tope de pasos). Ahora ese patrón no compila, y el
    /// que compila busca con lo que se contó: la tabla no es crecimiento.
    #[test]
    fn the_size_limit_counts_what_a_search_needs() {
        let letters = |n: usize| format!(r"(?=\w)({})", r"(\w)".repeat(n));
        let row = |n: usize, class: &str| format!("(?m)^(?={}){}", class, vec![format!("({}+)", class); n].join(","));
        // 60 grupos: 39,7 y 39,3 MiB con la tabla; también cuando el patrón va entero al motor
        // lineal (sin programa: 39,1)
        for pattern in [letters(60), row(60, r"\w"), r"(\w)".repeat(60)] {
            assert_eq!(invalid(&pattern), too_large(), "{}", pattern);
            assert_eq!(find_all("a", &pattern, 1), Err(Failure::InvalidPattern(too_large())), "{}", pattern);
        }
        // 30 entran (11,9 y 11,7 MiB): lo contado para sus cachés es casi todo
        let text = format!("{} ", "a".repeat(100)).repeat(200);
        for (pattern, counted) in [(letters(30), 10_786_654), (row(30, r"\w"), 10_540_668)] {
            let mut search = Search::new(&pattern, false, NO_LIMIT).unwrap();
            assert_eq!(search.regex().fresh_search_cache_bytes(), counted, "{}", pattern);
            assert!(counted > MAX_COMPILED_BYTES / 2 && counted > 4 * KEPT_SEARCH_CACHE_BYTES);
            each_match(&text, &mut search, |re, pos, steps| find_span(re, &text, pos, steps), |(), _, _| ()).unwrap();
            // y buscar no suelta nada: la caché no crece por encima de lo contado
            assert_eq!(search.regex().search_cache_drops(), 0, "{}", pattern);
            assert!(search.regex().search_cache_bytes() <= counted, "{}", pattern);
        }
        // en esas búsquedas el motor lineal resolvió los grupos sin la PikeVM (cada coincidencia
        // es corta). Con palabras largas la usa, y la tabla aparece: la caché tiene lo contado
        // más lo poco que crece su DFA perezoso, y eso solo es lo que mira el presupuesto
        let ambiguous = format!(r"(?=\w){}", r"(\w+)".repeat(10));
        let long_words = format!("{} ", "a".repeat(2_000)).repeat(2);
        let mut search = Search::new(&ambiguous, false, NO_LIMIT).unwrap();
        let counted = search.regex().fresh_search_cache_bytes();
        assert_eq!(counted, 1_462_094);
        let mut found = 0;
        each_match(&long_words, &mut search, |re, pos, steps| find_span(re, &long_words, pos, steps), |(), _, _| found += 1)
            .unwrap();
        let held = search.regex().search_cache_bytes();
        assert_eq!(found, 2);
        assert!(held > counted && held < counted + (1 << 20), "{} de {}", held, counted);
        assert_eq!(search.regex().search_cache_drops(), 0);
        // con un presupuesto menor que lo contado tampoco se suelta nada: lo que tiene pasa del
        // presupuesto, lo que creció no (ronda 4, A-1: midiendo el total, cada búsqueda soltaba
        // la tabla y la siguiente la rehacía)
        let tight = RegexBuilder::new(&ambiguous)
            .backtrack_limit(usize::MAX)
            .program_size_limit(MAX_COMPILED_BYTES)
            .search_cache_limit(1 << 20)
            .build()
            .unwrap();
        assert_eq!(tight.fresh_search_cache_bytes(), counted);
        let (mut steps, mut pos, mut found) = (u64::MAX, 0, 0);
        while let Some(m) = tight.find_from_pos_with_steps(&long_words, pos, &mut steps).unwrap() {
            found += 1;
            pos = m.end();
        }
        assert_eq!(found, 2);
        assert!(tight.search_cache_bytes() > (1 << 20), "{}", tight.search_cache_bytes());
        assert_eq!(tight.search_cache_drops(), 0);
        // lo que pesa son los grupos sobre clases Unicode: con clases ASCII la misma fila de 60
        // campos entra en 1 MiB, y las 60 letras sin grupos, en 5 (con ellos eran 39,7)
        for (pattern, at_most) in [(row(60, "[0-9]"), 1 << 20), (format!(r"(?=\w)(?:{})", r"\w".repeat(60)), 5 << 20)] {
            let re = build_one(&pattern, false, at_most);
            assert!(re.is_ok(), "{}", pattern);
        }
        // sin techo (la crate sola) lo contado es 0, y lo que tiene una caché recién hecha no
        // cuenta como crecimiento
        let free = RegexBuilder::new(&letters(30)).build().unwrap();
        assert_eq!(free.fresh_search_cache_bytes(), 0);
    }

    /// El corte es temprano: compilar para en el primer nodo que encuentra el programa pasado del
    /// techo, no al final. Si no, el error llegaría después de pedir toda la memoria.
    #[test]
    fn compiling_stops_where_the_program_goes_over_its_limit() {
        // entera, esta cadena son 81 891 instrucciones (10 MB)
        let pattern = chain(14, "a", 2);
        assert!(Regex::new(&pattern).unwrap().program_len() > 50_000);
        let reached = too_large_at(&pattern, 4_096);
        assert!(reached > 4_096 && reached < 8_192, "{}", reached);
        assert_eq!(build(&pattern, false, 4_096).err(), Some(Failure::InvalidPattern(too_large())));
        assert!(build(&pattern, false, MAX_COMPILED_BYTES).is_ok());
        // el último nodo también cuenta. Con el techo en 0 corta antes de compilar el primero, y
        // dice cuánto había (el preámbulo); con el techo ahí, el primer nodo entra a compilarse y
        // el programa termina pasado: es un error igual.
        let preamble = too_large_at("(?~a)", 0);
        assert!(preamble > 0);
        assert!(too_large_at("(?~a)", preamble) > preamble);
        assert!(RegexBuilder::new("(?~a)").program_size_limit(MAX_COMPILED_BYTES).build().is_ok());
    }

    /// Lo que cuenta el techo: cada instrucción y lo que tiene adentro. Estos programas son de
    /// unas diez instrucciones (menos de 1 KB) con una pieza grande cada uno.
    #[test]
    fn the_size_limit_counts_what_each_instruction_owns() {
        const LIMIT: usize = 4_096;
        let literal = format!("(?=a){}", "a".repeat(10_000));
        let cases = [
            // un tramo para el motor lineal (`\w+` con sus tablas Unicode y su caché: 103 KB)
            r"(?=x)\w+",
            // lo mismo adentro de `(?~…)`
            r"(?~\w+)",
            // el autómata hacia atrás de un look-behind de largo variable (63 KB)
            r"(?<=\w+)x",
            // un literal de 10 000 letras
            literal.as_str(),
        ];
        for pattern in cases {
            let instructions = Regex::new(pattern).unwrap().program_len();
            assert!(instructions > 0 && instructions < 16, "{}: {}", pattern, instructions);
            assert!(too_large_at(pattern, LIMIT) > LIMIT, "{}", pattern);
        }
        // El techo más chico con el que entra cada uno, y lo que de eso es la caché de búsqueda
        // (lo que tiene sea cual sea el texto). Son los números de `regex-automata` 0.4.18 en 64
        // bits: si cambian al actualizarla, se miden de nuevo. Lo que fijan es que cada parte
        // está contada: la regex del tramo, su caché, el autómata del look-behind con su NFA y
        // la caché de su DFA perezoso, el texto del literal.
        let counted = |pattern: &str| {
            let re = build_one(pattern, false, MAX_COMPILED_BYTES).unwrap();
            (smallest(pattern, false), re.fresh_search_cache_bytes())
        };
        assert_eq!(cases.map(counted), [(105_318, 47_054), (105_053, 47_054), (64_531, 24_687), (10_881, 0)]);
        // un tramo con grupos (su caché tiene la tabla de grupos) y dos tramos distintos (cada
        // uno con la suya: se suman)
        let (one, two) = (r"(?=x)(\w)(\w)", r"(?=x)(\w)(\w)|(?=y)(\w)(\w)(\d)");
        assert_eq!((counted(one), counted(two)), ((896_215, 131_646), (1_850_270, 290_636)));
        // un look-behind chico entra en ese techo: lo que cuenta es la pieza
        assert!(RegexBuilder::new(r"(?<=\s+)x").program_size_limit(LIMIT).build().is_ok());
        // el patrón que va entero al motor lineal (sin programa) tiene el mismo techo
        assert_eq!(Regex::new(r"\w+").unwrap().program_len(), 0);
        assert!(too_large_at(r"\w+", LIMIT) > LIMIT);
        assert_eq!(build(r"\w+", false, LIMIT).err(), Some(Failure::InvalidPattern(too_large())));
    }

    /// Lo que el techo cuenta es lo que el programa tiene. Las instrucciones con el mismo tramo
    /// usan una sola regex (la crate la arma una vez por compilación, y el techo la cuenta una
    /// vez), y tienen que compartir el objeto: un clon de la regex del motor lineal viene con un
    /// pool de cachés propio, unos 4 KB que el fork no usa y que nadie contaba. Un grupo con un
    /// tramo, copiado 8 192 veces por llamadas de subrutina (181 bytes de patrón), contaba
    /// 11,4 MiB y tenía 46. Y el programa no se queda con la capacidad de sobra del vector en el
    /// que se armó (crece duplicando: tenía hasta el doble de lo contado).
    #[test]
    fn instructions_that_share_a_piece_share_its_engine() {
        use fancy_regex::internal::{analyze, compile, AnalyzeContext, CompileOptions, Insn};
        let program = |pattern: &str| {
            let tree = Expr::parse_tree(pattern).unwrap();
            let info = analyze(&tree, AnalyzeContext::default()).unwrap();
            compile(&info, CompileOptions::default()).unwrap()
        };
        // El mismo tramo escrito en tres ramas, uno distinto en la cuarta, y un grupo con el
        // primero al que el patrón llama cuatro veces (cada llamada es una copia).
        let (same, other) = ("[ab]*a[ab]{2}c", "[ab]*b[ab]{2}c");
        let pattern = format!(r"(?=a){s}|(?=b){s}|(?=c){s}|(?=d){o}|(x{s})\g<1>\g<1>\g<1>\g<1>", s = same, o = other);
        let prog = program(&pattern);
        let engines = |of: &str| -> Vec<_> {
            prog.body
                .iter()
                .filter_map(|insn| match insn {
                    Insn::Delegate(d) if d.pattern == of => Some(std::sync::Arc::clone(&d.inner)),
                    _ => None,
                })
                .collect()
        };
        // (adentro del grupo, la repetición del principio corre en la VM y el tramo es el resto:
        // el grupo escrito y sus cuatro copias)
        let (branches, copies, apart) = (engines(same), engines("a[ab]{2}c"), engines(other));
        assert_eq!((branches.len(), copies.len(), apart.len()), (3, 5, 1), "{:?}", prog.body);
        for shared in [&branches, &copies] {
            for engine in shared {
                assert!(std::sync::Arc::ptr_eq(engine, &shared[0]), "cada instrucción con el tramo tiene otro objeto");
                assert!(!std::sync::Arc::ptr_eq(engine, &apart[0]));
            }
        }
        assert!(!std::sync::Arc::ptr_eq(&branches[0], &copies[0]));
        // el vector del programa, sin capacidad de sobra
        assert!(prog.body.len() > 40, "{}", prog.body.len());
        assert_eq!(prog.body.capacity(), prog.body.len());
    }

    /// Ronda 1, N-3: un conteo que no entra en 32 bits es un error. En la crate publicada era un
    /// `{` literal, y dónde empezaba a serlo dependía del ancho de `usize`: el mismo patrón
    /// significaba otra cosa en wasm32. El límite es el de la crate `regex`.
    #[test]
    fn a_repetition_count_that_does_not_fit_in_32_bits_is_an_error() {
        const TOO_LARGE: &str = "Repetition count is too large (the largest is 4294967295)";
        assert_eq!(invalid("a{4294967296}"), format!("Parsing error at position 2: {}", TOO_LARGE));
        assert_eq!(invalid("(?=a)a{99999999999999999999999}"), format!("Parsing error at position 7: {}", TOO_LARGE));
        assert_eq!(invalid("a{1,4294967296}"), format!("Parsing error at position 4: {}", TOO_LARGE));
        assert_eq!(invalid("a{4294967296,}"), format!("Parsing error at position 2: {}", TOO_LARGE));
        assert_eq!(invalid_in_full("a{4294967296}"), format!("Parsing error at position 2: {}", TOO_LARGE));
        // el mayor que entra se lee como conteo (y no compila por tamaño, que es otro error)
        assert!(!invalid("a{4294967295}").contains("Repetition count"), "{}", invalid("a{4294967295}"));
        // los conteos de siempre, y lo que nunca fue un conteo sigue siendo texto
        assert_eq!(all("aaa", "(?=a)a{3}"), ["aaa"]);
        assert_eq!(all("aaaa", "(?=a)a{1,2}"), ["aa", "aa"]);
        assert_eq!(all("a{x} a{", r"a\{x\}|a\{(?=$)"), ["a{x}", "a{"]);
        assert_eq!(all("a{x}", "(?=a)a{x}"), ["a{x}"]);
        // `{,5}` es «de 0 a 5» en esta crate (no cambia), y su techo tiene el mismo límite
        assert_eq!(all("aaaaaaa", "(?=a)a{,5}"), ["aaaaa", "aa"]);
        assert_eq!(invalid("a{,4294967296}"), format!("Parsing error at position 3: {}", TOO_LARGE));
        // Ronda 2, N-1: sin la llave que cierra no es una repetición, por grande que sea el
        // número: es el texto que era (como `a{2`). El error salía apenas se leía el número.
        assert_eq!(all("a{4294967296", "a{4294967296"), ["a{4294967296"]);
        assert_eq!(all("a{4294967296", "(?=a)a{4294967296"), ["a{4294967296"]);
        assert_eq!(all("a{4294967296,", "(?=a)a{4294967296,"), ["a{4294967296,"]);
        assert_eq!(all("a{1,4294967296", "(?=a)a{1,4294967296"), ["a{1,4294967296"]);
        assert_eq!(all("a{4294967296,x}", "(?=a)a{4294967296,x}"), ["a{4294967296,x}"]);
        assert_eq!(all("a{2", "(?=a)a{2"), ["a{2"]);
        // con las dos cuentas fuera de rango, el error señala la primera
        assert_eq!(invalid("a{4294967296,4294967297}"), format!("Parsing error at position 2: {}", TOO_LARGE));
    }

    /// Ronda 2, B-2: el mensaje del tope vale para cualquier causa (antes afirmaba que el patrón
    /// retrocedía de más o tenía look-arounds en repeticiones, y un lexer lineal no hace eso).
    #[test]
    fn the_messages_of_the_limits() {
        let Control::Error(e) = failure("backtrack_find_all", "x", 1_048_576, Failure::StepLimit) else { unreachable!() };
        assert_eq!(
            e.message,
            "backtrack_find_all: step limit exceeded (max_steps = 1048576) — the pattern did more work on this text \
             than the limit allows; if a repetition is tried again from every position of a long run \
             (\\d+(?![\\d.]) reads a long number once from each of its digits), say where a match may start \
             ((?<!\\d)\\d+(?![\\d.])); if it backtracks (nested or ambiguous repetitions, look-arounds inside \
             repetitions), make repetitions possessive (a++, a*+) or atomic ((?>…)); if the work is what the pattern \
             needs, pass a higher max_steps"
        );
        let Control::Error(e) = failure("backtrack_matches", "(a|b\\g<1>\\g<1>)", 0, Failure::InvalidPattern(too_large()))
        else {
            unreachable!()
        };
        assert_eq!(
            e.message,
            "invalid regex pattern '(a|b\\\\g<1>\\\\g<1>)': the compiled pattern, with the memory its searches need, \
             is over 16 MiB: a subroutine call (\\g<1>) copies its group at every call, a counted repetition of a \
             Unicode class (\\w{300}) is large, and capture groups multiply what a search needs (groups × size of \
             the pattern); write it so that it repeats less, capture less ((?:…) does not capture) or use ASCII \
             classes ([0-9A-Za-z_] for \\w), or split it into several patterns"
        );
        // el ejemplo del mensaje: `\w{300}` no compila, y con la clase ASCII sí
        assert_eq!(invalid(r"\w{300}"), too_large());
        assert!(Search::new(r"[0-9A-Za-z_]{300}", false, DEFAULT).is_ok());
        let Control::Error(e) = failure("backtrack_find_all", "x", 1, Failure::VmStack) else { unreachable!() };
        assert_eq!(
            e.message,
            "backtrack_find_all: more than 1000000 pending backtrack points — a repetition that is not possessive \
             ran over a long stretch of text, or look-behinds inside repetitions left their alternatives pending; \
             make repetitions possessive (a++, a*+) or atomic ((?>…))"
        );
    }

    #[test]
    fn the_continue_anchor_is_rejected() {
        for pattern in [r"\G", r"\Ga", r"(?:\G|x)a?", r"(?=\G)a", r"a|(b\G)"] {
            assert_eq!(invalid(pattern), NO_CONTINUE_ANCHOR, "{}", pattern);
        }
        assert_eq!(matches("a", r"\Ga", DEFAULT), Err(Failure::InvalidPattern(NO_CONTINUE_ANCHOR.to_string())));
        // una `G` escapada o dentro de una clase no es el ancla
        assert_eq!(all(r"\G", r"\\G"), [r"\G"]);
        assert_eq!(all("G", r"[\\G](?=$)"), ["G"]);
    }

    #[test]
    fn matches_validates_the_pattern_as_written() {
        // envuelto en `^(?:…)$` este patrón desbalanceado compilaría
        assert!(Regex::new("^(?:a)(b)$").is_ok());
        assert_eq!(
            matches("ab", "a)(b", DEFAULT),
            Err(Failure::InvalidPattern(Regex::new("a)(b").unwrap_err().to_string()))
        );
        // el error habla del patrón escrito: la posición es la suya
        assert_eq!(
            matches("a", "(", DEFAULT),
            Err(Failure::InvalidPattern("Parsing error at position 1: Opening parenthesis without closing parenthesis".into()))
        );
    }

    /// Ronda 1, B-1: la clave del compilado de `backtrack_matches` es el patrón escrito. Con el
    /// texto envuelto como clave, un `^(?:a)(b)$` escrito a mano dejaba en la caché el compilado
    /// que `backtrack_matches(t, "a)(b")` iba a buscar, y la validación no corría.
    #[test]
    fn a_wrapped_pattern_written_by_hand_does_not_skip_the_check() {
        clear_thread_caches();
        assert_eq!(find_all("ab", "^(?:a)(b)$", DEFAULT), Ok(vec!["ab"]));
        assert_eq!(invalid_in_full("a)(b"), Regex::new("a)(b").unwrap_err().to_string());
        // y al revés: el compilado que cubre todo el texto no sirve a `find_all`
        assert_eq!(matches("xa", "a(?=$)", DEFAULT), Ok(false));
        assert_eq!(find_all("xa", "a(?=$)", DEFAULT), Ok(vec!["a"]));
        assert_eq!(matches("xab", "^(?:a)(b)$", DEFAULT), Ok(false));
        assert_eq!(matches("ab", "^(?:a)(b)$", DEFAULT), Ok(true));
    }

    /// Ronda 1, B-2: en modo verboso un patrón que termina en comentario se comía el cierre del
    /// envoltorio, y `backtrack_matches` daba un error de paréntesis sobre un patrón válido.
    /// Desde la ronda 2 no hay envoltorio de texto (`full_match` del fork).
    #[test]
    fn a_verbose_pattern_that_ends_in_a_comment_matches_in_full() {
        let pattern = "(?x) a (?=b) b # una a seguida de b";
        assert_eq!(matches("ab", pattern, DEFAULT), Ok(true));
        assert_eq!(matches("xab", pattern, DEFAULT), Ok(false));
        assert_eq!(matches("abx", pattern, DEFAULT), Ok(false));
        assert_eq!(matches("ab\n", pattern, DEFAULT), Ok(false));
        assert_eq!(matches("a", "(?x)a # c", DEFAULT), Ok(true));
        assert_eq!(matches("b", "(?x)a # c", DEFAULT), Ok(false));
        // sin envolver ya andaba, y con el salto escrito por el programa da lo mismo
        assert_eq!(all("xabx", pattern), ["ab"]);
        assert_eq!(matches("ab", "(?x) a (?=b) b # una a seguida de b\n", DEFAULT), Ok(true));
        // fuera del modo verboso un `#` es un carácter: el patrón no gana un salto de línea
        assert_eq!(matches("a#b", "a#(?=b)b", DEFAULT), Ok(true));
        assert_eq!(matches("a#b\n", "a#(?=b)b", DEFAULT), Ok(false));
        // un inválido con `#` sigue siendo el error de lo que el programa escribió
        assert_eq!(invalid_in_full("(?x)( # abre"), invalid("(?x)( # abre"));
    }

    /// Ronda 2: cubrir todo el texto no le cambia el significado al patrón. Envuelto como
    /// `^(?:…)$` (la ronda 1), `\g<0>` (el patrón entero) incluía las anclas y no coincidía nunca
    /// adentro del texto: la respuesta era `false`, sin error.
    #[test]
    fn matching_in_full_keeps_what_the_pattern_means() {
        let balanced = r"\((?:[^()]|\g<0>)*\)";
        assert_eq!(all("x ((a)(b)) y", balanced), ["((a)(b))"]);
        assert_eq!(matches("((a)(b))", balanced, DEFAULT), Ok(true));
        assert_eq!(matches("()", balanced, DEFAULT), Ok(true));
        assert_eq!(matches("(a(b)", balanced, DEFAULT), Ok(false));
        assert_eq!(matches("((a)(b)) ", balanced, DEFAULT), Ok(false));
        assert_eq!(matches(" ((a)(b))", balanced, DEFAULT), Ok(false));
        assert_eq!(matches("(a)(b)", balanced, DEFAULT), Ok(false));
        // el envoltorio escrito a mano es otro patrón: ahí las anclas sí son parte de la llamada
        assert_eq!(matches("((a)(b))", &format!("^(?:{})$", balanced), DEFAULT), Ok(false));
        assert_eq!(matches("()", &format!("^(?:{})$", balanced), DEFAULT), Ok(true));
        // cubrir todo el texto retrocede adentro del patrón: la primera rama sola no alcanza
        assert_eq!(matches("ab", "a|ab", DEFAULT), Ok(true));
        assert_eq!(matches("ab", "(?=a)(?:a|ab)", DEFAULT), Ok(true));
        assert_eq!(matches("aab", "(?=a)a*?(?:a|ab)", DEFAULT), Ok(true));
        assert_eq!(matches("abc", "(?=a)(?:a|ab)", DEFAULT), Ok(false));
        // un look-around del final mira más allá de lo que coincide, y ahí termina el texto
        assert_eq!(matches("ab", "a(?=b)", DEFAULT), Ok(false));
        assert_eq!(matches("a", "a(?=b)", DEFAULT), Ok(false));
        assert_eq!(matches("a", "a(?!b)", DEFAULT), Ok(true));
        assert_eq!(matches("a", "(?=a)", DEFAULT), Ok(false));
        assert_eq!(matches("", "(?=$)", DEFAULT), Ok(true));
        // el principio y el fin son los del texto, con las banderas que traiga el patrón
        assert_eq!(matches("a\nb", "(?m)(?=a)a", DEFAULT), Ok(false));
        assert_eq!(matches("b\na", "(?m)(?=a)a", DEFAULT), Ok(false));
        assert_eq!(matches("a\n", "(?=a)a", DEFAULT), Ok(false));
        assert_eq!(matches("a\nb", "(?m)(?=a)a$\n^b", DEFAULT), Ok(true));
        assert_eq!(matches("A", "(?i)(?=a)a", DEFAULT), Ok(true));
        // los grupos se numeran igual que en el patrón escrito
        assert_eq!(matches("abab", r"(ab)\1", DEFAULT), Ok(true));
        assert_eq!(matches("aa", r"(?=a)(a)\g<1>", DEFAULT), Ok(true));
        assert_eq!(matches("aXa", r"(?<x>a)X\k<x>", DEFAULT), Ok(true));
        // está anclado: donde no coincide no prueba cada posición del texto
        let mut search = Search::new("(?=a)a", true, NO_LIMIT).unwrap();
        let text = "b".repeat(10_000);
        assert_eq!(search.run(|re, steps| re.find_from_pos_with_steps(&text, 0, steps).map(|m| m.is_some())), Ok(false));
        assert!(search.spent() < 16, "{}", search.spent());
        // y lo que va entero al motor lineal sigue yendo entero (no gasta pasos)
        assert_eq!(Search::new(r"\w+|x", true, NO_LIMIT).unwrap().regex().program_len(), 0);
        assert_eq!(matches("año", r"\w+|x", 1), Ok(true));
    }

    /// El envoltorio no es texto: no le suma un nivel al límite de anidamiento del parser (el
    /// más profundo que compila, compila también para cubrir todo el texto). Lo que sí puede no
    /// entrar es el tamaño: el compilado que cubre todo el texto es otro programa, y cuando pasa
    /// del techo y el de las búsquedas no, el error dice que es por eso.
    #[test]
    fn a_valid_pattern_that_does_not_fit_in_full_says_so() {
        let nested = |d: usize| format!("(?=a){}a{}", "(?:".repeat(d), ")".repeat(d));
        let deepest = (1..200).take_while(|d| Regex::new(&nested(*d)).is_ok()).last().expect("alguna compila");
        // escrito a mano, el envoltorio de la ronda 1 no entraba
        assert!(Regex::new(&format!("^(?:{})$", nested(deepest))).is_err());
        assert_eq!(matches("a", &nested(deepest), DEFAULT), Ok(true));
        assert_eq!(matches("xa", &nested(deepest), DEFAULT), Ok(false));
        assert_eq!(invalid_in_full(&nested(deepest + 1)), invalid(&nested(deepest + 1)));
        assert!(invalid(&nested(deepest + 1)).ends_with("Pattern too deeply nested"));

        // el que cubre todo el texto lleva una pieza más, la que comprueba el fin del texto
        // (medido: 64 531 bytes el de las búsquedas, 68 777 el otro)
        let pattern = r"(?<=\w+)x";
        let (written, full) = (smallest(pattern, false), smallest(pattern, true));
        assert!(full > written, "{} y {}", full, written);
        // no siempre es el más grande: cuando lo que sigue al último look-around es largo, las
        // búsquedas se lo dan entero al motor lineal (una pieza con sus tablas), y para cubrir
        // todo el texto corre en la VM, clase por clase (225 KB contra 20 KB)
        let other = r"(?=a)\w+\d+\s+\w+\d+";
        assert!(smallest(other, true) < smallest(other, false));
        assert!(build(pattern, false, written).is_ok());
        assert_eq!(
            build(pattern, true, written).err(),
            Some(Failure::InvalidPattern(format!("{}{}", FULL_MATCH_DOES_NOT_FIT, too_large())))
        );
        assert!(build(pattern, true, full).is_ok());
        // con un techo en el que no entra ni el escrito, el error es el del patrón
        assert_eq!(build(pattern, true, written - 1).err(), Some(Failure::InvalidPattern(too_large())));
        assert_eq!(build(pattern, false, written - 1).err(), Some(Failure::InvalidPattern(too_large())));
    }

    // ---------- la caché ----------

    #[test]
    fn a_pattern_is_compiled_once() {
        clear_thread_caches();
        let before = builds();
        for _ in 0..50 {
            assert_eq!(all("a   b", r"\s+(?!\S)|\s+"), ["  ", " "]);
        }
        assert_eq!(builds() - before, 1);
        // `matches` compila el suyo (el que cubre todo el texto), una vez
        let before = builds();
        for _ in 0..50 {
            assert_eq!(matches("abab", r"(ab)\1", DEFAULT), Ok(true));
        }
        assert_eq!(builds() - before, 1);
        // …y el mismo patrón en una búsqueda es otro compilado
        let before = builds();
        for _ in 0..50 {
            assert_eq!(all("abab", r"(ab)\1"), ["abab"]);
            assert_eq!(matches("abab", r"(ab)\1", DEFAULT), Ok(true));
        }
        assert_eq!(builds() - before, 1);
        // uno verboso que termina en comentario, una vez también (no hay texto que envolver)
        let before = builds();
        for _ in 0..50 {
            assert_eq!(matches("a", "(?x)(?=a)a # c", DEFAULT), Ok(true));
        }
        assert_eq!(builds() - before, 1);
        // un patrón inválido no se guarda: vuelve a dar su error
        let before = builds();
        assert!(find_all("a", "(?=", DEFAULT).is_err());
        assert!(find_all("a", "(?=", DEFAULT).is_err());
        assert_eq!(builds() - before, 2);
    }

    /// El tope no es del compilado: el mismo sirve a todas las llamadas, con el presupuesto que
    /// traiga cada una.
    #[test]
    fn the_same_compiled_pattern_serves_every_limit() {
        clear_thread_caches();
        let before = builds();
        let short = a_then(8, "b");
        let (spent, _) = spent_by(&short, SLOW);
        assert_eq!(find_all(&short, SLOW, spent), Ok(vec![]));
        assert_eq!(find_all(&short, SLOW, spent - 1), Err(Failure::StepLimit));
        assert_eq!(find_all(&a_then(28, "b"), SLOW, DEFAULT), Err(Failure::StepLimit));
        assert_eq!(find_all(&short, SLOW, NO_LIMIT), Ok(vec![]));
        assert_eq!(builds() - before, 1);
    }

    /// Ronda 1, M-2 y N-2: el fin de una unidad de trabajo suelta los compilados del hilo.
    #[test]
    fn clearing_the_thread_caches_drops_the_compiled_patterns() {
        clear_thread_caches();
        let before = builds();
        assert_eq!(all("ab", "a(?!c)"), ["a"]);
        assert_eq!(matches("ab", "a(?!c)b", DEFAULT), Ok(true));
        assert_eq!(all("ab", "a(?!c)"), ["a"]);
        assert_eq!((builds() - before, CACHE.with(|c| c.borrow().len())), (2, 2));
        clear_thread_caches();
        assert_eq!(CACHE.with(|c| c.borrow().len()), 0);
        assert_eq!(all("ab", "a(?!c)"), ["a"]);
        assert_eq!(builds() - before, 3, "después de vaciar se compila de nuevo");
        // lo mismo desde el intérprete, que es quien lo llama al terminar una request
        let mut interp = Interpreter::new();
        interp.reset_for_request();
        assert_eq!(CACHE.with(|c| c.borrow().len()), 0);
    }

    #[test]
    fn more_patterns_than_the_cache_holds_still_give_their_own_results() {
        for round in 0..2 {
            for i in 0..40 {
                let pattern = format!("(?<=n{}=)\\d+", i);
                let text = format!("n{}={} n{}=7", i, i * 3 + round, i + 100);
                assert_eq!(all(&text, &pattern), [(i * 3 + round).to_string()], "{}", pattern);
            }
        }
    }

    // ---------- ronda 3 ----------

    fn groups(text: &str, pattern: &str) -> Vec<Option<String>> {
        capture(text, pattern, DEFAULT).unwrap().unwrap().into_iter().map(|g| g.map(String::from)).collect()
    }
    fn some(texts: &[&str]) -> Vec<Option<String>> {
        texts.iter().map(|t| Some(t.to_string())).collect()
    }

    /// Una referencia escrita adentro del grupo al que apunta (`(a\1?)+`) corre mientras ese
    /// grupo todavía está coincidiendo. Lee lo que el grupo coincidió la vez anterior, como en
    /// PCRE, Perl y Oniguruma; la primera vez no hay nada que leer y no coincide. Es lo que hace
    /// la crate desde la 0.20.
    ///
    /// La 0.18.0 leía desde el comienzo de esta vuelta hasta el fin de la anterior, que es otro
    /// texto, o ninguno cuando quedaban cruzados: ahí entraba en pánico (`(?:x(a\1?))+` sobre
    /// `xaxa`, ronda 3, A-1). Por eso en la ronda 3 estos patrones eran un error de compilación;
    /// ya no hace falta.
    #[test]
    fn a_backreference_inside_its_group_reads_what_the_group_matched_the_time_before() {
        for (pattern, text, found, group) in [
            // la primera vuelta deja `a`; en la segunda, `\1?` no tiene otra `a` para leer
            (r"(?:x(a\1?))+", "xaxa", "xaxa", "a"),
            (r"(?:x(a\1?)){2}", "xaxa", "xaxa", "a"),
            (r"(?:x(a\1*)){2}", "xaxa", "xaxa", "a"),
            (r"(?:b(a\1?))+", "baba", "baba", "a"),
            // la segunda vuelta lee la `a` de la primera: el grupo queda con `aa`
            (r"(a\1?)+", "aaa", "aaa", "aa"),
            (r"(?<n>a\k<n>?)+", "aaa", "aaa", "aa"),
            (r"(?:x(\1?a))+", "xaxaa", "xaxaa", "aa"),
            // y la tercera no tiene dos más para leer
            (r"(a\1?)+", "aaaa", "aaaa", "a"),
            (r"^(?:x?(a|b\1))+$", "aba", "aba", "ba"),
            (r"(?:(\1|a)b){2}", "abab", "abab", "a"),
            (r"(a(?:b|c\1)*)", "abcab", "ab", "ab"),
        ] {
            assert_eq!(all(text, pattern).first().map(String::as_str), Some(found), "{} sobre {}", pattern, text);
            assert_eq!(groups(text, pattern), some(&[group]), "{} sobre {}", pattern, text);
            // el que cubre todo el texto compila igual
            assert!(matches(text, pattern, DEFAULT).is_ok(), "{}", pattern);
        }
        // sin una vez anterior, la referencia no coincide; tampoco la de un grupo de más afuera
        for (pattern, text) in [
            (r"(a\1)", "aa"),
            (r"(a(?=\1))", "aa"),
            (r"(a)(b\2)", "ab"),
            (r"(a(b)\1)", "aba"),
            (r"((a)(b\3))", "ab"),
        ] {
            assert_eq!(all(text, pattern), Vec::<String>::new(), "{} sobre {}", pattern, text);
            assert_eq!(capture(text, pattern, DEFAULT), Ok(None), "{} sobre {}", pattern, text);
            assert_eq!(matches(text, pattern, DEFAULT), Ok(false), "{} sobre {}", pattern, text);
            assert_eq!(replace(text, pattern, "-", DEFAULT), Ok(None), "{} sobre {}", pattern, text);
        }
        // la referencia después de que el grupo cierra es la de siempre, también en una repetición
        // y adentro de otro grupo
        assert_eq!(all("xaxa", r"(?:x(a)\1?)+"), ["xaxa"]);
        assert_eq!(all("abab", r"(ab)\1"), ["abab"]);
        assert_eq!(all("aa-bb", r"((a)\2)"), ["aa"]);
        assert_eq!(groups("abab", r"((ab)\2)"), some(&["abab", "ab"]));
        // una referencia a un grupo que está más adelante, o en otra rama
        assert_eq!(all("ab", r"(?:(a)|b\1)+"), ["a"]);
        assert_eq!(all("aa", r"(?:\1a|(a))+"), ["aa"]);
    }

    /// Ronda 4, M-1: `(?(1)…)` escrito adentro del grupo 1 pregunta si el grupo coincidió, no si
    /// empezó: en la primera vuelta todavía no, y toma la otra rama. La 0.18.0 miraba sólo el
    /// comienzo y daba un resultado que no da ningún otro motor (`xab` en la primera fila, y sin
    /// coincidencia en la segunda y la tercera). En las tres primeras filas es lo que dan Perl y
    /// el módulo `regex` de Python; en la última Perl da `ac`, y `regex` y `re`, esto.
    #[test]
    fn a_condition_inside_its_group_asks_whether_the_group_has_matched() {
        for (pattern, text, found, group) in [
            (r"(?:x(a(?(1)b|c)))+", "xacxab", "xacxab", "ab"),
            (r"(?:x(a(?(1)b|c)))+", "xac", "xac", "ac"),
            (r"(a(?(1)b|c))+", "ac", "ac", "ac"),
            (r"(a(?(1)b|c))+", "acab", "acab", "ab"),
        ] {
            assert_eq!(all(text, pattern), [found], "{} sobre {}", pattern, text);
            assert_eq!(groups(text, pattern), some(&[group]), "{} sobre {}", pattern, text);
            assert_eq!(matches(text, pattern, DEFAULT), Ok(true), "{} sobre {}", pattern, text);
        }
    }

    /// Una referencia que llega a su grupo por una llamada de subrutina (`(a\g<2>)(\1)`: la
    /// llamada corre una copia del grupo 2, con su `\1`, adentro del grupo 1). Lee lo mismo: lo que
    /// el grupo coincidió la vez anterior. Ronda 4, B-1: la 0.18.0 leía el texto vacío cuando la
    /// vuelta empezaba donde había terminado la anterior, y coincidía (`abb` en la primera fila,
    /// `abaa` entero en la segunda, `ab` en la tercera). La primera y la tercera son lo que dan
    /// Perl y el módulo `regex` de Python; la segunda, lo que da `regex` (Perl no coincide).
    #[test]
    fn a_backreference_that_reaches_its_open_group_through_a_call() {
        assert_eq!(all("abb", r"(?:(a|b\g<2>))+(\1)"), Vec::<String>::new());
        assert_eq!(all("abaa", r"(?:(a|b\g<2>))+(\1)"), ["aa"]);
        assert_eq!(groups("abaa", r"(?:(a|b\g<2>))+(\1)"), some(&["a", "a"]));
        assert_eq!(all("ab", r"(?:(a|b\g<2>))+$(\1)?"), Vec::<String>::new());
        assert_eq!(capture("ab", r"(?:(a|b\g<2>))+$(\1)?", DEFAULT), Ok(None));
        // la de la ronda 3: en la segunda vuelta la llamada no tiene otra `a` para leer
        let pattern = r"(?:x(a\g<2>?))+(\1)";
        assert_eq!(all("xaxaa", pattern), ["xaxaa"]);
        assert_eq!(groups("xaxaa", pattern), some(&["a", "a"]));
        assert_eq!(matches("xaxaa", pattern, DEFAULT), Ok(true));
        assert_eq!(matches("xaxa", pattern, DEFAULT), Ok(false));
        assert_eq!(replace("xaxaa-", pattern, "<\\1\\2>", DEFAULT), Ok(Some("<aa>-".to_string())));
    }

    /// Ronda 3 (lo encontró el fuzz propio, no el auditor): el comienzo de un grupo se guarda al
    /// entrar, salvo que el grupo ya esté abierto (una llamada desde adentro de él). Upstream lo
    /// decidía al correr, mirando si el fin guardado quedaba adelante de la posición: un grupo que
    /// ya había coincidido y se volvía a entrar más atrás quedaba con el comienzo viejo.
    #[test]
    fn a_group_comes_out_with_the_start_and_the_end_of_the_same_match() {
        // la llamada, adentro de un look-ahead, coincide en 1; después el grupo coincide en 0.
        // Upstream dejaba el grupo de 1 a 0 y leerlo era un pánico (`Match::as_str`).
        assert_eq!(groups("b", r"(?=b\g<1>)((?=))"), some(&[""]));
        assert_eq!(groups("b", r"(?=(?:b\g<1>)(?!(?:A)))((?=))"), some(&[""]));
        assert_eq!(replace("b", r"(?=b\g<1>)((?=))", "[\\1]", DEFAULT), Ok(Some("[]b".to_string())));
        // paréntesis balanceados con el grupo que los captura: upstream daba `(b))`
        assert_eq!(groups("((a)(b))", r"(\((?:[^()]|\g<1>)*\))"), some(&["((a)(b))"]));
        assert_eq!(
            replace("f((a)(b)) g(c)", r"(\((?:[^()]|\g<1>)*\))", "<\\1>", DEFAULT),
            Ok(Some("f<((a)(b))> g<(c)>".to_string()))
        );
        // una llamada repetida desde adentro del grupo: la segunda vuelta encuentra el fin que
        // dejó la primera, y no mueve el comienzo del grupo, que sigue abierto (upstream: `abb`)
        assert_eq!(groups("aababb", r"(a(?:\g<1>)*b)"), some(&["aababb"]));
        assert_eq!(groups("aababbab", r"(a(?:\g<1>)*b)"), some(&["aababb"]));
        // una llamada desde afuera del grupo: mientras corre su copia el grupo está abierto, y la
        // llamada de adentro de la copia tampoco mueve el comienzo
        assert_eq!(groups("abaabb", r"(a\g<1>?b)\g<1>"), some(&["aabb"]));
        assert_eq!(groups("aabbab", r"\g<1>(a\g<1>?b)"), some(&["ab"]));
        // lo que ya daba bien sigue igual: una llamada desde adentro, grupos anidados, una llamada
        // después del grupo y una antes
        assert_eq!(groups("aabb", r"(a\g<1>?b)"), some(&["aabb"]));
        assert_eq!(groups("aaa", r"((a)\g<1>?)"), some(&["aaa", "a"]));
        assert_eq!(groups("ab", r"((a|b)\g<1>?)"), some(&["ab", "b"]));
        assert_eq!(groups("ab", r"(a|b)\g<1>"), some(&["b"]));
        assert_eq!(groups("abb", r"(a|b)\g<1>\g<1>"), some(&["b"]));
        assert_eq!(groups("ab", r"\g<1>(a|b)"), some(&["b"]));
        assert_eq!(groups("aba", r"(?:(a)|b)+"), some(&["a"]));
        assert_eq!(groups("abcd", r"(?:(?=(.)(.))..)+"), some(&["c", "d"]));
    }

    /// Ronda 3, M-2: el largo del patrón tiene máximo, y se mira antes de parsearlo.
    #[test]
    fn a_pattern_longer_than_the_limit_is_an_error_before_it_is_parsed() {
        let fits = format!("(?=a){}", "a".repeat(MAX_PATTERN_BYTES - 5));
        assert_eq!(fits.len(), MAX_PATTERN_BYTES);
        assert_eq!(find_all("a", &fits, DEFAULT), Ok(vec![]));
        assert_eq!(matches("a", &fits, DEFAULT), Ok(false));
        let long = format!("{}a", fits);
        let before = builds();
        let error = Err(Failure::PatternTooLong(MAX_PATTERN_BYTES + 1));
        assert_eq!(find_all("a", &long, DEFAULT), error.clone().map(|()| vec![]));
        assert_eq!(capture("a", &long, DEFAULT), error.clone().map(|()| None));
        assert_eq!(replace("a", &long, "b", DEFAULT), error.clone().map(|()| None));
        assert_eq!(matches("a", &long, DEFAULT), error.clone().map(|()| false));
        assert_eq!(default_max_steps_for("a", &long, false), error.map(|()| 0));
        // uno que además no parsea da este error, no el del parser: no se llegó a parsear
        let unbalanced = "(".repeat(MAX_PATTERN_BYTES + 1);
        assert_eq!(find_all("a", &unbalanced, DEFAULT), Err(Failure::PatternTooLong(MAX_PATTERN_BYTES + 1)));
        assert_eq!(builds() - before, 0, "un patrón demasiado largo no se compila");
        // el largo es en bytes
        let two_bytes = "\u{e9}".repeat(MAX_PATTERN_BYTES / 2 + 1);
        assert_eq!(find_all("a", &two_bytes, DEFAULT), Err(Failure::PatternTooLong(MAX_PATTERN_BYTES + 2)));
        // el mensaje no repite el patrón
        let Control::Error(e) = failure("backtrack_find_all", &long, 0, Failure::PatternTooLong(long.len())) else {
            unreachable!()
        };
        assert_eq!(
            e.message,
            "backtrack_find_all: the pattern is 16385 bytes long, and a backtrack_* pattern may be at most 16384; \
             split it into several patterns"
        );
    }

    /// Ronda 3, M-2: buscar recursión por izquierda es lineal en los grupos. Upstream empezaba
    /// cada búsqueda con los visitados vacíos: una cadena de G grupos que se llaman al principio
    /// se recorría G veces (16 000 grupos, 7,6 s en release). Acá son milisegundos; el umbral es
    /// holgado a propósito (el cuadrático, con esta cadena y sin optimizar, pasa de 15 s).
    #[test]
    fn the_left_recursion_check_is_linear_in_the_groups() {
        let mut pattern = String::from("(a)");
        for i in 2..=16_000 {
            pattern.push_str(&format!("(\\g<{}>)", i - 1));
        }
        // en un hilo con pila de sobra: la búsqueda es recursiva, una vuelta por grupo de la cadena
        let took = std::thread::Builder::new()
            .stack_size(256 << 20)
            .spawn(move || {
                let started = std::time::Instant::now();
                // compilar corta en el techo (cada grupo copia al anterior); el análisis corre
                // entero antes
                assert!(too_large_at(&pattern, 1 << 20) > 1 << 20);
                started.elapsed()
            })
            .unwrap()
            .join()
            .unwrap();
        assert!(took < std::time::Duration::from_secs(3), "{:?}", took);
        // y el grupo que nombra el error de una recursión por izquierda es el primero, siempre el
        // mismo (upstream recorría un mapa de hash: podía nombrar otro en cada corrida)
        for _ in 0..20 {
            let e = RegexBuilder::new(r"(?<a>\g<b>x)(?<b>\g<c>y)(?<c>\g<a>z)").build().unwrap_err().to_string();
            assert_eq!(e, "Error compiling regex: Left-recursive subroutine call detected: group 'a' (1)");
        }
    }

    /// Ronda 3, N-2: los tamaños del análisis saturan. Con `a{2147483648}` anidado el producto
    /// desbordaba: pánico con chequeo de desbordes (los tests corren así), y sin él un tamaño que
    /// daba la vuelta y hacía pasar por recursión por izquierda una llamada que no lo es.
    #[test]
    fn the_sizes_of_the_analysis_saturate() {
        for pattern in [
            r"(?:(?:a{2147483648}){2147483648}){4}",
            r"(?:(?:a{2147483648}){2147483648}){4}|c",
            r"(?<g>(?:(?:b{2147483648}){2147483648}){4}\g<g>|c)",
            r"(?<g>(?:(?:b{2147483648}){2147483648}){3}\g<g>|c)",
            r"(?<=(?:(?:a{2147483648}){2147483648}){4})c",
            r"(?=x)(?:(?:a{2147483648}){2147483648}){4}",
            r"(?:a{4294967295}){4294967295}(?:b{4294967295}){4294967295}",
            r"(?=x)(?:a{4294967295}){4294967295}(?:b{4294967295}){4294967295}",
            r"(?<=(?:a{4294967295}){4294967295}(?=x)(?:b{4294967295}){4294967295})c",
        ] {
            let detail = invalid(pattern);
            assert!(!detail.contains("Left-recursive"), "{}: {}", pattern, detail);
        }
        // un condicional cuya condición es una expresión: su tamaño (acá ya saturado) se suma al
        // de las ramas y a la posición adentro del grupo
        let outcomes: Vec<String> = [
            r"(?((?:(?:a{2147483648}){2147483648}){4})b|c)",
            r"(a(?((?:(?:a{2147483648}){2147483648}){4})b|c))",
            r"(?<g>a(?((?:(?:a{2147483648}){2147483648}){4})b\g<g>|c))",
        ]
        .iter()
        .map(|pattern| format!("{:?}", Search::new(pattern, false, DEFAULT).map(|_| ())))
        .collect();
        // (el primero pasa del techo y los otros dos compilan: ninguno es un pánico ni una
        // recursión por izquierda que no hay)
        assert_eq!(outcomes, [format!("Err(InvalidPattern({:?}))", too_large()), "Ok(())".to_string(), "Ok(())".to_string()]);
        // un look-behind con dos tramos seguidos que corren en la VM: lo que tiene que caminar
        // hacia atrás es la suma de los dos. El patrón compila (son dos contadores), y no hay
        // texto de ese largo donde coincida.
        let far_back = r"(?<=(?:(?:(?=x)a){4294967295}){4294967295}(?:(?:(?=x)b){4294967295}){4294967295})c";
        assert_eq!(find_all("abc", far_back, DEFAULT), Ok(vec![]));
        // lo mismo en un look-behind de largo variable, que suma lo que camina tramo por tramo
        let far_back_variable = format!("(?<=a*{})c", &far_back[4..far_back.len() - 2]);
        assert_eq!(find_all("abc", &far_back_variable, DEFAULT), Ok(vec![]));
    }

    /// Ronda 3, M-1: una repetición seguida de algo que falla se vuelve a leer desde cada
    /// posición de la corrida. Es cuadrático (en todo motor que retrocede), el tope por defecto lo
    /// corta desde corridas de unos 750 caracteres, y lo posesivo no lo arregla; decir dónde
    /// puede empezar una coincidencia, sí.
    #[test]
    fn a_repetition_retried_from_every_position_of_a_run_needs_an_anchor() {
        let number = |digits: usize| format!("x {}. fin", "1".repeat(digits));
        let default_run = |text: &str, pattern: &str| find_all(text, pattern, default_for(text, pattern)).map(|v| v.len());
        // 500 cifras entran, 800 no
        assert_eq!(default_run(&number(500), r"\d+(?![\d.])"), Ok(0));
        assert_eq!(default_run(&number(800), r"\d+(?![\d.])"), Err(Failure::StepLimit));
        // el trabajo crece con el cuadrado de la corrida
        let (short, _) = spent_by(&number(400), r"\d+(?![\d.])");
        let (long, _) = spent_by(&number(800), r"\d+(?![\d.])");
        assert!(long > 3 * short && long < 5 * short, "{} y {}", short, long);
        // posesivo: sigue cuadrático (alcanza para un poco más, no para una corrida larga)
        assert_eq!(default_run(&number(16_000), r"\d++(?![\d.])"), Err(Failure::StepLimit));
        // con el comienzo dicho, lineal: menos de 16 pasos por byte en una corrida de 16 000
        for pattern in [r"(?<!\d)\d+(?![\d.])", r"(?<!\d)\d++(?![\d.])"] {
            let text = number(16_000);
            assert_eq!(default_run(&text, pattern), Ok(0), "{}", pattern);
            let (spent, _) = spent_by(&text, pattern);
            assert!(spent < 16 * text.len() as u64, "{}: {} pasos", pattern, spent);
            // y sigue encontrando lo que tiene que encontrar
            assert_eq!(all("a 12 b 3.5 c 77.", pattern), ["12", "5"], "{}", pattern);
        }
        // los otros tres de la auditoría, y su forma con el comienzo dicho
        let word = |letters: usize| format!("x {}- fin", "a".repeat(letters));
        assert_eq!(default_run(&word(1000), r"\w+(?![\w-])"), Err(Failure::StepLimit));
        assert_eq!(default_run(&word(16_000), r"(?<!\w)\w+(?![\w-])"), Ok(2));
        assert_eq!(default_run(&word(1000), r"\w+(?=:)|\d+"), Err(Failure::StepLimit));
        assert_eq!(default_run(&word(16_000), r"(?<!\w)\w++(?=:)|\d+"), Ok(0));
    }

    /// `\b`, `\B`, `\<` y `\>` van al motor lineal (desde la 0.20 de la crate; en la 0.18 corrían
    /// en la VM, ronda 3, B-1): un patrón que no tiene nada más que pida retroceso va entero, sin
    /// instrucciones ni pasos, y una lista de palabras entre dos `\b` es una sola pieza. Al lado
    /// de algo que sí lo pide corren en la VM, y dan lo mismo.
    #[test]
    fn word_boundaries_go_to_the_linear_engine() {
        let text = "a foo b food xfoo";
        for (pattern, found) in [(r"\bfoo\b", 1), (r"\Bfoo", 1), (r"\<foo", 2), (r"foo\>", 2)] {
            let re = Search::new(pattern, false, NO_LIMIT).unwrap();
            assert_eq!(re.regex().program_len(), 0, "{}", pattern);
            assert_eq!(find_all(text, pattern, 1).map(|v| v.len()), Ok(found), "{}", pattern);
            // con un look-ahead adelante el patrón corre en la VM: las mismas coincidencias
            let in_the_vm = format!("(?=.){}", pattern);
            assert!(Search::new(&in_the_vm, false, NO_LIMIT).unwrap().regex().program_len() > 0, "{}", pattern);
            assert_eq!(all(text, &in_the_vm), all(text, pattern), "{}", pattern);
        }
        assert_eq!(all("a foo b food", r"\bfoo\b"), ["foo"]);
        // una lista de 200 palabras, sin fronteras y con ellas: 0 instrucciones, 0 pasos
        let words: Vec<String> = (0..200).map(|i| format!("w{:03}", i)).collect();
        let list = format!("(?:{})", words.join("|"));
        let bounded = format!(r"\b{}\b", list);
        let text = "w007 x w199 w0077 ".repeat(50);
        for (pattern, found) in [(&list, 150), (&bounded, 100)] {
            assert_eq!(Search::new(pattern, false, NO_LIMIT).unwrap().regex().program_len(), 0);
            assert_eq!(find_all(&text, pattern, 1).map(|v| v.len()), Ok(found));
            assert_eq!(spent_by(&text, pattern), (0, found));
        }
    }

    /// Ronda 3, N-1: caminar hacia atrás cobra los bytes que camina (antes mezclaba la cuenta de
    /// caracteres con la de bytes). Un look-behind de 1 000 caracteres sobre letras de dos bytes
    /// camina el doble de bytes que sobre letras de uno, y cuesta eso.
    #[test]
    fn walking_back_pays_for_the_bytes_it_walks() {
        let pattern = r"(?<=a{1000})x";
        // lo que cobra caminar hacia atrás desde cada posición del texto: 1 paso cada 16 bytes
        let walk = |text: &str| -> u64 {
            let mut positions: Vec<usize> = text.char_indices().map(|(i, _)| i).collect();
            positions.push(text.len());
            positions
                .iter()
                .enumerate()
                .map(|(chars_before, &at)| {
                    let from = positions[chars_before.saturating_sub(1000)];
                    ((at - from) / 16) as u64
                })
                .sum()
        };
        let one = format!("{}x", "e".repeat(2000));
        let two = format!("{}x", "\u{e9}".repeat(2000));
        let ((spent_one, _), (spent_two, _)) = (spent_by(&one, pattern), spent_by(&two, pattern));
        // lo demás que gasta la búsqueda es por carácter, igual en los dos textos
        assert_eq!(spent_two - spent_one, walk(&two) - walk(&one));
        assert_eq!((walk(&one), walk(&two)), (92_876, 187_249));
        assert_eq!((spent_one, spent_two), (106_014, 200_387));
    }

    /// El texto de la sonda de la auditoría (ronda 3, A-2): corridas de `a` y `b` al azar, de 40
    /// letras, separadas por `x`.
    fn runs_of_a_and_b(bytes: usize) -> String {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut text = String::new();
        while text.len() < bytes {
            for _ in 0..40 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                text.push(if state % 2 == 0 { 'a' } else { 'b' });
            }
            text.push('x');
        }
        text
    }

    /// Ronda 3, A-2, y ronda 4, A-1: las cachés de búsqueda de un patrón tienen presupuesto
    /// mientras busca. Lo que cada una tiene sea cual sea el texto se contó al compilar, adentro
    /// del techo; el presupuesto (`SEARCH_CACHE_BYTES`) es para lo que crecen leyendo texto: los
    /// estados de sus DFA perezosos. Cada rama de este patrón es una regex distinta del motor
    /// lineal cuyo DFA tiene miles de estados (medio megabyte); sin presupuesto, las 48 juntas
    /// llegan a 22 MiB. Y al terminar la llamada el patrón no se queda con más que lo retenido.
    #[test]
    fn the_search_caches_of_a_pattern_have_a_budget() {
        // (48 ramas iguales compartirían una regex y una caché: cada una termina en otra letra)
        let tails: Vec<char> = ('c'..='z').chain('C'..='Z').chain('0'..='9').filter(|c| *c != 'x').take(48).collect();
        let pattern = tails.iter().map(|c| format!("(?=[ab])[ab]*a[ab]{{12}}{}", c)).collect::<Vec<_>>().join("|");
        // cada corrida del texto termina en una de esas letras: hay coincidencias, y entre una
        // y otra se puede mirar cuánto tienen las cachés
        let mut tail = tails.iter().cycle();
        let text: String =
            runs_of_a_and_b(12_000).chars().map(|c| if c == 'x' { *tail.next().unwrap() } else { c }).collect();
        // lo que encuentra, lo que gasta, y lo más que tuvieron las cachés entre dos búsquedas
        let search_all = |re: &Regex| {
            let mut steps = u64::MAX;
            let mut pos = 0;
            let mut found = 0;
            let mut most = 0;
            while let Some(m) = re.find_from_pos_with_steps(&text, pos, &mut steps).unwrap() {
                found += 1;
                most = most.max(re.search_cache_bytes());
                pos = if m.end() > pos { m.end() } else { next_char(&text, pos) };
            }
            (found, u64::MAX - steps, most.max(re.search_cache_bytes()))
        };
        // sin presupuesto (el fork por defecto, como upstream): lo que piden
        let unlimited = RegexBuilder::new(&pattern).backtrack_limit(usize::MAX).build().unwrap();
        let free = search_all(&unlimited);
        assert!(free.0 > 100, "{} coincidencias", free.0);
        assert!(free.2 > SEARCH_CACHE_BYTES + (4 << 20), "sin presupuesto piden {} bytes", free.2);
        assert_eq!(unlimited.search_cache_drops(), 0);
        drop(unlimited);
        // con el presupuesto del módulo: nunca tienen más que lo contado al compilar más el
        // presupuesto, para eso se sueltan, y el resultado y los pasos son los mismos
        clear_thread_caches();
        let search = Search::new(&pattern, false, NO_LIMIT).unwrap();
        let counted = search.regex().fresh_search_cache_bytes();
        assert_eq!(counted, 105_888);
        let limited = search_all(search.regex());
        assert_eq!((limited.0, limited.1), (free.0, free.1));
        assert!(limited.2 <= counted + SEARCH_CACHE_BYTES, "{} bytes", limited.2);
        assert!(limited.2 > SEARCH_CACHE_BYTES / 2, "{} bytes", limited.2);
        assert!(search.regex().search_cache_drops() >= 1);
        // al terminar la llamada, el compilado que queda en la caché del hilo suelta lo que pasa
        // de lo retenido
        let re = Rc::clone(&search.re);
        let held = re.search_cache_bytes();
        assert!(held > KEPT_SEARCH_CACHE_BYTES, "{} bytes", held);
        drop(search);
        assert_eq!(re.search_cache_bytes(), 0);
        // y una llamada entera, por la función, lo deja igual
        assert_eq!(find_all(&text, &pattern, NO_LIMIT).map(|v| v.len()), Ok(free.0));
        assert!(Rc::ptr_eq(&re, &compiled(&pattern, false).unwrap()), "es el compilado de la caché");
        assert_eq!(re.search_cache_bytes(), 0);
        // un patrón que usa poco se queda con lo suyo para la llamada siguiente
        let (spent, n) = spent_by(&text, CL100K);
        assert!(n > 0 && spent > 0);
        let small = compiled(CL100K, false).unwrap().search_cache_bytes();
        assert!(small > 0 && small <= KEPT_SEARCH_CACHE_BYTES, "{} bytes", small);
    }

    /// Ronda 4, A-2: un patrón que va entero al motor lineal (sin programa) también tiene una
    /// caché de búsqueda, la de la crate `regex`, que antes nadie contaba ni recortaba: 16
    /// patrones de 100 grupos retenían 1 857 MB. Lo que tiene sea cual sea el texto se cuenta al
    /// compilar, adentro del techo, y al terminar la llamada se suelta si pasa de lo retenido.
    #[test]
    fn a_pattern_that_goes_whole_to_the_linear_engine_has_its_cache_counted_and_trimmed() {
        // 100 grupos: no compila (antes, 99,6 MB de caché)
        assert_eq!(invalid(&r"(\w)".repeat(100)), too_large());
        // 10 grupos, con palabras largas (el motor lineal usa la PikeVM, que arma su tabla)
        let pattern = r"(\w+)".repeat(10);
        let text = format!("{} ", "a".repeat(2_000)).repeat(2);
        let search = Search::new(&pattern, false, NO_LIMIT).unwrap();
        assert_eq!(search.regex().program_len(), 0);
        let counted = search.regex().fresh_search_cache_bytes();
        assert_eq!(counted, 1_462_094);
        let mut steps = u64::MAX;
        assert!(search.regex().captures_from_pos_with_steps(&text, 0, &mut steps).unwrap().is_some());
        assert_eq!(steps, u64::MAX, "el motor lineal no gasta pasos");
        let held = search.regex().search_cache_bytes();
        assert!(held > counted && held < KEPT_SEARCH_CACHE_BYTES, "{} de {}", held, counted);
        // lo retenido: esta entra, y queda para la llamada siguiente
        let re = Rc::clone(&search.re);
        drop(search);
        assert_eq!(re.search_cache_bytes(), held);
        // 20 grupos: 5,0 MB contados; la caché que armó la búsqueda no sobrevive a la llamada
        let pattern = r"(\w+)".repeat(20);
        assert_eq!(capture(&text, &pattern, DEFAULT).map(|c| c.map(|gs| gs.len())), Ok(Some(20)));
        let re = compiled(&pattern, false).unwrap();
        assert_eq!(re.fresh_search_cache_bytes(), 4_964_686);
        assert_eq!(re.search_cache_bytes(), 0);
    }

    /// Soltar las cachés no cambia lo que una búsqueda encuentra ni lo que gasta. Con un
    /// presupuesto de cero se sueltan cada vez que una crece.
    #[test]
    fn dropping_the_search_caches_changes_neither_the_result_nor_the_steps() {
        let prose = "El perro come 42 veces; la perra \u{f1}and\u{fa} duerme. Hello, world! It's fine.\n".repeat(20);
        // Uno por cada lugar de la VM que busca con el motor lineal: un tramo sin grupos (los
        // dos primeros), uno con grupos, uno con grupos adentro de un grupo atómico, `(?~…)`, y
        // un look-behind de largo variable sin grupos y con ellos. Cada lugar tiene que contar
        // su caché después de buscar: si no, lo que crece ahí no lo ve nadie. Por eso en cada
        // patrón el único tramo con caché es el de ese lugar (un look-around de una sola clase
        // no tiene), y es uno que la hace crecer (con dos repeticiones seguidas de la misma
        // clase el motor lineal no puede usar su tabla de una pasada, que no crece).
        for (pattern, text) in [
            (CL100K, prose.as_str()),
            (GPT2, prose.as_str()),
            (r"(?=\w)(\w*)(\w+)-(\d+)", "ab-12 cd-345 x-y"),
            (r"(?>(\w*)(\w)(\d))x", "a1x b2y c3x"),
            (r"x(?~ab)y", "xaay xby xaby"),
            (r"(?<=a+)b", "ab aab b cb"),
            // Con grupos, el tramo que los llena es el de un look-behind negativo: desde la
            // ronda 10 un grupo adentro de uno positivo de largo variable es un error.
            (r"(?<!(a*)(a+)(-?))b", "ab a-b b aab a"),
        ] {
            let run = |limit: Option<usize>| {
                let mut builder = RegexBuilder::new(pattern);
                builder.backtrack_limit(usize::MAX);
                if let Some(limit) = limit {
                    builder.search_cache_limit(limit);
                }
                let re = builder.build().unwrap();
                let mut steps = u64::MAX;
                let mut pos = 0;
                let mut found = Vec::new();
                while let Some(c) = re.captures_from_pos_with_steps(text, pos, &mut steps).unwrap() {
                    let m = c.get(0).unwrap();
                    found.push((m.start(), m.end()));
                    pos = if m.end() > pos { m.end() } else { next_char(text, pos) };
                }
                (found, u64::MAX - steps, re.search_cache_bytes(), re.search_cache_drops())
            };
            let (free, tiny) = (run(None), run(Some(0)));
            assert!(!free.0.is_empty());
            assert_eq!((&free.0, free.1), (&tiny.0, tiny.1), "{}", pattern);
            // sin límite quedan, y no se sueltan nunca; con cero se sueltan
            assert!(free.2 > 0, "{}", pattern);
            assert_eq!(free.3, 0, "{}", pattern);
            assert!(tiny.3 > 0, "{}", pattern);
            assert!(tiny.2 <= free.2, "{}: {} y {}", pattern, tiny.2, free.2);
        }
        // Un look-behind de largo variable con grupos tiene dos cachés (la de su DFA hacia atrás
        // y la del tramo que llena los grupos), y uno que corre en la VM, la del DFA que busca
        // los comienzos además de la de su tramo: con un presupuesto de cero, que se suelten no
        // dice cuál de las dos se contó. Lo dice cuánto tienen después de buscar (los números de
        // `regex-automata` 0.4.18 en 64 bits).
        let held = |pattern: &str, text: &str| {
            let re = RegexBuilder::new(pattern).backtrack_limit(usize::MAX).build().unwrap();
            let (mut steps, mut pos) = (u64::MAX, 0);
            while let Some(m) = re.find_from_pos_with_steps(text, pos, &mut steps).unwrap() {
                pos = if m.end() > pos { m.end() } else { next_char(text, pos) };
            }
            re.search_cache_bytes()
        };
        assert_eq!(
            [held(r"(?<!(a*)(a+)(-?))b", "ab a-b b aab a aaa-b"), held(r"(?<=\bab+)x", "abx abbx bx x ab abbbx")],
            [2_387, 1_209]
        );
    }

    /// El optimizador de la crate (nuevo en la 0.20) reescribe repeticiones, y con grupos adentro
    /// cambia los grupos: en estos patrones agrega uno y deja sin coincidir los que el programa
    /// escribió (lo encontró el fuzz diferencial de esta versión: 8 patrones de 3 000). Las
    /// `backtrack_*` compilan las repeticiones como están escritas (`optimize_repeats(false)` del
    /// fork) y se quedan con lo que el optimizador hace sin tocar grupos: sacar el look-ahead del
    /// final, y `\K`.
    #[test]
    fn repetitions_are_compiled_as_written() {
        for (pattern, text) in [(r"(a){1,3}\n??(a){2,}", "aaa"), (r"b(a){1,3}\n??(a){2,}", "baaa")] {
            assert_eq!(groups(text, pattern), some(&["a", "a"]), "{}", pattern);
            assert_eq!(compiled(pattern, false).unwrap().captures_len(), 3, "{}", pattern);
            // La crate con sus opciones: tres grupos donde hay dos. Si esto cambia al actualizar
            // el fork, upstream lo arregló: volver a correr el fuzz diferencial antes de sacar
            // `optimize_repeats(false)`.
            let theirs = Regex::new(pattern).unwrap();
            assert_eq!(theirs.captures_len(), 4, "{}", pattern);
            let caps = theirs.captures(text).unwrap().unwrap();
            assert_eq!((caps.get(1).is_none(), caps.get(2).is_none()), (true, true), "{}", pattern);
        }
        assert_eq!(groups("aaaa", r"(a){2,}(b)?(a)+"), vec![Some("a".to_string()), None, Some("a".to_string())]);
        // el look-ahead del final sale del patrón, y lo demás va entero al motor lineal
        assert_eq!(compiled(r"\w(?=\s|$)", false).unwrap().program_len(), 0);
        assert_eq!(spent_by("a b", r"\w(?=\s|$)"), (0, 2));
        assert_eq!(all("a b", r"\w(?=\s|$)"), ["a", "b"]);
        // para cubrir todo el texto no se saca: el look-ahead tiene que mirar el fin del texto
        assert!(compiled(r"\w(?=\s|$)", true).unwrap().program_len() > 0);
        assert_eq!(matches("a", r"\w(?=\s|$)", DEFAULT), Ok(true));
        assert_eq!(matches("a ", r"\w(?=\s|$)", DEFAULT), Ok(false));
        // Para cubrir todo el texto el optimizador no corre: reescribe raíces, y la raíz es la
        // que arma `full_match`. Con un patrón de más de una pieza no encontraría nada que sacar
        // (el patrón queda un nivel más adentro); con `\K` solo, sí, y el patrón dejaría de
        // correr en la VM.
        assert!(compiled(r"\K", true).unwrap().program_len() > 0);
        assert_eq!([matches("", r"\K", DEFAULT), matches("a", r"\K", DEFAULT)], [Ok(true), Ok(false)]);
    }

    /// Un pánico de la crate publicada (0.20.2, `vm.rs:1610`, «slice index starts at 2 but ends
    /// at 1»): una referencia a un grupo cuyo comienzo quedó después de su fin. Lo encontró el
    /// fuzz propio, con el primer patrón de este test. En el fork las puntas de un grupo no se
    /// cruzan (`a_group_comes_out_with_the_start_and_the_end_of_the_same_match`), y una
    /// referencia a un grupo así lee la coincidencia que el grupo tiene.
    ///
    /// Desde la ronda 10 el patrón del fuzz no llega a buscar: su llamada `\g<1>` está adentro
    /// de un look-behind positivo de largo variable, que es un error al compilar
    /// (`a_capture_group_in_a_look_behind_of_variable_length_is_an_error`).
    #[test]
    fn a_backreference_never_reads_a_group_with_crossed_ends() {
        let pattern = "(?ms)[ab]|(b|.++[^a]?.*)*(?<=[^a]{2,}|\\g<1>??(?m:\\b\\1{2}|(?<=\u{e9})(?~ab)*+(?:[ab]{2}^\u{e9}{2}|\\A)*+){2})\u{e9}";
        let detail = invalid(pattern);
        assert!(
            detail.starts_with("Error compiling regex: A look-behind of variable length has a capture group or a subroutine call"),
            "{}",
            detail
        );
        for text in ["b\n\n", "b\n\u{e9}", "ab\n\n"] {
            assert_eq!(find_all(text, pattern, NO_LIMIT), Err(Failure::InvalidPattern(detail.clone())), "{:?}", text);
            assert_eq!(capture(text, pattern, NO_LIMIT), Err(Failure::InvalidPattern(detail.clone())), "{:?}", text);
        }
        // y con las opciones de la crate (el optimizador puesto) tampoco compila
        assert!(Regex::new(pattern).is_err());
        // Un grupo que upstream dejaba cruzado (de 1 a 0: la llamada, adentro de un look-ahead,
        // coincide en 1, y después el grupo coincide en 0), leído por una referencia: lee el
        // vacío de su coincidencia.
        assert_eq!(all("b", r"(?=b\g<1>)((?=))\1b"), ["b"]);
        assert_eq!(groups("b", r"(?=b\g<1>)((?=))\1{2}b"), some(&[""]));
    }

    /// Ronda 4, A-3, la clase entera: un pánico de la crate adentro de una llamada es un error de
    /// la llamada, que el programa puede atrapar, y no el fin del programa. Los compilados del
    /// hilo se sueltan (el que estaba en uso pudo quedar a medias).
    #[test]
    fn a_panic_inside_the_crate_is_an_error_of_the_call() {
        clear_thread_caches();
        assert_eq!(all("a", "(?=a)a"), ["a"]);
        let before = builds();
        PANIC_IN_SEARCH.with(|p| p.set(true));
        let results = (
            find_all("a", "(?=a)a", DEFAULT).map(|v| v.len()),
            capture("a", "(?=a)a", DEFAULT).map(|_| ()),
            replace("a", "(?=a)a", "b", DEFAULT).map(|_| ()),
            matches("a", "(?=a)a", DEFAULT),
        );
        PANIC_IN_SEARCH.with(|p| p.set(false));
        // el texto del pánico y, entre paréntesis, dónde fue (ronda 5, B-4: el hook no lo
        // imprime, así que el lugar va en el error)
        let detail = match &results.0 {
            Err(Failure::Engine(detail)) => detail.clone(),
            other => panic!("{:?}", other),
        };
        let (text, at) = detail.split_once(" (").expect(&detail);
        assert_eq!(text, "un pánico plantado por el test");
        let line: u32 = at.rsplit_once("backtrack.rs:").expect(at).1.trim_end_matches(')').parse().expect(at);
        assert!(at.ends_with(')') && line > 0, "{}", at);
        let engine = || Failure::Engine(detail.clone());
        assert_eq!(results, (Err(engine()), Err(engine()), Err(engine()), Err(engine())));
        // la primera llamada usó el compilado que había; cada una de las otras tres compiló el
        // suyo, porque la anterior los soltó
        assert_eq!(builds() - before, 3);
        // y la llamada siguiente compila de nuevo, y anda
        assert_eq!(all("a", "(?=a)a"), ["a"]);
        assert_eq!(builds() - before, 4);
        let Control::Error(e) = failure("backtrack_find_all", "x", 1, engine()) else { unreachable!() };
        assert_eq!(
            e.message,
            format!(
                "backtrack_find_all: internal error in the regex engine (a bug, not your program — please report \
                 it with the pattern and the text): un pánico plantado por el test ({}",
                at
            )
        );
    }

    /// Ronda 5, B-4: el pánico que `guarded` atrapa no se imprime. `catch_unwind` no frena el
    /// hook de pánico, que escribe en stderr el mensaje de la crate (puede citar el texto de la
    /// llamada, y stderr es el log de `serve`: lo que ve el programa se redacta, eso no). Un
    /// pánico de afuera de `guarded` se imprime como siempre.
    ///
    /// Stderr es del proceso: el test se corre a sí mismo en otro, con la variable puesta, y
    /// mira lo que ese escribió.
    #[test]
    fn a_panic_inside_the_crate_prints_nothing() {
        const CHILD: &str = "SYNSEMA_TEST_BACKTRACK_PANIC_CHILD";
        if std::env::var_os(CHILD).is_some() {
            PANIC_IN_SEARCH.with(|p| p.set(true));
            let inside = find_all("a", "(?=a)a", DEFAULT);
            PANIC_IN_SEARCH.with(|p| p.set(false));
            assert!(matches!(inside, Err(Failure::Engine(_))), "{:?}", inside);
            let outside: std::thread::Result<()> = std::panic::catch_unwind(|| panic!("un pánico de afuera de guarded"));
            assert!(outside.is_err());
            // y después de uno de afuera, el de adentro sigue callado
            PANIC_IN_SEARCH.with(|p| p.set(true));
            let again = matches("a", "(?=a)a", DEFAULT);
            PANIC_IN_SEARCH.with(|p| p.set(false));
            assert!(matches!(again, Err(Failure::Engine(_))), "{:?}", again);
            eprintln!("el hijo terminó");
            return;
        }
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "backtrack::tests::a_panic_inside_the_crate_prints_nothing", "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&child.stderr);
        let stdout = String::from_utf8_lossy(&child.stdout);
        assert!(child.status.success(), "{}\n{}", stdout, stderr);
        // el control: el hijo corrió el test, y su stderr es el que se lee
        assert!(stdout.contains("1 passed"), "{}", stdout);
        assert!(stderr.contains("el hijo terminó"), "{}", stderr);
        // el de afuera se imprimió, por el hook que había
        assert!(stderr.contains("panicked at") && stderr.contains("un pánico de afuera de guarded"), "{}", stderr);
        assert_eq!(stderr.matches("panicked at").count(), 1, "{}", stderr);
        // el de adentro, no
        assert!(!stderr.contains("plantado"), "{}", stderr);
    }

    /// Ronda 6, B-1: el pánico que `guarded` atrapa no le saca el modo raw a una terminal
    /// abierta. `term.rs` instala su propio hook, que restaura la consola antes de que un pánico
    /// termine el programa; cada hook envuelve al que había, así que el último instalado corre
    /// primero. Si `term_open` venía después de la primera llamada de `backtrack_*`, el hook de
    /// la terminal corría antes que el de este módulo y restauraba la consola por un pánico que
    /// no termina nada: el programa seguía, con su terminal abierta y la consola cocida. Con el
    /// orden inverso no pasaba. Ahora ese hook pregunta `panic_is_caught`, y el orden no importa.
    ///
    /// Los hooks son del proceso: el test se corre a sí mismo en otro, una vez por cada orden.
    /// No abre una terminal (el test no tiene una): mira el estado que el hook de `term.rs`
    /// apaga al restaurar (`term_guard`), y como control, que un pánico de afuera sí lo apaga.
    #[cfg(feature = "native")]
    #[test]
    fn a_panic_inside_the_crate_leaves_an_open_terminal_as_it_was() {
        use synsema_core::term_guard;
        const CHILD: &str = "SYNSEMA_TEST_BACKTRACK_TERM_CHILD";
        const NAME: &str = "backtrack::tests::a_panic_inside_the_crate_leaves_an_open_terminal_as_it_was";
        if let Some(order) = std::env::var_os(CHILD) {
            if order == "terminal-last" {
                // la primera llamada instala el hook de este módulo; el de la terminal lo envuelve
                assert_eq!(all("a", "(?=a)a"), ["a"]);
                crate::term::install_panic_hook();
            } else {
                crate::term::install_panic_hook();
                assert_eq!(all("a", "(?=a)a"), ["a"]);
            }
            term_guard::set_raw(true);
            PANIC_IN_SEARCH.with(|p| p.set(true));
            let inside = find_all("a", "(?=a)a", DEFAULT);
            PANIC_IN_SEARCH.with(|p| p.set(false));
            assert!(matches!(inside, Err(Failure::Engine(_))), "{:?}", inside);
            assert!(term_guard::is_raw(), "el pánico atrapado restauró la consola");
            // el control: uno de afuera de `guarded` la restaura, como siempre
            let outside: std::thread::Result<()> = std::panic::catch_unwind(|| panic!("un pánico de afuera de guarded"));
            assert!(outside.is_err());
            assert!(!term_guard::is_raw(), "el pánico de afuera no restauró la consola");
            return;
        }
        for order in ["terminal-last", "terminal-first"] {
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
                .env(CHILD, order)
                .output()
                .unwrap();
            let stderr = String::from_utf8_lossy(&child.stderr);
            let stdout = String::from_utf8_lossy(&child.stdout);
            assert!(child.status.success(), "{}:\n{}\n{}", order, stdout, stderr);
            // el control: el hijo corrió el test
            assert!(stdout.contains("1 passed"), "{}:\n{}", order, stdout);
        }
    }

    /// Ronda 5, M-1: el grupo de una repetición sin tope que puede coincidir vacía se lee igual
    /// corra donde corra el patrón. Cuando la última vuelta es la vacía, el motor lineal la
    /// descarta (el grupo se queda con la última que leyó algo) y la VM la deja pasar una vez,
    /// como Perl y PCRE (el grupo queda vacío). Qué motor corría la repetición dependía de lo de
    /// alrededor: un look-ahead al final (que el optimizador saca del patrón), un look-behind
    /// adelante o atrás, un grupo atómico. Ninguno cambia lo que el patrón coincide, y cambiaban
    /// el grupo: 22 patrones de 23 000 en el fuzz del auditor. En el fork esa repetición corre
    /// siempre en la VM (`analyze.rs`), y la lectura es la de Perl, `re` y `regex` de Python.
    #[test]
    fn the_groups_of_a_repetition_that_can_match_empty_do_not_depend_on_where_it_runs() {
        // la tabla del informe: el patrón, el texto y los grupos, que son los de Perl
        for (pattern, text, expected) in [
            ("(b?)*", "b", some(&[""])),
            ("(b?)*(?=)", "b", some(&[""])),
            ("(b?)*(?<!x)", "b", some(&[""])),
            ("(b?)*(?!x)", "b", some(&[""])),
            ("(?<!x)(b?)*", "b", some(&[""])),
            ("(b?)*+", "b", some(&[""])),
            ("(?>(b?)*)", "b", some(&[""])),
            (r"(?:(\w*),?)*", "ab,cd,", some(&[""])),
            (r"(?:(\w*),?)*(?<!x)", "ab,cd,", some(&[""])),
            ("(a|)*", "aaa", some(&[""])),
            ("(a|)*(?<=a)", "aaa", some(&[""])),
            ("(a*)*", "a", some(&[""])),
            ("(a*)*(?=)", "a", some(&[""])),
            ("(a*)*(?<!x)", "a", some(&[""])),
            ("(a*)+", "a", some(&[""])),
            ("(a*){2,}", "a", some(&[""])),
            ("b?((a|b){0,2})+", "ak", some(&["", "a"])),
            ("b?((a|b){0,2})+(?=.a*)", "ak", some(&["", "a"])),
            ("b?((a|b){0,2})+(?<!x)", "ak", some(&["", "a"])),
            // el grupo adentro del look-ahead que el optimizador saca, y adentro de uno que no
            ("(?=(a*)+)", "a", some(&[""])),
            ("(?=(a*)+)(?<!x)", "a", some(&[""])),
            (r"\w(a*)*(?=(?:ab)?$)", "Aa", some(&[""])),
        ] {
            assert_eq!(groups(text, pattern), expected, "{}", pattern);
            // corre en la VM: tiene instrucciones
            assert!(compiled(pattern, false).unwrap().program_len() > 0, "{}", pattern);
        }
        // `backtrack_replace` lee los mismos grupos
        for pattern in ["(b?)*", "(b?)*(?=)", "(b?)*(?<!x)"] {
            assert_eq!(replace("b", pattern, r"<\1>", DEFAULT), Ok(Some("<>".to_string())), "{}", pattern);
        }
        // las coincidencias de esos patrones, que no dependían de eso
        assert_eq!(all("ab,cd,", r"(?:(\w*),?)*"), ["ab,cd,"]);
        assert_eq!(all("aaa", "(a|)*"), ["aaa"]);
        // Lo que sigue yendo entero al motor lineal, porque los dos motores leen lo mismo: una
        // repetición contada (no tiene lazo) y una cuyo cuerpo no puede coincidir vacío (no
        // tiene vuelta vacía).
        for (pattern, text, expected) in [
            ("(b?){0,3}", "b", some(&[""])),
            ("(b?){2}", "b", some(&[""])),
            ("(b)*", "bb", some(&["b"])),
            (r"(\w+,?)*", "ab,cd,", some(&["cd,"])),
            (r"(\w+)(?:,\w*)*", "ab,cd,", some(&["ab"])),
        ] {
            assert_eq!(groups(text, pattern), expected, "{}", pattern);
            assert_eq!(compiled(pattern, false).unwrap().program_len(), 0, "{}", pattern);
            // y con algo al lado que lo manda a la VM, el mismo grupo
            assert_eq!(groups(text, &format!("{}(?<!x)", pattern)), expected, "{}", pattern);
        }
        // el look-ahead del final sigue saliendo del patrón: lo demás no gasta pasos
        assert_eq!(spent_by("clave: valor", r"\w+(?=:)"), (0, 1));
        assert_eq!(find_all("clave: valor", r"\w+(?=:)", 1), Ok(vec!["clave"]));
    }

    /// Ronda 6, M-1: la repetición sin tope que puede coincidir vacía se lee distinto en los dos
    /// motores también sin un grupo adentro, y lo que cambia es la coincidencia. Cuando el
    /// cuerpo prueba un camino vacío antes que uno que lee (`a?|b`, `b??`, `a*|b`, `a||b`), la VM
    /// toma la vuelta vacía y sale del lazo, como Perl y PCRE; el motor lineal nunca sigue una
    /// vuelta vacía, descarta ese camino y toma el que lee. `(?:a?|b)+` sobre `ab` daba `ab`
    /// suelto y `a` con un `(?<!x)` al lado, que no cambia lo que el patrón coincide: 14
    /// patrones de 30 000 en el fuzz del auditor. La condición de la ronda 5 miraba que hubiera
    /// un grupo adentro; la regla es más simple: esa repetición corre siempre en la VM.
    #[test]
    fn a_repetition_that_can_match_empty_matches_the_same_wherever_it_runs() {
        // la tabla del informe: el patrón, el texto y las coincidencias (la primera es la de
        // Perl, `re` y `regex` de Python y PCRE2; las que siguen llevan la regla de las
        // coincidencias vacías de esta familia, que es la de `regex_*`)
        for (pattern, text, expected) in [
            ("(?:a?|b)+", "ab", vec!["a", ""]),
            ("(?:a?|b)*", "ab", vec!["a", ""]),
            ("(?:a|b??)+", "ab", vec!["a", ""]),
            ("(?:a*|b)+", "ab", vec!["a", ""]),
            ("(?:a||b)*", "ab", vec!["a", ""]),
            ("c{2,}(?:a?|b??)+", "ccab", vec!["cca"]),
            (r"(?:\s*|,)*", " , ,", vec![" ", " ", ""]),
            // los dos motores ya daban lo mismo en estos; ahora corren en uno solo
            ("(?:b?)*", "bb", vec!["bb"]),
            ("(?:a??|b)+", "ab", vec!["", "", ""]),
            ("x(?:a?|b)*y", "xaby", vec!["xaby"]),
        ] {
            assert_eq!(all(text, pattern), expected, "{}", pattern);
            // con algo al lado que no cambia lo que el patrón coincide: adelante, atrás, y el
            // look-ahead del final que el optimizador saca
            for around in [format!("(?<!x)(?:{})", pattern), format!("(?:{})(?<!x)", pattern), format!("(?:{})(?=)", pattern)] {
                assert_eq!(all(text, &around), expected, "{}", around);
            }
            // corre en la VM: tiene instrucciones
            assert!(compiled(pattern, false).unwrap().program_len() > 0, "{}", pattern);
        }
        // el grupo de afuera se mueve con la coincidencia
        for pattern in ["((?:a?|b)*)", "((?:a?|b)*)(?<!x)", "(?<!x)((?:a?|b)*)", "((?:a?|b)*)(?=)"] {
            assert_eq!(groups("ab", pattern), some(&["a"]), "{}", pattern);
        }
        // gasta pasos también sin nada más de la familia, y es la forma que retrocede
        assert_eq!(find_all("b", "(?:b?)*", 1), Err(Failure::StepLimit));
        assert_eq!(find_all(&"a".repeat(30), "(?:a*)*b", DEFAULT), Err(Failure::StepLimit));
        assert_eq!(all("aaab", "(?:a*)*b"), ["aaab"]);
        // Lo que sigue yendo entero al motor lineal: la contada (aunque su cuerpo prefiera el
        // vacío) y la que siempre lee. Con algo al lado, lo mismo.
        for (pattern, text, expected) in [
            ("(?:a?|b){0,3}", "ab", vec!["a", ""]),
            ("(?:a?|b){2}", "ab", vec!["a", ""]),
            ("(?:a|b)*", "ab", vec!["ab"]),
            (r"\w+(?:-\w*)*", "ab-cd-", vec!["ab-cd-"]),
        ] {
            assert_eq!(all(text, pattern), expected, "{}", pattern);
            assert_eq!(compiled(pattern, false).unwrap().program_len(), 0, "{}", pattern);
            assert_eq!(find_all(text, pattern, 1).map(|v| v.len()), Ok(expected.len()), "{}", pattern);
            assert_eq!(all(text, &format!("(?:{})(?<!x)", pattern)), expected, "{}", pattern);
        }
    }

    /// Ronda 6, propio (lo encontró el fuzz del auditor con más semillas, después de arreglar
    /// M-1): una alternancia cuyas ramas empiezan igual coincidía distinto según el motor que la
    /// corría. `regex-syntax` saca factor común de lo que todas las ramas tienen al principio
    /// (`x*a|x*b` pasa a ser `x*(?:a|b)`), sea lo que sea; cuando ese comienzo puede terminar en
    /// más de un lugar, la forma factorizada prueba las maneras en otro orden. `a?a|a?b` sobre
    /// `ab` es `a` como está escrito (la primera rama, con su `a?` vacío): es lo que dan Perl,
    /// `re` y `regex` de Python y la VM. Factorizado es `ab`, que es lo que daba suelto. RE2
    /// factoriza sólo un comienzo de largo fijo, por esto mismo.
    ///
    /// La regla es la de M-1: lo que el motor lineal leería distinto corre siempre en la VM. Qué
    /// alternancias son no se deduce de la forma del patrón: el fork arma lo que el motor lineal
    /// recibiría y mira qué devolvió `regex-syntax` (`analyze_for_linear`, en `analyze.rs`; lo
    /// que mira, `reordered`, en `to_hir.rs`). Las rondas 6 y 7 lo deducían, con una copia de
    /// las reglas de `regex-syntax`, y tres veces seguidas apareció un caso que la copia no
    /// tenía: la cuenta de algo que sólo coincide vacío (ronda 7), el `{0}` de algo sin tope
    /// (ronda 8) y lo que queda de un `{0}` cuando el patrón va entero al motor lineal (propio,
    /// al arreglar la ronda 8). Están los tres en la primera tabla.
    ///
    /// Como ahora se mira lo que se arma, dejó de marcar de más: una alternancia que
    /// `regex-syntax` no factoriza, o cuyo comienzo común termina en un solo lugar, va al motor
    /// lineal aunque sus ramas sean concatenaciones de largo variable (la segunda tabla).
    #[test]
    fn an_alternation_that_the_linear_engine_would_factor_matches_the_same_wherever_it_runs() {
        let variants = |pattern: &str| {
            [format!("(?<!@)(?:{})", pattern), format!("(?:{})(?<!@)", pattern), format!("(?:{})(?=)", pattern)]
        };
        for (pattern, text, expected) in [
            ("a?a|a?b", "ab", vec!["a", "b"]),
            (r"b??\b|b??a?", "ab", vec!["", "b"]),
            (r"\s*\n|\s*x", " \nx", vec![" \n", "x"]),
            ("(b*(^)|(?:b*()))", "b", vec!["", ""]),
            (r"\d+\.\d+|\d+e\d+", "1.5 2e3", vec!["1.5", "2e3"]),
            (r"\w+a|\w+b", "xab", vec!["xa"]),
            // el comienzo común es más de una pieza, y la ambigua no es la primera
            ("ab+c|ab+d", "abbd", vec!["abbd"]),
            // una rama es otra alternancia, que `regex-syntax` factoriza primero (su comienzo
            // es de largo fijo) y deja como una concatenación
            ("k[xy](?:|c)z|(?:k[xy]|k[xy]c)", "kxcz", vec!["kxcz"]),
            // una rama es el cuerpo de un `{1}`, que `regex-syntax` desenvuelve
            ("(?:a?a){1}|(?:a?b){1}", "ab", vec!["a", "b"]),
            // lo mismo sin distinguir mayúsculas
            ("(?i:ab(?:|c)z|(?:ab|abc))", "ABCZ", vec!["ABCZ"]),
            // adentro de algo más
            ("x(?:a?a|a?b)y", "xaby", vec!["xaby"]),
            // el comienzo común es una cuenta fija de algo que termina en más de un lugar
            (r"(?:\wx*){2}a|(?:\wx*){2}b", "cxdxb", vec!["cxdxb"]),
            // Ronda 7, M-1: una rama es una cuenta (de al menos una vez) de algo que sólo
            // coincide vacío. `regex-syntax` la lleva a `{1}` y devuelve su cuerpo, que es una
            // concatenación: la alternancia de adentro se factoriza (`\b^(?:a|)`), queda con el
            // mismo comienzo que la otra rama de afuera, y la de afuera se factoriza también.
            // Suelta daba `["a"]`; Perl, `re` y `regex`, `aa`.
            (r"\b^(?:a|)aa|(?:\b^a|(?:\b^){2})", "aa", vec!["aa"]),
            ("^^(?:a|)aa|(?:^^a|(?:^^){2})", "aa", vec!["aa"]),
            ("^^(?:a|)aa|(?:^^a|(?:^^){1,3})", "aa", vec!["aa"]),
            ("^^(?:a|)aa|(?:^^a|(?:^^){3,7}?)", "aa", vec!["aa"]),
            (r"\B\B(?:a|)aa|(?:\B\Ba|(?:\B\B){2})", "caa", vec!["aa"]),
            // y la cuenta de una cuenta
            ("^^(?:a|)aa|(?:^^a|(?:(?:^^){2}){3})", "aa", vec!["aa"]),
            // Ronda 8, M-1: lo que sólo coincide vacío es un `{0}` de algo sin tope. El análisis
            // le daba tamaño máximo sin tope y `regex-syntax` lo deja en nada, así que la regla
            // de la ronda 7 (que copiaba la cuenta de `regex-syntax` con el tamaño del análisis)
            // no las veía. Sueltas daban `["a"]`.
            (r"\b^(?:a|(?:a*){0})aa|(?:\b^a|(?:\b^(?:a*){0}){2})", "aa", vec!["aa"]),
            ("^^(?:a*){0}(?:a|)aa|(?:^^(?:a*){0}a|(?:^^(?:a*){0}){2})", "aa", vec!["aa"]),
            ("(?:a*){0}(?:a*){0}(?:a|)aa|(?:(?:a*){0}(?:a*){0}a|(?:(?:a*){0}(?:a*){0}){2})", "aa", vec!["aa"]),
            ("(?:a*){0}(?:a*){0}(?:a|)aa|(?:(?:a*){0}(?:a*){0}a|(?:(?:a*){0}(?:a*){0}){1,3})", "aa", vec!["aa"]),
            ("(?:a*){0}(?:a*){0}(?:a|)aa|(?:(?:a*){0}(?:a*){0}a|(?:(?:a*){0}(?:a*){0}){3,7}?)", "caa", vec!["", "aa"]),
            ("(?:a*){0}(?:a*){0}(?:a|)aa|(?:(?:a*){0}(?:a*){0}a|(?:(?:(?:a*){0}(?:a*){0}){2}){3})", "aa", vec!["aa"]),
            (
                "(?:a{0,5}){0}(?:a{0,5}){0}(?:a|)aa|(?:(?:a{0,5}){0}(?:a{0,5}){0}a|(?:(?:a{0,5}){0}(?:a{0,5}){0}){2})",
                "aa",
                vec!["aa"],
            ),
            // Propio, al arreglar la ronda 8: cuando el patrón va entero al motor lineal, un
            // `{0}` no queda en nada (se guarda el lugar de sus grupos, y `(?:a?b?){0}` son dos
            // repeticiones vacías). Con eso las dos ramas vuelven a empezar igual, cosa que en
            // un tramo que entrega la VM no pasa: se pregunta de las dos maneras. Con cualquiera
            // de las tres reglas que se probaron para la ronda 8 daba `["x", "x"]` suelta.
            ("(?:a?b?){0}(?:x|)xx|(?:(?:a?b?){0}x|(?:a?b?){0})", "xx", vec!["xx"]),
            ("(?:a*b*){0}(?:x|)xx|(?:(?:a*b*){0}x|(?:a*b*){0})", "xx", vec!["xx"]),
            // y al revés: con los grupos en su lugar las ramas empiezan distinto, y en un tramo
            // de la VM (donde el `{0}` es nada) empiezan igual
            ("(x){0}a?a|(y){0}a?b", "ab", vec!["a", "b"]),
        ] {
            assert_eq!(all(text, pattern), expected, "{}", pattern);
            for around in variants(pattern) {
                assert_eq!(all(text, &around), expected, "{}", around);
            }
            // corre en la VM: tiene instrucciones
            assert!(compiled(pattern, false).unwrap().program_len() > 0, "{}", pattern);
        }
        // los grupos, lo mismo
        for pattern in ["(b*(^)|(?:b*()))", "(b*(^)|(?:b*()))(?<!@)"] {
            assert_eq!(groups("b", pattern), vec![Some(String::new()), Some(String::new()), None], "{}", pattern);
        }
        // Lo que va entero al motor lineal, porque `regex-syntax` lo deja en el orden en que
        // está escrito: no lo factoriza (una rama que no es una concatenación, o ramas que
        // empiezan distinto), lo junta en una clase, o le saca un comienzo que termina en un
        // solo lugar, que no cambia qué rama gana.
        for (pattern, text, expected) in [
            (r"\w+|\d+", "ab 12", vec!["ab", "12"]),
            ("foo|ba+r", "foo baar", vec!["foo", "baar"]),
            ("a+|b+c", "aa bbc", vec!["aa", "bbc"]),
            ("a?a|b", "ab", vec!["a", "b"]),
            ("(a+b)|(a+c)", "aac", vec!["aac"]),
            ("(a?a)|a?b", "ab", vec!["a", "b"]),
            ("[ab]c|[ab]d", "bd", vec!["bd"]),
            (r"\b(?:foo|bar)\b", "foo bar", vec!["foo", "bar"]),
            (r"\p{L}+|\d+x", "ab 12x", vec!["ab", "12x"]),
            // todas las ramas de un carácter: una clase, o un literal si es el mismo
            ("x|y", "xy", vec!["x", "y"]),
            ("a|a", "a", vec!["a"]),
            // Una cuenta que `regex-syntax` no devuelve como una concatenación (ronda 7): la que
            // puede ser cero veces (queda como `{0,1}`), la de una aserción sola (devuelve la
            // aserción) y la de algo que lee texto (sigue siendo una repetición).
            (r"\b^(?:a|)aa|(?:\b^a|(?:\b^){0,2})", "aa", vec!["aa"]),
            (r"\b^(?:a|)aa|(?:\b^a|(?:\b){2})", "aa", vec!["aa"]),
            ("(?:a?b){2}|a?c", "abb ac", vec!["abb", "ac"]),
            // Ramas que son concatenaciones de largo variable y empiezan distinto: no hay qué
            // factorizar. Hasta la ronda 8 corrían en la VM (la regla no miraba el comienzo).
            (r"foo\s+bar|baz\s+qux", "foo bar baz  qux", vec!["foo bar", "baz  qux"]),
            (r"\bfoo\b|\bbar\b", "foo bar", vec!["foo", "bar"]),
            (r"a?a|(?:\b^){1,3}", "ab", vec!["a"]),
            // El comienzo común termina en un solo lugar: un literal, una aserción, una clase
            // (aunque sus caracteres midan distinto en bytes), una alternancia de ramas del
            // mismo largo, una cuenta fija de eso, y una cuenta fija de una concatenación.
            ("ax*|ay*", "axx ayy", vec!["axx", "a"]),
            (r"\bx|\by+", "x yy", vec!["x", "yy"]),
            ("[aé]x*|[aé]y*", "éxx ayy", vec!["éxx", "a"]),
            ("(?:ab|cd)e|(?:ab|cd)f", "cdf", vec!["cdf"]),
            (r"\d{2}a|\d{2}b", "12b", vec!["12b"]),
            (r"\w{2}a|\w{2}b", "ñub", vec!["ñub"]),
            (r"(?:\wx){2}a*|(?:\wx){2}b", "ñxñxb", vec!["ñxñx"]),
            // Los controles de la ronda 8: un `{0}` que queda en nada de las dos maneras (su
            // cuerpo lee al menos una vez), la cuenta que puede ser cero veces, y sin
            // alternancia afuera.
            ("(?:a+){0}(?:a+){0}(?:a|)aa|(?:(?:a+){0}(?:a+){0}a|(?:(?:a+){0}(?:a+){0}){2})", "aa", vec!["aa"]),
            (
                r"(?:\w{2,}){0}(?:b*c){0}(?:a|)aa|(?:(?:\w{2,}){0}(?:b*c){0}a|(?:(?:\w{2,}){0}(?:b*c){0}){2})",
                "aa",
                vec!["aa"],
            ),
            ("(?:a*){0}(?:a*){0}(?:a|)aa|(?:(?:a*){0}(?:a*){0}a|(?:(?:a*){0}(?:a*){0}){0,2})", "aa", vec!["aa"]),
            ("(?:a*){0}(?:a*){0}(?:a|)(?:aa|)", "aa", vec!["a", "a"]),
            // con grupos en el `{0}`, las ramas empiezan distinto de las dos maneras
            ("(a?b?){0}(?:x|)xx|(?:(a?b?){0}x|(a?b?){0})", "xx", vec!["xx"]),
        ] {
            assert_eq!(all(text, pattern), expected, "{}", pattern);
            assert_eq!(compiled(pattern, false).unwrap().program_len(), 0, "{}", pattern);
            assert_eq!(find_all(text, pattern, 1).map(|v| v.len()), Ok(expected.len()), "{}", pattern);
            for around in variants(pattern) {
                assert_eq!(all(text, &around), expected, "{}", around);
            }
        }
        // los grupos de un `{0}` no participan, corra donde corra
        for pattern in ["(a?b?){0}(?:x|)xx|(?:(a?b?){0}x|(a?b?){0})", "(?:(a?b?){0}(?:x|)xx|(?:(a?b?){0}x|(a?b?){0}))(?<!@)"] {
            assert_eq!(groups("xx", pattern), vec![None, None, None], "{}", pattern);
        }
        for pattern in ["(x){0}a?a|(y){0}a?b", "(?:(x){0}a?a|(y){0}a?b)(?<!@)"] {
            assert_eq!(groups("ab", pattern), vec![None, None], "{}", pattern);
        }
        // Lo que define un bloque DEFINE no es parte de lo que el motor lineal recibe (el bloque
        // es nada donde está): sus alternancias se miran aparte, como lo que la VM compila
        // cuando se llama a la definición, y no mandan a la VM lo que rodea al bloque.
        assert_eq!(compiled("(?(DEFINE)(a?a|a?b))(c)", false).unwrap().program_len(), 0);
        assert_eq!(groups("c", "(?(DEFINE)(a?a|a?b))(c)"), vec![None, Some("c".to_string())]);
        // Llamada, la definición lee como está escrita. En la tercera la llamada es una rama
        // del patrón, y ahí el cuerpo de una definición sin nada difícil va entero al motor
        // lineal (con `ab|cd` son 11 instrucciones; con ésta, que se marca, 14).
        for pattern in [
            r"(?(DEFINE)(?<n>a?a|a?b))\g<n>",
            r"(?<!@)(?(DEFINE)(?<n>a?a|a?b))\g<n>",
            r"\g<n>|(?(DEFINE)(?<n>a?a|a?b))",
        ] {
            assert_eq!(all("ab", pattern), ["a", "b"], "{}", pattern);
        }
        assert!(
            compiled(r"\g<n>|(?(DEFINE)(?<n>ab|cd))", false).unwrap().program_len()
                < compiled(r"\g<n>|(?(DEFINE)(?<n>a?a|a?b))", false).unwrap().program_len()
        );
    }

    /// Ronda 8, propio (apareció al probar la regla nueva de la alternancia con bloques DEFINE):
    /// un grupo que sólo guarda su lugar, sin leer nada, no le cambia el número a ningún otro,
    /// corra donde corra el patrón. Son los grupos de un bloque DEFINE y los de un `{0}`. La
    /// crate tenía dos defectos, los dos sin arreglar en upstream:
    ///
    /// - Al traducir para el motor lineal, un bloque DEFINE era nada y sus grupos no se
    ///   contaban: todo grupo que venía después, en el mismo tramo o con el patrón entero,
    ///   quedaba con el número de un grupo del bloque. `(?(DEFINE)(?<d>\d))(a)\g<d>` sobre `a1`
    ///   daba `["1", nothing]` (la `a` se guardaba en el grupo 1 y la llamada la pisaba), y
    ///   `(?(DEFINE)(?<n>a)(?<m>b))(c)` sobre `c` daba `["c"]`: un grupo donde hay tres.
    /// - Con el grupo 0 explícito (lo arma el pase que saca un look-ahead del final), los grupos
    ///   que no participan se buscaban por el número que pide quien llama y no por el que tienen
    ///   en lo que recibió el motor lineal, que es uno más: `(x){0}(a)(?=b)` sobre `ab` daba
    ///   `["", nothing]`.
    ///
    /// Y al arreglar el primero apareció un tercero (lo encontró `gen13.py`, el generador de
    /// esta clase): dos tramos con el mismo texto comparten motor, y como un bloque DEFINE no
    /// escribía nada en ese texto, el tramo `(?(DEFINE)(q))(a)` usaba el motor del tramo `(a)`,
    /// que numera su grupo desde uno antes.
    ///
    /// El test arma todos los patrones de hasta tres piezas (grupos que leen, texto, algo de
    /// largo variable, grupos de un `{0}`, bloques DEFINE con uno y con tres grupos), y cada uno
    /// corre de las seis maneras en que un patrón llega a los motores. Lo que cada grupo guarda
    /// se sabe al armarlo.
    #[test]
    fn groups_that_only_hold_a_place_do_not_move_the_others() {
        // (patrón, lo que lee, lo que guarda cada uno de sus grupos)
        let pieces: [(&str, &str, &[Option<&str>]); 8] = [
            ("(a)", "a", &[Some("a")]),
            ("b", "b", &[]),
            // de largo variable: parte la concatenación en tramos cuando corre en la VM
            ("x*", "", &[]),
            ("((c)d)", "cd", &[Some("cd"), Some("c")]),
            ("(x){0}", "", &[None]),
            ("(?:(x)(y)){0}", "", &[None, None]),
            ("(?(DEFINE)(q))", "", &[None]),
            ("(?(DEFINE)((q)r)(s))", "", &[None, None, None]),
        ];
        let mut tried = 0;
        for length in 1..=3u32 {
            for mut n in 0..pieces.len().pow(length) {
                let (mut pattern, mut text, mut expected) = (String::new(), String::new(), Vec::new());
                for _ in 0..length {
                    let (p, t, g) = pieces[n % pieces.len()];
                    n /= pieces.len();
                    pattern.push_str(p);
                    text.push_str(t);
                    expected.extend(g.iter().map(|g| g.map(String::from)));
                }
                // sin ningún grupo, `capture` da la coincidencia entera
                if expected.is_empty() {
                    expected.push(Some(text.clone()));
                }
                // (cómo corre, si va entero al motor lineal)
                for (how, linear) in [
                    (pattern.clone(), true),
                    // el pase saca el look-ahead del final y el grupo 0 pasa a ser explícito
                    (format!("{}(?=)", pattern), true),
                    // la VM arriba, y los tramos sin nada difícil al motor lineal
                    (format!("(?<!@){}", pattern), false),
                    (format!("{}(?<!@)", pattern), false),
                    (format!("(?:{})(?<!@)", pattern), false),
                    (format!("(?<!@){}(?=)", pattern), false),
                ] {
                    assert_eq!(groups(&text, &how), expected, "{} sobre {:?}", how, text);
                    assert_eq!(compiled(&how, false).unwrap().program_len() == 0, linear, "{}", how);
                    tried += 1;
                }
            }
        }
        assert_eq!(tried, (8 + 64 + 512) * 6);
        // Dos tramos con el mismo texto comparten motor, y un bloque DEFINE no escribía nada:
        // el tramo del bloque y el último grupo leía con el motor del primer grupo, un número
        // antes. (Está entre los de arriba; acá queda a la vista.)
        assert_eq!(
            groups("aa", "(?:(a)x*(?(DEFINE)(q))(a))(?<!@)"),
            vec![Some("a".to_string()), None, Some("a".to_string())]
        );
        // un bloque solo sigue sin ser una instrucción
        assert_eq!(
            compiled("(?(DEFINE)(q))x*(?<!@)", false).unwrap().program_len(),
            compiled("x*(?<!@)", false).unwrap().program_len()
        );
        // Un bloque adentro de otra cosa: de un `{0}`, de un look-around, de una rama, de un
        // grupo, de una repetición, de un grupo atómico y de otro bloque.
        for (pattern, text, expected) in [
            ("(?:(?(DEFINE)(q))){0}(a)", "a", vec![None, Some("a")]),
            ("(?:(z)(?(DEFINE)(q))){0}(a)", "a", vec![None, None, Some("a")]),
            ("(a)(?:(x)|(?(DEFINE)(q))){0}(b)", "ab", vec![Some("a"), None, None, Some("b")]),
            ("(?=(?(DEFINE)(q))a)(a)(a)", "aa", vec![None, Some("a"), Some("a")]),
            ("(?!(?(DEFINE)(q))b)(a)(a)", "aa", vec![None, Some("a"), Some("a")]),
            ("(a)(?<=(?(DEFINE)(q))a)(b)", "ab", vec![Some("a"), None, Some("b")]),
            ("(?:(?(DEFINE)(q))a|b)(c)", "ac", vec![None, Some("c")]),
            ("(?:(?(DEFINE)(q))a|b)(c)", "bc", vec![None, Some("c")]),
            ("(?:a|(?(DEFINE)(q))b)(c)", "bc", vec![None, Some("c")]),
            ("((?(DEFINE)(q))a)(b)", "ab", vec![Some("a"), None, Some("b")]),
            ("(a)(?:(?(DEFINE)(q))|x)(b)", "ab", vec![Some("a"), None, Some("b")]),
            ("(?:(?(DEFINE)(q))(a))+(b)", "aab", vec![None, Some("a"), Some("b")]),
            ("(?:(a)(?(DEFINE)(q)))+(b)", "aab", vec![Some("a"), None, Some("b")]),
            ("(?>(?(DEFINE)(q))(a))(b)", "ab", vec![None, Some("a"), Some("b")]),
            ("(?(DEFINE)(?(DEFINE)(q))(r))(a)", "a", vec![None, None, Some("a")]),
            (r"(?(DEFINE)(?<d>\d))(a)(?:\g<d>|x)(b)", "a1b", vec![Some("1"), Some("a"), Some("b")]),
            (r"(a)(?:(?(DEFINE)(?<d>\d))\g<d>)(b)", "a1b", vec![Some("a"), Some("1"), Some("b")]),
        ] {
            let expected: Vec<Option<String>> = expected.into_iter().map(|g| g.map(String::from)).collect();
            for how in [
                pattern.to_string(),
                format!("(?<!@){}", pattern),
                format!("(?:{})(?<!@)", pattern),
                format!("{}(?=)", pattern),
            ] {
                assert_eq!(groups(text, &how), expected, "{} sobre {:?}", how, text);
            }
        }
        // Con llamadas: el grupo que se llama guarda lo que leyó la llamada, y los demás, lo suyo.
        for (pattern, text, expected) in [
            (r"(?(DEFINE)(?<d>\d))(a)\g<d>", "a1", vec![Some("1"), Some("a")]),
            (r"(a)(?(DEFINE)(?<d>\d))\g<d>", "a1", vec![Some("a"), Some("1")]),
            (r"x(?(DEFINE)(?<d>\d)(?<e>\w))(a)(\g<d>)", "xa1", vec![Some("1"), None, Some("a"), Some("1")]),
            (r"(?(DEFINE)(?<d>\d))(x){0}(a)(?:\g<d>)(b)(?=c)", "a1bc", vec![Some("1"), None, Some("a"), Some("b")]),
        ] {
            let expected: Vec<Option<String>> = expected.into_iter().map(|g| g.map(String::from)).collect();
            assert_eq!(groups(text, pattern), expected, "{}", pattern);
        }
        // y en un reemplazo, que lee los grupos de cada coincidencia
        assert_eq!(
            replace("a1 a2", r"(?(DEFINE)(?<d>\d))(a)\g<d>", r"[\1|\2]", DEFAULT),
            Ok(Some("[1|a] [2|a]".to_string()))
        );
        assert_eq!(replace("ab", "(x){0}(a)(?=b)", r"[\1|\2]", DEFAULT), Ok(Some("[|a]b".to_string())));
    }

    /// Rondas 9 y 10: un grupo de captura adentro de un look-behind positivo de largo variable
    /// es un error. Lo que ese grupo guarda no es una sola cosa. La crate lo compila de tres
    /// maneras según lo que tenga el cuerpo, y no dan lo mismo: con un cuerpo sin nada difícil
    /// toma el comienzo que da un DFA hacia atrás y llena los grupos con una búsqueda hacia
    /// adelante anclada sólo a ese comienzo (`(?<=(a|ab))c` sobre `abc` daba `a`, un grupo que
    /// termina antes de donde está el look-behind); con algo difícil prueba los comienzos del
    /// más cercano al más lejano (`(?<=(\d+));` sobre `12345;`: `12345` por un camino y `5` por
    /// el otro); y una alternancia arriba de todo la parte en un look-behind por rama. Los
    /// motores tampoco coinciden: Java toma el comienzo más cercano, V8 y .NET leen el cuerpo
    /// de derecha a izquierda.
    ///
    /// En la ronda 9 se llevó todo a la segunda manera, la de la VM, y la ronda 10 midió lo que
    /// cuesta: la VM corre el cuerpo hacia adelante, pasa de largo la posición y vuelve, y con
    /// un cuerpo que puede repartir el mismo texto de varias maneras eso es exponencial
    /// (`(?<=((?:\w+\s?)+))!` sobre una frase de 35 caracteres: 80 millones de pasos donde el
    /// camino del DFA gastaba 340, y con 29 caracteres ya era el error del tope). Y un grupo que
    /// escribe una llamada (`\g<g>`) desde adentro seguía dependiendo del camino. No hay una
    /// manera que sea la misma para todo cuerpo y que no cueste eso, así que no se elige una.
    ///
    /// Con un largo fijo hay un solo comienzo, un look-behind negativo no deja grupos, y uno sin
    /// grupos sólo dice si coincide: los tres siguen como estaban.
    #[test]
    fn a_capture_group_in_a_look_behind_of_variable_length_is_an_error() {
        const EXPECTED: &str = "Error compiling regex: A look-behind of variable length has a capture group or a \
                                subroutine call in it: use (?:...) if the group is only for grouping, capture outside \
                                the look-behind, or give the look-behind one fixed length";
        let opt = |groups: &[Option<&str>]| -> Vec<Option<String>> {
            groups.iter().map(|g| g.map(String::from)).collect()
        };
        for pattern in [
            // las filas del informe de la ronda 9
            "(?<=(a|ab))c",
            "(?<=(a|abc))d",
            "(?<=(ab??))c",
            r"(?<== (\d+|\d+\.\d+));",
            r"(?<=: (\d+?));",
            r"(?<=(\d+));",
            r"(?<=(\w+)-(\d+))",
            "(?<=(a*))b",
            // con nombre, con algo difícil al lado, y con una referencia adentro
            "(?<=(?<n>a+))b",
            r"(?<=(a|ab)|(?!)\1)c",
            r"(?<=(a+)\1)x",
            // una alternancia arriba de todo, también con ramas de largo fijo distinto
            "(?<=(ab)|(b))x",
            "(?<=(?:(ab)|(b)))x",
            "(?<=(a)|(bc))x",
            // el cuerpo ambiguo de la ronda 10, y un grupo vacío bajo una cuenta
            r"(?<=((?:\w+\s?)+))!",
            "(?<=c+(){2})",
            // una llamada adentro, que escribe el grupo que llama (ronda 10, M-2)
            r"(?(DEFINE)(?<g>\w))(?<=\g<g>\d+)!",
            r"(?(DEFINE)(?<g>.))(?<=\g<g>x+)y",
            // un bloque DEFINE adentro tiene sus grupos
            "(?<=(?(DEFINE)(q))a+)b",
            // adentro de una repetición, de un look-ahead y de un look-behind negativo
            "(?:(?<=(a+))b)+",
            "(?=(?<=(a+))b)b",
            "(?<!(?<=(a+))b)c",
        ] {
            assert_eq!(invalid(pattern), EXPECTED, "{}", pattern);
            assert_eq!(invalid_in_full(pattern), EXPECTED, "{}", pattern);
        }
        // las cuatro funciones
        let expected = || Failure::InvalidPattern(EXPECTED.to_string());
        assert_eq!(find_all("abc", "(?<=(a|ab))c", DEFAULT), Err(expected()));
        assert_eq!(capture("abc", "(?<=(a|ab))c", DEFAULT), Err(expected()));
        assert_eq!(replace("abc", "(?<=(a|ab))c", "x", DEFAULT), Err(expected()));
        assert_eq!(matches("abc", "(?<=(a|ab))c", DEFAULT), Err(expected()));

        // Lo que sigue como estaba. De largo fijo hay un solo comienzo, con grupos y con una
        // llamada:
        assert_eq!(groups("cde", "(?<=(ab|cd))e"), opt(&[Some("cd")]));
        assert_eq!(groups("abc", "(?<=(a)(b))c"), opt(&[Some("a"), Some("b")]));
        assert_eq!(groups("a!", r"(?(DEFINE)(?<g>\w))(?<=\g<g>)!"), opt(&[Some("a")]));
        // uno negativo no deja grupos:
        assert_eq!(groups("cb ab", "(?<!(a+))b"), opt(&[None]));
        assert_eq!(groups("a1! !", r"(?(DEFINE)(?<g>\w))(?<!\g<g>\d+)!"), opt(&[None]));
        // y sin grupos sólo dice si coincide:
        assert_eq!(all("ab aab b cb", "(?<=a+)b"), ["b", "b"]);
        assert_eq!(all("bcx ax x", "(?<=a|bc)x"), ["x", "x"]);

        // Lo que el mensaje propone. `(?:…)` cuando el paréntesis sólo agrupa:
        assert_eq!(all("abc", "(?<=(?:a|ab))c"), ["c"]);
        // y capturar afuera, con `\K`:
        assert_eq!(groups("abc", r"(a|ab)\Kc"), opt(&[Some("ab")]));
        assert_eq!(groups("id: 12345;", r"(\d+)\K;"), opt(&[Some("12345")]));
        // El cuerpo ambiguo de la ronda 10, sin el grupo, no cuesta: 307 pasos, y con el grupo
        // afuera lee la frase entera.
        let phrase = "hola mundo esto es una frase larga!";
        assert_eq!(find_all(phrase, r"(?<=(?:\w+\s?)+)!", 1_000).map(|v| v.len()), Ok(1));
        assert_eq!(groups(phrase, r"((?:\w+\s?)+)\K!"), opt(&[Some("hola mundo esto es una frase larga")]));

        // Ronda 10, N-3: al buscar los comienzos de un look-behind que corre en la VM, un grupo
        // vacío bajo una cuenta no escribía nada y la cuenta quedaba pegada a lo de antes (para
        // `c+(){2,}?`, `c+{2,}`: los comienzos de `(?:c+){2,}`). En uno negativo eso es una
        // coincidencia de más: `(?<!c+(){2,}?)x` coincidía con la `x` de `cx`, que tiene una `c`
        // atrás. Ahora se escribe `(?:)` donde no había nada.
        assert_eq!(all("cx", r"(?<!c+(){2,}?)x"), Vec::<String>::new());
        assert_eq!(all("cx", r"c(?<!c+(){2,}?)"), Vec::<String>::new());
        assert_eq!(all("x", r"(?<!c+(){2,}?)x"), ["x"]);
    }

    /// Ronda 10, B-1: una condición con las dos ramas vacías sigue siendo un si-entonces-si-no,
    /// y coincide diga lo que diga la condición. La crate devolvía la condición sola, que es lo
    /// que significa acá `(?(1))` sin ramas (seguir sólo si el grupo participó): `(?(1)|)`
    /// fallaba cuando el grupo 1 no había participado. En Perl y en `re` de Python coincide.
    #[test]
    fn a_conditional_with_two_empty_branches_matches_whatever_the_condition_says() {
        for pattern in ["(?:|(a))(?(1)|)b", "(?:|(a))(?(1)(?:)|(?:))b", "(?:|(?<n>a))(?(<n>)|)b"] {
            assert_eq!(all("b", pattern), ["b"], "{}", pattern);
            assert_eq!(all("ab", pattern), ["ab"], "{}", pattern);
        }
        // sin ramas es otra cosa: seguir sólo si el grupo participó
        assert_eq!(all("b", "(a)?(?(1))b"), Vec::<String>::new());
        assert_eq!(all("ab", "(a)?(?(1))b"), ["ab"]);
        // y con una rama escrita, lo de siempre
        assert_eq!(all("ax y", "(a)?(?(1)x|y)"), ["ax", "y"]);
        assert_eq!(all("a y", "(a)?(?(1)|y)"), ["a", "y"]);
    }

    /// Ronda 6, M-2: una cuenta con el mínimo mayor que el máximo es un error. La crate la
    /// aceptaba y cada parte la leía a su modo: el motor lineal como `{n}`, la VM como `{m}`, y
    /// el DFA de un look-behind no compilaba, así que `a{3,2}` sobre `aaa` daba `aaa` suelto y
    /// `aa` con un `(?<!x)` al lado. El análisis le daba el tamaño de la cuenta mayor, y la VM
    /// daba vueltas vacías sobre `(a{1,0})*` sin el chequeo que las corta, hasta el tope. PCRE2,
    /// `re` y las `regex_*` la rechazan; Perl la acepta y no coincide nunca.
    #[test]
    fn a_count_with_its_minimum_over_its_maximum_is_an_error() {
        for (pattern, at) in [
            ("a{3,2}", 1),
            ("a{1,0}", 1),
            ("(a){3,2}b", 3),
            ("(a{1,0})*", 2),
            ("(?:a{1,0})*(?<!x)", 4),
            // no el error del DFA del look-behind, ni el del techo del compilado
            ("(?<=a{3,2})b", 5),
            ("a{4294967295,0}", 1),
            // con su modificador, en modo verboso, y sobre lo que no es una letra
            ("a{3,2}?", 1),
            ("a{3,2}+", 1),
            ("(?x)a { 3 , 2 }", 6),
            ("[ab]{2,1}c", 4),
            (r"\b{3,2}", 2),
        ] {
            let expected =
                format!("Parsing error at position {}: Repetition count has its minimum greater than its maximum", at);
            assert_eq!(invalid(pattern), expected, "{}", pattern);
            assert_eq!(invalid_in_full(pattern), expected, "{}", pattern);
        }
        // las cuatro funciones
        let expected = || Failure::InvalidPattern(invalid("a{3,2}"));
        assert_eq!(find_all("aaa", "a{3,2}", DEFAULT), Err(expected()));
        assert_eq!(capture("aaa", "a{3,2}", DEFAULT), Err(expected()));
        assert_eq!(replace("aaa", "a{3,2}", "x", DEFAULT), Err(expected()));
        assert_eq!(matches("aaa", "a{3,2}", DEFAULT), Err(expected()));
        // después de otro cuantificador sigue siendo el error de siempre, y una cuenta que no
        // entra en 32 bits es el suyo
        assert_eq!(invalid("a{2}{3,2}"), "Parsing error at position 4: Target of repeat operator is invalid");
        assert_eq!(
            invalid("a{4294967296,0}"),
            "Parsing error at position 2: Repetition count is too large (the largest is 4294967295)"
        );
        // en orden, o iguales, es la cuenta
        assert_eq!(all("aaaa", "a{2,3}"), ["aaa"]);
        assert_eq!(all("aaa", "a{2,2}"), ["aa"]);
        assert_eq!(all("a", "a{0,0}"), ["", ""]);
        // y una llave sin nada adelante, o sin cerrar, sigue siendo texto
        assert_eq!(all("{3,2}", "{3,2}"), ["{3,2}"]);
        assert_eq!(all("{3,2}", "a|{3,2}"), ["{3,2}"]);
        assert_eq!(all("a{3,2", "a{3,2"), ["a{3,2"]);
    }

    /// Ronda 6, N-2: un comentario `(?#…)` adentro de la llave de una cuenta no se saltea. La
    /// crate lo salteaba, y `a{(?#c)2}` era la cuenta `a{2}`; para Perl, PCRE2, `re` y `regex`
    /// de Python una llave con un comentario adentro no es una cuenta, y el texto es `a{2}`. El
    /// comentario entre la letra y la llave sigue siendo transparente, y el modo verboso no
    /// cambia (sus espacios y sus comentarios `#` se saltean adentro de la llave, como antes).
    #[test]
    fn a_comment_inside_the_braces_of_a_count_is_not_skipped() {
        for (pattern, text) in [
            ("a{(?#c)2}", "a{2}"),
            ("a{2(?#c)}", "a{2}"),
            ("a{2(?#c),3}", "a{2,3}"),
            ("a{2,(?#c)3}", "a{2,3}"),
            ("a{2,3(?#c)}", "a{2,3}"),
        ] {
            assert_eq!(all(text, pattern), [text], "{}", pattern);
            assert_eq!(all("aaa", pattern), Vec::<String>::new(), "{}", pattern);
        }
        // después de un cuantificador, lo mismo: es texto, no un cuantificador sobre otro
        assert_eq!(all("aa{3}", "a{2}{(?#c)3}"), ["aa{3}"]);
        // el comentario entre la letra y la llave, y el modo verboso
        assert_eq!(all("aa", "a(?#c){2}"), ["aa"]);
        assert_eq!(all("aa", "(?x)a{ 2 }"), ["aa"]);
        assert_eq!(all("aaa", "(?x)a { 2 , 3 }"), ["aaa"]);
        assert_eq!(all("aa", "(?x)a{2 # dos\n}"), ["aa"]);
    }

    /// Ronda 5, B-3: un cuantificador no lleva otro encima. La crate terminaba la pieza en el
    /// primer cuantificador, y una llave contada que venía después empezaba otra pieza, como
    /// texto: `a{2}{3}` coincidía con `aa{3}` y no con `aaaaaa`, sin error (y `a**` y `a{2}*`
    /// sí eran error). Las `regex_*` lo leen como repetición de la repetición; Perl («Nested
    /// quantifiers») y `re` («multiple repeat») lo rechazan, y acá es el error que ya daba `a**`.
    #[test]
    fn a_quantifier_on_a_quantifier_is_an_error() {
        for (pattern, at) in [
            ("a{2}{3}", 4),
            ("a*{2}", 2),
            ("a+{2}", 2),
            ("a?{2}", 2),
            ("a{2,}{0,}", 5),
            ("a{2}{,3}", 4),
            ("a{2}{4294967296}", 4),
            ("a+?{2}", 3),
            ("a++{2}", 3),
            ("(?=a)a{2}{3}", 9),
            // con un comentario o, en modo verboso, un espacio en el medio
            ("a{2}(?#c){3}", 9),
            ("(?x)a{2} {3}", 9),
            // y lo mismo después del `?` o del `+` del primero
            ("a+?(?#c){2}", 8),
            ("(?x)a++ {2}", 8),
            // los que ya eran error
            ("a**", 2),
            ("a{2}*", 4),
            ("a+??", 3),
            // el `+` después de un `?` perezoso: la crate lo leía como perezoso y posesivo a la vez
            ("a+?+", 3),
            ("a{2}?+", 5),
            // con `(?U)` también: lo que cuenta es el `?` escrito, no la preferencia que queda
            // (ronda 6, N-1)
            ("(?U)a+?+", 7),
        ] {
            let expected = format!("Parsing error at position {}: Target of repeat operator is invalid", at);
            assert_eq!(invalid(pattern), expected, "{}", pattern);
            assert_eq!(invalid_in_full(pattern), expected, "{}", pattern);
        }
        // agrupada, es la repetición de la repetición
        assert_eq!(all("aaaaaa", "(?:a{2}){3}"), ["aaaaaa"]);
        assert_eq!(all("aa{3}", "(?:a{2}){3}"), Vec::<String>::new());
        // un modificador solo: perezoso o posesivo
        assert_eq!(all("aaa", "a{2}?"), ["aa"]);
        assert_eq!(all("aaa", "a{2}+a"), ["aaa"]);
        assert_eq!(all("aaa", "a+?"), ["a", "a", "a"]);
        assert_eq!(all("aaa", "a?+a"), ["aa"]);
        // una llave que no es una cuenta sigue siendo texto, después de un cuantificador también
        assert_eq!(all("aa{x}", "a{2}{x}"), ["aa{x}"]);
        assert_eq!(all("aa{3", "a{2}{3"), ["aa{3"]);
        assert_eq!(all("aa{", "a+{"), ["aa{"]);
        assert_eq!(all("{2}a", "{2}a"), ["{2}a"]);
        assert_eq!(all("{2}", "a|{2}"), ["{2}"]);
        assert_eq!(all(r"aa{3}", r"a{2}\{3}"), ["aa{3}"]);
        // En modo verboso, el `+` y el `?` separados por un espacio siguen siendo el modificador
        // (como en Perl): `a+ +a` es `a++a`.
        assert_eq!(all("aaa", "(?x)a+ +a"), Vec::<String>::new());
        assert_eq!(all("aaa", "(?x)a+ ?"), ["a", "a", "a"]);
    }

    /// Ronda 6, B-2: con `(?U)` (que da vuelta golosos y perezosos) una repetición posesiva
    /// sigue siendo golosa, como en PCRE2, cuyo manual dice que un posesivo es siempre goloso. La
    /// crate la daba vuelta como a las demás y después la hacía atómica: tomaba lo mínimo y no lo
    /// devolvía, así que `(?U)a++` sobre `aaa` daba tres `a` y `(?U)a*+` no leía nunca nada. La
    /// tabla es la de PCRE2 (`grep -P`, que no muestra las coincidencias vacías).
    #[test]
    fn a_possessive_repetition_is_greedy_with_the_u_flag() {
        for (pattern, expected) in [
            ("(?U)a++", vec!["aaa"]),
            ("(?U)a*+", vec!["aaa"]),
            ("(?U)a?+", vec!["a", "a", "a"]),
            ("(?U)a{2,}+", vec!["aaa"]),
            ("(?U)(?:a|b)++", vec!["aaa"]),
            // sin el `+`, `(?U)` da vuelta la preferencia, como siempre
            ("(?U)a+", vec!["a", "a", "a"]),
            ("(?U)a+?", vec!["aaa"]),
            // y sin `(?U)` no cambia nada
            ("a++", vec!["aaa"]),
            ("a+?", vec!["a", "a", "a"]),
        ] {
            assert_eq!(all("aaa", pattern), expected, "{}", pattern);
            // corra donde corra
            assert_eq!(all("aaa", &format!("(?:{})(?<!x)", pattern)), expected, "{}", pattern);
        }
        // posesivo de verdad: no devuelve lo que tomó
        assert_eq!(all("aaa", "(?U)a++a"), Vec::<String>::new());
        assert_eq!(all("aaa", "(?U)a{2}+a"), ["aaa"]);
        // `(?-U)` vuelve a lo de siempre
        assert_eq!(all("aaa", "(?U)(?-U)a+"), ["aaa"]);
    }

    /// Ronda 5, B-2: un nombre de grupo en más de un grupo es un error. La crate los acepta y
    /// `\k<n>` lee sólo el último: en `(?:(?<n>a)|(?<n>b))\k<n>` la referencia no coincidía con
    /// `aa`, sin error (Perl y `regex` de Python coinciden; `re` y las `regex_*` rechazan el
    /// patrón).
    #[test]
    fn a_group_name_on_two_groups_is_rejected() {
        let expected = "the group name 'n' is on more than one group, and backtrack_* take one group per name (regex \
                        engines disagree on what \\k<n> reads otherwise); give each group its own name";
        assert_eq!(repeated_name("n"), expected);
        for pattern in [
            r"(?:(?<n>a)|(?<n>b))\k<n>",
            r"(?<n>a)(?<n>b)",
            r"(?P<n>a)|(?'n'b)",
            r"(?<m>x)(?<n>a)(?=(?<n>b))",
            r"(?<n>a)(?(<n>)b|c)(?<n>d)",
        ] {
            assert_eq!(invalid(pattern), expected, "{}", pattern);
            assert_eq!(invalid_in_full(pattern), expected, "{}", pattern);
        }
        assert_eq!(matches("aa", r"(?:(?<n>a)|(?<n>b))\k<n>", DEFAULT), Err(Failure::InvalidPattern(expected.to_string())));
        // el primero que se repite es el que nombra
        assert_eq!(invalid(r"(?<a>x)(?<b>y)(?<b>z)(?<a>w)"), repeated_name("b"));
        // un nombre por grupo
        assert_eq!(all("aa", r"(?<n>a)\k<n>"), ["aa"]);
        assert_eq!(all("ab", r"(?<n>a)(?<m>b)(?<!x)"), ["ab"]);
        assert_eq!(groups("ab", r"(?<n>a)(?P<m>b)(?'o'c)?"), vec![Some("a".to_string()), Some("b".to_string()), None]);
    }
}
