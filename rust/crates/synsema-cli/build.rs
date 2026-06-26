//! Hace que el binario reporte la versión del **release**, no el commit de main.
//!
//! `release.yml` setea `SYNSEMA_VERSION=<tag>` (p. ej. `v0.3.2`) al compilar el
//! binario oficial; el CLI lo lee con `option_env!`. `rerun-if-env-changed` fuerza
//! recompilar el CLI cuando ese valor cambia, así un `target` cacheado entre
//! releases no reusa una versión vieja.
fn main() {
    println!("cargo:rerun-if-env-changed=SYNSEMA_VERSION");
}
