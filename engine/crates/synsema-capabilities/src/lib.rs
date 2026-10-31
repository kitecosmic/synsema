//! Synsema capabilities. Espeja `synsema/capabilities/`.
//! Capa 5 del port: model (Capability/CapabilitySet), intent (IntentEnforcer).
//! Falta el enforcement program-level (enforcer, builtins seguros) — se conecta
//! al intérprete coordinando el corpus program-level.

pub mod intent;
/// v0.6.52: las carpetas que un hijo aislado pudo escribir (sus links no se siguen).
pub mod isolated_areas;
pub mod model;
/// v0.6.46 (E8): abrir sin ventana entre el chequeo y la apertura.
pub mod nofollow;
pub mod secure;
