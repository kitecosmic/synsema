//! Synsema capabilities. Espeja `synsema/capabilities/`.
//! Capa 5 del port: model (Capability/CapabilitySet), intent (IntentEnforcer).
//! Falta el enforcement program-level (enforcer, builtins seguros) — se conecta
//! al intérprete coordinando el corpus program-level.

pub mod intent;
pub mod model;
pub mod secure;
