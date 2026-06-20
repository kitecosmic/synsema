//! Syntecnia agents. Espeja `syntecnia/agents/`.
//! Capa 7: blackboard, resource_lock, swarm, memory, progress, builtins.
//! `spawn` se porta con std::thread (paridad), no tokio (eso es feature posterior).
//!
//! Estado: blackboard HECHO. Pendiente (estaginado): progress, memory, swarm,
//! builtins (resource_lock no tiene test en el gate).

pub mod blackboard;
pub mod builtins;
pub mod memory;
pub mod progress;
pub mod resource_lock;
pub mod swarm;
