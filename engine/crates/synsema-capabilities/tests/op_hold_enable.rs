//! v0.6.52 (ronda 4, A1): conceder `exec` enciende las tenencias de los builtins (`op_hold`), antes
//! de que corra nada: un hijo aislado sólo puede lanzarse con `exec`, y lo que otra tarea juzgó antes
//! de que preste su carpeta tiene que estar anotado. En su propio binario: el interruptor es del
//! proceso.

use synsema_capabilities::model::{Capability, CapabilitySet, CapabilityType};

#[test]
fn granting_exec_turns_holds_on() {
    let mut set = CapabilitySet::new("test");
    set.grant(Capability::new(CapabilityType::FileRead, Some("./data/**".to_string())));
    assert!(!synsema_core::op_hold::enabled(), "sin exec, apagado");
    // Ronda 5: un `exec` que el techo rechaza no entra, y no enciende nada.
    let mut boxed = CapabilitySet::new("test");
    boxed.ceiling = Some(std::rc::Rc::new(vec![Capability::new(CapabilityType::Stdout, None)]));
    boxed.grant(Capability::new(CapabilityType::Exec, Some("sh".to_string())));
    assert!(!synsema_core::op_hold::enabled(), "exec por encima del techo");
    set.grant(Capability::new(CapabilityType::Exec, Some("sh".to_string())));
    assert!(synsema_core::op_hold::enabled());
}
