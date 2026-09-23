//! El SUJETO de una unidad de trabajo (T1 del spec de identidad): en nombre de quién corre,
//! con qué techo delegado y con qué presupuestos. Es lo que viaja de la request a todo lo
//! que la request crea — agentes spawneados, workers de `parallel_map`, programas hijos —
//! junto con el techo del host: "la identidad viaja con el techo" (§10.2 del spec).
//!
//! Cuatro campos, cuatro dueños de la verdad:
//! - `identity`: quién pidió (`identity_of` sobre lo que devolvió `auth with`; `cron:<job>`
//!   para un tick de cron; `SYNSEMA_IDENTITY` para `run`). La consume el ledger de `spend`,
//!   el techo LLM por identidad y el rate limit por identidad.
//! - `spend_limits`: el caveat `spend` del captoken (techo de gasto delegado, T6.4).
//! - `llm_tokens`: el caveat `llm_tokens` del captoken (presupuesto LLM delegado).
//! - `delegations`: el techo delegado — los `caps` del captoken (y su `deterministic`) más
//!   los `sandbox under` vigentes. Se apilan sobre el techo del host en el `CapabilitySet`.
//!
//! Es `Send` a propósito (un `Delegation` es owned): cruza al hilo del agente o del worker
//! y se `apply`-ca allá sobre el intérprete y el set locales.

use std::cell::RefCell;
use std::rc::Rc;

use synsema_capabilities::model::{CapabilitySet, Delegation};
use synsema_core::interpreter::Interpreter;
use synsema_core::types::SynValue;

use synsema_stdlib::routing::{delegated_llm_tokens_of, delegated_spend_of, delegation_of, identity_of};

use crate::llm_providers::{current_delegated_llm_budget, delegation_scope, LlmIdentityScope};

#[derive(Clone, Debug, Default)]
pub struct Subject {
    pub identity: Option<String>,
    pub spend_limits: Vec<(String, String)>,
    pub llm_tokens: Option<u64>,
    pub delegations: Vec<Delegation>,
}

impl Subject {
    /// El sujeto de una request, desde lo que devolvió `auth with` (`request.user`). Sin
    /// auth → anónimo: sin identidad, sin techo delegado, sin presupuestos delegados.
    pub fn of_user(user: Option<&SynValue>) -> Subject {
        match user {
            Some(u) => Subject {
                identity: identity_of(u),
                spend_limits: delegated_spend_of(u),
                llm_tokens: delegated_llm_tokens_of(u),
                delegations: delegation_of(u).into_iter().collect(),
            },
            None => Subject::default(),
        }
    }

    /// El sujeto sintético de un tick de cron: `cron:<job>`. Un tick nunca corre "sin
    /// nadie": el ledger y el audit dicen qué job gastó.
    pub fn cron(job: &str) -> Subject {
        Subject { identity: Some(format!("cron:{}", job)), ..Subject::default() }
    }

    /// El sujeto de `run`: el operador. Con `SYNSEMA_IDENTITY` puesto, ése es el nombre
    /// (el ledger de `spend` y el techo LLM por identidad lo usan); sin él, anónimo.
    pub fn operator() -> Subject {
        // Un hijo de `run_program`: el sujeto que el padre fijó (protocolo interno).
        if let Ok(s) = std::env::var(crate::run_program::RUN_SUBJECT_VAR) {
            if let Some(subject) = Subject::from_env_json(&s) {
                return subject;
            }
        }
        // `SYNSEMA_IDENTITY` es un knob del host: environ o `.env` (misma precedencia que el
        // resto de los knobs; antes sólo se leía del environ y el `.env.example` lo ofrecía).
        let store = synsema_stdlib::secrets::EnvStore::load_default();
        let identity = crate::llm_providers::resolve_knob("SYNSEMA_IDENTITY", &store)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        Subject { identity, ..Subject::default() }
    }

    /// El sujeto como JSON para el protocolo padre → hijo de `run_program` (sin los techos
    /// delegados: ésos viajan como `--cap-set`).
    pub fn to_env_json(&self) -> String {
        let limits: Vec<serde_json::Value> = self
            .spend_limits
            .iter()
            .map(|(u, a)| serde_json::json!([u, a]))
            .collect();
        serde_json::json!({
            "identity": self.identity,
            "spend_limits": limits,
            "llm_tokens": self.llm_tokens,
        })
        .to_string()
    }

    pub fn from_env_json(s: &str) -> Option<Subject> {
        let v: serde_json::Value = serde_json::from_str(s).ok()?;
        let identity = v.get("identity").and_then(|x| x.as_str()).map(str::to_string);
        let spend_limits = v
            .get("spend_limits")
            .and_then(|x| x.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|p| Some((p.get(0)?.as_str()?.to_string(), p.get(1)?.as_str()?.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        let llm_tokens = v.get("llm_tokens").and_then(|x| x.as_u64());
        Some(Subject { identity, spend_limits, llm_tokens, delegations: Vec::new() })
    }

    /// Captura el sujeto VIGENTE de una unidad de trabajo (para propagarlo a lo que crea):
    /// identidad y techo de gasto del intérprete, techos delegados del set, presupuesto LLM
    /// delegado del hilo.
    pub fn capture(interp: &Interpreter, caps: &Rc<RefCell<CapabilitySet>>) -> Subject {
        Subject {
            identity: interp.request_identity().map(str::to_string),
            spend_limits: interp.request_spend_limits().to_vec(),
            llm_tokens: current_delegated_llm_budget(),
            delegations: caps.borrow().delegations(),
        }
    }

    /// Fija este sujeto sobre un intérprete y su set: identidad + techo de gasto en el
    /// intérprete, techos delegados en el set (reemplazando los que hubiera: es el sujeto
    /// entero de la unidad, no un incremento), y el scope LLM (identidad + presupuesto
    /// delegado) del hilo. El guard devuelto limpia el scope LLM al soltarse; la identidad y
    /// los techos los limpia `reset_for_request` / `reset_keeping_ceiling` (serve) o mueren
    /// con el intérprete (agente, worker).
    pub fn apply(&self, interp: &mut Interpreter, caps: &Rc<RefCell<CapabilitySet>>) -> LlmIdentityScope {
        let scope = delegation_scope(self.identity.clone(), self.llm_tokens);
        interp.set_request_identity(self.identity.clone(), self.spend_limits.clone());
        caps.borrow_mut().set_delegations(self.delegations.clone());
        scope
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_child_subject_round_trips_through_the_env_protocol() {
        let s = Subject {
            identity: Some("agent-7".to_string()),
            spend_limits: vec![("USD".to_string(), "0.5".to_string()), ("ETH".to_string(), "0.01".to_string())],
            llm_tokens: Some(1000),
            delegations: Vec::new(),
        };
        let back = Subject::from_env_json(&s.to_env_json()).expect("json");
        assert_eq!(back.identity.as_deref(), Some("agent-7"));
        assert_eq!(back.spend_limits, s.spend_limits);
        assert_eq!(back.llm_tokens, Some(1000));
        // Anónimo: identidad ausente, no un texto vacío.
        let anon = Subject::from_env_json(&Subject::default().to_env_json()).expect("json");
        assert!(anon.identity.is_none() && anon.spend_limits.is_empty() && anon.llm_tokens.is_none());
        // Basura en la variable: no se inventa un sujeto.
        assert!(Subject::from_env_json("not json").is_none());
    }
}
