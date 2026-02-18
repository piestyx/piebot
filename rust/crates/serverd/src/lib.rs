#![cfg_attr(not(feature = "bin"), allow(dead_code))]

mod audit;
// mod cli;
pub(crate) mod capsule;
mod context;
mod mutations;
mod operator_actions;
pub(crate) mod policy;
mod route;
mod runner;
pub(crate) mod runtime;
pub(crate) mod task;
mod tick_core;
// pub use crate::cli::run;
pub use crate::policy::context_policy::{load_context_policy, CONTEXT_POLICY_SCHEMA};
pub mod lenses;
pub mod memory;
pub mod memory_lattice;
pub mod modes;
pub mod output_contract;
pub mod prompt;
pub mod provider;
pub mod redaction;
mod ref_utils;
pub mod retrieval;
mod router;
pub use crate::capsule::run_capsule::RUN_CAPSULE_SCHEMA;
pub use crate::runtime::explain::EXPLAIN_SCHEMA;
pub mod command;
pub mod skills;
pub mod state_delta_artifact;
pub mod tools;

#[cfg(feature = "bin")]
pub mod cli;

#[cfg(feature = "bin")]
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    cli::run()
}
