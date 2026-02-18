#![cfg_attr(not(feature = "bin"), allow(dead_code))]

mod audit;
// mod cli;
mod mutations;
pub(crate) mod task;
mod runner;
pub(crate) mod capsule;
pub(crate) mod policy;
pub(crate) mod runtime;
mod tick_core;
mod route;
mod context;
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
pub mod skills;
pub mod state_delta_artifact;
pub mod tools;
pub mod command;

#[cfg(feature = "bin")]
pub mod cli;

#[cfg(feature = "bin")]
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    cli::run()
}