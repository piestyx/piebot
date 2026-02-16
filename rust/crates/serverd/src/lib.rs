pub mod memory;
pub mod memory_lattice;

#[cfg(feature = "bin")]
pub mod cli;

#[cfg(feature = "bin")]
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    cli::run()
}