#[cfg(all(feature = "backend-hudsucker", feature = "backend-rama"))]
compile_error!("features `backend-hudsucker` and `backend-rama` are mutually exclusive");

#[cfg(not(any(feature = "backend-hudsucker", feature = "backend-rama")))]
compile_error!("select one proxy backend: `backend-hudsucker` or `backend-rama`");

pub mod ca;
pub mod cli;
pub use baffle_client as client;
pub mod config;
pub mod control;
pub mod daemon;
mod policy;
pub mod proxy_runtime;
mod secrets;
pub mod telemetry;
