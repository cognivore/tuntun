//! Port-trait adapters: the only place in the laptop binary where I/O
//! actually happens.

pub mod clock;
pub mod fs;
pub mod http;
pub mod process;
pub mod secret;
