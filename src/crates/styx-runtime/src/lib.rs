//! OS and transport adapters; composition belongs in the styx binary.
/// This describes the implementation stage, never runtime readiness.
pub const IMPLEMENTATION_STAGE: &str = "foundation; not a deployed Host or Gateway";

pub mod crypto;
pub mod store;
