//! Pure, versioned wire contracts. No filesystem, network, OS authorization or executors.
pub mod capability;
pub mod control;
pub mod error;
pub mod identity;
pub mod legacy;
pub mod operation;
pub mod session;

pub const CONTRACT_VERSION: u16 = 1;
pub const CONTROL_FRAME_BYTES: usize = 1_048_576;
pub const EXEC_FRAME_BYTES: usize = 2_097_152;
pub const DESKTOP_BROWSER_FRAME_BYTES: usize = 8_388_608;
pub const TERMINAL_OPERATION_RETENTION_MS: u64 = 600_000;
pub const OPERATION_METADATA_BYTES: usize = 16_777_216;

pub const PER_PEER_QUEUED_BYTES: usize = 16_777_216;
pub const HOST_QUEUED_BYTES: usize = 67_108_864;

pub mod enrollment;

pub mod management;

pub mod native_management;

pub mod native_release;

/// Private historical journal codec; not a remote protocol extension.
pub mod historical_enrollment;

/// Private native Host bootstrap data, never enrollment or execution authority.
pub mod native_host;

/// Exact historical deployment connection projection, not admission authority.
pub mod legacy_deployment;
