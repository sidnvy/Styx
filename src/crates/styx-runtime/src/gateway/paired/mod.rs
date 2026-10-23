//! Paired routing only; enrollment Core and Host retain authorization authority.
mod relay;
pub(crate) mod transport;
pub use crate::enrollment::service::GatewayExecProfile;
pub use relay::{BoundOwner, DeviceStatus, RelayError, RelayHandle};

pub mod backend;
pub use backend::PairedGatewayBackend;
pub const PAIRED_LINK_BYTES: usize = 16 * 1024 * 1024;
