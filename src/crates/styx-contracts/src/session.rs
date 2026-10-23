use crate::{capability::CapabilityId, identity::*};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionBinding {
    pub id: SessionId,
    pub generation: SessionGeneration,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Discovered,
    Connecting,
    Ready,
    Degraded,
    AuthorizationRequired,
    Locked,
    Disconnected,
    Revoked,
    Terminated,
}

/// Platform-specific facts must come from the authenticated native adapter, not environment variables.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "platform", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionIdentity {
    Linux {
        uid: u32,
        login_instance: String,
        seat: Option<String>,
        compositor_instance: String,
        display_identity: String,
    },
    Macos {
        uid: u32,
        audit_session: u64,
        console_instance: String,
        window_server_instance: Option<String>,
    },
    Windows {
        sid: String,
        authentication_luid: u64,
        session_id: u32,
        window_station: String,
        desktop: String,
        integrity_level: u32,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionDescriptor {
    pub binding: SessionBinding,
    pub identity: SessionIdentity,
    pub agent_instance: AgentInstanceId,
    pub state: SessionState,
    pub capabilities: Vec<CapabilityId>,
    pub protocol_version: u16,
}
