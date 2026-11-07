//! Correlation inside an independently authenticated forwarding domain only.
//! Neither JSON owner claims nor the ordinary model bearer reach this adapter.
use super::{GatewayHttp, GatewayOwnerLifecycle, Life, lifecycle};
use crate::gateway::{auth::AuthenticatedGatewayPrincipal, mcp::GatewayToolBackend};
use http::StatusCode;
use rmcp::model::RequestMetaObject;
use std::sync::Arc;
use std::time::Duration;
use styx_contracts::identity::Sha256Digest;
use tokio::sync::Semaphore;

pub(super) struct Conversation<B: GatewayToolBackend + GatewayOwnerLifecycle> {
    pub life: Arc<Life<B>>,
    pub calls: Arc<Semaphore>,
}
/// Constructed only after outer HTTP authentication. SDK preserves this typed
/// value in HTTP Parts; it has no Deserialize or JSON constructor.
pub(super) struct AuthorizedCall<B: GatewayToolBackend + GatewayOwnerLifecycle> {
    pub conversation: Arc<Conversation<B>>,
    _activity: Arc<lifecycle::ActivityGuard<B>>,
}
impl<B: GatewayToolBackend + GatewayOwnerLifecycle> Clone for AuthorizedCall<B> {
    fn clone(&self) -> Self {
        Self {
            conversation: self.conversation.clone(),
            _activity: self._activity.clone(),
        }
    }
}
fn correlation(meta: &RequestMetaObject, principal: Sha256Digest) -> Result<[u8; 32], StatusCode> {
    let mut values = Vec::with_capacity(4);
    let principal = principal.to_hex();
    values.push(principal.as_str());
    for name in ["openai/organization", "openai/subject", "openai/session"] {
        let value = meta
            .get(name)
            .and_then(serde_json::Value::as_str)
            .filter(|value| {
                !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
            })
            .ok_or(StatusCode::BAD_REQUEST)?;
        values.push(value);
    }
    // Canonical length-delimited serialization, not string concatenation. Only
    // the hash is retained; raw service correlations never become owner IDs.
    let bytes = serde_json::to_vec(&values).map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(*Sha256Digest::of_bytes(&bytes).as_bytes())
}
impl<B: GatewayToolBackend + GatewayOwnerLifecycle> GatewayHttp<B> {
    pub(super) fn conversation_call(
        &self,
        principal: &AuthenticatedGatewayPrincipal,
        meta: &RequestMetaObject,
    ) -> Result<AuthorizedCall<B>, StatusCode> {
        if !principal.is_tunnel() || self.stop.is_cancelled() {
            return Err(StatusCode::FORBIDDEN);
        }
        let key = correlation(meta, principal.fingerprint())?;
        self.expire_conversations(super::SESSION_IDLE);
        let mut registry = self.conversations.lock().expect("Tunnel conversations");
        if self.stop.is_cancelled() {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        let conversation = if let Some(existing) = registry.get(&key) {
            existing.clone()
        } else {
            let owner = principal
                .new_tunnel_conversation_owner()
                .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
            let life = self
                .new_life(owner, lifecycle::Boundary::TunnelConversation)
                .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
            let value = Arc::new(Conversation {
                life,
                calls: Arc::new(Semaphore::new(1)),
            });
            registry.insert(key, value.clone());
            value
        };
        let activity = conversation.life.activity().ok_or(StatusCode::NOT_FOUND)?;
        Ok(AuthorizedCall {
            conversation,
            _activity: Arc::new(activity),
        })
    }
    pub(super) fn expire_conversations(&self, minimum: Duration) {
        let mut registry = self.conversations.lock().expect("Tunnel conversations");
        for value in registry.values() {
            let activity = value.life.activity.lock().expect("conversation activity");
            if activity.users == 0
                && activity.last.elapsed() >= minimum
                && value.calls.available_permits() == 1
                && value.life.is_active()
                && !self.backend.owner_has_live_work(&value.life.owner)
            {
                let _ = value.life.close();
            }
        }
        registry.retain(|_, value| !value.life.is_complete());
    }
    pub(super) fn close_conversations(&self) {
        for value in self
            .conversations
            .lock()
            .expect("Tunnel conversations")
            .values()
        {
            let _ = value.life.close();
        }
    }
}
