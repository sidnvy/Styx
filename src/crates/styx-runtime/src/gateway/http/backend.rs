use super::{
    conversation::AuthorizedCall,
    lifecycle::{GatewayOwnerLifecycle, Life},
    session::bounded_message,
};
use crate::gateway::{auth::VerifiedGatewayOwner, mcp::GatewayToolBackend};
use rmcp::{
    ErrorData,
    model::{CallToolRequestParams, CallToolResult, ListToolsResult, PaginatedRequestParams},
};
use std::{future::Future, sync::Arc};
use tokio::sync::{Semaphore, oneshot};
pub(super) struct BackendBridge<B: GatewayToolBackend + GatewayOwnerLifecycle> {
    pub backend: Arc<B>,
    pub life: Arc<Life<B>>,
    pub calls: Arc<Semaphore>,
    #[cfg(test)]
    pub before_register:
        std::sync::Mutex<Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>>,
}
impl<B: GatewayToolBackend + GatewayOwnerLifecycle> BackendBridge<B> {
    fn admitted(&self, owner: &VerifiedGatewayOwner) -> bool {
        self.life.is_active()
            && owner.owner_id() == self.life.owner.owner_id()
            && owner.principal_fingerprint() == self.life.owner.principal_fingerprint()
    }
}
impl<B: GatewayToolBackend + GatewayOwnerLifecycle> GatewayToolBackend for BackendBridge<B> {
    async fn list_tools(
        &self,
        owner: &VerifiedGatewayOwner,
        request: Option<PaginatedRequestParams>,
    ) -> Result<ListToolsResult, ErrorData> {
        if !self.admitted(owner) {
            return Err(refused());
        }
        let _slot = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.calls.clone().acquire_owned(),
        )
        .await
        .map_err(|_| refused())?
        .map_err(|_| refused())?;
        if !self.admitted(owner) {
            return Err(refused());
        }
        let result = self.backend.list_tools(owner, request).await?;
        if !bounded_message(&result) {
            let _ = self.life.close();
            return Err(uncertain());
        }
        Ok(result)
    }
    fn call_tool(
        &self,
        owner: &VerifiedGatewayOwner,
        request: CallToolRequestParams,
    ) -> impl Future<Output = Result<CallToolResult, ErrorData>> + Send {
        self.submit(owner, request, None)
    }
    fn call_tool_with_extensions(
        &self,
        owner: &VerifiedGatewayOwner,
        request: CallToolRequestParams,
        extensions: rmcp::model::Extensions,
    ) -> impl Future<Output = Result<CallToolResult, ErrorData>> + Send {
        let authorized = extensions
            .get::<http::request::Parts>()
            .and_then(|parts| parts.extensions.get::<AuthorizedCall<B>>())
            .cloned();
        self.submit(owner, request, authorized)
    }
}
impl<B: GatewayToolBackend + GatewayOwnerLifecycle> BackendBridge<B> {
    fn submit(
        &self,
        owner: &VerifiedGatewayOwner,
        request: CallToolRequestParams,
        authorized: Option<AuthorizedCall<B>>,
    ) -> impl Future<Output = Result<CallToolResult, ErrorData>> + Send {
        let transport = self.life.clone();
        let context_valid = authorized.as_ref().is_some_and(|call| {
            call.conversation.life.owner.principal_fingerprint() == owner.principal_fingerprint()
                && call.conversation.life.owner.is_tunnel()
        });
        let admitted = self.admitted(owner)
            && (if owner.is_tunnel() {
                context_valid
            } else {
                authorized.is_none()
            });
        let (owner, life, slots) = match &authorized {
            Some(call) => (
                call.conversation.life.owner.clone(),
                call.conversation.life.clone(),
                call.conversation.calls.clone(),
            ),
            None => (owner.clone(), self.life.clone(), self.calls.clone()),
        };
        let backend = self.backend.clone();
        #[cfg(test)]
        let before_register = self
            .before_register
            .lock()
            .expect("test registration gate")
            .take();
        async move {
            if !admitted || !transport.is_active() || !life.is_active() {
                return Err(refused());
            }
            let slot =
                tokio::time::timeout(std::time::Duration::from_secs(5), slots.acquire_owned())
                    .await
                    .map_err(|_| refused())?
                    .map_err(|_| refused())?;
            let supervisor = life.supervisor.upgrade().ok_or_else(refused)?;
            let (tx, rx) = oneshot::channel();
            #[cfg(test)]
            if let Some((arrived, release)) = before_register {
                arrived.notify_one();
                release.notified().await;
            }
            {
                // Same lock order as Life.close: facts -> jobs. No await under
                // either lock. A close cannot pass between admission/registration.
                // Original transport admission and the selected logical owner
                // must both remain open at the actual registration boundary.
                let transport_guard = if Arc::ptr_eq(&transport, &life) {
                    None
                } else {
                    Some(transport.facts.lock().expect("transport lifetime"))
                };
                let life_guard = life.facts.lock().expect("owner lifetime");
                if life_guard.closing || transport_guard.as_ref().is_some_and(|f| f.closing) {
                    return Err(refused());
                }
                let job_life = life.clone();
                let mut jobs = supervisor.jobs.lock().expect("backend supervisor");
                while jobs.try_join_next().is_some() {}
                jobs.spawn(async move {
                    // Capacity follows actual work, not the HTTP response waiter.
                    let _slot = slot;
                    let _authorized_call = authorized;
                    let mut result = backend.call_tool(&owner, request).await;
                    if !bounded_message(&result) {
                        let _ = job_life.close();
                        result = Err(uncertain());
                    }
                    let _ = tx.send(result);
                });
            }
            rx.await.map_err(|_| uncertain())?
        }
    }
}
fn refused() -> ErrorData {
    ErrorData::invalid_request("session closed or call capacity exhausted", None)
}
fn uncertain() -> ErrorData {
    ErrorData::internal_error(
        "response unavailable; action outcome may be unknown; do not replay",
        None,
    )
}
