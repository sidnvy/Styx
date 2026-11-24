//! No weaker Unix/macOS or Windows pipe simulation is provided.
use super::*;
use std::{marker::PhantomData, path::Path};
use tokio_util::sync::CancellationToken;
#[derive(Clone)]
pub enum EndpointRoot {}
impl EndpointRoot {
    pub fn open(_: impl AsRef<Path>) -> Result<Self> {
        Err(IpcError::Unsupported)
    }
}
pub struct ManagementServer<H: ReadHandler>(PhantomData<H>);
impl<H: ReadHandler> ManagementServer<H> {
    pub async fn bind(_: EndpointRoot, _: H) -> Result<Self> {
        Err(IpcError::Unsupported)
    }
    pub fn expected_server(&self) -> Result<ExpectedServer> {
        Err(IpcError::Unsupported)
    }
    pub async fn run(self, _: CancellationToken) -> Result<ServerReport> {
        Err(IpcError::Unsupported)
    }
}
pub struct ManagementClient;
impl ManagementClient {
    pub async fn connect(_: &EndpointRoot, _: ExpectedServer) -> Result<Self> {
        Err(IpcError::Unsupported)
    }
    pub async fn call(&mut self, _: &ControlRequest, _: Duration) -> Result<ControlResponse> {
        Err(IpcError::Unsupported)
    }
    pub async fn read_pending(&mut self, _: Duration) -> Result<ControlResponse> {
        Err(IpcError::Unsupported)
    }
}
