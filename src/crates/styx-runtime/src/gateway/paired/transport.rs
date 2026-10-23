//! Owned Hyper upgrades. Registry routes; Core lease and owner gates authorize.
use super::relay::{Command, Entry, RelayError, RelayHandle};
use crate::host::protocol::wire::{Call, Reply, Request as WireRequest, Response as WireResponse};
use bytes::Bytes;
use futures_util::{Sink, SinkExt, StreamExt};
use http::{Method, Request, Response};
use http_body::Body;
use http_body_util::Full;
use std::{
    collections::BTreeMap,
    io::Write,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use styx_contracts::identity::*;
use styx_core::enrollment::ConnectionLease;
use tokio::sync::{OwnedSemaphorePermit, mpsc};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        Message,
        protocol::{Role, WebSocketConfig},
    },
};
use tokio_util::sync::CancellationToken;
const FRAME: usize = 256 * 1024;
const RETAINED_CONNECTIONS: usize = 128;
pub(crate) fn device_path(path: &str) -> Option<DeviceId> {
    let s = path.strip_prefix("/styx/host/v3/")?.strip_suffix("/exec")?;
    if !s.starts_with("styx-")
        || s.len() != 29
        || !s[5..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    s.to_owned().try_into().ok()
}
fn reject(status: u16) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("connection", "close")
        .header("cache-control", "no-store")
        .body(Full::new(Bytes::new()))
        .expect("static response")
}
struct LiveFence(Arc<Entry>);
impl Drop for LiveFence {
    fn drop(&mut self) {
        self.0.live.store(false, Ordering::Release);
        self.0.stop.cancel();
    }
}
struct Pending {
    command: Command,
    control: bool,
    deadline: tokio::time::Instant,
}
impl RelayHandle {
    pub(crate) async fn upgrade(
        &self,
        mut req: Request<hyper::body::Incoming>,
        connection: Arc<OwnedSemaphorePermit>,
    ) -> Response<Full<Bytes>> {
        let Some(device) = device_path(req.uri().path()) else {
            return reject(404);
        };
        if req.method() != Method::GET
            || req.version() != http::Version::HTTP_11
            || req.uri().query().is_some()
            || req.uri().scheme().is_some()
            || req.uri().authority().is_some()
            || req.headers().contains_key("origin")
            || req.headers().contains_key("sec-websocket-protocol")
            || req.headers().contains_key("sec-websocket-extensions")
            || req.headers().contains_key("transfer-encoding")
            || req
                .headers()
                .get_all("content-length")
                .iter()
                .any(|v| v != "0")
            || !req.body().is_end_stream()
            || req.body().size_hint().exact() != Some(0)
        {
            return reject(400);
        }
        let response =
            match tokio_tungstenite::tungstenite::handshake::server::create_response_with_body(
                &req,
                || Full::new(Bytes::new()),
            ) {
                Ok(r) => r,
                Err(_) => return reject(400),
            };
        let slot = match self.inner.slots.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => return reject(429),
        };
        let generation: ConnectionGeneration =
            match format!("paired-{}", uuid::Uuid::new_v4()).try_into() {
                Ok(g) => g,
                Err(_) => return reject(503),
            };
        let profile = match self.inner.shared.profiles().await {
            Ok(p) => match p.into_iter().find(|p| p.device_id == device) {
                Some(p) => p,
                None => return reject(403),
            },
            Err(_) => return reject(503),
        };
        let admitted = self
            .inner
            .shared
            .with(|s| {
                s.profile_is_current(&device, &profile.capability_generation)?;
                s.admit_upgrade(req.headers(), &device, generation.clone())
            })
            .await;
        let lease = match admitted {
            Ok(Ok(v)) => v,
            _ => return reject(403),
        };
        let upgraded = hyper::upgrade::on(&mut req);
        let relay = self.clone();
        let stop = CancellationToken::new();
        let task_stop = stop.clone();
        let mut lease = Some(lease);
        let attached = {
            if let Ok(mut state) = self.inner.state.lock() {
                if !state.closing && state.tasks.len() < RETAINED_CONNECTIONS {
                    let lease = lease.take().expect("admitted lease");
                    let task = tokio::spawn(async move {
                        let _slot = slot;
                        let _connection = connection;
                        let mut lease = Some(lease);
                        let mut entry: Option<Arc<Entry>> = None;
                        let result=async{
       let io=tokio::select!{_=task_stop.cancelled()=>return Err(RelayError::Offline),r=tokio::time::timeout(Duration::from_secs(5),upgraded)=>r.map_err(|_|RelayError::Unknown)?.map_err(|_|RelayError::Unknown)?};
       let config=WebSocketConfig::default().max_message_size(Some(FRAME)).max_frame_size(Some(FRAME)).max_write_buffer_size(FRAME+64*1024);
       let socket=WebSocketStream::from_raw_socket(hyper_util::rt::TokioIo::new(io),Role::Server,Some(config)).await;
       let(mut sink,mut source)=socket.split();
       let challenge=format!("challenge-{}",uuid::Uuid::new_v4());
       let request=WireRequest{request_id:request_id()?,connection_generation:None,call:Call::Negotiate{version:3,challenge:challenge.clone(),gateway_namespace:relay.inner.gateway.clone(),gateway_epoch:relay.inner.epoch.clone()}};
       guarded_send(&relay,lease.as_ref().expect("owned lease"),None,&mut sink,&request,&task_stop).await?;
       let response=tokio::select!{_=task_stop.cancelled()=>return Err(RelayError::Offline),r=tokio::time::timeout(Duration::from_secs(5),read_response(&mut source))=>r.map_err(|_|RelayError::Unknown)??};
       if response.request_id!=request.request_id{return Err(RelayError::Invalid)}
       let(host_generation,host_connection,grant_revision)=match response.reply{Reply::Negotiated{version:3,challenge:got,device_id,host_generation,connection_generation,grant_revision:Some(rev),owner_issuance,features,write:true,terminate:true,read_resume:false,..}if ["prepare_start","dispatch_start","inspect_start","read","prepare_action","dispatch_action","inspect_action","owner_open","owner_revoke","owner_cleanup"].iter().all(|f|features.iter().any(|v|v==f))&&got==challenge&&device_id==device&&connection_generation==response.connection_generation&&owner_issuance=="gateway_authenticated"=>(host_generation,connection_generation,rev),_=>return Err(RelayError::Unauthorized)};
       let(tx,mut rx)=mpsc::channel::<Command>(3);
       let e=Arc::new(Entry{device:device.clone(),transport_generation:generation.clone(),host_connection,host_generation,grant_revision,profile,tx,stop:task_stop.clone(),live:AtomicBool::new(true),lease:tokio::sync::Mutex::new(lease.take())});
       entry=Some(e.clone());let _fence=LiveFence(e.clone());
       {let mut s=relay.inner.state.lock().map_err(|_|RelayError::Unknown)?;if s.closing||s.entries.contains_key(&device){return Err(RelayError::Busy)}s.entries.insert(device.clone(),e.clone());}
       let mut pending:BTreeMap<RequestId,Pending>=BTreeMap::new();
       loop{
        let until=pending.values().map(|p|p.deadline).min().unwrap_or_else(||tokio::time::Instant::now()+Duration::from_secs(30));
        tokio::select!{
         _=task_stop.cancelled()=>break,
         _=tokio::time::sleep_until(until)=>{if !pending.is_empty(){return Err(RelayError::Unknown)} relay.authorize(&e).await?;},
         command=rx.recv()=>{
          let Some(command)=command else{break};
          let control=matches!(command.call,Call::OwnerOpen{..}|Call::OwnerRevoke{..}|Call::OwnerCleanup{..});
          let business=pending.values().filter(|p|!p.control).count();
          if (!control&&business>=2)||pending.len()>=3 {let _=command.result.send(Err(RelayError::Busy));continue}
          let request=WireRequest{request_id:request_id()?,connection_generation:Some(e.host_connection.clone()),call:command.call};
          let locked=e.lease.lock().await;let Some(l)=locked.as_ref()else{return Err(RelayError::Offline)};
          let result=guarded_send(&relay,l,command.gate.as_deref(),&mut sink,&request,&task_stop).await;drop(locked);
          // Keep the exact request's responder without retaining sensitive payload.
          let command=Command{call:Call::Write{},result:command.result,gate:command.gate};
          match result{Ok(())=>{pending.insert(request.request_id,Pending{command,control,deadline:tokio::time::Instant::now()+Duration::from_secs(35)});},Err(error)=>{let _=command.result.send(Err(error));return Err(error)}}
         },
         response=read_response(&mut source)=>{
          let response=response?;
          if response.connection_generation!=e.host_connection{return Err(RelayError::Invalid)}
          let Some(p)=pending.remove(&response.request_id)else{return Err(RelayError::Invalid)};
          let locked=e.lease.lock().await;let Some(l)=locked.as_ref()else{return Err(RelayError::Offline)};
          relay.inner.shared.with(|s|{
           let allowed=s.authorize_host_frame(l).is_ok();
           let gate=p.command.gate.as_ref().map(|g|g.lock());
           let gate_allowed=match &gate{None=>true,Some(Ok(g))=>!**g,Some(Err(_))=>false};
           let result=if allowed&&gate_allowed{Ok(response.reply)}else{Err(RelayError::Unauthorized)};
           let _=p.command.result.send(result);
          }).await.map_err(|_|RelayError::Unknown)?;
         }
        }
       }
       drop(sink);drop(source);Ok::<(),RelayError>(())
      }.await;
                        if let Some(e) = entry {
                            e.live.store(false, Ordering::Release);
                            e.stop.cancel();
                            if let Ok(mut state) = relay.inner.state.lock()
                                && state
                                    .entries
                                    .get(&device)
                                    .is_some_and(|current| Arc::ptr_eq(current, &e))
                            {
                                state.entries.remove(&device);
                            }
                            lease = e.lease.lock().await.take();
                        }
                        if let Some(lease) = lease {
                            let _ = relay
                                .inner
                                .shared
                                .with(|s| s.host_connection_ended(lease, true))
                                .await;
                        }
                        let _ = result;
                    });
                    state.tasks.push((stop, task));
                    true
                } else {
                    false
                }
            } else {
                false
            }
        };
        if !attached {
            if let Some(lease) = lease {
                let _ = self
                    .inner
                    .shared
                    .with(|s| s.host_connection_ended(lease, true))
                    .await;
            }
            return reject(503);
        }
        response
    }
}
fn request_id() -> Result<RequestId, RelayError> {
    format!("relay-{}", uuid::Uuid::new_v4())
        .try_into()
        .map_err(|_| RelayError::Invalid)
}
struct Bounded(Vec<u8>);
impl Write for Bounded {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if self.0.len().saturating_add(b.len()) > FRAME {
            return Err(std::io::Error::other("frame capacity"));
        }
        self.0.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
async fn guarded_send<S: Sink<Message> + Unpin>(
    relay: &RelayHandle,
    lease: &ConnectionLease,
    gate: Option<&Mutex<bool>>,
    sink: &mut S,
    request: &WireRequest,
    stop: &CancellationToken,
) -> Result<(), RelayError> {
    let mut out = Bounded(Vec::new());
    serde_json::to_writer(&mut out, request).map_err(|_| RelayError::Invalid)?;
    let text = String::from_utf8(out.0).map_err(|_| RelayError::Invalid)?;
    tokio::select! {_=stop.cancelled()=>return Err(RelayError::Offline),ready=tokio::time::timeout(Duration::from_secs(5),futures_util::future::poll_fn(|cx|Pin::new(&mut *sink).poll_ready(cx)))=>{ready.map_err(|_|RelayError::Unknown)?.map_err(|_|RelayError::Unknown)?;}}
    relay
        .inner
        .shared
        .with(|s| {
            s.authorize_host_frame(lease)
                .map_err(|_| RelayError::Unauthorized)?;
            let guard = gate.map(|g| g.lock());
            if match &guard {
                None => false,
                Some(Ok(g)) => **g,
                Some(Err(_)) => true,
            } {
                return Err(RelayError::Unauthorized);
            }
            if stop.is_cancelled() {
                return Err(RelayError::Offline);
            }
            Pin::new(&mut *sink)
                .start_send(Message::Text(text.into()))
                .map_err(|_| RelayError::Unknown)
        })
        .await
        .map_err(|_| RelayError::Unknown)??;
    tokio::select! {_=stop.cancelled()=>Err(RelayError::Unknown),r=tokio::time::timeout(Duration::from_secs(5),sink.flush())=>r.map_err(|_|RelayError::Unknown)?.map_err(|_|RelayError::Unknown)}
}
async fn read_response<
    S: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
>(
    source: &mut S,
) -> Result<WireResponse, RelayError> {
    loop {
        match source.next().await {
            Some(Ok(Message::Text(text))) if text.len() <= FRAME => {
                return serde_json::from_str(text.as_str()).map_err(|_| RelayError::Invalid);
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            _ => return Err(RelayError::Unknown),
        }
    }
}
