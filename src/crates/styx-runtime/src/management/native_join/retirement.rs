use super::{
    RecordedReply,
    deployment::tls,
    pending,
    work::{Work, load_with_candidate},
    *,
};
use crate::store::{
    PrivateRoot,
    native_root::{
        self,
        host::{NativeHostJoinFile as File, NativeHostJoinStore},
    },
};
use serde::Deserialize;

/// Holds the original protected Join store/writer and exact prefix pins.
/// No claim secret, private identity or authorization is exposed.
pub(crate) struct RetirementHostProof {
    work: Work,
    pub(crate) selection: styx_core::enrollment::RejectionRequest,
    pub(crate) pairing: styx_contracts::enrollment::PairingContext,
    pub(crate) expires_at: u64,
    pub(crate) seed_sha256: Sha256Digest,
    pub(crate) dispatch_sha256: Sha256Digest,
    pub(crate) reply_sha256: Sha256Digest,
    pub(crate) anchor_sha256: Sha256Digest,
}
impl RetirementHostProof {
    pub(crate) fn validate(&self) -> Result<()> {
        if PrivateRoot::open(&self.work.state_dir)
            .map_err(|_| unknown())?
            .identity()
            != self.work.root.identity()
        {
            return Err(unknown());
        }
        self.work.validate()?;
        let prefix = self.work.store.read_prefix().map_err(|_| unknown())?;
        let [Some(dispatched), Some(reply), None, None, None] = prefix else {
            return Err(unknown());
        };
        if self
            .work
            .store
            .read(File::Rejected)
            .map_err(|_| unknown())?
            .is_some()
            || Sha256Digest::of_bytes(&reply) != self.reply_sha256
            || Sha256Digest::of_bytes(&dispatched) != self.dispatch_sha256
            || Sha256Digest::of_bytes(&self.work.seed_raw) != self.seed_sha256
        {
            return Err(unknown());
        }
        self.work.validate()
    }
    pub(crate) fn validate_gateway_ca(&self, ca: &[u8]) -> Result<()> {
        // Both CA files must validate to the original seed's pinned DER CA.
        let _ = tls(ca, self.anchor_sha256)?;
        self.validate()
    }
}
/// Caller owns the Host execution lease and transfers the original root
/// and configuration writer. No second lease or writer is acquired here.
pub(crate) fn retirement_host_preflight(
    path: &Path,
    root: PrivateRoot,
    writer: crate::store::ConfigurationWriterGuard,
) -> Result<RetirementHostProof> {
    if !path.is_absolute()
        || PrivateRoot::open(path).map_err(|_| bad())?.identity() != root.identity()
    {
        return Err(bad());
    }
    let binding = native_root::reopen_native(root, writer).map_err(JoinError::root)?;
    let store = NativeHostJoinStore::from_binding(binding).map_err(JoinError::root)?;
    let work = load_with_candidate(store, path.to_owned(), None, None)?;
    work.validate()?;
    let [Some(dispatched), Some(reply), None, None, None] =
        work.store.read_prefix().map_err(|_| unknown())?
    else {
        return Err(unknown());
    };
    if work
        .store
        .read(File::Rejected)
        .map_err(|_| unknown())?
        .is_some()
    {
        return Err(unknown());
    }
    // Recheck the original signed dispatch against the retained seed/key.
    // The invitation-bearing buffer is zeroized with the original prefix.
    let mut wire: serde_json::Value = serde_json::from_slice(&dispatched).map_err(|_| unknown())?;
    let object = wire.as_object_mut().ok_or_else(unknown)?;
    let signature = object
        .remove("signature")
        .and_then(|v| v.as_str().map(str::to_owned))
        .ok_or_else(unknown)?;
    let mut payload: styx_contracts::legacy::JoinPayload =
        serde_json::from_value(wire).map_err(|_| unknown())?;
    let valid_dispatch = crate::enrollment::validate_local_join(&payload, &signature).is_ok()
        && payload.device_id == work.seed.device_id
        && payload.public_key_pem == work.seed.public_key_pem
        && payload.label == work.seed.label
        && payload.platform == work.seed.platform
        && payload.cwd == work.seed.cwd
        && payload.shell == work.seed.shell
        && payload.computer_requested == work.seed.computer_requested
        && payload.browser_requested == Some(work.seed.browser_requested);
    use zeroize::Zeroize as _;
    payload.invitation.zeroize();
    if !valid_dispatch {
        return Err(unknown());
    }
    let recorded: RecordedReply<'_> = serde_json::from_slice(&reply).map_err(|_| unknown())?;
    let validated = pending(&work, &reply, true)?;
    #[derive(Deserialize)]
    struct Context {
        ingress: Ingress,
    }
    #[derive(Deserialize)]
    struct Ingress {
        origin: String,
        certificate_sha256: Sha256Digest,
        generation: styx_contracts::identity::PairingIngressGeneration,
    }
    let context: Context = serde_json::from_str(recorded.body.get()).map_err(|_| unknown())?;
    if context.ingress.origin != work.seed.gateway_origin
        || context.ingress.certificate_sha256 != recorded.peer_leaf_sha256
    {
        return Err(unknown());
    }
    let pairing = styx_contracts::enrollment::PairingContext {
        origin: context.ingress.origin,
        leaf: context.ingress.certificate_sha256,
        ingress_generation: context.ingress.generation,
        window: None,
    };
    let selection = styx_core::enrollment::RejectionRequest {
        request: validated.request_id.try_into().map_err(|_| unknown())?,
        device: work.seed.device_id.clone(),
        fingerprint: work.seed.fingerprint,
        comparison: validated.comparison_code,
    };
    let proof = RetirementHostProof {
        expires_at: validated.expires_at,
        seed_sha256: Sha256Digest::of_bytes(&work.seed_raw),
        dispatch_sha256: Sha256Digest::of_bytes(&dispatched),
        reply_sha256: Sha256Digest::of_bytes(&reply),
        anchor_sha256: work.seed.anchor_sha256,
        work,
        selection,
        pairing,
    };
    proof.validate()?;
    Ok(proof)
}
