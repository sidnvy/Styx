//! Original protected CA to a separately bound maintenance endpoint. No file
//! mutation, new trust root, credential rotation, or ordinary admission.
use super::*;
use crate::{
    foreground::profile::LoadedMaintenanceProfile,
    store::{PrivateRoot, legacy_handoff::CutoverEndpointInputs},
    tls::{PrivateKeyPem, issue_server_leaf},
};
use std::{
    io::Cursor,
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};
use styx_contracts::{
    identity::{Sha256Digest, TransactionId},
    native_management::{NativeGatewayEndpointBinding, NativeRootMarker},
};
use zeroize::Zeroizing;

pub(super) fn issue_original_endpoint(
    root: &PrivateRoot,
    profile: &LoadedMaintenanceProfile,
    marker: &NativeRootMarker,
    transaction: &TransactionId,
    candidate: Sha256Digest,
) -> Result<CutoverEndpointInputs, TransitionError> {
    profile.revalidate().map_err(|_| TransitionError::Unknown)?;
    if profile.tls().configured_leaf().is_some() {
        // CA continuity cannot silently replace an explicitly pinned leaf.
        return Err(TransitionError::Unsupported);
    }
    let deployment = root
        .read_raw("deployment.json", 1024 * 1024)
        .map_err(|_| TransitionError::Unknown)?;
    let cfg: serde_json::Value =
        serde_json::from_slice(deployment.bytes()).map_err(|_| TransitionError::Conflict)?;
    if cfg.get("schema").and_then(|v| v.as_u64()) != Some(1)
        || cfg.get("mode").and_then(|v| v.as_str()) != Some("create-local")
    {
        return Err(TransitionError::Unsupported);
    }
    let gateway = cfg.get("gateway").ok_or(TransitionError::Conflict)?;
    if gateway
        .get("deviceIngress")
        .and_then(|v| v.get("enabled"))
        .is_some_and(|v| v != &serde_json::Value::Bool(false))
    {
        return Err(TransitionError::Unsupported);
    }
    let raw_origin = gateway
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or(TransitionError::Conflict)?;
    let origin = url::Url::parse(raw_origin).map_err(|_| TransitionError::Conflict)?;
    let ip: IpAddr = origin
        .host_str()
        .ok_or(TransitionError::Conflict)?
        .parse()
        .map_err(|_| TransitionError::Unsupported)?;
    let listen: IpAddr = gateway
        .get("listenHost")
        .and_then(|v| v.as_str())
        .unwrap_or("127.0.0.1")
        .parse()
        .map_err(|_| TransitionError::Unsupported)?;
    if !ip.is_loopback()
        || !ip.is_ipv4()
        || listen != ip
        || origin.port().is_none_or(|port| port < 1024)
    {
        return Err(TransitionError::Unsupported);
    }
    let mut host_origin =
        url::Url::parse(profile.endpoint().as_str()).map_err(|_| TransitionError::Conflict)?;
    host_origin
        .set_scheme("https")
        .map_err(|_| TransitionError::Conflict)?;
    if host_origin.origin() != origin.origin() {
        return Err(TransitionError::Conflict);
    }
    let ca = root
        .read_raw("gateway/certificate.pem", 128 * 1024)
        .map_err(|_| TransitionError::Unknown)?;
    let anchors = profile.tls().configured_anchors();
    if anchors.len() != 1 {
        return Err(TransitionError::Unsupported);
    }
    let key = root
        .read_raw("gateway/private-key.pem", 64 * 1024)
        .map_err(|_| TransitionError::Unknown)?;
    let protected = PrivateKeyPem::from_protected_reader_bytes(key.bytes().to_vec())
        .map_err(|_| TransitionError::Conflict)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TransitionError::Conflict)?
        .as_secs();
    let issued = issue_server_leaf(ca.bytes(), &protected, &anchors[0], raw_origin, now).map_err(
        |e| match e {
            crate::tls::IssuerError::UnsupportedIssuer => TransitionError::Unsupported,
            crate::tls::IssuerError::EntropyUnavailable
            | crate::tls::IssuerError::IssuanceFailed => TransitionError::Unavailable,
            _ => TransitionError::Conflict,
        },
    )?;
    // The PEM chain must retain the ORIGINAL CA bytes, rather than re-encoding
    // or promoting the new server leaf into the trust-anchor position.
    let leaf = rustls_pemfile::certs(&mut Cursor::new(&issued.certificate_chain_pem))
        .next()
        .ok_or(TransitionError::Conflict)?
        .map_err(|_| TransitionError::Conflict)?;
    if crate::tls::GatewayLeafPin::from_certificate_der(&leaf) != issued.leaf_pin {
        return Err(TransitionError::Conflict);
    }
    let binding = NativeGatewayEndpointBinding {
        schema: 1,
        transaction_id: transaction.clone(),
        root_identity: marker.root_identity.clone(),
        candidate_manifest_sha256: candidate,
        origin: issued.origin,
        anchor_sha256: issued
            .anchor_pin
            .as_hex()
            .try_into()
            .map_err(|_| TransitionError::Conflict)?,
        leaf_sha256: issued
            .leaf_pin
            .as_hex()
            .try_into()
            .map_err(|_| TransitionError::Conflict)?,
        chain_sha256: Sha256Digest::of_bytes(&issued.certificate_chain_pem),
        not_before_unix: issued.not_before_unix,
        not_after_unix: issued.not_after_unix,
    };
    let result = CutoverEndpointInputs {
        binding: serde_json::to_vec(&binding).map_err(|_| TransitionError::Conflict)?,
        chain: issued.certificate_chain_pem,
        key: Zeroizing::new(issued.private_key.as_protected_bytes().to_vec()),
    };
    for (name, previous, max) in [
        ("gateway/certificate.pem", &ca, 128 * 1024),
        ("gateway/private-key.pem", &key, 64 * 1024),
    ] {
        let current = root
            .read_raw(name, max)
            .map_err(|_| TransitionError::Unknown)?;
        if current.observation() != previous.observation() || current.bytes() != previous.bytes() {
            return Err(TransitionError::Unknown);
        }
    }
    profile.revalidate().map_err(|_| TransitionError::Unknown)?;
    Ok(result)
}
