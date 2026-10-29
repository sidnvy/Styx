//! Paired routing only; enrollment Core and Host retain authorization authority.
mod relay;
pub(crate) mod transport;
pub use crate::enrollment::service::GatewayExecProfile;
pub use relay::{BoundOwner, DeviceStatus, RelayError, RelayHandle};

pub mod backend;
pub use backend::PairedGatewayBackend;
/// Gateway-only reservation; Host link queues retain their independent budget.
/// Reservation measurement (Linux x86_64, Rust 1.97.1, 2026-10-29):
/// an isolated System GlobalAlloc counter recorded requested live/peak bytes
/// around the production WebSocketConfig and decode_message, over AWS-LC
/// Rustls TLS 1.3 and a 64 KiB Tokio duplex (no sockets). Both TLS configs use
/// the Gateway's TLS 1.3/1.2 + http/1.1 settings with a disposable RSA-3072 cert.
/// Workloads are reproduced by transport's
/// exec_snapshot_and_screenshot_at_frame_ceiling_use_production_decoder test.
/// Idle TLS + WS: 277,483 bytes. Peak traffic increments at exactly 2,097,152
/// wire bytes: Exec stdout 6,272,451; Browser text snapshot 6,274,182;
/// screenshot base64 6,274,176. The counter conservatively includes both TLS
/// endpoints and peer-side WS write/copy allocations, excludes shared config,
/// Hyper, command queues and executor/provider memory (separately budgeted),
/// and measures requested allocations rather than RSS or kernel socket memory.
/// Idle plus largest measured increment = 6,551,665 bytes. 8 MiB leaves
/// 1,836,943 bytes (28.0%) for four 256 KiB requests (three queued plus one
/// sending), Hyper/control/task overhead and allocator rounding. Incoming
/// frame/message (2 MiB), WS write buffer (2 MiB + 64 KiB), three commands and
/// two in-flight business calls plus one control remain bounded independently.
/// This is a capped reservation, not an allocator-enforced RSS bound for every
/// possible JSON shape. Native socket/platform acceptance remains separate.
pub const PAIRED_LINK_BYTES: usize = 8 * 1024 * 1024;
pub const GATEWAY_RELAY_BYTES: usize = 256 * 1024 * 1024;
pub const CONNECTED_COMPUTERS_CAPACITY: usize = GATEWAY_RELAY_BYTES / PAIRED_LINK_BYTES;
pub const CAPACITY_ERROR_CODE: &str = "gateway_wss_capacity_exhausted";
pub const CAPACITY_HINT: &str = "This hub is at its limit of 32 connected computers. Disconnect a computer from this hub, then reconnect.";

#[cfg(all(test, target_os = "linux", target_env = "gnu"))]
mod namespace_tests {
    use crate::{foreground::profile::fresh_connection_profile, tls::*};
    use styx_contracts::identity::{DeviceId, Sha256Digest};

    #[test]
    fn host_profiles_for_loopback_and_lan_match_the_gateway_ca_namespace() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let ca = generate_gateway_ca(now, now - 60, now + 86400).unwrap();
        let der = rustls_pemfile::certs(&mut std::io::Cursor::new(&ca.certificate_pem))
            .next()
            .unwrap()
            .unwrap();
        let hash = Sha256Digest::of_bytes(&der);
        let gateway = paired_gateway_namespace(&ca.anchor_pin);
        assert_eq!(gateway.as_str(), format!("paired.{}", hash.to_hex()));
        let device = DeviceId::try_from("styx-namespace-profile-test").unwrap();
        for origin in [
            "https://127.0.0.1:22022",
            "https://10.0.2.19:22022",
            "https://10.118.53.220:22022",
        ] {
            let (endpoint, host_namespace, tls) =
                fresh_connection_profile(origin, &device, hash, &ca.certificate_pem).unwrap();
            assert_eq!(host_namespace, gateway, "configured origin: {origin}");
            assert!(
                endpoint
                    .as_str()
                    .starts_with(&origin.replacen("https:", "wss:", 1))
            );
            assert!(tls.configured_leaf().is_none());
            assert_eq!(
                tls.configured_anchors(),
                std::slice::from_ref(&ca.anchor_pin)
            );
            assert!(
                fresh_connection_profile(
                    origin,
                    &device,
                    Sha256Digest::of_bytes(b"foreign CA"),
                    &ca.certificate_pem
                )
                .is_err()
            );
        }
        // PEM line endings and endpoint leaf rotation cannot change CA identity.
        let crlf = String::from_utf8(ca.certificate_pem.clone())
            .unwrap()
            .replace('\n', "\r\n");
        assert_eq!(
            fresh_connection_profile("https://10.0.2.19:22022", &device, hash, crlf.as_bytes())
                .unwrap()
                .1,
            gateway
        );
        let other = generate_gateway_ca(now, now - 60, now + 86400).unwrap();
        assert_ne!(paired_gateway_namespace(&other.anchor_pin), gateway);
    }
}
