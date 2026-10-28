//! Paired routing only; enrollment Core and Host retain authorization authority.
mod relay;
pub(crate) mod transport;
pub use crate::enrollment::service::GatewayExecProfile;
pub use relay::{BoundOwner, DeviceStatus, RelayError, RelayHandle};

pub mod backend;
pub use backend::PairedGatewayBackend;
pub const PAIRED_LINK_BYTES: usize = 16 * 1024 * 1024;

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
