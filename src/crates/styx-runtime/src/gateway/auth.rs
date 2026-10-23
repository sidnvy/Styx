//! HTTP bearer admission. Protocol owner IDs are minted after authentication;
//! client tool arguments and metadata never construct this authority.
use aws_lc_rs::constant_time::verify_slices_are_equal;
use http::{
    HeaderMap,
    header::{AUTHORIZATION, HOST, ORIGIN},
};
use std::collections::BTreeSet;
use styx_contracts::identity::{OwnerId, Sha256Digest};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GatewayAuthError {
    #[error("invalid Gateway admission configuration")]
    InvalidConfiguration,
    #[error("Gateway authentication required")]
    Unauthenticated,
    #[error("Gateway ingress is not authorized")]
    Forbidden,
}

pub struct GatewayBearerPolicy {
    token_digest: Sha256Digest,
    allowed_hosts: BTreeSet<String>,
    allowed_origins: BTreeSet<String>,
}
impl std::fmt::Debug for GatewayBearerPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayBearerPolicy")
            .field("token", &"[REDACTED]")
            .field("allowed_hosts", &self.allowed_hosts)
            .field("allowed_origins", &self.allowed_origins)
            .finish()
    }
}
#[derive(Clone)]
pub struct AuthenticatedGatewayPrincipal {
    digest: Sha256Digest,
}
impl std::fmt::Debug for AuthenticatedGatewayPrincipal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthenticatedGatewayPrincipal([REDACTED])")
    }
}
/// Ordinary HTTP session ownership, not a ChatGPT-account identity claim.
/// No Deserialize and no public constructor accepting an OwnerId.
#[derive(Clone)]
pub struct VerifiedGatewayOwner {
    owner_id: OwnerId,
    principal: Sha256Digest,
}
impl std::fmt::Debug for VerifiedGatewayOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedGatewayOwner")
            .field("owner_id", &self.owner_id)
            .finish_non_exhaustive()
    }
}
impl VerifiedGatewayOwner {
    pub fn owner_id(&self) -> &OwnerId {
        &self.owner_id
    }
    pub fn principal_fingerprint(&self) -> Sha256Digest {
        self.principal
    }
}
impl AuthenticatedGatewayPrincipal {
    /// Exact service-principal binding, not a client-supplied owner claim.
    pub fn matches_owner(&self, owner: &VerifiedGatewayOwner) -> bool {
        verify_slices_are_equal(self.digest.as_bytes(), owner.principal.as_bytes()).is_ok()
    }
    /// Factory is confined to Gateway adapters after an authenticated ingress.
    pub(super) fn new_mcp_session_owner(&self) -> VerifiedGatewayOwner {
        VerifiedGatewayOwner {
            owner_id: format!("mcp-session:{}", Uuid::new_v4())
                .try_into()
                .expect("fixed UUID owner syntax"),
            principal: self.digest,
        }
    }
}
impl GatewayBearerPolicy {
    pub fn new(
        token: &[u8],
        allowed_hosts: Vec<String>,
        allowed_origins: Vec<String>,
    ) -> Result<Self, GatewayAuthError> {
        if !(32..=4096).contains(&token.len())
            || !token
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
            || allowed_hosts.is_empty()
        {
            return Err(GatewayAuthError::InvalidConfiguration);
        }
        let mut total = 0usize;
        for host in &allowed_hosts {
            total = total
                .checked_add(host.len())
                .ok_or(GatewayAuthError::InvalidConfiguration)?;
            let authority = host
                .parse::<http::uri::Authority>()
                .map_err(|_| GatewayAuthError::InvalidConfiguration)?;
            if host.is_empty()
                || host.len() > 512
                || authority.as_str() != host
                || host.contains('@')
            {
                return Err(GatewayAuthError::InvalidConfiguration);
            }
        }
        for origin in &allowed_origins {
            total = total
                .checked_add(origin.len())
                .ok_or(GatewayAuthError::InvalidConfiguration)?;
            let url =
                url::Url::parse(origin).map_err(|_| GatewayAuthError::InvalidConfiguration)?;
            if !matches!(url.scheme(), "http" | "https")
                || url.origin().ascii_serialization() != *origin
            {
                return Err(GatewayAuthError::InvalidConfiguration);
            }
        }
        if total > styx_contracts::CONTROL_FRAME_BYTES {
            return Err(GatewayAuthError::InvalidConfiguration);
        }
        Ok(Self {
            token_digest: Sha256Digest::of_bytes(token),
            allowed_hosts: allowed_hosts.into_iter().collect(),
            allowed_origins: allowed_origins.into_iter().collect(),
        })
    }
    pub fn authorize(
        &self,
        headers: &HeaderMap,
    ) -> Result<AuthenticatedGatewayPrincipal, GatewayAuthError> {
        if headers.get_all(HOST).iter().count() != 1 || headers.get_all(ORIGIN).iter().count() > 1 {
            return Err(GatewayAuthError::Forbidden);
        }
        let host = headers
            .get(HOST)
            .and_then(|v| v.to_str().ok())
            .ok_or(GatewayAuthError::Forbidden)?;
        if !self.allowed_hosts.contains(host) {
            return Err(GatewayAuthError::Forbidden);
        }
        if let Some(origin) = headers.get(ORIGIN) {
            let origin = origin.to_str().map_err(|_| GatewayAuthError::Forbidden)?;
            if !self.allowed_origins.contains(origin) {
                return Err(GatewayAuthError::Forbidden);
            }
        }
        // Dedicated Tunnel conversation authority is a separate adapter. Reject
        // claims until that authenticated path is installed; never trust _meta.
        if headers.contains_key("x-styx-tunnel-context") {
            return Err(GatewayAuthError::Forbidden);
        }
        if headers.get_all(AUTHORIZATION).iter().count() != 1 {
            return Err(GatewayAuthError::Unauthenticated);
        }
        let authorization = headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(GatewayAuthError::Unauthenticated)?;
        let token = authorization
            .strip_prefix("Bearer ")
            .ok_or(GatewayAuthError::Unauthenticated)?;
        if !(32..=4096).contains(&token.len())
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        {
            return Err(GatewayAuthError::Unauthenticated);
        }
        verify_slices_are_equal(
            Sha256Digest::of_bytes(token.as_bytes()).as_bytes(),
            self.token_digest.as_bytes(),
        )
        .map_err(|_| GatewayAuthError::Unauthenticated)?;
        Ok(AuthenticatedGatewayPrincipal {
            digest: self.token_digest,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(HOST, "localhost:8795".parse().unwrap());
        h.insert(
            AUTHORIZATION,
            format!("Bearer {}", "a".repeat(43)).parse().unwrap(),
        );
        h
    }
    #[test]
    fn only_a_valid_ingress_can_mint_independent_session_owners() {
        let token = "a".repeat(43);
        let policy =
            GatewayBearerPolicy::new(token.as_bytes(), vec!["localhost:8795".into()], vec![])
                .unwrap();
        let a = policy
            .authorize(&headers())
            .unwrap()
            .new_mcp_session_owner();
        let b = policy
            .authorize(&headers())
            .unwrap()
            .new_mcp_session_owner();
        assert_ne!(a.owner_id(), b.owner_id());
        assert_eq!(a.principal_fingerprint(), b.principal_fingerprint());
        assert!(!format!("{policy:?}").contains(&token));
        assert!(!format!("{a:?}").contains(&Sha256Digest::of_bytes(token.as_bytes()).to_hex()));
        for change in 0..8 {
            let mut h = headers();
            match change {
                0 => {
                    h.remove(AUTHORIZATION);
                }
                1 => {
                    h.append(AUTHORIZATION, "Bearer duplicate".parse().unwrap());
                }
                2 => {
                    h.insert(
                        AUTHORIZATION,
                        format!("Bearer {}", "b".repeat(43)).parse().unwrap(),
                    );
                }
                3 => {
                    h.insert(HOST, "other.invalid".parse().unwrap());
                }
                4 => {
                    h.append(HOST, "localhost:8795".parse().unwrap());
                }
                5 => {
                    h.insert(ORIGIN, "https://unapproved.invalid".parse().unwrap());
                }
                6 => {
                    h.insert("x-styx-tunnel-context", "claimed-context".parse().unwrap());
                }
                7 => {
                    h.insert(AUTHORIZATION, format!("bearer {}", token).parse().unwrap());
                }
                _ => unreachable!(),
            }
            assert!(policy.authorize(&h).is_err(), "case {change}");
        }
    }
}
