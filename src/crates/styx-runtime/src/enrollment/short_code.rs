//! Bootstrap only: SPAKE2 authenticates the two endpoints, then the Host uses
//! the existing CA-pinned TLS enrollment protocol for all device mutations.
use super::shared::SharedEnrollment;
use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use std::collections::BTreeMap;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use zeroize::Zeroizing;

// Distinct from legacy 43-character tokens. Both tagged values retain the full
// random 256 bits and are authenticated by the existing enrollment journal.
pub(crate) const INVITE_PREFIX: &str = "SCP1";
pub(super) const CLAIM_PREFIX: &str = "SCC1";
pub(crate) fn is_invitation(token: &str) -> bool {
    token.len() == 47 && token.starts_with(INVITE_PREFIX)
}
pub(super) fn is_claim(token: &str) -> bool {
    token.len() == 47 && token.starts_with(CLAIM_PREFIX)
}
const ALPHABET: &[u8; 32] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
const MAGIC: &[u8; 4] = b"SP01";
const GROUP_BYTES: usize = 33;
const MAX_BUNDLE: usize = 32768 + AES_TAG_BYTES;
const AES_TAG_BYTES: usize = 16;
const CLIENT: &[u8] = b"Styx Host pairing v1";
type Result<T> = std::result::Result<T, &'static str>;
const INVALID: &str = "pairing_code_invalid_or_expired";

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Issued {
    pub(crate) pairing_code: String,
    pub(crate) expires_at: u64,
    one_use: bool,
}
impl Issued {
    pub(crate) fn valid(&self, now: u64) -> bool {
        let code = self.pairing_code.as_bytes();
        self.one_use
            && self.expires_at > now
            && code.len() == 14
            && code.iter().enumerate().all(|(i, b)| {
                if i == 4 || i == 9 {
                    *b == b'-'
                } else {
                    ALPHABET.contains(b)
                }
            })
    }
}

pub(super) struct Offer {
    origin: String,
    password: Zeroizing<String>,
    bundle: Zeroizing<String>,
    token_hash: styx_contracts::identity::Sha256Digest,
    expires: u64,
    attempts: u8,
}
#[derive(Default)]
pub(super) struct Offers(BTreeMap<String, Offer>);
impl Offers {
    pub(super) fn prepare(
        &mut self,
        origin: &str,
        ca: &str,
        token: &str,
        expires: u64,
        now: u64,
    ) -> Result<(String, Offer)> {
        self.0.retain(|_, offer| offer.expires > now);
        if self.0.len() >= 64 {
            return Err("pairing_offer_capacity");
        }
        let bundle = crate::enrollment::pairing_link::build(origin, token, expires, ca, now)
            .map_err(|e| e.code())?;
        let mut random = [0u8; 12];
        getrandom::fill(&mut random).map_err(|_| "pairing_random_unavailable")?;
        let chars: String = random
            .iter()
            .map(|b| ALPHABET[(b & 31) as usize] as char)
            .collect();
        let (id, password) = chars.split_at(4);
        if self.0.contains_key(id) {
            return Err("pairing_offer_collision");
        }
        let offer = Offer {
            origin: origin.into(),
            password: Zeroizing::new(password.into()),
            bundle,
            token_hash: styx_contracts::identity::Sha256Digest::of_bytes(token.as_bytes()),
            expires,
            attempts: 5,
        };
        Ok((format!("{id}-{}-{}", &password[..4], &password[4..]), offer))
    }
    pub(super) fn publish(&mut self, code: &str, offer: Offer) {
        self.0.insert(code[..4].into(), offer);
    }
    pub(super) fn consume(&mut self, token_hash: styx_contracts::identity::Sha256Digest) {
        self.0.retain(|_, o| o.token_hash != token_hash);
    }
    pub(super) fn clear(&mut self) {
        self.0.clear();
    }
    pub(super) fn reply(&mut self, id: &str, peer: &[u8], now: u64) -> Result<(Vec<u8>, Vec<u8>)> {
        let offer = self
            .0
            .get_mut(id)
            .filter(|o| o.expires > now && o.attempts > 0)
            .ok_or(INVALID)?;
        offer.attempts -= 1;
        let server = Identity::new(offer.origin.as_bytes());
        let (exchange, public) = Spake2::<Ed25519Group>::start_b(
            &Password::new(offer.password.as_bytes()),
            &Identity::new(CLIENT),
            &server,
        );
        let secret = Zeroizing::new(exchange.finish(peer).map_err(|_| INVALID)?);
        let mut ciphertext = offer.bundle.as_bytes().to_vec();
        // Fresh SPAKE ephemeral keys on every exchange. One message per key.
        key(&secret)?
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key([0; 12]),
                Aad::from(MAGIC),
                &mut ciphertext,
            )
            .map_err(|_| INVALID)?;
        Ok((public, ciphertext))
    }
}
fn key(secret: &[u8]) -> Result<LessSafeKey> {
    UnboundKey::new(&AES_256_GCM, secret)
        .map(LessSafeKey::new)
        .map_err(|_| INVALID)
}
pub(super) async fn serve(mut tcp: TcpStream, service: &SharedEnrollment) -> Result<()> {
    let mut input = [0u8; 8 + GROUP_BYTES];
    tcp.read_exact(&mut input).await.map_err(|_| INVALID)?;
    if &input[..4] != MAGIC {
        return Err(INVALID);
    }
    let id = std::str::from_utf8(&input[4..8]).map_err(|_| INVALID)?;
    let (public, data) = service
        .with(|s| s.short_reply(id, &input[8..]))
        .await
        .map_err(|_| INVALID)??;
    tcp.write_all(&public).await.map_err(|_| INVALID)?;
    tcp.write_u32(data.len() as u32)
        .await
        .map_err(|_| INVALID)?;
    tcp.write_all(&data).await.map_err(|_| INVALID)
}

pub(crate) async fn resolve(input: &str) -> Result<(String, Zeroizing<String>)> {
    if input.len() > 2048 {
        return Err(INVALID);
    }
    let mut fields = input.split_whitespace();
    let address = fields.next().ok_or(INVALID)?;
    let code = fields
        .next()
        .ok_or(INVALID)?
        .replace('-', "")
        .to_ascii_uppercase();
    if fields.next().is_some() || code.len() != 12 || !code.bytes().all(|b| ALPHABET.contains(&b)) {
        return Err(INVALID);
    }
    let address = if address.contains("://") {
        address.into()
    } else {
        format!("https://{address}")
    };
    let origin =
        crate::enrollment::pairing_link::normalize_origin(&address).map_err(|e| e.code())?;
    let url = url::Url::parse(&origin).map_err(|_| INVALID)?;
    let host = url
        .host_str()
        .ok_or(INVALID)?
        .trim_start_matches('[')
        .trim_end_matches(']');
    let port = url.port_or_known_default().ok_or(INVALID)?;
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut tcp = TcpStream::connect((host, port))
            .await
            .map_err(|_| "pairing_gateway_unreachable")?;
        let (exchange, public) = Spake2::<Ed25519Group>::start_a(
            &Password::new(&code.as_bytes()[4..]),
            &Identity::new(CLIENT),
            &Identity::new(origin.as_bytes()),
        );
        tcp.write_all(MAGIC).await.map_err(|_| INVALID)?;
        tcp.write_all(&code.as_bytes()[..4])
            .await
            .map_err(|_| INVALID)?;
        tcp.write_all(&public).await.map_err(|_| INVALID)?;
        let mut peer = [0; GROUP_BYTES];
        tcp.read_exact(&mut peer).await.map_err(|_| INVALID)?;
        let size = tcp.read_u32().await.map_err(|_| INVALID)? as usize;
        if !(AES_TAG_BYTES..=MAX_BUNDLE).contains(&size) {
            return Err(INVALID);
        }
        let mut bytes = Zeroizing::new(vec![0; size]);
        tcp.read_exact(&mut bytes).await.map_err(|_| INVALID)?;
        let secret = Zeroizing::new(exchange.finish(&peer).map_err(|_| INVALID)?);
        let opened = key(&secret)?
            .open_in_place(
                Nonce::assume_unique_for_key([0; 12]),
                Aad::from(MAGIC),
                &mut bytes,
            )
            .map_err(|_| INVALID)?;
        Ok((
            origin.clone(),
            Zeroizing::new(std::str::from_utf8(opened).map_err(|_| INVALID)?.to_owned()),
        ))
    })
    .await
    .map_err(|_| "pairing_gateway_timeout")?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_closed_and_exhausted_offers_refuse_exchange() {
        let mut offers = Offers::default();
        let code = "2222-3333-4444";
        let offer = || Offer {
            origin: "https://localhost".into(),
            password: Zeroizing::new("33334444".into()),
            bundle: Zeroizing::new("test invitation".into()),
            token_hash: styx_contracts::identity::Sha256Digest::of_bytes(b"test invitation"),
            expires: 1000,
            attempts: 5,
        };
        let (_, peer) = Spake2::<Ed25519Group>::start_a(
            &Password::new(b"33334444"),
            &Identity::new(CLIENT),
            &Identity::new(b"https://localhost"),
        );
        offers.publish(code, offer());
        assert!(offers.reply("2222", &peer, 1000).is_err());
        for _ in 0..5 {
            assert!(offers.reply("2222", &peer, 999).is_ok());
        }
        assert!(offers.reply("2222", &peer, 999).is_err());
        offers.publish(code, offer());
        offers.clear();
        assert!(offers.reply("2222", &peer, 999).is_err());
    }
}
