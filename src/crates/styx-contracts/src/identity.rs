use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid identity syntax")]
pub struct InvalidIdentity;

macro_rules! identity {
    ($name:ident, $max:expr, $extra:literal) => {
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);
        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl TryFrom<String> for $name {
            type Error = InvalidIdentity;
            fn try_from(value: String) -> Result<Self, Self::Error> {
                if value.is_empty()
                    || value.len() > $max
                    || !value
                        .bytes()
                        .next()
                        .is_some_and(|b| b.is_ascii_alphanumeric())
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || $extra.as_bytes().contains(&b))
                {
                    return Err(InvalidIdentity);
                }
                Ok(Self(value))
            }
        }
        impl TryFrom<&str> for $name {
            type Error = InvalidIdentity;
            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::try_from(value.to_owned())
            }
        }
        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name)).field(&self.0).finish()
            }
        }
    };
}
identity!(DeviceId, 128, "._-");
identity!(GatewayId, 128, "._-");
// A wire identity is not authentication evidence.
identity!(OwnerId, 256, ":._-");
identity!(HostGeneration, 128, "._-");
identity!(OwnerEpoch, 128, "._-");
identity!(ConnectionGeneration, 128, "._-");
identity!(SessionId, 256, ":._-");
identity!(SessionGeneration, 128, "._-");
identity!(AgentInstanceId, 128, "._-");
identity!(ObservationId, 128, "._-");
identity!(RequestId, 128, "._-");
identity!(TransactionId, 128, "._-");
identity!(ReleaseId, 128, "._-");
identity!(ProviderId, 128, "._-");

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Sha256Digest([u8; 32]);
impl Sha256Digest {
    pub fn of_bytes(bytes: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        Self(Sha256::digest(bytes).into())
    }
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn to_hex(self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}
impl TryFrom<String> for Sha256Digest {
    type Error = InvalidIdentity;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(InvalidIdentity);
        }
        let mut bytes = [0; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::from_str_radix(&value[2 * i..2 * i + 2], 16).map_err(|_| InvalidIdentity)?;
        }
        Ok(Self(bytes))
    }
}
impl From<Sha256Digest> for String {
    fn from(value: Sha256Digest) -> Self {
        value.to_hex()
    }
}
impl fmt::Debug for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}
