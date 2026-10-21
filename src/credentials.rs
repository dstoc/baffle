//! Session-scoped credential seed and fake-value derivation.

use std::{
    fmt,
    fs::File,
    io::{self, Read},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::hmac::{self, HMAC_SHA256, Key};

const SEED_BYTES: usize = 32;
const DOMAIN_SEPARATOR: &[u8] = b"baffle:credential-substitution:v1\0";

/// A cryptographically random seed shared with trusted session integrations.
#[derive(Clone)]
pub(crate) struct CredentialSeed([u8; SEED_BYTES]);

impl CredentialSeed {
    pub(crate) fn random() -> io::Result<Self> {
        let mut bytes = [0; SEED_BYTES];
        File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        Ok(Self(bytes))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; SEED_BYTES] {
        &self.0
    }

    pub(crate) fn as_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    #[cfg(test)]
    pub(crate) fn from_test_bytes(bytes: [u8; SEED_BYTES]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for CredentialSeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialSeed([REDACTED])")
    }
}

/// Derive the recognizable fake value for one canonical secret identifier.
pub(crate) fn derive_fake_credential(seed: &CredentialSeed, identifier: &str) -> String {
    let key = Key::new(HMAC_SHA256, seed.as_bytes());
    let mut context = hmac::Context::with_key(&key);
    context.update(DOMAIN_SEPARATOR);
    context.update(identifier.as_bytes());
    let digest = context.sign();
    format!("baffle_v1_{}", URL_SAFE_NO_PAD.encode(digest.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::{CredentialSeed, derive_fake_credential};

    #[test]
    fn derives_the_documented_v1_test_vector() {
        let seed = CredentialSeed::from_test_bytes(std::array::from_fn(|index| index as u8));
        assert_eq!(
            derive_fake_credential(&seed, "github-api"),
            "baffle_v1_Tamc3Pa1DyIVEIq8yK6rlwaPc_L-LdF8S9YHz-17h1I"
        );
    }

    #[test]
    fn seed_debug_output_is_redacted() {
        let seed = CredentialSeed::from_test_bytes([0xa5; 32]);
        assert_eq!(format!("{seed:?}"), "CredentialSeed([REDACTED])");
    }
}
