use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_PAD_INDIFFERENT};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::{MAX_SECRET_BYTES, MIN_SECRET_BYTES, SECRET_PREFIX};

/// Domain label of [`WhsecSecret::fingerprint`], so a fingerprint can never
/// equal any other hash of the key.
const FINGERPRINT_DOMAIN: &[u8] = b"mcpg:whsec-fingerprint:v1\0";

/// A Standard Webhooks signing key: `whsec_` followed by the standard base64
/// of 24 to 64 bytes.
///
/// The decoded key is zeroized on drop. `Debug` prints a placeholder and there
/// is no `Display`, so the key cannot reach a log through formatting.
#[derive(Clone)]
pub struct WhsecSecret {
    key: Zeroizing<Vec<u8>>,
}

/// Why a value is not a usable secret. The messages never contain the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretError {
    /// The value does not start with `whsec_`.
    MissingPrefix,
    /// The part after `whsec_` is not standard base64.
    NotBase64,
    /// The decoded key is shorter than 24 or longer than 64 bytes.
    KeyLength,
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MissingPrefix => "webhook secret does not start with whsec_",
            Self::NotBase64 => "webhook secret is not standard base64 after whsec_",
            Self::KeyLength => "webhook secret key must decode to 24 to 64 bytes",
        })
    }
}

impl std::error::Error for SecretError {}

impl WhsecSecret {
    /// Parse a `whsec_<base64>` value. Padding on the base64 is optional; the
    /// alphabet is the standard one (`+` and `/`).
    pub fn parse(value: &str) -> Result<Self, SecretError> {
        let encoded = value
            .strip_prefix(SECRET_PREFIX)
            .ok_or(SecretError::MissingPrefix)?;
        let key = Zeroizing::new(
            STANDARD_PAD_INDIFFERENT
                .decode(encoded)
                .map_err(|_| SecretError::NotBase64)?,
        );
        Self::from_key(key)
    }

    /// A secret over raw key bytes, for a caller that derives its own key.
    pub fn from_key_bytes(key: &[u8]) -> Result<Self, SecretError> {
        Self::from_key(Zeroizing::new(key.to_vec()))
    }

    fn from_key(key: Zeroizing<Vec<u8>>) -> Result<Self, SecretError> {
        if !(MIN_SECRET_BYTES..=MAX_SECRET_BYTES).contains(&key.len()) {
            return Err(SecretError::KeyLength);
        }
        Ok(Self { key })
    }

    /// The `whsec_<base64>` form, padded, in a buffer that is zeroized on
    /// drop.
    pub fn to_whsec_string(&self) -> Zeroizing<String> {
        let encoded_len = self.key.len().div_ceil(3) * 4;
        // Reserved up front so the encoder never reallocates and leaves a
        // copy of the key behind in freed memory.
        let mut out = Zeroizing::new(String::with_capacity(SECRET_PREFIX.len() + encoded_len));
        out.push_str(SECRET_PREFIX);
        STANDARD.encode_string(self.key.as_slice(), &mut out);
        out
    }

    /// Length of the decoded key in bytes.
    pub fn key_len(&self) -> usize {
        self.key.len()
    }

    /// Whether both secrets hold the same key, compared in constant time.
    pub fn same_key(&self, other: &Self) -> bool {
        self.key.len() == other.key.len() && bool::from(self.key.ct_eq(&other.key))
    }

    /// A short, stable, non-reversible identifier of the key (16 hex
    /// characters) for audit records that must tell keys apart without
    /// holding one.
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(FINGERPRINT_DOMAIN);
        hasher.update(self.key.as_slice());
        let digest = hasher.finalize();
        digest[..8].iter().map(|b| format!("{b:02x}")).collect()
    }

    pub(crate) fn key(&self) -> &[u8] {
        &self.key
    }
}

impl fmt::Debug for WhsecSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WhsecSecret(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLISHED: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";

    fn key_of(n: usize) -> Vec<u8> {
        (0..n).map(|i| i as u8).collect()
    }

    #[test]
    fn parses_the_published_secret() {
        let s = WhsecSecret::parse(PUBLISHED).unwrap();
        assert_eq!(s.key_len(), 24);
    }

    #[test]
    fn refuses_a_value_without_the_prefix() {
        assert_eq!(
            WhsecSecret::parse("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw").unwrap_err(),
            SecretError::MissingPrefix
        );
        assert_eq!(
            WhsecSecret::parse("WHSEC_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw").unwrap_err(),
            SecretError::MissingPrefix
        );
    }

    #[test]
    fn refuses_non_base64_and_the_url_safe_alphabet() {
        assert_eq!(
            WhsecSecret::parse("whsec_not base64!").unwrap_err(),
            SecretError::NotBase64
        );
        let url_safe = format!(
            "whsec_{}",
            STANDARD
                .encode([0xfb_u8; 30])
                .replace('+', "-")
                .replace('/', "_")
        );
        assert_eq!(
            WhsecSecret::parse(&url_safe).unwrap_err(),
            SecretError::NotBase64
        );
    }

    #[test]
    fn enforces_the_24_to_64_byte_key_range() {
        for (len, ok) in [
            (0, false),
            (23, false),
            (24, true),
            (32, true),
            (64, true),
            (65, false),
        ] {
            let value = format!("whsec_{}", STANDARD.encode(key_of(len)));
            assert_eq!(WhsecSecret::parse(&value).is_ok(), ok, "len {len}");
            assert_eq!(
                WhsecSecret::from_key_bytes(&key_of(len)).is_ok(),
                ok,
                "len {len}"
            );
        }
        assert_eq!(
            WhsecSecret::parse("whsec_").unwrap_err(),
            SecretError::KeyLength
        );
    }

    #[test]
    fn padding_is_optional() {
        let padded = format!("whsec_{}", STANDARD.encode(key_of(32)));
        assert!(padded.ends_with('='));
        let unpadded = padded.trim_end_matches('=');
        let a = WhsecSecret::parse(&padded).unwrap();
        let b = WhsecSecret::parse(unpadded).unwrap();
        assert!(a.same_key(&b));
    }

    #[test]
    fn round_trips_through_the_whsec_form() {
        let s = WhsecSecret::from_key_bytes(&key_of(64)).unwrap();
        let text = s.to_whsec_string();
        assert!(text.starts_with("whsec_"));
        assert!(WhsecSecret::parse(&text).unwrap().same_key(&s));
        assert_eq!(
            WhsecSecret::parse(PUBLISHED)
                .unwrap()
                .to_whsec_string()
                .as_str(),
            PUBLISHED
        );
    }

    #[test]
    fn same_key_tells_keys_apart() {
        let a = WhsecSecret::from_key_bytes(&key_of(32)).unwrap();
        let mut other = key_of(32);
        other[31] ^= 1;
        let b = WhsecSecret::from_key_bytes(&other).unwrap();
        let shorter = WhsecSecret::from_key_bytes(&key_of(24)).unwrap();
        assert!(a.same_key(&a.clone()));
        assert!(!a.same_key(&b));
        assert!(!a.same_key(&shorter));
    }

    #[test]
    fn debug_and_errors_never_show_the_key() {
        let s = WhsecSecret::parse(PUBLISHED).unwrap();
        let debug = format!("{s:?}");
        assert_eq!(debug, "WhsecSecret(..)");
        assert!(!debug.contains("MfKQ"));
        for err in [
            WhsecSecret::parse("whsec_!!").unwrap_err(),
            WhsecSecret::parse("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw").unwrap_err(),
        ] {
            assert!(!err.to_string().contains("MfKQ"));
            assert!(!format!("{err:?}").contains("MfKQ"));
        }
    }

    #[test]
    fn fingerprint_is_stable_short_and_key_specific() {
        let a = WhsecSecret::parse(PUBLISHED).unwrap();
        let fp = a.fingerprint();
        assert_eq!(fp.len(), 16);
        assert!(fp.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(fp, a.clone().fingerprint());
        let b = WhsecSecret::from_key_bytes(&key_of(24)).unwrap();
        assert_ne!(fp, b.fingerprint());
        assert!(!fp.contains("MfKQ"));
    }
}
