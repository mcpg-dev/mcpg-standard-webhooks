use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_PAD_INDIFFERENT;
use http::HeaderMap;
use subtle::ConstantTimeEq as _;

use crate::sign::mac;
use crate::{
    DEFAULT_TOLERANCE_SECS, HEADER_ID, HEADER_SIGNATURE, HEADER_TIMESTAMP, MAX_SIGNATURES,
    WhsecSecret,
};

/// Longest `webhook-timestamp` value read; `u64::MAX` has 20 digits.
const MAX_TIMESTAMP_DIGITS: usize = 20;

/// Checks Standard Webhooks signatures against one or more secrets (several
/// during a rotation) and a timestamp tolerance.
#[derive(Clone)]
pub struct Verifier {
    secrets: Vec<WhsecSecret>,
    tolerance_secs: u64,
}

/// Why a [`Verifier`] could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierError {
    /// No secret was given.
    NoSecret,
}

impl fmt::Display for VerifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a webhook verifier needs at least one secret")
    }
}

impl std::error::Error for VerifierError {}

/// Why a message was refused. Carries header names only, never a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// A required header is absent or empty.
    MissingHeader(&'static str),
    /// A header is repeated, is not visible ASCII, or (for the timestamp) is
    /// not a decimal number; or the signature header holds more than
    /// [`MAX_SIGNATURES`] entries.
    InvalidHeader(&'static str),
    /// The timestamp is older than the tolerance allows.
    TimestampTooOld,
    /// The timestamp is further in the future than the tolerance allows.
    TimestampTooNew,
    /// No `v1` entry matches any secret.
    NoMatchingSignature,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingHeader(name) => write!(f, "missing {name} header"),
            Self::InvalidHeader(name) => write!(f, "invalid {name} header"),
            Self::TimestampTooOld => f.write_str("webhook timestamp is too old"),
            Self::TimestampTooNew => f.write_str("webhook timestamp is too new"),
            Self::NoMatchingSignature => f.write_str("no matching webhook signature"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// What a successful verification established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The `webhook-id`, the key a receiver deduplicates on.
    pub msg_id: String,
    /// The signed timestamp, in Unix seconds.
    pub timestamp: u64,
}

impl Verifier {
    /// A verifier that accepts a signature made with any of `secrets`, with
    /// a five-minute tolerance ([`DEFAULT_TOLERANCE_SECS`]).
    pub fn new(secrets: Vec<WhsecSecret>) -> Result<Self, VerifierError> {
        if secrets.is_empty() {
            return Err(VerifierError::NoSecret);
        }
        Ok(Self {
            secrets,
            tolerance_secs: DEFAULT_TOLERANCE_SECS,
        })
    }

    /// The same verifier with another tolerance, in seconds, applied in both
    /// directions.
    pub fn with_tolerance_secs(mut self, tolerance_secs: u64) -> Self {
        self.tolerance_secs = tolerance_secs;
        self
    }

    /// Verify a message from its three header values and the raw body bytes
    /// as received. `now` is the receiver's clock in Unix seconds.
    ///
    /// A `msg_id` with a `.` is accepted, as the reference libraries accept
    /// it: the rule against a `.` binds the sender, and
    /// [`crate::sign_message`] refuses such an id.
    pub fn verify(
        &self,
        msg_id: &str,
        timestamp: &str,
        signature_header: &str,
        body: &[u8],
        now: u64,
    ) -> Result<Verified, VerifyError> {
        if msg_id.is_empty() {
            return Err(VerifyError::MissingHeader(HEADER_ID));
        }
        if timestamp.is_empty() {
            return Err(VerifyError::MissingHeader(HEADER_TIMESTAMP));
        }
        if signature_header.trim().is_empty() {
            return Err(VerifyError::MissingHeader(HEADER_SIGNATURE));
        }
        let ts = parse_timestamp(timestamp)?;
        if now.saturating_sub(ts) > self.tolerance_secs {
            return Err(VerifyError::TimestampTooOld);
        }
        if ts.saturating_sub(now) > self.tolerance_secs {
            return Err(VerifyError::TimestampTooNew);
        }

        let candidates = signature_entries(signature_header)?;
        // The signature covers the decimal form of the parsed timestamp, as the
        // reference verifiers compute it, not the header text.
        let expected: Vec<[u8; 32]> = self
            .secrets
            .iter()
            .map(|s| mac(s.key(), msg_id, ts, body))
            .collect();
        let mut matched = false;
        for candidate in candidates {
            let Ok(bytes) = STANDARD_PAD_INDIFFERENT.decode(candidate) else {
                continue;
            };
            if bytes.len() != 32 {
                continue;
            }
            for want in &expected {
                matched |= bool::from(want.as_slice().ct_eq(&bytes));
            }
        }
        if matched {
            Ok(Verified {
                msg_id: msg_id.to_owned(),
                timestamp: ts,
            })
        } else {
            Err(VerifyError::NoMatchingSignature)
        }
    }

    /// [`Self::verify`] over the `webhook-*` headers of a request. A repeated
    /// header is refused rather than guessed at.
    pub fn verify_headers(
        &self,
        headers: &HeaderMap,
        body: &[u8],
        now: u64,
    ) -> Result<Verified, VerifyError> {
        let id = single_header(headers, HEADER_ID)?;
        let ts = single_header(headers, HEADER_TIMESTAMP)?;
        let sig = single_header(headers, HEADER_SIGNATURE)?;
        self.verify(id, ts, sig, body, now)
    }
}

impl fmt::Debug for Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verifier")
            .field("secrets", &self.secrets.len())
            .field("tolerance_secs", &self.tolerance_secs)
            .finish()
    }
}

fn single_header<'h>(headers: &'h HeaderMap, name: &'static str) -> Result<&'h str, VerifyError> {
    let mut values = headers.get_all(name).iter();
    let first = values.next().ok_or(VerifyError::MissingHeader(name))?;
    if values.next().is_some() {
        return Err(VerifyError::InvalidHeader(name));
    }
    first.to_str().map_err(|_| VerifyError::InvalidHeader(name))
}

fn parse_timestamp(value: &str) -> Result<u64, VerifyError> {
    let digits_only =
        value.len() <= MAX_TIMESTAMP_DIGITS && value.bytes().all(|b| b.is_ascii_digit());
    if !digits_only {
        return Err(VerifyError::InvalidHeader(HEADER_TIMESTAMP));
    }
    value
        .parse::<u64>()
        .map_err(|_| VerifyError::InvalidHeader(HEADER_TIMESTAMP))
}

/// The base64 part of every `v1,<sig>` entry. Entries of other versions
/// (`v1a`, a future `v2`) are skipped, as the specification's
/// multi-signature rule implies.
fn signature_entries(header: &str) -> Result<Vec<&str>, VerifyError> {
    let entries: Vec<&str> = header.split(' ').filter(|e| !e.is_empty()).collect();
    if entries.len() > MAX_SIGNATURES {
        return Err(VerifyError::InvalidHeader(HEADER_SIGNATURE));
    }
    Ok(entries
        .into_iter()
        .filter_map(|entry| match entry.split_once(',') {
            Some(("v1", sig)) => Some(sig),
            _ => None,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;

    use super::*;
    use crate::{sign, signature_header};

    const NOW: u64 = 1_759_490_000;

    fn secret(byte: u8) -> WhsecSecret {
        WhsecSecret::from_key_bytes(&[byte; 32]).unwrap()
    }

    fn verifier(byte: u8) -> Verifier {
        Verifier::new(vec![secret(byte)]).unwrap()
    }

    #[test]
    fn accepts_its_own_signature() {
        let sig = sign(&secret(1), "msg_1", NOW, b"{}").unwrap();
        let ok = verifier(1)
            .verify("msg_1", &NOW.to_string(), &sig, b"{}", NOW)
            .unwrap();
        assert_eq!(ok.msg_id, "msg_1");
        assert_eq!(ok.timestamp, NOW);
    }

    #[test]
    fn accepts_a_dotted_id_that_sign_refuses() {
        use base64::engine::general_purpose::STANDARD;
        let id = "orders:2026-10-03.42";
        assert!(sign(&secret(1), id, NOW, b"{}").is_err());
        let sig = format!(
            "v1,{}",
            STANDARD.encode(mac(secret(1).key(), id, NOW, b"{}"))
        );
        let ok = verifier(1)
            .verify(id, &NOW.to_string(), &sig, b"{}", NOW)
            .unwrap();
        assert_eq!(ok.msg_id, id);
    }

    #[test]
    fn refuses_another_key_body_id_or_timestamp() {
        let sig = sign(&secret(1), "msg_1", NOW, b"{}").unwrap();
        let ts = NOW.to_string();
        let v = verifier(1);
        assert_eq!(
            verifier(2)
                .verify("msg_1", &ts, &sig, b"{}", NOW)
                .unwrap_err(),
            VerifyError::NoMatchingSignature
        );
        assert_eq!(
            v.verify("msg_1", &ts, &sig, b"{ }", NOW).unwrap_err(),
            VerifyError::NoMatchingSignature
        );
        assert_eq!(
            v.verify("msg_2", &ts, &sig, b"{}", NOW).unwrap_err(),
            VerifyError::NoMatchingSignature
        );
        assert_eq!(
            v.verify("msg_1", &(NOW + 1).to_string(), &sig, b"{}", NOW)
                .unwrap_err(),
            VerifyError::NoMatchingSignature
        );
    }

    #[test]
    fn tolerance_applies_in_both_directions() {
        let v = verifier(1);
        let at = |ts: u64| {
            let sig = sign(&secret(1), "msg_1", ts, b"x").unwrap();
            v.verify("msg_1", &ts.to_string(), &sig, b"x", NOW)
        };
        assert!(at(NOW - DEFAULT_TOLERANCE_SECS).is_ok());
        assert!(at(NOW + DEFAULT_TOLERANCE_SECS).is_ok());
        assert_eq!(
            at(NOW - DEFAULT_TOLERANCE_SECS - 1).unwrap_err(),
            VerifyError::TimestampTooOld
        );
        assert_eq!(
            at(NOW + DEFAULT_TOLERANCE_SECS + 1).unwrap_err(),
            VerifyError::TimestampTooNew
        );
        assert_eq!(at(0).unwrap_err(), VerifyError::TimestampTooOld);
        assert_eq!(at(u64::MAX).unwrap_err(), VerifyError::TimestampTooNew);

        let wide = verifier(1).with_tolerance_secs(3_600);
        let ts = NOW - 3_000;
        let sig = sign(&secret(1), "msg_1", ts, b"x").unwrap();
        assert!(
            wide.verify("msg_1", &ts.to_string(), &sig, b"x", NOW)
                .is_ok()
        );
    }

    #[test]
    fn timestamp_must_be_plain_decimal() {
        let v = verifier(1);
        let sig = sign(&secret(1), "msg_1", NOW, b"x").unwrap();
        for bad in [
            "+1759490000",
            "-1",
            "1759490000.0",
            " 1759490000",
            "0x10",
            "1e9",
            "123456789012345678901",
        ] {
            assert_eq!(
                v.verify("msg_1", bad, &sig, b"x", NOW).unwrap_err(),
                VerifyError::InvalidHeader(HEADER_TIMESTAMP),
                "{bad}"
            );
        }
    }

    #[test]
    fn leading_zeros_verify_against_the_decimal_form() {
        let v = verifier(1);
        let sig = sign(&secret(1), "msg_1", NOW, b"x").unwrap();
        let padded = format!("000{NOW}");
        assert!(v.verify("msg_1", &padded, &sig, b"x", NOW).is_ok());
    }

    #[test]
    fn missing_values_are_named() {
        let v = verifier(1);
        let ts = NOW.to_string();
        assert_eq!(
            v.verify("", &ts, "v1,x", b"", NOW).unwrap_err(),
            VerifyError::MissingHeader(HEADER_ID)
        );
        assert_eq!(
            v.verify("m", "", "v1,x", b"", NOW).unwrap_err(),
            VerifyError::MissingHeader(HEADER_TIMESTAMP)
        );
        assert_eq!(
            v.verify("m", &ts, "  ", b"", NOW).unwrap_err(),
            VerifyError::MissingHeader(HEADER_SIGNATURE)
        );
    }

    #[test]
    fn any_listed_v1_signature_may_match_and_other_versions_are_skipped() {
        let (new, old) = (secret(1), secret(2));
        let both = signature_header(&[&new, &old], "msg_1", NOW, b"x").unwrap();
        let ts = NOW.to_string();
        assert!(verifier(1).verify("msg_1", &ts, &both, b"x", NOW).is_ok());
        assert!(verifier(2).verify("msg_1", &ts, &both, b"x", NOW).is_ok());
        assert!(verifier(3).verify("msg_1", &ts, &both, b"x", NOW).is_err());

        let good = sign(&new, "msg_1", NOW, b"x").unwrap();
        let encoded = good.strip_prefix("v1,").unwrap();
        let mixed = format!("v1a,{encoded} v2,{encoded} v1,AAAA {good}");
        assert!(verifier(1).verify("msg_1", &ts, &mixed, b"x", NOW).is_ok());
        let only_other_versions = format!("v1a,{encoded} v2,{encoded}");
        assert_eq!(
            verifier(1)
                .verify("msg_1", &ts, &only_other_versions, b"x", NOW)
                .unwrap_err(),
            VerifyError::NoMatchingSignature
        );
    }

    #[test]
    fn a_verifier_with_two_secrets_accepts_either() {
        let v = Verifier::new(vec![secret(1), secret(2)]).unwrap();
        let ts = NOW.to_string();
        for byte in [1, 2] {
            let sig = sign(&secret(byte), "msg_1", NOW, b"x").unwrap();
            assert!(v.verify("msg_1", &ts, &sig, b"x", NOW).is_ok());
        }
        let sig = sign(&secret(3), "msg_1", NOW, b"x").unwrap();
        assert!(v.verify("msg_1", &ts, &sig, b"x", NOW).is_err());
    }

    #[test]
    fn signature_entry_count_is_bounded() {
        let good = sign(&secret(1), "msg_1", NOW, b"x").unwrap();
        let mut entries = vec!["v1,AAAA"; MAX_SIGNATURES];
        entries.push(&good);
        let header = entries.join(" ");
        assert_eq!(
            verifier(1)
                .verify("msg_1", &NOW.to_string(), &header, b"x", NOW)
                .unwrap_err(),
            VerifyError::InvalidHeader(HEADER_SIGNATURE)
        );
    }

    #[test]
    fn verify_headers_reads_the_webhook_headers() {
        let sig = sign(&secret(1), "msg_1", NOW, b"x").unwrap();
        let mut h = HeaderMap::new();
        h.insert("Webhook-Id", HeaderValue::from_static("msg_1"));
        h.insert(
            "webhook-timestamp",
            HeaderValue::from_str(&NOW.to_string()).unwrap(),
        );
        h.insert("webhook-signature", HeaderValue::from_str(&sig).unwrap());
        assert!(verifier(1).verify_headers(&h, b"x", NOW).is_ok());

        let mut missing = h.clone();
        missing.remove(HEADER_SIGNATURE);
        assert_eq!(
            verifier(1).verify_headers(&missing, b"x", NOW).unwrap_err(),
            VerifyError::MissingHeader(HEADER_SIGNATURE)
        );

        let mut repeated = h.clone();
        repeated.append(HEADER_ID, HeaderValue::from_static("msg_2"));
        assert_eq!(
            verifier(1)
                .verify_headers(&repeated, b"x", NOW)
                .unwrap_err(),
            VerifyError::InvalidHeader(HEADER_ID)
        );

        let mut opaque = h.clone();
        opaque.insert(HEADER_ID, HeaderValue::from_bytes(b"msg_\xff").unwrap());
        assert_eq!(
            verifier(1).verify_headers(&opaque, b"x", NOW).unwrap_err(),
            VerifyError::InvalidHeader(HEADER_ID)
        );
    }

    #[test]
    fn needs_a_secret_and_never_prints_one() {
        assert_eq!(Verifier::new(vec![]).unwrap_err(), VerifierError::NoSecret);
        let debug = format!("{:?}", verifier(0x41));
        assert!(debug.contains("secrets: 1"));
        assert!(!debug.contains("QUFB"));
    }
}
