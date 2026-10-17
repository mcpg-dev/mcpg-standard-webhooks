use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, KeyInit as _, Mac as _};
use http::{HeaderMap, HeaderName, HeaderValue};
use sha2::Sha256;

use crate::{HEADER_ID, HEADER_SIGNATURE, HEADER_TIMESTAMP, MAX_MSG_ID_BYTES, WhsecSecret};

type HmacSha256 = Hmac<Sha256>;

/// Why a message could not be signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignError {
    /// No secret was given.
    NoSecret,
    /// The message id is empty, longer than 256 bytes, holds a byte outside
    /// visible ASCII, or holds a `.`. The specification forbids a `.` in the
    /// id: the signed content is `{id}.{timestamp}.{body}`, so a dot would
    /// let one id and body pass for another.
    InvalidMessageId,
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoSecret => "no webhook secret to sign with",
            Self::InvalidMessageId => {
                "webhook message id must be 1 to 256 bytes of visible ASCII other than `.`"
            }
        })
    }
}

impl std::error::Error for SignError {}

/// The three Standard Webhooks headers of one delivery attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHeaders {
    /// `webhook-id`.
    pub id: String,
    /// `webhook-timestamp`, decimal Unix seconds.
    pub timestamp: String,
    /// `webhook-signature`, one `v1,<base64>` entry per secret.
    pub signature: String,
}

impl SignedHeaders {
    /// Set the three headers on `headers`, replacing any earlier values.
    pub fn insert_into(&self, headers: &mut HeaderMap) -> Result<(), SignError> {
        for (name, value) in [
            (HEADER_ID, &self.id),
            (HEADER_TIMESTAMP, &self.timestamp),
            (HEADER_SIGNATURE, &self.signature),
        ] {
            let value = HeaderValue::from_str(value).map_err(|_| SignError::InvalidMessageId)?;
            headers.insert(HeaderName::from_static(name), value);
        }
        Ok(())
    }
}

/// The raw HMAC-SHA256 of `{msg_id}.{timestamp}.{body}` under `key`.
pub(crate) fn mac(key: &[u8], msg_id: &str, timestamp: u64, body: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(msg_id.as_bytes());
    mac.update(b".");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    mac.finalize().into_bytes().into()
}

fn check_msg_id(msg_id: &str) -> Result<(), SignError> {
    let ok = !msg_id.is_empty()
        && msg_id.len() <= MAX_MSG_ID_BYTES
        && msg_id.bytes().all(|b| b.is_ascii_graphic() && b != b'.');
    if ok {
        Ok(())
    } else {
        Err(SignError::InvalidMessageId)
    }
}

/// One `v1,<base64>` signature of `body` for message `msg_id` sent at
/// `timestamp` (Unix seconds).
pub fn sign(
    secret: &WhsecSecret,
    msg_id: &str,
    timestamp: u64,
    body: &[u8],
) -> Result<String, SignError> {
    signature_header(&[secret], msg_id, timestamp, body)
}

/// The `webhook-signature` value: one `v1,<base64>` entry per secret, in the
/// order given, separated by single spaces. A sender rotating its secret
/// passes the new and the previous secret so that a receiver holding either
/// one accepts the message.
///
/// `msg_id` must be 1 to 256 bytes of visible ASCII without a `.`; any
/// other id is refused with [`SignError::InvalidMessageId`].
pub fn signature_header(
    secrets: &[&WhsecSecret],
    msg_id: &str,
    timestamp: u64,
    body: &[u8],
) -> Result<String, SignError> {
    if secrets.is_empty() {
        return Err(SignError::NoSecret);
    }
    check_msg_id(msg_id)?;
    let mut out = String::with_capacity(secrets.len() * 48);
    for (i, secret) in secrets.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str("v1,");
        STANDARD.encode_string(mac(secret.key(), msg_id, timestamp, body), &mut out);
    }
    Ok(out)
}

/// The three headers for one delivery attempt. Call it once per attempt with
/// that attempt's time: the id stays the same across retries of a message,
/// the timestamp and the signature do not.
pub fn sign_message(
    secrets: &[&WhsecSecret],
    msg_id: &str,
    timestamp: u64,
    body: &[u8],
) -> Result<SignedHeaders, SignError> {
    let signature = signature_header(secrets, msg_id, timestamp, body)?;
    Ok(SignedHeaders {
        id: msg_id.to_owned(),
        timestamp: timestamp.to_string(),
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(byte: u8) -> WhsecSecret {
        WhsecSecret::from_key_bytes(&[byte; 32]).unwrap()
    }

    #[test]
    fn signature_has_the_v1_shape() {
        let sig = sign(&secret(1), "msg_1", 1_700_000_000, b"{}").unwrap();
        let encoded = sig.strip_prefix("v1,").unwrap();
        assert_eq!(STANDARD.decode(encoded).unwrap().len(), 32);
    }

    #[test]
    fn every_input_changes_the_signature() {
        let base = sign(&secret(1), "msg_1", 1_700_000_000, b"{}").unwrap();
        for other in [
            sign(&secret(2), "msg_1", 1_700_000_000, b"{}").unwrap(),
            sign(&secret(1), "msg_2", 1_700_000_000, b"{}").unwrap(),
            sign(&secret(1), "msg_1", 1_700_000_001, b"{}").unwrap(),
            sign(&secret(1), "msg_1", 1_700_000_000, b"{ }").unwrap(),
        ] {
            assert_ne!(base, other);
        }
    }

    #[test]
    fn rotation_emits_one_entry_per_secret_in_order() {
        let (new, old) = (secret(1), secret(2));
        let header = signature_header(&[&new, &old], "msg_1", 5, b"x").unwrap();
        let first = sign(&new, "msg_1", 5, b"x").unwrap();
        let second = sign(&old, "msg_1", 5, b"x").unwrap();
        assert_eq!(header, format!("{first} {second}"));
    }

    #[test]
    fn refuses_no_secret() {
        assert_eq!(
            signature_header(&[], "msg_1", 5, b"x").unwrap_err(),
            SignError::NoSecret
        );
    }

    #[test]
    fn refuses_message_ids_that_are_not_header_safe() {
        let s = secret(1);
        let long = "a".repeat(MAX_MSG_ID_BYTES + 1);
        for bad in [
            "",
            "msg\r\nx-injected: 1",
            "msg 1",
            "msg\t1",
            "caf\u{e9}",
            long.as_str(),
            "msg_gap_AbC-12.3:x",
            ".",
            "x.1790000000",
        ] {
            assert_eq!(
                sign(&s, bad, 5, b"x").unwrap_err(),
                SignError::InvalidMessageId,
                "{bad:?}"
            );
            assert_eq!(
                sign_message(&[&s], bad, 5, b"x").unwrap_err(),
                SignError::InvalidMessageId,
                "{bad:?}"
            );
        }
        let longest = "a".repeat(MAX_MSG_ID_BYTES);
        assert!(sign(&s, &longest, 5, b"x").is_ok());
        assert!(sign(&s, "msg_gap_AbC-12_3:x~!", 5, b"x").is_ok());
    }

    #[test]
    fn a_dotted_id_would_let_one_message_pass_for_another() {
        let s = secret(1);
        let shifted = mac(s.key(), "x.1790000000", 1_790_000_005, b"{}");
        let original = mac(s.key(), "x", 1_790_000_000, b"1790000005.{}");
        assert_eq!(shifted, original);
        assert_eq!(
            sign(&s, "x.1790000000", 1_790_000_005, b"{}").unwrap_err(),
            SignError::InvalidMessageId
        );
    }

    #[test]
    fn sign_message_fills_all_three_headers() {
        let s = secret(7);
        let h = sign_message(&[&s], "evt_1", 1_759_490_000, b"{}").unwrap();
        assert_eq!(h.id, "evt_1");
        assert_eq!(h.timestamp, "1759490000");
        assert_eq!(
            h.signature,
            sign(&s, "evt_1", 1_759_490_000, b"{}").unwrap()
        );

        let mut map = HeaderMap::new();
        map.insert(HEADER_ID, HeaderValue::from_static("stale"));
        h.insert_into(&mut map).unwrap();
        assert_eq!(map.get(HEADER_ID).unwrap(), "evt_1");
        assert_eq!(map.get(HEADER_TIMESTAMP).unwrap(), "1759490000");
        assert_eq!(map.get(HEADER_SIGNATURE).unwrap(), h.signature.as_str());
        assert_eq!(map.get_all(HEADER_ID).iter().count(), 1);
    }

    #[test]
    fn a_retry_keeps_the_id_and_changes_timestamp_and_signature() {
        let s = secret(9);
        let first = sign_message(&[&s], "evt_1", 1_000, b"{}").unwrap();
        let retry = sign_message(&[&s], "evt_1", 1_030, b"{}").unwrap();
        assert_eq!(first.id, retry.id);
        assert_ne!(first.timestamp, retry.timestamp);
        assert_ne!(first.signature, retry.signature);
    }
}
