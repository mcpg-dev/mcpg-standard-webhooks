//! [Standard Webhooks](https://www.standardwebhooks.com/) signing and
//! verification, version `v1` (HMAC-SHA256).
//!
//! A sender signs `{webhook-id}.{webhook-timestamp}.{raw body}` with the key
//! that a `whsec_` secret carries (the base64 after the prefix, decoded) and
//! sends three headers:
//!
//! | Header | Value |
//! |---|---|
//! | `webhook-id` | a message id without a `.`, stable across retries of one message |
//! | `webhook-timestamp` | Unix seconds of this attempt |
//! | `webhook-signature` | `v1,<base64 HMAC>`, space-separated when several keys sign |
//!
//! A receiver recomputes the HMAC over the raw body bytes it received,
//! compares it in constant time with every `v1` entry of the signature header,
//! and refuses a timestamp outside its tolerance (five minutes by default).
//!
//! ```
//! use mcpg_standard_webhooks::{Verifier, WhsecSecret, sign_message};
//!
//! let secret = WhsecSecret::parse("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw").unwrap();
//! let body = br#"{"test": 2432232314}"#;
//! let headers = sign_message(&[&secret], "msg_p5jXN8AQM9LWM0D4loKWxJek", 1614265330, body).unwrap();
//! assert_eq!(headers.signature, "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=");
//!
//! let verifier = Verifier::new(vec![secret]).unwrap();
//! let verified = verifier
//!     .verify(&headers.id, &headers.timestamp, &headers.signature, body, 1614265330)
//!     .unwrap();
//! assert_eq!(verified.msg_id, "msg_p5jXN8AQM9LWM0D4loKWxJek");
//! ```
//!
//! Secrets live in [`WhsecSecret`], which zeroizes its key on drop and never
//! prints it: `Debug` shows a placeholder and there is no `Display`. Errors
//! never carry a secret, a signature or a body.

mod secret;
mod sign;
mod verify;

#[cfg(test)]
mod vectors;

pub use secret::{SecretError, WhsecSecret};
pub use sign::{SignError, SignedHeaders, sign, sign_message, signature_header};
pub use verify::{Verified, Verifier, VerifierError, VerifyError};

/// Header carrying the message id.
pub const HEADER_ID: &str = "webhook-id";
/// Header carrying the Unix-seconds timestamp of the attempt.
pub const HEADER_TIMESTAMP: &str = "webhook-timestamp";
/// Header carrying one or more space-separated `v1,<base64>` signatures.
pub const HEADER_SIGNATURE: &str = "webhook-signature";
/// Prefix every secret carries before its base64 key.
pub const SECRET_PREFIX: &str = "whsec_";
/// Smallest key a secret may carry, in decoded bytes.
pub const MIN_SECRET_BYTES: usize = 24;
/// Largest key a secret may carry, in decoded bytes.
pub const MAX_SECRET_BYTES: usize = 64;
/// The receiver tolerance the reference libraries use, in seconds. The
/// specification sets no number.
pub const DEFAULT_TOLERANCE_SECS: u64 = 300;
/// Longest message id [`sign`] accepts.
pub const MAX_MSG_ID_BYTES: usize = 256;
/// Most signature entries a verifier reads from one header.
pub const MAX_SIGNATURES: usize = 32;
