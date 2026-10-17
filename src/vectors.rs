//! Interoperability vectors.
//!
//! The first vector is the one the official JavaScript and Go libraries'
//! test suites share; the specification publishes no keyed vector. The
//! others were produced by the reference TypeScript library
//! (`standardwebhooks` 1.1.1, `Webhook#sign`), so they check this crate
//! against an implementation that shares no code with it. `svix_verify` is an
//! independent re-implementation of the reference verification algorithm on
//! another HMAC crate; it must accept what this crate signs, non-UTF-8 bodies
//! included. The `official` module holds the official Rust library's own
//! test cases and uses that library as an oracle in both directions.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use proptest::prelude::*;

use crate::{SignError, Verifier, VerifyError, WhsecSecret, sign, sign_message, signature_header};

struct Vector {
    secret: &'static str,
    msg_id: &'static str,
    timestamp: u64,
    body: Body,
    signature: &'static str,
}

enum Body {
    Text(&'static str),
    /// `JSON.stringify({items: [{i, name: "item-" + i, tags: ["a", "b"]}, …]})`
    /// for `i` in `0..40`.
    Items40,
}

impl Body {
    fn bytes(&self) -> Vec<u8> {
        match self {
            Body::Text(s) => s.as_bytes().to_vec(),
            Body::Items40 => {
                let items: Vec<String> = (0..40)
                    .map(|i| format!(r#"{{"i":{i},"name":"item-{i}","tags":["a","b"]}}"#))
                    .collect();
                format!(r#"{{"items":[{}]}}"#, items.join(",")).into_bytes()
            }
        }
    }
}

const SECRET_32: &str = "whsec_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const SECRET_64: &str = "whsec_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==";

const VECTORS: &[Vector] = &[
    Vector {
        secret: "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw",
        msg_id: "msg_p5jXN8AQM9LWM0D4loKWxJek",
        timestamp: 1_614_265_330,
        body: Body::Text(r#"{"test": 2432232314}"#),
        signature: "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=",
    },
    Vector {
        secret: SECRET_32,
        msg_id: "evt_0123456789abcdef",
        timestamp: 1_700_000_000,
        body: Body::Text(
            "{\"eventId\":\"evt_0123456789abcdef\",\"name\":\"orders.created\",\"data\":{\"note\":\"caf\u{e9} \u{20ac} \u{1f600}\"}}",
        ),
        signature: "v1,6OxcaoNMhKOvmFbXvfvW+0Fo0odPBPsxgcekwkxu82w=",
    },
    Vector {
        secret: SECRET_64,
        msg_id: "msg_verification_abc123",
        timestamp: 1_759_490_000,
        body: Body::Text(""),
        signature: "v1,3QuKJdu+zf9bj4obO5h/s1PauluoevDTMa5Dbji5D4E=",
    },
    Vector {
        secret: SECRET_64,
        msg_id: "evt_big",
        timestamp: 1_759_490_123,
        body: Body::Items40,
        signature: "v1,cKQ2/Q6B1U2VwFggaHuDBg2QoyLPuXjUVnezJJvUTv4=",
    },
];

/// Vectors whose id holds a `.`: a receiver accepts them, as the reference
/// libraries do, but this crate refuses to sign them.
const VERIFY_ONLY: &[Vector] = &[Vector {
    secret: SECRET_32,
    msg_id: "orders:2026-10-03.42",
    timestamp: 4_102_444_800,
    body: Body::Text("plain text, not JSON"),
    signature: "v1,fmIjTbFG4FcWPwRdh3p26qvVrUzNFhwjHk8ZsAsBAoY=",
}];

/// The reference verification algorithm, written independently of this
/// crate: strip `whsec_`, base64-decode the key, HMAC-SHA256 over
/// `id.timestamp.body`, base64-encode, and compare against every space-
/// separated `v1` entry.
fn svix_verify(secret: &str, msg_id: &str, timestamp: &str, signature: &str, body: &[u8]) -> bool {
    let key = STANDARD
        .decode(secret.strip_prefix("whsec_").unwrap_or(secret))
        .expect("reference secret decodes");
    let mut signed = Vec::new();
    signed.extend_from_slice(msg_id.as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(timestamp.as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(body);
    let expected = STANDARD.encode(hmac_sha256::HMAC::mac(&signed, &key));
    signature
        .split(' ')
        .any(|entry| match entry.split_once(',') {
            Some(("v1", sig)) => sig == expected,
            _ => false,
        })
}

#[test]
fn the_items40_body_matches_the_reference_input() {
    assert_eq!(Body::Items40.bytes().len(), 1711);
}

#[test]
fn signing_reproduces_every_reference_vector() {
    for v in VECTORS {
        let secret = WhsecSecret::parse(v.secret).unwrap();
        let got = sign(&secret, v.msg_id, v.timestamp, &v.body.bytes()).unwrap();
        assert_eq!(got, v.signature, "{}", v.msg_id);
    }
}

#[test]
fn signing_refuses_a_verify_only_vector_for_its_dotted_id() {
    for v in VERIFY_ONLY {
        let secret = WhsecSecret::parse(v.secret).unwrap();
        assert_eq!(
            sign(&secret, v.msg_id, v.timestamp, &v.body.bytes()).unwrap_err(),
            SignError::InvalidMessageId,
            "{}",
            v.msg_id
        );
    }
}

#[test]
fn verification_accepts_every_reference_vector() {
    for v in VECTORS.iter().chain(VERIFY_ONLY) {
        let verifier = Verifier::new(vec![WhsecSecret::parse(v.secret).unwrap()]).unwrap();
        let ok = verifier
            .verify(
                v.msg_id,
                &v.timestamp.to_string(),
                v.signature,
                &v.body.bytes(),
                v.timestamp,
            )
            .unwrap();
        assert_eq!(ok.msg_id, v.msg_id);
    }
}

#[test]
fn verification_refuses_a_reference_vector_with_one_changed_body_byte() {
    for v in VECTORS.iter().chain(VERIFY_ONLY) {
        let verifier = Verifier::new(vec![WhsecSecret::parse(v.secret).unwrap()]).unwrap();
        let mut body = v.body.bytes();
        body.push(b' ');
        assert_eq!(
            verifier
                .verify(
                    v.msg_id,
                    &v.timestamp.to_string(),
                    v.signature,
                    &body,
                    v.timestamp
                )
                .unwrap_err(),
            VerifyError::NoMatchingSignature
        );
    }
}

#[test]
fn the_reference_algorithm_accepts_what_this_crate_signs() {
    for v in VECTORS {
        let secret = WhsecSecret::parse(v.secret).unwrap();
        let body = v.body.bytes();
        let headers = sign_message(&[&secret], v.msg_id, v.timestamp, &body).unwrap();
        assert!(svix_verify(
            v.secret,
            &headers.id,
            &headers.timestamp,
            &headers.signature,
            &body
        ));
    }
}

#[test]
fn a_rotation_header_matches_the_reference_and_verifies_under_either_key() {
    let (new, old) = (
        WhsecSecret::parse(SECRET_32).unwrap(),
        WhsecSecret::parse(SECRET_64).unwrap(),
    );
    let header =
        signature_header(&[&new, &old], "msg_rotation", 1_759_490_000, br#"{"a":1}"#).unwrap();
    assert_eq!(
        header,
        "v1,b+qFQKVHHLRk1ds0qPrlOnRZMKdG8WayndpxnEX21/M= v1,Eb4Cxqdwr8OGuAQwbdqz7UfyfQ1fRkVKEWce9F26yD4="
    );
    for secret in [SECRET_32, SECRET_64] {
        assert!(svix_verify(
            secret,
            "msg_rotation",
            "1759490000",
            &header,
            br#"{"a":1}"#
        ));
        let v = Verifier::new(vec![WhsecSecret::parse(secret).unwrap()]).unwrap();
        assert!(
            v.verify(
                "msg_rotation",
                "1759490000",
                &header,
                br#"{"a":1}"#,
                1_759_490_000
            )
            .is_ok()
        );
    }
}

fn arb_secret() -> impl Strategy<Value = WhsecSecret> {
    prop::collection::vec(any::<u8>(), 24..=64)
        .prop_map(|key| WhsecSecret::from_key_bytes(&key).unwrap())
}

/// Visible ASCII other than `.`.
fn arb_msg_id() -> impl Strategy<Value = String> {
    r"[!-\-/-~]{1,64}"
}

proptest! {
    #[test]
    fn secret_parsing_never_panics(value in ".{0,200}") {
        let _ = WhsecSecret::parse(&value);
        let _ = WhsecSecret::parse(&format!("whsec_{value}"));
    }

    #[test]
    fn verification_never_panics_on_arbitrary_headers(
        id in ".{0,80}",
        ts in ".{0,30}",
        sig in ".{0,300}",
        body in prop::collection::vec(any::<u8>(), 0..256),
        now in any::<u64>(),
    ) {
        let v = Verifier::new(vec![WhsecSecret::parse(SECRET_32).unwrap()]).unwrap();
        let _ = v.verify(&id, &ts, &sig, &body, now);
    }

    #[test]
    fn whatever_is_signed_verifies_and_matches_the_reference(
        secret in arb_secret(),
        id in arb_msg_id(),
        ts in 0u64..=4_102_444_800,
        body in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        let headers = sign_message(&[&secret], &id, ts, &body).unwrap();
        let v = Verifier::new(vec![secret.clone()]).unwrap();
        prop_assert!(v.verify(&headers.id, &headers.timestamp, &headers.signature, &body, ts).is_ok());
        prop_assert!(svix_verify(&secret.to_whsec_string(), &headers.id, &headers.timestamp, &headers.signature, &body));
    }

    #[test]
    fn an_id_with_a_dot_is_never_signed(
        secret in arb_secret(),
        before in "[!-~]{0,32}",
        after in "[!-~]{0,32}",
        ts in any::<u64>(),
        body in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let id = format!("{before}.{after}");
        prop_assert_eq!(sign(&secret, &id, ts, &body).unwrap_err(), SignError::InvalidMessageId);
        prop_assert_eq!(
            sign_message(&[&secret], &id, ts, &body).unwrap_err(),
            SignError::InvalidMessageId
        );
    }

    #[test]
    fn whsec_form_round_trips(secret in arb_secret()) {
        let parsed = WhsecSecret::parse(&secret.to_whsec_string()).unwrap();
        prop_assert!(parsed.same_key(&secret));
    }
}

/// The official Rust library (`standardwebhooks` 1.0.1). Its own test cases
/// (`src/lib.rs`, the tests at lines 156-314) run against this crate, and the
/// library itself checks what this crate signs and signs what this crate
/// checks.
mod official {
    use std::time::{SystemTime, UNIX_EPOCH};

    use http::HeaderMap;
    use proptest::prelude::*;
    use standardwebhooks::Webhook;

    use super::{arb_msg_id, arb_secret};
    use crate::{
        HEADER_ID, HEADER_SIGNATURE, HEADER_TIMESTAMP, SecretError, Verifier, VerifyError,
        WhsecSecret, sign, sign_message,
    };

    const SECRET: &str = "whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD";
    const MSG_ID: &str = "msg_27UH4WbU6Z5A5EzD8u03UvzRbpk";
    const PAYLOAD: &[u8] = br#"{"email":"test@example.com","username":"test_user"}"#;
    const TIMESTAMP: u64 = 1_649_367_553;
    const SIGNATURE: &str = "v1,tZ1I4/hDygAJgO5TYxiSd6Sd0kDW6hPenDe+bTa3Kkw=";
    const WRONG_SIGNATURE: &str = "v1,R3PTzyfHASBKHH98a7yexTwaJ4yNIcGhFQc1yuN+BPU=";
    const DECOYS: [&str; 3] = [
        "v1,tFtCZ5RDCPxzWQRWXWPgrCgE2frDBe9gjpbWQxnVfsQ=",
        "v1,Mm7xgUVICxZfQ3bgf0h0Dof65L/IFx+PnZvnDWPCX6Q=",
        "v1,9DfC1c3eeOrXB6w/5dIDydLNQaEyww5KalE5jLBZucE=",
    ];

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn secret() -> WhsecSecret {
        WhsecSecret::parse(SECRET).unwrap()
    }

    fn verifier() -> Verifier {
        Verifier::new(vec![secret()]).unwrap()
    }

    fn check(signature: &str, timestamp: u64, now: u64) -> Result<(), VerifyError> {
        verifier()
            .verify(MSG_ID, &timestamp.to_string(), signature, PAYLOAD, now)
            .map(|_| ())
    }

    #[test]
    fn test_sign() {
        assert_eq!(
            sign(&secret(), MSG_ID, TIMESTAMP, PAYLOAD).unwrap(),
            SIGNATURE
        );
        assert_eq!(check(SIGNATURE, TIMESTAMP, TIMESTAMP), Ok(()));
    }

    #[test]
    fn test_verify() {
        let at = now();
        let signature = sign(&secret(), MSG_ID, at, PAYLOAD).unwrap();
        assert_eq!(check(&signature, at, at), Ok(()));
    }

    #[test]
    fn test_no_verify() {
        assert_eq!(
            check(WRONG_SIGNATURE, TIMESTAMP, TIMESTAMP),
            Err(VerifyError::NoMatchingSignature)
        );
    }

    #[test]
    fn test_verify_partial_signature() {
        assert_eq!(
            check("v1,", TIMESTAMP, TIMESTAMP),
            Err(VerifyError::NoMatchingSignature)
        );
        assert_eq!(
            check(&SIGNATURE[..8], TIMESTAMP, TIMESTAMP),
            Err(VerifyError::NoMatchingSignature)
        );
    }

    #[test]
    fn test_verify_incorrect_timestamp() {
        let at = now();
        let signature = sign(&secret(), MSG_ID, at, PAYLOAD).unwrap();
        assert_eq!(
            check(&signature, at - 301, at),
            Err(VerifyError::TimestampTooOld)
        );
        assert_eq!(
            check(&signature, at + 301, at),
            Err(VerifyError::TimestampTooNew)
        );
    }

    #[test]
    fn test_verify_with_multiple_signatures() {
        let header = format!("{} {} {SIGNATURE} {}", DECOYS[0], DECOYS[1], DECOYS[2]);
        assert_eq!(check(&header, TIMESTAMP, TIMESTAMP), Ok(()));
    }

    #[test]
    fn test_no_verify_with_multiple_signatures() {
        assert_eq!(
            check(&DECOYS.join(" "), TIMESTAMP, TIMESTAMP),
            Err(VerifyError::NoMatchingSignature)
        );
    }

    #[test]
    fn test_missing_headers() {
        let mut headers = HeaderMap::new();
        sign_message(&[&secret()], MSG_ID, TIMESTAMP, PAYLOAD)
            .unwrap()
            .insert_into(&mut headers)
            .unwrap();
        for name in [HEADER_ID, HEADER_SIGNATURE, HEADER_TIMESTAMP] {
            let mut missing = headers.clone();
            missing.remove(name);
            assert_eq!(
                verifier()
                    .verify_headers(&missing, PAYLOAD, TIMESTAMP)
                    .unwrap_err(),
                VerifyError::MissingHeader(name)
            );
        }
    }

    /// The JavaScript and Go libraries refuse an empty key; 1.0.1 accepts
    /// one, so this case checks this crate alone.
    #[test]
    fn an_empty_key_is_refused() {
        assert_eq!(
            WhsecSecret::parse("whsec_").unwrap_err(),
            SecretError::KeyLength
        );
    }

    #[test]
    fn the_official_library_verifies_what_this_crate_signs() {
        let at = now();
        let mut headers = HeaderMap::new();
        sign_message(&[&secret()], MSG_ID, at, PAYLOAD)
            .unwrap()
            .insert_into(&mut headers)
            .unwrap();
        Webhook::new(SECRET)
            .unwrap()
            .verify(PAYLOAD, &headers)
            .unwrap();
    }

    #[test]
    fn the_official_library_verifies_a_rotation_header_under_either_key() {
        let other = WhsecSecret::from_key_bytes(&[0x5a; 48]).unwrap();
        let at = now();
        let mut headers = HeaderMap::new();
        sign_message(&[&other, &secret()], MSG_ID, at, PAYLOAD)
            .unwrap()
            .insert_into(&mut headers)
            .unwrap();
        for key in [other.to_whsec_string(), secret().to_whsec_string()] {
            Webhook::new(&key)
                .unwrap()
                .verify(PAYLOAD, &headers)
                .unwrap();
        }
        let stranger = WhsecSecret::from_key_bytes(&[0x11; 32]).unwrap();
        assert!(
            Webhook::new(&stranger.to_whsec_string())
                .unwrap()
                .verify(PAYLOAD, &headers)
                .is_err()
        );
    }

    #[test]
    fn this_crate_verifies_what_the_official_library_signs() {
        let at = now();
        let signature = Webhook::new(SECRET)
            .unwrap()
            .sign(MSG_ID, at as i64, PAYLOAD)
            .unwrap();
        assert_eq!(check(&signature, at, at), Ok(()));
    }

    proptest! {
        #[test]
        fn both_libraries_sign_alike(
            secret in arb_secret(),
            id in arb_msg_id(),
            ts in 0u64..=4_102_444_800,
            body in ".{0,256}",
        ) {
            let theirs = Webhook::new(&secret.to_whsec_string())
                .unwrap()
                .sign(&id, ts as i64, body.as_bytes())
                .unwrap();
            prop_assert_eq!(sign(&secret, &id, ts, body.as_bytes()).unwrap(), theirs);
        }
    }
}
