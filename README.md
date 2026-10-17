# mcpg-standard-webhooks

> Sign and verify webhooks the [Standard Webhooks](https://www.standardwebhooks.com/) way.

`mcpg-standard-webhooks` implements version `v1` of the Standard Webhooks
signature scheme: HMAC-SHA256 over `{webhook-id}.{webhook-timestamp}.{body}`,
keyed with the bytes a `whsec_` secret carries. MCPG uses it to sign the
event deliveries it sends to MCP clients and to verify the webhooks it
receives. Any Rust service that sends or receives Standard Webhooks can use it
the same way.

## What's here

- `WhsecSecret` — parses `whsec_<base64>` (24 to 64 decoded bytes, standard
  alphabet, padding optional). The key is zeroized on drop; `Debug` prints a
  placeholder and there is no `Display`. `fingerprint()` gives a short,
  non-reversible id for audit records.
- `sign`, `signature_header`, `sign_message` — one `v1,<base64>` signature,
  or one entry per secret during a key rotation, plus the three headers of a
  delivery attempt. Sign every attempt again with its own timestamp; keep the
  message id across retries. The message id must not contain a `.`, as the
  specification requires: a dot would let one id and body pass for another
  in the signed `{id}.{timestamp}.{body}`. Signing refuses such an id.
- `Verifier` — accepts a message when any `v1` entry matches any configured
  secret in constant time and the timestamp is within the tolerance (five
  minutes by default, in both directions, the number the reference libraries
  use; the specification sets none). Entries of other versions are skipped.
  A message id with a `.` is accepted, as the reference libraries accept it.
  `verify_headers` reads the `webhook-*` headers from an `http::HeaderMap`
  and refuses a repeated header.

```rust
use mcpg_standard_webhooks::{Verifier, WhsecSecret, sign_message};

let secret = WhsecSecret::parse("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw")?;
let body = br#"{"test": 2432232314}"#;
let headers = sign_message(&[&secret], "msg_p5jXN8AQM9LWM0D4loKWxJek", 1614265330, body)?;

let verifier = Verifier::new(vec![secret])?;
verifier.verify(&headers.id, &headers.timestamp, &headers.signature, body, 1614265330)?;
```

Verify over the raw body bytes exactly as they arrived: any re-serialization
changes the signed content. Errors name a header at most; they never carry a
secret, a signature or a body.

The tests check the vector that the official JavaScript and Go libraries'
test suites share, the official Rust library's own test cases (from
`standardwebhooks` 1.0.1), and vectors produced by the reference TypeScript
library. The official Rust library is also an oracle: the official library
verifies what this crate signs, with one secret and with a rotation header;
this crate verifies what the official library signs; and both give the same
signature for any UTF-8 body under an id without a `.`. An independent
implementation of the reference verifier accepts what this crate signs,
non-UTF-8 bodies included.

## Build / test

```bash
cargo build -p mcpg-standard-webhooks
cargo test  -p mcpg-standard-webhooks
```

## Licence

Apache-2.0.

## See also

- [Standard Webhooks specification](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md)
- [`mcpg-safe-egress`](https://github.com/mcpg-dev/mcpg-safe-egress) — the outbound client that carries the signed requests.
