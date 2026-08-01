# fabric-protocol

Wire protocol primitives for ForgeWire Fabric: canonical JSON encoding, Ed25519 signing, and signature verification, shared by every hub/runner/client/dispatcher crate.

## What's here

- `canonicalize(value)` — the canonical-JSON byte encoding every signature is computed over.
- `sign_payload_hex()` / `verify_signature_hex()` — raw Ed25519 sign/verify over arbitrary bytes.
- `sign_envelope_hex()` / `verify_envelope_hex()` — sign/verify a JSON envelope by canonicalizing it first.
- `ProtocolError` — the single error type covering malformed hex, bad key/signature lengths, and canonicalization failures.

## License

Apache-2.0
