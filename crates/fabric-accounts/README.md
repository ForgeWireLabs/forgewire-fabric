# fabric-accounts

Human account, credential, membership, and session domain contracts for ForgeWire Fabric (114C).

Domain types, validation, and safe serialization only — no HTTP framework, no rqlite, and no cryptographic verification of its own. Structurally guarantees a human account can never hold the machine-only `runner` role, and that secret material (`secret::SecretString`) cannot be accidentally serialized (no `Serialize` impl on the type at all — only explicit-extraction DTOs can surface a value).

## What's here

- `domain` — `Membership`, `Role`, and the account/session domain model.
- `auth_context` — the resolved-identity shape hub authorization consumes.
- `password`, `webauthn` — credential-shape types (hashing/verification live in the hub's auth service, not here).
- `secret` — `SecretString`, the non-serializable secret wrapper.
- `repository` — storage-agnostic traits; `fabric-store`/`fabric-store-rqlite` provide the rqlite-backed implementation.

## License

Apache-2.0
