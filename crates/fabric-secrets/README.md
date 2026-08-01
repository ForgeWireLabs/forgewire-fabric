# fabric-secrets

Fail-closed envelope encryption and redaction for ForgeWire Fabric secrets.

## What's here

- `SecretBroker` — encrypts/decrypts secret values; never returns plaintext unless a caller explicitly asks and is authorized.
- `MasterKeyProvider` trait, with `EnvKeyProvider`, `FileKeyProvider`, `OsKeychainProvider`, and `UnavailableKeyProvider` implementations — pluggable master-key sourcing, fail-closed when none is configured.
- `SecretError` — the error type; every failure mode is a hard error, never a silent fallback to an unencrypted or partially-redacted value.

## License

Apache-2.0
