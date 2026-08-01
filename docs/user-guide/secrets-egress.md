# Secrets and task egress

Secrets are sealed by the hub before rqlite persistence. The stored form is an
AES-256-GCM `fwsecret:v1` envelope with a random nonce and secret-name
associated data. Values are never returned by list APIs.

## Key providers

The broker supports an ACL-restricted file provider and platform keychain
providers: Windows DPAPI machine protection, Linux libsecret through
`secret-tool`, and macOS Keychain through `security`. Provider failure is
fail-closed.

Tasks request secret names. The hub decrypts only for an authorized claim and
redacts matching values from progress, stream, result, note, and audit paths.
Names may appear in audit; values must not.

## Egress policy

A declared empty allowlist means default deny. An absent policy creates no
proxy. Fabric and Loom launch a per-task loopback SOCKS5 proxy when policy is
present. Exact hostnames and explicit leading-wildcard suffixes are supported;
IP literals are denied unless explicitly allowed.

Child processes receive a cleared environment plus a safe allowlist and proxy
variables. The proxy stops when the task ends. Denials are structured and
audited. This is the v1 userspace boundary; kernel enforcement remains later
work.

See [security](security.md).

