# fabric-settings

Schema-backed three-tier settings resolution for ForgeWire Fabric.

## What's here

- `defaults()` / `schema()` — the built-in default values and their JSON schema.
- `SettingsSnapshot` — a resolved settings view merging defaults, file config, and runtime overrides.
- `SettingsChange` — a single tracked settings mutation (for audit).
- `SettingsError` — validation/resolution failures.

## License

Apache-2.0
