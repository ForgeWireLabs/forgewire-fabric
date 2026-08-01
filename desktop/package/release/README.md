# Cross-platform desktop release lane

`desktop-release.mjs` plans and preflights native Tauri bundles without
pretending that one host can validate every operating system. It selects:

- Windows: NSIS, MSI, and the established portable ZIP package.
- macOS: app and DMG bundles.
- Linux: AppImage, plus DEB and RPM when their packaging tools are available.

The planner always writes machine-readable JSON evidence. Platform and tool
manifests exist for deterministic tests and release planning; they do not prove
that another platform was actually built. Evidence labels those runs as
`manifest-plan`, records the actual host separately, and marks whether the
target platform was selected by an override.

```powershell
npm run release:plan
npm run release:preflight
npm run release:build
```

Release mode fails closed. Every platform requires the Tauri updater private
key, its password, and `FORGEWIRE_UPDATER_PUBLIC_KEY`. Windows also requires a
certificate thumbprint and timestamp URL. macOS additionally requires its
Apple certificate, signing identity, account, app-specific password, and team
ID. Evidence records only whether each variable is present; secret values are
never written or printed.

Default evidence is written to `desktop/dist-release/release-evidence.json`.
Use `--evidence <path>` to choose a different destination.

## Signed update channel

Release builds embed `FORGEWIRE_UPDATER_PUBLIC_KEY` at compile time and Tauri
emits updater signatures because `bundle.createUpdaterArtifacts` is enabled.
The private signing key is used only by the build process. It is never bundled,
printed, or copied into release evidence. Publish the generated signature next
to each artifact and publish the reviewed stable manifest as
`forgewire-fabric-desktop-latest.json` on the ForgeWire GitHub release.

The application never checks or installs updates silently. An operator opens
Settings, selects **Check signed channel**, reviews the version and release
notes, and confirms **Install verified update**. The native updater downloads
the artifact and verifies its minisign signature with the embedded public key
before invoking the platform installer. Builds without embedded public-key
metadata expose updater status as unavailable and cannot install an update.

## Rollback

1. Retain the previous signed installer and its published checksum/signature
   before advancing the stable manifest.
2. If a desktop update fails, uninstall only ForgeWire Fabric Desktop.
3. Reinstall the previous signed desktop artifact.
4. Do not remove Fabric Hub, Runner, rqlite, `C:\ProgramData\forgewire`, the
   installed hub token, or the dispatcher identity.
5. Reopen the desktop app and validate connection, refresh, and a signed
   dispatch. Record the failed and restored versions in release evidence.

Windows compilation is validated by the local lane. macOS code
signing/notarization and Linux native packaging must be executed and recorded
on those operating systems; a manifest plan from Windows is not execution
evidence.
