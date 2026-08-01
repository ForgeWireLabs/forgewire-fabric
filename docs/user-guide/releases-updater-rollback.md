# Releases, updater, and rollback

The desktop release planner produces evidence before it builds. Windows plans
NSIS, MSI, and the existing portable ZIP. macOS plans app and DMG. Linux plans
AppImage and conditionally deb/rpm according to available tooling.

Release mode fails closed when signing or updater metadata is missing. Evidence
records presence booleans, tool versions, selected targets, commands, and
blocked reasons—not credential values.

## Signed updater

The Tauri updater uses an HTTPS GitHub release manifest and signed updater
artifacts. The build embeds the public key; the private key remains external.
The client checks only on operator request, shows the proposed version, asks
for confirmation, and verifies the signature before installation.

## Current gates

Windows build/package lanes are exercised. Real signed release preflight is
blocked because production signing/updater credentials are absent. macOS and
Linux builds and platform smokes have not run. Linux release mode also blocks
on `GHSA-wrw7-89jp-8q8g`: the current Tauri GTK dependency pins `glib 0.18.5`,
while the patched line requires `>=0.20.0`.

## Rollback

Uninstall only the desktop client, install the previous signed artifact, and
retain Fabric service data, hub tokens, and dispatcher identities. Validate
connect, refresh, dispatch, and audit after rollback. Never downgrade hub wire
compatibility silently to accommodate an old client.

