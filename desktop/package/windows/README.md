# ForgeWire Fabric Desktop Windows Package

This directory packages the Tauri 2 desktop control panel as a user-scope
Windows install. It is separate from the Fabric node/service installer because
the desktop UI is a client surface, not an NSSM service.

Build the package:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File desktop\package\windows\package-forgewire-fabric-desktop.ps1
```

Install from an unpacked package:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File install-forgewire-fabric-desktop.ps1
```

Uninstall:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File uninstall-forgewire-fabric-desktop.ps1 -Yes
```

The installer creates:

- `%LOCALAPPDATA%\Programs\ForgeWire Fabric\ForgeWire Fabric.exe`
- a Desktop shortcut
- a Start Menu shortcut
- an HKCU Add/Remove Programs uninstaller entry

The desktop installer does not store Fabric secrets. The app reads the installed
hub token and dispatcher identity from the normal Fabric locations at runtime.

The uninstaller removes only UI artifacts. It intentionally leaves Fabric hub,
runner, rqlite, hub token, dispatcher identities, and ProgramData state intact.
