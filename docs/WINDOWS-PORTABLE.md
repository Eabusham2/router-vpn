# Router VPN on Windows — Portable and PortableApps

Router VPN ships two related no-system-install layouts plus the normal Windows package.

## 1. Portable ZIP

Artifacts:

- `RouterVPN-Portable-Windows-amd64.zip`
- `RouterVPN-Portable-Windows-arm64.zip`

Extract the whole folder anywhere, including a removable drive, then run:

```text
RouterVPNPortable.exe
```

Do not separate the executable from its `App` and `Data` folders.

The package layout is intentionally portable:

```text
RouterVPNPortable-ARCH/
  RouterVPNPortable.exe
  Setup-Windows-Runtime.ps1
  App/
    RouterVPN/
      router-vpn-client.exe
      router-vpn-dns.exe
      modes.json
      logical-modes.json
      modes/
      client/
  Data/
    ...created/updated at runtime...
```

`App/RouterVPN` is immutable application/runtime material. `Data` contains mutable/private state: imported routers, generated private profiles, controller state, Windows runtime metadata and the portable browser profile.

The launcher regenerates absolute/WSL paths each time it starts, so moving the **whole** folder to a different drive/path does not bake in the old location.

## 2. PortableApps.com package

The PortableApps source layout uses PortableApps.com Format 3.9 and adds:

```text
App/AppInfo/appinfo.ini
App/AppInfo/installer.ini
Other/
Data/
```

GitHub CI uses the current official PortableApps.com Installer to generate installable `.paf.exe` artifacts for x64 and ARM64. The x64 PAF is then installed and executed on a Windows GitHub runner, installed over itself as an upgrade, and checked to confirm `Data` survives.

To use the PAF with PortableApps Platform, use the Platform's **Apps → Install a New App** flow and select the Router VPN `.paf.exe` artifact. Normal upgrades preserve `Data`.

The `.paf.exe` build is generic: it does not contain a specific user's router credentials. Import `router-vpn-bundle.json` after installation.

## 3. Home Setup Center portable downloads

The home node also publishes private, already-linked packages:

- `router-vpn-windows-portable-amd64.zip`
- `router-vpn-windows-portable-arm64.zip`
- `router-vpn-portableapps-amd64.zip`
- `router-vpn-portableapps-arm64.zip`

These contain the current node's private `Data/routers.json` and generated profile material. Treat them as credentials. Do not publish or share them.

The home PortableApps ZIP is a PortableApps.com Format 3.9 **source/folder package**. The official installable `.paf.exe` is produced in GitHub Actions rather than on the AI Board, so the AI Board remains a host/publisher instead of a Windows build environment.

## Windows full-mode runtime

The controller and app UI are native Windows executables. Router VPN's existing full multi-engine shell paths are Unix-oriented, so Windows Portable routes those scripts through WSL when a usable default distro exists.

Run once:

```powershell
.\Setup-Windows-Runtime.ps1
```

The helper verifies/installs the required WSL-side engines, including WireGuard tools, AmneziaWG, Rosenpass, sing-box with Naive support, Xray, Shadowsocks-rust and V2Ray-plugin. It fails visibly if a required engine is still missing.

After setup, close and reopen `RouterVPNPortable.exe`. The launcher regenerates `Data/modes.windows.json`, translating Windows paths into WSL paths and passing the Router VPN runtime environment through `WSLENV`.

If WSL is not ready, the app reports that dependency as the reason a shell-engine mode is unavailable instead of trying to execute `.sh` files directly on Windows.

## Logical modes

Portable and PortableApps use the same controller binary and logical-mode API as the normal desktop client:

- 16 logical user-facing methods
- raw 20 runtime variants remain internal
- compatible methods expose `Base: Auto / WireGuard / AmneziaWG`
- the alternate base can be tried as a fallback
- raw duplicate `max-quic-wg`, `max-quic-awg`, `max-tls-wg`, and `max-tls-awg` IDs are not separate user-facing rows

## Closing / removable-drive behavior

When Router VPN opens Edge/Chrome/Brave in app-window mode, the portable launcher owns that app window. Closing it causes the launcher to stop Router VPN transports and the controller process it started, allowing the portable folder/removable drive to be moved or ejected cleanly.

`RouterVPNPortable.exe --self-test` is used by CI to verify the real Windows launcher, local controller, 16-mode logical API, mutable `Data` generation, clean shutdown and relocation to another filesystem path.
