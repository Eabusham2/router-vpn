# Router VPN on Windows — Portable ZIP

Router VPN ships a normal Windows package plus one tested no-system-install Portable ZIP layout. PortableApps.com/PAF packaging was retired because the official packager was not reliable enough in unattended CI; Router VPN does not publish or advertise a PortableApps package.

## Portable ZIP

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
  RouterVPNSetupRuntime.exe
  Setup-Windows-Runtime.ps1
  README.txt
  App/
    RouterVPN/
      router-vpn-client.exe
      router-vpn-dns.exe
      modes.json
      logical-modes.json
      modes/
      client/
      LICENSE
  Data/
    ...created/updated at runtime...
```

`App/RouterVPN` is immutable application/runtime material. `Data` contains mutable/private state: imported routers, generated private profiles, controller state, Windows runtime metadata and the portable browser profile.

The launcher regenerates absolute/WSL paths each time it starts, so moving the **whole** folder to a different drive/path does not bake in the old location.

## Home Setup Center portable downloads

The home node provides private, already-linked packages on demand:

- `router-vpn-windows-portable-amd64.zip`
- `router-vpn-windows-portable-arm64.zip`

The Setup Center first tries the matching short-lived GitHub Actions artifact, overlays the current node's private data in a temporary directory, streams the ZIP, then deletes the temporary copy. If no usable GitHub artifact is available, the ARM64 AI Board compiles only the requested Windows Portable architecture locally, builds that one private ZIP in temporary storage, streams it, then deletes the temporary build/output.

These home-linked ZIPs contain private profile material. Treat them as credentials and do not publish or share them.

## Windows full-mode runtime

The controller and app UI are native Windows executables. Router VPN's existing full multi-engine shell paths are Unix-oriented, so Windows Portable routes those scripts through WSL when a usable default distro exists.

Run once:

```powershell
.\Setup-Windows-Runtime.ps1
```

or use `RouterVPNSetupRuntime.exe`.

The helper verifies/installs the required WSL-side engines, including WireGuard tools, AmneziaWG, Rosenpass, sing-box with Naive support, Xray, Shadowsocks-rust and V2Ray-plugin. It fails visibly if a required engine is still missing.

After setup, close and reopen `RouterVPNPortable.exe`. The launcher regenerates `Data/modes.windows.json`, translating Windows paths into WSL paths and passing the Router VPN runtime environment through `WSLENV`.

If WSL is not ready, the app reports that dependency as the reason a shell-engine mode is unavailable instead of trying to execute `.sh` files directly on Windows.

## Logical modes

Portable uses the same controller binary and logical-mode API as the normal desktop client:

- 16 logical user-facing methods
- raw 20 runtime variants remain internal
- compatible methods expose `Base: Auto / WireGuard / AmneziaWG`
- the alternate base can be tried as a fallback
- raw duplicate `max-quic-wg`, `max-quic-awg`, `max-tls-wg`, and `max-tls-awg` IDs are not separate user-facing rows

## Closing / removable-drive behavior

When Router VPN opens Edge/Chrome/Brave in app-window mode, the portable launcher owns that app window. Closing it causes the launcher to stop Router VPN transports and the controller process it started, allowing the portable folder/removable drive to be moved or ejected cleanly.

`RouterVPNPortable.exe --self-test` is used by CI to verify the real Windows launcher, local controller, 16-mode logical API, mutable `Data` generation, clean shutdown and relocation to another filesystem path.
