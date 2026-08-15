# Router VPN on Windows — Portable ZIP

Router VPN ships normal Windows packages plus tested no-system-install Portable ZIP layouts. PortableApps.com/PAF packaging is retired; Router VPN does not publish or advertise a PortableApps package.

## Portable ZIP artifacts

- `RouterVPN-Portable-Windows-amd64.zip`
- `RouterVPN-Portable-Windows-arm64.zip`

Extract the whole folder anywhere, including a removable drive, then run:

```text
RouterVPNPortable.exe
```

Do not separate the launcher from its `App` and `Data` folders.

Current layout is approximately:

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
      client/
      modes/
      LICENSE
  Data/
    ...writable/private state created at runtime...
```

`App/RouterVPN` is immutable application/runtime material. `Data` is writable and holds settings, private linked-node state, generated profiles and native Windows engine/runtime material.

The ZIP is **generic and secret-free**. It contains no pre-linked home node. On first run the launcher creates a blank writable node store under `Data`; add nodes separately using import/pairing. Router VPN state is kept with the Portable folder rather than being intentionally written to AppData or the registry by the portable launcher/app.

## Native daily-use app

`RouterVPNPortable.exe` starts the local Router VPN controller, opens the native Windows WPF app from `App/RouterVPN/client/RouterVPN-Windows-App.ps1`, then cleanly stops the controller it owns when the native window exits.

The current Portable product does **not** use Edge/Chrome app mode, an embedded browser/WebView, a portable browser profile or WSL as the native VPN dataplane.

`RouterVPNPortable.exe --self-test` is used by CI to verify the real launcher/controller/native-app contract, clean shutdown and relocation to a different filesystem path.

## Native Windows runtime

Run once when native layered TUN modes require their external engines:

```powershell
.\Setup-Windows-Runtime.ps1
```

or use:

```text
RouterVPNSetupRuntime.exe
```

The runtime helper prepares/verifies the pinned native Windows engines required by supported layered modes. Those runtime files live under `Data` so they move with the Portable folder. If a required engine is absent or unsupported, the capability remains unavailable with an exact reason rather than being replaced by a compatibility-layer engine.

Windows source includes native raw WireGuard, full-device layered TUN/DNS paths, Windows firewall kill-switch handling and real multihop where supported. WSL is not counted as the native Windows VPN implementation.

## Custom standard exits

Validated Windows custom exits support WireGuard, SOCKS5, Shadowsocks and Hysteria2. OpenVPN 2.7 profile import and native helper/adapter source are implemented as the Windows OpenVPN target, but the current product capability deliberately reports OpenVPN unavailable until strict Windows lifecycle cleanup passes native leak tests. Connected is withheld until the exact expected public exit is proven for every supported exit.

## Logical modes

Portable uses the same controller and logical-mode API as the normal Windows package:

- 16 logical user-facing modes
- 20 raw runtime profiles remain internal
- compatible methods expose `Base: Auto / WireGuard / AmneziaWG`
- the alternate compatible base can be tried as a real fallback
- raw duplicate WG/AWG MAX variants are not separate user-facing rows

## Home Setup Center downloads

The Setup Center serves the matching generic Portable package for the requested architecture. It prefers the matching same-SHA GitHub artifact and, if unavailable/unusable, can build only the requested generic package locally with the bounded router-local client build path.

The downloaded generic ZIP still contains **no linked home secrets**. Link/import one or more private Router VPN nodes after installation. Private bundles, pairing material and external-profile credentials are separate from the generic package and must not be published.

## Closing / removable-drive behavior

When the native WPF window exits, the portable launcher stops only the Router VPN controller/processes it owns and performs Router VPN emergency cleanup so the folder/removable drive can be moved or ejected cleanly.

Physical Windows validation remains a release gate for real VPN permission/elevation, full-device routing, DNS/IPv4/IPv6, reconnect/network-change behavior, leak-negative kill-switch behavior, custom exits and both amd64/arm64 package variants on real hardware.
