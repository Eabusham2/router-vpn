# Router VPN native applications

Router VPN client packages are **generic application/runtime packages**. Installing an app and linking a home router are separate operations. The app is installed once; private router/node data can then be added, replaced, revoked, or expanded without reinstalling the application.

## Windows

The Windows application is native WPF (`PresentationFramework`) and talks to the loopback Router VPN controller at `127.0.0.1:8788`. Installed and Portable packages launch the WPF application, not Edge/Chrome app mode or a WebView wrapper. Portable self-tests must exit the native UI/controller cleanly and still pass after the folder is relocated.

## macOS

The macOS package contains a native AppKit `RouterVPN.app` for amd64 and arm64. It owns a sibling Router VPN controller only when it starts that controller itself. Closing the app performs Router VPN emergency cleanup and stops only the owned process. The app contains no WebKit view.

Unsigned/local builds use the targeted System Settings → Privacy & Security → Open Anyway flow only after verifying the artifact. Do not globally disable Gatekeeper. Signed/notarized distribution is the expected long-term release path.

## Linux

Linux packages contain a native GTK3 application for amd64 and arm64, built on matching native GitHub runners. It uses libcurl/json-glib for the loopback controller API and does not launch or embed a browser. The package remains generic and requires GTK3/libcurl/json-glib desktop runtime libraries.

## Android

Android uses native `VpnService` paths: WireGuard, native AmneziaWG, and the pinned embedded libbox path for supported layered modes. AUTO/SMART/CUSTOM require selected-node private path proof. Strict embedded sessions require Android Always-on + lockdown proof; raw WG/AWG fail closed when strict policy is requested. The first real Android multihop subset is standard-WG entry → supported Shadowsocks/Hysteria2 exit with exit-node proof; AWG-entry and incompatible mixed-engine multihop remain unavailable rather than simulated.

## iOS / iPadOS

The PacketTunnel target runs the pinned WireGuardKit engine for real raw WireGuard. AUTO may choose the proven WireGuard path; unsupported AmneziaWG/layered/ALL/MAX/multihop paths remain unavailable. Strict Apple kill-switch semantics remain fail closed until a platform lifecycle is proven. The tunnel verifies the exact selected node identity before reporting success.

## Router linking and node identity

A private router bundle import is data, not application installation. Generic packages contain no linked router secrets. The desktop importer stages decoded private files in a bounded `0700` temporary tree, uses `0600` files, validates names/counts/sizes and the WireGuard server public-key-derived node identity, then atomically commits the generated profile. A failed import must not leave a partially visible node.

The stable public proof identity is derived from the server WireGuard public key. `Connected` requires the private Router VPN proof endpoint to return the exact expected node ID and proof kind. Generic Internet reachability or `{"ok":true}` alone is not a VPN path proof.
