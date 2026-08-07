# What this ZIP is

`router-vpn.zip` is the all-in-one project package. It contains the router stack, client source, generated desktop binaries/packages, build scripts, mode definitions, mobile projects, and documentation.

Included:

- Router/AI Board Portainer and SSH installers
- Raw WireGuard and AmneziaWG 2
- VLESS + REALITY + Vision + Chrome uTLS
- PQ VLESS + REALITY + Vision
- Hysteria2/QUIC, Shadowsocks 2022, dual TCP/QUIC profiles
- Generated XHTTP/FinalMask and MAX TLS/MAX QUIC branches on either WireGuard base
- ALL orchestration and AUTO light-to-heavy escalation
- Rosenpass, V2Ray-plugin TLS, NaiveProxy, and exact Maybenot/DAITA integration slots where their external engines are still required
- Private tunnel/LAN-only SOCKS5 using only IP + port, with no username/password
- Runtime-selectable router profiles
- IPv4/IPv6, AdGuard DNS, DAITA-like cover-traffic toggle, and jumbo TUN option
- Port, range, TCP/UDP/both, target-port, and protected-DMZ forwarding controls
- Native controller binaries and packages for Windows, Windows ARM64, macOS Intel/Apple Silicon, Linux, and Unix/BSD/illumos targets
- Windows PortableApps-style packages
- Android APK project/build artifact
- iOS SwiftUI/Xcode project, Packet Tunnel target, unsigned re-signable IPA build, and optional signed IPA workflow
- One unified GitHub Actions workflow at `.github/workflows/build-all.yml`
- The authoritative simple tutorial in `docs/FULL-TUTORIAL.md`

The router generates a separate private `router-vpn-client-bundle.zip` after installation. That file is unique to your router and contains private keys/profile material; it is not a second software project.

Mobile note: the APK and IPA projects build as controller/importer apps, but full native Android `VpnService` and iOS Packet Tunnel transport engines must be linked before those mobile apps can honestly provide all Router VPN tunnel modes themselves.
