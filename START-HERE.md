# Start here

Use only **`router-vpn.zip`**. It is the complete source package.

It contains:

- Portainer and SSH router installers
- Raw WireGuard and AmneziaWG 2 server/client generation
- REALITY, PQ-VLESS, Hysteria2/QUIC, and Shadowsocks generated profiles
- Private authenticated SOCKS5
- Desktop AUTO/manual mode controller
- Runtime-selectable router profiles; no backend is fixed into the binary
- IPv4/IPv6, AdGuard DNS, jumbo-payload option, and port/range/protected-DMZ controls
- Prebuilt desktop/router binaries
- Native iOS Xcode project and signed-IPA workflow

The router creates a second file after installation:

- **`router-vpn-client-bundle.zip`** — private keys and profiles for that particular router. Do not share it.

## Order

1. Install the home router stack with `docs/INSTALL-PORTAINER.md` or `docs/INSTALL-SSH.md`.
2. Download the generated `router-vpn-client-bundle.zip` while on your home LAN.
3. Install it on a Mac/Linux travel device using `docs/CLIENT.md`.
4. In the app, import `router-vpn-bundle.json`, enter/select the router public IP, IPv6, or hostname, and connect.
5. Build/sign the iPhone project with `docs/IOS.md` when Apple entitlements are available.

You can import multiple routers. Each router keeps its own keys, endpoint, credentials, and generated mode files.
