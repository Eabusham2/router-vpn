# Start here

This is the **only ZIP you need**. It contains the private-router server stack, Portainer and SSH installers, generated-profile scripts, desktop controller binaries, SOCKS5 support, IPv4/IPv6 routing, AdGuard DNS settings, port/range/protected-DMZ controls, jumbo-payload support where the selected TUN engine permits it, and the iPhone/iPad Xcode project.

## Easiest router installation

Open `docs/INSTALL-PORTAINER.md` and follow it from step 1. Portainer deploys `server/portainer-compose.yaml` from the private GitHub repository.

## After router setup

Download the generated private client bundle from the LAN-only address printed in the init-container logs, then follow `docs/CLIENT.md`.

## iPhone/iPad

Open `docs/IOS.md`. The project is included, but Apple requires your own signing identity, provisioning profiles, Network Extension entitlement, and a linked packet-tunnel engine before a working IPA can be produced.

## Implementation status

Open `docs/STATUS.md`. Modes labeled **Ready** have generated server/client configurations. Modes labeled **Adapter/Integration/Lab** are present in the picker and launcher but stay disabled until their required upstream engine or credentials are installed.
