# Install through Portainer

## 1. Reserve the AI Board address

1. Open the ASUS router app or `http://192.168.50.1`.
2. Open **LAN → DHCP Server**.
3. Reserve the AI Board/Portainer host as `192.168.50.133`.
4. Confirm AdGuard Home is reachable at `192.168.50.133`.

## 2. Create a read-only GitHub token

1. Open GitHub → **Settings → Developer settings → Personal access tokens → Fine-grained tokens**.
2. Create a token named `router-vpn-portainer`.
3. Repository access: **Only select repositories → router-vpn**.
4. Repository permission: **Contents: Read-only**.
5. Copy the token.

## 3. Deploy the private repository

1. Open ASUS **AI Board → Portainer**, or open Portainer directly.
2. Choose **Stacks → Add stack → Repository**.
3. Name: `router-vpn`.
4. Repository URL: `https://github.com/Eabusham2/router-vpn.git`.
5. Reference: `refs/heads/main`.
6. Compose path: `server/portainer-compose.yaml`.
7. Enable authentication.
8. Username: `Eabusham2`.
9. Password/token: paste the fine-grained token.
10. Add these environment variables:

```text
WAN_INTERFACE=eth0
LAN_CIDR=192.168.50.0/24
LAN_CIDR6=fd00::/8
ADGUARD4=192.168.50.133
ENDPOINT=AUTO
WG_PORT=51820
AWG_PORT=585
REALITY_PORT=443
HY2_PORT=8443
SS_PORT=8388
XRAY_PQ_PORT=9443
REALITY_TARGET=www.microsoft.com:443
```

11. Press **Deploy the stack**.
12. Wait until `router-vpn-init` exits with code `0` and the remaining containers show **running**.
13. Open the `router-vpn-init` logs and confirm the bundle URL was printed.

## 4. Test the firewall before enabling ASUS DMZ

1. In Portainer, open `router-vpn-agent` → **Console**.
2. Choose `/bin/sh` and connect.
3. Run:

```sh
nft list table inet router_vpn_guard
```

4. Confirm the table exists.
5. Exit the console.

## 5. Allow inbound traffic

For fixed VPN listeners only, add ASUS port-forward rules to `192.168.50.133`:

```text
UDP 51820
UDP 585
TCP 443
UDP 8443
TCP+UDP 8388
TCP 9443
```

For client-controlled arbitrary port/range/protected-DMZ forwarding:

1. Open ASUS **WAN → DMZ**.
2. Set the DMZ device to `192.168.50.133` only after Step 4 passed.
3. Never separately expose TCP 22, 1080, 8786, 8787, 9443-Portainer, or the AdGuard administration port.

For IPv6:

1. Open ASUS **Firewall → IPv6 Firewall**.
2. Allow the VPN listener ports to the AI Board global IPv6 address.
3. Keep ICMPv6 allowed.

## 6. Download the private client bundle

While connected to the home LAN, open:

```text
http://192.168.50.133:8786/router-vpn-client-bundle.zip
```

Do not expose port `8786` to the internet.

## 7. Diagnostics

In Portainer, open `router-vpn-init` logs for generated credentials. For full shell diagnostics use `docs/INSTALL-SSH.md`.
