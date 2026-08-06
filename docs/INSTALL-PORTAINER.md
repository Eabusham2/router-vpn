# Install through Portainer

## 1. Reserve the AI Board address

1. Open the ASUS router app or `http://192.168.50.1`.
2. Open **LAN → DHCP Server**.
3. Reserve the AI Board/Portainer host as `192.168.50.133`.
4. Confirm AdGuard Home is reachable at that address.

## 2. Create a read-only GitHub token

1. Open GitHub → **Settings → Developer settings → Personal access tokens → Fine-grained tokens**.
2. Create `router-vpn-portainer`.
3. Repository access: **Only select repositories → router-vpn**.
4. Permission: **Contents: Read-only**.
5. Copy the token.

## 3. Deploy

1. Open ASUS **AI Board → Portainer**.
2. Select **Stacks → Add stack → Repository**.
3. Name: `router-vpn`.
4. Repository URL: `https://github.com/Eabusham2/router-vpn.git`.
5. Reference: `refs/heads/main`.
6. Compose path: `server/portainer-compose.yaml`.
7. Enable repository authentication.
8. Username: `Eabusham2`.
9. Password/token: paste the fine-grained token.
10. Add:

```text
WAN_INTERFACE=eth0
LAN_CIDR=192.168.50.0/24
LAN_CIDR6=fd00::/8
ADGUARD4=192.168.50.133
ENDPOINT=
WG_PORT=51820
AWG_PORT=585
REALITY_PORT=443
HY2_PORT=8443
SS_PORT=8388
XRAY_PQ_PORT=9443
REALITY_TARGET=www.microsoft.com:443
```

11. Press **Deploy the stack**.
12. Wait for `router-vpn-init` to exit with code `0`.
13. Confirm every other service is running.

The endpoint is intentionally blank. It is selected later in the app and is not compiled into the client.

## 4. Verify the firewall

1. Portainer → `router-vpn-agent` → **Console**.
2. Select `/bin/sh`.
3. Run:

```sh
nft list table inet router_vpn_guard
```

4. Confirm the table is listed.

## 5. ASUS inbound rules

Forward to `192.168.50.133`:

```text
UDP 51820
UDP 585
TCP 443
UDP 8443
TCP+UDP 8388
TCP 9443
```

Do not forward TCP `1080`, `8786`, `8787`, SSH, Portainer, or the AdGuard admin port.

For arbitrary client-requested ports/ranges/protected DMZ:

1. Confirm Step 4 passed.
2. ASUS → **WAN → DMZ**.
3. Set the AI Board `192.168.50.133` as DMZ.

For IPv6:

1. ASUS → **Firewall → IPv6 Firewall**.
2. Allow the VPN listener ports to the AI Board global IPv6 address.
3. Keep ICMPv6 allowed.

## 6. Download your private client bundle

While on the home LAN, open:

```text
http://192.168.50.133:8786/router-vpn-client-bundle.zip
```

Do not expose port `8786` publicly.
