# Install Router VPN through Portainer

## 1. Stack source

```text
Repository: https://github.com/Eabusham2/router-vpn.git
Reference:  refs/heads/main
Compose:    server/portainer-current.yaml
```

The repository is public, so Git repository authentication is normally off.

## 2. Environment

Normal values:

```text
WAN_INTERFACE=eth0
LAN_CIDR=192.168.50.0/24
ADGUARD4=192.168.50.133
```

`ENDPOINT` may be omitted/blank for auto-detection. Listener variables already have defaults.

## 3. Deploy

Press **Deploy the stack** / **Pull and redeploy**.

The production Portainer compose is **image-only** and pins custom Router VPN services to exact GitHub-built SHA images. Router-local compilation is reserved for requested client packages inside the Setup Center broker, not for Portainer server images.

Expected one-shots:

```text
router-vpn-init       Exited (0)
router-vpn-finalize   Exited (0)
```

Expected long-running services include agent, WireGuard, AWG, Rosenpass, transports, Xray, Naive, SS-V2Ray, aux, Setup Center broker, and SOCKS5.

## 4. Setup Center

On the LAN:

```text
http://192.168.50.133:8786/
```

Do not WAN-forward `8786`.

Large client packages are generated on demand: matching GitHub artifact first, then a router-local build of only the requested client package if unavailable. Temporary private customization and build/output files are deleted after delivery.

## 5. ASUS forwarding

Use the Setup Center’s `asus-merlin-router-vpn-forwards.sh`.

Default public listeners:

```text
TCP      80      -> 18080
TCP      443     -> 443
UDP      585     -> 585
TCP+UDP  8388    -> 8388
UDP      8443    -> 8443
TCP      10443   -> 10443
TCP      11443   -> 11443
TCP      12443   -> 12443
TCP+UDP  13443   -> 13443
TCP      14443   -> 14443
TCP+UDP  15443   -> 15443
UDP      51820   -> 51820
UDP      51822   -> 51822
```

Never expose `1080`, `8786`, `8787`, `14444`, `9443`, SSH, Portainer, or AdGuard admin.

For the complete app/mode/DNS/testing guide, use `docs/CURRENT-GUIDE.md`.
