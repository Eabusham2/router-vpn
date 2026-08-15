# Install Router VPN through Portainer

## 1. Stack source

```text
Repository: https://github.com/Eabusham2/router-vpn.git
Reference:  refs/heads/main
Compose:    server/portainer-current.yaml
```

The repository is public, so Git repository authentication is normally off.

For production, use the release-approved `server/portainer-current.yaml` state whose custom Router VPN services are pinned to one exact GitHub commit-SHA image set. Do not substitute moving tags or a source-build fallback.

## 2. Environment

Normal values:

```text
WAN_INTERFACE=eth0
LAN_CIDR=192.168.50.0/24
ADGUARD4=192.168.50.133
```

`ENDPOINT` may be omitted/blank for auto-detection. Listener variables already have defaults. Keep the existing production environment unless a release explicitly adds a required variable.

## 3. Deploy

Use **Deploy the stack** / **Pull and redeploy** only after the exact release SHA has passed its source/build gates and the deployment change is deliberate.

The production Portainer compose is **image-only**. Router-local compilation is reserved for requested generic client packages inside the Setup Center broker, not for Portainer server images.

Expected one-shots:

```text
router-vpn-init       Exited (0)
router-vpn-finalize   Exited (0)
```

Expected long-running services include agent, WireGuard, AWG, Rosenpass, transports, Xray, Naive, SS-V2Ray, aux, Setup Center broker and SOCKS5.

After deploy verify container state first, then verify:

```text
http://192.168.50.133:8786/healthz = 200
```

Do not treat a successful pull as a successful live VPN deployment by itself.

## 4. Setup Center

On the LAN:

```text
http://192.168.50.133:8786/
```

Do not WAN-forward `8786`.

Generic client-package download policy is:

```text
matching same-SHA GitHub artifact
↓ if unavailable/unusable
bounded local build of requested generic client package only
↓
validate/package secret-free generic app
↓
stream
↓
cleanup temporary output
```

Private node data is linked/imported/paird **separately after installation**. It is not baked into the public generic installer or Portable ZIP.

## 5. ASUS forwarding

Use the Setup Center's `asus-merlin-router-vpn-forwards.sh`, but inspect current router/JFFS state before reinstalling or changing hooks. The helper must preserve unrelated JFFS hook contents.

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

External TCP `80` maps to internal `18080` for ACME. Never convert that to `80 -> 80`.

Never expose `1080`, `8786`, `8787`, `14444`, `9443`, SSH, Portainer or AdGuard admin.

## 6. Release/live validation

After the server is healthy, live release work still includes the relevant physical-device VPN tests, off-LAN Simple Method interoperability, exact selected-node/public-exit proof, DNS/IPv4/IPv6 and leak-negative behavior, native visual QA, Apple signing/notarization where applicable, production smoke tests and ASUS forwarding revalidation.

For the complete app/mode/DNS/testing guide, use `docs/CURRENT-GUIDE.md` and `docs/CURRENT-STATUS.md`.
