# Install Router VPN through Portainer

## 1. Exact release source

The tracked repository file:

```text
server/portainer-current.yaml
```

is the reproducible image-only production **template/baseline**. It is not the deploy target for a newer `main` commit merely because its filename says `current`.

For production, choose one verified exact `main` SHA and require both its normal release gates and these same-SHA workflows to succeed:

```text
Publish ARM64 Portainer images
Exact-SHA production compose
```

Then download the `RouterVPN-production-compose-<sha>` artifact, verify the included `.sha256`, and verify all Router VPN custom image tags plus `ROUTER_VPN_GITHUB_SHA` equal that exact SHA. Use the generated `RouterVPN-Portainer-<sha>.yaml` as the Portainer stack definition. Full contract: `docs/PRODUCTION-RELEASE.md`.

The repository is public, so Git repository authentication is normally off for source browsing; the generated release YAML itself is the deliberate production input.

## 2. Environment

Normal values:

```text
WAN_INTERFACE=eth0
LAN_CIDR=192.168.50.0/24
ADGUARD4=192.168.50.133
```

`ENDPOINT` may be omitted/blank for auto-detection. Listener variables already have defaults. Keep the existing production environment unless a release explicitly adds a required variable.

## 3. Deploy

Update the `router-vpn` stack with the verified generated exact-SHA YAML only after the exact release SHA has passed its source/build/image/materialization gates and the deployment change is deliberate.

The production Portainer compose is **image-only**. Router-local compilation is not a Portainer server-image fallback; the only approved production-host client build fallback is the bounded requested **Windows x64/ARM64 installed/Portable** generic package path.

Expected one-shots:

```text
router-vpn-init       Exited (0)
router-vpn-finalize   Exited (0)
```

Expected long-running services include agent, WireGuard, AWG, Rosenpass, transports, Xray, Naive, SS-V2Ray, aux, Setup Center broker and SOCKS5.

After deploy verify container state first, exact running image/provenance SHAs second, then verify:

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
↓ only for Windows x64/ARM64 installed/Portable when unavailable
bounded local build of that requested generic Windows package only
↓
validate/package secret-free generic Windows app
↓
stream
↓
cleanup temporary output
```

macOS and Linux require matching same-SHA artifacts or source built in their proper native build environments; the AI Board never substitutes for those native environments. Android and iOS/iPadOS never use router-local builds. Private node data is linked/imported/paired **separately after installation**. It is not baked into the public generic installer or Portable ZIP.

## 5. ASUS forwarding

Use the Setup Center's `asus-merlin-router-vpn-forwards.sh`. The current helper is fail-open for ordinary household Internet: it installs only direct IPv4 WAN-interface + protocol + exact-port DNAT rules and matching destination-scoped NEW-only FORWARD rules, all tagged `ROUTER_VPN`. It does not use a broad WAN catch-all chain, change built-in policies, add DROP/REJECT, modify IPv6, touch unrelated ASUS/AT&T rules, or disable hardware acceleration.

Before new exposure is added the helper requires the private Setup Center health endpoint on the AI Board. A failed health/config/rule install removes only Router VPN-owned exposure; LAN -> WAN Internet remains untouched. Repeated `nat-start` / `firewall-start` calls use `iptables -C` and do not duplicate or churn healthy rules.

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

External TCP `80` maps to internal `18080` for ACME. Current source still uses public OverTLS `14443/TCP` and legacy SSR `15443/TCP+UDP`. Never expose `22/53`, `1080`, `3000`, `8786-8793`, `9443`, `14444`, SSH, Portainer or AdGuard management.

The helper supports `status`, `apply`, `verify`, and `remove` in addition to the component `apply-nat` / `apply-filter` hook actions. `remove` preserves every unrelated line in `nat-start` and `firewall-start`.

No-reboot migration/update:

```bash
curl -fsS http://192.168.50.133:8786/asus-merlin-router-vpn-forwards.sh | ssh ROUTER_USER@192.168.50.1 'cat >/tmp/router-vpn-forwards.sh && chmod 755 /tmp/router-vpn-forwards.sh && sh /tmp/router-vpn-forwards.sh install && /jffs/scripts/router-vpn-forward.sh verify'
```

## 6. Release/live validation

After the server is healthy, live release work still includes the relevant physical-device VPN tests, off-LAN Simple Method interoperability, exact selected-node/public-exit proof, DNS/IPv4/IPv6 and leak-negative behavior, native visual QA, Apple signing/notarization where applicable, production smoke tests and ASUS forwarding revalidation.

For the complete app/mode/DNS/testing guide, use `docs/CURRENT-GUIDE.md` and `docs/CURRENT-STATUS.md`.
