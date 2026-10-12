# AdGuard block-page / Xray REALITY port coexistence

For the ASUS GT-BE19000AI and the AI Board at `192.168.50.133`.

## Why the Akamai error happened

AdGuard Home intentionally directs blocked A/AAAA queries to the AI Board. Its custom HTTP block page listens on TCP 80, but the host-networked `router-vpn-xray` process previously listened on TCP 443. Unauthenticated HTTPS connections to a blocked domain therefore reached REALITY, which forwarded them to its camouflage target `www.microsoft.com:443`. That server correctly served a Microsoft certificate and an Akamai `Invalid URL` response instead of your block page.

## New installations

The **standard REALITY listener** now defaults to **TCP 24443**. The separate PQ REALITY listener remains TCP 10443, and the decoy target stays `www.microsoft.com:443`: the target's port is not the server listener port. Keys, authenticated transport, encryption, and PQ modes do not change. A nonstandard port may provide less censorship/traffic camouflage than TCP 443.

The block page remains on TCP 80; with no listener on TCP 443, blocked HTTPS connections will fail normally rather than producing Akamai's error. HTTPS cannot transparently show the custom HTTP block-page HTML without trusted certificate interception. Check for other host services on 443 before assuming it is unused.

## Existing deployment: deliberate opt-in migration

**Do not blindly redeploy and expect your existing listener or clients to move.** Upgrade logic intentionally preserves the current 443 port unless you explicitly opt in.

1. Before touching production, verify 24443/TCP is unused, maintain an independent management route or alternative VPN mode, and back up the Portainer stack config, ASUS router forwarding config, and private Router VPN state. Do not publish credentials to GitHub.
2. Use only a verified, exact-SHA production release compose with matching successful ARM64 images. The tracked `server/portainer-current.yaml` is **not** a ready-to-deploy release.
3. In Portainer set `REALITY_PORT_MIGRATE_TO=24443` on the `router-vpn` stack. The generated compose passes this flag to **`finalize-current` only**. Without it, upgrades keep the preserved port. The finalizer validates the requested port, regenerates Xray server and standard/PQ client configs when their ports disagree, and preserves REALITY identity.
4. Redeploy using the exact-SHA release procedure. Verify the `router-vpn-finalize` job succeeded and `/opt/router-vpn/config/xray/server.json` contains the new `reality-in` port. Restart or recreate **only** `router-vpn-xray` as necessary to pick up atomically replaced read-only bind-mounted config. Confirm it listens on 24443 and no longer owns 443.
5. Update ASUS owned WAN forwards using the existing verified helper: from the **ASUS router**, `REALITY_PORT=24443 /jffs/scripts/router-vpn-forward.sh install` and then `/jffs/scripts/router-vpn-forward.sh verify`. `install` removes/replaces only Router VPN-owned rules and saves the new configuration; it must pass its health preflight. Confirm every other existing forward remains untouched.
6. Re-download/reimport authenticated client profiles so standard REALITY now dials the correct **24443/TCP** port. Old clients configured with 443 will not work after the cutover. Verify external access and VPN leak/fail-closed properties.
7. Verify `http://xtramath.org/` still displays the block page and `https://xtramath.org/` no longer reaches the Microsoft/Akamai fallback. No AdGuard DNS change is necessary.

**Rollback:** Remove `REALITY_PORT_MIGRATE_TO` after reverting to saved 443 state, redeploy the verified release or known-good backup, restart the Xray container, and reinstall the old `REALITY_PORT=443` Router VPN-owned ASUS forwarding config. Verify old clients reconnect. Do not rotate any credentials.

## Temporary stop

In **Portainer → Containers → `router-vpn-xray` → Stop**, or on the AI Board host run `docker stop router-vpn-xray`. This temporarily disables standard/PQ REALITY (and XHTTP on Xray), not AdGuard, the block page, WireGuard, or other independent transport containers. Re-enable with **Start** or `docker start router-vpn-xray` if needed.

Do not stop `router-vpn-transports`, change `REALITY_TARGET`, globally block HTTPS on your ASUS, or disable AdGuard. A generic LAN-to-AI-Board TCP 443 reject rule would also affect legitimate local TLS services and does not reliably identify specific DNS-blocked hostnames.
