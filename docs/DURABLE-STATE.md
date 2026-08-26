# Durable state and transaction safety

This document describes the **current source contract** for Router VPN durable/private state. It is not physical-device, production-deployment, off-LAN, or release evidence by itself. Exact-current CI/artifact/native/runtime gates remain separate.

## Core invariant

If an operation reports failure, Router VPN must not silently leave a half-adopted state across RAM, disk, live networking, or recovery metadata.

If rollback itself cannot complete, Router VPN must report that truthfully and keep enough durable recovery state to retry safely. A successful source write is not the same thing as a proven shipped/runtime result.

## Client private stores

Authoritative client JSON/state stores use a common private-store boundary:

- regular files only; symlink targets are rejected;
- bounded reads;
- existing private stores converge to mode `0600` where appropriate;
- random same-directory temporary files;
- write + file sync + close before rename;
- atomic rename as the commit point;
- no fallible post-rename permission step that could make callers roll RAM back after disk already committed.

This covers the main client config, `routers.json`, whole-connection profile storage, setup-profile metadata, and startup/last-good runtime memory.

Router profile Save/Select/Delete/Import participate in the backend mutation ownership boundary. Save/Select restore the previous in-memory selection/profile state when persistence fails.

## Session-bound result adoption

Long-running measurements or proofs that write state must capture the identity they measured and re-prove it before adoption.

Examples include:

- Fastest-node selection;
- public-exit proof;
- DNS Retest measurement fields;
- MTU Retest;
- startup/last-successful runtime memory.

MTU Retest remains explicitly two-phase: measure first, re-prove the same session/profile/path, then apply/persist. A stale result is rejected. Persistence or post-adoption freshness failure restores live MTU and the previous durable measurement fields.

## Router-agent privileged state

Privileged router-agent state uses strict private regular files with bounded reads and atomic publication. Group/world-readable, symlinked, non-regular, corrupt, or unsupported state fails closed where it is security-sensitive.

Forwarding-extension ownership and Protected DMZ use transaction semantics across RAM, durable metadata, and live nftables state. A failed live DMZ adoption attempts to restore both the previous durable intent and previous live rules. If either restoration step fails, the API reports rollback as incomplete.

Admin forwarding/LAN/ban/revoke mutations similarly surface rollback failures rather than silently discarding them.

Stop / Emergency Stop / Resume state uses the same privileged private-state primitive. Emergency Stop remains scoped to Router VPN WG/AWG peers and does not become a generic Docker or host-destructive control.

## Endpoint synchronization

Endpoint synchronization is one staged multi-file transaction.

It owns only:

- raw WireGuard/AmneziaWG `Endpoint` fields; and
- the owned home Router VPN profile endpoint (`id=home`, `node_kind=router-vpn`).

It does **not** recursively rewrite arbitrary `server` or `address` fields and does not alter linked external nodes or unrelated Router VPN profiles.

All owned changes are computed and staged before adoption. If a later replacement fails, already-adopted files are restored from captured originals. The obsolete broad endpoint rewrite script remains removed.

## DNS benchmark ownership

The server DNS benchmark is measurement-only.

It publishes private atomic `config/dns-fastest.json` measurement data and does not mutate current `routers.json` DNS policy. Fresh bundle generation may consume the benchmark as measured default metadata, but running the benchmark cannot overwrite a newer user-selected DNS host/mode/policy.

## Exact-SHA updater recovery

The update controller treats persisted recovery state as a hard transaction boundary.

Before the first Portainer mutation it requires the current production stack to resolve to one exact SHA and saves that exact compose as a private rollback snapshot.

The update sequence is:

1. persist a pre-deployment recovery checkpoint;
2. preserve the old updater while phase-one target services are applied;
3. prove core health;
4. persist `finalizing` before replacing the updater itself;
5. apply the full exact target;
6. prove full health and prove the Portainer compose is exactly the target SHA;
7. only then persist `complete` and retire the rollback snapshot.

Any Portainer mutation/health/identity failure after the rollback snapshot boundary restores the private previous compose, proves the full core health contract, and re-reads Portainer to prove the previous exact SHA again.

Terminal `failed` is written only after that prior exact stack is restored and health/identity-proved. If rollback cannot complete, durable status remains `rolling-back` so restart reconciliation retries recovery instead of forgetting a potentially mixed deployment.

Restart reconciliation handles interrupted `applying`, `rolling-back`, and `finalizing` states conservatively. A finalizing restart becomes complete only when the current stack is already exactly the target SHA and passes health verification; otherwise the previous exact snapshot is restored.

Updater state, rollback snapshots, Portainer API credentials, and TLS pin inputs are private bounded regular files and fail closed on unsafe/corrupt recovery state.

## Stable generated credentials and identities

Credential-bearing generated state follows preserve-or-fail-closed semantics:

- a genuinely missing credential family may be generated once;
- a complete valid existing family is preserved;
- partial, corrupt, inconsistent, or symlinked preserved state does not silently rotate into new credentials that linked clients do not know.

Related files are staged/validated before multi-file adoption where consistency spans more than one file.

Covered source families include:

- Setup Center access token;
- router-agent/node-proof identity;
- WG/AWG client/server configuration publication;
- Hysteria2 TLS certificate/private-key pair;
- Shadowsocks/Hysteria2 generated secrets and configs;
- REALITY/PQ/Xray identity and client/server configs;
- SS+V2Ray/Naive credentials and client metadata;
- OverTLS/SSR auxiliary credentials;
- Rosenpass server/WG-PQ/AWG-PQ identity;
- advanced XHTTP/MAX REALITY state;
- MAX Rosenpass overlays;
- derived split/MAX combined profiles;
- private `client.json`, `routers.json`, bundle JSON, and `CREDENTIALS.txt` publication.

Candidate transport/Xray/TLS/XHTTP states are validated before their authoritative files are replaced when the relevant runtime validator is available in the generation environment.

## Derived Setup Center assets

`setup-assets.json` and the generated Setup Center HTML can contain private import payloads, so they remain `0600` and are served only through the authenticated private Setup Center boundary.

They are **derived presentation data**, not stable identity or active policy. Finalization fails if required Setup assets cannot be generated, and they can be regenerated from already-transactional private source material.

Persistent unauthenticated/static node bundles and `CREDENTIALS.txt` are explicitly removed from the downloads directory. Private bundles are produced on demand by the authenticated broker and cleaned up after delivery.

## Release gate

`deploy/durable-state-transaction-audit.py` is the authoritative source gate for this safety class. It is invoked by `deploy/release-orchestration-audit.py`, which the exact-SHA release candidate already runs.

The durable-state gate checks source invariants and executes focused behavior/fault-injection tests for private publication, endpoint rollback, DNS ownership, Setup Center credential preservation, and generated-state preservation.

A green durability audit proves only the source/release-gate contract for that exact SHA. The project still requires the exact-current native/package/image chain and then physical/live/production validation before release.