# Mobile imported entry to paired Router final

## Requirement and implemented direction

The original August 19 map-first request allows Router and imported/custom nodes
in either hop role. The original requirements and later corrections also require
independent Start Layers, complete saved connection profiles, selected-path DNS,
owned temporary tests, and native tunnel integration. This change adds one
previously missing direction to Android and iOS/iPadOS:

```text
Imported Shadowsocks 2022 entry → independently paired Router Shadowsocks final
```

Execution is Local, inside the application's existing Android VpnService or Apple
PacketTunnel. The imported entry supports `2022-blake3-aes-128-gcm`,
`2022-blake3-aes-256-gcm`, and `2022-blake3-chacha20-poly1305`. Entry and final
retain their separate Off, AES-256-GCM, or AES-256-GCM + XOR whitening choices.
All nine layer combinations are constructed from the original sources.

Other imported entry protocols, other paired final transport families, and
Server/Compare for this new direction remain requirements to implement and
verify. Existing supported directions retain their own admission and proof
rules. This document does not mark the complete external-node requirement or
the complete product delivered.

## Selection and saved state

Android's multihop editor lists eligible imported entries alongside Router
entries. Choosing an imported SS2022 entry allows selection of its paired Router
final. Saving selects that final and the complete Local graph; Connect still
requests permission, starts the native graph, and proves the path.

Apple's multihop editor admits the same imported entry when a paired Router
final is selected. It shows the fixed Shadowsocks final transport and Local
execution for this direction. Saving retains both original node references.

Android connection profiles use schema 6 at the existing private store location.
Add, Load, Update, and Delete retain the imported entry's external policy and
the final node's independent Router policy. Credentials remain in their original
node stores. Older schema-five imported-entry/Tor profiles retain their typed
read path. Validation precedes node or preference writes, and selection rollback
does not overwrite a newer selection.

Permission, Activity rotation, startup, restore, and node-usage accounting retain
the original typed entry and final references. A matching text ID does not turn
an imported node into a paired node. A changed source, protocol, execution
choice, pending permission owner, or Home generation prevents the old request
from starting or being adopted. Startup does not invent a historical Compare
winner for this Local-only direction.

## Compiler and proof ownership

`internal/mobilemultihop/imported_entry.go` composes the actual imported
transport with the paired final transport. The typed constructor accepts the
seven original source inputs, captures their digest, and produces the config,
metadata, and MTU profile together. Metadata or a prebuilt config alone cannot
create an imported-entry proof owner through the legacy constructor.

The imported entry has public-path proof. It never receives a fabricated private
Router API, token, node proof, or entry proof listener. The final retains its
paired private identity and proof lane. Connected requires the imported entry's
expected public address, the final's private identity, the selected DNS policy,
and the original live engine owner. Native peer tests separately check actual
encrypted traffic through both Shadowsocks peers and reject wrong entry keys,
wrong final keys, bypassed final routing, wrong DNS routing, and wrong final
identity.

Application DNS comes from the final's captured policy, including Home AdGuard.
The imported source's standalone DNS configuration remains part of its original
source digest, but it does not replace the final's DNS in this two-hop graph.
An internal transport-validation projection is discarded; it is not the running
DNS config. LAN and IPv6 choices are reconciled from both original policies.
The stronger required protection applies to the one native tunnel.

Legacy paired profiles may omit `node_kind` or contain an empty string. Only
that discriminator is normalized for compilation. The original bytes remain in
the source digest, and the final still needs its paired proof and API authority.
Explicit null, nonstring, or external final kinds are rejected.

Android captures the explicitly selected Local execution in a copied final
profile. A stored Server/Compare preference from an imported node bundle cannot
override that new graph choice. The complete original bundle and its source
digest still govern preparation and restoration; selecting Local does not
rewrite that bundle or grant Server execution to this direction.

## Measurements, MTU, cancellation, and restoration

Typed hop and MTU factories require the same successful native controller and
core instance. The public entry and private final retain different measurement
kinds. The hop adapter maps its public entry role only to the captured native
entry outbound; it does not relax general hop validation. Network changes,
owner replacement, or retirement revoke those factories and their retained
operations.

The complete compiled graph supplies the MTU plan. Fixed-value conflicts are
validated, and compatible Jumbo is virtual TUN capacity, not a claim of a
9,000-byte physical path. The existing Auto/Retest/Cancel transaction retains
its original native interface and proof owner. No cached measurement becomes
fresh proof merely because a source compiles.

Android stages original sources in its private session directory and recreates
the typed native owner from those sources before launch. Config, metadata, and
source digest must match the recreated owner. A cancelled preparation retains
ownership of its exact directory until cleanup is proved. Failed cleanup remains
reachable through Disconnect and blocks replacement startup. The service closes
an unadopted typed preparation and retains its usual native teardown rules after
adoption.

Both hosts restore the same captured Local direction and source identities.
Neither substitutes a paired entry for an import nor reruns an unrelated
Compare selection during restoration.

## Executable gates and evidence limits

The shared compiler/runtime tests cover the independent layer matrix, all three
entry ciphers, policy and source ownership, strict paired-final admission,
public-entry/private-final/DNS proof, full Run-to-Healthy measurement ownership,
retirement, and malformed or forged source rejection.

`deploy/test_mobile_imported_entry.py` consumes the exact eleven shared source
fixtures and the eleven emitted by the actual Android helper. The pinned
libbox constructor must reproduce their original config and source digest.
Its actual native parser, MTU profile reader, and MTU planner must accept them.
The required fixture gate rejects missing, skipped, duplicated, foreign, or
malformed cases. The Linux native peer gate additionally executes two encrypted
Shadowsocks peers and the negative routing/key controls.

Android gates exercise the actual helper, saved-profile store, permission
controller, startup policy, multihop runtime, MTU session, node-usage recorder,
and service composition with explicit OS/native boundaries. Deliberate source
mutations must fail the intended assertions. The Java syntax gate covers every
shipping Java source; the actual SDK/AAR APK build remains separately required.

`deploy/test_ios_imported_router_pinned.py` is mandatory in Apple smoke and
release preparation. It consumes the actual Swift-produced eleven-graph matrix
and requires native parser verdicts for all of it. Swift harnesses cover
selection, profiles, restoration, typed MTU, and PacketTunnel composition.
Local Swift/Xcode execution was unavailable during implementation; Python source
checks and a Go helper build are not reported as an Apple native pass.

Exact-SHA Android/iOS builds, release publication, physical-device routing,
permission and network transitions, leaks, off-LAN interoperability, visual
acceptance, and Apple signing/distribution are distinct evidence stages. No
private deployment or physical-device acceptance is established by these local
tests.
