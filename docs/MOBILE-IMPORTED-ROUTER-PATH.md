# Mobile imported entry to paired Router final

Source scope reconciled November 6, 2026, through `30a5fff9`. Current admission,
required executable inventories, earlier observed results, and pending native/device
acceptance are distinguished below. The complete continuation evidence is in
[CONTINUATION-EVIDENCE-2026-11-06.md](CONTINUATION-EVIDENCE-2026-11-06.md).

## Requirement and implemented direction

The original August 19 map-first request allows Router and imported/custom nodes
in either hop role. The original requirements and later corrections also require
independent Start Layers, complete saved connection profiles, selected-path DNS,
owned temporary tests, and native tunnel integration. Android and iOS/iPadOS
implement the Local compiler and host admission for the following captured
sources. These rows do not by themselves establish native-package or device acceptance:

| Imported entry | Independently paired final transports | Captured graph cases |
|---|---|---:|
| Shadowsocks 2022 or Hysteria2 | Shadowsocks, Hysteria2, WireGuard, AmneziaWG Fast, AmneziaWG Strong | 100 |
| WireGuard or AmneziaWG | Shadowsocks or Hysteria2 | 36 |
| WireGuard or AmneziaWG | WireGuard, AmneziaWG Fast or AmneziaWG Strong | 54 |
| SOCKS5 | Shadowsocks, Hysteria2, WireGuard, AmneziaWG Fast, AmneziaWG Strong | 45 |
| SOCKS5 | REALITY/Vision, both independently captured Start Layers Off | 1 |
| OpenVPN, TCP or UDP outer transport | Shadowsocks, Hysteria2, WireGuard, AmneziaWG Fast, AmneziaWG Strong | 90 |
| HTTP CONNECT or HTTPS CONNECT | Shadowsocks 2022, both Start Layers Off, captured Home/custom literal TCP DNS | 12 |

The original-source inventory now contains 338 captured cases: the earlier
247 proxy/packet/SOCKS5/CONNECT cases, 90 OpenVPN cases, and one separately
bounded SOCKS5 to REALITY/Vision case. The OpenVPN cases retain two original
outer networks, five paired finals and nine independent entry/final layer pairs.
The twelve retained baseline CONNECT cases use two entry protocols, three SS2022
final ciphers and two selected literal TCP DNS policies. Each of the five
non-Xray SOCKS5 finals supports all nine independent entry/final Start Layer
pairs; REALITY/Vision currently requires both layers Off. The earlier five pairs with both layers Off, four
SOCKS5-to-SS/Hysteria pairs with only a final layer, six SOCKS5-to-WG/AWG
pairs with only a final layer, and ten pairs with only an entry layer remain
in the matrix. Twenty pairs with both layers enabled extended the published
215-case matrix to 235 before the CONNECT addition. These counts describe
executable configurations, not completed user requirements. The separately
captured configured-CONNECT inventory adds 24 required cases, and the selected
encrypted-DNS inventory adds 44 accepted captures plus four plain-carrier H3
refusals. Those inventories remain separate from the 338 original-source files;
they are not added into a product-completion denominator.

The later Android host correction `95f36b95` is required for the daily Connect,
Home transition, startup and cold reattachment paths to use this capability
consistently. Earlier duplicated protocol lists still rejected SOCKS5 after
the producer and native-peer matrix passed. Those callers and usage now consult
the same captured entry/final capability. The recorded runtime composed with the
Home store passed 35 cases and rejected three old-guard mutations at that
historical checkpoint; later host inventories and results are recorded in the
continuation evidence. Native proof and OS boundaries remain explicit doubles
in that host test. Producer/native
configuration evidence alone did not establish this daily-app admission.

Packet composition validates the complete data, handshake, cookie and enabled
junk envelope, including the final's separately captured Start Layer, before
constructing a native owner.

Execution is Local, inside the application's existing Android VpnService or Apple
PacketTunnel. A Shadowsocks entry supports `2022-blake3-aes-128-gcm`,
`2022-blake3-aes-256-gcm`, and `2022-blake3-chacha20-poly1305`. Hysteria2 preserves
its original server, port, password and verified TLS server name. For the five
non-Xray paired final families reached through non-CONNECT entries, entry and
final retain their separate Off, AES-256-GCM, or AES-256-GCM + XOR whitening
choices. All nine layer combinations for each admitted pair are constructed
from the original sources. Two alternate SS2022 ciphers are retained for each final family.
For SS2022/Hysteria2 entries, each of the five final families has twenty cases:
nine independent layer pairs for SS2022 AES-256 and Hysteria2, plus the two alternate SS2022 entry
ciphers with both layers Off. Thirty-six additional packet-entry cases cover both
packet protocols, both proxy finals and all nine independent layer pairs.
WireGuard and AmneziaWG retain the original endpoint, private key, peer key, PSK,
addresses, AllowedIPs, keepalive and packet MTU. AmneziaWG also retains its exact
obfuscation parameters. The packet endpoint belongs to the same native graph;
this does not start a second system VPN. The Hysteria2 final retains its original TLS
server name, password, certificate trust and Salamander parameters. Its optional
outer AES transport comes from the same final node's original SS asset map,
separate from the inner QUIC transport and the imported entry's own layer.
WireGuard and AmneziaWG finals likewise use their own raw same-node SS assets
when a final Start Layer is selected. Their complete endpoint object retains its
captured keys and all AWG fields. The original requested packet MTU remains in
the captured source; a nested Auto graph may derive a smaller final endpoint
cap before startup, as described below. The paired WG public identity and
the selected AWG transport's independent peer key are not substituted for one
another.

A SOCKS5 entry retains its original server, port, version, username and password.
It uses the paired final's authenticated encrypted transport; SOCKS5 alone is
not presented as an encrypted VPN. An entry Start Layer requires that imported
node's separately provisioned AES transport and exact whitening choice. A final
Start Layer requires the paired final's own original assets. A missing layer
provision, a provision belonging to the other node, or a changed credential
prevents construction. No second system VPN is started.

The additional SOCKS5 to paired REALITY/Vision path is Local with both Start
Layers Off. The original paired-node compiler retains the final's complete
VLESS/REALITY source and validates its exact native transport before attaching
the captured SOCKS5 entry. Entry public-address proof, final authenticated
private-node proof and selected final DNS remain independent. Android and Apple
selection, preparation and restoration retain these same captured sources.
PQ REALITY, XHTTP, Split, MAX, other imported entry protocols to this final,
independent layers on this pair, and Server/Compare for this direction remain
outside its implemented admission. Their safe rejection does not close those
requirements.

An OpenVPN entry retains its exact inline profile, ordered public remotes,
original TCP/UDP network, TLS trust, username/password and bounded supported
profile directives. It uses the existing userspace native packet endpoint in the
same graph. System-device mode, scripts and unsupported profile directives remain
refused. An enabled entry layer uses the existing source-validated per-remote
layer map even for one remote; the authenticated receipt continues to name the
original public remote, while only the owned physical transport reaches the
captured private service. The final's independent source and credentials remain
separate. No Router API, response-probe authority or second system VPN is
invented for the imported entry.

A CONNECT entry retains its original proxy address, port and credentials;
HTTPS also retains the original TLS name and trust. The paired SS2022 final
keeps its separate credentials and all three supported ciphers. The imported
entry Start Layer currently remains Off.

Without the final's separately captured service declaration, the composition
remains TCP-only with the final Start Layer Off. It supports compatible selected
TCP, DNS-over-TLS and DNS-over-HTTPS policies, including a hostname only when
its complete captured bootstrap policy can use the same carrier. Default Home
UDP, DoH3 and a UDP-only bootstrap cannot use this plain carrier. Rejection
preserves the saved resolver instead of substituting another transport or service.

With the final's original service declaration validated against its node and
source assets, the compiler derives explicit SS UoT-v2 transport. That bounded
path supports the selected UDP/Home DNS policy and final Off, AES-256-GCM or
AES-256-GCM + XOR whitening, as well as compatible encrypted DNS and captured
bootstrap. A raw inline udp_over_tcp option never grants this authority.
The declaration is configured source evidence, not proof that a live receiver
works. Actual selected-path proof remains required.

Both forms retain the final-owned resolver's transport, address, port, TLS name,
HTTP path and query/bootstrap options. No DNS fallback or public resolver is
invented. Android and Apple host admission, captured preparation and saved state
follow the same capability; unrelated imported directions keep their own bounds.

Other imported entry protocols, other paired final transport families, and
Server/Compare for this new direction remain requirements to implement and
verify. Existing supported directions retain their own admission and proof
rules. This document does not mark the complete external-node requirement or
the complete product delivered.

## Open graph requirements

The original Router/imported choice for each hop is still broader than this
implemented Local matrix. These are current source
limitations, not merely missing credentials, live access or physical tests.

| Direction or capability | Current source boundary | Work still required |
|---|---|---|
| Imported HTTP/HTTPS CONNECT → paired Shadowsocks with an entry Start Layer | The entry remains Off. Final AES/XOR and compatible datagrams require the final's validated configured SS UoT-v2 service declaration. With both layers Off, plain TCP/DoT/DoH remains available without it. | Implement and validate independently provisioned entry-layer capture and routing without borrowing the final's credentials. Complete native and device evidence for the already-admitted configurations. |
| Imported HTTP/HTTPS CONNECT → paired Hysteria2/WG/AWG | Admission still excludes these final modes. The existing configured SS UoT-v2 composition is specific to the paired SS final and does not automatically authorize other finals. | Implement the particular compatible carrier, source ownership and native graph for each final. A successful CONNECT stream or a service declaration for another final is insufficient. |
| Other imported entry protocols and paired final families | The constructor and mobile hosts retain eight entry labels and five general paired final modes, with the additional SOCKS5-only REALITY/Vision Off/Off case. Other Xray families and pairings remain excluded. Bounded OpenVPN Local is implemented; Trojan/VLESS are not ordinary imported catalogue entries. | Implement and validate each particular protocol/source capture, encrypted graph, credential/reference ownership, restoration and native path. Standalone support or the bounded SOCKS5/REALITY path does not prove another pairing. |
| Imported entry → paired final with Server or Compare | The constructor requires captured Local execution; both host adapters enforce Local and restoration deliberately does not invent a Compare winner. | Design actual execution and proof authority, measurement/comparison and restore semantics for this direction. An ordinary imported entry has no paired Router API/token; a public-address proof cannot grant server-side authority. |

Any extension of CONNECT→SS must retain the final-selected Home/custom DNS
transport, address, port, TLS name and HTTP path. UDP or DoH3 selection
cannot silently become TCP/DoH or a public resolver just to make the graph work.
The existing `externalUDP`, `externalExitRequiresUDP` and selected-DNS validator
express the carrier's actual transport limits. `importedCONNECTCapture` and
`importedCONNECTDNS` preserve those limits and the complete final-owned DNS
closure through mobile preparation; they do not choose another resolver.

The baseline `node_imported_connect_entry_test.go.tmpl` covers CONNECT to
encrypted SS traffic, final-owned TCP DNS, auth/target/HTTPS trust rejection,
public-entry/private-final proof, UDP refusal without service authority,
unsupported finals, cancellation and restoration. Later configured-service and
encrypted-DNS captures have their own mandatory source and parser inventories.
The existing `node_external_ss_connect_test.go.tmpl` exercises **SS→CONNECT**,
the reverse direction, and cannot certify CONNECT→SS. Actual Android/Swift
capture, pinned native parsing, protocol-peer execution and physical acceptance
remain separate evidence stages.

## Selection and saved state

Android's multihop editor lists eligible imported entries alongside Router
entries. Choosing an imported SS2022, Hysteria2, WireGuard, AmneziaWG, SOCKS5,
HTTP CONNECT, HTTPS CONNECT or OpenVPN entry allows
selection of its paired Router final and an eligible complete transport from
the table above. The picker
compiles each offered choice from captured sources and retains the final-file
digest through selection. A changed entry or final cannot adopt the old choice.
Saving selects that final and the complete Local graph; Connect still
requests permission, starts the native graph, and proves the path.

Apple's multihop editor admits the same imported entry when a paired Router
final is selected. Its final-transport picker requires the selected pair and
that linked final's complete raw transport/Start Layer assets, with Local
execution for this direction. A different saved mode remains visible
as an explicit unsupported placeholder until deliberately changed. Saving
retains both original node references; only one paired final is required for an
imported entry.

Android connection profiles use schema 6 at the existing private store location.
Add, Load, Update, and Delete retain the imported entry's external policy and
the final node's independent Router policy. Credentials remain in their original
node stores. Older schema-five imported-entry/Tor profiles retain their typed
read path. Validation precedes node or preference writes, and selection rollback
does not overwrite a newer selection. Preference publication and rollback
compare the original and intended maps under the actual shared preference
monitor. The same owner covers node selection and the profile mutation interval.
A newer owner prevents an older failure from reverting either source files or
selection; incomplete rollback is reported. Automatic selection during refresh
reads and checks the current selection under that monitor.

Permission, Activity rotation, startup, restore, and node-usage accounting retain
the original typed entry and final references. A matching text ID does not turn
an imported node into a paired node. A changed source, protocol, execution
choice, pending permission owner, or Home generation prevents the old request
from starting or being adopted. Activity recreation compares the exact captured
entry protocol; node usage also checks that original protocol against the proved
Home owner. Startup does not invent a historical Compare
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
encrypted traffic through proxy and packet entries and SS/Hysteria2 finals,
including a Hysteria2 final behind its actual AES outer transport. They reject wrong
entry credentials, wrong final keys, bypassed final routing, wrong DNS routing,
and wrong final identity. Hysteria2 additionally rejects incorrect SNI and
untrusted certificates using the actual native TLS/QUIC certificate error.
Packet tests add actual WG-to-SS and AWG-to-Hysteria2 encrypted traffic, entry
AES wrapping, and wrong private/public keys, PSK, AWG parameters, entry route,
outer-layer key and public-entry identity. An invalid entry route must fail at
its actual startup boundary with no authority over the original peer or final.
New actual encrypted peers also exercise SS-to-WireGuard, SS-to-AWG Fast,
Hysteria2-to-AWG Strong and a packet final behind its AES outer transport. Their
controls reject incorrect final private/public keys, PSK, AWG parameters, entry
keys and TLS trust, outer-layer keys, routes, selected DNS and private/public
identities. A transport that must authenticate during Start may reject there;
the fixture requires a live original context and no acquired final authority.
Timeouts and cancellation cannot satisfy certificate-refusal assertions.

SOCKS5 peer tests send actual encrypted TCP and UDP traffic through all 45
independent layer combinations. The entry wrapper carries the original SOCKS
control connection and its UDP association. The tests reject wrong entry/final
layer keys, changed whitening, SOCKS authentication downgrade, a foreign relay,
retired control connections, and bypassed final or DNS routing. The previously
published SS/Hysteria and WG/AWG final-layer fault matrices are retained
separately, including their authentication refusals and MTU-sized DNS checks.
Dynamic UDP test peers retain the original
control owner until their workers join; deterministic controls exercise a
retiring worker, concurrent root cleanup, a replacement owner and foreign or
closed associations. This peer evidence is separate from physical VpnService
or PacketTunnel routing.

Nested packet tests add seven successful encrypted paths, including WG-to-WG,
AWG Fast-to-WG, AWG Strong-to-AWG, independent entry/final layers, both layers,
and an IPv6 carrier. Fourteen negative cases reject changed private/public keys,
PSKs, AWG parameters, layer keys, final/DNS routes and proof identities. The
independent decrypted peers observe full-size IPv4/IPv6 payloads and reject
fragmentation; a UDP socket being bound is not sufficient evidence. Closing the
captured graph joins its workers and prevents a late dial from reusing them.

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

OpenVPN path authority captures the exact authenticated public remote,
generation, connection timestamp and negotiated native PortMTU. The initial
capacity must satisfy the complete compiled entry envelope. Any subsequent
receipt or MTU change, including an increase, revokes the old proof and its
measurement factories; revalidation captures a new owner. A cancelled measurement
cannot publish a result and does not by itself retire an otherwise unchanged
path. Native receipt/capacity, public/private proof and selected DNS observations,
plus the imported hop engine's `IdentityContext` and `Dial` methods, retain the
actual caller context through instance, selector and outbound readback.
Contextless native identity queries use the existing 1,500 ms observation bound.
A connection returned after cancellation or original owner replacement is closed
before the operation returns; it cannot be handed to a replacement owner. Startup
publishes its cancellation owner before observing native identity and joins that
read on Close. The shared `hopmeasure.Service` now uses an available
`IdentityContext` capability throughout its original operation and never queries
native identity while holding its admission/status lock. It registers cancellation
before identity or activity acquisition; a rejected start preserves the previous
completed result and drains any returned activity release before returning. Late
status observations cannot invalidate a replacement request or cancellation, and
an expired final observation cannot publish a 50-sample result. The existing
90-second complete request budget includes admission; the five-second drain
allowance is unchanged. Context-capable activity owners can retain that same
caller through `BeginMeasurementContext`; legacy engines and activity callbacks
keep their compatibility behavior and are not claimed to be interruptible.
The ordinary MTU adapter retains its separate context-bound readback and rollback
contract, while external/Tor constructors, proof callbacks and Tor lease
observations remain follow-ups. Native factory adoption of the optional shared
`NewContext` constructor must preserve the original caller separately from the
returned service lifetime; the contextless constructor uses a 1,500 ms observation
budget only for owners that support context-bound reads.

The complete compiled graph supplies the MTU plan. For a nested packet final,
`internal/awgpolicy` accounts for the actual IPv4/IPv6 carrier, 16-byte transport
padding, AWG data/control parameters and the selected authenticated outer layer.
The entry endpoint keeps its original MTU. Auto derives a fitting final endpoint
cap; Fixed must fit unchanged. Oversized control packets are rejected even when
data would fit. Metadata records the original request, effective endpoint cap,
data overhead and largest control envelope as **configured-unmeasured**.
Those values are configuration bounds, not a measured physical path MTU.

Fixed-value conflicts are
validated, and compatible Jumbo is virtual TUN capacity, not a claim of a
9,000-byte physical path. The existing Auto/Retest/Cancel transaction retains
its original native interface and proof owner. No cached measurement becomes
fresh proof merely because a source compiles. The already-compiled packet
endpoint and its cap remain unchanged when the application TUN is retuned. Packet-entry
and packet-final graph tests verify that application TUN retuning preserves each
complete captured packet endpoint; the new final tests use a 1392 target. This is configuration/lifecycle evidence;
it is not proof that a particular physical path carries 1400-byte or Jumbo
payloads. Effective/interface readback and authenticated path measurements keep
their separate ownership and validation requirements.

Android stages original sources in its private session directory and recreates
the typed native owner from those sources before launch. Config, metadata, and
source digest must match the recreated owner. Its session label must also match
the recreated final transport; a different final label cannot adopt the plan. A cancelled preparation retains
ownership of its exact directory until cleanup is proved. Failed cleanup remains
reachable through Disconnect and blocks replacement startup. The service closes
an unadopted typed preparation and retains its usual native teardown rules after
adoption.

Both hosts restore the same captured Local direction and source identities.
Neither substitutes a paired entry for an import nor reruns an unrelated
Compare selection during restoration. Ordinary `wireguard` and `amneziawg` entry
labels remain distinct from the paired raw-mode catalogue. Home state, startup,
permission recreation and live usage retain those original protocol identities.
Android's stored `http`/`https` labels are canonicalized through its existing
external-policy mapping into the captured `http-connect`/`https-connect`
identities. Saved profiles, startup and Home retain the same canonical identity;
changing it cannot adopt an older proof. The CONNECT Retest witnesses use the
actual MTU controller and retained native outbound for refusal, cancellation
and successor retention, with the OS TUN capture/apply boundary modeled. They
do not establish measured PMTU through a TCP-only entry.

The pinned native WG/AWG stack drains an admitted packet delivery before entering
gVisor teardown. Late writes and attaches cannot revive the retired dispatcher.
A deterministic native race test covers the actual stack and rejects both lost
delivery retention and draining under the stack lock. This correction is shared
by Android and Apple runtime preparation.

The original AmneziaWG bind also checks its captured generation, connection and
context before and after receiving. A retired native UDP error becomes
`net.ErrClosed`, so the upstream receive worker exits promptly. A late successful
read cannot publish a packet into a successor. The lifecycle regression covers
both native close errors and late success, using the actual bind implementation.

OpenVPN native peer fixtures execute all 90 TCP/UDP, final and independent-layer
combinations with actual TLS/authenticated entry traffic, paired private proof
and final-owned UDP DNS. Three additional real TCP failovers retain ordered
first-remote refusal and successful original-public-remote receipt through Off,
AES and XOR entry layers. Fourteen negative cases require observed native
password, independent layer authentication/whitening or private-route refusal,
with no authenticated receipt or decrypted final traffic; a timeout is failure.
Foreign public host/port, private identity substitution and network changes are
also rejected by the actual layer mapper before physical dialing. These are
userspace encrypted-protocol and ownership results, not operating-system
interface or physical-policy acceptance.

## Executable gates and evidence limits

The shared compiler/runtime race tests cover the independent
layer matrix, all three SS2022 entry ciphers, Hysteria2 TLS/password capture,
WG/AWG endpoint capture, policy and source ownership,
strict paired-final admission,
public-entry/private-final/DNS proof, full Run-to-Healthy measurement ownership,
retirement, and malformed or forged source rejection.

`deploy/test_mobile_imported_entry.py` now requires exactly 338 shared original
source fixtures and 338 from the actual Android helper. Configured CONNECT and
selected encrypted DNS are retained in their separate required directories. The pinned
libbox constructor must reproduce their original config and source digest.
Its actual native parser, MTU profile reader, and MTU planner must accept them.
The required fixture gate rejects missing, skipped, duplicated, foreign, or
malformed cases. The Linux native peer gate executes actual encrypted pairs
across the implemented entry and final families, including the complete SOCKS5
layer matrix and Hysteria2 finals behind their actual AES transport. Every
group and negative case in the runner's explicit inventory must execute and
pass once. The expanded groups run separately under the unchanged finite
native-test deadlines. All 338 original-source graphs retain the primary native-parser and typed-MTU
requirements. The new SOCKS5/REALITY file additionally requires its focused
native-parser root in the existing non-peer invocation. With the configured
CONNECT and selected-DNS groups, the default non-peer inventory requires 410
exact verdicts; the Android source group remains additional. These are required
inventories, not a statement that the new current-SHA invocations have passed. This does not claim physical mobile
TUN traffic for every layer combination. Removing the final outer-edge ownership or bypassing actual
native TLS verification is rejected by the corresponding causal controls.
Dropping the captured packet endpoint or bypassing the final detour also fails
at its intended native witness. Additional compiler controls reject lost endpoint
discovery, overwriting an inner final detour, and an outer Start Layer from a
foreign node. Prepared native source retains the complete mobilemtu/mtuprobe
import closure; copied test imports must compile in the actual pinned module.

Android gates exercise the actual helper, saved-profile store, permission
controller, startup policy, multihop runtime, MTU session, node-usage recorder,
and service composition with explicit OS/native boundaries. Deliberate source
mutations must fail the intended assertions. The mandatory imported-profile
dispatcher includes the three added nested final families as well as the six
existing families. Original preference, forward-apply and rollback ownership
retain their 57 focused checks and seven causal controls. The Java syntax gate
covers every shipping Java source; the actual SDK/AAR APK build remains separately
required.

`deploy/test_ios_imported_router_pinned.py` is mandatory in Apple smoke and
release preparation. It now requires the actual Swift-produced 338-graph matrix
and all 339 exact native verdicts, including the parent. The new full pinned
invocation remains required even when a Swift-only producer or host fixture passes. Swift harnesses cover
selection, profiles, restoration, typed MTU, and PacketTunnel composition.
The local Swift 6.4.2 harness executes actual selection, save and graph-building
source. This is separate from the required Xcode app/PacketTunnel build, native
Apple networking and physical-device acceptance.

The new `deploy/test_mobile_imported_socks_xray.py --reference-only` stage
requires twelve real SOCKS5/REALITY reference leaves plus their parent. It drives
actual authenticated SOCKS5 and Xray REALITY/Vision outbounds, selected UDP Home
DNS, distinct entry/final proofs, credential/route/identity rejection and owned
cancellation/teardown. Its desktop source closure is separate from the mandatory
mobile parser, and its receipt explicitly records `native_parser: false`.
The new runner regressions, pinned parser and reference were source-reviewed
but unexecuted when published in fc261fd0. Passing this reference would still
not prove Box DNS-router integration, the shipping host proof adapter, OS TUN
behavior, a mobile Connected result or device acceptance.

The following CONNECT results are historical evidence with explicit source
cutoffs. They do not certify later configured UoT, selected encrypted DNS or
SOCKS5/REALITY additions. The complete encrypted
peer run passed 976 mandatory verdicts (the previous 925 plus 51 new ones) on
the `bc6cffef`-based snapshot, before the additional explicit UoT-field refusal
and later Compare-progress merge. The Swift producer passed 5,568 checks and
the pinned Apple parser passed 248 verdicts before those two changes. The
Android/shared 496-verdict parser run used the `d847152e`-based source, including
the UoT refusal and corrected runtime capability. After the progress merge,
the focused shared race run passed 457 imported-entry verdicts and 12 Compare
progress verdicts. All twelve complete CONNECT source/capture/config arrays
remained byte-identical to the full encrypted run. Existing HY fixtures
regenerate certificates, so the complete 247-source arrays are not claimed
byte-identical. Final actual host fixtures additionally passed 2,481 Swift
selection checks, 110 CONNECT profile checks, and the Android runtime/Home
checks with the original and canonical-admission causal controls retained.
After preserving the concurrent `9e0341f0` baseline, the actual Android startup
deadline fixture passed 3,785 checks across 1,089 cases and all three premature
deadline/dependency mutations, including delayed native readiness and ordinary
timeout teardown.
These results do not claim that the entire encrypted suite was rerun on the
final published commit; exact-SHA integrated CI remains a separate gate.

Exact-SHA Android/iOS builds, release publication, physical-device routing,
permission and network transitions, leaks, off-LAN interoperability, visual
acceptance, and Apple signing/distribution are distinct evidence stages. No
private deployment or physical-device acceptance is established by these local
tests.
