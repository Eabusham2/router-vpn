# Networking Reference

Consolidated technical references. Existing protocol and platform restrictions remain in force; historical validation statements are not certification of current main.


---

<a id="section-adguard-blockpage-reality"></a>

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


---

<a id="section-desktop-mtu"></a>

# Desktop MTU ownership and restoration

The native Windows, macOS and Linux applications expose **Auto, Fixed, Retest
and Cancel**. Retest has its own progress view, current interface value,
candidate results and final restoration/commit state. A saved historical MTU
is labelled as saved; it is not presented as a fresh measurement of the current
connection. Invalid fixed values are rejected by the profile/runtime contract.

This document describes the shipping source contract. Exact-commit native
builds, kernel execution, physical networking and private-server acceptance
remain separate evidence. See [REQUIREMENTS-RECONCILED.md](CURRENT-REQUIREMENTS.md#section-requirements-reconciled)
and [the production release contract](PRODUCTION-RELEASE.md#section-current-certification).

## Requirement evidence for this change

These identifiers retain the recovered numbered requirement set in `mm.md`
and `router_vpn_chat_audit_addendum_v2.txt`.
Its old missing/partial labels describe that historical checkpoint; they do not
override current source or supply today's device evidence. The later product
request explicitly retained the best-MTU finder and all-device native scope.

| Requirement | Current source and test connection | Evidence still required |
|---|---|---|
| 231–232: effective manual MTU and WG/AWG plumbing | Profile policy, native configuration, retained TUN and kernel-interface adapters | Exact new native packages and applicable real-device readback |
| 233: default/manual/auto/effective display | Native PowerShell, AppKit and GTK MTU views; operation-specific status and saved-value labels | Packaged visual, scaling and accessibility acceptance |
| 234–237: finder, bounded probes/comparison, path storage and Retest | Captured optimizer capability, Auto admission, authenticated path probes, transactional persistence and cancellation tests | Private-server/cellular performance and current-path measurements |
| 214–224: compatible real multihop | Both node identities, exit DNS/proof, selected execution and entry protection remain captured through MTU and Speed Lab | Real entry-to-exit, forwarding, per-hop and off-LAN acceptance for each requested platform |
| 324–325: Portable clean exit and relocation (also Portable Exit, §86) | Terminal controller drain, exact launcher PID/nonce, checked native cleanup and process join | Actual removable-drive/folder release and normal device exit |

Requirements 225–230 and 239 include live performance diagnosis, CPU/path
comparison and appropriate Jumbo validation. This change does not supply those
observations or establish the cause of the historical cellular regression.

## Captured path and native interface

Ordinary Router VPN native paths and compatible Router VPN multihop use the
retained `routervpn-node` process. Its system TUN belongs to the exact native
Box, private runtime directory, session nonce and configuration digest. Changing
the TUN MTU retains the graph, DNS, independent entry parameters and credentials;
it does not construct a second VPN or relaunch a different selected profile.

The controller captures the actual interface MTU before it starts measurement.
The native process verifies the same interface index, reader generation,
physical path, session and configuration for every command. Begin, Set, Commit
and Rollback carry an owned request/lease identity. Leases expire after a fixed
150 seconds; polling and repeated requests do not extend them. An expired or
failed operation cannot authorize a later result. Successful rollback requires
the original MTU and an explicit restoration receipt. A late Commit receipt is
resolved with a private capability bound to that exact commit and its original
deadline. A confirmed Commit discards the parent capability; ordinary rollback
cannot change an inactive committed lease. Expiry and runtime-retirement
receipts cannot be relabelled as a successful measurement.

Other supported desktop interfaces retain a kernel owner. Linux holds the
sysfs MTU/ifindex objects and validates their filesystem, inode and device
identity. Windows retains the interface LUID and full IP interface row, checks
its GUID/index/alias, and changes only MTU policy on that captured interface.
Neither implementation resolves a replacement interface by its reused name
when rolling back. Native and IPv6 paths retain a 1280-byte minimum; eligible
IPv4 kernel paths use their captured lower bound. Jumbo virtual-interface
capacity does not prove that the physical transport carries 9000-byte packets.

The Python and PowerShell optimizers use a bounded loopback capability owned by
the parent controller. Only its exact current session may read or change that
interface. They cannot fall back to an alias-based mutator after ownership is
lost. The optimizer's deferred result is checked against the original interface
and path, persisted transactionally, re-proved and committed. A failure after
persistence can undo only the measurement fields written by that operation.

## Router VPN multihop

Multihop captures the control profile, entry, exit, both node proofs, running
native graph and already-proved Local or Server execution. Server execution
also retains its authenticated relay lease. A changed node, graph, process,
network, policy or lease disqualifies the result.

The measured value describes the **exit-path system TUN**. It is saved on the
exit profile with that scope; it does not overwrite the entry MTU or claim an
underlay PMTU measurement. Selected control-profile protection and the physical
entry's firewall exception remain captured. The exit's selected DNS policy
continues to govern the path.

The compatible Router VPN graph family remains distinct from the external-node
catalog. The retained compiler uses `NodeMultihopEntryModes()` and
`NodeMultihopExitModes()` in `internal/mobilemultihop`, currently 19 raw modes
each, including packet, proxy, PQ and complete composite/MAX graphs.
`TestNativeEntryMultihopLocalServerCaptureMatrix` exercises those exact catalogs
with all three Start Layers and Local/Server retention. The retained-graph
restoration tests require the system-TUN MTU to be the only changed setting;
the entry, exit, DNS, proof lanes and protection remain captured. Constructor
coverage does not establish every physical pair or a current native package,
and an accepted external-node graph does not expand this Router catalog.

## Cancellation, Auto and Speed Lab

Every native Retest view carries its request, session and profile identities.
Poll, Cancel and final status apply only to that operation. A late HTTP reply
cannot replace a newer window or connection. A cancelled POST can finish with
an error while the final GET correctly reports that rollback completed; the UI
waits for that final owned state.

Auto starts after the Router-node connection is proved and its startup operation
has released ownership. Temporary measurement/connection holds cancel and drain
MTU work before capturing the path. Nested Speed Lab stops share that hold.
Releasing a hold resumes an interrupted Auto attempt, including holds that win
before the operation publishes its cancellable view. Manual Cancel does not
immediately restart the cancelled operation.

Speed Lab captures the **live readback**, rather than the original configuration
file's MTU or a saved historical value. Restoration changes only the captured
system TUN value and its configuration digest, retains the original entry and
exit policy/credentials, restores the already-proved execution choice and
re-proves it. It never reruns Compare both to choose an unrelated replacement.

Failed cleanup remains visible as `cleanup-pending`. It retains its native
owner and blocks replacement until checked Close succeeds. A process exit or
missing acknowledgement is not substituted for a successful rollback. Explicit
Disconnect can retire only its exact native runtime when an unresolved lease
cannot drain, then join MTU cleanup through the checked stopped receipt. A
Speed Lab measurement hold does not take that teardown fallback.

## Application exit

Controller shutdown closes admission to new connection and settings work,
cancels startup/temporary measurements, and drains owned cleanup before exit.
An app-owned controller has a fresh launch nonce. Its launcher requests shutdown
with that nonce and exact process ID, then requires both the matching closed
receipt and that same child's normal exit. HTTP timeout, pending cleanup and
an unexpected process exit cannot authorize a forced replacement or a success
message. Windows installed and Portable use the same shutdown client.

SIGINT/SIGTERM use the same terminal drain for independently launched
controllers. A controller that failed to acquire any runtime does not release
another controller's persisted firewall protection. A native application that
reuses an existing controller does not take ownership of its process.

## Executable evidence

| Boundary | Executable coverage |
|---|---|
| Progress, Cancel and final readback | `deploy/test_desktop_mtu.py`, `deploy/test_macos_mtu.py`, the shipping PowerShell, GTK and Swift fixtures |
| Parent capability and retained interface | `cmd/client/mtu_live_owner_capability_test.go`, `desktop_node_mtu_owner_test.go`, `mtu_kernel_*_test.go` |
| Auto hold races and nested transitions | `cmd/client/mtu_automatic_test.go` |
| Multihop identity, persistence and restoration | `cmd/client/mtu_multihop_snapshot_test.go`, `desktop_node_mtu_restore_test.go` and native multihop/Speed Lab tests |
| Real native construction and cancellation | `mobile/desktop/mtu_node_test.go.tmpl`, included in the actual native builder's race test invocation |
| Shipping native command and real kernel TUN | `deploy/test_desktop_node_mtu_kernel.py`, run against the exact built Linux native artifact in a fresh network namespace |
| Checked process shutdown | `internal/controllerprocess/client_test.go` and controller/native GUI lifecycle fixtures |

The kernel gate retains its existing same-name replacement/rollback cases and
adds the shipping native command's private-file protocol. The local development
environment lacks `/dev/net/tun`, so that new privileged command path must pass
on CI before being described as kernel-tested. Real private probes, leaks,
network transitions, performance and physical UI acceptance remain live tests.


---

<a id="section-dns-proxy"></a>

# Raw-tunnel DNS proxy

`router-vpn-dns` is the package-owned local UDP/TCP DNS service used by raw
WireGuard, AmneziaWG and Rosenpass paths. The captured node policy supplies the
upstream protocol, literal IP, port, TLS certificate name and request path. The
controller separately verifies that captured policy against the runtime hint,
then sends its randomized DNS-query proof through this local service.

## Selected DoH3 behavior

`--protocol h3` and `--protocol doh3` use HTTP/3 over QUIC v1. The selected
literal IPv4/IPv6 address is the only dial destination. `--server-name` is the
TLS certificate identity and HTTP authority; it is never resolved through the
ordinary network. The selected port and local absolute request path are
preserved. TLS 1.3 and certificate validation are mandatory, and DNS data is
sent only after the handshake. The helper has no insecure certificate option.

One service owns one reusable HTTP/3 transport, QUIC connection pool and UDP
socket. Queries use POST with `application/dns-message`. A request must return
HTTP 200, the DNS media type, a bounded complete body and a correctly framed
response matching the actual query. Redirects, wrong certificates, wrong DNS
questions/IDs, oversized bodies, truncated HTTP bodies and DNS TC responses
fail. There is no HTTP/2, TCP or plaintext DNS fallback for H3. The separately
selected **Rescue** mode retains its explicit existing fallback policy.

Each request has a four-second upper bound and receives the captured service
context. Shutdown cancels both local listeners, joins admitted UDP/TCP workers,
joins pending H3 dialing and connections, retires the QUIC packet reader, and
closes the exact owned socket. A cancelled operation cannot write a response
for a replacement owner. The local listener has a bounded 256-worker limit.

Home resolver identity remains a node policy responsibility. The proxy does
not invent an AdGuard address or silently switch an unavailable Home resolver
to a public service. Encrypted Home DNS requires a real server certificate
trusted by the device and matching the captured certificate name (or IP SAN).

## Build and notices

The nested `cmd/dnsproxy` module uses installed **Go 1.26.3** and
**quic-go v0.64.1**. Keeping it separate preserves the root controller/server
module's Go contract. The checksum-pinned runtime dependency closure is
quic-go, qpack, x/crypto, x/net, x/sys and x/text. The build helper validates
the exact module files, module-cache h1 content checksums, actual compiled
dependency versions/checksums, license text and final binary metadata.

```sh
python3 deploy/build-dnsproxy.py test
python3 deploy/build-dnsproxy.py build linux/amd64 /tmp/router-vpn-dns
python3 deploy/build-dnsproxy.py notices /tmp/DNS-PROXY-NOTICES.json
```

`test` runs the nested module's complete race suite explicitly; root
`go test ./...` does not enter this module. `build` accepts the existing
Windows/macOS/Linux and qualified Unix target matrix, uses readonly modules
with CGO disabled, and never installs or replaces the Go toolchain. Existing
package scripts, the CI-built initialization image and its bounded client-only
package fallback all use this helper. Production server deployment remains
image-only.

Windows ARM64 uses `test --without-race` because Go1.26.3 has no race detector
for that native host. It executes the same full H3/CLI tests. That option is
rejected on hosts where the pinned toolchain supports race instrumentation.

The exact notices are both embedded in the binary (`router-vpn-dns --licenses`)
and staged as `DNS-PROXY-NOTICES.json` beside it. Generic package assembly
includes that file in the existing exact-source package manifest/checksums.
Checkout builds retain Go VCS metadata; source-archive builds retain the
enclosing package's source-SHA provenance rather than inventing a Git checkout.

## Verification boundary

Tests perform real loopback QUIC/TLS/HTTP3 exchanges with a private test CA,
real subprocess CLI startup, UDP/TCP forwarding and the same DNS probe used
by kernel connection proof. A TCP listener on the H3 endpoint detects an
unwanted HTTPS downgrade. Negative tests cover certificate, selected path,
response framing, cancellation and resource ownership failures. These are
automated local tests; they do not establish physical-device behavior, a live
AdGuard endpoint, live tunnel routing or private deployment acceptance.


---

<a id="section-mobile-tor-mtu"></a>

# Mobile Tor interface capacity and MTU ownership

## What Jumbo means

Jumbo selects a **9000-byte virtual VPN interface** for a compatible Tor graph.
It is not a claim that the physical network, an entry protocol, or the Internet
can carry a 9000-byte datagram. Tor carries application TCP streams; the native
system stack segments those streams using the lower transport's own limits.
The UDP rejection and selected DNS policy remain in the same owned VPN graph.

The shared compiler accepts exactly one strict, automatically routed TUN. A
saved Fixed/manual value must be an integer from 1280 through 9000. Explicit
Jumbo and Fixed/manual can coexist only when the Fixed value is 9000. The
optimizer's candidate ceiling remains 1500; configured capacity is reported as
`configured-unmeasured`, not as a measured packet-path limit.

## Entry and exit preferences

The Tor exit and a captured Router VPN predecessor share the same TUN. Their
preferences therefore have to be compatible:

| Captured request | Effective interface | Optimization |
| --- | --- | --- |
| Exit Jumbo, compatible entry | 9000 | Disabled |
| Captured entry Jumbo, exit Auto/Default | The entry's validated 9000 | Disabled; the saved exit choice is retained |
| Captured entry Fixed 9000, exit Auto/Default | The entry's validated 9000 | Disabled; this is inherited Fixed, not a rewritten Jumbo preference |
| Exit Fixed/manual | Exact requested value, compatible with any entry Fixed/Jumbo | Disabled |
| Exit Auto, no entry Fixed/Jumbo | Captured interface and bounded Tor transfer candidates | Existing Auto/Retest/Cancel transaction |
| Conflicting entry and exit Fixed/Jumbo | Rejected before runtime adoption | No measurement |

`PredecessorProof` captures the complete entry profile identity and private MTU
preferences. `MTUAuthorityWithPredecessor` binds them to the compiled graph,
entry/exit IDs, session, exit profile, and live native reader. An arbitrary
9000 in a graph cannot mint an authority. The original saved profiles and raw
WireGuard/AmneziaWG endpoint MTUs are not rewritten by Tor preparation.

Predecessor capability restrictions still apply. In particular, the existing
raw WG/AWG **Jumbo request** guard remains in the predecessor performance
compiler. A compatible proxy predecessor's Jumbo and a distinct captured Fixed
9000 are covered separately; the implementation does not relabel one as the
other to bypass that guard.

## Native ownership

The retained Tor proof supplies the exact predecessor to the MTU lease. The
Libbox constructor compares the compiled interface tag and capacity to the
platform's current OS readback before adopting that lease. Fixed/Jumbo leases
cannot mutate the TUN through the optimizer. `RouterMTU.AutoRequested()` reports
the retained authority's decision, including inherited entry constraints; a
host must not infer that decision solely from the exit's saved Auto preference.

Close, cancellation, network changes, and delayed constructor completion keep
the existing owner and drain barriers. The native tests construct the real Box,
daemon, retained proof, selected DNS transport, and Libbox controller. They
replace OS TUN I/O and external circuit peers, so they do not constitute a
physical-device acceptance test.

## Android host

The Tor editor exposes Jumbo separately from the MTU preference. Toggling it
preserves an untouched Auto/Default choice, selected DNS, LAN/IPv6 policy,
protection, bridge credentials, and node identity. Complete connection profiles
retain the typed Jumbo choice and reject conflicting Fixed values transactionally.

Preparation applies a captured entry Fixed value to the single interface before
the performance and Tor compilers validate the graph. Protocol endpoint MTUs
remain unchanged. The VpnService passes the compiled capacity to
`Builder.setMtu`; the MTU session then requires matching current OS readback and
native ownership. Only after that adoption does the host consult
`AutoRequested()`. A failed adoption of a configured capacity above 1500 aborts
the captured session; it cannot remain a successful Jumbo connection.

The MTU view displays configured capacity as unmeasured and disables Retest for
the non-optimizing authority. Failed Tor shutdown invalidates Connected and
actual-exit evidence before draining. It retains the exact session/node/entry
generation while cleanup is pending and clears it only after confirmed release.
A delayed failure cannot change a replacement Home owner.

Executable coverage is in the Android Tor profile, form, MTU, service, Home
state, and connection-profile fixtures, including source mutations that remove
ownership, drain, capacity, and policy guards. The real APK/AAR build and device
networking remain separate gates.

## Apple host

The external-node device editor exposes a Tor-only Jumbo switch. Its captured
save preserves Auto/Runtime default, the selected resolver, protection, entry
references, and private bridge configuration. Fixed values other than 9000
cannot be combined with Jumbo. Active, stale-source, and failed persistence
transactions leave the previous node unchanged.

The existing entry preparation applies its saved interface preference before
the Tor compiler receives that complete graph. Tor retains the captured entry
profile and the exact resulting single TUN. Proxy and composite predecessors
that pass their existing capacity validation may provide Jumbo; packet-bearing
WG/AWG/PQ/MAX entry guards remain in force. Inherited Fixed 9000 is distinct from
an explicit Jumbo request, and neither changes the saved exit Auto/Default
selection. Tor does not rewrite the prepared predecessor's protocol endpoints.

`RouterVPNMTUSession` adopts the real Libbox Tor owner after proof and matching
OS readback, then asks its retained `AutoRequested()` authority. The platform
passes the compiled capacity unchanged to NetworkExtension settings. A late
platform open or failed native adoption cannot report a successful connection.
Failed Close retains the exact native handle for a later drain attempt.

The app requires current readback before displaying configured capacity or
enabling Retest. Configured 9000 is shown as unmeasured, and inherited Fixed or
Jumbo disables both deferred Auto and explicit Retest. The displayed measured
candidate ceiling remains 1500. The app control binds replies and Cancel
to the captured session/request; an old response cannot revive permission in a
replacement session.

Executable coverage runs the shipping Swift editor, provider graph assembly,
MTU platform/open method, owner, decoder and app client. Native Go policy
compilers are used for the graph and editor checks. The framework and OS
boundaries in these fixtures are doubles; actual generated Libbox binding,
Xcode app/extension builds and device acceptance remain separate evidence.

## Remaining platform evidence

Apple connection-profile schema 5 captures Tor and Tor-bridge DNS, LAN ranges,
protection, IPv6, MTU/Jumbo, startup, AUTO requirements and the selected local
Router entry/exit references. Add and Update validate the saved preferences
through the native Tor parser; Load validates them against the currently linked
private node and entry before the transactional import. Bridge lines, keys and
entry credentials remain in their owning node bundles. Tor retains dynamic exit
proof rather than acquiring a fixed public IP. Schema 1–4 selection-only Tor
records remain selection-only until the user explicitly updates them.

`deploy/test_ios_tor_connection_profiles.py` executes the shipping view callbacks,
profile/node stores, model import and rollback, entry readiness, and real Go Tor
validation. The Darwin native-runtime contract invokes it before the iOS compile
smoke and authoritative release builds. Storage and native marshalling boundaries
are substituted; fresh circuit/DNS/entry proof and physical acceptance remain
separate. Direct Home DNS can be saved as an unresolved draft and still needs its
paired entry at Connect. Server/Compare, unsupported Tor predecessor families and
standalone Tor padding remain separate implementation requirements.

Android and Apple real-device interface readback, traffic segmentation, reconnect,
network transitions, leak checks, and signed-package upgrade acceptance require
their own device evidence. Standalone Tor padding and additional graph families
are separate requirements and are not closed by virtual Jumbo support.


---

<a id="section-naive-h2-native-resolution"></a>

# Naive H2 native address and TLS-name resolution

## Behavior

Naive H2 keeps its captured TCP lower transport and application UoT-v2. Its
Cronet client now treats the original IPv6 server address as a literal even
when the verified TLS name is a DNS hostname. An exact hostname-to-literal
resolver rule prevents Chromium's unrelated IPv6 reachability heuristic from
suppressing that address. The rule grants no UDP socket and introduces no
resolver address.

An absolute DNS name such as `captured-naive.test.` remains unchanged in the
caller's options, saved graph and source receipt. The H2 client derives
`captured-naive.test` for its runtime URL and resolver alias. This matches
[RFC 6066 section 3](https://www.rfc-editor.org/rfc/rfc6066.html#section-3),
which excludes a trailing dot from wire SNI. The derived name preserves the
original DNS identity, case, port, credentials and certificate trust. It does
not change the captured endpoint or selected DNS transport.

Only exact ASCII DNS labels are admitted into the resolver rule or dotted-name
derivation. Wildcards, rule separators, whitespace, escapes, malformed labels,
oversized names and address zones are rejected. Already encoded IDNA labels
retain their original spelling. The original H2 unit left H3 unchanged; its
later captured transport and name-resolution hardening is documented in the
[Naive H3 ownership unit](NETWORKING-REFERENCE.md#section-naive-h3-native-ownership).

## Source preparation and required gates

`deploy/native_naive_literal_policy.py` creates an owned private copy of
`github.com/sagernet/cronet-go` at
`v0.0.0-20260912104727-0d28acc44093`. It verifies the whole original module
against `h1:CsvsLVIli53L6nzgEpyRjjWnRRhTds4D3eh5sEnF5Sw=` and the original
`naive_client.go` against SHA-256
`367a29cbc783270e07f00d28d77f6b463033805bf4e100b53100f9373bf0f5a5`.
Exactly two source anchors derive the H2 wire name and install the IPv6 rule.
Reversing both anchors must recover the complete original module checksum.
The native Cronet library is unchanged.

The existing Naive transport policy invokes this preparation from the shipping
mobile, relay/server and desktop preparations. Their source receipts include
the complete copied module and exact helper templates. Preparation refuses an
unrelated module replacement, altered source, partial projection, linked file
or shared file owner. It never edits the shared Go module cache.

The release source audit runs both policy suites:

```sh
python3 deploy/test_native_naive_transport_policy.py
python3 deploy/test_native_naive_literal_policy.py
```

The prepared native host runner retains its original H2/H3 transport suite and
requires `TestRouterVPNDesktopNodeNaiveLiteral` with all 23 leaves and its
parent verdict. Missing, duplicated, skipped or replaced verdicts fail the
gate. The source authority and native library must pass the existing runner's
readback before and after execution.

## Validation on 2026-11-09

The first real native baseline failed both captured IPv6 endpoint cases with
`name not resolved`; its eight original IPv4, credential and DNS controls
passed. An exact original-startup control then confirmed that a dotted IPv4
name also failed before reaching its TLS peer. The untrimmed native resolver
alias did not match the DNS question. With IPv6 mapping installed alone, the
dotted IPv6 case reached the correct peer, which rejected the trailing dot in
wire SNI. Those failures were retained separately from the final passing run.

The final production-order prepared source passed:

- 18 policy/source contract tests, including eight deliberate policy mutations
  that each failed at the intended boundary.
- 64 existing native-runner and source-authority contract tests.
- All 13 original prepared H2/H3 transport verdicts under the race detector.
- All 47 actual projected Cronet rule/name verdicts under the race detector.
- All 24 shipping native peer verdicts, plus all 11 verdicts from the unchanged
  original IPv6 witness, under the race detector.

The native peer cases used real TLS, the pinned Naive H2 client and inbound,
authenticated TCP and UoT-v2 payloads, captured UDP/TCP bootstrap definitions,
and separate wrong-user, password, TLS-name and certificate refusals. Dotted
IPv4 and IPv6 names both authenticated successfully; their wrong-host and
wrong-trust variants still failed. The caller's original native options were
checked byte-for-byte after construction/startup. Successful literal cases
made zero upstream DNS queries and zero lower UDP calls.

Two separate declared native overlays removed one anchor at a time. Removing
the IPv6 rule restored the original IPv6 failure. Removing wire-name derivation
restored the dotted IPv4 and IPv6 failures. Both controls retained the TCP-only
guard, native peer assertions and all other prepared source. The final source,
native library and executable identities were read back after execution.

## Evidence limits

This is a native protocol and source-preparation result. The captured IPv6
tuple was checked exactly and then mapped only to the owned local TLS peer;
the test does not establish a physical IPv6 route, system-TUN operation,
installed application behavior or current release acceptance. These H2
measurements alone do not establish native H3 IPv6 behavior; the separate
[H3 ownership unit](NETWORKING-REFERENCE.md#section-naive-h3-native-ownership) records that later evidence.

Zero bootstrap lookups in these literal cases do not authorize removing the
compiled resolver dependency or changing a captured UDP resolver to TCP.
Imported H2 graph admission, all producer inventories, physical peer matrices
and default Home-DNS compatibility have their own required source and native
checks. This unit preserves those boundaries.


---

<a id="section-naive-h3-native-ownership"></a>

# Naive H3 captured transport and native name resolution

## Shipping behavior

A captured literal Naive H3 endpoint owns one UDP tuple: its original IP address
and port. The Cronet transport callback now admits only UDP to that exact tuple.
It rejects TCP, alternate ports or addresses, noncanonical literals and packet
listeners before invoking the retained lower dialer. Application TCP and UDP
still travel through authenticated Naive H3; application datagrams retain UoT-v2.
The original caller context, returned connection and lower error are preserved.

Cronet can request an unrelated IPv6 reachability socket even when an outbound
has one captured server. The original native diagnostic observed and refused
`[2001:4860:4860::8888]:443` at its strict lower owner. The new literal guard
prevents that callback from reaching the lower owner. It supplies no synthetic
probe result and grants no substitute destination.

The checksum-bound Cronet projection now applies the existing IPv6 literal
mapping and terminal-dot-free runtime name to H3 as well as H2. The exact
hostname maps only to the original captured IPv6 literal, preserving its port.
The derived runtime name is used consistently for URL, resolver alias and TLS
SNI, following [RFC 6066 section 3](https://www.rfc-editor.org/rfc/rfc6066.html#section-3).
Saved options, source identity, credentials, certificate trust and selected DNS
are unchanged. Strict ASCII hostname validation prevents wildcard or resolver
instruction injection. The native Cronet library is unchanged.

## Raw hostname compatibility and scope

Shipping paired/imported Naive compilers validate a literal server. The broader
underlying native constructor also accepts raw hostnames. This unit returns the
identical original H3 dialer for that raw-hostname path, preserving its existing
DNS callback and lower-owner enforcement. It introduces no DNS-answer grant
observer, alternate resolver, ambient lookup or public-UDP exception.

The pinned outbound changes only the Cronet `Dialer` argument. Reversing that
one exact edit must recover the complete original source SHA-256
`9e01f79402408a0325b7e14334c0c8e72183f7963ca5efcc80bf201ea14c59f3`.
The original `DNSResolver` closure and its `ResolveDialer` remain byte-identical.
All mobile, relay/server and desktop preparations include the policy and its
source closure. The private Cronet copy retains the complete checksum/reversal,
ownership and drift checks documented in [the H2 resolution unit](NETWORKING-REFERENCE.md#section-naive-h2-native-resolution).

## Validation on 2026-11-09

The final production-order preparation passed `go mod verify`, then the following
strict gates without skipped verdicts:

| Gate | Observed result |
| --- | --- |
| Policy/source contracts | 18 roots passed, including seven transport and five resolver/name causal mutations |
| Existing runner/source-authority contracts | 64 roots passed |
| Prepared transport helpers | All 40 verdicts passed under the race detector |
| Projected Cronet helpers | All 83 verdicts passed under the race detector |
| Real native H2 and H3 peers | All 48 verdicts passed under the race detector, 24 for each protocol |
| Separate native causal overlays | All three failed at their intended boundary: unwrapped H3, removed IPv6 mapping, and removed dotted-name derivation |

The native peers retained the original IPv4/IPv6, UDP/TCP bootstrap, username,
password, TLS-name, certificate and fresh-owner controls. Wrong identity or
trust delivered no authenticated payload. Positive captured-literal cases
performed real authenticated TCP and UoT-v2 exchanges with zero upstream
bootstrap queries and zero unexpected lower callbacks. Removing only the H3
wrapper restored the unrelated callback; removing only the IPv6 mapping or
wire-name derivation restored the corresponding name/handshake failure.

The first literal-only run passed every actual literal case but failed the two
negative cases that deliberately replace the endpoint with a raw hostname.
Their former blanket zero-callback assertion did not match the chosen raw
compatibility scope. The corrected negatives require the exact original
refusal and exact original DNS authority; they do not permit any additional
lower I/O. The initial failure, final source and causal overlays are separate
records.

A separate test-only overlay compared the published original production at
`8be50dbfbd16173980ce672aa91dfba2cee65cc7` against this unit, using the same strict
lower owner and original resolver. Both A cases made one A query, opened one
owned UDP connection and delivered one authenticated TCP and one UoT payload.
Both still failed the strict unowned-callback diagnostic because the original
lower refused one unrelated reachability request. Both AAAA-only cases made
two A queries and no AAAA queries, failed name resolution, and opened no owned
UDP connection or authenticated payload path. Those failed diagnostics confirm
unchanged raw behavior; they are not successful generic hostname acceptance.

The actual native image SHA-256 was
`b97f181521e84aa2f06482388afaa997b07dcd0a7ac82ab6f943e8714b28b283`.
The frozen shipping source receipt contained 3,142 files with digest
`02a23a6922253ab1e3cee478f4ac7c66ebb02095324b77d763800a99390c5863`;
the 4,711 prepared entries had digest
`4a98b43bb3061de53fb9f7f7c5fecc2a197367399171a481f189cf20e5715e9f`.
The unchanged Linux AMD64 Cronet library SHA-256 was
`23109c55b08829bb1a68682a61a64852b1bbf243753b153cbd8f6e4ea2c05294`.
Source, prepared bytes and native library were read back after the final native
execution at 07:15:32 UTC and raw comparison at 07:17:32 UTC.

These measurements used the declared unit on base `8be50dbf`, not an existing
release artifact. The subsequent rebase preserves the tested unit bytes.
Current package/release source receipts must be regenerated for the combined
main tree; these protocol measurements do not substitute for them.

## Evidence limits

The native cases exercise actual pinned TLS/QUIC authentication, TCP payload and
UoT-v2 datagrams, with exact original lower tuples and independently captured
trust. The IPv6 tuple is remapped only to the owned local peer. This establishes
native protocol behavior; it does not establish a physical IPv6 route, system
TUN/WFP acceptance, an installed device result, or a completed current release.

The deliberately forced-hostname negative cases leave the literal scope. They
require the exact original lower rejection, a live original DNS request for
`unowned-bootstrap.invalid.`, the captured resolver with cache disabled, and
zero lower sockets, QUIC traffic or authenticated payload. Every actual literal
case separately requires zero unexpected lower callbacks and zero upstream
bootstrap queries. No failed raw-hostname diagnostic is counted as successful
literal ownership or generic raw-AAAA support.

An earlier experimental hostname-answer observer is explicitly superseded. Its
A/CNAME/TTL-zero controls did not establish raw-AAAA compatibility: the real
AAAA-only diagnostic requested A records, requested no AAAA records, and failed
before reaching the peer. That observer and its additional shipping gates are
absent from this unit. The experiment and initial fixture-scope failures remain
separate evidence, not native acceptance for the published source.

The imported H3 graph inventories, real entry-peer matrix, Windows protected
composition and package/release gates remain separate required evidence.
This standalone policy does not claim those feature gates are complete.


---

<a id="section-reality-udp443"></a>

# Explicit REALITY UDP/443 client capability

REALITY/Vision can carry UDP payloads, including selected DoH3, through its owned
encrypted TCP connection. The pinned Xray engine deliberately refuses UDP
destination port 443 for the ordinary `xtls-rprx-vision` client flow. The explicit
`xtls-rprx-vision-udp443` client flow permits that destination. Both use the same
existing mode identity, server credentials and ordinary Vision server inbound.
This adds no raw mode or logical picker entry.

## Obtain a capable original private bundle

For an intended installation or update, choose **on** at the installer's
**REALITY DoH3/QUIC on UDP 443 (keep/on/off)** question. With the image-only
Portainer stack, set:

```text
REALITY_CLIENT_FLOW=xtls-rprx-vision-udp443
```

The value reaches both initialization and finalization. An existing readiness
marker cannot suppress an explicit capability change: the finalizer compares
the requested flow with both actual generated client assets and their saved
generation state before deciding that the profiles are ready.

After finalization succeeds, obtain a new private `router-vpn-bundle.json` from
the authenticated Setup Center, then explicitly update or relink the intended
node in the app. Its original `reality-vision/xray.json` and
`reality-pq-vision/xray.json` contain the chosen flow before client capture.
Selecting DoH3 uses those captured assets and the selected resolver's address,
port, path, TLS name, trust and bootstrap. It never changes the original client
flow, substitutes another resolver, or grants SS UoT authority.

The installer defaults to **keep**, represented by an empty stack value:

| Choice | Generation behavior |
|---|---|
| `keep` / empty | Preserve each existing standard/PQ client flow independently. A fresh generation keeps ordinary Vision. |
| `on` / `xtls-rprx-vision-udp443` | Explicitly enable UDP/443 in both generated Vision client families. |
| `off` / `xtls-rprx-vision` | Explicitly return both generated client families to ordinary Vision. |

Removing an explicit stack setting later preserves the saved choice. To disable
the capability, select **off**, regenerate and explicitly update the device's
private node assets. A saved/imported device profile remains unchanged until
that update; regenerating server-side download assets does not rewrite a device.
The UDP payload travels inside the configured REALITY TCP transport.

## Source and lifecycle contract

`generate-xray-pq.sh` captures the exact requested flow in each original client
and persists `standard_client_flow` and `pq_client_flow` independently. Older
state without these fields is recovered from each existing original client.
An absent older client falls back to the ordinary historical flow; a saved
capability can regenerate a missing client without losing its choice.

Malformed or foreign flows, duplicate client fields, a different client UUID,
non-private or redirected files, and disagreement between an existing client
and saved state are refused before authoritative generation. Explicit enable
or disable does not override a malformed source. Engine validation precedes
the existing private atomic batch, and a partial adoption failure restores the
previous client assets and state.

The shared native compiler and actual Swift host accept exactly the two Vision
flow strings and retain their source bytes. Saved wrappers cannot be restored
using a different original flow. Both independently owned Start Layers retain
the captured capability. XHTTP still requires its original empty flow; its
transport is not converted to Vision. Dual-transport modes keep their existing
packet route and mode identity.

The native flow option changes only client-side permission to carry UDP/443.
The server inbound continues to use `xtls-rprx-vision`; the pinned engine
normalizes the explicit client suffix for the wire protocol. Private/public
node proof, DNS proof, connection ownership, cancellation and teardown remain
required before reporting a usable connection.

## Shared Vision detector ownership

The pinned engine's Vision reader and writer share one TLS detector. Native
race instrumentation exposed an unsynchronized packet-budget read in the writer
while the reader updated that detector. The runtime preparation now protects
the complete detector transaction: packet budget, TLS classification, cipher,
remaining ServerHello bytes and permission to switch to direct copying.

Each state has its own lock. The writer captures one coherent detector result
for its padding decisions; the reader checks the detector budget through the
same synchronization. Existing direction-specific framing fields keep their
reader or writer owner, and the user identity stays immutable. The public
`XtlsFilterTls` entry remains available and uses the same protected parser.

Only in-memory detection holds this lock. Underlying reads and writes, raw
connection access, counters and padding run outside it. Parser diagnostics
capture scalar arguments during detection and invoke the logger after unlock,
so a diagnostic callback may reenter the parser. No handshake rule, cipher,
authentication check, flow, packet bound or wire byte is changed.

The preparation accepts only the complete original or complete synchronized
`proxy.go` for the existing Xray pin. Partial changes and different source bytes
are refused before preparation writes another file. The native regression uses
actual Vision readers, writers and independent padding peers; its causal
control restores only the original pinned parser and must expose the original
race. Bounded blocked-I/O and isolated logger-callback cases also remain
required. These checks supplement the selected-DNS protocol matrix.

## Verification boundaries

The generation suite executes the actual generator, preservation reader,
private bundle writer and atomic transaction. It uses explicit engine-command
test doubles, then sends the generated bundle through the real shared Go
compiler. It covers ordinary fresh defaults, explicit enable/disable, mixed
saved choices, older state, missing-client recovery, rejected malformed/private
sources, candidate validation failure and observed partial-adoption rollback.
These checks establish the provisioning/capture path, not encrypted traffic.

The actual Swift fixture exercises original source preservation, selected DNS,
cold Codable restoration, saved-wrapper mismatch rejection and unchanged mode
identities. The separate native gate runs the pinned Xray and actual sing-box
DNS transports through the captured native owner, including HTTP/3, ordinary
Home UDP DNS, DoT and DoH. It must retain plain Vision's UDP/443 refusal and
reject incorrect TLS trust/name, resolver route/port/path, Xray key and stale
owners. Cancellation, close and replacement ownership remain mandatory.

The final source-bound native result, exact-SHA native packages, release
publication, private deployment and physical-device acceptance are separate
evidence. No live target is modified by implementing or testing this capability.


---

<a id="section-desktop-tor-owned-egress"></a>

# Captured desktop Tor physical sockets

The desktop Tor native lower dialer and selected bootstrap DNS use an explicit
owned-socket capability for dynamic Direct paths. Linux now has an implemented
privileged UID/socket guardian, native factory and exact nftables boundary for
plain Tor, meek, WebTunnel and Snowflake. It requires the captured privileged
launch path; an ordinary user process cannot manufacture that authority from
JSON or a command argument. Public dynamic strict admission on Windows and
macOS remains gated until their corresponding native policy/identity and
launcher integration has passed its actual host checks. The Darwin guardian and
retained-utun foundation below is implemented behind that gate; its source and
cross-compilation are not a native PF acceptance result. The existing exact,
fixed obfs4 endpoint path remains available.

## Actual native call path

The real `routervpn-desktop-tor-network` service captures the immutable session,
full source identity and a fresh network-generation nonce. A source may request
`physical_broker`, but that flag creates no authority. Before activation, the
native host must supply a `DesktopSocketBroker` backed by an independently
provisioned `DesktopSocketPolicy` and bind it to the actual concrete
`routervpn-tor-physical-egress` outbound in the same Box.

Activation emits a private context capability. Both the C Tor guard SOCKS proxy
and the in-process pluggable transports already call the captured desktop lower
dialer. When this capability is required, that lower dialer detours through the
physical outbound. Every selected bootstrap-DNS transport and dependency must
use the same detour; the existing native resolver dependency capture rejects a
DNS path that escapes it. The broker receives numeric destinations and never
resolves a hostname using the system resolver.

Missing capability, wrong full source, another network generation, duplicate
binding, an unrelated context, a replaced native outbound or a network reset
rejects the operation before any socket permit. Ordinary predecessor-routed
Tor continues to use its captured predecessor; the physical capability cannot
replace that owner.

## Kernel socket and policy lifetime

`DesktopSocketPolicy` is an OS boundary, not a receipt decoder. Its owner must
identify an independently provisioned kernel identity. A process path, shared
UID, printed PID or caller-supplied tuple is insufficient. `Current` is a bounded
memory-only witness. `Bind` captures and verifies the actual raw descriptor and
creator identity, then applies and reads back the captured physical interface.
`Grant` independently verifies the actual bound socket's kernel owner before
installing and reading back the exact owner, interface, transport, local
address/port and remote address/port. This permits native bound-socket identity
queries that are unavailable before bind; it does not permit any connect or
data write before the complete owner/tuple acknowledgment.
`Revoke` acknowledges both deletion and an independent absent readback.

The native broker exclusively binds the actual kernel socket before requesting
permission. It retains a duplicate handle until permission removal and all
entered I/O have joined. A failed or canceled connect cannot free an authorized
source port while a late/unknown control result remains outstanding.

There are at most 128 captured sockets and 32 actual peer tuples per UDP socket.
Binding UDP alone grants no traffic. Each new STUN/ICE/peer destination requires
its own acknowledged tuple before a datagram is written. Incoming datagrams
from ungranted peers are discarded without copying their bytes into the
application's buffer. A valid existing grant continues to carry data while its
renewal is pending; the renewal does not serialize healthy UDP traffic.

An accepted receipt must match every captured field and the actual request
sequence. Native observations are at most five seconds old, and a grant ends
within ten seconds of its observation. Data deadlines and an independent
memory-only monitor enforce the earlier bound even when a control operation is
blocked. Expiry cancels the exact socket's connect/renewal work and interrupts
entered reads/writes. Cleanup joins delayed control calls, confirms exact
permission absence, then releases the socket handles. A failure remains owned
and retryable; it does not acknowledge a successful close or touch a replacement.

### Platform socket implementation

Linux and macOS disable and read back address/port reuse, bind the actual local
address and retain a duplicate descriptor. The ordinary creator continues
through the native Go TCP dialer. Windows uses `SO_EXCLUSIVEADDRUSE` and retained
Winsock handles. Its TCP
connection directly owns nonblocking Winsock connect/read/write with bounded
`WSAPoll` waits, cancellation and actual I/O joins. The Go Windows dialer binds
again before `ConnectEx`, so handing an already bound/authorized socket back to
it would fail. No temporary unbind, guessed source port, unsafe netFD or
`CloseHandle` substitution is used. Other qualified Unix targets still reject
this new capability until their socket adapter exists.

### Imported Unix socket creator

A trusted policy may additionally implement `DesktopSocketSource`. This is a
typed factory capability; JSON cannot select a socket provider. Its request and
reply bind the entire source/session/network capture, kernel owner, physical
interface/address, fresh socket ID and TCP/UDP protocol. The broker takes
ownership of a returned file before inspecting any reply or error, including a
late result after cancellation. Missing or changed fields cannot reach Bind.

The Unix implementation independently checks the actual descriptor is the
expected kernel socket family/type, still unbound, not listening and not
connected. It then uses the same Bind and exact grant path as the ordinary
creator. `net.FileConn` and `net.FilePacketConn` duplicate the supplied kernel
socket; they do not create a new socket under the receiving process's UID. TCP
connect begins only after acknowledged permit readback and uses that same
descriptor with Go's network poller, bounded cancellation and an actual peer
readback. UDP import installs no peer grant until the captured peer is used.

The privileged policy must still read the actual kernel creator independently.
On macOS, XNU stores the creator credential in the socket's `so_cred`; both the
PF socket lookup and socket `fstat` UID derive from that credential. An SCM_RIGHTS
reply's claimed UID is not this proof. The Darwin guardian below implements the
separate allocator, helper authentication and PF boundary; imported-descriptor
tests alone do not prove that privileged composition.

Cancellation revokes pending source creation. Broker Close waits for the
creation/transfer operation, every exact permit's absent readback, all entered
I/O, and all original/imported/retained socket handles. It then requires the
source's retryable Close to join its creator processes and descriptor transfer.
An error or unknown creator close cannot release the isolated identity. The
privileged guardian must retain the identity until that complete acknowledgment
and must also cover native-process crashes independently.

## Linux privileged guardian

`DesktopLinuxSocketPolicy` is constructed by the native network-owner factory
after the real default-interface monitor initializes and before the Box starts
its TUN. Captured interface name, index and addresses are independently checked
against the kernel. IPv6 Off omits the IPv6 physical binding. A real default
network change retires the generation; creation of the owned TUN does not replace
the captured physical interface.

The launcher first installs the existing `inet router_vpn_killswitch` output
chain with policy drop and an exact session/source comment. Dynamic Direct
launch adds no global public-endpoint exemption. The guardian requires the
complete expected baseline, including selected LAN allowances, before creating
any account. It then captures the table, chain and every baseline rule handle
and expression. A later broader accept, changed rule, inactive marker or
replacement chain cannot become a new grant. Permits live inside this same
output chain: acceptance in an unrelated nftables table would not override its
drop policy.

An independently running root guardian allocates a fresh high numeric UID with
a locked password, expired account, no home directory and a nologin shell. A
private root-owned record captures the source and UID before `useradd` can
mutate the account database. Kernel/socket ownership does not come from a
printed account name. Every socket is created by an otherwise empty fork/exec
child under the allocated UID with no supplementary groups. The child transfers
the unconnected descriptor over an inherited anonymous sequenced Unix socket
and joins before the guardian acknowledges creation. Actual SCM credentials,
socket inode, `SO_COOKIE`, socket UID, transport and address family are checked.
The guardian retains a duplicate independently of the native process.

Before a grant, the guardian verifies the retained descriptor's identity and
actual local tuple, reads back `SO_BINDTODEVICE`, checks the captured interface
address, and rejects either address or port reuse. The nftables rule combines
the dedicated originating socket UID with the exact interface, local address and
port, remote address and port, and TCP/UDP family. Each tuple has a nine-second
kernel timeout; the native receipt expires after seven seconds and is issued
only after independent rule, set, tuple and timeout readback. A stopped or
killed guardian cannot extend a permit. Every selected bootstrap DNS socket
uses this boundary, with exact private resolver/bridge exceptions. An enabled
Home LAN policy retains its explicitly captured private-prefix allowances;
choosing Home AdGuard alone grants no other LAN access.

Cancellation retains the source port until the exact permit is absent and all
native I/O and handles have joined. Per-socket `ReleaseSocket` then closes the
guardian's duplicate, so sequential connections do not consume the 128-socket
limit indefinitely. Final account retirement requires every source descriptor
to have completed that acknowledgment, all rules/sets to be absent, and the
creator processes to have joined. Native-process EOF makes the independent
guardian remove permits and close its retained handles. Exceptional or unknown
outcomes retain the locked account and its recovery record to quarantine the
UID; they never guess that identity reuse is safe. Old-owner cleanup removes
only its captured rule/set identities and preserves a replacement session.

The Linux source requires root, nftables, `useradd`, `userdel`, and `nologin` in
the trusted system locations checked by the installer and runtime. The native
installed GUI now uses a fixed polkit-authorized controller, anonymous
credentials/lifetime input, authenticated local API, and retained installation
locks; see [native installation and permissions](LINUX-NATIVE-INSTALL.md).
Its separate fixed-install namespace and real GTK callback tests supplement
the socket guardian tests. These results do not establish an interactive
authorization prompt, a public Tor circuit, or physical-device acceptance.

## Darwin guardian and retained-control foundation

`DesktopDarwinSocketPolicy` uses a separate root guardian and an otherwise empty
creator under a fresh, disabled high numeric UID. A root-owned private record
captures the UID before Directory Services changes; the allocator also checks
the actual system user namespace. Reuse is prohibited while an outcome remains
unknown. Normal retirement requires exact account readback, absent permits,
joined creators and complete descriptor acknowledgment. Unexpected native or
guardian death quarantines the UID and its recovery record.

The anonymous inherited Unix stream transfers descriptors with `SCM_RIGHTS`.
Each bounded frame checks the actual peer PID after reception. Unexpected
ancillary rights on later stream fragments are closed and rejected. The
retained physical socket's creator UID, socket/PCB identity and generation come
from `fstat` and `proc_pidfdinfo`; claimed JSON identity does not grant a tuple.
`IP_BOUND_IF`/`IPV6_BOUND_IF`, transport, family, bound address/port, reuse flags
and the current kernel interface are checked before permission.

The scoped PF baseline uses `com.apple/000.router-vpn`. An exact session/source
label and complete canonical rule readback precede account allocation. A packet
starts with an unproved tag. Only the exact isolated UID and complete physical
tuple, the retained TUN, or selected LAN/link allowances can apply the permitted
tag. These permitted rules and their enclosing anchors are nonquick so later
foreign blocks can still apply. An untagged packet takes a quick deny before a
later foreign pass. The native tests exercise both nested-anchor directions;
lexical anchor placement alone is not the proof.

Physical permits use `no state`. PF has no independent absolute timeout for
these rules: its state timeout can refresh with traffic, and closing `/dev/pf`
does not remove a committed rule. This implementation does not claim otherwise.
Native receipt deadlines and an independent memory-only monitor bound new and
entered application I/O. The guardian retires expired grants independently of
native control requests. Both processes retain the actual socket until absent
readback and I/O join. If both die, their descriptors close; a different UID
reusing the tuple does not inherit the stateless permit. A stalled holder still
pins the socket and UID, including already queued native traffic. A quarantined
UID is never automatically recycled after an unknown outcome.

Before new physical admission, the code captures all current addresses on all
up physical adapters, including temporary IPv6 addresses and nondefault
adapters. It retires interface-bound states and floating states for those exact
local addresses in both directions, then verifies actual state absence and
interface policy. It does not globally flush PF state, require an empty global
state table, or modify unrelated loopback/tunnel states. A changed address set,
PF bypass flag, replacement baseline or replacement generation retires the
captured admission.

The Unix launcher installs an empty captured native baseline, with no invented
public endpoint or name-only utun allowance. It persists the exact PF reference
and both fixed owned anchors before changing a filter during handoff. A failed
or ambiguous kernel command therefore retains cleanup authority and deny. The
intermediate record stays pending until final successful installation; status
does not promote it to active. The Always path restores an inactive baseline
without a former session, UID, tuple or tunnel permission. Only the native
owner can subsequently admit a new descriptor.

TUN permission requires the actual exclusively created utun control descriptor.
The checksum-pinned `sing-tun` adapter duplicates that descriptor under the same
native lifecycle ownership used for Close and MTU replacement. The independently
running guardian receives and verifies the real kernel control, retains it, and
removes its PF permission before releasing it. A name and interface index alone
cannot authorize a reusable utun.

Current compatibility is bounded: foreign stateful passes in either direction
and active translations are rejected before a grant because their states can
bypass the next creator-UID check. The code preserves those foreign owners; it
does not rewrite their rules. Support for narrower nonintersecting stateful
coexistence remains unfinished. Stock/stateless composition must first pass the
actual Darwin gate before public dynamic strict admission is enabled.

`deploy/test_desktop_darwin_guardian.py` compiles exact repository or prepared
sources with the selected native Go compiler, Cgo, and the race detector. Only
the captured test executable is elevated. The fixture creates four fresh
loopback aliases, a unique PF anchor and disabled temporary identities; every
permit/deny mutation is limited to those aliases. It retains an actual utun
without installing default routes. Cleanup joins only processes whose executable
is the exact unique fixture path, clears only its anchors, removes its aliases,
and balances its PF reference. Failed cleanup retains its private recovery
record instead of claiming success.

The required kernel cases cover TCP/UDP over IPv4/IPv6, wrong creator UID at the
same tuple, uncaptured private peers, 130 sequential socket retirements, actual
utun descriptor retention, native-only and simultaneous guardian/native crashes,
foreign-block and later-pass composition, stateful inbound/outbound rejection,
blocked control with source-port retention, floating-state retirement, stale
network capture, replacement-safe cleanup, and refusal to finish with an
unretired descriptor. The runner rejects skipped or missing cases. The early reusable Intel/ARM job
and the matching native packaging gate use
`--mutations`, requiring the specific native assertion to reject five
intentionally broken production boundaries. Source cross-compilation and a
Linux socket run do not establish any of these Darwin kernel results.

## Remaining platform boundaries

Windows now has actual native evidence for its isolated token/socket identity,
exact WFP baseline and socket permits, four-family connected traffic/renewal,
blocked-control cleanup and process-death rundown. The generated Windows
factory captures the real adapter, mask, DHCP lease and generation; its
constructor-seam tests establish wiring only. The final compiler-to-native
selected-DNS and launcher composition remains required before public admission.
See [Windows owned sockets](PLATFORM-INTEGRATION.md#section-windows-owned-sockets) for the exact completed
job steps and their release limits. The macOS foundation and captured launcher above
still need their actual
native compiler/kernel result and final compiler/admission integration.
Its broader foreign-stateful PF coexistence remains a separate unfinished
boundary. Both platforms must prove identity retention across native-process
and launcher crashes before public strict dynamic Direct admission can open.

## Executable evidence and limits

The shared suite uses actual local TCP/UDP sockets, transferred bytes, bound-port
conflicts, expiry, cancellation and entered-I/O joins. Its portable policy calls
use explicit fixture doubles. The separate Linux kernel suite below uses the
actual privileged implementation. The native suite constructs the actual lower dialer, physical
outbound and selected TCP DNS transport, and checks their real loopback traffic
and rejected capability/owner/DNS substitutions.

The selective desktop preparer copies the exact shared lifetime tests. The
mandatory native runtime build executes `TestDesktopSocket` on matching desktop
hosts, alongside the PT/network-owner tests, before building and packaging the
runtime. Windows ARM64 uses the existing no-race exception from the pinned Go
toolchain; other shipped desktop hosts retain race instrumentation. Successful
cross-compilation alone does not establish those Windows/macOS socket results,
kernel firewall enforcement, public Tor operation or physical-device acceptance.

The explicit `routervpn_privileged` UID fixture uses a real fork/exec under a
random unused test UID and SCM_RIGHTS transfer, then verifies the actual creator
UID after transfer, connection/packet import and retained duplication. Its
IPv4/IPv6 TCP/UDP cases exchange actual loopback bytes; a wrong kernel UID is
rejected before any grant. This fixture creates no accounts or firewall policy
and is not production UID allocation or PF acceptance. Tests selected by this
tag fail when their required root privilege is missing; they do not skip.

`deploy/test_desktop_socket_uid.py` verifies the exact copied socket sources,
compiles the fixture as the build user, and executes only the privileged UID
tests under available root or noninteractive system sudo. Matching Linux and
macOS native builds require this gate before packaging. The Windows build path
is unchanged. macOS socket execution must be established by its actual native
runner, separately from a Linux fixture or Darwin cross-compilation.

`deploy/test_desktop_linux_guardian.py` verifies and hashes the exact prepared
Linux sources, resolves the native build's actual selected Go compiler, and
builds the `routervpn_linux_guardian` tests with race instrumentation. It executes
them only in fresh user, PID, mount and network namespaces with private account
files and `/run`, a veth link and a separate peer namespace. The host account
database, routes and firewall are untouched. Every required case must run and
pass; missing privilege or kernel functionality fails the gate instead of
skipping it. Matching Linux native packages require this gate before compilation
and packaging.

The ten real-kernel cases cover actual TCP/UDP bytes over IPv4 and IPv6, kernel
rejection of a matching tuple from the wrong UID, uncaptured private peers,
independent expiry after guardian SIGKILL, 130 sequential socket retirements,
broader-baseline rejection, native-parent crash cleanup and guardian join,
blocked-control source-port retention, stale source/network generations,
replacement-safe cleanup, and refusal to retire an identity with an outstanding
native descriptor. The runner's `--mutations` mode uses temporary Go compiler
overlays to remove UID enforcement, extend kernel expiry, omit baseline checks,
skip per-socket release, and skip final descriptor acknowledgment. Each broken
production variant must fail its corresponding actual-kernel assertion. The
working tree and prepared source are not edited by those controls.

## Primary mechanism references

- Go Windows connect implementation: https://cs.opensource.google/go/go/+/refs/tags/go1.26.3:src/net/fd_windows.go
- Winsock exclusive binding: https://learn.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse
- Winsock socket duplication: https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaduplicatesocketw
- Winsock nonblocking mode: https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-ioctlsocket
- Winsock polling: https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsapoll
- WFP condition identities: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/filtering-condition-identifiers
- WFP dynamic-session object cleanup: https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
- nftables owner expressions, tuple sets and timeouts: https://netfilter.org/projects/nftables/manpage.html
- nftables originating socket UID matching: https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_metainformation
- Linux socket inode credential allocation and UID changes: https://github.com/torvalds/linux/blob/master/net/socket.c
- XNU socket creator credentials: https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/uipc_socket.c
- XNU socket fstat UID readback: https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/sys_socket.c
- XNU PF socket lookup: https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pf.c
- XNU TCP/UDP PCB credential lookup: https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/in_pcb.c

The Darwin mechanism also relies on the primary XNU control/state definitions:

- PF state matching and rule ordering: https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/net/pf.c
- PF interface-bound and address-specific state retirement: https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/net/pf_ioctl.c
- Actual utun control lifetime: https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/net/if_utun.c


---

<a id="section-desktop-tor-runtime"></a>

# Bundled desktop Tor runtime

The complete desktop native bundle owns `tor-routervpn` (`tor-routervpn.exe`
on Windows), `TOR-RUNTIME.json`, `TOR-SOURCE-LOCK.json`,
`TOR-PADDING-SOURCE-LOCK.json`, and `TOR-LICENSES.json`. These five files are
included in the existing `NATIVE-RUNTIME.json` payload inventory and exact-source
package. They are installed and upgraded with the native runtime transaction;
private node/profile files remain separate.

## Build and native acceptance

`deploy/build-desktop-tor.py` uses the same four pinned upstream source archives
as the mobile and server builds. OpenSSL, libevent and zlib are linked statically.
The Tor process keeps its original standalone lifecycle, with only the captured
outgoing padding extension applied. The installed Linux executable has no ELF
interpreter or dynamic dependencies. macOS permits only its explicit system
libraries, and Windows permits only the explicit OS/API-set DLL inventory.

| Application package | Tor executable | Required execution gate |
|---|---|---|
| Linux AMD64 | Linux AMD64 | Actual native C tests and disabled-network control |
| Linux ARM64 | Linux ARM64 | Actual native C tests and disabled-network control |
| macOS Intel | macOS x86-64 | Actual native C tests and disabled-network control |
| macOS Apple Silicon | macOS ARM64 | Actual native C tests and disabled-network control |
| Windows AMD64 | Windows AMD64 | Actual native C tests and disabled-network control |
| Windows ARM64 | Windows AMD64 user-mode helper | Actual tests on Windows 11 ARM64 under supported x64 emulation |

The Windows ARM64 application and driver remain ARM64. Its Tor receipt explicitly
records `executable_target: windows/amd64` and
`execution: windows11-amd64-emulation`; it does not assert a native ARM64 Tor
build. Microsoft documents the distinction between user-mode x64 emulation and
native drivers in [Windows on Arm emulation](https://learn.microsoft.com/en-us/windows/arm/apps-on-arm-x86-emulation).

The Windows prerequisite job cross-compiles Tor and the matching C tests with
the existing checksum-pinned LLVM-MinGW toolchain on Linux. Its
`TOR-COMPILE.json` is marked `compiled-awaiting-native-execution`; this artifact
cannot be consumed as a completed package. Each actual Windows runner validates
the entire source/file closure, executes the tests, then seals its own platform
receipt. Linux and macOS compile and execute on their actual architecture.

The native test selectors are `routervpn_padding/..`, `routervpn_lastrelay/..`,
`relaycrypt/..`, and
`cellqueue/..`. The separate test executable is CI material and never enters the
installed native payload. Tor's Linux test executable may use the host C loader;
the installed Tor executable still requires fully static linkage.

## Offline owner and extension proof

Packaging starts the actual process with `DisableNetwork=1`, a fresh private
data directory, no SOCKS/DNS/transparent listeners, and one numeric loopback
control listener. The gate verifies the exact cookie path and SAFECOOKIE server
authentication, rejects incorrect authentication, checks the process ID,
listener inventory and zero traffic counters, and confirms the selected PT
socket configuration without enabling network traffic.

`ROUTERVPN_PADDING INFO` must reject a controller before `TAKEOWNERSHIP` and must
return the exact compiled outgoing-only capability afterward. An attempted
padding start must remain rejected while networking is disabled. Closing the
owning control connection must terminate the process. A stock Tor executable
passing `--version` cannot satisfy these checks.

`deploy/test_desktop_tor_package.py --package ... --target ...` repeats these
checks after relocation and verifies the package's source locks, licenses,
architecture and dependencies. `--within-native` validates the Tor files inside
the larger native inventory. Six-target object-format fixture tests exercise
negative metadata and dependency cases; those fixtures are explicitly separate
from actual C/process evidence.

The controller's `verifyBundledTor` resolver verifies the complete native
package and exact Tor payload at the fixed owned path. It does not search PATH
or an unrelated stock Tor directory. Native packaging CI also runs the actual
Go receipt/architecture verifier against the produced C executable. macOS
signing signs both native executables, updates only their controlled receipts,
and preserves the source and license records.

These build/control gates do not establish public-network bootstrap, selected
live circuit behavior, physical-device acceptance, Apple distribution signing,
or completion of every Tor graph requirement. Those retain their separate
runtime and device acceptance evidence.
