# Current implementation status

Updated October 22, 2026 (America/Chicago). This file describes committed source
and remaining delivery work. The binding scope is [REQUIREMENTS-RECONCILED.md](REQUIREMENTS-RECONCILED.md).
Source tests, native configuration tests and older releases do not establish
completion of the current commit's packages, physical devices or deployment.

## Current continuation

The source has advanced beyond the old WireGuard-only mobile multihop and
mobile-Tor exclusions. Those historical restrictions no longer describe the
application source and must not trigger reimplementation of committed work.

The October 22 continuation has published these bounded changes:

- Complete Android connection profiles and desktop connection profiles retain
  the captured external path and references to private credentials. Android
  measured hop selection uses a temporary owned entry, rejects stale results,
  and restores the captured session. Its quick candidate sample is separate
  from the durable 50-sample node benchmark.
- Desktop external paths preserve Home AdGuard as the default and capture its
  address from the Router VPN entry. A direct path without a usable selected
  resolver is rejected before stopping a working connection. Explicit Rescue
  and custom resolver choices remain explicit.
- Shared paired external Shadowsocks Server/Compare execution uses an
  authenticated isolated lease, an explicit TLS response endpoint, independent
  node/DNS/exit proof, the required comparison formula, and checked cleanup.
  Apple hosts now wire that path through PacketTunnel, all 19 supported entry
  mode families and their Start Layers, saved profiles and source-bound
  restoration of the already-proved winner. This does not establish server
  execution of every external protocol.
- The Apple MAX hostname handoff, captured LAN-policy fixtures, macOS session
  transform and Windows/macOS Tor composition checks have executable
  regressions. The current source does not need the old MAX hostname or
  composite-exit fixture patches reapplied.

Published references for these changes are `5dfc934a`, `520b50ba`, `e4f82958`,
`a6188b3d`, `75a90caf`, `b28178a1`, and `a444e6df`. Their local tests and source
integration do not certify another commit's native packages or device behavior.

The further October 22 continuation has published these source changes:

| Commit | Captured behavior and regression boundary |
| --- | --- |
| `34ab1386` | Requirement audits retain authenticated AES Start Layer and optional XOR whitening. |
| `23aced17` | The pinned native SOCKS UDP endpoint race is fixed in the owned source copy, with race-detector and unpatched negative-control evidence. |
| `e5495b8c` | Apple Tor Home drafts, DNS editing and runtime composition retain the complete captured predecessor. Native host/export source gates agree. |
| `de5cf026` | Android paired external Server/Compare reaches the real native lifecycle, preserves its permission/profile capture and restores the previously proved winner. |
| `0ec5a1c7` | The registered server HTTP boundary accepts and authenticates the captured external fingerprint/authentication pair; malformed and replayed requests remain rejected. |
| `453d1966` | Missing or blank mobile external-node DNS uses Home. Idle editing and runtime share the actual parser; explicit Rescue/custom choices are preserved. |
| `4a1f7cd6` | Android profile contracts verify execution retention at the actual new call site. The four previously failing source gates pass on this commit. |
| `0bfb3bf3` | Windows, macOS and Linux measure exit candidates through an owned native entry and validate current receipts before changing the exit picker. Generated full/split WG/AWG assets share one strict native parser. |
| `4485a69a` | Windows PowerShell 5.1 and isolated Unix MTU fixtures exercise the same production behavior with portable test inputs. |
| `70325a69` | Apple candidate measurement binds the entry, source, physical network and selection; waits for native socket drain; and restores captured state. Linked-node reads are pure, imports make one validated atomic commit, and ambiguous native cleanup retains ownership. |
| `3c46bc57` | WG/AWG assets must match the saved endpoint before bootstrap. Native candidate cleanup captures Windows directory identity eagerly and preserves replacement directories. Source audits follow the current Android execution and Apple atomic-link contracts. |
| `b2ae0257` | Repeated native preparation composes packet concurrency and UDP capacity fixes in one checksum-verified `sing` copy, including default/low-memory builds and verified upgrade of the earlier owned copy. |
| `f29b6d2d` | Android and Apple DNS comparison runs through the captured native external/Tor path, validates complete source-bound receipts, and retains cancellation ownership until actual native drain. |
| `1394ec8f` | Standalone native runners prepare their complete Tor/AWG policy dependency closure. Windows source checks normalize CRLF; TLS denial fixtures use real joined TCP connections; mobile MTU/proof fixtures include the owned DNS activation boundary. |
| `34fb6128` | Native vector maps, mobile telemetry/startup/update controls, captured desktop WG/AWG profiles and complete six-target runtime delivery are wired into the native application and release paths. The full Linux runtime producers passed on both architectures; the first cross-platform run exposed the preparation and fixture failures described below. |

This native UI continuation replaces the visible Apple stock map with a
shared opaque vector basemap. Both application packages ship the same pinned
land outlines; native MapKit still owns coordinate transforms, gestures and
annotations. Refresh preserves the custom base, date-line routes stay short,
and macOS map taps use guarded saved node selection without connecting.
The shared geometry passes 298 executable Swift checks, with route and
selection negative controls. Apple SDK compilation and real bitmap rendering
are mandatory in the native shipping lanes; the Linux run does not claim them.
See [NATIVE-VECTOR-MAP.md](NATIVE-VECTOR-MAP.md).

Android updates are reachable from Help → More → Updates even when notification
permission is denied. Discovery joins one owned worker, and download actions
require an unexpired receipt tied to the installed source and exact release
asset. The real provider/dialog source passes 117 executable checks with
Android and HTTPS boundaries doubled, plus installed-source and expiry
mutation controls. This does not establish a physical Android upgrade or a
production APK signing identity; see [AUTO-UPDATES.md](AUTO-UPDATES.md).

Android startup now executes the saved per-node policy once per cold app
process. Auto-connect defaults to Off; SMART AUTO, AUTO, Last / AUTO and Manual
are reachable settings. Permission recreation retains only a nonce referring
to the captured private request. Router and external paths preserve the saved
entry, exit, execution choice, credentials and policy; a foreign VPN, changed
selection/source, manual Disconnect or newer owner invalidates the request.
External choices retain the saved protocol and path, with fresh native proof.
Router Last / AUTO tries the last proved runtime only when it still satisfies
the current policy, then uses AUTO after ordinary failure and completed cleanup.
Resume/rotation never starts another attempt. Startup passes 899 executable
checks and two mutation controls; the real mode selector passes 70 scenarios
and 442 checks, including cancellation before late proof adoption. The complete
Android runtime contract passes all 44 registered executable fixtures in one
uninterrupted run against this continuation's source.

Mobile telemetry now separates direct probing, live routed RTT, current-path
throughput and saved 50-sample statistics. Android captures the exact native
VPN owner and physical network; iOS uses a provider-owned connection with
proof-before-token delivery. Both reject changed source/session/network state
and retain measurement/MTU ownership until native cleanup completes. Only a
complete 50-sample run replaces a durable record, including minimum, median,
average, 10% trimmed mean, p90, maximum and measurement date. A partial run or
failed write leaves the previous record and ranking intact. Android telemetry
passes 159 checks and nine negative controls; iOS telemetry passes 230 checks
and two controls. Its native read adapter additionally passes 21 signed-limit
and callback checks against the imported unsigned API shape; the historical
Int-to-UInt call fails compilation as expected. These executable tests double
the declared OS boundaries;
physical routing, endpoint throughput and network transitions remain separate.

The desktop candidate backend uses a private authenticated userspace lane with
real upstream TCP handshake timing, exact entry proof before and after samples,
captured private sources and physical-network validation. It changes no system
TUN or route. Results become selectable only after sockets and the owned process
have drained. Windows, macOS and Linux now follow the same saved Auto/WG/AWG
base decision as Connect. Complete captured Router profiles retain both hops'
DNS, cover traffic and authenticated Start Layers. The real complete Linux
engine accepts the 36 captured Local/Server WG/AWG graphs; stale proof/source
regressions pass with race detection. Quick samples do not overwrite direct
latency or the durable 50-sample benchmark.

Desktop delivery previously omitted the complete runtime despite having its
builder in source. All six native target producers now build/verify the engine,
its Cronet payload where required, licenses and exact source/target/file
receipt. Installed and Portable archives are checked after compression.
macOS signs a verified staged bundle and seals only its own signed result;
Windows/Linux installation and the same-image Windows download fallback carry
all required runtimes. The actual Linux engine passed 28 receipt/relocation
checks plus the graph gate, and its payload survived artifact extraction and
installed/Portable archive roundtrips. Delivery/signing boundary tests pass 375
checks. Windows runtime installation passes 202 filesystem checks and two
rollback mutation controls. Linux passes 15 transaction checks and actual
first-install and upgrade verification of all three built engines. These
transactions cover runtime directories, not every outer installer action.
A six-target packaged result still requires the new commit's CI.
See [NATIVE-DESKTOP-DELIVERY.md](NATIVE-DESKTOP-DELIVERY.md).

The `34fb6128` CI built, validated and uploaded the complete native Linux
runtime for both x64 and ARM64. Its first Windows and Apple runs exposed
platform-specific preparation and test boundaries: Windows text-mode source
copies changed canonical line endings, Cargo output was decoded with the host
code page and mixed progress into JSON, macOS bindgen lacked its SDK sysroot,
and the standalone Apple bitmap fixture used Quartz coordinates and a different
color space from the native map. The corrective continuation preserves copied
source bytes, separates strict UTF-8 metadata from compiler diagnostics,
supplies the macOS SDK explicitly, and gives the bitmap fixture the real map
transform and palette. The corrected geographic bitmap checks passed on the
`55c6a903` Apple runners. The next native check exposed the ineffective
`showsBuildings` setting with custom overlays, so the map now installs the supported
flat/muted MapKit configuration with traffic and points of interest excluded.
The opaque geometry renderer is unchanged; mirrored-land and omitted-map-policy
negative controls remain subject to the actual Apple SDK gate. Source audits
now follow the captured multihop proof implementation and require both owned
proof lanes at their current call sites. These corrections retain their
verification gates. The real Git checkout fixture also prevents detached
maintenance from racing its temporary-directory cleanup and verifies the
actual child-process trace. Windows/macOS packages and the downstream image/release
chain still require the corrected commit's native CI results.

The `55c6a903` run passed both complete Linux runtime producers, the Windows
native source contract, the full source/release audit and the native Xray,
MTU, Rosenpass and SIP003 interoperability gates. Its native Windows x64 link
then exposed a missing external `liboqs.a`; Windows ARM64 exposed the pinned
bindgen declaration bug under Clang 22. The corrective source stages only the
locked Cargo invocation's target-checked static OQS archive, including its
content receipt, and applies the upstream bindgen fix to a checksum-verified
private build-tool copy. The original ARM64 bindings reproduce the exact
one-byte-versus-88-byte layout failure locally. The fixed bindings pass the
unchanged Rust ARM64 layout assertions; independent C compilation confirms
the same size, alignment and callback offsets. These checks do not substitute
for the resulting native Windows package and installer runs.

The corrected desktop policy builds the complete Windows x64 engine locally
with the pinned cross compiler. An explicit `-loqs` link against its staged
archive succeeds; removing only that archive reproduces the CI linker error.
The complete Linux x64 engine also passes its native captured-graph/race gate,
28 receipt/relocation checks, 375 delivery/signing boundaries and actual
artifact/installed/Portable archive roundtrips with the corrected policy.
The Windows cross build does not claim execution on a Windows host.

That Windows link also exposed an undeclared `libunwind.dll` dependency that
the compiler's PATH could mask. The final build links its compiler runtime
statically and verifies ordinary and delay imports from both the engine and
the pinned Cronet DLL, including during foreign-host package inspection.
The rebuilt x64 engine has 18 OS/API-set imports and no `libunwind.dll` import;
both pinned Cronet architectures have 15 accepted OS/API-set dependencies.
Actual PE metadata from the compiler tools agrees with the new verifier.

The same run advanced macOS through Rust/PQ compilation and exposed missing
SDK flags in the final Go C compilation. The corrective source supplies the
selected macOS SDK to both C/C++ and the external link, preserves those flags
when adding the verified PQ libraries, and keeps foreign-bundle metadata
verification independent of Xcode. Actual macOS engine and package acceptance
remains with the corrected source's native runners.

The surviving `34fb6128` Apple producer completed the pinned Libbox
XCFramework and generated-API verification, then the full app compile caught
the telemetry adapter passing `Int` to an Objective-C `NSUInteger` parameter.
The adapter now checks and converts that bound to `UInt`, rejects nonpositive
limits before issuing a read, and preserves the callback. The existing real
iOS header/adapter typecheck remains mandatory alongside the full app build.

The `55c6a903` authoritative Android job reached gomobile after all 570 Android
and 570 iOS native graph cases passed, and
exposed a late Tor preparation step lowering the combined module's Go version
from 1.26.3 to 1.26.0. Host tests did not import the Android-only libXray bridge,
whose pinned module requires 1.26.3. Preparation now preserves the greater of
the existing Go requirement and the PT module's minimum. A replay against the
exact native core and libXray passes eight readonly Android target/build-tag
loads, repeated preparation and the original downgrade negative control
without changing the shipping module files. That check runs immediately
before gomobile and contributes to the AAR proof/cache identity. The resulting
APK and native device behavior still require their own build and execution.

The four `f71b33fa` Android APK lanes then passed those eight readonly target
loads and late-preparation controls, completed gomobile into `libbox.aar`, and
reached Java compilation. The compiler exposed a telemetry network matcher
using a `LinkAddress(String)` constructor absent from the public Android SDK.
The matcher now parses numeric CIDRs and compares complete address bytes plus
prefix lengths through the public address getters, retaining exact address-set
and unique-interface ownership checks. The corrected source compiles against
the actual Android 36 SDK; the exact previous source reproduces the reported
constructor failure against that same SDK. The telemetry fixture no longer
provides that hidden constructor and includes IPv6 spelling equivalence and
wrong-address/prefix/extra-interface rejection. Its 159 checks and nine
mutation controls pass. The full corrected APK remains an exact-commit CI gate.

The `f71b33fa` native Windows runners passed PQ compilation, final engine
linking, target metadata and PE dependency verification on both architectures.
Their next failure was the final builder's license-metadata reader decoding
Cargo UTF-8 through CP1252. That reader now joins binary stdout and decodes it
strictly as UTF-8, retaining separate diagnostics and its existing newline
behavior. Fifteen output tests include the actual license collection boundary,
legacy-code-page output, process failure and exact provenance.
The download fallback fixture also now supplies real PE headers and import
tables to the shipping verifier: all four archived Windows/Portable packages
pass, and 20 controls include correctly re-sealed ordinary and delay imports
of an unowned compiler DLL. Removing the dependency check fails the fixture
before controller compilation. The `f71b33fa` macOS Intel and Apple Silicon
producers completed their native builds and artifact uploads, confirming the
final SDK fix. The standalone native AppKit packages then passed their payload,
package and signature checks for both architectures, and both native GTK app
jobs passed. Its actual Apple SDK gates also passed the map bitmap/configuration
checks, including both negative controls, and the native telemetry adapter's
unsigned read-bound typecheck. Those results precede the final reader correction;
the resulting commit still needs its complete native/package/image/compose
release chain and the separately required physical/distribution acceptance.

The full `f71b33fa` iOS client lane also completed its pinned Libbox XCFramework
and project generation. Its Release iPhoneOS build then reached the application
target and rejected an internal coordinator property exposing the private map
annotation type. The packet property now has matching file-scoped visibility.
The existing map gate additionally typechecks the complete shipping iOS map,
annotations and coordinator against SwiftUI/MapKit, with only the application
model boundary substituted. A portable Swift compiler check preserves the
shipping access declarations and reproduces the original error as a negative
control. Full corrected SDK/app acceptance remains with the next exact commit.

The same Apple source gate subsequently exposed the Naive graph fixture's
120-second deadline. Its 178 graphs and 2,151 assertions launch 840 fresh Go
helpers; Foundation's polling exit wait added substantial per-call overhead.
The fixture now installs a completion handler before launching each process
and joins its signal, preserving the full matrix and the existing deadline.
A controlled local run fell from 46.9 to 5.6 seconds, and the complete edited
fixture passed in 8.7 seconds including compilation. Large pipe payloads,
nonzero exit diagnostics and executable-launch failure also pass; this is a
fixture synchronization correction, with no application or native policy change.
The later Xray exit fixture uses the same bounded completion join: all 87
graphs, 1,167 assertions, 538 fresh helper calls and its 90-second deadline
remain intact. Its measured local execution fell from 29.3 to 3.5 seconds,
with the full fixture and the same pipe/exit/launch controls passing.

Apple candidate measurement passed 240 executable Swift checks and two negative
controls. Persistence and native restoration passed 61 and 85 checks respectively;
the existing 433-check Speed Lab suite also passes. These tests exercise shipping
source with declared platform boundaries doubled, not physical-device routing.
This continuation also adds captured native DNS comparison for mobile Tor and
ordinary external paths. Both hosts retain the exact proved session and native
cleanup owner, validate complete results, and offer an explicit next-connection
DNS edit. The Apple hop-measurement handshake now also distinguishes the
provider epoch from the MTU session instead of rejecting valid sessions whose
identifiers differ. Executable fixtures deliberately use distinct identifiers.

The `3c46bc57` native matrix has passed the Windows installed/Portable packages
for x64/ARM64, macOS for Intel/Apple Silicon, Linux for x64/ARM64 and the ARM64
Portainer image/preflight job. Repeated native preparation then exposed a
competing `sing` replacement in the mobile build sequence. The current fix
composes the UDP buffer limits and packet-endpoint concurrency correction in
one verified dependency copy. Both preparation orders, repeated preparation,
default/low-memory capacity builds and the actual native UDP race regression
pass; unrelated or partially modified copies remain rejected.

Those earlier package results do not certify the newer source: its exact-SHA
APK, Xcode/IPA, desktop packages, server images, generated compose and
publication gates must run on the resulting source generation.

The `1394ec8f` run also passed its then-existing desktop and ARM64 preflight
gates, but mobile gates exposed stale Tor-MTU and Apple hop-proof fixtures.
The real Android native producer additionally emitted 570 external graphs
while its consumer still required 456. The corrected consumer requires all
456 Local plus 114 paired Server/Compare cases from each mobile host, and
Apple now exports those paired cases as well. No matrix entries are removed
to obtain a passing result. The real prepared native registry accepts all 570
graphs from each host and rejects every corresponding missing-engine control.
Earlier desktop success did not test the missing
complete-runtime delivery path described above.

The actual `1394ec8f` Xcode build also exposed a generated-binding mismatch:
native String-returning proof and MAX calls require an explicit NSError
pointer, as does the MAX DNS callback. The adapters now match headers generated
by the pinned gomobile version, preserve the native error domain/code, and
reject an errored result even when it contains nonempty proof text. The affected
full-engine, MAX and external-execution gates pass with these real API shapes;
the next exact-SHA Xcode build owns native SDK acceptance.

The Apple MAX source gate, LAN-policy fixture, canonical macOS native-test
paths and Android pinned-NDK setup order have been corrected on main. These
fixes preserve production validation and native failure propagation. The final
release pipeline is not declared complete by those individual corrections.

## Product split

- **Router VPN app:** the native daily VPN client with map and shared node
  catalog, Connect/Disconnect, modes, saved connection profiles, DNS, multihop,
  Speed Lab, MTU, kill switch, LAN policy, forwarding and settings.
- **Setup Center:** private deployment, administration, recovery, downloads,
  pairing, simple third-party Methods, Full Guide and AI Help.

Generic packages contain no private node credentials. Install once and link
nodes separately. Node selection never silently connects. Fastest requires
usable measurements; missing coordinates are never replaced by IP-derived
fiction. Profile changes require an idle, validated transaction with rollback.

## Native application source

| Platform | Application and runtime |
| --- | --- |
| Windows x64/ARM64 | Native WPF application, normal installer and Portable ZIP, native tunnel engines, firewall ownership, custom exits and local/server multihop. |
| macOS Intel/Apple Silicon | Native AppKit/MapKit application, tunnel engines, PF policy and desktop multihop. The installed application is not a browser wrapper. |
| Linux x64/ARM64 | Native GTK application, tunnel engines, nftables policy and desktop multihop. |
| Android | Native VpnService with WG/AWG and the combined pinned Libbox/Xray runtime. Layered modes, Tor, complete MAX and multihop use one owned system VPN interface. |
| iOS/iPadOS | SwiftUI app and one PacketTunnel. Raw WG/AWG uses the pinned WireGuardKit owner where appropriate; layered, adaptive-MTU, Tor, complete MAX and multihop use the owned Libbox runtime. |

Strict Apple sessions require actual NetworkExtension route-lockdown settings
and LAN exclusion matching the selected graph. Both nodes participate in
multihop LAN policy. Native session ownership rejects stale Connect, proof,
measurement, cancellation and profile handoffs.

Compilation and executable boundary tests remain distinct from physical
permission, routing, leak, reconnect, sleep and network-transition tests.

## Modes, helpers and profiles

The source implements WG, AWG Fast/Strong, Rosenpass-protected WG/AWG,
Shadowsocks 2022, Hysteria2, REALITY/Vision, PQ REALITY, XHTTP, Naive H2/H3,
SIP003/TLS helpers, split transport, complete MAX TLS/QUIC and validated
Start Layer compositions. Raw Xray mode `max` is distinct from a complete MAX
chain containing its mandatory PQ base and middle/outer layers.

AUTO, SMART AUTO, logical fallback, CUSTOM and ALL use captured profiles under
the saved encryption, obfuscation, base and fallback policy. ALL requires
complete MAX branches. Labels or incomplete credentials do not grant readiness.
Apple trials run inside one provider session with checked native close, fresh
node/DNS proofs, final MTU activation and restoration semantics; see
[IOS-OWNED-STRATEGIES.md](IOS-OWNED-STRATEGIES.md).

Saved connection profiles retain node references, mode, DNS, policy and
multihop choices without duplicating private keys into another credential store.

## Multihop and comparison

Mobile graphs now include WG/AWG, proxy, native Xray, PQ, complete MAX and
helper/composite families, including captured entry and exit Start Layers.
They are no longer restricted to WG entry with WG/Shadowsocks/Hysteria2 exits.
Every accepted graph preserves node credentials, separate entry/exit proofs,
routing ownership, selected DNS and individual MTU bounds.

**Local** executes the nested exit on the device. **Server** executes an
isolated exit session on a paired entry server and therefore gives the entry
the exit-tunnel trust role. **Compare both** retains the eligible lower score:

```text
(last-node routed response time + external-server routed response time) / 2
```

Both candidates use the same randomly selected external endpoint. A timeout,
failed identity/probe, stale path or invalid measurement disqualifies the
candidate. The selected candidate must pass both probes again before adoption.
These are routed response times, not mislabeled ICMP pings.

Private registry pairing, separate protocol peer ownership where required,
authentication, expiry, acknowledged deletion and relay cleanup remain
mandatory. See [MULTIHOP-EXECUTION.md](MULTIHOP-EXECUTION.md).

## DNS, MTU and measurement

Router VPN node paths support Home AdGuard, measured Fastest, Custom UDP/TCP,
DoT, DoH, DoH3 and Rescue through captured policy. Resolver names, bootstrap
routes and destination retain the selected tunnel owner. Mobile ordinary
external and Tor policies now use the shared native validation and exact
predecessor capture. An unpaired Home draft may be edited, but it does not grant
runtime readiness or silently select a public resolver. Tor public DNS requires
a supported TCP transport; the selected resolver must pass the live proof.

Android and Apple now compare the twelve public IPv4/IPv6 endpoints of
Cloudflare, Google and Quad9 through the captured ordinary external exit or
native Tor connection. The user explicitly chooses TCP DNS, authenticated DoT
or authenticated DoH. Each public time includes a fresh TCP connection, TLS
setup where applicable and a matching usable DNS answer; all three samples
must succeed before a median is eligible. IPv6-Off prevents IPv6 socket attempts.
No ambient resolver, proxy, direct path, public UDP or HTTP/3 fallback can
silently substitute for the measured transport.

The separate Selected DNS row queries the actual native DNS router with local
caches disabled. It retains its own transport and route, including Home AdGuard
through the exact paired entry, and is labelled separately from the public
exit comparison. The existing Router VPN UDP comparison remains labelled as
app-originated queries following the device route and its exclusions; it does
not certify public DNS timing through a Tor or ordinary external exit.

Both mobile hosts reject changed sessions, saved sources, selections, physical
networks and expired results. A successful public row or the fastest eligible
row fills an explicit DNS editor draft with its protocol, address, port,
certificate name and path. The user must Disconnect and Save before that policy
can apply to a later connection. Comparisons never initiate Connect, alter the
active resolver or write the ambiguous legacy `fastest_dns_*` cache.

Cancellation retains late native sockets, failed closes and measurement/MTU
ownership until actual drain acknowledgement. Android retains its service
owner after UI dismissal. Apple reserves requests before acknowledging Info
and keeps the same app transaction visible after reopening the editor. If
system Disconnect removes provider messaging, an exact drained receipt can
recover cleanup through the shared App Group. It contains no credentials or
measurement results and cannot select a resolver. A single retained provider
timer retries native cleanup and receipt persistence after transient failures,
without another IPC request. Missing or failed evidence leaves cleanup pending;
an abrupt process exit before acknowledgement is not treated as proof.

Verification includes the complete Go suite and reconciled requirements audit,
Go race tests, actual prepared pinned-native factory and adapter tests, and two
native late-socket/failed-close negative controls. Android passes 261 DNS
ownership checks and 3,550 editor checks, including 200 real native compiler
roundtrips and the corresponding mutation controls. Apple passes 324 DNS checks
with four mutation controls, whole-engine runs of 382/382/383 checks, and 67
real-filesystem receipt checks with two mutation controls. Apple SDK compilation
is a separate Darwin gate. These are source/native boundary checks, not a
public Tor circuit or physical-device acceptance. See
[../internal/dnsmeasure/README.md](../internal/dnsmeasure/README.md).

Android and Apple implement Auto-MTU, Retest and Cancel using the owned native
interface, actual readback, authenticated through-tunnel probes, rollback,
path-specific history and measurement holds. History is not presented as a
fresh current-path result. Adaptive WG/AWG uses the Libbox endpoint owner
without discarding AWG parameters; fixed/manual/default may retain the raw
backend. See [../internal/mobilemtu/README.md](../internal/mobilemtu/README.md).

The private optimizer requires an authenticated probe peer. An external node
cannot claim that optimizer merely by accepting Auto or applying a default
MTU; it needs a supported probe and actual native interface owner.

Bounded padding, compatible Jumbo TUN policy and nested MTU checks are present
in mobile source. A configured 9000-byte TUN does not prove that a public path
carries 9000-byte packets.

Speed Lab and per-hop measurements use owned transfer lanes, actual bytes,
latency samples and stale-result rejection. Live RTT, 50-sample node statistics,
current-path Mbps, per-hop Mbps and optimizer throughput remain distinct.
Temporary trials preserve saved policy and restore the captured prior runtime.
See [SPEED-LAB.md](SPEED-LAB.md).

## Native Tor and external protocols

Android and Apple now contain native Tor and pluggable-transport source for
plain Tor, obfs4, meek_lite, Snowflake, WebTunnel and validated bridge sets.
The C package and PT/session implementation join the existing VPN runtime;
Tor is not simulated by an ordinary SOCKS profile. Its native proof request
requires a live query through the exact captured DNS router before delivery;
both mobile hosts require that DNS confirmation. Home DNS traverses the
captured private entry, while an explicitly selected public resolver traverses
Tor. Entry credentials and policy are fingerprinted, and a retired DNS or entry
owner invalidates the proof. Native constructor and in-memory network tests do
not establish a public circuit or a physical device's routing. Imported values cannot
inject torrc commands or executable plugin paths.

Real Java/Swift graph fixtures cover 348 Tor variants per mobile platform.
The pinned native registry accepts those graphs and rejects corresponding
missing-Tor-engine mutations. These constructor/configuration checks do not
start a public Tor circuit or replace APK/IPA and device networking tests.

Windows x64, macOS and Linux use pinned owned Tor/helper processes. Windows
ARM64 uses verified Windows 11 x64 userspace compatibility for Tor/Lyrebird;
the app, VPN engine and driver stay ARM64. Capability checks describe this
accurately and reject hosts without the required execution support.
See [WINDOWS-TOR-ARM64.md](WINDOWS-TOR-ARM64.md).

External imports include validated WG/AWG, SOCKS5, HTTP(S) CONNECT, Shadowsocks,
Hysteria2 and OpenVPN paths exposed by native hosts. Ordinary external exits
prove the saved expected public IP. Tor uses its separate owned public-exit
proof. Plain proxies are not labeled authenticated encrypted VPNs.

Windows OpenVPN capability checks its installed native runtime/helper; it is
not unconditionally disabled. Mobile OpenVPN uses the pinned userspace TLS
client and documented inline-profile subset. Exact transport, authentication,
certificate and hop requirements still apply; see [MOBILE-OPENVPN.md](MOBILE-OPENVPN.md).

## Server and private production

Server source includes the protocol/helper families, private node proof and
authenticated MTU services, paired relay sessions, forwarding, Setup Center
administration and server-side multi-provider AI Help. Actual provider
credentials and availability require live validation.

Production Portainer compose is exact-SHA and image-only. Nine custom images
and their compose references must match the release source. A moving branch
or unrelated green workflow cannot certify it. The stack obtains no
Docker-socket mount.

Setup Center/admin ports **8786-8793**, private SOCKS5 and DAITA-like port
**45999** remain private. ASUS exposure owns only exact tagged Router VPN
DNAT/FORWARD rules. Foreign same-port rules win. Failure withdraws Router VPN
exposure while preserving household Internet, DNS, DHCP, IPv6 and unrelated
hooks.

## Build, downloads and acceptance

GitHub Actions is the normal native build environment. Downloads require the
exact requested revision, source provenance and checksums:

```text
matching exact-SHA GitHub Release asset or Actions artifact
→ Windows x64/ARM64 installed/Portable only: bounded requested-package fallback
→ verified generic secret-free package
→ download with owned progress, cancellation and retained retry
```

macOS and Linux never use the AI Board as a substitute native build environment.
Android and iOS/iPadOS never use router-local builds. The router-local fallback is bounded to the requested generic **Windows/Portable** package
and uses approved same-image components. PortableApps/PAF is retired; normal
Router VPN Portable ZIP x64/ARM64 remains supported.

READY output and its workspace remain available for 30 minutes. Repeat or
interrupted download does not extend the deadline. Cancel/Delete, expiry and
shutdown clean owned files; failure remains visible and retried.

The final source generation needs its authoritative native matrix, ARM64
server/preflight checks, exact compose and publication. Whole-project acceptance
then also requires physical devices, visual/DPI testing, leak/network
transitions, off-LAN interoperability, private server and AI-provider checks,
Apple signing/distribution, deliberate deployment and live ASUS validation.
Use [LIVE-RELEASE-EVIDENCE.md](LIVE-RELEASE-EVIDENCE.md) and
`deploy/live-release-evidence.py` to bind real evidence to the exact SHA.
This source-status document marks none of those live gates complete.
