# Complete hostname routes and original AWG2 Fast selected execution

This continuation addresses compatible route families still excluded by the
earlier source. Original requirements #214–224 and #336, the August 13/14
external-node requests and the August 19 recursive selected-prefix request
remain binding. Neither an eight-node implementation boundary nor a passing
source audit reduces those requirements.

## One original hostname followed by additional streams

A Local route can retain one imported SS2022 hostname as its first stream
immediately after a nonempty contiguous prefix of paired WG/AWG packet nodes.
The remaining original stream members may be literal imported SS2022 nodes or
independently paired Shadowsocks intermediates, followed by the same paired
Shadowsocks final. All Start Layers in this mixed family remain Off. The
original source-size, endpoint/key identity, MTU and 96-position physical
traversal bounds still apply.

The hostname retains its saved numeric Custom TCP resolver. Both resolution
and the imported outbound use the same immediately preceding original packet
node. A separate resolver, direct fallback, moved hostname or altered suffix
cannot borrow the original capture. Named Save/Load, startup Last, linked
source reopening, measurement and recursive insertion retain the complete
route on the desktop, Android and Apple clients.

The native compiler binds an answer validator to that particular imported
outbound's existing resolver. It checks the exact address batch consumed by
each actual dial, including cached and CNAME-derived answers. An address that
would collide with an original peer at the same port is refused before use.
Different peers may legitimately use the same port; there is no blanket
unique-port restriction. Cancellation, NXDOMAIN, a substituted resolver and a
later rebinding response do not acquire a successful measurement receipt.

Controlled native tests exercise a nine-member AWG2 Fast route containing the
hostname, a paired stream intermediate, later literal imports and the original
final. They transfer 8 MiB in each direction, retain warm cached CNAME
resolution, and reject a colliding CNAME/address answer, NXDOMAIN, rebinding
after earlier success and a changed later key. Closed-prefix measurement at the
hostname and connected measurement through a later stream each require fifty
fresh authenticated replies and joined cleanup. Source and consumer tests
also cover four, nine and sixteen members. These are controlled native peers,
not evidence of installed-device or off-LAN acceptance.

## Longer selected routes with their original Fast entry

The longer selected family now admits exactly one original AWG2 Fast packet
entry, independently captured literal public SS2022 intermediates, and the
original paired SS2022 final. Explicit Server and Compare execution preserve
that complete original source. A Compare result can select either measured
winner; loading Last, reading history or restoring a retained session cannot
repeat the comparison or silently change the selected route.

The separate native classifier rejects a hostname, a paired stream
intermediate, another packet node, Strong in this longer selected family, an
altered member or an active Start Layer. The existing shorter families and
the separately qualified Local families retain their own rules. This is a
qualified addition, not a claim that every protocol sequence is implemented.

The MTU combiner verifies the original Amnezia packet endpoint and every
original prefix plan. It cannot raise the captured Local packet ceiling when
the Server route is selected. The original source, TUN tag, execution epoch
and remote lease remain bound through pause and readback; a missing
replacement reader is a refusal. Source/configuration checks do not substitute
for positive interface readback on the actual host.

The mandatory canonical native runner preserves all eighteen earlier selected
cases and adds fifteen Fast cases. It includes nine- and sixteen-member
Server/Compare response paths, both forced Compare winners, complete
per-position latency, 8 MiB transfers in each direction at each original
position and MTU pause/refusal checks. The runner compiles the complete original
worker bodies and checks their bytes, original source, executable identities,
authenticated endpoint responses, parameter continuity and joined remote
leases. Pruned experimental registries are not release evidence. Both Linux
architectures remain mandatory in the complete release pipeline.

The local Linux amd64 qualification completed all fifteen Fast cases and
seven hostname cases against the complete registered worker with the race
detector. Every case retained the original 85-second fixture lifetime,
90-second Go alarm and 105-second parent deadline, with source and executable
identity checks before and after execution. The Fast latency cases retained
450 nine-member and 800 sixteen-member samples; the two complete throughput
cases transferred 400 MiB in aggregate across both directions and all original
positions. These totals describe test workloads, not physical WAN performance.
A separate overlapping latency repeat exhausted the fixture lifetime and
failed closed. Its failed receipt is retained alongside the successful serial
replay; no timeout or cleanup requirement was relaxed.

## Consumer and integration checks

The actual Go desktop parent tests exercise named Save/Load with rollback,
retained selected Last restoration, source-bound history, the HTTP throughput
transaction, original per-position roles and Darwin policy capture at nine
and sixteen members. The complete MTU and relay packages pass separately.
Windows and GTK exercise their shipping editor and profile callbacks; GTK
uses real widgets and persistence with an explicit controller boundary double.
The Android combined native/JVM suite retains all twenty-six old and new
phases, 3,135 assertions and eight causal controls. Apple tests preserve
original nine- and sixteen-member selected captures, the legacy selected
inventory, named profile reopening and recursive hostname insertion controls.

Source audits check the new precise classifiers and retain tests that remove
or broaden their source, role, hostname, packet-count and traversal-bound
guards. They remain required checks. Consumer tests and source audits do not
establish physical TUN behavior or packaged-device acceptance.

## Reproducible mobile dependency fetches

The iOS hosted build failed while advertising all upstream Git refs before
the pinned source was fetched. The mobile preparation scripts now initialize
a fresh staging repository and fetch only the full immutable commit ID, with
no tags and a detached-HEAD equality check. Each of the three attempts uses
fresh staging; an incomplete checkout cannot become the dependency source.

When available, the current Actions checkout's GitHub authorization is scoped
to that exact official dependency fetch. It is not put in command arguments,
dependency remotes or the upstream build environment. Local real-Git tests
cover the immutable source, retry, failure cleanup and authorization scope.
All existing upstream source pins and package identity checks remain in place.

The complete required native, package, image and compose jobs must succeed at
one exact main revision before release publication. The thirteen physical and
private acceptance gates in [the live evidence contract](LIVE-RELEASE-EVIDENCE.md)
remain separate. No source change, local test count or GitHub artifact awards
those gates automatically.
