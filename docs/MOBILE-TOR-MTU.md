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

## Remaining platform evidence

The shared/native capacity foundation supports both mobile hosts. The Apple
host still needs its corresponding editor and effective-authority adoption
integration; the shared implementation alone does not complete that task.
Android and Apple real-device interface readback, traffic segmentation, reconnect,
network transitions, leak checks, and signed-package upgrade acceptance require
their own device evidence. Standalone Tor padding and additional graph families
are separate requirements and are not closed by virtual Jumbo support.
