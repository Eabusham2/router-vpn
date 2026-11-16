# Hysteria2 final Start Layers: native acceptance

This change adds actual encrypted final-layer execution to the existing paired
Hysteria2 Server acceptance gate. The final node can retain its own
AES-256-GCM or AES-256-GCM plus XOR whitening, independently of the preceding
WG/AWG nodes. Off remains supported. The shared compiler and native host
consumers have separate evidence; this document describes the original native
worker, reference peers and mandatory release gate.

## Preserved boundaries

The captured graph still contains two through eight paired nodes. Its entry
belongs to the original client and lease; the Server worker executes the suffix
after that entry. The native fixture exercises zero, one and six remote packet
prefixes. It does not infer a client entry lease from suffix traffic or admit an
imported middle with a Hysteria2 final.

The final encrypted layer uses the original SS2022 or whitening implementation.
It decrypts only to the captured Hysteria2 private UDP tuple. Its key, outer
endpoint, private destination and counters are distinct from all prefix layers.
The inner Hysteria2 transport retains QUIC/TLS, private trust, server name,
password and Salamander mask. The test's private port 443 is a fixture parameter;
the production compiler retains the actual captured port.

The co-located component fixture uses a distinct loopback address for its final
outer layer so it cannot collide with a prefix whitening listener. A zero-prefix
Server suffix instead uses its isolated peer namespace's original public /32.
No production endpoint, selected Home DNS policy or proof is substituted.

The new fixture is registered for both the Linux peer and the existing Darwin
test-source projection. Projection changes only the original build constraint;
it is not evidence that the Darwin peer ran.

## Mandatory whole-worker cases

All previous 22 Server cases remain required. The following 14 are added:

| New final-layer cases | Count |
| --- | ---: |
| Direct AES and AES+XOR suffixes | 2 |
| WG/AES and AWG/AES+XOR suffixes | 2 |
| Maximum-six AES, AES+XOR and independently mixed-prefix/AES+XOR suffixes | 3 |
| Wrong final key or whitening for direct and maximum-six suffixes | 4 |
| Maximum-six AES with failed selected DNS | 1 |
| Joined active UDP for direct AES and maximum-six AES+XOR | 2 |
| **Additional required cases** | **14** |

The gate therefore requires **36 exact whole-worker cases on each architecture**.
Every case must retain its original source and capture hashes, complete prefix
inventory, exact final-layer tuple and counters, selected DNS result, and joined
worker and peer. A rejected final layer may retain valid preceding prefix
proofs, but cannot deliver a QUIC packet or an application proof to the final
provider. A direct suffix must leave the unused WG reference counters at zero.

The original per-case bounds remain 90 seconds for Go, 105 seconds for its
namespace child and 125 seconds for the outer observer. Each native compilation
retains 600 seconds. Missing, duplicate, skipped or foreign cases cannot satisfy
the gate. The independent API-token correction from `a56cd4bb` is retained.

## Executed local evidence

The canonical preparation used the original pinned core and Xray revisions,
Go 1.26.3, race instrumentation, the full native tags and read-only module
resolution. These receipts describe private proof commit `a55a0493` based on
`a56cd4bb`, not an exact build of a later composed publication commit.

The canonical digest of all checked prepared inputs was:

`33b2ab1c97432fa63f3dcf83c59cb8a0f982db154d039925ee2ed07148ee002e`

| Actual compiled image | Seconds / bound | SHA-256 |
| --- | ---: | --- |
| Original encrypted reference peer | 217.111 / 600 | `578a490e926a799597f91b92b5b70d92d12f052b72b37cd7860d9e3900d90c13` |
| Shipping `cmd/sing-box` worker | 79.926 / 600 | `04dfa697e4dcbb6511b0eda3d9cf79fcc221d2c6ad7d284e78dbb470370b2bcd` |
| Whole-worker acceptance driver | 59.818 / 600 | `f963b8a170c0b874eb58bf182b88fd7929aac859e4bc91d702ddab0c8bd8db8a` |

The immutable peer passed the new nine final-layer leaves plus their root in
15.638 seconds under the unchanged 90/105-second component bounds. These execute
real WG/AWG, SS2022, whitening and Hysteria2 traffic: AES, AES+XOR, both mixed-six
compositions, wrong key, wrong whitening, wrong private destination, held-request
cancellation and joined close. No kernel TUN or host firewall is modeled as an
accepted device.

The same peer also passed all 37 original Hysteria2 traffic records in 19.393
seconds under 90/100 seconds, and all six original prefix-layer records in 6.108
seconds under 90/105 seconds. Existing authentication, trust, routing, DNS,
cancellation and socket-retirement checks remain required.

The provider's original private-source export passed in 0.115 seconds. The
driver passed all 36 new source cases plus their root in 6.567 seconds, and all
14 original source/carrier cases plus their root in 2.486 seconds. The source
roots retain 60/75-second bounds. These 59 provider/prefix/source records have
receipt SHA-256:

`e9569eaff60df0f5f7fcad952635c182cd0c1c1d1172d54a2a2ee1bf5f91d700`

The dedicated runner passed 21 checks, including compilation of the actual
request constructor and provider admission with 15 topologies, 12 independent
identity refusals and the former duplicate-token counterexample. Nine original
Hysteria2 runner checks and four Darwin source-projection checks also passed.
These runner checks do not supply encrypted traffic receipts.

The first component attempt correctly rejected an incomplete Start Layer fixture
which omitted its original TUN/route declaration. Only that fixture was repaired;
the strict source validator was preserved. A later local observer omitted the
required `case=None` argument when parsing the completed original source root.
Its exact successful child log, unchanged image and source digest were rechecked
through the unchanged strict shipping parser. Neither failed attempt is counted
as a passing native run, and their diagnostics remain recorded.

## Remaining evidence

This local environment previously refused the first required namespace network
operation, `ip link set lo up`. It has not supplied a completed 36-case veth/TUN
receipt. The required hosted workflow must build the exact published commit and
complete all 36 cases on Linux amd64 and arm64. The earlier 22-case Off-final
results do not establish the new final-layer cases.

Installed client networking, public host/controller operation, real-device leak
and network-transition checks, signing, private deployment and the complete
release retain their own acceptance requirements.

## Selected DNS failure boundary review

Read-only review found that a failed-selected-DNS case could previously accept
an earlier unrelated private-proof failure: both the driver and strict receipt
parser required failed readiness, but did not require the selected resolver to
have received a query. This affected the existing direct/max-six cases and the
new max-final-AES case. The actual shared proof order is private proofs, then
selected DNS, then public proof.

The driver assertion and parser now require positive Hysteria2 stream/datagram,
private-proof and DNS-query counters, zero authentication failures, and zero
public queries/cover replies for precisely those three cases. Failed readiness
and joined worker/peer retirement remain mandatory. All 36 cases, other fault
boundaries and every operation/process deadline are unchanged.

The new parser controls independently invalidate each counter requirement and
causally remove the exact parser guard; the latter recreates acceptance of an
earlier failure with no private proof or DNS query. These synthetic transcripts
are validator-only evidence. The previously recorded native peer/worker images
are unchanged. The earlier driver image predates this assertion and is retained
as its original snapshot. The subsequent driver-only rebuild is recorded below;
the mandatory hosted 36-case namespace run must execute the new Go assertion
against actual failed selected DNS.

All 22 Python-only runner tests passed in 0.231 seconds, including 21 individual
counter mutations across the three selected-DNS cases and the exact guard-removal
control. The existing actual Go constructor test was explicitly excluded from
this parser-only invocation; it retains its separate compilation requirement.

The retained a56 hosted native logs also confirm compatibility for the existing
direct and max-six failed-selected-DNS cases on both amd64 (job 133271343548) and
arm64 (job 133271343956). Each original receipt has stream, packet, private-proof
and DNS-query counters equal to one, zero authentication/public/cover counters,
failed readiness, and completed worker/peer retirement. These four historical
receipts satisfy the new phase predicate. They do not exercise the added Go
assertion or the new layered case. Raw-log hashes and exact event locations are
retained in `dns-existing-native-compatibility.json` alongside the review receipt.


## Rebuilt driver and final validator checks

The actual acceptance driver was rebuilt at private proof commit
`f85edbb0875e305f13d7286e72fe8c10dfb27145`. A before/after inventory of all 4,994
prepared Go/module files confirms that only the generated Hysteria2 acceptance
driver changed. The original reference-peer and worker images, all earlier
receipts, and the earlier driver image were retained unchanged. This remains
the recorded a56-derived canonical source composition; it is not relabeled as
a native build of the later publication head.

The new driver compiled with race instrumentation and all original native and
acceptance tags in **92.181 seconds under 600 seconds**. Its SHA-256 is:

`9e35ade10a76588715b963a543a899ee230c97186d527e0c1cbf5882b5b7a3f6`

The checked prepared-source digest is:

`45f943cf8dc72f57daee59f9e2ed38e8c9648be442ac76d31a7c8ceeb0c55b24`

That exact image reran all 37 Hysteria2 source records in 7.073 seconds and all
15 original source/carrier records in 2.051 seconds. Each retained its original
60-second Go and 75-second process limit. These are repeated source checks,
not additional encrypted-traffic cases or execution of the DNS-fault namespace.

The complete updated validator suite then passed **23 tests in 4.861 seconds**.
This includes the actual compiled request constructor/provider admission,
independent-identity refusals, duplicate-token counterexample, and the new
selected-DNS counter controls. The observer completed in 5.129 seconds; the
constructor's original 30-second test and 60-second process limits were kept.
The final validator log has SHA-256:

`a1f9f5f0e436a90938831bc3a37c54ac462c992fcc2d37655770a5e1f260e576`

The whole-worker namespace, both hosted architectures, native platform packages
and exact publication/release checks remain mandatory. No historical or local
source-only result supplies those missing verdicts.
