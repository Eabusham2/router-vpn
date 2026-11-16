# Complete Android ordered-source gate in bounded phases

The original combined Java invocation exceeded its 180-second limit after the
source/profile matrix grew. This change divides that aggregate into eight
required invocations. Every original function call and all eleven original
paired roundtrips remain. Each invocation retains the same 180-second bound;
the Go fixture-generation and Java-compilation limits remain unchanged.

The large saved-profile size-limit case runs as its own required phase. It
retains the actual aggregate-size fixture and rejection checks. No production
source, connection deadline, credential validation or native proof changes.

## Complete observed run

`python3 android/test_android_node_chain_capture.py` completed successfully.
The actual shipping Java stores, profile/editor callbacks and captures executed
against the shared Go compiler. The eight core phases passed 1,329 checks:

The local run used Go 1.26.3 and Java 17 with the shipping Java/shared Go source
at `369520a3918670e1b0cf582ca64a002beae0c8f2` and the new test partition. Those
production paths were unchanged through `6db6b58cb1812f466d651084e1b7f718bf69ea1b`.
Later concurrent source changes retain their own tests and exact-SHA CI evidence;
this local receipt does not relabel an earlier source run as a later native build.

| Required core phase | Passing checks |
|---|---:|
| Paired roundtrips | 569 |
| Captured-source and atomicity controls | 101 |
| Ordered editor | 89 |
| Aggregate profile-size limit | 2 |
| Product/editor handoff | 42 |
| Paired identities and mixed modes | 81 |
| Imported Shadowsocks | 357 |
| Original SOCKS source/profile cases | 88 |

The same complete command then ran the unchanged remaining families: hostname
policy (570 checks), CONNECT (360), longer CONNECT prefixes (510), longer SOCKS
prefixes (44), OpenVPN middle sources (222), and paired Hysteria2 finals (167).
The total is 3,202 executable checks. All 29 original compiled causal controls
were rejected at their required witnesses. These are test counts, not a
percentage of product requirements.

The first partitioned diagnostic executed all eight core groups, but its new
receipt parser rejected the existing SOCKS method's additional completion line.
The parser now requires that exact existing line and the new phase receipt to
report the same count. A complete subsequent run, including all remaining
families and causal controls, passed. The diagnostic failure was not counted as
a successful aggregate.

## Required coverage and receipts

The shipping gate has a closed Python phase inventory and matching Java dispatch.
The existing mandatory profile contract checks every original function call,
the full roundtrip inventory and the complete dispatch. Omission and duplication
controls remove each phase and each original call and must be rejected.

Every actual JVM phase must exit successfully and produce its exact positive
receipt. Missing, duplicate, foreign or zero-count receipts fail. The SOCKS
method's existing receipt must also be present and agree. Failed commands and
timeouts cannot become successful receipts. Contract tests execute the receipt
function with controlled process outputs and verify the original checked
180-second invocation.

The focused imported-only and OpenVPN entry points remain separate. The default
ordered-source command runs every core phase, every additional protocol family
and all original controls. Its required workflow call is unchanged.

## Evidence boundary

This is shipping source/compiler and profile behavior with explicit Android OS
and native-service boundaries. It does not establish an Android TUN, remote
encrypted traffic, package provenance, physical-device acceptance or deployment.
Those retain their independent required gates and observations.
