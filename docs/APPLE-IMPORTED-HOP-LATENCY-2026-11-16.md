# Apple latency receipts for every original imported interior hop

The ordinary Local PacketTunnel delivery now exposes a proved imported hop at
any interior position in its original two-to-eight-node inventory. Its former
three-node-only check prevented longer supported paths from reaching the
measurement interface. Public-path entries remain forbidden at the entry and
exit, and every position, node identity, proof and current Local owner is still
checked.

The historical receipt parser also accepts every interior position in a
three-to-eight-node path. It previously accepted only the penultimate position.
The parser reconstructs and exactly matches the complete canonical label from
the original position and count. Exact node, role, source/configuration,
request, measurement method, endpoint, 50 successful samples, zero failures,
and distribution validation remain required. Selected execution labels cannot
be substituted into this ordinary Local receipt grammar.

The history description identifies responses through the custom node, timed
after DNS, TCP and TLS preparation. Existing endpoint and DNS policy behavior
is unchanged. The result remains historical cumulative-path response time; it
does not become ICMP RTT, direct-node ranking or connection authority.

## Executed evidence

The tests compile and execute the shipping receipt/history implementation,
the complete extracted `NodeChainDelivery` class, and the App's actual capture,
IPC, transaction and history callbacks. Native engine, operating-system and
private-storage boundaries are explicitly modeled.

| Original fixture | Passing positive checks | Compiled controls rejected |
| --- | ---: | ---: |
| History, transaction and retained IPC owner | 400 | 10 |
| Ordinary PacketTunnel delivery | 150 | 5 |
| Ordinary App callbacks | 274 | 3 |

The inventory covers all 21 interior positions across path lengths three
through eight and all 68 App positions across the private and imported path
sets. Cases preserve endpoint refusal, unknown-kind refusal, moved and unproved
prefix refusal, exact source/configuration/node binding, original MTU ownership,
failed-close retention, stale-source rollback, and refusal when provider kinds
do not match the App's original capture. All original controls remain, with
five additional controls registered in the mandatory Apple gate.

The first run passed the 400-check baseline, but a new earlier label-refusal
case intercepted the existing closed-label control before its required original
witness. Moving the additive cases after the original mutation cases preserved
every test and control. The complete rerun passed with the original Swift
compile and execution bounds. Its three phases took 25.471, 8.809 and 13.936
seconds respectively; no timeout or unjoined process counted as a result.

The tested source was based on `c89ec732`. Integration over `238eb571` preserves
the later Apple connected-candidate engine and multiple-imported-hop Local
foundation. The entire affected delivery class is byte-identical to the
executed class; the other consumed Swift and fixture inputs are unchanged.

| Evidence | SHA-256 |
| --- | --- |
| Corrected six-file source manifest | `be004f0b555f6305b062b9d482bcf0b4aae61098c08122a793943e4681a2932d` |
| Complete joined Swift execution receipt | `972a822d40ba9f64ee802be37d41784faf20a09820ce5ec596eab8c94a4e0396` |
| Exact executed delivery class | `d6eb530aec54df3fbcc669a456f527e030fb0e6653feb411fc590395ea676cf2` |

These results establish the shipping Swift behavior at the stated boundaries.
They do not establish installed-device traffic, arbitrary graph admission,
Server/Compare support for multiple imported hops, or a complete final release.
