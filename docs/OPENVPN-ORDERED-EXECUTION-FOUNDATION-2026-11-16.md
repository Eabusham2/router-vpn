# Ordered OpenVPN Server/Compare foundation — November 16, 2026

This implementation lane continues original requirements 214–224, addendum
336, and the recovered August 13/14 custom-node, hop and exit requests. It
extends the existing Local schema-five family; it does not replace the
separate already-shipping paired external OpenVPN execution path.

The source baseline is `9ff381aa543b9509fb13e7aa80c70583472e5e73`.
This unit implements the shared Server, private operator plan and provisioning
boundary. Typed client execution, native Server construction and host adoption
remain separate follow-on units. No native, installed, package or physical
acceptance follows from this source validation.

## Source and ownership boundary

The existing family is one through six original paired WG/AWG packet prefixes,
one literal TCP/UDP imported OpenVPN penultimate member, and an independent
paired SS2022 final. Existing final Off, AES and AES/XOR closures remain intact.
These are implementation bounds, not a recovered user-approved hop maximum.

The shared/server lane owns schema-five policy, canonical pairing identity,
typed execution, relay descriptor/request validation and operator provisioning.
The native Server lane separately owns the original OpenVPN endpoint observer,
worker dispatch and actual native component fixture. Public desktop, Android
and Apple admission remains closed until its own typed runtime adoption passes.
No generic parser may infer OpenVPN execution authority from a schema number.

## Private pairing and public discovery

Only typed schema-five `NodeChainServerSource` accepts `openvpn_pairing`:

```text
private_key: the Server role's dedicated pairing key
local: canonical nativeopenvpn.PublicDescriptor for the Local provider
server: canonical nativeopenvpn.PublicDescriptor for the Server provider
```

The Server's original imported member contains its own provider profile and
credentials. Its pairing descriptor must match `DescribePeer` of that exact
profile/key. Existing `ValidatePublicPair` rejects shared provider certificate
keys, common names or usernames and unequal transport policy. The Local source
uses its existing `external.openvpn_pairing`; neither private role is copied
into the opposite compiled graph. Public discovery carries only the canonical
domain-separated `openvpn_pair_sha256`, never the private descriptors' provider
names, passwords, certificate keys or pairing keys.

## Native API

The distinct source constructors are:

```go
NewNodeChainOpenVPNServerPolicy(source string) (*NodeChainServerPolicy, error)
NewNodeChainOpenVPNServerCarrierContext(ctx, lifetime context.Context, source string) (*NodeChainServerCarrier, error)
```

One fresh `ReadOpenVPNServerCapture(capture)` returns the exact configuration
and `NodeChainOpenVPNServerCapture`: its original binding, configured middle
capture, device policy and an independent copy of the proof inventory.
`Middle.ConfiguredMTU` is a demanded ceiling; it is never a connected native
capacity receipt.

The native owner retains the original policy pointer, Box, endpoint manager,
actual `*openvpn.ClientEndpoint`, configuration and connected
`nativeopenvpn.PacketObservation`. Before and after proof, DNS and traffic it
must observe the original remote, generation, connection time and packet
capacity. A configured value, equivalent reconstructed endpoint, replacement
connection or restored numeric generation cannot authorize the owner.

Shared Server proof additionally requires the existing
`NodeChainOpenVPNEngine.OpenVPNMiddleStateContext` method and keeps the first
valid observation unchanged throughout that proof. Native cancellation and
joined Box retirement retain the original lifetime/cleanup contracts.

## Mobile handoff contract

The planned distinct `RouterNodeChainOpenVPNExecutionFromLaunch` and
`RouterNodeChainOpenVPNExecutionFromLast` factories consume the existing sealed
schema-five Local `routervpn-node-chain-launch-input`. Hosts must not strip
its receipt into a reconstructed plain source. The typed preparation kind is
`routervpn-node-chain-openvpn-execution-preparation-input`; generic execution
factories remain closed to schema five.

## Validation record

The final shared source was frozen at the above baseline plus this unit and
compiled with Go 1.26.3, `go test -race -c -p=1 -mod=readonly
./internal/mobilemultihop`. Compilation passed in 43.910 seconds under the
original 300-second wrapper. The image SHA-256 was
`1c06bb68550c080c1afe6ffe2b9d77cc2dfe8baac67a110bbcf01b4fde19eb13`.
A file hash manifest confirmed unchanged compiled source.

Each root ran from that immutable race image with the original 120-second Go
and 135-second external limits, two runtime CPUs, and no skipped tests:

| Root | Run/pass records |
| --- | ---: |
| `TestNodeChainOpenVPNServerCompleteOriginalSuffix` | 37 |
| `TestNodeChainOpenVPNServerRefusesForeignAuthority` | 17 |
| `TestNodeChainOpenVPNServerRequiresConnectedNativeProof` | 12 |
| `TestNodeChainOpenVPNServerPlanIndependentOriginalPair` | 13 |
| `TestNodeChainOpenVPNServerPlanRefusesRoleSubstitution` | 11 |
| `TestNodeChainOpenVPNPairingFieldCannotEnterOtherFamilies` | 5 |
| Total | 95 |

The longest root took 21.544 seconds. All six roots are explicit required
members of the existing shared CI core group in a disjoint bounded phase.
The grouping runner's 24 executable self-tests passed, including removal of
each new required root. Existing whole-root batching and deadlines remain.

`go test -race -p=1 -mod=readonly -count=1 -json -timeout=120s
./internal/multihoprelay
-run='^TestNodeChain(OpenVPN|CONNECT|SOCKS|Imported).*Capture'` passed all 263
run/pass records in 10.508 seconds. This includes schema-five source/request
domains, all original packet positions, pair-digest ownership, rejected family
substitution, and existing SS/SOCKS/CONNECT capture regressions.

`python deploy/test_server_node_chain_pairing.py` passed all 33 required
transaction tests in 80.574 seconds. It built the real agent, generated 33
original source fixtures and 29 complete private bundle plans, checked all 34
original private-reader records, and retained all 20 Go-generated digest
vectors. The six OpenVPN fixtures cover TCP/UDP, WG/Fast/Strong, short/long
prefixes and independent final Off/AES/AES+XOR layers. Existing 31 transaction
tests remain; two new methods exercise actual schema-five source publication,
independent role refusal, private file modes, and equal-byte inode replacement.
The installed command is redirected only to that freshly built actual agent.
No native offline checker was configured for this local run.

`python deploy/test_server_node_chain_preparation.py` passed its nine exact
source-owner tests. This is validator evidence, not a native routing result.

The reusable test helper `nodeChainOpenVPNServerPlanFixture` returns the
original Local source and independently compiled Server plan for native and
mobile consumers. It never fabricates a successful connected observation.

Earlier bounded evidence is retained separately: the first 36-case source run
failed only the two longest UDP layered Local fixtures whose original packet
MTU budgets were too small. Those test-owned original assets were recompiled
with adequate budgets; production capacity checks were unchanged. A subsequent
compile found and removed one unused test import. The first operator run's two
new methods bypassed its fixed-command fixture redirection; they were corrected
to use the original actual-agent transaction, and the complete gate reran.
No failed result is counted as successful evidence.

The connected proof fixture doubles only endpoint-state observation and native
routing/DNS ownership. It executes real authenticated HTTP, verified public
TLS, exact response parsing and joined connection close through shipping
`NodeChainServerPolicy.Prove`. It does not establish an encrypted OpenVPN
connection. Native provider authentication, original Box/endpoint ownership,
full joined retirement, installed host behavior, exact-SHA release and private
physical acceptance remain mandatory and are not marked complete by this unit.

## Operator file contract

A schema-five file plan uses an explicit `openvpn` row at the original
penultimate position. It names `local_capture_file`, `server_capture_file` and
`pairing_file`. The first two contain the exact original `config` and `capture`
strings. The last contains only the Server dedicated key and the two canonical
public pairing descriptors. Each file uses the existing owned regular mode-0600
snapshot and total source byte bound; every original inode and byte sequence is
rechecked before publication. Schemas one through four retain their existing
forms and reject the schema-five private pairing field, including null.
