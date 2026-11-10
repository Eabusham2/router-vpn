# Captured literal Naive H2 over CONNECT with Home UDP

This source change admits selected Home UDP DNS for an imported HTTP CONNECT or
HTTPS CONNECT entry followed by an original literal-address Naive H2 final with
its final Start Layer Off. All three independently captured entry Start Layers
remain supported. A single explicitly selected literal UDP resolver also meets
this rule. The selected resolver is never silently replaced.

## Native behavior and ownership

The pinned sing-box core is
`1ac1a339cb1223e9c70eae14c44411c75033c02d`. Its prepared Naive outbound passes the
original server address and separate TLS server name to pinned Cronet.
`wrapDNSResolverForServerRedirect` answers matching A/AAAA TLS identity requests
from that exact literal address. Other names still invoke the original resolver.
H2 connects over the authenticated CONNECT stream; application UDP uses the
final node's existing UDP-over-TCP v2 connection.

`internal/mobilemultihop/imported_naive_h2.go` admits this case after existing
strict original transport and selected DNS validation. The final must be literal,
unlayered, and retain its exact credentials, TLS identity and resolver. The
application DNS closure must contain one literal UDP resolver. Hostname bootstrap
closures, DoH3, changed/missing resolvers, foreign lower owners and layered-final
UDP bootstrap retain their rejection.

The executable resolver tree remains unchanged except for the existing owned
entry detour. `imported_entry_desktop.go` and `desktop_egress.go` record the
validated literal H2 bootstrap as a retained dependency without granting it an
unused lower UDP socket. Generic egress callers keep their original behavior.
Application DNS remains final-owned. Apple producer admission checks the same
narrow prerequisites; Android uses the shared compiler.

## Verification

| Check | Result and boundary |
| --- | --- |
| Shared `TestImportedNaiveH[23]` roots, Go race | Passed in 38.504 seconds, including existing DNS and independent-layer controls. |
| New `TestImportedNaiveH2CONNECTLiteralHomeUDP`, Go race | Passed in 1.356 seconds. Two CONNECT types × three entry layers retain exact source/DNS/bootstrap. Protected Windows policy derives without changing original graph objects. Physical roots are TCP only; bootstrap has no physical authority. Hostname, missing/wrong resolver, foreign owner and changed captured graph reject. |
| Actual pinned native H2/H3 and CONNECT literal roots, Go race | All **77 required verdicts** passed: original H2 24, original H3 24, new CONNECT 29. Counts include root verdicts and exact leaves, not device coverage percentages. |
| New native CONNECT leaves | HTTP/HTTPS CONNECT × IPv4/IPv6 original final literals × seven cases: Home success, wrong final password, wrong TLS name, wrong certificate, forced hostname query, wrong CONNECT credentials and wrong CONNECT route. Success completes real authenticated TCP, UDP-over-TCP and final-owned Home DNS, with zero lower UDP and zero bootstrap exchanges/lookups. |
| Native causal control | A Go overlay disabling only pinned Cronet's literal redirect makes the Home case fail: name resolution failure, two bootstrap exchanges, zero lower TCP/final peer connection. Real source remains unchanged. |
| Shared source causal controls | Separate overlays restoring old admission or eager bootstrap traversal each fail the Home test at the intended boundary. |
| Android producer | Both CONNECT phases pass 1,249 checks each and all six existing causal controls. Each phase retains its nine original independent-layer graphs. |
| Apple producer | Actual Swift/shared-Go validation passes 81 graphs and 4,327 checks, retaining existing hostname/bootstrap refusals. |
| Actual desktop Home producer | New retained-selection/launch test passes Go race in 1.177 seconds and exports both original CONNECT graphs with final-owned Home UDP, retained lower descriptor and TCP-only physical grants. |
| Actual exported Home graphs → pinned Libbox | All six Java/Swift/desktop graphs passed native `CheckConfig` under race: seven exact verdicts, 1.146 seconds total. Separate changed-lower-owner and invalid-native-type graph controls fail at the ownership check and actual native parser respectively. |
| Persistent contracts | Workflow nine tests, imported H2 runner ten tests, native literal policy ten tests passed. |

The original 81-graph TCP inventories remain intact. Separate optional producer
export directories hold exactly two Home graphs per Java, Swift and desktop
producer. The existing imported H2 workflow supplies all three directories to a
mandatory separate native parser root; missing roles, missing/extra files,
symlinks, empty/nonobject files, native failure and changed bytes fail the gate.
The reader checks exact CONNECT axes, selected UDP/53 ownership and the retained
bootstrap before calling actual pinned Libbox `CheckConfig` on all six graphs.
Source receipts include the producers, new desktop test, parser template, runner,
workflow and workflow contract. The runner requires seven exact native verdicts.

The new 28-leaf native CONNECT root is registered beside the existing literal
root in `deploy/test_desktop_node_physical.py` and in the imported H2 loopback
inventory. Contract checks preserve every original verdict and reject missing,
duplicate, skipped and failed verdicts. No operation timeout, failure status,
DNS substitution or native lower-UDP guard is relaxed.

## Evidence limits and remaining requirements

The native witness executes on Linux amd64 with the actual pinned core,
checksum-verified Cronet library, authenticated local CONNECT/Naive peers and
declared mapping of captured literal addresses to owned local peers. Focused
native validation copies current changed readers/compiler files into the prepared
pinned tree with the builder's import rewrite; it does not assert a whole current
bundle identity or replace source-pinned CI. Producer/graph and protected-policy
checks do not prove physical host enforcement, signing, deployment or READY.

Final AES/AES+XOR with UDP bootstrap and hostname-dependent UDP bootstrap over
stream-only CONNECT remain unsupported. Imported Server/Compare, additional
selected-hop composition and remaining platform host integrations remain separate
requirements. The original all-device/native scope is unchanged.
