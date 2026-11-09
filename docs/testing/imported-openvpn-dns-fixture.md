# Imported OpenVPN selected-DNS fixture

## Failure and correction

The Linux native application workflow for `f23dea2f6d1650bac010cd569ee27392651b539d`
reached the real OpenVPN connected observation, then failed the first selected
DNS mailbox operation for both TCP and UDP. The failed run is
[42564425756](https://github.com/Eabusham2/router-vpn/actions/runs/42564425756),
jobs `128987785015` and `128987784976`.

The fixture graph had no TUN inbound. Its separate MTU fixture therefore did
not satisfy `RouterVPNStrategyDNSProofContext`, which requires exactly one
owned tagged TUN in the same Box before it queries the captured DNS route.
The fixture now registers its explicit platform TUN in that Box. The MTU
owner reads and claims that exact manager entry. Its modeled interface
replacement also updates the real manager, and the test checks that rollback
leaves the packet observer and DNS proof attached to the same registered
reader.

The actual mutual-TLS/data endpoint, native DNS router, uncached TCP DNS
exchange, original caller, mailbox publication, connected generation and
reconnect refusal remain production code. The public endpoint maps to a
loopback test provider. OS TUN creation and interface replacement remain
explicit test boundaries; this is not physical TUN acceptance.

The DNS peer now validates the bounded proof question and returns an A record
only to an A question. AAAA connection-reuse probes receive a matching empty
answer. Positive / NXDOMAIN / positive transitions must still each advance
the real upstream query counter. A failed proof includes its native error and
query count in the test diagnostic.

## Validation on November 9, 2026

The isolated prepared core used pinned source
`1ac1a339cb1223e9c70eae14c44411c75033c02d`. The two original test templates and
the production DNS proof template matched the publication parent byte for
byte before the correction was supplied through a Go source overlay.

On Linux AMD64, Go 1.26.3:

- The corrected native command package compiled with the real OpenVPN remote
  test provider and race instrumentation.
- **41 passing verdicts across five roots** covered the original constructor,
  tuple, caller, mailbox and cancellation/join cases. The final focused run
  passed in 27.546 seconds, including compilation; no cases failed or skipped.
- The ten existing desktop imported OpenVPN packaging contracts passed in
  35.227 seconds, including exact native test inventory and prepared-template
  registration.
- Both the unchanged and corrected native connected cases stopped earlier
  at `create netlink socket: operation not permitted` in this workspace. The
  ordinary native DNS and real provider bind-collision tests hit the same
  environment boundary. The focused package run therefore **did not pass**,
  and local execution did not reproduce or close the later hosted DNS failure.
- An initial attempt with the complete CI tag set could not link the absent
  `libroutervpn_rosenpass` archive. The bounded OpenVPN execution above omitted
  only the unrelated `routervpn_native_pq` tag. Shipping workflow tags and
  native PQ requirements were not changed.

The exact-commit hosted Linux native jobs remain the acceptance gate for
the complete native tag set and actual provider / selected-DNS / MTU handoff
sequence. A local compiler result or the five passing roots cannot substitute
for those jobs.
