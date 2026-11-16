# Desktop candidate prefix: saved imported protection

The desktop candidate preparation adapter now reads an imported member's
original device policy at its actual penultimate position. It handles the
already supported imported OpenVPN capture before attempting paired-node
capture. This mirrors the existing complete desktop chain policy constructor.
Previously the adapter recognized only imported Shadowsocks at position1;
an otherwise valid saved OpenVPN prefix preparation reached a nil paired node
and was refused during desktop protection capture.

The change is confined to
`internal/mobilemultihop/desktop_node_candidate_preparation_policy.go`. It does
not widen generic source parsing or candidate admission. All saved members
still contribute kill-switch, IPv6 and home-LAN restrictions; the final paired
profile remains the durable protection control. Only the selected WG/AWG
prefix contributes executable transports and physical roots. Application and
DNS ingress remain closed, and the saved OpenVPN/final suffix remains source
provenance rather than a runtime dependency.

## Focused validation

Source base: `638808faedacaf7b6482f0cf63027679c6e12675` plus this correction.
The new `desktop_node_candidate_preparation_imported_policy_test.go` exercises
the actual shared source, desktop physical projection and strict reopener:

- OpenVPN complete lengths3/4/8 on Linux, Windows and Darwin, rotating WG,
  AWG-fast/AWG-strong and TCP/UDP captures (nine leaves).
- The original imported Shadowsocks trio on all three desktop targets (three
  leaves); no unpublished longer imported-SS admission is assumed.
- Copied middle owner, changed middle policy, changed protection metadata,
  changed physical-root identity and foreign candidate catalog refusal (five
  leaves).

The fixture deliberately makes every paired member permissive and only the
uncontacted imported middle restrictive (`always`, IPv6Off, LAN denied). Thus
omitting that member cannot pass as a merely equivalent aggregate. Positive
cases also check final control identity, closed selector/ingress, absence of
suffix transports, original physical roots, detached exact replay, configured
MTU restore and over-ceiling refusal.

All20 unique Go run/pass records (17 leaves and three roots) passed with race
instrumentation in28.523 package seconds,81.463 seconds including compilation.
The original120-second Go bound and240-second wrapper bound were retained.
Source hashes were unchanged during execution. Positive log SHA-256:
`9c0fbc10d47c2421b878e9e606528e2c6ed6255e186446d6ac7ff8dc8b6c4c15`.

A separate race-instrumented replay restored the exact original638 production
helper through a read-only Go overlay, retaining the new test unchanged. The
Linux three-member OpenVPN case failed at its intended constructor witness,
`saved imported middle must retain desktop prefix protection`; no other test,
timeout or panic supplied the failure. The process joined in47.306 seconds.
Causal log SHA-256:
`fe18fce9d7adfb810fd12842cfea743096440d7823041c43767bb27184eb9987`.

The unit was guarded forward to
`b4558b31b11567fbf224c5714d17a2f5db5bc96e` after both runs joined. Its production
and new test bytes remained unchanged; the preceding execution evidence stays
attributed to638 rather than being reported as a rerun on the newer parent.

This proves source/projection/protection behavior. It does not claim an
installed Linux kernel, Windows WFP or Darwin PF/TUN execution, nor does it
add typed SOCKS/CONNECT candidate preparation or grant a saved suffix any
connection, DNS, Ready, Last or measurement authority.
