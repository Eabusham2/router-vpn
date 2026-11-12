# Connected ordered-prefix candidate workflow

## Published source identities

| Unit | Published commit |
| --- | --- |
| Controller API, permanent freshness invalidation and save-time MTU hold | `edf69b3683d57ae930f5e5d99d5ae166ca19e1f0` |
| Native Windows controls | `f30990fd774f261177a9d1ca32c8bb88f19c951e` |
| Native AppKit controls and transport | `2a7101ad6a1f7248c49863ede1317e17fe703208` |
| Native GTK controls and mandatory widget fixture | `baec5478b5a3fff59cbf4560dbfc1c15db80492f` |

These identify published source units. They do not certify pending hosted
platform gates or a physical-device release.

## User-visible behavior

Performance on the native desktop clients has a separate **Candidates through
connected prefix** action. It captures an existing retained WG/AWG packet
prefix and original saved SS2022 sources. The user selects candidates and tests
50 TCP connections through that prefix. This measures destination TCP
reachability; it does not authenticate the candidate's credentials, measure
ICMP, or invent a private Router VPN identity for an imported source.

Only complete, drained, finite 50/50 receipts are scored. Results retain the
native producer's measurement timestamp and expire exactly 120 seconds later.
Status polling does not extend that timestamp. It observes the original saved
catalog, session, source files, native MTU reader and ready proof. Loss of any
original owner permanently invalidates that job's displayed/scored rows, even
if the previous values later reappear. A changed picker selection must be
captured before Test or Save becomes available.

**Save next-connection profile** is explicit and requires a profile name and
confirmation of the complete displayed path. A paired SS2022 candidate replaces
the suffix after the chosen packet prefix. A custom SS2022 candidate currently
supports the bounded three-member shape: original first WG/AWG node, the
original imported SS2022 source, and the original paired SS2022 final. Other
insertions remain unavailable. The actual ordered compiler validates the full
proposed original source before saving.

Saving appends a complete existing connection-profile record, preserving each
node's own policy and credential references. It does not rewrite the active
profile inventory, credentials, selected node, or native runtime. Normal Load
continues to require disconnecting before applying the saved profile.

## Controller protocol and ownership

- `GET /api/multihop/prefix-candidates/catalog?prefix_position=N` returns a
  bounded selection view with an opaque 256-bit token, exact eligible source
  identities, prefix choices and explicit proposed paths. It grants no path
  proof or measurement permission.
- `POST /api/multihop/prefix-candidates` requires the original view token,
  prefix position, distinct saved candidate IDs, a new 128-bit request ID and
  exactly 50 samples. The synchronous POST retains its original HTTP context;
  no detached background measurement job is created.
- `GET /api/multihop/prefix-candidates?request_id=...` observes that exact
  retained job. Its bounded observer runs outside the shared control lock. An
  atomic loss latch prevents stale results from reviving even if cancellation
  expires before the observer can reacquire the lock.
- `POST /api/multihop/prefix-candidates/cancel` reuses the existing candidate
  cancellation owner. Premature Cancel records the request nonce, so a delayed
  start cannot resurrect it.
- `POST /api/multihop/prefix-candidates/save-profile` requires the original
  request/view/candidate, a name and the exact proposed node list. It rechecks
  the live reader/proof, catalog and source compiler before atomic profile-store
  publication. Save reacquires the exact retained launch's MTU hold before
  rechecking the original reader and retains that hold through the atomic write.
  Any reader change while Auto was allowed to resume invalidates the receipt;
  the new reader is never substituted. A receipt permits one explicit save.

The existing operation lock, public Stop/shutdown admission and candidate
ownership are shared with the pre-connect pair workflow. Native exchange owns
its exact original source/pulse/request/cancel inodes. An unjoined failure keeps
its opaque retirement handle and original MTU hold; Cancel retries only that
handle. Replacement operations remain blocked until that owner joins. A late
successful response after user cancellation cannot re-enable a result in any
native dialog.

## Executable evidence boundaries

The Go HTTP fixture exercises the real connected owner/source capture, actual
native mailbox request, response adoption, joined MTU hold and complete saved
profile transaction. Its native response producer is an explicit boundary;
real encrypted 50-handshake evidence belongs to the independent mandatory
native prefix witness described in `ORDERED-PREFIX-CANDIDATE-NATIVE-EVIDENCE.md`.
The save fixture also checks that Retest/Auto cannot acquire the MTU mutex
during publication and that the hold is released afterward. Additional tests mutate the actual saved source, session and MTU mailbox, then
restore them, and require permanent row invalidation.

The Windows fixture executes the final launcher composition and actual dialog
functions/callbacks with explicit WPF/HTTP boundaries. The Swift fixture executes
extracted shipping controller methods and separately compiles/tests the real
bounded transport. AppKit object behavior still belongs to hosted macOS builds.
The GTK fixture compiles the shipping form with real GTK widgets under Xvfb and
controlled HTTP completion; it is mandatory in the existing native form lane.
No local GTK execution or physical/TUN acceptance is claimed where those
privileges or libraries are unavailable.

Local verification:

| Scope | Result and boundary |
| --- | --- |
| Complete API freshness suite | `-race` PASS, 217.456 seconds; original source/session/reader loss cannot revive rows |
| Final save-time MTU hold | Focused `-race` PASS, 129.130 seconds; both full validations and the original 20-second Save deadline retained |
| Windows composition | 38 existing Performance checks, 22 ordered-candidate checks and four existing causal controls passed under PowerShell 7.7 |
| Swift candidate controller and transport | 17 controller checks and 14 actual bounded transport checks passed |
| Swift live response integration | 71 existing checks and six causal controls passed |
| GTK | Mandatory shipping-form/real-widget/Xvfb fixture added; local execution unavailable, hosted result still required |

One prior focused Save attempt returned the opaque original-owner guard. The
same path subsequently passed with cancellation diagnostics added and all full
validations retained. Its exact earlier cause was not established; no deadline,
identity equality or source check was relaxed to obtain the passing result.
Packaged Windows PowerShell 5.1/WPF and actual AppKit runtime acceptance also
remain hosted evidence boundaries.

Commands:

```
go test -race -p=1 ./cmd/client -run '^TestOrderedCandidate' -count=1 -timeout=300s -v
pwsh -NoProfile -File client/test-windows-ordered-candidates.ps1 -Root .
python deploy/test_desktop_ordered_candidates.py --platform darwin
python deploy/test_desktop_ordered_candidates.py --platform linux
```

These units do not claim candidate authentication, arbitrary imported protocol
families, every ordered graph, or physical acceptance on every device. Existing
pre-connect pair measurement and connection-profile load guards remain in force.
