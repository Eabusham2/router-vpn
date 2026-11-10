# November 10 unfinished-work recovery record

## Publication and availability

All completed source units through
`d493015fe308262f713785ab10c728a9a4d951b9` were committed, pushed to `main`
and verified by rereading the remote reference. That was also the last
successfully synchronized local head. The execution environment then became
unavailable: process creation reported an exec-server transport disconnect,
recovery timed out after 45 seconds, and the environment explicitly reported
unavailable. This is an execution-infrastructure failure, separate from the
earlier local Netlink/Unix-socket capability restrictions.

Connected GitHub remained available. The reviewed Windows fixture repair
`885fb23c935b4006d8766e9a0b184bd4184063c5` was subsequently published with
normal ancestry and its remote contents checked. It requires hosted validation;
no local PowerShell execution after the outage is claimed. The evidence/status
update containing this record is documentation only.

The Linux parent/host unit described below is **unfinished, unpublished and
not backed up as a verified byte-exact patch**. Its most recent working files
are inaccessible. Their persistence cannot currently be checked. This record
preserves the last observed design, path inventory, tests and known defects;
it does not establish that an archived patch or usable workspace exists.

## Published Linux prerequisites

- `f166f0b19ea37b7857ff3b81e7a2d195817650eb`: sealed imported WG-entry to
  paired SS-final physical policy, both Start Layers Off, and retained Linux
  native lifecycle.
- `cd9c69031682d1cb03081ebc42f09ac29ac2cf78`: authenticated inherited child,
  independent imported source parsing, selection hashes, final-owned cover,
  DNS/MTU control and original constructor retention through native join and
  retirement acknowledgment.

These are available in normal upstream history. Do not rebuild or replay them.
Their strict real Linux physical/guardian cases still require the matching
privileged native runner. Local source/model checks were not physical acceptance.

The public imported dispatcher remains closed. The unpublished client source
also deliberately rejects with “Linux imported protected host is not yet
admitted.” A successful partial compile is insufficient to remove either guard.

## Last observed parent/host validation

A capped `cmd/client` compile completed with `go test -p=1 ./cmd/client -run
'^$'`, using Go 1.26.3, GOMAXPROCS=1, GOGC=20 and GOMEMLIMIT=512MiB. The test
process reported success after compilation. **Later temporary-owner changes
and additional tests were not included in that completed result.**

A subsequent `go test -p=1 ./cmd/client -run '^TestDesktopLinuxImported'
-count=1 -timeout=120s` process was started, but its result could not be
retrieved after the environment became unavailable. Treat it as unverified.
No actual privileged imported host/TUN, encrypted peer, DNS/MTU, restoration
or retirement case passed for this parent/host unit. No Windows/macOS
cross-compile of its common interface changes completed.

## Pending parent/host files

These paths were reported edited or created before the outage. Inspect the
actual restored tree before deciding which versions exist.

| New file | Intended responsibility |
| --- | --- |
| `cmd/client/desktop_imported_platform.go` | Common captured-platform/runtime interfaces and Start-before-DNS-registration helper. |
| `cmd/client/desktop_imported_platform_other.go` | Non-Linux capture stub. |
| `cmd/client/desktop_imported_linux_source.go` | Strict WG-to-SS/Off capture, installed-parent/network ownership, independent profile revisions and temporary-owner handling. |
| `cmd/client/desktop_imported_linux_host.go` | Typed imported source/current/readiness and inherited transaction. |
| `cmd/client/desktop_imported_linux_lifecycle.go` | Existing real Linux session/host adapter, dual proof, selected DNS, activation, restore, observation and retirement. |
| `cmd/client/desktop_imported_linux_source_test.go` | Eligibility, sealed identity, independent source and digest negatives; no retrieved result. |

Modified paths:

- `cmd/client/desktop_external_linux_host.go`
- `cmd/client/desktop_node_host_linux.go`
- `cmd/client/desktop_node_host_linux_active.go`
- `cmd/client/desktop_node_host_linux_proof.go`
- `cmd/client/desktop_node_host_linux_ready.go`
- `cmd/client/desktop_node_host_linux_start.go`
- `cmd/client/desktop_node_linux_transaction.go`
- `cmd/client/desktop_node_mtu.go`
- `cmd/client/desktop_node_mtu_linux.go`
- `cmd/client/desktop_node_native.go`
- `cmd/client/desktop_imported_mtu.go`
- `cmd/client/multihop_execution.go`
- `cmd/client/multihop_native_capture.go`
- `cmd/client/multihop_native_imported.go`
- `cmd/client/multihop_native_imported_dns.go`
- `cmd/client/multihop_native_launch.go`
- `cmd/client/multihop_native_restore.go`
- `cmd/client/multihop_native_routes.go`
- `cmd/client/speed_lab_imported_preparation.go`

The published measurement-clock and Home literal H2 files are separate units.
Do not attribute their completed results to this Linux parent integration or
overwrite their later changes while recovering the unfinished source.

## Captured ownership and child contract

The Linux integration must keep the existing session, process, journal and
physical socket broker as lifecycle owners. It must not create a second
`desktopNodeOwners` process/Wait/retirement authority merely to satisfy a
Windows-oriented lookup.

| Contract | Captured value |
| --- | --- |
| Command | `routervpn-imported` |
| Canonical constructor | `imported-source.json` |
| Complete staged graph | `sing-box.json` |
| Native ready record | `node-ready.json` |
| Inherited capabilities | FD3 channel, FD4 private directory, FD5 exact image |
| Parent capture identity | `NodeSelection.CaptureSHA256` |
| Transfer identity | `NodeSelection.ControlSHA256` |
| Entry proof | Port 1098, `multihop-entry-proof` |
| Paired final proof | Port 1099, `multihop-proof` |
| Constructor lifetime | Retained through actual source join and parent retirement acknowledgment |

Linux staging creates private files first; the actual process/command exists
only after Start. DNS runtime registration and common binding order must
respect that lifecycle, retain partial owners on failure and verify both
original node identities before Connected.

## Known correctness work before public admission

1. **Temporary projection:** after staging/start, transaction acceptance must
   require the applied temporary profile projection and exact Speed Lab owner.
   Matching the reverted original saved profiles must not authorize a live
   transaction. Check both independent source revisions and runtime options.
2. **Successor stop intent:** extend the relevant
   `stopModeWithIntent(native.ownedNode != nil)` decision to the retained Linux
   imported owner so a successor does not accidentally release protection.
3. **Activation and monitor:** synchronize activation idempotency under the
   original host gate. Establish the real session monitor after both public
   and Local/Speed Lab activation.
4. **MTU retirement:** retain the typed imported MTU owner until child join.
   Stop/hold/error cleanup must not require a capability that the same host
   has already deliberately marked closing.
5. **Partial failures:** inspect every stage from private staging through
   start, readiness, DNS registration, dual proof, binding and activation.
   A started child cannot be cleaned only by `retireUnstarted`; do not clear
   source/configuration authority before real session retirement succeeds.
6. **Registry assumptions:** imported Speed Lab and restoration must observe
   the actual Linux session rather than assume the legacy Windows registry.
7. **Causal cases:** complete temporary-owner replacement, changed saved
   sources, changed applied projection, cancellation, lifecycle ordering,
   wrong identity and incomplete-retirement tests. Current new tests have no
   retrieved result.
8. **Actual public path:** add the installed-controller/native-image fixture
   with independent encrypted WG and SS peers, final-owned DNS, both proofs,
   MTU/restore and joined retirement. Exercise the public API path and its
   persistent native release gate before opening admission.
9. **Cross-platform regression:** compile the common interface edits on the
   requested desktop targets and preserve existing Windows and macOS behavior.

## Unfinished encrypted peer fixture

The peer agent reported successfully writing these before the outage:

- `mobile/desktop/node_imported_peer_linux_test.go.tmpl`
- Its registration in `deploy/prepare-desktop-external.py`

They have **not compiled or run**. A subsequent command to append traffic and
capture cases failed at process creation; assume it did not execute until an
actual file inspection establishes otherwise. Do not publish the incomplete
peer template or treat it as a working native gate.

The intended root is `TestRouterVPNDesktopImportedWGSSReferenceProcess`,
selected in the child by `ROUTERVPN_IMPORTED_WG_SS_REFERENCE_CHILD=1`.
The isolated topology uses peer/client 192.168.210.2/192.168.210.1, an
independent WireGuard transport, inner SS2022 at 10.77.0.1:8388, paired HTTP
proof at 10.77.0.1:8787 and Home DNS at 192.168.50.133:53. These are fixture
addresses, not a live deployment.

Entry public proof uses a real TLS trace for 1.1.1.1:443 with a dedicated
fixture CA and a leaf containing IP SAN 1.1.1.1. Normal certificate validation
uses the captured CA; no insecure verifier is intended. Independent counters
must distinguish entry, final, public proof, paired proof and final DNS. The
optional direct-router control has a separate counter so bypass traffic cannot
masquerade as final traversal. Wrong-node, DNS refusal, wrong public proof and
cover failure/restore controls remain required.

## Safe continuation

Inspect live `main`, the actual working tree and ancestry first. Preserve
any remaining dirty files before updating the checkout. The last synchronized
local head was `d493015f`; later remote fixture/document commits must be
retained. Do not reset or overwrite an accessible dirty tree.

If the pending files are absent, any recreation is a **new reconstruction**
from the published baseline and this design record, not restoration of a
verified patch. Recompile and rerun the full relevant tests. Compare the actual
diff to the published child/policy units and the measurement commits before
admitting the result.

Once a coherent unit passes its relevant checks, commit and push it promptly
to `main` using normal ancestry, reread the remote reference, and verify its
matching native jobs. Keep package publication, physical acceptance, signing
and authorized private deployment separate. No private router or server
deployment was performed in this continuation.
