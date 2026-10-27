# Desktop MTU ownership and restoration

The native Windows, macOS and Linux applications expose **Auto, Fixed, Retest
and Cancel**. Retest has its own progress view, current interface value,
candidate results and final restoration/commit state. A saved historical MTU
is labelled as saved; it is not presented as a fresh measurement of the current
connection. Invalid fixed values are rejected by the profile/runtime contract.

This document describes the shipping source contract. Exact-commit native
builds, kernel execution, physical networking and private-server acceptance
remain separate evidence. See [REQUIREMENTS-RECONCILED.md](REQUIREMENTS-RECONCILED.md)
and [LIVE-RELEASE-EVIDENCE.md](LIVE-RELEASE-EVIDENCE.md).

## Requirement evidence for this change

These identifiers retain the recovered numbered requirement set in `mm.md`
and `router_vpn_chat_audit_addendum_v2.txt`.
Its old missing/partial labels describe that historical checkpoint; they do not
override current source or supply today's device evidence. The later product
request explicitly retained the best-MTU finder and all-device native scope.

| Requirement | Current source and test connection | Evidence still required |
|---|---|---|
| 231–232: effective manual MTU and WG/AWG plumbing | Profile policy, native configuration, retained TUN and kernel-interface adapters | Exact new native packages and applicable real-device readback |
| 233: default/manual/auto/effective display | Native PowerShell, AppKit and GTK MTU views; operation-specific status and saved-value labels | Packaged visual, scaling and accessibility acceptance |
| 234–237: finder, bounded probes/comparison, path storage and Retest | Captured optimizer capability, Auto admission, authenticated path probes, transactional persistence and cancellation tests | Private-server/cellular performance and current-path measurements |
| 214–224: compatible real multihop | Both node identities, exit DNS/proof, selected execution and entry protection remain captured through MTU and Speed Lab | Real entry-to-exit, forwarding, per-hop and off-LAN acceptance for each requested platform |
| 324–325: Portable clean exit and relocation (also Portable Exit, §86) | Terminal controller drain, exact launcher PID/nonce, checked native cleanup and process join | Actual removable-drive/folder release and normal device exit |

Requirements 225–230 and 239 include live performance diagnosis, CPU/path
comparison and appropriate Jumbo validation. This change does not supply those
observations or establish the cause of the historical cellular regression.

## Captured path and native interface

Ordinary Router VPN native paths and compatible Router VPN multihop use the
retained `routervpn-node` process. Its system TUN belongs to the exact native
Box, private runtime directory, session nonce and configuration digest. Changing
the TUN MTU retains the graph, DNS, independent entry parameters and credentials;
it does not construct a second VPN or relaunch a different selected profile.

The controller captures the actual interface MTU before it starts measurement.
The native process verifies the same interface index, reader generation,
physical path, session and configuration for every command. Begin, Set, Commit
and Rollback carry an owned request/lease identity. Leases expire after a fixed
150 seconds; polling and repeated requests do not extend them. An expired or
failed operation cannot authorize a later result. Successful rollback requires
the original MTU and an explicit restoration receipt. A late Commit receipt is
resolved with a private capability bound to that exact commit and its original
deadline. A confirmed Commit discards the parent capability; ordinary rollback
cannot change an inactive committed lease. Expiry and runtime-retirement
receipts cannot be relabelled as a successful measurement.

Other supported desktop interfaces retain a kernel owner. Linux holds the
sysfs MTU/ifindex objects and validates their filesystem, inode and device
identity. Windows retains the interface LUID and full IP interface row, checks
its GUID/index/alias, and changes only MTU policy on that captured interface.
Neither implementation resolves a replacement interface by its reused name
when rolling back. Native and IPv6 paths retain a 1280-byte minimum; eligible
IPv4 kernel paths use their captured lower bound. Jumbo virtual-interface
capacity does not prove that the physical transport carries 9000-byte packets.

The Python and PowerShell optimizers use a bounded loopback capability owned by
the parent controller. Only its exact current session may read or change that
interface. They cannot fall back to an alias-based mutator after ownership is
lost. The optimizer's deferred result is checked against the original interface
and path, persisted transactionally, re-proved and committed. A failure after
persistence can undo only the measurement fields written by that operation.

## Router VPN multihop

Multihop captures the control profile, entry, exit, both node proofs, running
native graph and already-proved Local or Server execution. Server execution
also retains its authenticated relay lease. A changed node, graph, process,
network, policy or lease disqualifies the result.

The measured value describes the **exit-path system TUN**. It is saved on the
exit profile with that scope; it does not overwrite the entry MTU or claim an
underlay PMTU measurement. Selected control-profile protection and the physical
entry's firewall exception remain captured. The exit's selected DNS policy
continues to govern the path.

The compatible Router VPN graph family remains distinct from the external-node
catalog. The retained compiler uses `NodeMultihopEntryModes()` and
`NodeMultihopExitModes()` in `internal/mobilemultihop`, currently 19 raw modes
each, including packet, proxy, PQ and complete composite/MAX graphs.
`TestNativeEntryMultihopLocalServerCaptureMatrix` exercises those exact catalogs
with all three Start Layers and Local/Server retention. The retained-graph
restoration tests require the system-TUN MTU to be the only changed setting;
the entry, exit, DNS, proof lanes and protection remain captured. Constructor
coverage does not establish every physical pair or a current native package,
and an accepted external-node graph does not expand this Router catalog.

## Cancellation, Auto and Speed Lab

Every native Retest view carries its request, session and profile identities.
Poll, Cancel and final status apply only to that operation. A late HTTP reply
cannot replace a newer window or connection. A cancelled POST can finish with
an error while the final GET correctly reports that rollback completed; the UI
waits for that final owned state.

Auto starts after the Router-node connection is proved and its startup operation
has released ownership. Temporary measurement/connection holds cancel and drain
MTU work before capturing the path. Nested Speed Lab stops share that hold.
Releasing a hold resumes an interrupted Auto attempt, including holds that win
before the operation publishes its cancellable view. Manual Cancel does not
immediately restart the cancelled operation.

Speed Lab captures the **live readback**, rather than the original configuration
file's MTU or a saved historical value. Restoration changes only the captured
system TUN value and its configuration digest, retains the original entry and
exit policy/credentials, restores the already-proved execution choice and
re-proves it. It never reruns Compare both to choose an unrelated replacement.

Failed cleanup remains visible as `cleanup-pending`. It retains its native
owner and blocks replacement until checked Close succeeds. A process exit or
missing acknowledgement is not substituted for a successful rollback. Explicit
Disconnect can retire only its exact native runtime when an unresolved lease
cannot drain, then join MTU cleanup through the checked stopped receipt. A
Speed Lab measurement hold does not take that teardown fallback.

## Application exit

Controller shutdown closes admission to new connection and settings work,
cancels startup/temporary measurements, and drains owned cleanup before exit.
An app-owned controller has a fresh launch nonce. Its launcher requests shutdown
with that nonce and exact process ID, then requires both the matching closed
receipt and that same child's normal exit. HTTP timeout, pending cleanup and
an unexpected process exit cannot authorize a forced replacement or a success
message. Windows installed and Portable use the same shutdown client.

SIGINT/SIGTERM use the same terminal drain for independently launched
controllers. A controller that failed to acquire any runtime does not release
another controller's persisted firewall protection. A native application that
reuses an existing controller does not take ownership of its process.

## Executable evidence

| Boundary | Executable coverage |
|---|---|
| Progress, Cancel and final readback | `deploy/test_desktop_mtu.py`, `deploy/test_macos_mtu.py`, the shipping PowerShell, GTK and Swift fixtures |
| Parent capability and retained interface | `cmd/client/mtu_live_owner_capability_test.go`, `desktop_node_mtu_owner_test.go`, `mtu_kernel_*_test.go` |
| Auto hold races and nested transitions | `cmd/client/mtu_automatic_test.go` |
| Multihop identity, persistence and restoration | `cmd/client/mtu_multihop_snapshot_test.go`, `desktop_node_mtu_restore_test.go` and native multihop/Speed Lab tests |
| Real native construction and cancellation | `mobile/desktop/mtu_node_test.go.tmpl`, included in the actual native builder's race test invocation |
| Shipping native command and real kernel TUN | `deploy/test_desktop_node_mtu_kernel.py`, run against the exact built Linux native artifact in a fresh network namespace |
| Checked process shutdown | `internal/controllerprocess/client_test.go` and controller/native GUI lifecycle fixtures |

The kernel gate retains its existing same-name replacement/rollback cases and
adds the shipping native command's private-file protocol. The local development
environment lacks `/dev/net/tun`, so that new privileged command path must pass
on CI before being described as kernel-tested. Real private probes, leaks,
network transitions, performance and physical UI acceptance remain live tests.
