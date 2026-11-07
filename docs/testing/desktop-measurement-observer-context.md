# Desktop measurement observer context

Public-IP and DNS Retest observation, and the current/temporary Speed Lab
identity observers, retain the original request context through tracker and
application mutex admission. They do not start a replacement session tracker.
Speed Lab also captures the tracker pointer so an identical session ID in a
replacement tracker cannot authorize an old measurement.

The observer and terminal validator share the same immutable profile/session
binding. Multihop graph generation, both profile tokens, runtime command,
physical network, Tor source/predecessor, and native readiness checks remain
required. Context-capable network, Tor, external, Linux-path, and owned-Node
observers receive the original caller. A legacy callback is not invoked as a
fallback when a contextual native capability is missing.

Cancellation stops measurement requests and joins the observer. It does not
retire a healthy VPN. Terminal adoption acquires tracker/application locks with
the same caller and rejects cancellation or identity replacement before it
authorizes a write.

## Explicit synchronous boundaries

`beginNodeBoundOperation` retains its general protection/recovery transaction
contract. An already-entered transaction may outlive request cancellation and
must finish synchronously. The measurement rejects adoption after that join if
the request was canceled. This is not a hard cancellation deadline for general
protection recovery.

Private asset and native record reads remain bounded regular-file operations.
Mutex admission is cancellable, but an OS read already entered is joined until
return. Already-admitted profile persistence also retains its existing joined
transaction and rollback semantics. No file operation or persistence worker is
detached to manufacture a prompt cancellation result.

The contextless compatibility observer APIs retain those older boundaries.
Fastest and external comparison dependency adoption are a separate increment;
this change does not claim all desktop callbacks are contextual.

## Executable evidence

`deploy/test_desktop_mtu_client_context.py` requires the exact measurement test
roots and leaves alongside the existing MTU/network/process/protection
inventory. Missing, duplicate, skipped, failed, or foreign verdicts fail the
gate. The measurement controls cover held application/tracker/workspace gates,
the original Tor/host caller and deadline, exact tracker replacement, observer
join, and cancellation before/during the joined adoption transaction.

These are source and composed controller tests. They do not establish physical
traffic, device acceptance, or completion of the remaining platform graphs.
