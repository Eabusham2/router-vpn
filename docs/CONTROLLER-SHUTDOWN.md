# Owned controller shutdown

Portable Exit must disconnect its VPN, close its transports and controller, and
release its application directory. An installed application that attaches to an
existing background controller does not acquire permission to stop that process.

The controller handles `SIGINT` and `SIGTERM` through the same terminal cleanup
transaction used by an owning native launcher. It first refuses new connections,
settings changes, temporary Speed Lab tests, candidate measurements, and automatic
MTU work. It cancels pending startup and active operation contexts before waiting
for their serialized completion. The existing captured runtime teardown then
checks MTU rollback, server leases, native close acknowledgements, process exit,
private workspace retirement, and owned protection release.

A cleanup error retains the exact owner and is retried. Neither a repeated signal
nor an HTTP timeout authorizes force-killing a child or reporting successful
cleanup. A process that never acquired a connection does not release another
controller's persisted firewall when its own listener fails to bind.

## Launcher protocol

An owning launcher creates a fresh random launch token, represented by exactly
32 lowercase hexadecimal characters. It supplies that token only to its newly
started controller as `HOMEVPN_CONTROLLER_OWNER`, and retains the child process
object, PID, and token. The controller captures the token at startup. A reused
controller is not adopted merely because it is listening at the expected address.

The owner sends `POST /api/controller/shutdown` with this exact bounded JSON shape:

```json
{"schema":1,"process_id":12345,"owner_token":"0123456789abcdef0123456789abcdef"}
```

The request is limited to 1,024 bytes. Unknown, duplicate, case-aliased, missing,
malformed, or mismatched fields are rejected before cleanup begins. The nonce and
PID must both match this controller. CLI/service processes without a launcher
nonce still support signals; they do not enable this HTTP capability.

Only after every owned cleanup operation succeeds does the controller send HTTP
200 and this exact receipt:

```json
{"schema":1,"process_id":12345,"owner_token":"0123456789abcdef0123456789abcdef","closed":true}
```

Each request waits at most 30 seconds. HTTP 503 means cleanup remains pending;
the launcher keeps the same process and retries the same identity with a request
timeout of at least 35 seconds. Request cancellation does not cancel cleanup.
After a timeout, the completed receipt remains available until the matching
owner successfully receives a response. A failed receipt write does not retire
the controller. After flushing a successful response, graceful HTTP shutdown
joins the response handler before process exit.

The launcher checks all four receipt fields and then joins its exact child. It
must not kill the process because a response timed out, failed to parse, or named
a different owner. Process exit by itself is not a native lease or rollback
receipt. Signals are appropriate for an independently owned CLI/service process;
they do not provide a launcher with the HTTP acknowledgement above.

## Executable evidence

`cmd/client/controller_shutdown_test.go` exercises admission and startup
cancellation, temporary Speed Lab restore suppression, bounded strict owner
requests, timeout/retry and failed-response retention, actual HTTP response
delivery, and failed-listener isolation. It also runs separate controller and
native helper processes: real SIGINT/SIGTERM must obtain the native close
acknowledgement and retire the owned workspace before controller exit. A native
cleanup failure must retain its registry entry and workspace until the exact
cleanup command succeeds on retry. These are automated ownership tests; physical
device and removable-drive acceptance remain separate evidence.
