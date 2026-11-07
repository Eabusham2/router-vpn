# Native PQ dial observations

The protected PQ transport failures below are **not causally resolved** by the
admission diagnostic. The diagnostic preserves their original native error and
records bounded evidence for the next executed failure. It neither retries the
connection nor changes a transport, peer, permit, timeout, or acceptance gate.

## Observed CI boundary

| Exact source and job | Observation |
| --- | --- |
| `100c1e5abbf7e9f7ebaedb459a41e961425283ab`, [Aux ARM64 job 128336558558](https://github.com/Eabusham2/router-vpn/actions/runs/42340818031/job/128336558558) | `TestRouterVPNDesktopNodePQTraffic/awg2-pq/off` failed during native PQ startup with `protected PQ peer transport could not open`. The entire leaf took 1.47 seconds. The other five mode/layer leaves passed. |
| Same source, [Windows ARM64 job 128321441483](https://github.com/Eabusham2/router-vpn/actions/runs/42340816527/job/128321441483) | `TestRouterVPNDesktopNodeCompleteMAXQUIC/max-quic-wg/aes-256-gcm+xor-whitening` failed with the same admission error. Its reported construction took 1.743363 seconds and the entire leaf took 1.76 seconds. The other five QUIC leaves passed. |
| `6fa3efa1e315a032018c1e88bd00f51bda3c6dd2`, [later native Windows MAX run 42398899779](https://github.com/Eabusham2/router-vpn/actions/runs/42398899779) | The ARM64 QUIC job passed. AMD64 job `128482204527` failed the separate actual-WFP credential case `max-quic-wg/off/kem-peer`: the negative did not reach its retained encrypted peer. That different fixture/failure does not establish a cause or repair for the earlier composed-peer admission failures. |

Both initial failed leaves completed before the existing five-second dial
admission limit. Their generic errors discard the underlying native result, so
they do not identify a timeout, socket syscall, protected permit rejection, or
caller cancellation. Extending the limit would not follow from this evidence.
At the initial review of published selector source
`35e72a44c1df446b57d71d94d3725c23f51757ab`, its auxiliary ARM64 and relevant
Windows runs were still pending or queued; no successful rerun was claimed.

## Retained diagnostic

`internal/mobilepq/controller.go` captures the rejected dial result before
closing any returned socket. The private `dialAdmissionFailure` retains the
original error through `Unwrap`, so `errors.Is` and `errors.As` can inspect the
native syscall and wrapper identity. A separately captured caller error and
five-second budget expiry remain distinguishable.

Its formatted startup message contains only:

- Elapsed admission milliseconds and whether the admission budget expired.
- A fixed caller-error class and whether the native dial returned a socket.
- A fixed native-error class, numeric syscall error, and allowlisted operation
  and network names.

Unknown error types produce `other`; arbitrary error text, addresses, keys,
paths, and operation names are not formatted. Classification visits at most
16 nodes, reads concrete standard-library wrapper fields, and unwraps only
the exact standard-library `fmt`/`errors` wrapper types. It never invokes a
custom `Error`, `Is`, `As`, `Timeout`, or `Unwrap` callback. Deep or opaque error
trees remain inspectable by an explicit caller but cannot delay the diagnostic.

## Ownership and execution boundary

The original admission predicate remains: stop the five-second timer, require
the monotonic return time to precede its deadline, require a live retained dial
context, require no dial error, and require a returned socket. A late or failed
socket is still closed synchronously before protocol cleanup. Failed admission
cannot process a cryptographic event, install a key, or publish readiness.

The existing virtual-clock tests still prove the exact before/at/after
five-second boundary, post-admission transport lifetime and rekey I/O, and
cancellation joining the original late socket. New tests execute the actual
controller against native error shapes, cancelled and expired admission,
late sockets, cleanup failure, opaque callback errors, and bounded redaction.
They retain original cause identity and prove exactly one peer revocation and
protocol cleanup. These tests do not execute a real Rust KEM or establish the
cause of the recorded Windows failures. Existing native Rosenpass, NodePQ,
complete MAX, real peer traffic, credential rejection and physical-owner gates
remain required without timeout or verdict changes.

## Local validation of this diagnostic

- `go test -p=2 -race -json ./internal/mobilepq -count=20 -timeout=90s`
  passed: 66 distinct root/subtest verdicts, repeated 20 times (1,320 verdicts).
- `go vet ./internal/mobilepq` and the Windows ARM64 test-binary
  cross-compilation passed. Cross-compilation is not Windows execution.
- `deploy/test_native_pq_bridge.py` passed all six existing bridge tests with
  their declared modeled native handles and protocol events.
- An overlay restoring the original generic admission error fails the new
  actual-controller `native-syscall` case because the original admission
  evidence is missing. The overlay does not modify the tested source tree.
- `deploy/test_native_pq_factory.py` could not launch its C compilation because
  `clang` was unavailable locally. No local real Rosenpass archive was available;
  a real native KEM exchange was not executed for this diagnostic.

At the final CI review of source `35e72a44c1df446b57d71d94d3725c23f51757ab`,
[Native Rosenpass protocol and ownership run 42402763402](https://github.com/Eabusham2/router-vpn/actions/runs/42402763402)
had succeeded, while the relevant auxiliary ARM64 and Windows PQ/MAX runs
remained pending. That published source predates this diagnostic.
