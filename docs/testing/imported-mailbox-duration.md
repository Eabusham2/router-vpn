# Imported mailbox completion and measured DNS duration

The native imported mailbox carries two distinct operations: an empty operation
selects the original Box DNS proof, while `openvpn-observe` reads the retained
OpenVPN packet connection. A current observation may finish within one clock
tick. Failed or pre-cancelled requests may also complete without elapsed time.
Those results can acknowledge completion of their exact request; they do not
provide a successful DNS latency measurement.

## Original failure and repair

On source [`8be50dbf`](https://github.com/Eabusham2/router-vpn/commit/8be50dbfbd16173980ce672aa91dfba2cee65cc7), the Windows AMD64
native job `129011912997`
reported successful native OpenVPN observations as failed with an actual zero
`milliseconds` value. Its native proof error was nil. The producer applied the
positive DNS duration rule to the observation operation, and the client also
rejected zero-duration completion receipts.

The producer now permits zero-duration `openvpn-observe` success. The client
permits finite, nonnegative, bounded durations for observations and unsuccessful
completion. Passing DNS still requires a strictly positive interval. Negative,
nonfinite, oversized, foreign, stale, or unconsumed results remain invalid. All
original request, source, TUN, reader, generation, OpenVPN receipt, heartbeat,
deadline, cancellation, and join checks remain in force.

The Windows ARM64 uncached-DNS failure showed a new upstream query but omitted
the proof error and measured duration. The fixture now reports both. Its prior
log alone does not prove that its failure had the same cause as the AMD64
observation failure.

## Executable coverage

`TestRouterVPNImportedDNSOperationDuration` uses the actual native mailbox and
retained-owner constructors inside a Go `synctest` bubble. It requires exactly
zero elapsed time for an observation, immediate DNS success/error callbacks,
and pre-cancelled DNS/observation requests. Only the current observation passes;
zero-time DNS fails and cancellation completes without borrowing DNS or packet
evidence. Each case requires its original request and cancellation entry to drain.

`TestDesktopImportedDNSOperationDuration` publishes a real private request and
exercises the actual client decoder, result reader, and cleanup path. Its 20
cases distinguish DNS from observation for positive and zero measurements,
failed/cancelled zero completion, negative/nonfinite/oversized values, and
changed reader/operation identity. Invalid evidence uses an explicit modeled
native close acknowledgement to finish cleanup; it never gains passing or
joined-result authority.

The mandatory native inventory retains its original 13 verdicts and adds six
zero-tick verdicts. The client inventory retains every original case and adds
21 duration verdicts. Missing, duplicate, failed, skipped, or foreign verdicts
remain rejected. The existing OpenVPN inventory is unchanged.

The bounded Linux validation passed 55 client race verdicts across 10 roots
(package 1.863 seconds), and 59 native mailbox/OpenVPN race verdicts across eight
roots (package 1.765 seconds), with no failure or skip. Replacing only the
client production reader with its original source rejected exactly five new
zero-completion leaves. Replacing only the native producer with its original
source rejected the zero-tick observation leaf. The other duration controls
continued to pass; neither control failed by timeout, panic, or race. Four
source/inventory contract tests also passed.

The native component run compiled the actual prepared `cmd/sing-box` package
with explicit overlays for this unit's four templates. Original mailbox,
OpenVPN, and strategy inputs were byte-compared before execution, and the
prepared tree and overlay inputs were hash-checked afterward. This local run
omitted the unrelated native-PQ build tag because the Rosenpass static archive
was unavailable. It is not a completed full-runtime bundle or Windows runtime
acceptance result.

One execution of the original uncached-DNS and OpenVPN TCP/UDP native cases
failed at `create netlink socket: operation not permitted`, before their actual
resolver assertions. Those three cases remain mandatory in hosted native CI;
the local boundary was neither skipped nor bypassed.

## Remaining Windows DNS timing boundary

Go 1.26.3's Windows AMD64 and ARM64 `runtime.nanotime1` read the shared interrupt
clock, and `time.Since` uses that monotonic clock. The mailbox converts elapsed
nanoseconds directly to floating-point milliseconds; zero is not an integer
millisecond truncation. A sufficiently fast real local or Home DNS exchange can
therefore still finish within one tick and be refused by the positive DNS rule.
The selected-DNS measurement in `node_box_dns.go.tmpl` has the same boundary.

DNS-only fixtures wait for a real positive response interval within their
original bounded context. They do not clamp, fabricate, or relax a measured RTT.
This makes those fixtures suitable for proving resolver and ownership behavior;
it does **not** repair real fast Windows DNS measurement.

A separate DNS elapsed-time integration can reuse the existing
`internal/hopmeasure` platform clock, which already uses Windows
[QueryPerformanceCounter](https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancecounter)
and its
[boot-stable frequency](https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancefrequency)
for that exact measurement bracket, while retaining the existing context and
deadline clocks. That work requires checked conversion, failure and zero-time
controls, and actual fast-DNS execution on both Windows architectures. It is not
implemented by this operation-specific repair.
