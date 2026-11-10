# Darwin grouped-renewal fixture capture

The November 9 source `83c0ae617858e331bbb7bc1fd3385120938d45c6`
failed the macOS Intel native ownership gate in
[run 42583227125, job 129046739068](https://github.com/Eabusham2/router-vpn/actions/runs/42583227125/job/129046739068).
`TestDesktopDarwinGuardianKernelSOCKSAssociations` failed both IPv4 and IPv6
`group-renewal` and subsequent `renewal-authority` checks. The recorded first
loss was an expired child receipt while its next operation was applying;
its acknowledged parent was still valid. The error was observed while the
manual fixture captured a group, before that group's PF renewal call.

The fixture acquired each peer operation with blocking `Lock`, retaining
already-acquired parent operations while waiting for later children. It also
bypassed the broker's one-group `renewing` owner. This allowed the manual
capture to interfere with the monitor's existing renewal transaction.
Production capture already uses a reserved group owner and nonblocking peer
admission. The repair applies those ownership rules to the native fixture.

The fixture now reserves the original broker renewal slot, acquires all peer
operations without blocking, and releases every partial peer and the slot
before a bounded cancellation-aware admission wait. It reads each original
receipt again after acquisition. Only a complete fresh group reaches the
existing native renewal operation; native execution is not retried.

No production PF code, five-second readback age, seven-second permit cap,
three-second control budget, socket identity check, or receipt timestamp is
changed. The original native PF assertions and parent-derived expiry checks
remain mandatory.

Local validation executes the exact platform-independent capture helper and
its focused test bodies extracted from the Darwin test source, using the real
broker/peer types with modeled native policy. Six race cases cover immediate
capture, a held child, capture after that child joins, an existing monitor
transaction, caller cancellation, and a stale child. The complete group
preserves receipts and releases operations and the renewal slot. Two deliberate
source mutations that retain a partial parent lock or borrow the monitor slot
fail at their corresponding ownership assertions.

The existing Darwin runner now requires the parent and all six capture-case
verdicts. Its sixteen SOCKS boundary/runner tests pass locally. A broader
45-test runner attempt passed 44 tests and was blocked only by the environment's
refusal to create Unix sockets in the separate original-channel lifetime test.
These are fixture and runner results, not native Darwin acceptance. The new
source still needs its complete Intel and ARM64 hosted kernel runs; this repair
does not claim to prove that every prior expiry had the same cause.
