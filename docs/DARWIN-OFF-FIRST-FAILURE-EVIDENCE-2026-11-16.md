# Darwin Off native fixture: preserve the first failed family

## Observed failure

The retained log for macOS physical socket run `43768501865`, job `132978897101`, at historical source `c7f43af`, shows the deliberately broken “Off preserves ordinary host traffic” control reaching its intended assertion in TCP4, UDP4 and TCP6. The fixture nevertheless started UDP6 after those failures. That last ordinary `net.Conn.Write` reported 33,554,436 bytes for a 38-byte input, followed by the existing poll-layer panic and race reports from the oversized read range. The native runner correctly rejected that transcript; it was never a passing control.

The upstream [Go issue 61060](https://github.com/golang/go/issues/61060) records the same 33,554,436 return count in Darwin networking and packet-filter scenarios. This is supporting context, not a claim to have reproduced or repaired the kernel/runtime cause here. No production networking, Go runtime, race instrumentation or packet-filter policy is changed.

## Fixture change

`TestDesktopDarwinGuardianKernelOffHostAndBroker` now returns when a synchronous `t.Run` reports failure. The child’s registered cleanup finishes before that return. The first actual failed boundary remains a failure, and another family does not begin after it. Successful execution still runs TCP4, UDP4, TCP6 and UDP6 with the original source, assertions, ownership checks, deadlines and cleanup. The unchanged positive validator requires all four unique passing child verdicts and their passing parent.

The mutation validator additionally rejects the actual cleanup message `original Darwin Off guardian did not retire`, even when the transcript also contains the intended ordinary-host denial. Existing panic, race, timeout, skip and cleanup rejection remains intact.

## Executed evidence

A Go race executable compiles the actual family loop extracted from the committed native fixture. Explicit helper boundaries model only sequencing and cleanup; they do not claim PF or socket acceptance. It verifies the complete successful inventory, a failure in each of the four original positions, a cleanup-only failure, and an intended assertion followed by failed cleanup. Every entered family completes its registered cleanup, and no later family enters after failure. Restoring the original continue-after-failure loop fails that dispatch requirement. All eight observations completed under the original small regression process bounds.

The focused compiled-loop check passed in 2.166 seconds. The five existing mutation-overlay checks and the existing SOCKS/Off native-verdict tests passed. The preserved outputs are `darwin-off-family-sequence.log` and `darwin-off-family-verdicts.log` in this continuation workspace.

Actual Intel and Apple Silicon PF/guardian execution remains the mandatory hosted gate. This publication establishes the fixture sequencing and strict verdict correction, not a native kernel pass, a new release, or full product completion.
