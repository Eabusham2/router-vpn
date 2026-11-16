# Original whitening owner and joined retirement receipts

This prerequisite adds observation and cleanup receipts to the existing authenticated whitening transport. It does not enable a new public CONNECT Start Layer or grant a new connection, packet, key, or dialing capability.

`Owner.CaptureOriginalContext` captures the exact original owner and live generation. Its returned observation rejects a copied owner, replacement context or generation, Reset, Close, cancellation, and a caller whose deadline expires while the owner lock is busy.

`AuthenticatedStream.CaptureJoinedRetirement` can be captured only from the original live authenticated stream and a raw connection already held by the caller. The receipt remains unusable until the original raw connection, both I/O directions, and cipher have joined Close and the original owner map entry has retired. It retains exact stream, cipher, raw, owner, and generation identities. Both authenticated stream and packet constructors initialize the close-completion channel.

The receipt records joined cleanup only. `Close` continues to return its original error on every retry; consumers must still apply their existing operation and error-classification checks. Replacement or unrelated cipher errors gain no new acceptance from this library change.

## Validation

The complete `internal/startwhitening` package passed `go test -race -json -count=1 -timeout=90s ./internal/startwhitening`: **32 test roots, 67 records, no skips or failures**, in 13.637 seconds including compilation, within the existing 180-second process bound. The package used Go 1.26.3 with one compile CPU and an 800 MiB compiler memory limit. The four changed Go files and every other package Go source were checked against the exact passing source manifest after copying to the publication worktree; no package source changed after that run.

The added tests use the shipping owner, an actual `net.Pipe`, and an explicit blocking cipher lifecycle double. They cover held-close refusal, exact close-error retention across retries, copied and foreign owners, typed-nil raw input, raw and cipher replacement, retained owner-map entries, cancellation, and caller deadlines. Existing stream and packet ownership tests also ran in the same package suite.

The proof was captured on repository base `0f07335da94b015fbc73d2581f29cbe16dbc9047`. The publication unit was prepared on `58a73bcf284d0d91a1dc22ac98c164c90f51e7aa`, then integrated onto `b0f13141a21a750aeeeed21efb06411c2ba59c8b` while preserving its newer Local OpenVPN restoration work. All fifteen package Go inputs still match the passing source manifest. Native CONNECT concrete-final adoption, actual encrypted SS2022/UoT-v2 traffic, native Box execution, and public host final-layer admission remain separate work. This package result is not a native, kernel, device, or installed-path acceptance claim.
