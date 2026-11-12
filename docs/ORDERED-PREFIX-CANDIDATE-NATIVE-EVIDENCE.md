# Encrypted retained-prefix candidate timing evidence

`TestRouterVPNDesktopNodeChainEncryptedPrefixCandidates` supplies the mandatory
encrypted transport witness for prospective candidate TCP timing. It uses the
shared `hopmeasure.NewPrefixCandidatesContext` service with an explicit native
adapter boundary, real native WG/AWG outbounds, and independent reference
peers. It does not instantiate a system TUN or substitute for the production
host mailbox, catalog capture, or full `NodeChain` readiness tests.

## Original source and retained transport

Each of the WG, AWG Fast and AWG Strong cases creates two independent paired
packet prefixes and an original SS2022 final source. The candidate is that
source's exact literal endpoint, `10.77.0.1:8388`, measured through retained
prefix position 1. The compiler validates the complete candidate inventory;
its original source digest and capture digest identify the result. The test
checks the endpoint and original credential against the compiled source.

All measurements in one case reuse the same native outbound instances. The
adapter boundary checks their captured pointer and original source/config
identity, observes the complete captured inventory, and authenticates the
original prefix's private health service through that retained outbound.
These are real encrypted network observations. The adapter's activity hold is
an explicit fixture boundary; real host MTU exclusion and system-network
ownership remain responsibilities of the separate native host integration.

A successful result requires fifty fresh TCP connections and fifty closes,
fifty accepted connections at the independent SS listener, and traffic through
the original encrypted entry. The service must report fifty samples of
`routed-tcp-connect`, with a positive trimmed mean and the exact candidate
source/capture digests. No SS plaintext or final private API request may occur.
The result therefore proves TCP reachability and connection timing, not SS
credential validity, application readiness, ICMP latency or final-node proof.
Private endpoints and credentials must not appear in the public receipt.

## Required negative controls

The 28-verdict inventory includes each of the three transport cases and these
checks per case:

- Fifty original destination handshakes and the complete scored receipt.
- Rejection of an uncaptured candidate, outbound tag or endpoint, and of a
  lazy SS prefix as a destination-handshake timing capability.
- A legitimately recompiled changed SS credential source, retaining the same
  profile ID and catalog revision, invalidates the old result after one real
  connection. Restoring the old source cannot revive that capture.
- Replacing the retained prefix owner invalidates the result after one real
  connection; changing back cannot revive it.
- Cancellation while closing an actual native connection retains the original
  activity hold. A bounded close timeout cannot claim drain; releasing and
  joining that original close releases the hold once and publishes no score.
- A wrong live authenticated private node proof produces no candidate score.
- Closing the actual SS destination listener refuses the candidate connection
  and produces no partial or zero-valued score.
- Closing the retained encrypted prefix's UDP bind prevents a score and does
  not fall back to another prefix or an ambient connection.

The Linux native-host runner executes this witness before its separate
installed namespace/TUN scenarios and records its output digest. Missing,
duplicated, skipped, failed, panicking or race-reporting verdicts fail the gate.

## Causal reference-fixture correction

The first execution of the listener-refusal control failed for all three
transport modes. The independent SS listener had been closed and accepted no
new connections, but the old reference handler still allowed fifty successful
virtual TCP handshakes and a scored receipt.

The cause was specific to the pinned reference forwarding adapter:
`desktopReferenceHandler.NewConnectionEx` called `SetDeadline` on a gVisor
`gLazyConn` before dialing its configured physical target. In the pinned
implementation, `gLazyConn.SetDeadline` calls `HandshakeContext`, so this
operation completed the virtual destination handshake before actual target
acceptance. It could therefore measure the forwarding stack alone.

The reference handler now attempts the exact target connection first and sets
the downstream deadline only after success. On target refusal, existing owned
cleanup closes the still-lazy connection, which rejects its pending handshake.
The echo-only branch retains its own immediate deadline. No production
candidate, WG/AWG, SS or system-network policy is weakened or changed.

This fixture uses TCP forwarding to connect an isolated virtual endpoint to
its original independent loopback listener. Its destination-handshake witness
therefore includes that reference forwarding mechanism. It establishes that
actual target acceptance precedes the successful virtual handshake in this
fixture; it does not claim that an arbitrary remote deployment has no
intermediate TCP-terminating proxies. The permanently required listener-loss
control rejects the premature-handshake behavior observed above.
