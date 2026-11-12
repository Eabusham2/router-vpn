# Apple retained candidate session and Performance view — 2026-11-12

This unit wires the previously tested catalog/capture/receipt components to the
original PacketTunnel NodeChain and the Performance view. It does not save or
activate another route; next-connection proposal adoption remains a follow-up.

## Ownership and cleanup

The extension registers one original plan/server/source owner before invoking the
actual generated `LibboxRouterNodeChainNewCandidateMeasurement` factory. The
catalog callback checks the original engine generation, plan/server references,
and live protected catalog/request-file bytes and replacement identities. Info
reads the retained plan's existing LaunchInput through the shipping capture
parser; it does not create another plan or WireGuard runtime.

Factory failures retain the exact cleanup arguments even when no handle returns.
Native close failure retains that owner. Cancellation before Open leaves a
registry tombstone so a late provider message cannot start work. Operations use
nonblocking admission to the per-session lock: repeated Close messages do not
queue behind a pending factory or callback. Exact native close acknowledgments
are also published to the protected app group, allowing the app to recover from
a lost provider reply. Those files contain no timing or private source. Bounded
receipt storage refuses capacity exhaustion rather than discarding another
pending owner's only recovery evidence. The app consumes acknowledged receipts.

Original NodeChain teardown invalidates and joins candidates alongside existing
proof, throughput and DNS owners. Failed joins continue through the existing
retained teardown gate. A stale cleanup cannot unlink a replacement request file
or retire another factory slot.

## Performance behavior

The app offers only the active original WG/AWG packet prefixes, then captures all
actual saved sources and compiles eligible candidates once. It holds the parent
MTU lease through native work, displayed results, cancellation and actual close.
Each result requires all fifty TCP connections and exact source/prefix/request
receipts. Valid rows sort by the 10% trimmed mean. Unsupported, failed, changed
and expired rows have no score. Fixed 120-second native expiry is never renewed.
The app polls native status while results are visible, preserving native
reader/proof freshness as well as live store checks. Selecting another prefix
invalidates the operation; other Performance actions cannot overlap it.

## Verification and boundary

- Real-file catalog/commit controls and two causal variants passed.
- Actual shipping Swift/shared-Go source and receipt cases passed (46 checks),
  including paired/imported sources for all three ciphers and two causal variants.
- Actual session/registry and engine request method passed original owner,
  failed factory, repeated failed close, cancel-before-open, late returned handle,
  nonqueued close, source mutation and exact durable recovery controls. Two causal
  variants fail when original owner checking or failed-factory cleanup is removed.
- Shipping async transaction passed foreign epoch, source mutation, cancellation
  after a late reply, repeated failed closes and lost-IPC recovery. Removing its
  exact epoch/owner comparison fails the causal control.
- The complete shipping app controller typechecks under Swift 6 with OS/store/UI
  declarations substituted; the SwiftUI source parses. Generated ObjC callback,
  factory, handle and scoped-cleanup signatures were checked against the actual
  gobind output. The original NodeChain has no Metadata method; Info uses its
  real LaunchInput API.
- The complete engine compiles with actual candidate session/publication source.
  Its existing ordered teardown suite passed 30 lifecycle checks and all three
  original causal variants, plus existing proof-cancellation and ordered
  measurement-delivery checks.

All four candidate test scripts are mandatory in the existing Apple shipping
runtime-contract gate. Linux execution doubles the Apple SDK/native-handle
boundaries and uses the existing OpenSSL SHA256 shim. These results do not claim
signed iOS NetworkExtension, actual mobile TUN traffic, or Apple SwiftUI SDK build
acceptance; those remain hosted build/native gates.
