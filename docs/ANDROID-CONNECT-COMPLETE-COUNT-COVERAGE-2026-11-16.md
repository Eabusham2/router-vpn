# Android CONNECT complete-count coverage — 2026-11-16

This adds coverage to the Android CONNECT Server/Compare implementation already
published in `9ac3f3a6075b282f4ecc193d5bb016acfae78f43`. It does not replace that
implementation or its final-Start-Layer-Off product boundary. The tested base is
`a1a1bbea` and the two-test source snapshot is
`467a9791f6bf09fbf35638e9ac99e606c40c800b`.

The source/profile gate now exercises all total counts three through eight with
HTTP and HTTPS CONNECT. The added five-, six-, and seven-node cases keep the
original mixed WireGuard/AmneziaWG positions and independently selected prefix
layers. Every positive case checks the complete proof inventory: global position,
paired node/profile identity, original mode and Start Layer, and an empty private
Router identity only for the imported penultimate proxy. Existing profile
Add/Load/Update/Delete, original credential references, replacement invalidation,
member/identity readback, malformed inputs, final-layer refusal, and all nine
causal controls remain active.

The host fixture also exercises every supported count rather than only three,
four, and eight. Both HTTP and HTTPS fixtures run the shipping session, VPN
service, MTU bridge, cleanup, and retained-restoration code. The typed factory,
native-proof, and foreign-restore causal controls remain independent.

Validation of the frozen source snapshot
`467a9791f6bf09fbf35638e9ac99e606c40c800b`:

- Actual shared Go compiler plus shipping Java stores/editor/capture: **1,401
  checks and all nine causal controls passed**, 473.663 seconds total. Every
  original Go compile and individual Java process bound was retained.
- Shipping Java host/restoration: **1,570 checks and all three causal controls
  passed** (671 lifecycle plus 114 restore checks for each proxy transport).
- Android workflow contract: **30 tests passed**, 37.070 seconds.
- All 5,933 tracked files were unchanged during the source gate. The five
  production files `AndroidNodeChainCapture`, `AndroidNodeChainExecutionCapture`,
  `AndroidNodeStore`, `AndroidOrderedPathSelection`, and `ProductActivity` were
  independently compared byte-for-byte with published `9ac3f3a6` and matched.

The tests retain the existing 120-second Go helper build, 180-second Go fixture
generator, 60-second javac, and 120-second Java process limits. The helper compiler used one CPU; the immutable
helper runtime used two CPUs. Validation used Go 1.26.3 and JDK 17.

This is source/profile and shipping Java ownership evidence. The host fixture
explicitly doubles native handles and OS services. It is not APK, Android-device,
TUN, encrypted-traffic, native lease, or installed-kernel acceptance evidence.
The earlier unpublished Android draft is not used as proof for the published
implementation or this test-only change.
