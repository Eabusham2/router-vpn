# Android SOCKS complete-count coverage — 2026-11-16

This extends the tests for the Android SOCKS Server/Compare implementation
published in `9ff381aa543b9509fb13e7aa80c70583472e5e73`. It does not duplicate or
replace that implementation. The tested base is
`462b1c49674386f93208fa520f9ac01b5571d42f`, and the frozen two-test snapshot is
`d906cadc9a3650fc6df3766b0ceefad25c6269d4`.

The source/profile gate retains every published phase, profile
Add/Load/Update/Delete case, final-layer replacement case, malformed-source
refusal, and all five original causal controls. It adds the missing five-, six-,
and seven-node paths, so all total counts three through eight exercise Server and
Compare with mixed WireGuard/AmneziaWG prefixes. Every positive path checks every
original global proof position, paired node/profile identity, selected mode and
Start Layer. Only the imported penultimate SOCKS node has an empty private Router
identity. The source checks also pin the original SOCKS5 credentials, TCP
predecessor and final detour, and the absence of CONNECT-style UDP-over-TCP.

Both AES-256-GCM and AES-256-GCM plus XOR final layers are exercised for every
count and requested execution, alongside the original Off cases. The tests keep
the published layered profile CRUD and invalidation checks. Two additional
compiled controls restore an Off-only preview or capture guard and must fail at
the corresponding real public Save or launch-capture witness. They protect the
existing independent final-layer capability; no new production restriction is
introduced. The shipping Java host/session and retained-restoration fixture also
now covers every count three through eight.

Validation of the frozen snapshot:

- The fresh shipping Java stores, editor and capture classes passed **2,048
  actual source/compiler checks across 25 baseline phases and all seven compiled
  causal controls**, in **614.517 seconds**. All 5,949 tracked files remained
  unchanged during this run.
- This run explicitly reused the previously compiled actual Go source helper
  and generated private fixtures. All 1,395 shared Go/module inputs and the
  helper generator source matched their retained source records byte-for-byte.
  The helper SHA-256 is
  `e921803be514065d859e774eb0d0f64b13ed08f805d055af0cf34cb0e0191ec6`;
  the fixture SHA-256 is
  `669efda0f5d45822621ed1effde84eccdbc9d9db8921471c9f1fe5641a38301c`.
  This is not a new Go compile or a newly timed full cold invocation.
- The independent shipping Java host/restoration gate passed **785 checks and
  all three causal controls**: 671 lifecycle checks and 114 retained-restoration
  checks. Native handles and OS services remain explicit fixture boundaries.
- All five production files (`AndroidNodeChainCapture`,
  `AndroidNodeChainExecutionCapture`, `AndroidNodeStore`,
  `AndroidOrderedPathSelection`, and `ProductActivity`) remain byte-identical to
  published `9ff381aa`. This change modifies tests and this evidence document
  only.

The original bounds remain unchanged: the actual helper build has 120 seconds,
fixture generation has 180 seconds, javac has 60 seconds, and every Java phase
has 120 seconds. `test_android_connection_profiles.py` calls the ordered family
directly, without a 300- or 600-second outer subprocess limit. The dedicated
`android_socks_source` job in `android-multihop-contract.yml` has the existing
15-minute (900-second) job limit and invokes the source script directly, without
a shorter step limit. The 614.517-second retained-helper replay is below that
limit; it does not establish the elapsed time of checkout, dependency setup and
a cold helper/fixture build. The release and combined-runtime callers have no
shorter explicit source-script timeout. `test_android_runtime_contract.py` also
has no per-script timeout; its later 300-second subprocess bound belongs to the
separate generated SS-service host gate.

The historical manual `finish-mtu-graph-contract.yml` had a 15-minute job
limit, but first requires exact older source/document blob hashes before its
large runtime aggregate. Those reviewed hashes no longer match this source;
that workflow was not a runnable acceptance route for this change. It was
retired after its completed integration was verified; the current regression
callers and their budgets are retained. See [repository maintenance](REPOSITORY-MAINTENANCE.md).

This is source/profile and shipping Java ownership evidence. It is not APK,
Android-device, TUN, encrypted-traffic, native lease, or installed-kernel
acceptance. The unpublished superseded Android feature draft is not substituted
for the exact published production classes tested here.
