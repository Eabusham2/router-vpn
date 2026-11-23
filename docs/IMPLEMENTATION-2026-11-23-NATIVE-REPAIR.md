# Native repair and map follow-up — November 23, 2026

This change follows main `8124eb3b30653493ef61c87ca36709cfe28433bc` and the
failed native jobs from that generation. The requirements remain those in
[Current Requirements](CURRENT-REQUIREMENTS.md) and
[Reconciled Requirements](REQUIREMENTS-RECONCILED.md). Source implementation,
controlled executable checks, native platform execution, published packages
and installed-device acceptance have separate evidence.

## Application and runtime changes

| Area | Resulting behavior |
| --- | --- |
| Android map | A retired ordered session stops its packet animation immediately. Opt-in device location uses monotonic age, expires, rechecks permission and retires its callbacks when hidden or detached. Intermediate hops have position colors; custom nodes retain their outline; routes and moving packets wrap at the date line. The map draws the shared offline Natural Earth outlines and ships their original attribution. |
| Windows and Linux maps | Native cached land geometry, ocean boundaries and graticules use the existing node projection. Date-line routes and packets take the short path. Disconnect and captured-route retirement stop old packets before a later map refresh. Package verification requires the exact shared geometry and attribution. |
| iOS saved routes | Provider reopening binds an independently selected final Start Layer to its original saved credentials, including the paired Hysteria2 final path. Local, Server, Compare and captured candidate-prefix handoffs use the same check. |
| Darwin shutdown | Cancelling the native socket policy wakes its idle guardian immediately. Existing in-progress probes still finish through the original retirement path. |
| Naive engine lifetime | Stream accounting starts before native construction and ends at native termination. Client closure cancels late and already-published streams, joins concurrent close callers, drains admitted socket callbacks and DNS/relay workers, and checks native shutdown before destroying an engine. Failed shutdown retains the remaining handles for retry. The pinned upstream source and checksum verification still bound the derived module. |

## Native verification repairs

Windows ownership controls now run in four bounded groups. The WPF editor runs
in six groups with all 33 original negative witnesses required by its aggregate
validator. No individual test deadline is increased. Socket fixtures wait for
their original operations to settle before taking one strict WFP/kernel read;
the OpenVPN TCP rejection case observes the actual connected descriptor before
its rejected control-key handshake closes it.

Darwin Ready validation requires the parent plus all 20 binding/MTU leaves.
The HTTPS CONNECT retirement fixture distinguishes a clean real credential
refusal from a separately exercised native half-close error. Native command
tests are discovered from the compiled package and partitioned into disjoint
batches under the original race settings and execution deadlines. Failed native
test diagnostics retain the initial fault site as well as the process tail.
Native fatal output is retained even when the process cannot emit a final
per-test verdict. Three older source assertions that required the Android wall
clock now require its monotonic animation clock and current-session guard.

The Android geography test runs independently in the authoritative runtime
shards and the relevant pull-request workflow. APK delivery validation compares
both map assets byte-for-byte with the release source.

## Evidence available before the hosted release run

- Android checks exercised the shipping map and session code through controlled
  Canvas/location boundaries, including complete 9- and 96-node paths,
  retirement, location expiry and date-line traversal. Both map classes compiled
  against Android API 36. AAPT2 packaged the exact geometry and attribution.
- The shipping Windows editor callbacks passed in PowerShell Core on Linux,
  including all six positive groups and 33 negative witnesses. The separate
  profile fixture passed 5,064 checks. The production WFP policy and observer
  compiled for Windows AMD64 and ARM64.
- Swift/Go capture checks exercised saved-layer substitution, provider handoff
  and candidate-prefix rejection. Darwin tagged packages cross-compiled; a
  controlled Go race test exercised the production guardian wakeup.
- Twelve Naive policy tests passed, including eight race-enabled runs of nine
  compiled pinned-client lifecycle tests and ten causal negative controls. The
  native symbol results were controlled; these tests did not transmit encrypted
  traffic through the actual Cronet library. The transformed production package
  compiled for Linux AMD64 with CGO and Darwin AMD64/ARM64 with purego.
- Native delivery/signing boundary checks passed 5,219 assertions. The combined
  map, release materialization, Compose, Windows gate, Darwin phase and recovered
  requirement checks passed. These are not substitutes for native release jobs.
- The composed Linux GTK app and native Cairo fixture compiled. Controlled
  rendering checked inland and water positions, both map sizes, short route
  segments and seven local owner-retirement cases. Windows' composed geometry,
  packet and cancellation functions passed in PowerShell Core. Its native
  WPF bitmap checks are required in the hosted workflow. Both desktop archive
  formats reject missing, changed, ambiguous or oversized map assets.

The broad local Go run was not green: physical-interface inventory was denied
in this workspace, and two large packages reached their cumulative ten-minute
timeouts. The interrupted leaves passed individually. Diagnostic overlays
confirmed that ambiguous observer/child-cleanup failures occurred before any
observer or child was acquired because physical-network capture was denied.

## Release and acceptance

The authoritative [build-all workflow](../.github/workflows/build-all.yml)
must produce and verify packages, manifests, ARM64 images and production Compose
for the same complete source SHA. Real Windows WFP/WPF, Darwin native execution,
encrypted Naive H2/H3 traffic and the prior Linux ARM64 crash outcome still
require that run. [Live release evidence](LIVE-RELEASE-EVIDENCE.md) continues to
track installed-device routing, leak protection, off-LAN interoperability,
applicable signing and deployment acceptance. This record does not establish
those outcomes or expand the currently implemented multihop route families.
