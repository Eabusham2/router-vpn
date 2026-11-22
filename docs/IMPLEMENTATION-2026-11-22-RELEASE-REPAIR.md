# Native release repair and verification — November 22, 2026

This change repairs failures observed on source commit
`6498bd53054ed7d733eb5a5694d00a06e2702b2f`. Its
[authoritative Build all run](https://github.com/Eabusham2/router-vpn/actions/runs/45005915700)
finished with 64 successful jobs, 11 failures, one cancellation and 44 skipped
jobs. Release publication was skipped. The most recent published prerelease
when this repair was prepared still targeted
`745b3e41e5a78d734391976af9b7cd0637660a0b`; that release is not evidence for
this change.

## Repairs

| Boundary | Observed failure and change |
| --- | --- |
| Windows isolated native account | Native source shutdown could block in `NetUserSetInfo` even though preparation had already disabled the account. After independent native readback verifies the same SID and ownership comment, an already-disabled account now needs no second write. Enabled accounts still follow the original write and readback path. Account removal, absence verification, retained ownership after failure and shutdown deadlines are preserved. |
| Windows account regression | The native test retains the real account reader and original cleanup API, but removes the setter only from a local API copy. Repeated quarantine must not call it. Foreign SID/comment inputs must still fail. The causal control accepts only the exact setter call site; unrelated crashes, races, skips, timeouts and failed test-owned recovery cannot satisfy the evidence parser. |
| Windows candidate heartbeat fixture | The fixture used pathname `os.Rename`, which failed while a Windows reader held the previous heartbeat. It now uses the retained directory's `Root.OpenFile` and `Root.Rename`, matching the shipping parent publisher. The immutable source, file identity and live-pulse checks remain required. |
| Darwin CONNECT startup fixture | The shared mailbox-refusal test demanded the ordinary packet-policy field even for a typed CONNECT owner. It now checks the exact retained physical policy and requires exclusive policy ownership, while preserving the no-resource retirement and joined native-owner checks. |
| Windows Hysteria2 Start Layer evidence | A valid benchmark can retain one SS2022 association for all fifty requests. The former test incorrectly required a new association during the benchmark. The peer now counts each successful native SS2022 packet authentication separately. Fresh raw, authenticated and forwarded packet counters, original layer mode/private destination, actual TLS/DNS requests and credential refusals remain required. |
| Windows OpenVPN entry lifecycle | On ARM64, the successor case inherited almost all of a 180-second alarm already spent on earlier starts. Each original entry lifecycle leaf now runs against the same immutable binary with its own unchanged 180-second alarm. Exact leaf inventory, refusal families, causal controls and result validation are retained. |
| Native compiler identity | Imported-trio and physical-controller gates could find an older bootstrap `go` on PATH, then disable automatic toolchain selection before resolving the pinned compiler. They now share the existing exact compiler-identity capture: select Go 1.26.3, verify its root and native host, and bind compilation and `test2json` to that executable before switching to local-only toolchain mode. |
| Android ABI contract | A stale opaque digest rejected the legitimate paginated candidate metadata method. The contract now checks the complete explicit set of nineteen candidate signatures, including `metadataPage(int)`, and separately checks each typed execution factory. Missing, mistyped, duplicate and foreign-owner signatures are rejected. |
| Mobile Go suite scheduling | The growing shared/native suites exhausted a package-wide alarm before later independent tests began. The runner compiles the actual original package once, discovers every selected root from that binary, and validates the actual `test2json` result with independent original alarms. The nine expensive typed-suffix trials are partitioned by whole protocol branch; an exact complement retains every other and future branch, and the combined receipts must contain the complete required inventory without duplication. Android/iOS tags, race settings, linker flags, package selection and product operation deadlines remain unchanged. Other shared packages still execute unfiltered. Preparation digests and Gradle inputs include the runner and its regression. |
| Swift native capture fixtures | Test bridges omitted newly shipping extended-node metadata and private-JSON validation. They now call the actual Go implementation for those operations and compile the shipping receipt/validation sources. The existing independent imported-prefix path is tested through its own selector. |
| Windows profile mutation fixture | The ordered-source adversary now mutates the actual selected fixture profile, so it reaches the shipping ownership rejection instead of a stale lookup. |
| Darwin first-grant diagnosis | The Intel PF failure did not reveal whether its shared caller deadline expired before or after the guardian completed the grant. The existing private, nonblocking fixture observer now records the first Off grant's phase and durations; the caller records its own elapsed time and context error. This changes no PF decision, privilege, permission, connection deadline or production output stream. |

## Verification before the source update

- All 34 combined recovered-requirement, native UI, map-first, profile,
  transaction, household-safety, download-retention and release-orchestration
  audits passed. The orchestration audit also executed its required nested
  publication, provenance and source-safety checks. These are source and
  composition results, not a percentage of the user's requirements completed.
- The Windows identity driver passed 27 cases. The changed native identity
  package compiled for Windows amd64 and arm64 with pointer checking enabled.
  Independent review verified that the new early return follows actual native
  SID/comment/disabled-state readback, and that final account removal still
  requires the original identity.
- The native selected-candidate runner passed eight driver cases. The Darwin
  lifecycle runner passed seventeen cases. The actual extracted startup and
  retirement fixtures passed their original baseline and causal controls.
- The Windows physical orchestrator passed all 83 tests, including actual Go
  test filters and complete result validation. A separate exact-inventory
  check compared the partitioned OpenVPN entry leaves with an unfiltered
  compiled fixture.
- The real SS2022 UDP layer peer passed retained-association datagrams for AES
  and AES with XOR whitening, plus wrong-key, wrong-destination and
  wrong-whitening controls. This is peer evidence; it does not replace WFP
  enforcement on Windows.
- Pinned compiler-selection runners passed their 13, eight and five cases.
  Android workflow validation passed all 34 cases, and the existing actual
  AAR guard passed 62 boundary cases.
- Swift fixtures invoked the real Go compiler/validator: typed CONNECT passed
  1,747 checks and six controls; ordinary CONNECT passed 1,206 checks and three
  controls; SOCKS passed 636 checks and three controls; the ordinary host
  passed 153 checks and five controls. OpenVPN passed 576 checks and imported
  Shadowsocks passed 783, each with four original-capture controls.
- The mobile grouped runner passed its real compiled test-inventory fixture
  and negative controls, and the existing source-group runner passed all 23
  checks. All 35 roots in the actual prepared Android native chain selection
  passed, with 156 distinct passing root/descendant results and zero skips.
  The former eight-hop HTTPS timeout passed in 16.33 seconds. The previously
  timed-out shared independent-final-layer root also passed all nine exact
  subcases with its original individual budget. The complete shared wildcard
  suite remains a separate release gate.
- Darwin readback baseline and causal checks passed, and the tagged package
  compiled for both Darwin architectures. Native PF execution remains a
  hosted Darwin check.
- `git diff --check` passed.

## Acceptance still required

The exact new main commit must pass the hosted Windows, macOS, Linux, Android
and Apple build/runtime gates and the authoritative package/image/compose
publication chain. A cross-compile or source fixture does not prove an actual
Windows WFP/account lifecycle, macOS PF/utun lifecycle, rendered WPF/AppKit
interface, or mobile-device tunnel. The previous lost-runner annotations do
not establish a resolved runtime cause.

Source inspection also confirms that the generated Darwin child test installs
the shipping full-host PF baseline inside the same hosted VM as the Actions
runner. Its deliberate fail-closed retention can block that runner's network
control channel if verified cleanup is unavailable. This is an observability
and isolation issue to resolve, not proof of the exact historical disconnect.
A weaker shipping firewall or an artificial Actions-network permission would
not establish the original full-host safety behavior.

Longer Server/Compare paths and still-unimplemented protocol combinations
remain part of the requested work. The existing qualified longer Local
capability does not waive them. Experimental evidence is not presented as
available UI behavior.

The separate [live acceptance gates](LIVE-RELEASE-EVIDENCE.md) still require
actual installed-device, off-LAN, visual, private-server/provider, applicable
Apple provisioning, production deployment and ASUS fail-open evidence tied to
the released source. No release-success or physical-acceptance assertion is
made by this source repair record.
