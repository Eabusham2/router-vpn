# November 25 native client and Setup Center repairs

## Product behavior

- **iOS multihop editor.** Selecting an imported Shadowsocks exit keeps the paired WireGuard entry selectable. The map editor retains the node order, the entry for Home DNS, and the imported public exit. [Reconciled UI requirements](CURRENT-REQUIREMENTS.md)
- **Verified onboarding.** The guide can restart from step one when browser storage is corrupt or unavailable. Restart discards pending checks. When two checks overlap, only the newest request can update its result. Browsers with checks saved before response validation repeat verification once and retain their Full Guide step. Setup Center distinguishes zero observed peers, missing peer coverage and an unknown deployed revision.
- **Candidate measurement.** Desktop skips duplicate prefix members before reading their private files. Suffix collisions retain the original execution-eligibility rule, and independent sources are checked after file capture. Launch input can be reused only after graph ownership, mutable members, physical path, DNS, projection and digest checks. Raw and desktop physical graphs retain separate inputs.

## Verification

| Area | Observed evidence |
| --- | --- |
| iOS entry and exit selection | The compiled Swift editor model and final-picker callback passed 363 checks and rejected six deliberately changed implementations on Linux. The shipping view parsed. The separate candidate-base compilation reached its 90-second limit. |
| Setup Center | The composed scripts passed 28 malformed-reply cases, eight invalid status or coverage cases, empty and populated responses, storage failures and restart. The guide, release-status and authenticated proxy tests passed. |
| macOS installer | An executable change at the same path still blocks installation. After an unrelated host process changes, the fixture may make one fresh observation with the original files and children. It must reject the same owned child. Linux tests passed 90 cases and rejected 36 deliberately introduced defects. |
| Windows and macOS networking fixtures | Windows prepares the independent executable before either bounded peer starts. Darwin stages the native fixture image with bounded memory. The Windows helper cross-compiled for x64 and ARM64. Firewall behavior still needs native execution. |
| Desktop release checks | Darwin retains six baseline packages and 47 controls split 24/23. Limits remain 120 seconds per test, 600 per process and 1,800 per phase. All 19 runner tests passed. Four workflows now run once per main push through the release workflow, retaining all 21 required jobs and their pull-request and manual entry points. |
| Original ownership refusals | `go vet ./internal/mobilemultihop` passed. Nine complete ownership roots and the five affected OpenVPN subcases passed with the race detector. The test helpers preserve aliased owners while creating fresh synchronization primitives. |
| Native toolchain and project audits | Across the initial run and a rerun of nine tests with Go 1.26.3, 74 passed and one was skipped. The release-orchestration and reconciled-project-contract audits both passed. |

On Linux/amd64 with Go 1.26.3, all nine original selected private-response cases passed together in 21.86 seconds without the race detector, within the 120-second limit. This focused build included all production code and the 326 fixtures and initializers needed by the test. It omitted unrelated test declarations from the full package test binary. [Controller regression test](../cmd/client/desktop_selected_private_response_http_test.go)

In the corresponding focused Linux build with the race detector enabled, all nine original cases passed individually. The production changes are committed as `164ee84bd`. The slowest case took 30.62 seconds. The combined run reached the 120-second limit during case four (120.897 seconds elapsed). The earlier Windows run at `8cbd5708` reached that limit during case nine. Ownership and physical-envelope checks passed, as did 28 additional candidate metadata, source and session mutation cases with the race detector. Removing the digest binding in a test copy made the physical source accept the wrong graph and the test correctly failed.

On November 25, the native Windows amd64 diagnostic at `7d86b5ccd` passed all 18 connected controller roots and 91 required verdicts with race detection. The original private-response root completed all nine cases in 115.16 seconds under its 120-second limit. The controller source-input digest matched at `9cda43e30`. Release publication still requires the full gate set on the commit being published. [Windows receipt and transcripts](evidence/windows-selected-controller-2026-11-25/README.md)

## Native follow-up repairs

The `9cda43e30` release run exposed two additional failures. The Windows Xray bootstrap reached its 90-second aggregate limit during the sixth case's expected post-retirement refusal. Four earlier authenticated transfers had each waited about five seconds for cold REALITY detection. Commit `86e0272f4` uses the existing pinned detector observer at startup, with the original source inventory, race flags, child process/configuration checks and Windows compiler ownership. It retains all nine traffic cases and the 90-second limit and records each stage's elapsed time. Fifty ordinary source-authority, phase, scoped-reference and dependency tests passed. A hosted Windows rerun must establish the complete matrix's timing.

The Naive HTTP/2 native traffic test crashed during stream startup in its owner-close case. Source review identified request-header storage passed through integer addresses without pinning. Commit `67bac88cf` pins the enclosing header array, record backing and each NUL-terminated key/value before address conversion, then unpins after the native call returns. This follows the call-scoped storage lifetime in the pinned module's Cgo wrapper and leaves engine and stream shutdown behavior intact. All 31 existing checks passed, including the patched Go client race suite and ten ownership controls. The original native HTTP/2 traffic job remains mandatory on the release commit.

## Remaining acceptance

The ordered external-final constructor covers Local routes of 3–96 members with a paired WireGuard entry, literal-address imported Shadowsocks 2022 interiors and exit, and Start Layer Off. Broader imported-final combinations, including AWG entries, other imported protocols, additional Start Layers and Server or Compare execution, remain outside this family. [Ordered external exits and their verification](IMPLEMENTATION-2026-11-25-EXTERNAL-FINAL-AND-SERVER-RESPONSES.md)

The resulting commit requires hosted native compilation and encrypted-path checks, matching client packages and checksums, ARM64 images, and generated production Compose. Installed-device rendering, iOS signing and provisioning, off-LAN routing and DNS, kill-switch and network transitions, and private deployment still need direct evidence. [Release and live acceptance criteria](LIVE-RELEASE-EVIDENCE.md)
