# Router VPN continuation evidence — October 29, 2026

This supplements [the reconciled requirements](REQUIREMENTS-RECONCILED.md)
and [the preceding evidence ledger](CONTINUATION-EVIDENCE-2026-10-28.md).
The original audit identifiers, C1–C7, later product corrections and live
acceptance requirements remain binding. Reconciliation is already complete;
this record does not replace the original sources or introduce a completion
percentage.

## Publication and scope

Each source change below was committed directly on the current `main` parent,
pushed without force and checked by a fresh remote reference read. The last
implementation head covered here is
`448ca1c55f45f18f83e3683ddc4cef51d892dc46`. Concurrent unfinished changes were
preserved when synchronizing the local tree.

| Commit | Published change | Evidence and remaining boundary |
|---|---|---|
| [`c6113e93`](https://github.com/Eabusham2/router-vpn/commit/c6113e93f55e09c7e2d9c1e44d366d69e2e0b69a) | Execute protection-absence checks as a fresh ordinary Windows primary-token process, retaining its private desktop and creation-time Job. | Both Windows architectures compile. The actual process-creation failure and later repair below remain part of this acceptance case; this commit alone did not prove ordinary-caller denial. |
| [`123d2d36`](https://github.com/Eabusham2/router-vpn/commit/123d2d366c4c8f14108c8f93b68bbf59a09bbb14) and [`6292194b`](https://github.com/Eabusham2/router-vpn/commit/6292194b62077845df3f5014329fd476458063cb) | Capture the actual Windows adapter, addresses, DHCP and policy owner in the native factory; carry owned protection through public lifecycle dispatch. | Both architectures compile. Local preparation/toolchain, wrapper and full dispatcher tests pass. Completed native identity and traffic steps are recorded below; public dynamic Direct admission remains closed. |
| [`0901baf0`](https://github.com/Eabusham2/router-vpn/commit/0901baf043050cffd79a2dbb3b1e7959bb90e12b) | Remove guessed Allow recovery for damaged legacy firewall state; retain exact recorded profile defaults until restoration and rule-absence readback succeed. | 26 cases, 32 real PowerShell child dispatches, 242 assertions and three rejected production defects. The authoritative durable-state audit passes. This is bounded legacy recovery, not completion of ordinary/fixed WFP migration. |
| [`5c04b1fb`](https://github.com/Eabusham2/router-vpn/commit/5c04b1fbee8fe4bef2bfcca88070496285ed5b03) | Select the first actual Go application on PATH in the Windows dispatcher fixture. | Reproduced the two-Go-installation failure, then passed 22 full dispatcher cases/70 assertions. Production process ownership and test assertions are unchanged. |
| [`9a072a8e`](https://github.com/Eabusham2/router-vpn/commit/9a072a8ebd776152d6ddf1046c13c024a4889a7a) and [`b5fa9f34`](https://github.com/Eabusham2/router-vpn/commit/b5fa9f34fbad79b5fe51be5e3664ac146f3422fb) | Diagnose rejected Windows probe creation against a held non-executable control, then use CreateProcessAsUserW with the same captured primary token, private desktop and atomic Job list. | Actual former API controls returned 87 for every extended-startup variant and 5 for basic startup, before any child ran. The replacement compiles for AMD64/ARM64. Its actual privilege/session result remains required; no privilege grant, weaker fallback or skipped assertion was added. |
| [`3a3fd09d`](https://github.com/Eabusham2/router-vpn/commit/3a3fd09d92e9fa0dc872a2132d86f6a305040a62) | Retain exact compiled Router-node physical tuples through native capture, Local/Server selection and MTU restoration; canonicalize derived WG/AWG IPv6 hosts. | All 19 graph families and three Start Layers retain their actual protocol sockets. Shared races pass in 6.069 seconds; controller capture/restoration races in 70.218 seconds. Saved credentials and endpoint ports are unchanged. |
| [`d9a099d6`](https://github.com/Eabusham2/router-vpn/commit/d9a099d61b8f65371de25956d1255899332c0b7c) | Pass captured private Router tuples into the Windows firewall helper, retain them after ENTRY/CONTROL environment replacement, and copy them into single-node Speed Lab restoration. | 48 compiled Local/Server combinations, invalid/stale/mixed-owner cases, 49.191-second combined races and a 4.290-second final focused race pass. Both lost-capture and shared-slice defects fail their intended assertions. Actual PowerShell rule-builder plans and 5.1 array emulation pass; final AMD64/ARM64 controller source compiles. Windows native/release scopes now execute the staging checks. Actual packaged kernel/device behavior is separate. |
| [`bcf95cf5`](https://github.com/Eabusham2/router-vpn/commit/bcf95cf58f81ca6c3ca475e69ee5a60bbafe9092) and [`c1ce840c`](https://github.com/Eabusham2/router-vpn/commit/c1ce840c5fb332f309820b19605341324c2c8222) | Add a prospective Windows compiler/Box/factory/socket/WFP/selected-DNS bootstrap diagnostic; normalize its source-ledger path labels on Windows. | Seven executable source/overlay checks and native toolchain checks pass. Both actual Windows architectures compile and reach the selected real DoH lookup, which currently fails. A harmless TUN fixture deliberately excludes actual tunnel and Tor-circuit claims. Full package builds also run the diagnostic. |
| [`ce234f93`](https://github.com/Eabusham2/router-vpn/commit/ce234f93a8e55bbd204b280e95953a07ed77f935) | Expose the underlying selected-DNS failure only in the bootstrap test overlay. | The same production failure branch retains its original error plus its cause. Resolver selection, socket guards, real response and public admission are unchanged. Native rerun is required. |
| [`e76f418a`](https://github.com/Eabusham2/router-vpn/commit/e76f418aa117dbc5bc33371d841566449e71c35e) | Add Windows controller foundation: pinned stable local-volume image, retained UAC process handle, authenticated private pipe, joined I/O and owned Job lifetime. | Both architectures and all 12 AMD64 production mutants compile. The native gate requires 20 cases and all 12 intended failure witnesses. Review repaired remappable DOS paths and elevated-process handle reopening. Installed/Portable launcher composition and distinct-user UAC token-query acceptance remain unfinished. |
| [`a97b505c`](https://github.com/Eabusham2/router-vpn/commit/a97b505c3a68a1a0a95a5d6e544f23e33b9570fd) and [`aa41749e`](https://github.com/Eabusham2/router-vpn/commit/aa41749ea9cb0ccae797a65ba66abcbc86e0ee1d) | Retain bounded outer and nested macOS controller diagnostics after owned child teardown. | Actual subprocess-output tests and tagged Darwin compilation pass. Diagnostics preserve assertions and joined output ownership; no native ownership pass is inferred. |
| [`f6f77985`](https://github.com/Eabusham2/router-vpn/commit/f6f7798560eafda760f37bf8d138478e10651a6e) | Replace the Darwin group-equals-wheel restriction with actual root ownership, mutation permissions, ACL and private-mode checks. | Real Intel execution exposed the overly strict group check before kernel cases. Both architectures compile; the native gate adds root-owned non-wheel positives and nine owner/mode/link/ACL negatives. Actual rerun remains required. |
| [`9cb023a2`](https://github.com/Eabusham2/router-vpn/commit/9cb023a23cb4f35dff3792725ed1b3f015a93d0e) and [`448ca1c5`](https://github.com/Eabusham2/router-vpn/commit/448ca1c55f45f18f83e3683ddc4cef51d892dc46) | Preserve active native diagnostics, then give each macOS matrix architecture its own pending queue. | Parsed workflow comparisons prove that only concurrency changed. Commands, runner matrices, deadlines, assertions and exact-SHA release obligations remain unchanged. |

## Actual native observations

At `6292194b`,
[Windows job 123233123568](https://github.com/Eabusham2/router-vpn/actions/runs/40808445397/job/123233123568)
completed 17 isolated-identity cases and 12 production mutants, the earlier
baseline/status cases, all four TCP/UDP IPv4/IPv6 traffic families, bounded
control expiry, retained-source-port cleanup, process-death cleanup, both
traffic mutants and 111 owned-protection PowerShell assertions. The ordinary
probe child failed before execution with error 87. The full dispatcher also
failed on the two-Go PATH fixture subsequently fixed in `5c04b1fb`.
That workflow failed; it is not a complete native acceptance.

At `aa41749e`,
[Windows job 123238481232](https://github.com/Eabusham2/router-vpn/actions/runs/40810102616/job/123238481232)
again completed the identity and traffic gates. Its probe parameter diagnostics
provided the concrete evidence described above. The WFP gate still failed.

At `c1ce840c`,
[Windows bootstrap run 40810962239](https://github.com/Eabusham2/router-vpn/actions/runs/40810962239)
compiled the prepared native Box on AMD64 and ARM64. Both reached the real
selected DNS request and failed with the production-redacted lookup error.
This does not establish DNS bootstrap, actual Wintun binding, Tor circuit,
Connected proof or device acceptance.

At `123d2d36`,
[macOS Intel job 123232276378](https://github.com/Eabusham2/router-vpn/actions/runs/40808267916/job/123232276378)
passed Cgo compilation after the earlier missing-header repair, then rejected
fixture startup and cleanup at the protected-path authority check. No kernel
test case passed in that attempt. `f6f77985` addresses that concrete boundary.
Queued or unallocated Apple Silicon/controller jobs are neither failures nor
passes.

## Concrete remaining implementation and evidence

- Finish the Windows dynamic bootstrap failure, real Wintun binding/retirement
  and unmodified admitted compiler/native composition. A prospective test
  overlay is not public feature admission.
- Complete installed and Portable Windows administrator/controller startup,
  private authenticated transport, original-user data identity, repeated launch
  and shutdown ownership, including distinct-account UAC.
- Complete ordinary/fixed Windows protection migration. The private Router
  handoff now uses exact tuples; that alone does not replace the legacy global
  firewall-profile mechanism or finish every ordinary external-node path.
- Resolve actual Intel/Apple Silicon kernel and installed-controller failures,
  execute every required native mutant, then validate the final unmodified
  Darwin compiler and shipping host composition before public admission.
- Preserve all other original requirement families and the preceding ledgers.
  Source, local tests, push, native build, package publication, deployment and
  physical acceptance remain distinct states.

No current all-platform release or private deployment is claimed. Physical
networking/leaks/transitions, off-LAN interoperability, real visual/accessibility
checks, private benchmarking/forwarding/management/updater/provider checks,
production signing/distribution and deliberate ASUS/Portainer deployment still
need their appropriate live evidence. No router, private deployment or signing
environment was changed for these commits.
