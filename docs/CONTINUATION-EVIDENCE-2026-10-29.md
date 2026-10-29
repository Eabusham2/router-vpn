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
`f9c66253c9e0c5ecb909fad2a90df9f95167652f`. Concurrent unfinished changes were
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

## Subsequent published changes

These extend the same reconciled scope. A tested prerequisite below is not
an assertion that its complete shipping launcher or network path is admitted.

| Commit | Published change | Evidence and remaining boundary |
|---|---|---|
| [`2ca80607`](https://github.com/Eabusham2/router-vpn/commit/2ca806072c7f35914eba5648f013b26f725626fd) | Exercise real, uniquely created Wintun adapters, retained readers/LUIDs, exact WFP binding, stale-reader rejection and retirement. | Baseline and three broken protection variants compile for both Windows architectures. Native preparation initially stopped before adapter creation; the repair below preserves checksum authority. |
| [`f84b70e0`](https://github.com/Eabusham2/router-vpn/commit/f84b70e067b906c9e551653696daaa6fa956523c) | Identify original, returned and imported socket ALE/tuple failure stages without accepting a failed proof. | Both Windows architecture suites compile. Actual ARM bootstrap localized error 10022 to the original socket ALE readback; successful DNS/bootstrap is still unproved. |
| [`3826dbbf`](https://github.com/Eabusham2/router-vpn/commit/3826dbbf854c9460b22aa1224194b74b11d83202) | Reconstruct the Wintun reference from the exact pinned original Git module objects after prepared-graph tidy removes the upstream checksum. | Nine source tests pass, including replacement-object and missing-pin negatives. Actual reconstruction verifies 180 dependency files and four module records without repairing the prepared subject. |
| [`65e9f588`](https://github.com/Eabusham2/router-vpn/commit/65e9f588f9c604d848b5c99102d6307600b21495) | Recheck exact owner/context revocation after joining Windows pipe completion; isolate actual controller diagnostics in a preserved workflow. | Both architectures compile; actual Windows pending-read Close now passes. Failure-only stable-GUID launch diagnostics preserve exact image and child ownership; neither initial directory variant launched. |
| [`1e9c9dd1`](https://github.com/Eabusham2/router-vpn/commit/1e9c9dd11e3f61540f9a8fbbdc03764440b1f794) | Use the shipping ordinary-user Python selector in native Mac verification and exclude ambient site initialization from privileged helpers. | Six selector/diagnostic cases, 16 installer cases, six production mutants, ten Darwin dispatch cases, actual interpreter ownership negatives and both Darwin cross-compiles pass. A generated wrapper rejects a planted global site hook; removing only `-S` executes that hook. Actual native interpreter/supervisor verification remains required. |
| [`e1804ab2`](https://github.com/Eabusham2/router-vpn/commit/e1804ab2c976b4ba6d572fce9325e713ee984560) | Move Darwin registry and paired Go/AppKit supervisor socket authority below protected `/opt` paths. | Addresses actual root-owned mode-0775 `/private/var/run` rejection without relaxing ancestor, ACL, UID or link checks. Shared socket races and both Darwin architecture compiles pass. Subsequent actual ARM execution reaches PF parsing, exposing the separate syntax failure below. |
| [`b3656d30`](https://github.com/Eabusham2/router-vpn/commit/b3656d308eeb375102d5a6bea76a1678fb99b62b) | Run the complete retained-handle DACL test under a same-user derived primary token with only SeDebug removed. | Baseline and reopened-process mutant compile for both architectures. Actual Windows retained-handle case passes inside that worker; no parent privilege or production authorization change was made. Full foundation still fails its separate Shell launch cases. |
| [`71cdd2f7`](https://github.com/Eabusham2/router-vpn/commit/71cdd2f73900832bfde7ca912cb00eddb8ceb5c0) | Own ordinary-user probe workers with nested non-breakaway Jobs and require actual child membership before Resume. | Both architectures compile; 20 preparation checks pass. Actual basic WithToken launch still returns access denied before child creation. Ordinary-caller proof and both owner-death cases therefore remain unproved; no post-creation assignment or privilege grant is substituted. |
| [`1e843ac8`](https://github.com/Eabusham2/router-vpn/commit/1e843ac80ac4e048fbaf59e794db6401f6c2fa91) | Add in-memory pinned TLS tied to the retained controller process, exact identity/shutdown receipts and complete 32 MiB import requests. | Fourteen actual transport/shipping-handler race cases and eight compiled production mutants pass locally; both Windows architecture controller suites compile. Windows server/launcher wiring is separate unfinished work. |
| [`439b95de`](https://github.com/Eabusham2/router-vpn/commit/439b95def16b3b2c0e0461bca5b1609d87e4ae4c) | Add bounded GUI request framing, exact cancellation ownership, queued-response reclassification and joined forwarding. | Fifteen blocking-stream race cases and 14 compiled production mutants pass; both Windows architecture suites compile. Pipe peer authentication, C# consumer and installed/Portable composition require their own native evidence. |
| [`a3973649`](https://github.com/Eabusham2/router-vpn/commit/a3973649d4bc736d06e591c5e7229c66bd5b652e) | Retain the real process handle and explicit exit code in the protection dispatcher fixture. | All 22 real-child cases and 92 assertions pass locally. Missing-code and false-zero variants reach their intended rejections. This addresses the redirected Start-Process exit-code boundary without weakening expected denial; actual PS5.1 rerun remains required. |
| [`0ba18bf3`](https://github.com/Eabusham2/router-vpn/commit/0ba18bf35cff2f47d2312cdba920ab3a29869295) | Carry complete compiled ordinary-external physical tuples into native protection, preserving predecessor, DNS, Start Layers and restored execution selection. | The 189-case controller matrix and focused controller race suite pass in 14.230 seconds; final shared projection/rejection races pass in 6.134 seconds. Both Windows architecture controller compiles pass. Physically negotiated SOCKS UDP remains an explicit dynamic-socket gap; no relay port is invented. |
| [`ab356832`](https://github.com/Eabusham2/router-vpn/commit/ab3568321680a27112349abd351a47912140ef55) | Close the exact newly created Wintun adapter when StartSession fails, preserving the original error. | Twelve runner checks and all 184 pinned module/source records pass. Baseline and missing-Close test binaries compile for both architectures. The native fixture asks the actual driver for an invalid ring, checks adapter removal and control survival, and performs exact fallback cleanup even for the mutant. Actual driver execution remains pending. |
| [`7f1c6c5d`](https://github.com/Eabusham2/router-vpn/commit/7f1c6c5da436f5bb539ee9d6f502e62788d40034) | Diagnose retained-file-derived Windows Shell paths and actual probe file/station access. | Isolated controller and tagged WFP suites compile for both architectures. Diagnostics reject DOS-normalized PIDLs before execution and independently prove impersonation reversion. No permissions, privileges, production launch predicate or required test is loosened. |

## Continued transport and native repairs

| Commit | Published change | Evidence and remaining boundary |
|---|---|---|
| [`ca056061`](https://github.com/Eabusham2/router-vpn/commit/ca056061dca40caa4b356a3e11b29995e7f3a782) | Launch the GUI as the original user with its creation-time Job, retained child image/token and restricted inherited parent reference; join its binary pipe operations. | Fourteen real native cases and ten semantic variants are registered in both required Windows workflows; baseline and all variants compile on both architectures. Actual Windows reaches child cases but fails teardown with access denied, as recorded below. Shipping composition remains unfinished. |
| [`24315ca5`](https://github.com/Eabusham2/router-vpn/commit/24315ca5e5cdb8823f740b21769ab6bb3b47ca0f) | Emit `! tagged` in the Go and Python Darwin PF baselines and validate every generated variant with the real native parser. | Ten dispatcher and six runner checks pass; both Darwin tagged binaries compile. The native gate dry-runs production/scoped active/inactive/LAN variants, compares equivalent emitted rules, and requires the old malformed grammar to report its actual syntax error. Corrected native packet/lifecycle execution remains required. |
| [`3f862cf1`](https://github.com/Eabusham2/router-vpn/commit/3f862cf15f5f21adcc1a196b91793575488aa14c) | Require actual writable completion after pending Windows TCP Connect before SO_ERROR and exact-peer verification. | Ten repeated race runs and both architecture tagged compiles pass. Skipped completion, ignored socket error and wrong peer each fail their intended semantic check. Original/returned/imported ALE, token and application identity remain mandatory; no error 10022 retry or bypass is introduced. Corrected native bootstrap remains required. |
| [`058bb95c`](https://github.com/Eabusham2/router-vpn/commit/058bb95ce951691b353bc2e5f78c4ada59bc70e0) | Use object-mapped access for the fixture-owned Windows station and require a fresh captured-caller open. | Baseline and old file-mask defect compile on both architectures. Actual caller and ordinary-token station access now pass; WithToken process creation still returns access denied. The sixteen-case WFP gate retains eleven production and two fixture controls; production WFP permissions are unchanged. |
| [`739c0dc6`](https://github.com/Eabusham2/router-vpn/commit/739c0dc682fee2bcf16145ef85b44fdc4ffe4758) | Add the C# GUI consumer with bounded binary requests, captured deadlines, joined cancellation, shared-channel ownership and exception-safe native operation admission. | Seventeen actual cases and eleven semantic variants pass under PowerShell 7.6.9/.NET 10, with C# 5 compilation and production DLL loading. Required Windows workflows add the eighteenth real OVERLAPPED case under both shells and compile one Framework DLL for loading under both 5.1 and 7. No shipping UI call site is switched by this prerequisite alone. |
| [`9ae48336`](https://github.com/Eabusham2/router-vpn/commit/9ae483362e84e57ee0bb9556102133acb5f7e694) | Identify rejected macOS Python symbolic links with bounded quoted lexical/resolved targets, owner and resolution error. | Thirteen real ownership cases pass under race instrumentation in private namespaces, including escaping, dangling, cyclic, foreign-owned and long/control-character link diagnostics. Both Darwin tagged binaries compile. The rejection predicate, root containment, executable/library permissions and ACL checks are unchanged; actual CLT path diagnosis is pending the native rerun. |

## Fixed Direct and confirmed native boundary repairs

| Commit | Published change | Evidence and remaining boundary |
|---|---|---|
| [`5823f134`](https://github.com/Eabusham2/router-vpn/commit/5823f134da4aa1d819468d3f735cac3bf3ed4dab) | Diagnose an independently retained Windows DOS naming object before any alternative Shell launch. | Actual retained-link rebind is denied and the original target stays unchanged. Cross-account namespace and stable Shell launch remain unproved; no remappable pathname is adopted. |
| [`835403c1`](https://github.com/Eabusham2/router-vpn/commit/835403c1d9bc3d47771a2c7a81bfac8f805f55ae) and [`fdff2ec0`](https://github.com/Eabusham2/router-vpn/commit/fdff2ec056626e8a5f5353a08eaf99bb5db6f256) | Use PowerShell 5.1 CodeDOM compiler parameters, including their output path, without combining incompatible Add-Type switches. | Actual fdff Windows execution passes all 18 C# cases and 11 semantic mutants under each shell, then compiles one Framework DLL and loads that same file in both 5.1 and 7. No production C# guard was weakened. |
| [`8aaf11cf`](https://github.com/Eabusham2/router-vpn/commit/8aaf11cfac67cb55d0235b0c8ba6b96104fac692) and [`ee6ad6e5`](https://github.com/Eabusham2/router-vpn/commit/ee6ad6e5ddab3611c07e6a2e3a06987928b71116) | Diagnose primary-token handle rights with a held empty executable, then give only the fixture-owned copy the required adjustment access rights. | Same ordinary SID/logon/session: masks 0xb and 0xf return access denied; 0x18b reaches the expected invalid-executable error. Both architectures compile baseline and original-mask control. Actual ordinary-child execution remains required; no privilege, token-field or account-right change was introduced. |
| [`09c1841d`](https://github.com/Eabusham2/router-vpn/commit/09c1841d944ac9765a2ef7ecde4e279aa7760d1b) and [`e61b4bd5`](https://github.com/Eabusham2/router-vpn/commit/e61b4bd537d4fe850ef27173a8f7f560351c09f8) | Diagnose exact native PF readback, recognize only the observed stock normalization prefix, and bind short sibling PF generations to the complete session/source/network capture. | Actual Intel logs confirm both the stock scrub prefix and the old path's loader failure. Eleven Python dispatch cases, six runner cases and both Darwin tagged compiles pass. Full native slot/leaf loading, legacy-owner preservation and all packet/lifecycle mutants remain mandatory. No earlier nested owner is silently adopted. |
| [`b31d6634`](https://github.com/Eabusham2/router-vpn/commit/b31d663457f5537f710c361e46b5d8c92ef736ee) | Join the exact Windows GUI process after asynchronous Job termination, retaining access errors and ownership until exit is actually proved. | Actual native execution passes all fourteen other GUI cases, including restricted-handle error/cancellation/true join, Job retry, owner death, descendants and streams. The inheritance fixture fails separately on a reused numeric handle slot; no complete GUI gate is claimed. |
| [`276f00b4`](https://github.com/Eabusham2/router-vpn/commit/276f00b48e68f28307880ea926c7cd2e0ba9b149) | Route protected fixed Direct Tor through the captured Linux socket broker. Keep every fixed bridge in the hashed private profile while emitting no global endpoint, tuple or external-session launch authority. | Shared compiler races pass in 3.537 seconds; controller races in 6.567 seconds; prepared native Box/PT races in 1.143/1.049 seconds. All 36 Unix wrapper groups and 3,829 PowerShell wrapper assertions pass. Tests cover complete bridge sets, selected DNS, malformed/source-swapped projections, missing factories and network-generation teardown. Public Windows/Darwin admission remains unchanged; no public circuit or device acceptance is claimed. |
| [`f9c66253`](https://github.com/Eabusham2/router-vpn/commit/f9c66253c9e0c5ecb909fad2a90df9f95167652f) | Distinguish Windows numeric-handle reuse from actual GUI inheritance by round-tripping the owned Event through the exact retained child process before accepting absent/unsupported slot results. | Baseline and omitted-HANDLE_LIST production mutant compile for both architectures. The original observation precedes intentional control insertion; actual Event identity and exact remote cleanup remain mandatory. The complete native rerun remains required. |

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

At `65e9f588`,
[focused Windows job 123262208490](https://github.com/Eabusham2/router-vpn/actions/runs/40817589834/job/123262208490)
passes `CloseJoinsPendingKernelRead` and the existing cancellation/join cases.
Both stable-GUID executable launch diagnostics fail with Shell instance 5,
including the variant without a working directory. The complete gate fails.

At `71cdd2f7`,
[focused Windows job 123262914196](https://github.com/Eabusham2/router-vpn/actions/runs/40817770902/job/123262914196)
passes `RetainsGrantedLaunchHandle` both inside the reduced-privilege worker
and at its parent, and again passes the joined pending-read case. The stable
Shell launch remains unsuccessful; the ordinary-user probe returns access
denied at basic WithToken creation. No ordinary probe child executed in those
failed attempts, and no full foundation or WFP gate pass is claimed.

At `e1804ab2`,
[Apple Silicon kernel job 123262447241](https://github.com/Eabusham2/router-vpn/actions/runs/40817665679/job/123262447241)
passes the protected-path startup boundary and reaches the actual PF fixture.
PF rejects the generated baseline with `stdin:3: syntax error`. The workflow
fails; the syntax and subsequent packet/lifecycle cases remain to be resolved.

At `7f1c6c5d`, the real Wintun step passes on both
[AMD64 job 123266290445](https://github.com/Eabusham2/router-vpn/actions/runs/40818669793/job/123266290445)
and [ARM64 job 123266290221](https://github.com/Eabusham2/router-vpn/actions/runs/40818669793/job/123266290221).
Both execute actual driver failure and exact adapter cleanup, reject the
missing-Close defect, verify retained LUID and reader ownership for IPv4-only
and IPv4/IPv6 policies, and reject all three WFP tunnel defects. Their cleanup
readbacks prove the owned test adapters and permissions absent while the
independent control survives. The full jobs still fail the earlier bootstrap
TCP/ALE case; they predate `3f862cf1` and are not complete workflow passes.

At `058bb95c`,
[focused Windows job 123267560458](https://github.com/Eabusham2/router-vpn/actions/runs/40819222346/job/123267560458)
again passes all fourteen TLS cases/eight production controls and fifteen
blocking-stream bridge cases/fourteen production controls. The new GUI gate
executes child cases but fails exact-owner teardown with access denied; the
stream and captured-environment cases pass. The station repair is independently
observed: both captured caller and fresh ordinary token open the private
station successfully, and both read/execute the exact fixture file and directory.
WithToken creation still fails before the ordinary probe child executes, so
neither the GUI kernel nor complete WFP gate is accepted by this run.

At `058bb95c`, the complete prospective Windows bootstrap workflow succeeds on
[AMD64 job 123268286395](https://github.com/Eabusham2/router-vpn/actions/runs/40819222434/job/123268286395)
and [ARM64 job 123268286590](https://github.com/Eabusham2/router-vpn/actions/runs/40819222434/job/123268286590).
Both execute the compiled Box/factory/socket/WFP/selected-DNS composition,
reject the uncaptured and replaced-source/resolver paths, and repeat the real
Wintun baseline and four intended defects. This proves the repaired TCP
bootstrap under its explicitly isolated admission overlay. It does not prove
the unmodified shipping Windows gate, a Tor circuit, Connected or devices.

At `09c1841d`,
[Intel PF job 123270166721](https://github.com/Eabusham2/router-vpn/actions/runs/40820056595/job/123270166721)
passes actual production PF parsing, protected path authority, floating-state
retirement and inherited-channel ownership cases. Remaining kernel cases
reject the exact stock `scrub-anchor` prefix. Cleanup separately reports the
old long captured PF anchor's loader failure. These observations justify the
specific `e61b4bd5` repair; they do not prove its corrected native execution.

At `b31d6634`,
[Windows job 123271358873](https://github.com/Eabusham2/router-vpn/actions/runs/40820208050/job/123271358873)
passes fourteen GUI cases after the exact-process teardown repair. The sole
remaining GUI failure is the original excluded numeric slot returning Windows
error 50. The original-handle-list leak must still fail after `f9c66253` adds
its independently proved Event control. Other foundation/probe failures keep
the complete job unsuccessful.

At `fdff2ec0`,
[Windows job 123272536073](https://github.com/Eabusham2/router-vpn/actions/runs/40820789150/job/123272536073)
passes its complete C# transport step: all eighteen cases and eleven intentional
semantic defects under each shell, including actual OVERLAPPED I/O. A single
production DLL compiled with the Framework compiler is loaded under both
PowerShell 5.1 and 7. The overall job still fails its separate launcher, GUI
fixture and ordinary-probe steps. This is transport evidence, not installed or
Portable application acceptance.

At `5823f134`,
[ARM installed-controller job 123269250090](https://github.com/Eabusham2/router-vpn/actions/runs/40819770057/job/123269250090)
identifies the exact trusted-Python failure: the scanner walks the entire CLT
prefix and reaches the root-owned, dangling `usr/bin/crashlog` LLDB utility
link. This unrelated debugger file is outside the interpreter's runtime
closure; that closure still needs a source repair and its actual native gates.
Actual interpreter files, libraries, ancestors, symlinks and ACLs retain their
required trust checks.

## Concrete remaining implementation and evidence

- Finish unmodified shipping Windows compiler/native composition after the
  prospective bootstrap and real Wintun gates passed on both architectures.
  The passing prospective overlay is still not public feature admission.
- Complete installed and Portable Windows administrator/controller startup,
  private authenticated transport, original-user data identity, repeated launch
  and shutdown ownership, including distinct-account UAC.
- Complete ordinary/fixed Windows protection migration. Private Router and
  bounded ordinary-external handoffs now retain exact tuples; that alone does
  not replace the legacy global firewall-profile mechanism or implement
  physically negotiated SOCKS UDP through an owned per-socket broker.
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
