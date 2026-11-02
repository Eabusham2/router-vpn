# Router VPN continuation evidence — November 2, 2026 UTC

This continues [November 1](CONTINUATION-EVIDENCE-2026-11-01.md) and preserves
[the reconciled requirement authority](REQUIREMENTS-RECONCILED.md). Original
source recovery is complete for the recorded collection; continue the actual
implementation without replacing the original scope with this status record.
The independently read-back published source cutoff is
[`f2e750aa458050106a9b7f509e2f08bba5580c8e`](https://github.com/Eabusham2/router-vpn/commit/f2e750aa458050106a9b7f509e2f08bba5580c8e).
Later working files are outside this cutoff. No complete current release,
private deployment, signing or physical-device acceptance is established.

## Latest implementation and verification — through f2e750aa

The published source cutoff has Git tree `6491966010fba12b67ecae81b6a5b7fe54071cac`. The WireGuard
feature unit is `a276af2c2c3bcd760eec41bb40732adc04af8f64`, tree `c10beb4ace20bdfb7a809088613e95df239d0d43`.
The Linux budget unit `09f4dce1` has tree
`20125ec4ea7f3f41275d1ba7553b168da7386895`; the QPC unit `8e5a8b57` has tree
`cbfb497ee9f0b76caf0875d9f9cbe776e1777c19`. These changes preserve normal
ancestry on main. Earlier sections below keep their dated observations;
their old active-gap wording is historical where this section supersedes it.

| Commit | Implemented result and verification boundary |
|---|---|
| [6cff6226](https://github.com/Eabusham2/router-vpn/commit/6cff622696189c4d5d44b19605bf5613c837b0a0) | Canonicalize only newly created Tor/private-store fixture directories so the macOS `/var` alias cannot invalidate a positive comparison or mask a private-file negative. The original 409 refusal was reproduced using a symlinked Go test root; the same actual comparison, Tor predecessor and private-store groups then pass under race. Production symlink/private-store validation is unchanged. |
| [ed8640dd](https://github.com/Eabusham2/router-vpn/commit/ed8640ddad5b0a4af38a6a31af96539c23fbde9d) | Add fixed MTU phase and numeric-owner diagnostics, with a controlled log-only native overlay only after the original receipt failure and acknowledged namespace join. Preserve the original failed verdict, source/image identity, cleanup and all original deadlines. Seventeen runner checks and the actual diagnostic command compilation pass. This adds evidence; it does not waive receipt validation or prove the missing active receipt repaired. |
| [ae43c489](https://github.com/Eabusham2/router-vpn/commit/ae43c4898bbd803557299011acf53935fbc45142) | Preserve a safe fixed public-probe failure stage when an exact-50 benchmark is incomplete. Dial/deadline/TLS/response/cleanup remain distinguishable without raw native errors or private inputs. Actual TLS/race measurement tests include six stage/privacy cases, 49-of-50 refusal, stale ownership, cancellation, transferred-byte statistics and complete 50-sample benchmarks. The newest Windows logs report the combined duration/owner failure from after response validation; exact elapsed time, cause and actual native repair remain unproved. |
| [bd3df93c](https://github.com/Eabusham2/router-vpn/commit/bd3df93c3828ac03395acef80bbff69282cb369f) | Recheck the exact captured Stop or parent cancellation after heartbeat receipt readback is interrupted during shutdown. The old shipping loop failure was reproduced deterministically; the repair passes 20 race repetitions and all existing NodeMTU cases. Foreign session/config Stop, unrelated cancellation and malformed proof remain failures. The exact-SHA generated TUN CI also passes all six cases on both architectures below. |
| [a276af2c](https://github.com/Eabusham2/router-vpn/commit/a276af2c2c3bcd760eec41bb40732adc04af8f64) | Admit retained Linux direct Local ordinary WG with Start Layer Off and On-connect/Always protection, through public Connect, Speed Lab and complete Router restoration. Preserve the one captured UDP endpoint, separate WG keys/PSK/AllowedIPs/MTU/keepalive, selected UDP DNS, real HTTPS proof and sole native session owner. Real traffic exposed and repaired eager startup ordering using a WG-only authenticated lower-socket phase; full proof/TUN readiness is unchanged. The actual encrypted five-family suite, current native command checks, separate kernel evidence and corrected installed peer compilation are described below. |
| [8e5a8b57](https://github.com/Eabusham2/router-vpn/commit/8e5a8b57e47a4c90f173559f8c9773773d118b0b) | Use genuine Windows QueryPerformanceCounter ticks with the cached native frequency for short public-response intervals. Subtract integer ticks before conversion and reject unavailable, zero, backward or mismatched clock data. Preserve TLS/bytes, current ownership, cancellation, timing boundaries and all 50 samples; split duration-invalid from owner-changed diagnostics. The full shared measurement race suite passes in 6.898 seconds and Windows AMD64/ARM64 checkptr test compilations pass. Native Windows success is still pending; the earlier logs did not record an exact zero duration. |
| [09f4dce1](https://github.com/Eabusham2/router-vpn/commit/09f4dce10702d945c3f03db6b7a7591502a0473d) | Published `09f4dce1` gives the complete Linux source gate 1,800 seconds, preserving serial execution, all 19 baseline suites and 48 compiled controls, every individual deadline and every required verdict. Windows keeps its 1,200-second source-gate bound. The two-test regression passes in 86.182 seconds across six targets and injected failure/timeout propagation; a new complete native gate result remains required. |
| [f2e750aa](https://github.com/Eabusham2/router-vpn/commit/f2e750aa458050106a9b7f509e2f08bba5580c8e) | Give `native-node-composition` and `native-node-kernel` Windows diagnostic jobs 30-minute aggregate budgets after all four 20-minute jobs were cancelled during compiled controls. Preserve every baseline/control, each individual compiler/test deadline and existing prerequisite step limit. Thirteen existing workflow contract tests pass in 0.037 seconds. Completed native jobs are still required. |

### WireGuard source, encrypted traffic and ownership evidence

The original positive failed before any encrypted packet reached its owned
peer. The real endpoint attempted the saved 25-second keepalive during native
startup, when the lower object correctly denied an unactivated owner. Its
later five-second handshake retry came after selected-DNS proof cancellation.
The corrected owner follows the existing Router design: after the original
authenticated factory completes and proves its deny baseline, only the sealed
Linux WG lower tuple may open its connected UDP socket. Ordered native stages,
exact manager/source identity, revocation and joined cleanup remain required.
`Current()` still requires full activation for TUN, DNS/exit proof and
measurement. No timeout, keepalive, peer identity or proof check was weakened.

| Evidence layer | Verified observation | Remaining boundary |
|---|---|---|
| Actual encrypted Box composition | The normal production-tag/race suite passes 76 subtest verdicts in 34.58 seconds across HTTP/HTTPS CONNECT, SS, Hysteria2 and WG. All five complete 50 real routed HTTPS samples against owned local responders. WG uses independently generated keys and PSK, actual selected UDP DNS and certificate-checked HTTPS over one captured physical UDP destination. Wrong peer/PSK, DNS, trust/IP, truncated bodies, denied lower sockets, cancelled proof and MTU commit/rollback/reproof retain their full checks. | OS permit identity and TUN creation are explicit fixture substitutes. This does not establish installed networking or physical-device acceptance. |
| Source equivalence after peer-only repair | The installed peer required one explicit `uint16`-to-`int` port conversion in its test-only route helper. All 7,385 actual Box source/go.sum records remain byte-identical; the only module-file difference is the ordinary absolute checkout path to the same verified pinned Xray commit. The successful Box binary/log are preserved rather than claimed as a re-execution of a different source tree. | The peer helper is separately compiled from the corrected current source; provenance is recorded at each boundary. |
| Native physical and startup checks | Sixteen top-level groups and 98 subtest verdicts pass under race in 36.584 seconds, including captured UDP bytes, pre-initialization/reordered-stage rejection, source replacement and startup revocation. After the peer-only cast, 4,250 source/dependency and go.sum records remain byte-identical with the same sole pinned-Xray module-path difference. | These focused controls preserve their tested source identity; the peer test does not change their production or test dependencies. |
| Current native command | Twelve top-level groups plus 43 subtest verdicts pass on the current normal production-tag/race composition. Before/after source closures match. | A command test is distinct from a packaged application's real TUN and UI acceptance. |
| Actual current Linux kernel lifecycle | All seven actual nft/kernel/guardian and local-byte succession cases pass on the current source in 50.94 seconds (the WG case takes 5.13 seconds), with the outer process and private namespace cleanup joined. Before/after closures remain identical across 2,125 installed-source and 700 lifecycle records. | This is isolated kernel/guardian succession and ownership evidence, distinct from encrypted Box proof and the installed application inventory. |
| Installed application inventory | All 317 previous cases remain, followed by WG On-connect, Always, public Connect, cancellation, wrong peer, wrong PSK, DNS failure and replacement: 325 total. Nineteen runner checks and the 325-scenario readiness classification pass, preserving all 87 original rejection classifications. The exact corrected peer compiles under the runner's normal tags/race. | The local host has no genuine `/dev/net/tun`; none of the eight new installed scenarios has local acceptance evidence. All 325 remain required in native CI. |
| Complete local runtime bundle | The complete local Linux AMD64 runtime bundle from the WG feature source passes the normal production-tag link, verified PQ/Cronet/Tor payload checks, unchanged bundle verifier and actual version/external-help commands. It remains separate from application packaging and exact-SHA release publication. | A local bundle does not establish current application packages, authoritative release publication, signing, private deployment or physical-device acceptance. |

The WireGuard feature unit’s prepared external source digest is
`d89aada3a408b66a37abdb070546a0a00d4249405654f0ce083efb6df4f371da`.
Its final local runtime policy digest is `e304cebff91795ba241796830edb662399649f23298e5df2232e87aac9e4db5a`, and its native
receipt SHA-256 is `7eed34a75e8e979f713da6dd247dc0f1933fe5caec82b23e1361051a062ea693`. Full preparation verifies 2,125
installed-source records and 700 lifecycle records; that unit’s corrected
installed peer SHA-256 is
`e3adaa04a2540bb8d35bd1acae7d39a564b19bb1e42a456ef0331afe57e3265c`.
Temporary startup diagnostics remain outside the published source.

### Latest native CI and unresolved delivery boundaries

The latest completed [generated TUN run at bd3df93c](https://github.com/Eabusham2/router-vpn/actions/runs/41395919836)
passes both architectures with original namespace cleanup joined and no
fallback, race report or failed case:

| Exact native job | Verified result |
|---|---|
| [AMD64](https://github.com/Eabusham2/router-vpn/actions/runs/41395919836/job/125117093782) | All six On-connect, Always, captured-MTU, MTU-rollback, resolver-failure and wrong-key cases pass; group time 21.33 seconds. |
| [ARM64](https://github.com/Eabusham2/router-vpn/actions/runs/41395919836/job/125117093572) | The same six cases pass; group time 24.13 seconds. |

These are bounded exact-SHA native results, following the independently
reproduced shutdown repair. The earlier intermittent active routing-receipt
omission at `296461bd`/`c7b03676` still has no demonstrated cause. The newest
pass supersedes those older failures as the latest observation; it does not
prove causation or accept the separate 325-case installed application gate.

The [74bd942a Linux native aggregate](https://github.com/Eabusham2/router-vpn/actions/runs/41393374409)
instead ran out of its 900-second wrapper budget after all 19 baseline suites
passed and before any of the 48 compiled controls produced a verdict.
[AMD64](https://github.com/Eabusham2/router-vpn/actions/runs/41393374409/job/125110055580)
stopped during the first mutant compilation;
[ARM64](https://github.com/Eabusham2/router-vpn/actions/runs/41393374409/job/125110055657)
completed that compilation in 11.157 seconds and stopped during its execution.
No baseline assertion failure is shown. The aggregate remains incomplete,
distinct from both the active-receipt investigation and shutdown behavior.
Published `09f4dce1` gives the complete Linux source gate 1,800 seconds, preserving serial execution, all 19 baseline suites and 48 compiled controls, every individual deadline and every required verdict. Windows keeps its 1,200-second source-gate bound. The two-test regression passes in 86.182 seconds across six targets and injected failure/timeout propagation; a new complete native gate result remains required.

The separate Windows diagnostic jobs at `bd3df93c` also exhausted their
20-minute job budgets: captured Node AMD64/ARM64 passed all 15 baselines and
rejected 10/34 and 15/34 controls respectively; both kernel jobs passed the
baseline matrix and rejected three of four controls before cancellation
while compiling the last. Published `f2e750aa` raises only those two job
aggregates to 30 minutes, preserving all inner bounds, prerequisites and
verdict requirements. Its 13 workflow contract checks pass; a future native
completion is separate evidence.

The newest Windows native logs at `bd3df93c` still fail the ordinary exact-50
HTTP/HTTPS/SS benchmarks after passing the initial path proof:
[AMD64](https://github.com/Eabusham2/router-vpn/actions/runs/41395919673/job/125117821101)
and [ARM64](https://github.com/Eabusham2/router-vpn/actions/runs/41395919673/job/125117821011)
both report the fixed “public measurement owner changed” reason. That
condition is reached after the benchmark response has been validated, but it
combines nonpositive elapsed time with invalid ownership. The older TLS/public
counters describe the initial path proof, not individual benchmark samples.
These logs therefore do not establish the elapsed value or which predicate
failed. Safe-stage reporting is diagnostic evidence; a causal repair and
successful native Windows execution remain required.

Published `8e5a8b57` uses the native Windows QPC clock recommended by
[Microsoft for short intervals](https://learn.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps).
The pinned Go Windows clock uses interrupt time, so a nonpositive very short
interval is a plausible explanation for the earlier combined failure reason,
not an observed value. The repair uses actual counter/frequency data without
clamps, invented minima, sleeps, retries or longer proof timeouts. The shared
race suite and both Windows checkptr compilations pass; actual Windows
50-sample execution remains the acceptance gate.

The macOS installer image ownership and other exact-SHA packaging/release gates
also retain their own current evidence.

### Current remaining implementation and acceptance work

- Continue every applicable original requirement and later correction,
  including additional retained host coverage for ordinary external families,
  predecessors, multihop, Server/Compare, ordinary external Start Layers,
  unprotected admission and remaining recovery/platform integrations. Direct protected Local WG is a
  bounded addition, not universal graph or all-device support.
- Execute all 325 installed scenarios, retain the exact native receipt and
  source/owner checks, and investigate the earlier active-receipt omission if
  it recurs. Verify the published Windows QPC measurement change on actual
  native runners and complete every mandatory native suite/control within
  the recorded runner contract.
- Complete matching exact-SHA native applications, ARM64 server images,
  production compose and authoritative publication. No green current full
  release follows from local actual traffic, a complete local bundle or the
  older `745b3e41` release.
- Complete physical-device/off-LAN networking, leaks/transitions, visual and
  accessibility checks, signing/provisioning/notarization and real upgrades,
  private provider/server operations, ASUS forwarding/JFFS fail-open checks,
  deliberate deployment and post-deployment acceptance on authorized targets.
  These changes did not alter live ASUS, AdGuard, Portainer or household routing.


## Earlier implementation and verification — through 55d9f285

Six additional source units were committed directly to main and their remote
identities verified. The cutoff tree is `e570e88b3337f01489e9601e8279a015068b42eb`;
the Hysteria2 feature unit `74bd942a` has tree
`c61a8392de78a17927b1a575151625a504c052db`. The earlier sections below preserve their
own dated evidence; their missing-feature wording is historical where this
section provides a newer result.

| Commit | Implemented result and verification boundary |
|---|---|
| [1720180d](https://github.com/Eabusham2/router-vpn/commit/1720180d391447cc57f13b504436e4c39dc835ae) | Update the connection-launch source fixture for both retained native Start and direct command Start. AST checks require shared prelaunch guards, command publication and a post-publication guard in the same native ownership block. Seven malformed layouts are rejected, including relying on the separate OpenVPN guard or protecting only one native branch. Production cancellation checks are unchanged. |
| [90ffcbd2](https://github.com/Eabusham2/router-vpn/commit/90ffcbd2c017bf459ea73143be2bdf0b488fadb9) | Give the synthetic Tor IPC proof and heartbeat one observation timestamp, removing a second-clock-read race. Add an explicit proof-after-heartbeat negative alongside wrong-source/front/nonce/replay/DNS cases. The runtime proof-age/order validator remains unchanged. |
| [296461bd](https://github.com/Eabusham2/router-vpn/commit/296461bd017b6b3b322c92db167123aac4f7cff9) | Stage only the exact compiled routing fixture in a read/execute-only file and traversable owned temporary directory, so the fresh user namespace can reach it without opening the private compiler workspace. Recheck source and staged file identity, bytes, owner and permissions before and after execution; retain failure/cancellation cleanup and the existing process-group launcher. Replacements, symlinks, hardlinks, writable/foreign sources and corrupt copies remain rejected. |
| [c7b03676](https://github.com/Eabusham2/router-vpn/commit/c7b036768182551f262c2c080f65859f2484bea0) | Require actual IPv6 addresses, successful DAD and all expected main/local routes on both fixture veths before running the native routing assertion. The bounded observation stays within the original child deadline. Missing routes/addresses, tentative/failed DAD and foreign interface evidence are rejected. Three actual non-root-to-sudo namespace repetitions and three root race repetitions passed. Production receipt source is unchanged. |
| [74bd942a](https://github.com/Eabusham2/router-vpn/commit/74bd942a76c75719fcc62dc6a8c222941c55785a) | Carry retained Linux direct Local ordinary Hysteria2 through public Connect/Speed Lab, captured connected-UDP ownership, selected DNS, TLS/password identity, proof, MTU and exact original Router restoration. Admission remains bounded to Linux, no predecessor, Start Layer Off and On-connect/Always protection. Real encrypted testing exposed and repaired exact pinned client EOF and close semantics without changing public-proof validation. The full four-family Box suite, normal/low-memory transport races, four defect controls, five cross-target transport compilations and complete local Linux AMD64 runtime bundle pass. Seven installed scenarios are appended to all previous 310; installed TUN acceptance remains pending. |
| [55d9f285](https://github.com/Eabusham2/router-vpn/commit/55d9f285ff6bae4c9f2d50ba4960ecd7c35020d4) | Reuse retained-image staging for the network-cohort native fixture while preserving the original private 0700 compiler directory, captured namespace, unshare/60-second deadline, process-group cleanup and strict eight-case verdict. The original exit 126 was reproduced as a real UID-1000 non-root owner through sudo and a user namespace. The same race binary passed all eight actual isolated network-event cases in 0.21 seconds after the fix; ten runner checks pass. No host network configuration changed. |

### Hysteria2 source, real traffic and kernel evidence

The transport repairs address two separately reproduced failures. A final
native Read returned the complete TLS bytes with a wrapped EOF, preventing the
normal TLS/HTTP reader from recognizing completion. A normal remote code-zero
STOP_SENDING also made the first stream Close return an untyped error. The
client now preserves only literal EOF from the two actual stream reads and
maps only the same stream's typed remote code-zero close to the ordinary
closed-connection result. Protocol framing/authentication errors, nonzero or
local resets, the original reset cause, one Close, blocked-reader/writer join
and the shared QUIC connection remain protected. Temporary diagnostic overlays
were excluded from the published source and final native preparation.

| Evidence layer | Verified observation | Remaining boundary |
|---|---|---|
| Final encrypted Box composition | Normal production tags and race pass all HTTP/HTTPS CONNECT, SS and Hysteria2 cases. Hysteria2 carries actual selected UDP DNS and certificate-checked HTTPS over one captured physical UDP destination. Wrong credentials, DNS, trust/IP, truncated responses, denied lower sockets, cancellation and MTU rollback/reproof retain their checks. Final captured run passed in 3.39 seconds. | OS permit identity and TUN creation are explicit fixture substitutes; this is not installed-TUN or physical-device acceptance. |
| Actual Linux kernel lifecycle | Six namespace cases passed in 46.51 seconds, including the new Hysteria2 UDP succession/restoration case, real nft/guardian admission, forbidden-peer checks and retained protection. That run verified its 700-record source closure before and after execution. | This run preceded the two transport repairs and used identical lifecycle/family-admission source. It is preserved-source kernel evidence, not a rerun of the final prepared tree or an encrypted installed application test. |
| Final transport/compiler checks | The unchanged pinned runner passes normal and low-memory race variants, including exact body/EOF, local/remote reset identity, first Close and joined blocked IO; four compiled defects fail as intended. Windows AMD64/ARM64, Darwin AMD64/ARM64 and Linux ARM64 transport test images compile. | Cross-compilation does not execute those five target systems or enable retained Hysteria2 on non-Linux hosts. |
| Installed application inventory | All 310 earlier cases remain, followed by On-connect, Always, public Connect, cancellation, wrong key, wrong trust and DNS failure for Hysteria2. The 18-test verdict suite passes in 3.438 seconds, and the exact installed peer compiles under the runner's normal tags/race. | The local host has no genuine `/dev/net/tun`; zero of the seven new installed scenarios is locally accepted. All 317 remain mandatory in native CI. |
| Final local runtime bundle | The normal production-tag Linux AMD64 link, verified PQ/Cronet/Tor payloads, unmodified runtime verifier and actual version/external-help commands pass. Complete final closures cover 2,125 installed-source records and 700 lifecycle records. | This is a local native runtime bundle. Current application packages, full exact-SHA release publication, signing, private deployment and physical devices retain separate gates. |

The final local bundle was built from the `74bd942a` feature source, before
the separate network-cohort runner fix. It has policy digest
`738417a99c71d09b3795e1bab23c1be0a276ee13e30d624c27f8126c31e88602`
and native receipt SHA-256
`2f9328d0fd07cd78072c028bd321243afce6147b79ef4c9326225917681abb24`.
Its prepared external source digest is
`ef07c056ff365b8a388eb4acc51e0c48b175d6fec18a7720d77b8121fe454b95`.

### Historical generated-TUN CI — through c7b03676

| Exact source | AMD64 | ARM64 |
|---|---|---|
| [296461bd](https://github.com/Eabusham2/router-vpn/actions/runs/41392206605) | [All six cases passed](https://github.com/Eabusham2/router-vpn/actions/runs/41392206605/job/125105842531). | [MTU rollback failed](https://github.com/Eabusham2/router-vpn/actions/runs/41392206605/job/125105842722); the other five cases passed. |
| [c7b03676](https://github.com/Eabusham2/router-vpn/actions/runs/41392708155) | [MTU rollback failed](https://github.com/Eabusham2/router-vpn/actions/runs/41392708155/job/125107374802); the other five cases passed. | [All six cases passed](https://github.com/Eabusham2/router-vpn/actions/runs/41392708155/job/125107375132). |

Both failures report that the generated MTU owner omitted its exact current
native routing receipt because that receipt was unavailable or malformed;
the subsequent teardown EOF is secondary. Opposite architectures fail at the
two checkpoints, so an architecture-specific explanation is not established.
The cause remains under investigation. The check is mandatory, and no receipt
validator or retry rule was relaxed. These six generated-TUN cases also do not
substitute for the separate 317-case installed application inventory.

### Historical remaining implementation and acceptance work — through 55d9f285

- Continue the full original requirement ledger, including additional retained
  ordinary external families, predecessors/multihop/Server/Compare, ordinary
  external Start Layers, unprotected admission and remaining recovery/platform
  integration. The new direct Local family does not close those graph requirements.
- Diagnose the current generated MTU routing-receipt failure, then execute all
  required installed scenarios at the intended exact source. Preserve native
  owner, route, policy, proof and original/replacement restoration checks.
- Resolve remaining macOS installer image ownership and broader Windows/native
  acceptance boundaries using their actual failures. Preserve the separate
  Methods/interoperability, performance and source gaps in the full ledger.
- Complete matching exact-SHA native application packages, ARM64 server images,
  production compose and release publication. The older `745b3e41` release and
  successful local runtime bundle do not establish this newer full release.
- Complete physical-device networking/transitions/leaks, visual/accessibility,
  signing/real upgrades, private provider/server checks, ASUS forwarding/JFFS,
  deliberate exact-release deployment and post-deployment regression using the
  actual authorized targets. No live router, AdGuard, Portainer or deployment
  was changed by these source and isolated-test units.

## Earlier implementation and verification — through 34f65cb8

The continuation re-read the original user passages, the complete 312–356
addendum and C1–C7, the later product/breakage request and map-first/external
node corrections. Those sources agree with the existing requirement authority.
Personal-context retrieval was unavailable in this attempt; original private
documents were retrieved separately. This is not a claim of access to every
past conversation. No private transcripts or account identifiers are committed.

Live main initially pointed to `bb79e0cf`, 915 commits ahead of the historical
`745b3e41` release. The older green release therefore could not establish the
current source or packages. The following coherent changes were published
directly to main with expected-parent checks, exact tree comparison and
independent remote-ref verification.

| Commit | Change and completed verification |
|---|---|
| [0fa73df7](https://github.com/Eabusham2/router-vpn/commit/0fa73df7b6ac04426f8717bbeb553050705c3f27) | The Android saved-profile fixture exercises process-wide external comparison cancellation before dispatch, including a recreated Activity. All 2,211 checks across 181 cases pass; omitted-cancellation and independent-store controls reject the broken behavior. |
| [8cfa23e4](https://github.com/Eabusham2/router-vpn/commit/8cfa23e425890c3d8296e920d17182c5e622f42f) | Replace the hidden Android LinkProperties copy constructor with the public Parcel/CREATOR path, require full equality, and recycle on success or failure. The original failure was reproduced against the official API 36 SDK; repaired source compiles. All 438 lifecycle/store/usage checks and 20 existing defect controls pass, including incomplete-copy refusal. |
| [28e4602b](https://github.com/Eabusham2/router-vpn/commit/28e4602bded262efb4f3a73aff1a4574e7d9f1fb) | Update the native-toolchain fixture for the already-published mandatory Linux external lifecycle runner. Forty tests pass, with one existing Clang-unavailable skip explicitly retained. The test checks the exact platform, arguments, environment, ordering and source. |
| [ca22ce00](https://github.com/Eabusham2/router-vpn/commit/ca22ce003cb4125fe1cba3edec66fed7115e9a78) | Include the five current UAC/Shell fixture files in the explicit Windows GUI source closure. All 51 required records are present; missing and extra files remain rejected. |
| [72993f57](https://github.com/Eabusham2/router-vpn/commit/72993f57fa0e8acd164a30eebbdbc6db14623dac) | Preserve UTF-8 native diagnostics when the Windows wrapper starts with CP1252 stdout. Nine runner checks pass, including exact bytes and rejection of failed, skipped, incomplete and race results. |
| [972ee90a](https://github.com/Eabusham2/router-vpn/commit/972ee90ac70c9f35659ecfc86072f255b6b15283) | Execute only the already-compiled native Linux routing receipt through the existing owned namespace launcher. Eleven runner checks, twelve routing/foreign-owner cases and two actual kernel namespace cases pass under race, including real root and sudo invocation. Old-dispatch and missing-cleanup-owner controls fail as required. Compilation and unrelated suites keep ordinary privilege. |
| [317cb377](https://github.com/Eabusham2/router-vpn/commit/317cb3778c37dfd39558937b949ad256f8dbd78e) | A reproduced Darwin watcher flock collision now waits within a three-second admission bound, releasing partially acquired guards before retry. Once admitted, the action is never replayed. Forty-five lifecycle tests, the baseline journal checks, all 22 existing defect controls and the durable-state audit pass. The retirement and operation deadlines remain unchanged. |
| [11d4c86c](https://github.com/Eabusham2/router-vpn/commit/11d4c86c199cb06c3ec244ca03bb158401c36d75) | Schedule all ten required read-only macOS PF checks through the existing four-worker group and one original deadline. Preserve canonical parsing, generation dependencies, ownership and cancel/join. Three race tests repeated five times, six compiled defects and Darwin AMD64 compilation pass. Actual Intel/ARM kernel acceptance remains separate. |
| [53898838](https://github.com/Eabusham2/router-vpn/commit/5389883858f857fbeb2e0c1b90adf492a6460bbb) | Repair the newly exposed Android Speed Lab fixture using unchanged production benchmark/statistics classes and captured source/restoration types. The original 19 javac errors are reproduced; 3,165 checks and seven mutation controls pass. Downstream restoration also passes 3,174 checks and 19 controls; the whole-service multihop restoration fixture passes 145 checks plus its owner/MTU controls. |
| [2d65e917](https://github.com/Eabusham2/router-vpn/commit/2d65e917e29038904712c50bca15d76d95dbef58) | Wire protected direct Local SS/HTTP CONNECT/HTTPS CONNECT through the retained Linux public Connect, Speed Lab, session, journal and sole native process owner. External DNS/public-exit proof stays distinct from Router authentication. Captured measurements and Stop/restore use that same owner; DNS status rechecks source and final application state. Controller and generated native command race suites pass; Windows AMD64/ARM64 and Darwin AMD64/ARM64 controller test images compile. The complete current Linux AMD64 engine, verified PQ/Cronet/Tor payloads, normal bundle verifier and actual version/help pass. The installed fixture adds eleven cases after all 299 originals; native acceptance is pending as explained below. |
| [34f65cb8](https://github.com/Eabusham2/router-vpn/commit/34f65cb827bd20e8681bfc2e003d77d883a5848e) | Index complete native PASS selectors and newline-terminated lifecycle receipts once per verdict. The runner drops from 123–124 seconds to 2.997 seconds locally, passing 17 tests within the unchanged 60-second gate. All 1,482 existing missing-line negatives and 18 receipt families remain; additional checks reject unterminated, extended and colliding labels and accept CRLF. |

### Actual native observations and remaining boundaries

At `11d4c86c`, the [generated Linux TUN workflow](https://github.com/Eabusham2/router-vpn/actions/runs/41386878830)
passed all six existing cases on [AMD64](https://github.com/Eabusham2/router-vpn/actions/runs/41386878830/job/125089604466)
and [ARM64](https://github.com/Eabusham2/router-vpn/actions/runs/41386878830/job/125089604746):
On-connect, Always, captured MTU, MTU rollback, resolver failure and wrong key.
This predates the public external integration and does not accept its new cases.

The [authoritative Android job](https://github.com/Eabusham2/router-vpn/actions/runs/41386879203/job/125089865095)
at that SHA passed 347 Java statistics checks and the 438-check/20-control
comparison suite, then failed the obsolete Speed Lab fixture repaired in
`53898838`. That log is not an APK pass. The repaired head still requires its
complete native packaging and authoritative release.

For `2d65e917`, the local installed namespace fixture entered its original
isolation and readiness checks, then stopped because the host has no
`/dev/net/tun`. It failed before controller startup. **Zero of the eleven
new installed scenarios passed locally.** No device or proof was fabricated.
The unchanged real-device prerequisite and all 310 scenarios remain required
in Linux native CI. The runner optimization changes only verdict processing.

The complete local feature bundle has policy digest
`4ff0bc98b98b0c9ec43eaf2ee3d0bac501f7ddd7e21349411637ee9b483c122f`
and receipt SHA-256
`fadb0ac6b4982ec0793d5e31ba50a85c1810b8378a77a29b0831728d82788f5b`.
It used the exact verified PQ archive and a newly built pinned Tor helper whose
native C tests and disabled-network ownership check passed. This is a local
feature-source bundle before the separate runner change, not a published
release or a completed 310-case acceptance run.

Direct Local support above does not enable other external families,
multihop/Server/Compare compositions, or Always/torn/legacy crash recovery.
macOS first/legacy inventory and Intel managed unlinked-image identification
remain unresolved; an unidentifiable live process is still rejected rather
than silently excluded. The PF repairs do not close that installer boundary.
Current exact-SHA packages/publication, signing, private deployment and
physical/off-LAN acceptance remain separate and unproved.

## Earlier published source and native evidence — through bbd684f8

These changes extend the historical checkpoint below. Every commit was pushed
with an expected-parent check and independently read back from `main`. Tests
used isolated published-source projections; stopped unpublished PQ changes
were excluded. A local compilation, native CI result and public application
integration are reported separately.

| Commit | Implemented result and executed verification |
|---|---|
| [`0248dfb0`](https://github.com/Eabusham2/router-vpn/commit/0248dfb0b00ccd5d4108387d160d44db3ccd5127) | MTU status reads may retry a fully validated atomic replacement while retaining the original invocation, process, workspace, deadline and operation checks. Immutable reads remain strict. Real Linux file-lease synchronization passed five groups/thirteen leaves under race; four compiled defects were rejected. Generated TUN/controller compilation passed. This establishes a reachable status-read race, not the cause of the older `795e6ef7` failure. |
| [`00063c98`](https://github.com/Eabusham2/router-vpn/commit/00063c98b3b317e837f1979853605781f514eee5) | Canonicalize only fixture-owned temporary roots for the macOS comparison tests that encountered `/var` as a symlink. Actual aliased-root reproduction, repaired comparison/history cases and unchanged symlink rejection cases passed. No production private-path validation was relaxed; hosted macOS execution remains separate. |
| [`cc72da36`](https://github.com/Eabusham2/router-vpn/commit/cc72da362c419e65014ecf043de8766e743f68e5) | Recheck durable Router benchmark cancellation after acquiring the application mutex, immediately before save admission. The test proves actual mutex contention after the required TCP handshakes. The old implementation returned success and changed RAM/disk after cancellation. Seven groups/fourteen leaves, twenty cancellation runs and three compiled old-behavior controls passed; the final test-only canonical-root change also passed through an actual temporary-directory alias. This is ordinary TCP measurement, not tunnel-path proof or cancellation of an already committed write. |
| [`9b53dbcf`](https://github.com/Eabusham2/router-vpn/commit/9b53dbcf04843337d496c3b0b040f3f0c94d2aa2) | Preserve Linux multicast FIB families as ambient objects, corroborate the Windows unlimited loopback MTU against exact native interface rows, and recognize only an original TUN's GOTO resolution by its unique installed NOP target. Actual namespace route/rule installation and target-first retirement passed, with twelve delta cases and a compiled foreign-owner rejection. Eight real observer cases and seven compiled controls passed. All twenty-eight generated MTU groups passed with read-only inventory. The complete gate contains 693 source/runner records; 3,392 project and 3,610 native Go/module records were verified. Subsequent actual TUN CI passed both architectures as recorded below. |
| [`49df6051`](https://github.com/Eabusham2/router-vpn/commit/49df605122af0ed73f31a743224a7cc88501875f) | Require actual protected-global Shell suspension and post-creation cancellation through the retained path used by the shipping bootstrap. The exploratory GLOBALROOT spelling may report only the exact independently proved no-child outcome as unavailable; unknown, mixed, partial-child, image and cleanup errors still fail. Two portable groups/thirty-six leaves and six compiled classifier controls passed; both complete Windows images compiled with pointer checking. All forty-two earlier native requirements and twenty-nine production controls remain. The actual Windows diagnostic job then passed both mandatory outcomes and genuine Limited/Full checks. No launch privilege or UAC policy changed. |
| [`7b2eabab`](https://github.com/Eabusham2/router-vpn/commit/7b2eabab3cf7ee06c507b5f6b2d6d2c158748483) | Capture the private target's native file ID eagerly and validate the parent/target after the final ownership callback. The old source overwrote a replacement, accepted a newly appeared target or recreated a removed target. The repair preserves the other writer and the successful rename commit boundary. Final composition passed eight race groups/six leaves, ten runner checks and both complete Windows pointer-check builds; the wider history/cohort integration passed eleven groups/nine leaves. A compiled missing-check defect failed at its real filesystem assertion. Windows must execute all six cases and both final-check/lazy-ID defects. This does not turn pathname validation plus rename into a kernel-atomic compare-and-swap. |
| [`c318a79d`](https://github.com/Eabusham2/router-vpn/commit/c318a79d830ee1c262c89fc7f381f1b804c6f115) | Share Linux native source/guardian admission and joined retirement between distinct sealed Router and external policies. An external graph retains its own DNS/exit proof and never receives a fabricated Router identity. Five actual namespace groups passed SS/HTTP/HTTPS Router → external → original succession, live forbidden-peer rejection, retained Always protection and refused/cancelled candidates. Both native command architectures compiled; all twelve earlier lifecycle defects still failed after the routing-driver merge. The thirteen non-driver files are identical to the actual native run. Final closure checks cover 696 native/gate and 7,897 Go/module inputs. This is the native prerequisite: public app/session/journal succession remains guarded and unfinished. |
| [`bbd684f8`](https://github.com/Eabusham2/router-vpn/commit/bbd684f860a4956e9f9d27d5c7c5d2faeeefb4c6) | Use the existing trusted, owned process-group launcher only for the already compiled isolated network-event fixture. Keep compilation/read-only observation at the normal runner privilege; preserve the parent namespace check, empty initial inventory, all event assertions and joined timeout cleanup. Eight launcher/verdict checks and the complete local gate passed, including eight real namespace scenarios and seven compiled defects. The actual local root path passed; the hosted non-root invocation remains the next CI boundary. No host policy, sysctl or production observer was changed. |

### Native results that supersede the earlier failures

- At `9b53dbcf`, the [generated protected-TUN workflow](https://github.com/Eabusham2/router-vpn/actions/runs/41374140436)
  passed all six cases on [AMD64](https://github.com/Eabusham2/router-vpn/actions/runs/41374140436/job/125050638702)
  and [ARM64](https://github.com/Eabusham2/router-vpn/actions/runs/41374140436/job/125050639135).
  MTU rollback and original TUN retirement passed on both. The earlier
  `ce557096` routing-receipt failure is closed by this exact native evidence.
- The [Linux observer job](https://github.com/Eabusham2/router-vpn/actions/runs/41374140680/job/125050641551)
  passed actual read-only subscription, snapshot and joined close at that SHA.
  Its later failure was namespace setup: the runner could not write `uid_map`.
  The Windows and macOS matrix jobs were cancelled before their observer steps.
  `bbd684f8` repairs the fixture launch; cancellation supplies no platform pass.
- At `49df6051`, the [actual Windows diagnostic job](https://github.com/Eabusham2/router-vpn/actions/runs/41374288530/job/125051079990)
  passed protected-global creation and cancellation with exact file/image and
  primary-token proof, retained initial-thread suspension, no child code, and
  termination/join. Genuine Limited/normal `runas` Full and retained-parent
  lifetime/negative cases also passed. GLOBALROOT separately returned the exact
  no-creation capability observation; it did not supply launch authority.
- The [Windows installed/Portable Session gate at `49df6051`](https://github.com/Eabusham2/router-vpn/actions/runs/41374288530/job/125051080122)
  also passed actual shipping controller, App/Tray pipe, exact-volume image,
  cancellation, failed-join retention and retirement cases, including compiled
  negative controls. The protected Shell product branch ran on the elevated
  fixture desktop; this is separate from normal Medium-user, interactive
  consent, cross-account or physical-device acceptance.
- The [durable-state source gate at `bbd684f8`](https://github.com/Eabusham2/router-vpn/actions/runs/41374993550/job/125053176435)
  failed the real watcher lifecycle fixture in `modes/test_darwin_owned_pf.py`:
  release/Always retirement returned errno 11, followed by two startup failures.
  Its resource/lifetime cause remains under investigation at this cutoff. This
  is a distinct current failure; the earlier native successes do not waive it.
- The full 299-case installed Linux gate, full Windows MAX admission,
  macOS first/legacy inventory and Intel managed image capture, current
  APK/Xcode/package gates, signing, private deployment and physical-device
  acceptance remain distinct. This record does not establish a complete release.

Keep the durable Router 50–200 TCP benchmark, quick Router Fastest selection,
routed external fifty-sample HTTPS comparison and two-probe Local/Server score
separate. A successful native lifecycle prerequisite does not complete the
public retained Node-to-external connection, restoration or journal flow.

## Earlier published source and native evidence — through f103637f

This section preserves its historical observations. The newer source and
exact native outcomes above supersede its unresolved-failure descriptions.

The following units extend the earlier checkpoint below. Their publication was
independently read back from `main`; no pending working file is included.

| Commit | Implemented result and executed verification |
|---|---|
| [`e8bb2d90`](https://github.com/Eabusham2/router-vpn/commit/e8bb2d90994813e8eb11cf63749d6502941a94c5) | Remove the eight owned native DNS/latency mailbox files only after actual Stop and child join. An unknown replacement file blocks cleanup without partially deleting the workspace. Forty-six race-instrumented checks passed. |
| [`795e6ef7`](https://github.com/Eabusham2/router-vpn/commit/795e6ef7a7cec1f108cc592d7503150329fd101e) | Retained Linux AWG2 Fast/Strong adds AES and AES+XOR. Preserve all eleven AWG parameters, final peer/PSK identity, independent AES and outer-source authority, selected final-path DNS, cover and sealed restore. Fast and Strong each passed four native groups/42 subcases; preserved WG/AWG coverage added four/33, for 117 native subcases. The graph gate passed eight groups/32 subcases; the public gate passed five/36, the runner fourteen checks, and two compiled old-admission controls failed. The installed list grew from 157 to 227 while retaining every earlier case. Actual installed and ARM64 execution remain separate. |
| [`b38464ef`](https://github.com/Eabusham2/router-vpn/commit/b38464ef87e145fc9fa08f889d1c6ca70915eb19) | Repair real installed-test inputs after both architectures rejected `fixed`: use canonical `manual` MTU 1376 and saved Start Layer `off`, keeping the runtime's empty Off distinct. Wrong AES material is tested only for encrypted layers. Six race groups/263 subcases, all 227 exact saved-profile inputs and 66 rejection classifications passed; three compiled stale-fixture controls failed. Production validators remain unchanged. |
| [`50d36def`](https://github.com/Eabusham2/router-vpn/commit/50d36defb1e362182aadb66d9f8d3bbaa7e204bb) | Retained Linux SS-V2Ray supports all three Start Layers. Its SS2022 TLS/WebSocket/mux TCP path and independent Hysteria2 UDP/DNS path retain separate physical roots. Cover recognizes the started concrete composite owner and its exact TCP/UDP children, never a type string or borrowed child; Split/MAX remain outside this admission. Actual encrypted peers passed four groups/37 subcases, concrete owner/cover seven/16, graph nine/36, controller six/340, unchanged cover worker seven cases and fifteen runner checks. Six compiled defects failed as intended. Preserve the 227 existing installed cases and add 72, for 299 required cases. |
| [`ce557096`](https://github.com/Eabusham2/router-vpn/commit/ce5570967532bd7c64899208ce5c73b41581c288) | Add native desktop network event observers and exact owned route/rule/TUN receipts. Physical changes latch even when a snapshot later returns to its old value; owned transitions match their captured records. Eight actual Linux namespace scenarios passed and four deliberately broken observers were rejected; parent MTU/Tor/external proof race checks, generated receipt projection and Windows/macOS compilation passed. Native MTU status projects the current TUN receipt after replacement. The subsequent real Linux rollback failure is recorded below and remains unresolved at this cutoff. Windows offers no documented event flush: delivered-event latching, table checks and joined unregister are the verified boundary. |
| [`ca97c243`](https://github.com/Eabusham2/router-vpn/commit/ca97c2433252e2c47ac5a496b1fbbd3b2faa6b91) | Add native Windows/macOS/Linux Compare only and Compare and connect fastest actions. One captured candidate/source/network/settings cohort, batch owner and MTU lease span sequential trials and original restoration. Measure fifty routed HTTPS responses after TLS to one endpoint, rank the 10% trimmed mean, and give invalid candidates no score. Freshly prove the sealed winning Local/Server choice without rerunning Compare. History rollback requires the exact published file and bytes; only final committed adoption records usage. The full lifecycle race gate passed in 102.261 seconds; final published-source numeric/history/adoption/protection checks passed in 50.295 seconds. Native action checks passed Windows 19, Swift 25 and GTK 26; the full GTK app, fourteen shutdown scenarios, four launcher defects and two controller cross-compiles passed. Actual native packages, TUNs and physical devices remain separate. |
| [`6a699ba9`](https://github.com/Eabusham2/router-vpn/commit/6a699ba92c89d3dbaa3af6e3327f3ad177123e66), [`aca7282a`](https://github.com/Eabusham2/router-vpn/commit/aca7282ad5ca069ccaac8bc5e316a00248f9bddf) | Read the actual Windows linked-token level and existing UAC policy, then run a genuine Limited primary worker and normal `runas` Full continuation. Identification-only links remain observations. The fixture changes no privileges, UAC policy or shipping launcher. Ninety policy checks, three compiled defects and both pointer-check architectures passed. Actual CI then exposed an invalid startup parameter rather than proving acceptance. |
| [`7fe3c1e6`](https://github.com/Eabusham2/router-vpn/commit/7fe3c1e65db2e509ef44eed69233b249e6807507), [`fce65a3f`](https://github.com/Eabusham2/router-vpn/commit/fce65a3fa58e9d0bd6c95b7eda252c5e0027c4ef) | Use the supported basic startup request for that fixture, preserve independent creation-suspension readback and exact Job attachment before resume, and read the bounded retained Full report before rejecting the outer worker exit. Actual CI then started both genuine workers and exposed the next fixture error: it incorrectly required the Full worker's linked Limited observation to be primary. No production identity check was relaxed. |
| [`f103637f`](https://github.com/Eabusham2/router-vpn/commit/f103637f63235872ba2c144dd87135d6a1832615) | Retain the already-authenticated Limited parent process and open its actual primary token with query/duplicate rights for the native access fixture. Recheck process incarnation, exact token object/modified identity, reciprocal authority and original private lifetime before access and after reversion. A lease prevents token/process closure before the access thread joins. All five original native cases remain, plus mandatory real retained-parent lifecycle checks. Six policy groups/88 subcases and seven compiled defect controls passed; AMD64/ARM64 complete test images compiled with pointer checking. The 49-record native closure matches the published files. The real Windows run subsequently passed all policy and genuine Limited/Full cases, including retained-parent lifetime and cleanup. The separate GLOBALROOT launch probe still fails. |

The desktop comparison's final source is `ce557096` plus its exact 22 files;
all 2,229 published dependency records were independently matched to Git blobs
and the isolated source. Only the statistics validator and its test changed
after the full lifecycle run: a bounded floating-point allowance accepts native
summation roundoff while preserving finite/count/order/material-range checks.
The final focused run includes nine invalid-range controls. A sandboxed Swift
attempt could not read process/task metadata; identical source passed with
ordinary process visibility. Neither that failed attempt nor modeled native
launches is represented as actual AppKit or Windows WPF acceptance.

### Historical native results and unresolved failures — through f103637f

- The full installed Linux jobs at `26b294e9` failed the invalid fixture MTU
  policy on both architectures. `b38464ef` repairs those inputs; the 299-case
  expanded installed runtime gate still needs its actual completed run.
- The six-case generated Linux gate passed both architectures at `aca7282a`.
  An earlier `795e6ef7` AMD64 run failed a private status-file read while ARM64
  passed. An actual atomic-replacement race has been reproduced independently,
  but its causal connection to that old log is not established.
- At `ce557096`, [both generated Linux jobs failed](https://github.com/Eabusham2/router-vpn/actions/runs/41371129976)
  only `mtu-rollback`: line 565 reports that the current native routing receipt
  is unavailable or malformed. On-connect, Always, captured MTU, resolver
  failure and wrong-key scenarios passed. This newer failure is distinct from
  the earlier generic status read; the receipt assertion remains required.
- The [actual Windows job at `fce65a3f`](https://github.com/Eabusham2/router-vpn/actions/runs/41370124343/job/125038604675)
  reached the normal `runas` Full worker and exposed the incorrect linked
  primary expectation. `f103637f` repairs that fixture and binds access to the
  genuine retained parent primary. [Its native job](https://github.com/Eabusham2/router-vpn/actions/runs/41371852059/job/125043803384)
  passed all policy checks, real retained-parent lifetime/cleanup and the five
  original Limited/Full cases. The genuine Limited token was denied elevated
  thread rights 0x0802 with `ERROR_ACCESS_DENIED`, preserving the native access
  boundary. Protected mapping and constructed-Medium checks also passed. The
  job then failed the separate GLOBALROOT launch probe: file-not-found, instance
  2, zero callbacks, for both cancellation settings. Complete Windows/MAX and
  package acceptance remain unproved; existing policy displayed no consent
  prompt, so interactive consent and cross-account product use are separate.
- The exact-head source-blocker workflow passed at `ce557096`. The
  [authoritative release for `f103637f`](https://github.com/Eabusham2/router-vpn/actions/runs/41371852360)
  and its native jobs were pending/queued at this read. Later cancelled Xcode
  attempts provide no successful IPA evidence. No current all-platform release
  or deployment is established.

### Measurement distinction retained

The required durable Router benchmark in `cmd/client/extras.go` uses 50–200
TCP-handshake attempts and stores the actual successful count, failures and
robust statistics. The existing quick live Fastest selector in
`cmd/client/telemetry.go` uses 1–10 samples (default five), selects without
connecting and never overwrites those durable fields. The earlier blanket
statement that every five-sample Fastest call needs conversion conflated these
two operations. Keep their labels and records distinct; quick measurements do
not satisfy the durable fifty-sample requirement. External comparison uses
its own routed HTTPS statistic, and neither statistic replaces the separate
two-probe Local/Server formula recorded below.

## Earlier published changes and their evidence — through 6d6f4c15

The following entries and native observations describe their historical
checkpoint. Later implementation and failure evidence above take precedence.

Each unit below was published directly to `main` with an expected-parent check
and independently verified by reading the remote branch. Focused execution used
an isolated published-source projection containing only the stated changes.
The stopped, unpublished PQ fixture work was excluded from those projections.

| Commit | Result and verification boundary |
|---|---|
| [`5423bf92`](https://github.com/Eabusham2/router-vpn/commit/5423bf92d2d1cbd5b20e59db303b03c9af53e8f2) | Linux can finish a complete, same-boot On-connect release intent after independently proving the original controller, engine and guardian have exited and native policy is absent. Recheck absence before each anchored deletion, preserve foreign replacements, and retain the captured checkpoint rather than rebasing it. Recovery sends no process signals, removes no policy rules and grants no authority over a replacement. Fifty-three comparison leaves passed under race; fifteen native groups exercised forty-six recovery cases, and two compiled omission controls failed as intended. AMD64 race execution, ARM64 compilation and three runner tests passed. The final isolated source manifest contained 3,336 files, identified below. Always, incomplete/torn, foreign and legacy recovery remain separate. |
| [`ed0f6083`](https://github.com/Eabusham2/router-vpn/commit/ed0f60833fb3b666e649addd938480603980178e) | Retained Linux Hysteria2 adds AES and AES+XOR Start Layers while preserving final QUIC/TLS authentication, explicit or implicit server identity, selected DNS and the sole captured physical UDP destination. Preserve the original TLS name before rewriting the inner transport to its owned relay. Actual encrypted peer tests exercised incorrect trust, authentication, Salamander, AES and whitening keys, final-path DNS, cover and retirement. Sealed restoration survives independent corruption of the saved Hysteria2/CA/AES files. Eight native groups/48 subcases, six graph groups/26 subcases, four public-controller groups/36 subcases and twelve runner checks passed; three compiled old-behavior controls failed. The installed gate preserves all earlier 93 cases and adds 33, for 126 required scenarios. Its complete native TUN execution and ARM64 runtime result remain separate. |
| [`d6df33b3`](https://github.com/Eabusham2/router-vpn/commit/d6df33b32bf232e4b62754fea974d59a7c20bec8) | Desktop selected ordinary-external and Tor paths now expose a native fifty-sample HTTPS latency operation and cancellation. Capture the proved source, node, configuration, native session and network; hold native activity and MTU ownership through actual cancellation/drain. All fifty same-endpoint samples must be valid; report a 10% trimmed mean with its actual metric. Re-prove ownership before and after measurement. The physical resolver translates only its captured original destination, including the selected IPv6 policy. A cancelled generation cannot publish into a replacement; cancellation exhaustion resets only after a newly proved native session. Controller tests passed eleven groups/26 subcases, mailbox four/eight, actual encrypted SS2022 and HTTP/HTTPS-connect/Tor/factory six/51, Tor ownership one/five, shared statistics five/five, DNS two/four, controller DNS five/18 and Tor proof one/31. Two hundred actual successful TLS/HTTPS exchanges were observed, and an intentionally broken physical-translation build failed. Windows AMD64 and macOS ARM64 native compilation passed. Kernel TUN, controller IPC and the Tor daemon are explicit fixture boundaries. All-node transactions, durable history and the three desktop UIs are still active work. |
| [`d95b6963`](https://github.com/Eabusham2/router-vpn/commit/d95b6963cbe664a29ff5805789d465c78f4a66e8) | Add a Windows CI-only disposable-account fixture to obtain a genuine interactive UAC pair. It requires existing UAC enablement, exact native primary-token identities, reciprocal links, SID/session/integrity evidence and Limited-token privilege restrictions. It does not rewrite UAC policy, construct a pretend Limited token or change production launch behavior. Account collision/stale-receipt controls and exact owned cleanup are part of the fixture. Sixty package/model checks passed under race, three compiled bad-authority controls failed, both Windows architectures compiled with pointer checks, and the 45-file source closure passed. The actual Windows run created the account and passed its ownership/cleanup controls, then failed token validation before worker creation. This is an unresolved native failure, not ordinary-UAC acceptance. |
| [`b38a53be`](https://github.com/Eabusham2/router-vpn/commit/b38a53be178841e67c9905d5f49e146a7b6b9feb) | Make the captured Apple Speed Lab callback an explicit `@MainActor @Sendable` closure so Swift 6.1.2 accepts the actual terminal-restoration composition. Preserve native session, generation and protocol-policy checks. The official signature-verified Swift 6.1.2 compiler reproduced both original conversion errors; the repaired composition passed all 433 runner checks. Swift 6.4.2 with real SHA-256 also passed 353 comparison checks and all six compiled negative controls. This repairs a real compiler failure; the subsequent Xcode/IPA result remains separate. |
| [`742e7100`](https://github.com/Eabusham2/router-vpn/commit/742e7100e472de900c856cacbb5db00f0072d42b) | Update the Tor source audit for the actual latency-bearing maintenance call and require captured node identity, live latency service, invalidation and joined drain before the closed receipt. Preserve all earlier guards and add executable audit regressions for missing ownership and early completion. All 42 focused regressions and the full release-orchestration audit passed. This changes only the audit and its tests. |
| [`dade6203`](https://github.com/Eabusham2/router-vpn/commit/dade6203910a165f089c255b7e88bc0617b925d7) | Add precise diagnostic values to the failing Windows native UAC fixture: root/linked/reciprocal stage, ABI bytes, native type, primary/session observation and native error. Every acceptance condition remains unchanged. Sixty race-instrumented package/model checks, AMD64/ARM64 pointer-check compilation and the 45-file source closure passed. The actual subsequent Windows run identifies a linked impersonation token: type 2, session 2, 56 returned bytes, nonzero TokenID and no API error. The fixture still requires a primary token at that stage, so it fails before worker creation. No ordinary-UAC success follows. |
| [`6d6f4c15`](https://github.com/Eabusham2/router-vpn/commit/6d6f4c155654503057e40cd398a0cf3cbac28a81) | Retained Linux WireGuard adds AES and AES+XOR Start Layers with separate physical-client provenance, owned local relay and sole outer UDP authority. Final WG retains DNS, node proof and cover. Wrong WG peer/PSK/AES/whitening tests and independent outer-only DNS rejection exercise the actual encrypted boundaries; the full WG path must still succeed afterward. Sealed restore uses the captured WG and independent AES sources. Six race-enabled native groups/44 subcases, seven graph groups/28 subcases, five public-controller groups/36 subcases and thirteen strict runner tests pass; both compiled old-admission controls fail as intended. Preserve all previous 126 installed case names and ordering, then add 31 for 157 required scenarios with forty exact rejection classifications. Actual installed TUN and ARM64 execution remain CI requirements. |

The final release-intent recovery source manifest for `5423bf92` has SHA-256
`3f0c7842a212d41d3840f7382634e7ee81649ba531a947bd3abedcb764853727`.
It supersedes initial shared-checkout test attempts for that unit. The final
Hysteria2 preparation contains 2,045 closure records representing 2,036 distinct
physical files, with canonical identity
`b6b9256947adaf7ae4b727843d527105e69cfe1c1eb48383f0f1301726495019`.
The desktop latency closure contains 665 records with identity
`616616fd87a7e7d5dae59b23ae508d415b76c457f651de1c549262073dc7f6cd`.
The Windows diagnostic projection contains 3,348 files with identity
`17116c6e40a83dd85d4ee0d70ab488f229eec9498da53503f2128366f5c70c43`.
The layered WG projection contains 2,057 closure records representing 2,048
distinct files, with identity
`84feb97e2c88fed74b154b969be7221b6fa9afe586634e40d7f9cdaef57b4009`.
These identify their recorded source projections; they are not package or
deployment receipts.

The fifty-sample statistic above remains separate from the user's two-probe
Local/Server comparison formula. That formula remains
`(last_node_response_time + external_server_response_time) / 2`, using the
same chosen external endpoint, both actual candidate paths and repeat proof.
An invalid candidate receives no score. Restoring a measured execution choice
must not run a new Compare operation.

## Earlier actual native CI observations

The generated six-case Linux TUN gate at `5423bf92`
[passed on AMD64 and ARM64](https://github.com/Eabusham2/router-vpn/actions/runs/41363217473).
That gate does not establish all 157 installed retained-host scenarios.
Earlier full Linux engine builds at `26b294e9` were still in progress at the
last inspection, and their result must be read independently.

The actual Apple
[compile job at `5423bf92`](https://github.com/Eabusham2/router-vpn/actions/runs/41363217469/job/125017836842)
failed on the two Swift Sendable conversions repaired in `b38a53be`. Its
runner's default Xcode was 16.4; the separate Swift 6.1.2 reproduction was
therefore necessary even though the newer local compiler already passed.
The newer `b38a53be` native smoke run was cancelled after a subsequent push.
A cancelled job supplies no successful Xcode or IPA result.

The actual Windows
[controller job at `d95b6963`](https://github.com/Eabusham2/router-vpn/actions/runs/41364985597/job/125023126641)
proved fresh account creation, duplicate-account refusal, stale SID/marker
rejection and original owned-account/alias cleanup. It then reported
`native primary token object identity is unproved` before worker creation.
The [diagnostic run at `dade6203`](https://github.com/Eabusham2/router-vpn/actions/runs/41366040184/job/125026302921)
identifies the failing linked observation as a native impersonation token
(type 2), session 2, exact 56-byte ABI, nonzero TokenID and no native API error.
The root observation had passed. The linked token's usable impersonation level
and a supported primary-token launch path still require verification; do not
relabel the observed linked token or change the primary-token acceptance rule.
The independent GLOBALROOT Shell probe still reports file-not-found before its
creation callback. Production uses the separately retained protected bootstrap;
neither this fact nor passing constructed-token tests closes genuine UAC.

At `b38a53be`, the
[map-first gate](https://github.com/Eabusham2/router-vpn/actions/runs/41365186047)
and [native release-blocker source gate](https://github.com/Eabusham2/router-vpn/actions/runs/41365186119)
failed only the obsolete Tor maintenance audit expectation. Their relevant
local replacements pass in `742e7100`. The repaired
[map-first workflow passed at `742e7100`](https://github.com/Eabusham2/router-vpn/actions/runs/41365990221),
and the [native release-blocker source workflow passed at `dade6203`](https://github.com/Eabusham2/router-vpn/actions/runs/41366040105).
Other successful source workflows and cancelled native jobs must not be merged
into an all-platform release claim.

macOS first/legacy inventory and Intel managed CodeDirectory capture still have
the previously recorded native failures. ARM64 managed inventory passed its
own recorded checks. A fresh staging directory does not grant ownership of the
fixed installed supervisor, state, socket and PF namespace. Signing,
notarization, distribution and actual devices remain separate requirements.

## Historical remaining implementation and acceptance work — earlier checkpoint

The following list preserves the earlier checkpoint above. Current work is
identified in the latest section; superseded refusal and test-count wording
here must not be used as the present implementation state.

- Desktop batch/history/UI and native event observation are published. Complete
  exact-SHA native/package/device acceptance and the retained Linux Router
  Node → ordinary external protection handoff. Its current pre-Stop refusal
  preserves the original connection but does not implement that transition.
  Repair the actual generated MTU rollback receipt failure without waiving the
  current owner, route or policy checks. Keep quick TCP selection, durable
  Router benchmarking and routed external HTTPS measurements distinct.
- Continue the retained Linux graph/layer requirements. At this cutoff SS,
  Hysteria2, WG, AWG2 Fast/Strong and SS-V2Ray support Off/AES/AES+XOR.
  All 299 installed scenarios, broader graphs, Always/nonempty/torn recovery
  and legacy succession remain open.
- Resolve actual Windows native UAC/full-MAX and macOS installer ownership
  failures using the real native results. Do not weaken a validator or replace
  an unsuccessful launch with a fabricated success.
- Stock OverTLS UDP remains an actual interoperability gap. A fresh read of
  upstream [`de2878e4`](https://github.com/ShadowsocksR-Live/overtls/blob/de2878e41ea3d695bfac0982b695e3a5bca5beca/src/udprelay.rs)
  still discards the received datagram sender and supplies the local address
  as the SOCKS response sender. Cargo reports 0.3.18, while the newest binary
  release read was v0.3.17; an upgrade alone does not demonstrate a fix.
  Final ARM64 Methods, C1 simple AWG and off-LAN client acceptance remain.
- Complete a matching exact-SHA native/package/image/compose/release pass.
  The older `745b3e41` published release does not certify these newer sources.
  Do not call queued, running or cancelled jobs successful.
- Keep the stopped unpublished PQ fixture unit preserved and excluded. No
  repeated execution, publication or completion claim is made for that work.
- Physical-device reconnect/leak/network-transition, visual/accessibility,
  signing and real upgrade checks remain unproved. Private server/provider,
  ASUS forwarding/JFFS fail-open, exact-release deployment, updater rollback
  and post-deployment regression need their actual targets and authorization.
  No live router, AdGuard, Portainer or deployment changes were made here.

All original requirements and later corrections survive these bounded units.
Truthful rejection of an unsupported feature records a remaining requirement;
it does not complete that feature.
