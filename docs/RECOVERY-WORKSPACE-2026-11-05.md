# Workspace interruption and recovery — November 5, 2026

This record preserves the last confirmed source and verification state after the
execution workspace became unavailable around 12:29–12:31 UTC. It supplements
[the continuation evidence](CONTINUATION-EVIDENCE-2026-11-05.md) and
[the reconciled requirements](REQUIREMENTS-RECONCILED.md); it does not replace
the original user requirements or declare the project complete.

**The pending changes are not fully preserved by this document.** The companion
[JSON manifest](RECOVERY-WORKSPACE-2026-11-05.json) records paths, available
hashes, checks and recovery boundaries. It contains no source payload or patch.
The continued existence of the former workspace and snapshots cannot be verified
while the execution service is unavailable.

## Published source at the interruption

The last complete source change was pushed and independently read back from
`main`:

- Commit: [68011cbbed42a4b5391bf96a2fce09c2aa6d5511](https://github.com/Eabusham2/router-vpn/commit/68011cbbed42a4b5391bf96a2fce09c2aa6d5511).
- Parent: `7903b70da6c5a39ccd5d49d7a53aaad499f2058e`.
- Git tree: `cbfadf47827fbe6c29d53d15b2bf99e4051888c5`.
- Behavior: Linux bootstrap removal uses the retained original Netlink endpoint,
  original observed ruleset generation and exact acknowledged rule handle.
  A generation mismatch rejects the atomic deletion. An uncertain receipt keeps
  its original uncertain owner rather than issuing another deletion.
- Completed validation: 152 selected root race verdicts and 152 selected,
  ordinarily prepared native race verdicts; the compiled zero-generation
  causal control rejected the intended behavior; three focused Python
  gate/inventory/wiring checks passed.
- The six real-kernel removal cases were compiled and made mandatory in the
  native gate. They were not executed locally. An unrelated successful
  guardian namespace workflow does not prove those six cases ran.
- Kernel grant expiry and recovery from a lost creation acknowledgement remain
  unfinished requirements.

The local exact adoption of this commit completed before the interruption.
Its temporary local commit `7bf5e86a130c168dea36c107c31b37cb9f8e4215`
was not the GitHub commit. Any later connector-only commit must be compared and
adopted after workspace recovery; local adoption is not implied by a successful
remote update.

Earlier completed units remain in normal history:

| Published commit | Bounded change and verification |
|---|---|
| [356942ca7c29b90b8f7b0767168bd353fcdde1cd](https://github.com/Eabusham2/router-vpn/commit/356942ca7c29b90b8f7b0767168bd353fcdde1cd) | Retire an idle Linux standard child after loss of its original parent. 19 worker, 17 original-process bootstrap and 6 prepared native selected verdicts passed; four old-behavior controls were rejected. Local actual-TUN namespace acceptance remained unavailable. |
| [782e9f2a50a82693f05658c9efa0422a472610e4](https://github.com/Eabusham2/router-vpn/commit/782e9f2a50a82693f05658c9efa0422a472610e4) | Preserve captured machine resolver policy through protected Linux bootstrap. Final prepared native selection passed 48 verdicts and the installed runner passed 39 tests. The earlier 129-verdict root run preceded the final wire-bound correction. Actual privileged UDP/TCP cases were not run locally. |
| [1938916a8f080945ef11d86ae7a252d7580d5e2c](https://github.com/Eabusham2/router-vpn/commit/1938916a8f080945ef11d86ae7a252d7580d5e2c) | Retain SS2022 entries for HTTP/HTTPS CONNECT finals. 96 client/shared and 39 prepared native verdicts passed, with intended old-behavior controls rejected. Physical and installed runners passed 55 and 41 tests. Actual privileged host execution remains distinct evidence. |

Concurrent mobile work at
[7903b70da6c5a39ccd5d49d7a53aaad499f2058e](https://github.com/Eabusham2/router-vpn/commit/7903b70da6c5a39ccd5d49d7a53aaad499f2058e)
was preserved before publishing 68011cbb. It adds imported proxy entries followed
by paired WireGuard/AmneziaWG finals. Do not overwrite its preparation mappings
with an older pending snapshot. Its author-reported test counts were not
independently rerun by the root session during this adoption.

## Exact execution failure

The execution service returned:

> exec-server transport disconnected; failed to resume exec-server session:
> recovery timed out after 45s

GitHub repository reads and normal expected-head writes remained available.
That distinction allowed release diagnosis and this recovery record to continue.
It did not restore access to local files, the compiler or running session output.

Do not claim that an unobserved process joined successfully. Do not infer an
empty command log means success. Do not rerun or replace pending compilation
until its original process and source identity have been inspected.

## A — Read-only original resolved authority

The 15-file native foundation was frozen against 68011cbb, but was neither
committed nor fully verified. The JSON companion records the exact final
SHA-256 values printed and reviewed before access was lost.

Its bounded implementation captures the original authenticated system-bus
endpoint, bus ID, immutable daemon owner, credentials, optional received process
descriptor and original physical observer. It retains complete manager/link
policy, including DNSEx ports and SNI, domains, default-route and security
settings, and LLMNRHostname. A fixed read-only native command transports an
ordered, bounded policy with an immutable whole-policy digest.

Completed final checks were:

| Check | Observed result |
|---|---|
| Ordinary native preparation, session 65640 | Joined with exit 0; 2,067 source records verified and 1,019 Xray files unchanged. |
| Selected standardengine race tests | 19 PASS, 1.325 seconds. |
| Selected physical observer race tests | 6 PASS, 1.061 seconds. |
| Reachable native signal/security/gate race tests | 14 PASS, 1.056 seconds. |
| Physical runner inventory controls | 2 PASS, 0.112 seconds. |
| Service auxiliary inventory control | 1 PASS, 0.034 seconds. |

The nine-verdict fixed-command selection in session **12665** was still compiling
with an empty command log at the last successful observation, about 372 seconds
into its unchanged 600-second build ceiling. It was **not joined**. The
observer-hook causal control had not begun.

An earlier full native authority attempt failed at creation of its actual Unix
broker socket: `net.ListenUnix: socket: operation not permitted`. Fourteen
reachable verdicts passed, while ten broker socket cases failed before their
authentication/capture assertions. The package result was FAIL, not a pass or
skip. Do not bypass that boundary or change the transport to manufacture a pass.

This foundation alone does not implement public systemd-resolved queries.
Before admitting a scoped upstream query, complete:

1. An original-daemon local-only preflight for synthetic and hosts names,
   including the daemon's actual hostname authority. The helper's hostname or
   LLMNRHostname alone is insufficient.
2. Explicit provenance that the daemon and helper refer to the same original
   network namespace before treating an equal numeric interface index as the
   same kernel link.
3. Actual named-system-bus/native-command namespace acceptance.

No preflight or namespace-composition source was added to this frozen unit.

## B — Windows retained SS2022 entry graphs

The 18-file Windows draft admits the bounded local SS2022 entry followed by
SS, HTTP CONNECT or HTTPS CONNECT finals, with both Start Layers Off. It keeps
final policy/DNS identity separate from the physical entry and preserves the
original WFP creator/journal and captured source checks.

The initial isolated snapshot command, session 30723, joined with exit 0. A
subsequent edit to `node_layer_peer_test.go.tmpl` added final-method handling, so
that snapshot must be refreshed before testing. Final source hashes were not
recovered.

Two `NativeSSEntryGate` Python runner tests passed in 0.035 seconds and three
Python files passed syntax checks. **No B-owned Go compiler was launched.**
Neither native Windows cross-compilation nor actual WFP/Wintun acceptance ran.

Before freezing or publishing, correct bounded provider output-drain cleanup
ordering, strengthen Speed Lab response/cancellation/restored-MTU assertions,
assert final environment policy identity, and add explicit paired Always-to-Off
with original-owner retry coverage. Then refresh the source/hash snapshot,
execute the finite Go selection and causal controls, and run actual Windows
native gates. The new protocol gate inventories of 19/19/21 verdicts and two
compiled controls are declarations, not passing execution results.

The shipping Windows UI already offers an ordinary saved entry for Local and
captures both source preconditions. No production picker change was warranted
by the traced call path.

## C — Scoped resolved-policy bootstrap adapter

The 12-file draft was snapshotted against 68011cbb plus A's two typed
policy/protocol dependencies. Snapshot creation joined with exit 0; the final
hash read failed after access was lost. No new C tests compiled or ran.

The draft retains the originally created helper, captured operation deadline
and policy owner; RPC completion does not renew lifetime or invalidate the
original child by itself. Cleanup owns the created helper, never the resolver
daemon. Opt-in for the exact 127.0.0.53 stub is distinct from strict direct
machine-resolver capture.

The planned first executable path is limited to one eligible ordinary DNS
scope with DNSSEC=no and DNSOverTLS=no. It captures DNSEx endpoint port/SNI,
search/routing/default/fallback policy and physical link identity. The scoped
socket retains its exact mark, endpoint tuple and acknowledged grant, and
preserves the published 68011cbb conditional-removal transaction. The draft
copies mutable MAC bytes and explicitly translates Linux raw IFF bits into
Go network flags.

Do not publish upstream admission until A's original-daemon local-name
preflight and daemon/helper namespace composition are integrated. All new
deadline, cleanup, stub UDP/TCP, truncation, custom-port, wrong-policy/link,
mutable-MAC and flags cases still require execution. Actual encrypted DNS,
DNSSEC, equal-best parallel scopes and link-local DNS remain unfinished.

## Release observation and repair

At 12:40:08 UTC, exact commit 68011cbb had 28 workflow runs: 13 successful,
5 in progress, 4 pending, 4 queued and 2 failed. This is a point-in-time
observation, not the final disposition of those runs.

- [MTU policy contract, 42024718876](https://github.com/Eabusham2/router-vpn/actions/runs/42024718876):
  the Apple job failed because its old source slice grouped
  `startMultihop` and the newly inserted `startImportedEntryMultihop`.
  Both shipping methods have their own MTU hold before launch, but the combined
  range contains two holds. The prior three-control loop also stopped before
  the fourth startup path.
- [Aux proxies and setup assets ARM64, 42024718884](https://github.com/Eabusham2/router-vpn/actions/runs/42024718884):
  a failure was newly observed; its cause requires its own job/log evidence.
- [Authoritative release, 42024718919](https://github.com/Eabusham2/router-vpn/actions/runs/42024718919):
  pending at this observation.

A concurrent upstream change,
[d06193a61f41537b51c8b530e779a33e77ed95f7](https://github.com/Eabusham2/router-vpn/commit/d06193a61f41537b51c8b530e779a33e77ed95f7),
repairs the Apple fixture as a normal child of 68011cbb. Its four independent
startup ranges preserve exactly one original engine/lease hold before launch.
Twenty source controls remove, delay, change owner, change lease or duplicate
each hold. Independent source review and equivalent JavaScript predicates
accepted all four shipping paths and rejected all twenty variants. The
executable Swift IPC/startup-admission harness is unchanged. These source
checks are not execution of Python or Swift; actual macOS CI remains required.

The root's smaller duplicate candidate,
`b258f6a00887785d913681cca02afead2f80a05a`, exists only as a Git object.
Its expected-head update returned an error; fresh ref and ancestry reads
confirmed that d06193a6, not the duplicate, is on main. Do not replay the
duplicate or overwrite the stronger upstream fixture. Local adoption of
d06193a6 has not occurred because the workspace is inaccessible.

The latest published release found during this interruption remained
`router-vpn-sha-745b3e41e5a78d734391976af9b7cd0637660a0b`, published October 24,
with 12 assets. That older release does not verify current source.

## Subsequent exact-source diagnosis and preserved repairs

Before this recovery record was published, main advanced normally through the
following fixture-only changes. Their source was inspected; a later commit's
passing native execution must still be established separately.

| Commit | Preserved correction |
|---|---|
| [3dcdc4deb3dd8bce1b620253a1098f22239f9f6c](https://github.com/Eabusham2/router-vpn/commit/3dcdc4deb3dd8bce1b620253a1098f22239f9f6c) | Android comparison mutates the actual shared PreferenceUpdate rollback owner and requires the specific newer-selection failure witness. Production rollback behavior is unchanged. |
| [6a6cd1001b1d9dea6ea4af1aba2aa4dd5bf8eb77](https://github.com/Eabusham2/router-vpn/commit/6a6cd1001b1d9dea6ea4af1aba2aa4dd5bf8eb77) | The Tor whole-owner fixture requires the explicit TUN startup setter only on Linux, matching the shipping owner. Windows/macOS retain the original startup context on the native owner. |
| [3e6953a3bb24d6fe2b8ca5f3a0536e30ff5c6438](https://github.com/Eabusham2/router-vpn/commit/3e6953a3bb24d6fe2b8ca5f3a0536e30ff5c6438) | The WG drain fixture checks the actual paused delivery's read-lock retention before Close can acquire a transient detachment lock. The original failure witness, bounded joins, stack-lock and late-packet checks remain intact. |
| [176d1fa1bc44b7427c99a959744e652042348eb7](https://github.com/Eabusham2/router-vpn/commit/176d1fa1bc44b7427c99a959744e652042348eb7) | The Apple delivery fixture records ordinary Libbox startup bytes using its existing recorder, preserving exact graph/configuration assertions. |

The 68011cbb Aux failure was traced to both Windows native engine jobs,
[ARM64 127243526537](https://github.com/Eabusham2/router-vpn/actions/runs/42024718884/job/127243526537)
and [AMD64 127243526582](https://github.com/Eabusham2/router-vpn/actions/runs/42024718884/job/127243526582).
The real SAFECOOKIE/Box test failed at `starting-tun`. Source tracing confirmed
the fixture's platform-specific startup-setter mismatch; 6a6cd100 corrects it.
The immediate successor Aux run was cancelled before complete native build and
does not count as a successful rerun.

The 68011cbb Linux native run
[42024718931](https://github.com/Eabusham2/router-vpn/actions/runs/42024718931)
stopped in the earlier physical-source gate on both architectures:

- **ARM64 job 127240172756:** the current WG drain baseline passed. Its
  old-delivery mutation reached an unintended late-write nil-pointer panic
  instead of the required retained-delivery witness. The strict runner correctly
  rejected that result. The deterministic fixture correction is 3e6953a3.
- **AMD64 job 127240172518:** both native claim failure/cancel children failed
  namespace observation before entering the selected subtest or creating a TUN.
  Both the inherited original namespace descriptor and the child's own
  `/proc/thread-self/ns/net` returned permission denied after
  `CLONE_NEWUSER | CLONE_NEWNET`. There is no later explicit Setuid in this
  fixture. The cause is not yet established; attributing it to AppArmor without
  runner evidence would be an inference.

A capture-only namespace patch would not resolve the independently failing
fresh child observation. Further diagnosis must separate inherited-descriptor
fstat/Fstatfs, opening/identifying the child's own namespace, UID/GID maps,
capabilities and available security-context/denial evidence. Preserve the
original parent and child identity checks and mandatory namespace isolation.

**None of the six conditional-removal kernel children or the zero-generation
control were reached in either native job at 68011cbb.** The build runs the
physical-source gate before the guardian gate. A successful guardian namespace
workflow is a different executable boundary.

The 68011cbb authoritative release did not publish: aggregate candidate and
release publication were cancelled; image publication and production compose
were skipped. The previously published 745b3e41 prerelease remains the latest
publication found during this audit.

The source-only WG fixture correction was committed through GitHub while local
execution remained unavailable. Its exact remote source, parent and tree were
read back and matched. It has not been adopted in the inaccessible local
checkout, and no local Go execution is claimed.

## Safe continuation

1. Read live main, latest exact-SHA jobs and the actual recovered workspace.
   Preserve all unrelated newer changes. Do not reset main to this record.
2. Inspect session 12665 and the actual original compiler/process status
   before launching another compiler.
3. Locate and hash the recovered A files against every JSON value. A mismatch
   requires review; it is not permission to overwrite.
4. Refresh B's stale isolated snapshot and recover C's actual source and hashes.
   The listed old paths are evidence of prior writes, not working download links.
5. Adopt subsequent remote commits using their exact source and normal ancestry,
   without discarding the three pending units or the mobile proxy-to-packet work.
6. Complete each unit's missing focused validation, commit a coherent change,
   update main with an expected-head check, and reread the resulting remote ref.
7. Keep source, tests, push, native builds, release assets, private deployment
   and physical-device acceptance distinct.

The unfinished scope still includes source implementation, not merely live
devices: resolved preflight and namespace composition, encrypted/scoped DNS
coverage, grant expiry/lost-creation recovery, same-boot service-crash
continuation, the pending Windows graphs, and other graph coverage recorded in
the full ledger. Native release verification and the authorized live/device
requirements also remain open. No live router, private server, AdGuard,
signing or physical-device changes were performed for this recovery record.
