# Mobile and Windows workspace recovery — November 5, 2026

This record covers the separate continuation workspace last known at
`/workspace/scratch/b31c34e11f09`.
It supplements [the other workspace recovery record](RECOVERY-WORKSPACE-2026-11-05.md)
and [the reconciled requirements](REQUIREMENTS-RECONCILED.md).
The other record describes different Linux and Windows drafts; neither record
supersedes the other or the original product requirements.

The execution service reported **“No usable execution environment is available.”**
GitHub reads and normal expected-head writes remained available. Local files,
pending compiler results and worktree status could no longer be inspected.

The companion [recovery JSON](RECOVERY-MOBILE-WINDOWS-2026-11-05.json) contains:

- Complete guarded recovery operations for **six frozen Apple source files**,
  verified against their original and final SHA-256 hashes.
- Last-known paths, available hashes, completed checks and unfinished validation
  for the shared nested-packet compiler, Android integration and Windows draft.
- Exact publication identities and bounded CI observations.

**The complete pending implementation is not preserved by this record.**
Only the six Apple files have an exact source recovery payload. The other
hashes and paths identify earlier work but cannot recreate missing bytes.
No historical local path in this record is a currently verified download.

## Published baseline and later commits

The mobile imported-entry work was published in
[7903b70d](https://github.com/Eabusham2/router-vpn/commit/7903b70da6c5a39ccd5d49d7a53aaad499f2058e),
tree `7c46e622a46db8a6145dfc15bbf3a18c8d35d6ea`.
The equivalent local integration commit was
`7c60c64dcf58e1c548b1aef591e99defe90e1d00`;
the local and remote commit identities differ, while the source tree matches.

That published unit retains 136 configured imported-entry/paired-final fixtures.
Proxy entries can use paired WireGuard or AmneziaWG finals. Imported packet
entries still require a proxy final in the published source. The unfinished
nested-packet unit would add 54 configured graphs, bringing that specific
fixture inventory to 190. These numbers are graph/test inventories, not a
denominator for the full user requirements.

Before publication, the recorded focused validation included 218 shared race
verdicts, 59 actual encrypted native verdicts, and the shared/native Android
136-fixture composition checks. No local Swift/Xcode execution, physical-device
acceptance or private deployment was established by those results.

The canonical checkout was last confirmed clean at 7903b70d. The shared Git
database subsequently received 68011cbb for other worktrees, including the
Windows draft; that does not prove the canonical local main adopted it.
Later connector-only commits require safe adoption when execution returns.

The following published corrections are already in normal main ancestry:

| Commit | Scope |
|---|---|
| [d06193a6](https://github.com/Eabusham2/router-vpn/commit/d06193a61f41537b51c8b530e779a33e77ed95f7) | Four Apple startup MTU audit sections and 20 missing/late/owner/lease/duplicate controls; executable Swift harness preserved. |
| [3dcdc4de](https://github.com/Eabusham2/router-vpn/commit/3dcdc4deb3dd8bce1b620253a1098f22239f9f6c) | Android comparison mutation targets the captured preference rollback guard and requires the specific newer-selection assertion. |
| [6a6cd100](https://github.com/Eabusham2/router-vpn/commit/6a6cd1001b1d9dea6ea4af1aba2aa4dd5bf8eb77) | Tor whole-owner fixture follows the shipping Linux-only explicit TUN startup-admission interface; full Windows/macOS scenario retained. |
| [3e6953a3](https://github.com/Eabusham2/router-vpn/commit/3e6953a3bb24d6fe2b8ca5f3a0536e30ff5c6438) | Concurrent WG fixture correction captures read-lock retention before Close can create a transient writer observation. Reviewed and preserved without replay. |
| [176d1fa1](https://github.com/Eabusham2/router-vpn/commit/176d1fa1bc44b7427c99a959744e652042348eb7) | Apple Libbox ordinary-start test stub records actual configuration bytes; exact graph and substitution assertions retained. |
| [46e7dca7](https://github.com/Eabusham2/router-vpn/commit/46e7dca7f918c33c74e02ddbea923cfbb98ef8e6) | Concurrent bounded diagnostics for the Linux pre-TUN namespace permission failure. This adds evidence, not a waiver or a claimed fix. |

This recovery record was prepared against 46e7dca7. Read live main before any
restoration; do not reset it to a historical checkpoint.

## Exact six-file Apple recovery

The JSON's `apple_exact_recovery` object contains every ordered
literal edit for two production host/picker files and four fixtures:

- `ios/RouterVPN/App/IOSMultihopExecution.swift`
- `ios/RouterVPN/App/IOSMultihopView.swift`
- `deploy/test_ios_tor_profile.py`
- `deploy/test_ios_external_entry_selection.py`
- `deploy/test_ios_imported_router_pinned.py`
- `deploy/test_ios_imported_router_pinned_contract.py`

Original bytes were fetched from exact commit 7903b70d. The retained explicit
edit commands were replayed in memory, with no inferred source lines.
Both the agent and parent independently verified all six original SHA-256
values and all six frozen output values. The complete output bodies can be
recreated from the reachable base commit and the recorded operations.

Each operation records its exact before/after text, replacement scope and
expected occurrence count. Preserve UTF-8 and newline bytes. Verify the base
hash before applying anything and the final hash afterward. Use an isolated
recovery checkout; never apply these edits over newer main without review.

This is the frozen unfinished Apple unit. It must **remain inactive** until the
shared nested compiler/native path and required integration checks are complete.
Applying only the Apple admission/picker changes would not deliver the requested
native nested path.

Before the outage, this unit's Apple-shaped inputs exercised the actual Go
compiler: 54 new configured graphs, 252 associated refusals, 54 original-PSK
identity controls and 36 different-raw-MTU/same-effective-cap identity controls.
The preserved proxy-to-packet cases and inventory/picker controls also passed.
There was **no local Swift execution or Apple native/device acceptance** for
this frozen unit. Recovery proves source identity, not additional behavior.

## Shared nested-packet compiler and native engine

Last-known worktree:
`/workspace/scratch/b31c34e11f09/mobile-nested-packet/source`.

The immutable six-file host snapshot is last known under
`mobile-nested-packet/proof/host-source-v1`, with manifest SHA-256
`8ad682c225cd54ce0d17a19f060cd08d954dfe785297396e3f93550358566702`.
Its six file hashes are recorded in the JSON. The five production files were
frozen; additional native tests and preparation edits were still being completed.
The final full owned-file inventory was not observed.

The intended behavior preserves the original imported entry MTU and credentials.
For a packet final, Auto derives a bounded endpoint cap before construction,
including data, handshake/control, independent Start Layer and public-carrier
overhead. Fixed overflow is rejected. The native final endpoint must use the
derived cap; changing only the app TUN would not satisfy this requirement.

The six string metadata fields report the entry/requested/effective MTUs, data
overhead, control bound and `configured-unmeasured` state.
These configured bounds are not physical PMTU measurements. TUN retune/restore
must preserve both original endpoint configurations.

Recorded completed checks:

| Check | Result before outage |
|---|---|
| 54 new compiler graphs | Passed. |
| Focused shared compiler, mobile MTU and AWG policy suites | Passed, including configured envelope refusals and preserved legacy/MAX compatibility. |
| 190-fixture export and strict shared inventory | Passed. |
| Actual mobile preparation | Completed; source digest recorded in JSON. |

Native session **12057** was not joined. Its last-known log is
`mobile-nested-packet/proof/native-second.jsonl`.
No native pass is claimed for the pending independent peer, IPv4/IPv6 packet
length/fragmentation, authentication, selected-DNS/proof or cancellation/Close
cases. Causal controls, final native parser execution and projected-byte checks
remain unfinished.

The five production hashes and the six-file snapshot metadata do not substitute
for the missing full source payload. Recover actual bytes before resuming.

## Android integration and saved profiles

Last-known worktree:
`/workspace/scratch/b31c34e11f09/mobile-nested-packet/android-source`.

The JSON lists the five integration paths and the separately frozen three-file
profile subset. Shared compiler inputs were copied from the verified immutable
host snapshot before the final helper launch.

Recorded results include 4,646 permission checks and nine causal controls,
the full runtime ownership/restoration/retirement suite and fixture syntax checks.
The three additional saved-profile families passed 1,613 checks across 167 cases.
Their compiler-readiness boundary was doubled; those profile results do not
prove the native envelope calculation.

Two results are unknown:

- Startup session **79573**, last-known log `android-startup.log`.
- Actual 190-fixture helper/native composition session **73430**, last-known
  log `android-helper.log`.

A premature earlier session **86641** was cancelled with exit 130 before Java
export after a failed mutable-snapshot copy. It is explicitly excluded from
evidence. The immutable copy and the later launch are separate attempts.

The profile subset's exact file, manifest, evidence and patch hashes are retained
in JSON, but its full source bytes were not recovered from the disconnected
workspace. Prior profile families, summary and ownership checks remain mandatory
during final integration.

## Windows retained SS2022 entry draft

Last-known worktree:
`/workspace/scratch/b31c34e11f09/windows-ss-entry/source`,
based on exact 68011cbb. Eleven known paths are listed in JSON.

This draft is limited to Local SS2022 entry → SS2022 final with both Start Layers
Off. It separates the physical entry from final application/DNS/journal policy,
retains independent source tokens, and requires entry proof without inventing
paired-Router identity.

The first host suite compiled, then existing direct-host cases failed Netlink
observation before mutation. An explicitly unshipped OS-inventory model was used
for a subsequent focused run, session **3924**. Its result was not observed.
That modeled boundary is not Windows kernel or WFP acceptance.

A known test correction was never executed: the selected-DNS detour expectation
must use `mobilemultihop.ExternalFinalTag` (`custom-exit`),
not the draft's old `proxy` literal.

Before publication, complete the dual-source activation control, independent
encrypted entry/final traffic and credential/DNS/proof negatives, actual Windows
WFP composition, host/native compilation and a final source manifest.

The other workspace recovery record describes an overlapping 18-file
SS2022/HTTP/HTTPS Windows draft. Compare both actual drafts against latest main;
do not blindly combine or overwrite them. Neither is completed shipping support.

## CI evidence and limits

At exact **46e7dca7**, the complete
[Apple MTU policy job](https://github.com/Eabusham2/router-vpn/actions/runs/42031949729/job/127260687971)
passed. Its actual Swift log confirms all four startup paths and 20 causal
controls, 24 MTU IPC checks, and all four Libbox delivery variants:
1,305 / 1,305 / 1,306 / 1,305 checks. The existing runtime negative controls
remained mandatory. This accepts both published Apple fixture corrections.
Native handles and OS boundaries were doubled; the delivery fixtures opened
no network connections. This is not acceptance of the unfinished nested190 unit.
The separate Xcode/native iOS workflow was still in progress at the last read.

Earlier, at exact 176d1fa1, the
[authoritative Apple job](https://github.com/Eabusham2/router-vpn/actions/runs/42030448667/job/127255415092)
executed three positive Swift 6 Libbox delivery variants successfully:
1,305, 1,305 and 1,306 checks. Their native handles were doubled and they opened
no network connections. The job was cancelled before remaining variants and
negative controls when main advanced. This is useful partial evidence for the
recording-stub correction, not a full Apple gate or package pass.

The
[Linux generated-command/TUN workflow](https://github.com/Eabusham2/router-vpn/actions/runs/42030448497)
passed on ARM64 and AMD64, including selected DNS, MTU rollback and joined Stop.
Its logs did not establish all three separate WG drain causal verdicts.
Do not substitute that successful workflow for the unobserved WG execution.

Intermediate Android, Windows and Apple jobs were cancelled by later pushes.
Cancellation is neither failure of the repaired behavior nor successful
verification. Read current exact-SHA jobs before stating final status.
No new full release publication or private/device acceptance is established here.

## Safe continuation

1. Read live main and preserve its newer source. Inspect the returned workspace
   and original process/session state before launching overlapping compilers.
2. Recover actual shared, Android and Windows bytes and compare every available
   hash. A mismatch requires review, not an overwrite.
3. Recreate the six Apple files only from exact 7903b70d plus the guarded JSON
   operations, into an isolated recovery checkout. Verify both hash sets.
4. Integrate shared compiler, actual native engine, Android and Apple paths as one
   coherent nested unit. Keep configured caps distinct from physical PMTU proof.
5. Reconcile the two Windows drafts and complete their missing host, native and
   ownership tests. Preserve the physical entry/final policy distinction.
6. Commit and push each coherent validated change to main using normal ancestry,
   then reread the remote ref and verify native/package/release evidence.
7. Continue the full original requirements and later corrections. Source,
   executable tests, publication, deployment and physical acceptance remain
   separate. No completion percentage is implied.

No live router, private server, AdGuard, signing or physical-device changes were
made for this recovery record.
