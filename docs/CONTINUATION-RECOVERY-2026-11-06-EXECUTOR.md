# Router VPN execution recovery record — November 6, 2026 UTC

## Purpose and authority

This is an index to work interrupted by the execution-environment outage. It
supplements the [product evidence ledger](CONTINUATION-EVIDENCE-2026-11-06-PRODUCT.md)
and the original requirement sources. It is **not a code backup**, a replacement
for the original requirements, or evidence of deployment/device acceptance.

The executor became unavailable during an owned native CONNECT build. The
environment event explicitly reported it unavailable, shell access failed, and
the tool transport could not establish the build's final exit or descendant
join. GitHub remained reachable. Do not convert interrupted compilation into a
test pass, a timeout result, a confirmed OOM diagnosis or confirmed cleanup.

Published work through `25d0354f2462c85fd016a954f77e6269f958d1d3`, the
performance fixture correction `b792e879dcbe32856c99521cfab6e5a98b9cff15`,
and concurrent source-contract reconciliation
`40567e35d625a6620d3bc3e43dce4142d938f0c5` are upstream. The later native MTU capability correction
`20f1e423a90c039cf0380d7821c57e55d720fee1` and Darwin fixture repair
`765353bae2d610ceeea5ab6be89c1ed27c0ea8ca` were also published through GitHub
during the outage, with execution still required. Do not replay them.
Read live main before recovery because later commits may already incorporate
any item below.

## Last known primary checkout

`/workspace/scratch/da36851ab193/router-vpn` was clean at published
`25d0354f2462c85fd016a954f77e6269f958d1d3` before the outage.
The later GitHub-only commits were not fetched into that unavailable checkout.

The isolated source changes below were last seen in the same execution
filesystem. The paths and hashes identify what to inspect **if it returns**;
their presence in this document does not prove they are available in another
session. No complete export of these unpublished blobs was retained in the
tool-state stores. Do not reconstruct their source from prose.

## 1. CONNECT packet/layer/DNS extension — unpublished

### Core checkpoint

Known complete local commit:
`e1b22a32ab67cc7e4a3dbc18f00d29f5696a8498`, parent
`81f1e4f58f6a299a694bfeeaef1f97740efa0690`, in
`/workspace/scratch/da36851ab193/connect-uot-core-context-export`.

Its seven paths are:

- `deploy/mobile_imported_connect_cases.py`
- `internal/mobilemultihop/imported_connect_entry_test.go`
- `internal/mobilemultihop/imported_connect_runtime_test.go`
- `internal/mobilemultihop/imported_connect_uot.go`
- `internal/mobilemultihop/imported_connect_uot_runtime.go`
- `internal/mobilemultihop/imported_entry.go`
- `internal/mobilemultihop/imported_entry_runtime.go`

The larger `/workspace/scratch/da36851ab193/connect-uot-current` branch was
subsequently rebased onto published `25d0354f`. Its code was committed, but
the full post-rebase HEAD was not captured before the outage. Do not invent
that SHA. Its sole known uncommitted change was
`docs/MOBILE-IMPORTED-ROUTER-PATH.md`, describing the conditional wider
capability and explicitly pending native acceptance.

### Host checkpoint

Checkout:
`/workspace/scratch/da36851ab193/connect-uot-hosts-current`;
branch `connect-uot-host-final`; last observed clean HEAD prefix
`7396de19`, immediate parent prefix `298d8e49`, preceded by
`c95869b1` and consolidated core `4a809aa4`, on published
`25d0354f2462c85fd016a954f77e6269f958d1d3`.

Only abbreviated IDs were captured after this rebase. The older complete host
checkpoint `b58809f72d0f08f8e889deb7571eba6b23429974` remains the reference
named `checkpoint-connect-host-before-81`; compare ancestry and contents before
using it. The already published Apple profile prerequisite is not an unpublished
part of this branch.

The twenty host paths, in addition to the seven core paths above, are:

- `android/app/src/main/java/com/eabusham/routervpn/AndroidExternalPolicy.java`
- `android/app/src/main/java/com/eabusham/routervpn/AndroidImportedRouterPath.java`
- `android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java`
- `android/test_android_connection_profiles.py`
- `android/test_android_imported_router.py`
- `android/test_android_multihop_startup_last.py`
- `deploy/test_ios_external_entry_selection.py`
- `deploy/test_ios_external_connection_profiles.py`
- `deploy/test_ios_external_execution_owner.py`
- `deploy/test_ios_external_node_comparison.py`
- `deploy/test_ios_imported_router_pinned.py`
- `deploy/test_ios_imported_router_pinned_contract.py`
- `deploy/test_ios_multihop_execution.py`
- `deploy/test_ios_speed_lab_tunnel.py`
- `deploy/test_ios_startup_policy.py`
- `deploy/test_ios_tor_compare.py`
- `deploy/test_ios_tor_profile.py`
- `ios/RouterVPN/App/IOSMultihopExecution.swift`
- `ios/RouterVPN/App/IOSMultihopView.swift`
- `ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift`

### Completed and pending evidence

The current combined CONNECT/core/context subset passed 139 race verdicts
(3.427 seconds package time). Existing 337 captures remain byte-identical in
the proposed 355-input set. The exact published-baseline Android replay passed
25,473 checks, 337 outputs and its five causal controls.

Earlier focused host checks include Android profiles 1,100 checks/182 cases,
Runtime 1,787/243, Home 1,410/444, and Swift picker 3,231 plus 201 cases per
CONNECT protocol. Those focused results were at the earlier `4a` source
checkpoint and are not final-merged-host acceptance. The published Apple
profile prerequisite separately passed 1,365 checks; do not rerun or replay it
merely because this larger extension remains unfinished.

The current full 355 Android producer, Swift producer, merged Apple profile
matrix and native parser union were **not run** before the outage. Retained
artifacts under `/workspace/scratch/da36851ab193/`:

- `connect-uot-original355/`
- `connect-uot-original355-hashes.json`, SHA-256
  `ccce0212b3d8521adea47d51a3f295437d710e3c3d0c1a862dc4e767f813aac6`
- `connect-uot-baseline-android337/`
- `connect-uot-baseline-android337-hashes.json`
- `connect-uot-baseline-android337.log`
- `openvpn-candidate-core337/`, `openvpn-apple337/`
- `replay-connect-baseline.py`

The first ordinary native race build was killed in compiler packages and fully
drained after 256.187 seconds, before a binary. A single materially different
attempt used compiler `-c=1`, preserving the same race/shipping tags and
600-second build bound. It reported compiler kills in grpc, quic-go and netlink
before executor loss. Its final exit and process join remain unknown.

Inspect `/tmp/connect-uot-native-serial-compiler-build.log.result.json` if
present, plus the corresponding log/resource records, before reporting a
terminal result. No native peer pass was obtained from either attempt.

Before publication, finish the already identified negative-evidence refinement:
wrong final keys/whitening must show the peer's actual AEAD refusal, excluding
EOF, timeout and cancellation; wrong entry layers must show the original entry
and CONNECT phase witnesses. This refinement was proposed, not written.

The native plan retains 101 peer verdicts, ten actual datagram-adapter ownership
cases and the previously published proof/MTU groups. These counts describe
prepared verification, not executed acceptance. No broader final-family,
Server/Compare, physical-MTU or deployed-server support is inferred.

## 2. Ordinary external construction — uncommitted, uncompiled

Checkout:
`/workspace/scratch/da36851ab193/external-construction-observation`,
based on `25d0354f2462c85fd016a954f77e6269f958d1d3`.

Seven changed/new paths:

- `internal/mobilemultihop/external_proof.go`
- `internal/mobilemultihop/external_construction_context_test.go` (new)
- `mobile/externalpolicy/box.go.tmpl`
- `mobile/routervpn_external_policy_bridge.go.tmpl`
- `mobile/mtu/external.go.tmpl`
- `mobile/externalpolicy/box_test.go.tmpl`
- `mobile/externalpolicy/bridge_test.go.tmpl`

The draft separates a short construction observation from the returned proof's
VPN lifetime; propagates the original caller through captured native managers,
StartedService, proof health and MTU lease capture; and preserves legacy
cache/cleanup contracts. Later ordinary proof Run/Execution/legacy-current
callbacks remain separate work. Do not claim full external lifecycle adoption.

Formatting and diff checks passed, and the real source-copy gate
`deploy/test_native_policy_scope.py` passed seven tests in 3.316 seconds.
The last prepared input digest was
`d51202c6cae49ee540ba6c3c74b31af5ef97d76b500868275eef23bfbbd8c856`.
**No Go compilation or core/native execution was performed for this draft.**

Resume with the focused shared construction tests, then existing mandatory
native external-policy gates. The new native tests hold actual manager and
StartedService locks; OS TUN/platform boundaries remain explicit doubles.

## 3. Tor status prerequisite — uncommitted and untested natively

Checkout:
`/workspace/scratch/da36851ab193/tor-proof-observation`,
based on `25d0354f2462c85fd016a954f77e6269f958d1d3`.

Fifteen modified tracked paths and one new test:

- `.github/workflows/release-candidate.yml`
- `deploy/build-mobile-tor-package.py`
- `deploy/test_mobile_tor_loader.py`
- `deploy/test_mobile_tor_package_policy.py`
- `deploy/test_mobile_tor_packaged_link.py`
- `deploy/verify-mobile-tor-link.py`
- `mobile/tor/routervpn_tor_host.c`
- `mobile/tor/routervpn_tor_host.h`
- `mobile/torpack/README.md`
- `mobile/torpack/backend.go.tmpl`
- `mobile/torpack/native.go.tmpl`
- `mobile/torpack/testfixtures/fake.c`
- `mobile/torpack/testfixtures/helpers.go.tmpl`
- `mobile/torpack/testfixtures/loader_test.go.tmpl`
- `mobile/torpack/unavailable.go.tmpl`
- `deploy/test_mobile_tor_status_context.py` (new)

The draft adds native `routervpn_tor_status_try` and Cgo
`Instance.StatusContext(ctx)`. Busy means no status available, never healthy.
The captured handle is rechecked under existing ownership locks; cancellation
does not release or replace another invocation. The package must export the
new seventh symbol; old six-symbol packages are rejected. Existing consumer
import verification remains honest while the new observer is not yet adopted.

Python syntax, Go formatting and diff checks completed. **No C, Cgo, ELF,
packaged-link or full provenance execution is claimed.** No verified pinned
dependency archive cache was found. Run the actual C prerequisite, loader,
ELF/header/preparer checks; record any full archive gate still unavailable.

Twenty loader scenarios retain all fourteen originals; seven original causal
controls and four new context controls are prepared. These are inventories,
not passes. Full Tor proof, MTU lease and measurement call-chain adoption is
still required after this prerequisite. A context method must not delegate to
an unbounded owner callback and then claim cancellation support.

## Recovery order and safety

1. Recover the actual execution filesystem and inspect each checkout's status,
   full commit identity, ancestry and changed-file contents. First determine
   whether the interrupted compiler has exited and joined.
2. Fetch live `main`; compare each changed parent path with current source.
   Preserve newer unrelated work and any already-published equivalent changes.
3. Reuse the frozen 337/355 input arrays and retained hashes. Do not regenerate
   certificates or overwrite older captures simply to obtain new comparisons.
4. Keep heavy compilation serialized. Prior killed attempts do not justify
   repeated identical full builds or relaxed limits/negative controls.
5. Validate and publish one coherent unit at a time directly to `main` with
   normal ancestry and remote readback. A local object, recovery record or
   uploaded blob alone is not a branch update.
6. Track exact-SHA native builds/publication separately from private deployment,
   signing and physical-device acceptance. All original requirement boundaries
   remain binding.
