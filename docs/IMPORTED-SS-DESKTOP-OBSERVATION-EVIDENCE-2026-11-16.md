# Imported SS desktop observation and complete controller evidence — 2026-11-16

This follow-up preserves the Windows/Linux longer imported-SS implementation published in `06e5a1e3b68cbad54cdadb9f01e6576c06a54d7b`. Its eligible graph remains one through six paired WG/AWG2 packet prefixes, a literal imported SS2022 penultimate member, and a paired SS2022 final member. The separately typed CONNECT and SOCKS execution families retain their existing bounds. The feature, editor, common membership, and saved-profile production changes from that commit are not replayed by this patch.

## Fresh source, readiness and retained status

The implementation reuses the combined original-source and physical-read methods published in `ec5e9e93cd34976e6bd19e5ef207e96ff51dccbd`. It carries that fresh observation through the owned desktop Current path, avoiding repeated validation through adjacent getters. A ready record similarly reads one freshly validated projection and copies its original positional proof/DNS capture. Raw native assets, original policy and source pointers, preparation identity, physical owner, live host/process/network checks, original MTU derivation, and before/after Current checks remain required. The four-second selected-result and status deadlines are unchanged. No reusable source-validity or live-readiness receipt is added.

Status finalization now waits for the exact selected receipt mutex before taking `app.mu`. After waiting, it rechecks the same retained owner, original source, command, active graph, state token, selected proof, winner and epoch. Already app-locked observation still refuses a busy receipt immediately. The deterministic test holds the original receipt after a successful actual model Current observation, verifies that `app.mu` remains available while status waits, and covers both winners with original, changed winner, changed epoch, changed source, changed owner and cancelled-caller cases. Cancellation must finish while the receipt remains held.

An earlier eight-node publication failure was observed at the unchanged four-second Result boundary. A later four-node HTTP 409 did not reproduce under diagnostic repetition, so it is not assigned to the independently proved mutex race without a matching trace.

## Required controller inventory

The strict gate retains all original trio records and combines the published longer-path cases with complete packet-count/mixed-mode source coverage. The original 240-second compilation, 120-second root, and 135-second outer root limits are retained. Every root runs under the native race detector; missing, duplicate, foreign, skipped, raced or failed records remain fatal. Source and original executable fingerprints are checked before and after the roots, including the two shipping-audit files now explicitly included in this gate's source identity.

| Inventory | Roots | Required records |
| --- | ---: | ---: |
| Original trio preparation, source, public paths, restore, missing/foreign middle and saved profile | 6 | 57 |
| All one-through-six packet counts, mixed-mode original preparation and positional source refusals | 3 | 41 |
| Published longer source preparation/refusals, foreign native middle and saved bounds | 4 | 28 |
| Four/eight-node Server and both Compare winners | 6 | 12 |
| Four/eight-node chosen-source restore and saved-profile round trips | 2 | 14 |
| **Total** | **21** | **152** |

The saved tests retain all published cases and additionally cover Update for each choice, eight positional/source mutations, and a valid longer CONNECT Local capture that cannot obtain Server/Compare authority by changing its saved intent. The retained child, original source, private/public proof positions, selected DNS, exact comparison result, Last choice, live MTU and failed-retirement retry remain required.

```sh
GOTOOLCHAIN=local GOMAXPROCS=1 GOGC=25 GOMEMLIMIT=1200MiB \
  TMPDIR=/task-owned/build-temp GOTMPDIR=/task-owned/build-temp \
  python3 deploy/test_desktop_imported_trio_controller.py --receipt /task-owned/controller-receipt.json
python3 deploy/test_desktop_imported_trio_controller_runner.py
```

Pinned compiler: Go 1.26.3. Native target: Linux amd64. The task-owned temporary directory is outside the captured source tree.

**PASS: 152 records across all 21 roots**, Linux amd64 with `-race`, on frozen base `6ae72d87b2575faa5d4a83d94d57714d68cad31a` plus this remaining observation/status patch. The roots totalled 223.43 seconds; the longest root was the complete four/eight-node restore matrix at 48.16 seconds. The original trio restore passed in 12.75 seconds. Every root retained its original bound.

- Captured source SHA-256: `1308107ff0dbe31ea227b64fddb8cc4ffff0f923111c6f973ff386b0e65ad2ce`.
- Original race executable SHA-256: `278717adaee219aebbd6a848bebbbdebf0571a82711ced064f8c3f486dcad8e8`.
- Final receipt SHA-256: `1da9e21bbc0c0d7195183c0ddd2638c8fad052d1a04f4e30fd8bc146bb93ef6f`.

The final integration preserves subsequent main through `ded9b495c1bb247612d4ab40a4757f6cababed72`, including the macOS guard and expectation from `0a891267`. Enumerating the native race build with `go list -race -deps -test -json ./cmd/client` and comparing its **2,152 repository Go/test/embed inputs** found only the new Darwin prefix test file, the Darwin platform admission function and its corresponding existing preparation-test expectation changed. Module file contents/presence are identical. All remaining production and test inputs used by the completed Linux roots are unchanged. The two audit files retain the independent Darwin audit changes and passed their five affected source/control roots again in 22.795 seconds.

The affected preparation root then passed **all nine records in 11.55 seconds** on current `ded9b495` plus the unchanged remaining patch, using the strict native parser and unchanged 240/120/135-second compilation/root/outer limits. Its captured source SHA-256 is `e0070fc148b57683bef2c53672e7730fd3facff12eca0637f65d5ae3afe7f2a7` and original race executable SHA-256 is `9ff41084d8b4e29c561b9fe54c89850538d716de6fe1a9f8724925974703701c`. The already completed unaffected 152-record run was preserved, not relabelled as a fresh run on the new ancestry.

## Additional verification

The 56.139-second shared suite, 128-record controller suite, paired-source cases and 66-test audit below ran against the frozen converged `ec5e9e93` source plus this observation/status implementation. The final strict inventory runs against `6ae72d87` plus the remaining patch, preserving the later published Windows/Linux feature implementation. These scopes are recorded separately.

- The converged shared source/physical/readiness race suite passed in **56.139 seconds**, including both unchanged upstream observation roots and the additional exact-owner, source, proof, DNS and MTU mutation controls.
- The focused controller race suite passed **128 records across 12 roots in 95.749 seconds**. It covered the fresh eight-node owned source, typed CONNECT parents, original saved paired and imported execution, completed-operation status, changed-owner status, the existing busy-receipt guard and all twelve deterministic status-lock leaves (two winners times original, changed winner, epoch, source, owner or cancellation).
- Existing paired-source observation at two and eight nodes, Server/Compare, on Linux/Windows/Darwin passed all **12 cases in 9.29 seconds** using the original compiled race binary.
- The complete shipping-audit suite passed **66 tests in 243.022 seconds** on the converged source. After preserving the later published common-prefix predicate, the three affected combined-read, typed-owner and common-prefix audit roots passed again in **21.241 seconds**.
- On the integrated `6ae72d87` source, the same original race executable also passed **29 records across three roots**: the existing busy-receipt guard, twelve fresh eight-node source mutations and the deterministic retained-status matrix.
- The strict controller runner's **five tests** passed again on current source in **0.080 seconds**, with the complete 152-record inventory, all native target/race constraints, original per-root limits and complete parser failure controls.
- Two compiled causal controls restored only the previous membership bound and previous status finalization behavior. Independent selections failed at their exact required witnesses: `eligible original packet prefixes refused` and `status refused an unchanged concurrently observed receipt ordered execution receipt is already being observed`. Both ran from the same captured race image, SHA-256 `cb49b4047833f19701bf538fd6e2876e519fb6045b06319805a5f80346e52bfc`. The status production/test files are unchanged in the final remaining patch; the membership feature itself is retained from the later published commit.

The first integrated strict attempt compiled successfully and passed the first three roots, then exceeded the unchanged 135-second outer bound during original trio restore. That earlier runner did not retain the timeout subprocess output, so no blocked call was established. The same captured race image subsequently passed the exact restore root directly in **15.47 seconds** under its unchanged 120-second test deadline. The strict runner now preserves partial stdout/stderr and its partial root JSONL on timeout, while still failing without a completion receipt. The current constrained run preserves the original deadlines.

Earlier incomplete runs are not complete passing evidence: the first combined-read attempt still failed eight-node Result; a subsequent complete controller run passed 110 records and exposed the stale saved-profile count guard, now independently published in the feature commit. A test-only second-app root collision was corrected before the focused passing run. The final strict run supplies its own source/image receipt.

Local evidence files: `imported-ss-desktop-integrated-final-controller-receipt.json`, its 21 root JSONL files, `imported-ss-desktop-integrated-final-controller.log`, the failed first-attempt `imported-ss-desktop-integrated-controller.log`, `imported-ss-desktop-integrated-trio-restore-diagnostic.log`, `imported-ss-desktop-integrated-observation-status-race.log`, `imported-ss-desktop-converged-shared-race.log`, `imported-ss-desktop-converged-controller-final-race.log`, `imported-ss-converged-paired-extremes.log`, `imported-ss-desktop-converged-audit-fixed.log`, `imported-ss-desktop-integrated-audit-focused.log`, and `imported-ss-converged-controls-result.log`, `imported-ss-desktop-current-equivalence.json`, `imported-ss-desktop-current-nine-receipt.json`, `imported-ss-desktop-current-nine.log`, and `imported-ss-desktop-current-audit.log`.

## Native acceptance boundary

These are actual native-Go source/controller/ownership tests with the existing explicit process and kernel models. They do not certify an installed longer imported-SS encrypted Server/Compare connection. That separate mandatory acceptance must exercise the protected controller, original TUN/nft/routes/DNS, real encrypted packet prefixes, a non-loopback native Server carrier, exact positional private/public proofs, both Compare winners, measurements and joined cleanup. The existing portable trio peer explicitly refuses that longer native carrier and cannot be relabelled as installed acceptance.
