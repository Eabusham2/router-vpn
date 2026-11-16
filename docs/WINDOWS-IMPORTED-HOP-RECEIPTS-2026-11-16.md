# Windows ordinary imported-hop latency receipts

This unit extends the Windows per-hop viewer's receipt reader to retain every
captured interior public hop in an ordinary Local path. A public hop must still
have its original node, position, source/configuration, session generation,
request, timing method and complete fifty-response receipt. Selected Local or
Server execution labels keep their existing penultimate-only public position.

The change does not create a route or grant a graph permission. The controller
remains responsible for returning an authenticated original capture; native
multiple-import source and the editor/controller adoption have separate units.
It contributes to the original per-hop and external-node requirements without
closing the remaining graph, platform or live acceptance scope.

## Actual verification

The shipping PowerShell source and test/wrapper were executed from private
source commit `1f34b5e36cf1e2af00269acb8be2e4235f12711f`. The original controller
transport module is byte-identical to published parent
`76de49ad7af75b06853e445ffaff885de3d2d303`; all four executed input hashes were
unchanged before and after the run. This publication contains those exact three
changed source/test files and this evidence record.

Command: `python3 deploy/test_windows_ordered_latency.py --shell pwsh --self-test`.
The actual local PowerShell executable was the existing toolchain installation,
with telemetry disabled before launch. The existing 50-second bound for every
PowerShell child was unchanged. The whole run completed in 63.480 seconds,
returned zero and left no process in its owned process group.

| Evidence | Observed result |
|---|---|
| Shipping PowerShell model | 1,228 checks passed, including independent earlier and multiple public positions. |
| Actual loopback HTTP | All ten scenarios passed: success, public, exit, eight-member CONNECT, early cancel, cancel, owner close, partial result, foreign capture and transport failure. |
| Intentional defects | All thirteen source controls were rejected by their required `ORDERED CONTROL` witness. |
| Source and cleanup | All four captured inputs unchanged; runner and owned children joined. |

The controls cover imported position, old three-member-only CONNECT, selected
labels, selected receipt label, mixed inventory, three-member-only inventory,
private-middle timing budget, foreign capture, premature drain, partial fifty
samples, unjoined HTTP, invalidated history and invalidated drain.

The complete output SHA-256 is
`4c9fc31ed3684296d00d9d1a017fcb09a8b619bb9fab6b64944b2b610a09acba`.
The unchanged transport module SHA-256 is
`2c979c81caf5805d515bfa3f73e110cce1a866e305edec981301a8415b0df3e9`.

## Acceptance boundary

This run exercised PowerShell source/model behavior and real local HTTP on a
Linux host. Its authenticated-controller responses were explicit fixtures;
they do not prove a tunnel. WPF controls execute only in the existing Windows
workflow, which continues to run this gate under both PowerShell 7 and Windows
PowerShell 5.1. Exact-SHA Windows builds, actual widgets, installed networking,
physical devices and the full release retain their separate evidence gates.
