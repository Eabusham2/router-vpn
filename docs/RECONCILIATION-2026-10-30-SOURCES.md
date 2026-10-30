# Router VPN requirement sources — October 30, 2026

Reconciled October 30, 2026, using America/Chicago for the user-facing date.
This note records recovered authority and qualifications for the current
continuation. It does not replace the original requirements, certify a release,
or turn historical implementation labels into current gaps.

## Authority and repository snapshots

The latest explicit user correction refines earlier requirements. An assistant
summary cannot remove scope or silently promote an optional item to mandatory.
Current source, tests, publication, deployment and physical acceptance are
different kinds of evidence and must remain separately recorded.

| Snapshot | Evidence and boundary |
|---|---|
| `5967e9c355ecba26d5003decf9b71940e3d6521d` | Historical October 22 handoff checkpoint; not the continuation baseline. |
| `745b3e41e5a78d734391976af9b7cd0637660a0b` | The supplied later release report describes 25 successful workflows and published packages/images. That historical report does not certify newer source. |
| `08b25133` | Earlier live-main observation by the coordinating continuation; already superseded by the later read below. |
| `3a8f5bcbcc1b1a294726d00df852deeeb0014042` | Direct GitHub `refs/heads/main` read while preparing this note. This is a bounded observation, not a promise that main remains unchanged. |
| `463930170f0c0f8769c55a0d33442a1d7ee7794c` | Local recovered source snapshot inspected for requirements/status. The later publication-recovery section records which source changes reached main and their new commit identities. |

Remote reference: <https://api.github.com/repos/Eabusham2/router-vpn/git/ref/heads/main>.
The current status document records newer source integration and native evidence
work beyond the historical green release. Preserve that work; compare ancestry
and content before recovering any old package or changing publication status.

## Recovered source identities

Dates below are the dates recorded in the source messages, not upload dates.
Titles, recorded message dates and source roles distinguish the recovered
material. Private retrieval identifiers are not published in this repository.

| ID | Recovered source | Material read |
|---|---|---|
| S1 | `Continue Storage Diagnostics.md` | Original user turns, August 10–11, 2026; native app/map/nodes/DNS/onboarding, platform scope, WG/AWG selector, Portable correction. |
| S2 | `/Router/mm.md` | Original August 11, 2026 user product/breakage message and instruction to combine it with the recovered older requirements. |
| S3 | `Router VPN Handoff Audit.md` | Numbered audit 1–311, recovered 312–356 and C1–C7; original user continuation turns through August 12, 2026. |
| S4 | `Router VPN Audit Update.md` | August 11, 2026 user instruction to implement coherent parts, check CI, fix failures, continue, and recover source passages when uncertain. |
| S5 | `Pasted text(20261019-065229).txt` | Original local/server two-probe averaging and timeout rule embedded in the continuation; individual turn date is not retained. |
| S6 | `Router%20VPN%20Mega%20Handoff%20UPDATED%20IN%20PLACE%202026-08-24.md` | August 20/24 handoff layers preserving map-first, whole-profile, external-node, measurement and ownership decisions; these are summaries. |
| S7 | `Pasted text(20261026-022849).txt` | Opening lines identify **Speed City Collector 0.2.47**, with an October 25, 2026 app-session timestamp. Used only to prevent cross-project attribution. |

S1 and S2 contain actual `User` turns. S3's numbered items are an audit's
formulation of the recovered contract, not 356 separate verbatim user messages.
Its old missing/partial/done labels describe a historical baseline. S6 is useful
continuity evidence but cannot supersede an original user correction.

## Original messages that anchor the scope

- **S1, August 10, 11:26:39 p.m.:** open as an app, not a URL; multiple routers
  on a Mullvad-like map; remember selection; measured sorting, at least 50
  samples and robust statistics; multihop; Home AdGuard and resolver choices,
  correct selected-DNS display, encrypted DNS and retest; kill switch; full
  setup teaching, SSH/firmware/forward checks, permanent guide, AI Help and
  device-specific downloads.
- **S1, August 10, 11:48:42 p.m.:** WG/AWG is a selector/fallback inside each
  compatible logical mode, without duplicate mode rows; simple third-party
  Methods remain in Setup Center; import node data from file or LAN.
- **S1, August 10, 11:59:44 p.m.:** the native product spans the required
  operating systems, including Intel/Apple Silicon macOS and Unix targets.
- **S1, August 11, 2:39:31 a.m.:** remove unreliable PortableApps, retain normal
  Portable ZIP, and maintain one merged main branch.
- **S2, August 11, 9:53:19 p.m.:** actual native tunnel engines, real multihop
  and kill switch; download progress; teaching onboarding; working Methods;
  admin/connected-client controls; map/DNS/progress UI; generic installation
  plus separate multi-node linking; MTU/Jumbo/auto finder; public QR endpoints;
  reproduce the reported SOCKS5, OverTLS and Shadowsocks failures.
- **S2, August 11, 9:55:11 p.m.:** implement both that new list and the recovered
  older requirements fully. Neither list replaces the other.
- **S5:** implement local and server execution; average last-node and external
  response times for each candidate; keep the lower valid result; timeout
  disqualifies. The current explicit contract also requires the same external
  endpoint, actual candidate routing, stale-result rejection and winner proof.

## Corrections C1–C7 preserved

| Correction | Surviving contract |
|---|---|
| C1 | AWG configuration/architecture alone does not prove real off-LAN third-party interoperability. |
| C2 | Onboarding remembers progress/completion, reappears until completed, stays dismissed afterward, can be rerun, and leaves the full guide accessible. |
| C3 | Sensitive administrative mutations require authentication/authorization; full multi-admin login remains optional. |
| C4 | Blank AdGuard Allowed Clients is valid unrestricted access; do not create a restrictive list merely to add VPN ranges. |
| C5 | Bounded requested desktop/Portable fallback builds a generic client, not a home-specific installer. |
| C6 | Production server deployment stays exact-SHA and image-only; client fallback does not permit server compilation on the AI Board. |
| C7 | Generic install once, private node data imported/paired separately, additional nodes without reinstalling, public packages secret-free. |

## Scope retained during source and release work

- Preserve requirements 1–356, C1–C7, the later product/breakage list, map-first
  redesign, external nodes/hops/exits and subsequent explicit corrections.
  These overlap; do not add them into a new completion denominator.
- Keep the native desktop/mobile products and Setup Center distinct. Retain
  node/profile CRUD, 20 raw profiles grouped into 16 logical choices, WG/AWG
  bases, AUTO/SMART AUTO/CUSTOM/MAX/ALL and actual requested graph execution.
- Preserve DNS/MTU/protection policy through the real selected path, complete
  temporary-test restoration, owned cancellation, and stale-result rejection.
  A disabled feature remains unfinished; accurate wording alone is not delivery.
- Retain the current default and numerical contracts: SMART AUTO, IPv6 On,
  Auto MTU, AUTO encryption/obfuscation filters Off, 50-sample benchmarks,
  two-probe comparison average, and 30 minutes from READY without extension
  by downloads. Explicit Cancel/Delete/shutdown cleans immediately.
- Retain Off/AES-256-GCM/AES-256-GCM + XOR whitening, separate entry/exit
  ownership, generic installers, normal Portable ZIP and exact-SHA production.
- Preserve Portable clean exit/relocation, archive/path defenses, authenticated
  administration, stable forwarding ownership, real LAN-OFF enforcement,
  upgrade key preservation, packaged licenses and historical regression cases.

## Qualifications and attribution corrections

**S3 requirement 339:** macOS signing/notarization is explicitly
`OPTIONAL/POLISH`, to be done when practical, with truthful unsigned/custom-build
documentation until then. No original later user message upgrading that item
to mandatory was recovered. Keep it distinct from legitimate iOS provisioning,
signed physical-device acceptance and truthful distribution requirements.
The combined Apple evidence gate's "where applicable" qualification matters.

Other qualifications remain: node favorites are optional (#335); multi-admin
login is optional (C3); rare BSD/Unix targets are feasible CI/package targets
(#321–322), while mainstream native functionality has higher priority.

The `v0.2.47` reference belongs to **Speed City Collector** (S7), not Router
VPN. The original "tick on and approve" / "one selector" messages were not
recovered, so that compressed memory cannot authorize replacing Router VPN's
documented map-first design. Saved Router VPN settings remain independently
required by its node/profile and durable-state contracts.

## Retrieval limits and continuation use

Personal Context returned "Personal context is unavailable for this
conversation." The project source list was empty; the sources above were
resolved and read through Library. The standalone addendum filename was not
resolved, but its numbered 312–356/C1–C7 material was recovered in S3.
The original individual messages setting READY retention and XOR whitening
were not recovered here; both are explicit in the current user-supplied
handoff and repository contract and remain binding.

This note supports continued implementation and publication recovery. It does
not claim that all historical conversations were accessible, that every
feature was audited in this pass, or that native/device/deployment gates pass.
Update current status only from exact source, test and remote observations;
do not replay old fixes or erase newer work to match a historical checkpoint.
