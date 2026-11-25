# Exact saved choices and native release repairs — November 24, 2026

This continuation addresses the original saved-choice, native-client and
release requirements. It uses the October 12 comparison and the recovered
[requirements](REQUIREMENTS-RECONCILED.md), without narrowing their scope.
The hosted failures inspected for this batch belong to
`db75a21d022eb74e58d127dcdecb2c2a0011ef25`.

## Saved CUSTOM presets and connection profiles

Windows now looks up and deletes a preset by its exact literal name. AppKit
and iOS compare the original UTF-8 name where canonical Unicode equality could
otherwise address another saved record. Android preserves the exact saved
name and refuses missing modes instead of silently selecting SMART AUTO.

Creating or renaming a preset refuses a conflicting existing name before
writing. An explicitly edited original record remains distinct from a legacy
case variant. Captured editor checks protect the Apple and Android builders
from overwriting a changed original. Deleting an unrelated preset preserves
the persisted selection, including the GTK path that previously always reset
it to SMART AUTO.

Desktop Save & Connect retains the node displayed when the builder opened.
The request includes `expected_selected_node_id`; the controller verifies that
identity while holding its existing connection transaction, which also excludes
node selection and edits. A changed node returns a conflict before a CUSTOM
attempt starts. Existing API callers that omit the field retain their previous
behavior.

Both AppKit connection-profile entry points and the Windows and GTK profile
loaders preflight a CUSTOM name collision before asking the controller to load it.
They send the displayed `expected_mode`; the controller compares its exact
bytes with the saved profile while holding the profile mutation lock. A renamed
or changed saved mode cannot invalidate the preflight between GET and POST.
The existing saved-layer validation remains mandatory.

GTK restores the returned layers and selected preset together in its private
preset file. The builder rejects a new or renamed preset that would overwrite
another name. When a stored CUSTOM preset is missing, the mode chooser displays
its original name and a missing-preset label. A new profile cannot capture
that choice until the user restores its layers or selects another mode.

A real GTK display exercised the shipping profile dialog, preset store and
mode chooser with a fixture controller. All 26 checks passed, including
refusal before POST on a conflicting name, refusal of a changed response,
exact restoration of an unavailable layer, and retention of a missing preset.
Network path and tunnel acceptance require separate native evidence.

## DNS and release checks

The August 10 request R15 explicitly names Google's secondary address
`8.8.4.4`. Audit item 162 also asks for common primary and secondary IPv4
and IPv6 choices. The Windows, AppKit, GTK and Android paired-node DNS forms
now offer both addresses in each family for Cloudflare, Google and Quad9.
Android's ordinary external and Tor editors use the same picker for their
custom DNS transports. Both iOS daily entry points already open the full
twelve-resolver picker.

The desktop policy API reads the address and certificate name from the
existing twelve-resolver measurement catalog. The new menu entries fill
those two fields on explicit selection. Port, transport, HTTPS path and
bootstrap remain under their existing controls. Saving and measuring retain
their separate actions.

PowerShell, Swift and C fixtures invoked the shipping picker callbacks for
all six secondaries and checked the address and certificate name. The Android
paired-node fixture passed 100 checks with nine fault controls. The Android
external/Tor form fixture passed 7,333 checks, including 162 Java/Go compiler
roundtrips. Those runs use substitute host widgets. Installed-device DNS
traffic and exact-release network behavior require their own observations.

Reopening an iOS DoT, DoH or DoH3 shortcut preserves the existing resolver port
when the selected protocol is unchanged. Choosing a different protocol still
uses its appropriate default. The shipping editor fixture exercises a saved
nondefault port.

An explicitly saved HTTPS Rescue target on a paired Router node now keeps its
host, port, TLS name, path and bootstrap address in the iOS editor, named profile
and actual compiled DNS graph. This repairs a mismatch where the quick choice
stored HTTPS but the paired runtime used its legacy UDP form. Legacy mode-only
profiles and the separate ordinary/Tor Rescue preset keep their existing
behavior. The change does not claim a new automatic fallback implementation.

The Android comparison fixture now compiles the actual preset-commit dependency.
The iOS long-path fixture recognizes the qualified literal Fast family and
retains its refusal cases for other shapes. The shared Xray preparation check
follows the pinned Git-fetch helper and still requires the same immutable
upstream revision. Windows release checks read source as UTF-8, and the
PowerShell 5.1 fixture constructs its ellipsis without relying on BOM-less
source decoding.

Backend and product audits follow the current captured profile-settings
transaction. The native UI audit follows exact preset deletion and the
collision check. Their predicates remain required; the changes do not bypass
the shipping runtime tests or replace their evidence.

## Latency and DNS request ownership

The hosted native engine build also exposed a generation race in the Latency
mailbox. An early future-generation request was refused, but an independently
queued cancellation advanced the receipt. A later tick then claimed and deleted
the previously unowned request. The DNS measurement mailbox had the same
defect in a separately reproduced test.

Both mailboxes now retain a bounded identity and digest for an observed
premature input. Advancing the generation cannot turn that same file into owned
cleanup work. A genuinely new input with the same bytes remains eligible at the
correct generation. The request is checked again before acknowledging a queued
cancellation, covering its arrival between the two file reads. Foreign source,
proof, schema, nonce, worker-drain and cleanup checks remain required.

Four deterministic real-filesystem cases failed on the previous implementation
and passed 25 repetitions under the race detector after the repair. Their
compiled harness uses the original two command-loop templates and I/O methods,
with the native transport fixture boundary identified. The full generated
native command suite remains a hosted requirement.

## Windows native firewall monitor

The ARM64 MAX/QUIC failure includes five watchdog observations in
`verify-baseline`, with the worker still running at approximately 1.5 seconds.
The affected credential trials did not reach the reference server. They are
failed trials, not successful credential rejection evidence.

The old monitor enumerated all host filters once for the empty captured lock
and again for the complete baseline. It now reads both original sublayers in
one fresh read-only BFE transaction and one complete filter enumeration.
Metadata, weights, ACLs, the empty lock, baseline rules, tunnel rules and live
permits remain checked. The transaction must commit successfully. Failure
aborts the snapshot and cancels admission; the 1.5-second watchdog is unchanged.

The native WFP suite includes an absent lock, a foreign lock filter, an extra
baseline filter, an expected live filter and recovery after a rejected
snapshot. Two additional compiled defect controls exercise the lock proofs.
Cross-compilation and fixture composition do not establish actual Windows
kernel timing; that requires the new hosted native run.

## Verification and delivery boundary

The newer Windows H3 runner initially failed on both architectures because its
projected policy fixture omitted the monitor's dedicated baseline method.
The fixture now observes that method separately. All twenty runner contracts
pass, including a deliberate foreground-read substitution and the existing
held-gate watchdog failure. This fixture result does not replace actual WFP
execution. The AppKit broken-source control now reports its expected assertion
instead of exiting earlier in an unrelated throwing fixture path. All 85
distinct controls reached their specified rejection across the recorded
release and Strong-diagnostic runs; this was not one uninterrupted full run.

Android's forwarding confirmation now retains the authenticated node, exact
VPN session and captured path it displayed. Changing the session before the
request or before its first body byte refuses the write, and late results do
not update the replacement Home view. The real callback/request fixture covers
the normal write, cancellation, ten changed-owner cases and independent
missing-guard controls. iOS Home CUSTOM and builder Save & Connect likewise
capture the named preset and node before starting their asynchronous task and
revalidate through provider admission. Both entry points pass all eighteen
normal and changed-owner paths and their two causal controls.

The affected shipping Swift, Java and PowerShell callback and store tests were
run, including deliberate broken-source controls. The Windows device callback
suite passed 1,023 checks, its connection-profile matrix passed 5,177, and its
private UI-state filesystem suite passed 51. The AppKit profile fixture passed
36,957 checks. The focused Go HTTP tests compile the complete Linux shipping
controller source with the selected test files and exercise stale node/mode
capture, exact case and Unicode names, unchanged state after refusal, and the
legacy API form.

The compiled Linux shipping app also ran its real-widget layout check on the
desktop at 10- and 20-point fonts, at 640x480, 800x600, 960x680 and 1280x800.
All 15 actions and seven applicable primary controls remained reachable both
normally and with a 1,024-character mode label. This check deliberately keeps
controller admission closed and establishes rendered layout, not VPN traffic.
The full release-orchestration audit and native session-mutation audit passed
with their required local Java, Go and Swift toolchains.

The full local `cmd/client` test archive exceeded available compilation memory.
It is not recorded as a full-package pass. The complete source inventory stays
required in hosted CI. Native WFP execution, generated Apple frameworks and
real device behavior likewise retain their actual platform gates.

A further review reproduced a separate desktop profile-load failure boundary:
the controller can commit successfully before a local preset-store write
fails. The preflight repairs above do not make those two stores one atomic
transaction. Coordinated durable prepare/commit/recovery is being implemented
as a separate unit; it is not claimed complete by this repair batch.

The authoritative release remains `build-all.yml`: one exact main commit must
produce the required native packages, ARM64 images and verified production
compose before immutable release publication. This repair record is source and
targeted test evidence. Physical/off-LAN acceptance, private deployment,
applicable Apple provisioning and the remaining graph families keep their
separate requirements.

### Android paired Rescue DNS

Switching from Home or another DNS policy to Rescue in the quick picker or detailed DNS editor now starts with the Rescue HTTPS preset. Reopening an explicit saved Rescue retains its resolver address, certificate hostname, port and request path. The paired native graph validates that target and carries DNS through the selected tunnel detour. Incomplete explicit targets fail instead of substituting a public resolver. A legacy Rescue selection with no HTTPS settings retains the original preset.

The shipping Java editor methods and native graph passed the host-run Home/Rescue fixture, including a switch from a private Home resolver, an explicit IPv6 Rescue at port 8443, missing certificate names, invalid paths and the legacy preset. The fixture uses Android handle doubles and the real Go compiler for its generated graph cases. Physical Android transport, exit and DNS proof still require a device.
