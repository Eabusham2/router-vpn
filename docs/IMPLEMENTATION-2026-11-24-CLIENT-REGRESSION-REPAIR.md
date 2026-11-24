# Native builds and saved client settings — November 24, 2026

This repair continues the [reconciled requirements](REQUIREMENTS-RECONCILED.md),
the recovered original map-first requests, and the October 12 comparison.
It preserves the existing mode catalog, measured route ownership, profile
operations, generic packages, native protection checks and release gates.
The CUSTOM action and deletion defects also existed in the October 12 baseline;
their age does not remove them from the requested working product.

## User-facing repairs

- Android protection and multihop controls now use actual click callbacks.
  Accessibility clicks apply the preference; rendering a checkbox does not.
- Android Home DNS rendering no longer acts like a new user selection.
  Opening an editor retains the saved Home choice, the editor opens the chosen
  DNS mode, and successful Save refreshes Home. The saved node generation is
  checked at commit so an older editor cannot overwrite a newer profile.
- Windows, GTK and AppKit Router Settings now retain the displayed profile ID
  and policy revision. Loading another saved setup or changing the same node
  makes an old form stale. The controller checks the captured source again
  under its commit lock and applies preferences to the current record, keeping
  independent latency and effective-MTU readbacks.
- Desktop and Android CUSTOM creation commands use a distinct action ID,
  leaving a real preset named `new` available. Cancelling a builder or failing
  to open it restores the actual saved mode. Programmatic refreshes do not
  replace the saved choice.
- The iOS swipe and context-menu Delete buttons share the same guarded
  operation. Deleting the active preset resets that choice to SMART AUTO;
  deleting another preset preserves the selection. AppKit and WPF deletion
  target the captured original preset rather than an unrelated edited name.
- WPF Save & Connect carries the exact newly saved layers through the
  asynchronous Home refresh and verifies the selected Router node before
  requesting a connection. Save alone remains separate from Connect.
- Named connection profiles preserve CUSTOM display names, including case,
  spaces and Unicode, together with their exact captured layer set. Ordinary
  protocol identifiers keep their existing validation. An older profile with
  no captured CUSTOM layers is refused before applying it, with an instruction
  to select the intended preset and update that profile.
- Android profile restoration enforces the existing 64-preset and 512 KiB
  bounds before changing state. Replacement at capacity remains valid; a
  historical over-capacity list can recover through an explicit preset Delete.

## Native build and test repairs

The original hosted failures were inspected at source SHA
`3f3da4c1a44d60cc3e8b3547bf9d2c88c7c6f8f7`.

- The desktop OpenVPN projection fixture now contains the original pinned
  Shadowsocks files required by the real preparation transform. The pinned
  source checks and repeated-preparation controls remain required.
- The Android ABI guard on Windows selects native Git Bash and supplies its
  fixture by standard input. It retains the four missing-ABI negative checks.
- The hostname profile regression test now accepts the two newly supported
  first-stream hostname shapes with routed TCP DNS, then exercises the original
  refusal and no-write checks after removing that required DNS ownership.
- The iOS candidate fixture includes its complete shipping predicate closure.
  The candidate prefix value is compiled into both the app and PacketTunnel
  target. Native NSError output arguments use Swift inout bridging. These
  changes address the ten diagnostics in the original
  [Xcode job](https://github.com/Eabusham2/router-vpn/actions/runs/45339817038/job/138260624152).
- The PF journal harness retains all 136 cases and 55 deliberate defects. Each
  positive case has its own original 30-second watchdog instead of sharing one
  30-second limit across the whole suite.
- The H3 reference peer retains its authenticated UDP relay through WFP
  inspection, using the pinned native timeout. The existing two-association
  test sends again through both original relays after six seconds and checks
  their eventual retirement. Production WFP inspection is unchanged.

## Darwin foreign PF readback

Empty foreign PF queues can be checked through the already pinned XNU ABI
without spawning a separate pfctl process for each probe. This is a read-only,
uncached check of all relevant filter or translation selectors, repeated with
matching tickets. Recursive queries also require no child anchors.

A nonempty queue, a changed ticket, or an unsupported ioctl returns to the
existing pfctl inspection. Other errors refuse the proof. Own-anchor, global
PF and legacy-rule checks retain their existing paths. Cancellation is checked
after the synchronous native call; the implementation does not claim to
preempt a kernel ioctl at a wall-clock deadline.

The mandatory isolated macOS fixture now also installs real loopback-scoped
NAT and RDR rules, checks that neither receives an empty-queue proof, and
verifies cleanup restores its originally absent anchor. The actual kernel
fixture and 130-cycle guardian retirement run still require macOS execution.

## Evidence and release boundary

Targeted compiled Java, Swift, PowerShell and Go checks exercise the affected shipping
callbacks, profile save/load transactions, candidate captures and native
preparation paths. The controller regression slice passed after integration.
The Go HTTP lifecycle tests reproduced the original name corruption and
rejection before checking Save, Update, persisted readback and Load. The WPF
callback suite passed 1,009 checks and rejected all 23 deliberate defects.
The final Android store suite passed 508 checks in 46 isolated cases. Its
ordered CONNECT prefix case passed all 510 checks with the CI fixture setup
and original watchdog after an earlier umbrella invocation timed out.
The Darwin queue model passed 76 checks and rejected five deliberate defects;
it does not replace the required kernel tests. The iOS source checks do not
replace an Xcode build with the real generated framework.

The complete local Go source run stopped when the workspace denied physical
network inspection in
`TestControllerShutdownCancelsSpeedLabIntentWithoutRestoringConnection`.
The guardian Unix-socket fixture also encountered a local permission refusal.
Neither result is counted as a pass, and neither gate was removed or weakened.

Publication must use the authoritative `build-all.yml` chain on one exact
`main` SHA, including native tests, all ten packages, ARM64 images and the
verified production compose. Its GitHub delivery is an exact-SHA prerelease.
Physical device behavior, off-LAN interoperability, applicable Apple
provisioning, private server/provider checks, deliberate production deployment,
ASUS fail-open revalidation and final regression retain their separate
[live evidence requirements](LIVE-RELEASE-EVIDENCE.md).
