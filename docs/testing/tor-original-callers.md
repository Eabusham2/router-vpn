# Tor preparation retains its original callers

This follow-up completes the public preparation and prelaunch caller boundaries
left open in [the comparison identity guide](routechoice-identity-caller.md).
It preserves the selected graph and the existing proof, cleanup and adoption
requirements. It does not establish physical Tor or device acceptance.

## Shipping behavior

- **Original request and operation.** Public Connect, external-entry Connect,
  Compare and temporary Speed Lab preparation retain the original request or
  intent together with the captured connection operation. Initial registry
  locks, selection and predecessor capture, resolution, runtime preparation,
  preflight and prelaunch observe that caller. Either original lifetime can
  cancel work. A recorded Disconnect intent rejects adoption even while its
  cancellation callback is held. See
  [the captured caller](../../cmd/client/desktop_tor_caller.go) and
  [its causal controls](../../cmd/client/desktop_tor_caller_context_test.go).
- **Independent restoration.** The Speed Lab coordinator passes its existing
  `restoreCtx` through restart to the first restore-entry lock. Restoration
  remains independent of the cancelled temporary-test HTTP request, while its
  own expiry or Disconnect still stops admission. This preserves the existing
  separately owned cleanup allowance; it does not create a replacement budget.
- **Verification and private inputs.** Shipping runtime preparation uses the
  contextual runtime callback. Native and Tor version subprocesses inherit
  the original caller and retain their existing 10-second and 5-second limits.
  Cancellation joins the actual verification child. Private input capture,
  hashing and staging remain synchronous and retain caller checks and file
  identity protections. The capture reader returns literal `io.EOF` for a
  healthy completed read, while cancellation at read completion retains its
  context cause. This avoids treating successful hashing as an EOF failure.
  See [runtime preparation](../../cmd/client/desktop_tor_prepare.go),
  [Tor verification](../../cmd/client/bundled_tor.go) and
  [reader controls](../../cmd/client/desktop_tor_capture_reader_test.go).
- **Endpoint observations.** The shipping resolver uses the real
  `physicalNetworkIdentityContext` and `net.DefaultResolver.LookupNetIP`.
  The first network observation uses the original caller. Resolution and the
  final observation share the same remaining 10-second lookup context.
  Cancellation, expiry, changed networks and late results reject the lookup
  without replacing its original failure cause. The
  [endpoint controls](../../cmd/client/desktop_tor_endpoint_context_test.go)
  exercise each observation boundary.
- **Retained live monitor.** Periodic health checks use the captured contextual
  network observer under the existing live-monitor authority. Completing the
  HTTP request does not retire a valid connection. Monitor cancellation and
  joined retirement retain their existing implementation; this unit verifies
  observer selection and continuing ownership after HTTP completion. The
  [monitor controls](../../cmd/client/desktop_tor_monitor_context_test.go)
  witness a real fixture child through a completed monitor cycle and reject
  failed or foreign observations.
- **Initial prelaunch expiry.** A missing caller is rejected separately from
  an expired original caller. Cancellation or deadline expiry preserves
  `errTorPrelaunchRejected`, `errConnectionOperationCancelled` and the actual
  context cause. No admission callback or child starts, and the exact prepared
  workspace and DNS/native ownership are cleaned through the existing owner.
  [Prepared-owner controls](../../cmd/client/desktop_tor_prelaunch_cause_test.go)
  cover cancelled, expired and missing callers, including idempotent cleanup.

## Recorded execution

The following focused groups ran in the Go 1.26.3 race-instrumented controller
at local integrated snapshot
`7060aae83d6d15d135d6f510af5447ba7b7b4e51`. A verdict here includes a root or a
subtest; these counts are not distinct product requirements. Every listed
group had zero failures and zero skips.

| Evidence log | Test roots | Passing verdicts |
|---|---:|---:|
| `tor-caller.jsonl` | 9 | 32 |
| `tor-endpoint.jsonl` | 4 | 18 |
| `tor-monitor.jsonl` | 2 | 9 |
| `tor-durable-choice.jsonl` | 5 | 23 |
| `tor-admission-regression.jsonl` | 4 | 29 |
| `tor-capture-reader.jsonl` | 3 | 11 |

The separate existing cancelled-preparation case at that snapshot exposed the
lost connection-cancellation error identity. The final initial-expiry repair
was then executed at local snapshot
`f89a1caf387308ce6026e54a32ac1ac97fbf0553`: **15 passing verdicts across four
roots**, with no skips. These were the new prepared-owner cause/cleanup root
and the existing Speed Lab cancelled/replaced preparation, start-failure/success
handoff, and changed-private-directory roots. The receipt
`linux-tor-prelaunch-race.log` has SHA256
`6312282b5389e0a8e24bffcb56e375cf3b0c2d17f4982fc5a9b5c753e50536f3`.

The same `f89a1caf` snapshot also cross-compiled both `cmd/client` and
`internal/windowscontroller` test executables for Windows AMD64 and ARM64;
the resulting PE machine headers matched their targets. This is compilation
evidence for that integrated source, with Windows execution tracked separately.

Byte comparisons between those snapshots covered Tor source/tests,
`bundled_native.go`, `external_profile_connect.go` and Speed Lab source/tests.
Only `tor_bridge_prelaunch.go` and the added cause/cleanup test differed in that
comparison. The final guard and related prelaunch tests also matched local
fix `f519b5d2c8e12f5dd07df6417423770204d0a8b2` byte for byte. This bounds the
component comparison; it does not mean the complete earlier matrix ran again
at the later snapshot or that the two complete trees are identical.

On `f519b5d2`, the pure Python
[native shipping audit](../../deploy/test_native_shipping_audit_gates.py)
passed all **34** methods and the
[Windows release contracts](../../deploy/test_windows_release_gates.py)
passed all **22**. The new prelaunch root is already selected exactly once by
the mandatory `^TestDesktopTor` partition on both Windows architectures in
the native-contract and authoritative release workflows. No optional gate or
production timeout relaxation was added.

The isolated Tor publication was additionally checked on top of the preserved
`fb924d48` branch state: all **32** shipping-audit methods and **43** Tor
circumvention audit methods passed. The two extra shipping-audit methods in
the integrated snapshot belong to the separate protected imported-path unit.
Thirty-three changed files matched the final integrated snapshot byte for byte.
The contextual Tor callback changes in the two shared Speed Lab files also
matched; those files contain additional imported-host work in that snapshot.
The two Python audit files retain the corresponding independent unit scopes.

## Acceptance boundary

These tests establish executable caller, ownership, private-file and fixture
process behavior. Controlled network observers do not prove a real Tor circuit.
Local physical-network capture still encounters the recorded Netlink permission
denial; affected physical cases remain failed evidence, not passing or skipped
acceptance. Windows kernel execution, device and off-LAN networking, current
full-release publication, signing and private deployment require their own
evidence. None is inferred from this focused controller record.
