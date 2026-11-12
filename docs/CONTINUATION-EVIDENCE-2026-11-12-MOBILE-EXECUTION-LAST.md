# Mobile execution Last launch and capture

## Scope

The mobile ordered execution wrapper now carries an exact saved Last choice
through the original native discovery and adoption path. This is a bridge
component prerequisite for Android and Apple hosts, not device, signing,
physical traffic, or release acceptance.

`RouterNodeChainExecutionFromLast(localLaunchInput, execution, lastJSON)` first
validates the complete canonical original Local launch and requested settings,
then validates the saved record against that preparation. Its execution launch
uses schema 2 with one additional `last` string. Ordinary schema 1 bytes and the
three-field preparation Source JSON remain unchanged. Both schemas retain
canonical equality checks; unknown, duplicate, changed, or downgraded framing
is refused.

`Run` still captures the original CommandServer/StartedService/Instance/Box and
performs fresh discovery. A saved choice must use that engine's
`AdoptLastContext` and the shared Last runtime constructor. A missing capability
or failed adoption cannot fall back to a new Compare run. The persisted record
cannot grant readiness or open application traffic.

`CaptureLastJSON` requires current runtime health, invokes the actual runtime's
Last proof capture, and checks the exact retained controller and native owner
again before returning. The shared runtime retains entered Last observations
until their callbacks join; original close therefore cannot silently discard
an entered capture.

## Verification

The native source cutoff was `1e30d71d3639dfb09f1fc2ef854cb1845173f2c8`
plus this unit, including upstream execution measurement/MTU facades and the
native original TUN readback adapter. A pristine pinned sing-box
`1ac1a339cb1223e9c70eae14c44411c75033c02d` was prepared in the shipping mobile
order. The private Xray preparation staging tree matched all 1,020 files in the
immutable common pinned Xray tree before adopting its exact module replacement.
No checksum or source ownership guard was bypassed.

- All 33 declared mobile execution component roots passed under `-race`, with
  84 passing root/child records: libbox 9.573 seconds, daemon 1.394 seconds.
- All 19 preparation and runner tests passed, including exact prior inventory
  migration and refusal of a partial Last inventory.
- Three new causal overlays independently removed saved-choice replay,
  no-Compare-fallback, and exact-controller capture checks. Each entered its
  intended test and failed with the specified assertion; compilation errors,
  races, and unrelated failures were not accepted as evidence.
- The prepared mobile template inventory and its manifest were unchanged after
  baseline and controls. Source digest:
  `8aad0e1ae2eb56e41c8c25723deaa958aa2bba39f5cc3f1d667d3c9ba785fe2e`.
- Existing 22 mobile ownership/measurement/MTU causal controls remain mandatory
  in the runner. This focused replay executed the three new Last controls.

The Last persisted fixture is explicitly a source fixture, not an invented
prior live proof. Wrapper component tests use actual shared parsers, compilers,
canonical launches and original daemon ownership. Native Last refusal and live
capture callbacks have explicit component boundaries. The separate mandatory
Box Last tests retain actual native discovery/adoption evidence. Host admission
remains a separate integration unit.

SagerNet gobind v0.1.12 generated both Java and Objective-C declarations from
the actual prepared libbox package. Java exposes
`Libbox.routerNodeChainExecutionFromLast(String,String,String)` and
`RouterNodeChainExecution.captureLastJSON()`, both throwing `Exception`.
Objective-C exposes `LibboxRouterNodeChainExecutionFromLast(..., NSError**)`
and `-[LibboxRouterNodeChainExecution captureLastJSON:]`. This verifies binding
generation and signatures, not Android framework linking or Apple SDK/device
execution.
