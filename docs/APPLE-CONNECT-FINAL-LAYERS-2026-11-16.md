# Apple CONNECT final Start Layers

The iPhone/iPad capture, reopen, editor and saved-profile paths now retain an
independent Off, AES-256-GCM or AES-256-GCM plus XOR whitening selection on the
paired final node of a Server/Compare HTTP or HTTPS CONNECT chain. The imported
CONNECT node still requires its original Off policy. The original final private
configuration and SS UoT-v2 service remain mandatory; the public capture delegates
their validation to the typed shared compiler instead of imposing the obsolete
final-Off restriction.

This consumer depends on the original-owner native implementation published in
`e31d7d20d5862ecd86c3a3807ce752889d7138d8`. It does not introduce a second system
VPN or substitute an ordinary network lookup for the selected final DNS path.
The existing ordered-chain size, paired-prefix, transport, credential and
current-source constraints remain in force.

## Executed source and lifecycle evidence

The following gates ran with Swift 6 and the actual Go 1.26.3 shared source
compiler. All retained their existing per-child bounds and the 300-second
aggregate caller bound. Their source snapshots did not change during execution.

| Gate | Observed result | Elapsed seconds |
| --- | --- | ---: |
| Original capture and generic consumers | 1,721 assertions and six compiled source controls passed | 209.151 |
| Complete-prefix/final-layer controls | Seven positive assertions and seven compiled controls passed | 103.081 |
| Layered control and retained restoration | Actual source/reopen and same-winner restoration passed; four compiled intent/winner/process/release controls rejected their intended faults | 142.478 |
| Layered public launch and editor | Launch, cold Last, editor save, changed-source/cancellation checks and the original compiled source control passed | 88.689 |
| Layered profile Add/Load/Update/Delete | Separate four- and eight-node phases each passed 686 shipping-Swift assertions; all four original compiled controls rejected their intended faults | 90.916 |

The additive layer cases cover both supported encrypted finals, retained Local
and Server winners, preserved selected private final keys and UoT-v2 transport,
and rejection of a changed final layer during preference saving. Four-node cases
exercise independently selected encrypted entry and final layers; eight-node
cases preserve the existing packet budget with Off on preceding nodes. Original
complete-count/Off matrices remain separately mandatory. Profile tests exercise
both HTTP and HTTPS, Server and Compare, original node references and transactional
failure behavior. Saving preferences never reports a native connection.

The provider replies, NetworkExtension manager, private-store I/O and platform
interfaces in these executable source tests are explicit fixtures. These passes
establish the shipping Swift callbacks and shared compiler behavior, not an
Xcode package, installed VPN, physical-device networking or signing result. The
authoritative native build and device acceptance remain separate evidence.

An initial layered-control run failed against the old shared final-Off guard.
That failure was retained. The shared/native prerequisite was repaired and
independently validated before the successful layered run and publication of
this consumer. No timeout or negative acceptance condition was relaxed.

## Publication composition

The tested consumer paths were composed onto `e31d7d20` without replaying the
older Apple/OpenVPN bridge changes. The eight privately staged prerequisite
paths were checked byte-for-byte against their now-published versions. All
thirteen consumer paths retained their tested bytes except the native builder,
where the additive input registrations were merged with newer upstream work.
The workflow/runtime-selection contracts require all three new layer gates;
the compiled negative controls are included in those gates. The integrated
workflow contract passed its fourteen tests.

Retained complete-log SHA-256 values:

| Gate | SHA-256 |
| --- | --- |
| Capture | `29f1365f0f0846e32b2044b8b5c82f47716c70b293ba9160d51c0643786ac178` |
| Prefix controls | `0bd07dbc3d106a550c1cde1a4f9b9ca22db6500f68e994ca86eafc0e41120f4a` |
| Layered control | `ca59c57a8d15193c4b395362138e7b6f8bbee9e52b9de2efaf8b00ac0513ba8c` |
| Layered launch | `c5948c7af276c931fe6a6e16dc013b0ca7f20394f7bb12a88a57d836a5bfb748` |
| Layered profiles | `f97b87f78658541d1664035f24803aed1ba95c051104106b0824be4e03e9fa60` |
| Earlier rejected layered control | `c383db3653283ad7997c8cf1c4c2468c345e8eb8fdf517ad915032b291cba535` |
