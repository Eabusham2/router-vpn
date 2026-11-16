# OpenVPN Server suffix acceptance — November 16, 2026

This gate covers the existing schema-five Server graph whose remote worker
contains an imported OpenVPN member and an independent paired SS2022 final
member, without an additional remote WG/AWG prefix. The client's entry remains
outside that remote worker. It continues recovered requirements 214–224 and
addendum 336; it does not establish every requested graph or device scenario.

The source baseline for the completed local validation is
`9dfc56c6c0c61b22f84e686400d3edfb5d8e50e7` plus this unit.

## Required release path

`server-openvpn-direct-encrypted.yml` runs the actual prepared Server worker,
independent provider peer, and driver in owned Linux network namespaces on
AMD64 and ARM64. It is an unconditional reusable job of the existing
`server-node-chain-encrypted.yml`. The release candidate's
`server-ordered-encrypted` job calls that workflow, and the aggregate native
release requires that job. Standalone push and pull-request runs retain their
source path filters; an exact commit is required for standalone acceptance.

The gate requires all fourteen cases:

| Transport | Original final layers | Additional refusal or retirement cases |
| --- | --- | --- |
| TCP | Off, AES-256-GCM, AES-256-GCM + XOR whitening | Wrong Server provider password, wrong final key, failed selected DNS, Stop with an active pending UDP exchange |
| UDP | Off, AES-256-GCM, AES-256-GCM + XOR whitening | The same four cases |

Each accepted case requires actual provider stream and packet counters,
separate public-middle and private-final proofs, selected DNS, and joined
worker/provider retirement. Wrong Server credentials must produce an
authentication refusal without transferring application data. Foreign final
credentials and middle-only credentials cannot reach the final service.

## Original provider and namespace ownership

The reference uses a test-owned `203.0.113.24/32` alias inside its isolated peer
namespace. A narrow opt-in in the existing provider fixture permits only the
captured original literal remote, matching physical address, and two separate
provider credential identities. The ordinary provider fixture retains its
existing loopback boundary.

The reused reference prefix supplies the existing final services. It is not a
member of the product's remote graph and is never its packet carrier. Its
packet and proof counters must remain zero. The source controls additionally
require `NativeCarrierRequired()` to be false and reject both a shared provider
identity and a foreign captured source.

The new namespace program changes only the exact case inventory, selected
test root, and owned alias command. The original process, namespace,
bootstrap, proof, and cleanup bounds remain in force. The native receipt
parser requires exact case selection, complete counters and joins, strict
types, and a complete successful test inventory. Missing, duplicate, skipped,
foreign, or late output cannot produce an acceptance receipt.

## Completed local validation

The actual shipping preparers ran against pristine pinned checkouts:

* Native core: `1ac1a339cb1223e9c70eae14c44411c75033c02d`.
* Xray source: `50231eaff98ccc31b5cbd247a721c16e97fe5ec1`.

The complete source verifier checked **2,809 records** before and after the
build. Their combined identity was
`4dfe3754da27d0de1b10f00053942757797dc966b56fcd6cfbe837726f07af71`.
Compilation used pinned Go 1.26.3, race instrumentation, read-only modules,
the actual native build tags, and the original 600-second compile bounds.

| Actual output | Compile time | SHA-256 |
| --- | ---: | --- |
| Shipping worker | 97.024 s | `984ea348886f0d0fb16bef9d1fe8a04d9aaffef26a0177120abaf44c93addee9` |
| Independent provider peer | 75.150 s | `db09a1177fd67888ae2a73f50e41f2c15153f6d5e127fd0c227d52334f0a3843` |
| Acceptance driver | 48.277 s | `8fe9f7895fa400c1580c1a5be4e7c1832b39bfded9cfc22ad1f0947d93522353` |

Both actual provider source-export cases passed. All fourteen actual source
cases passed, including independent credentials, captured transport, source
refusals and the absence of a remote packet carrier. The existing source/MTU
inventory also passed. Total execution of this compile-and-source mode took
235.090 seconds, with all checked source bytes unchanged. Temporary private
exports and generated executables were removed by the original gate after
their identities were recorded.

The gate's fifteen runner controls passed at this baseline. They cover exact
case selection, receipt types, missing and duplicated output, source ownership,
namespace deltas, workflow inclusion and prevention of compile-only bypasses.

The retained compile/source receipt has SHA-256
`d659aaa41a6b4345085dc58678f64d519b0898e82dbaefeda69b80b2c1ee1ced`;
its log has SHA-256
`69430e5d2c19c9c0665417a2fc53b6e56f844a4ab5e26735778ed5d4af85dca7`.
An earlier copied-core preparation was refused by the existing generated-source
ownership guard. The first pristine compile then exhausted scratch disk space.
Neither attempt counts as a passing build; the successful attempt followed
removal of reproducible compiler-cache archives, without changing source or
test bounds.

## First hosted run and captured-final fixture repair

The first hosted run at `c7f9de2d5a44b1c4ab2012aeaa01a535cb9b49f0`
failed on both architectures before encrypted traffic. Jobs `133174688237`
and `133174688794` rejected the first `tcp/off/original` source because the
fixture compiled an unused loopback WireGuard reference while extracting the
independent final member. The real literal-unicast validation correctly
rejected that reference. The earlier source-only fixture had concealed this
with a substituted WireGuard address; that substitution is removed.

The original final-member builder is now shared with the ordinary fixture,
and the direct fixture calls only that final member. It preserves the actual
provider's credentials, source and final identity without introducing a remote
packet prefix. Source checks also prove that an absent unused reference socket
does not change the final authority. Production validation and encrypted
acceptance requirements are unchanged.

The repaired source passed all fourteen direct cases using the actual TCP and
UDP provider exports, all fourteen ordinary encrypted-source cases, and
sixteen runner tests. Both provider and complete acceptance-driver binaries
were compiled with race instrumentation. A separately compiled causal control
restoring the old full-WireGuard extraction failed the original first case
with the same literal-unicast rejection observed in CI. Source bytes remained
unchanged throughout validation. The retained validation receipt has SHA-256
`9a5ad80c2640fa04dff9ac2c7dde528651ad91db32588c7311dc657c1d4218e1`.
These results establish the fixture repair, not encrypted namespace acceptance.

## Hosted pending transport-counter correction

The direct ARM64 job `133184788625` at
`3b4b5d714d5111739e2148ea7be87fee3e1e51c1` passed all fourteen repaired source
cases, then failed the first encrypted case at its pending-traffic assertion.
The native constructor authenticates the retained OpenVPN transport before
exposing Pending IPC. The independent provider counts raw TCP accepts and
physical UDP reads, so these transport counters legitimately include the
handshake before application admission.

The pending check now distinguishes that control traffic from decrypted
application traffic. It still requires the original closed front, refused
private Router destination, no admitted traffic, zero decrypted provider
streams and packets, and zero middle/final proof, DNS, payload and service
counters. Negative raw counters are rejected. No counter baseline is
subtracted and no production authentication, admission or timeout is changed.

All seventeen runner tests passed. The additional compiled fixture exercises
the actual raw TCP/UDP wrappers with loopback sockets, rejects each forbidden
application counter independently, and rejects three compiled mutations: the
old raw-zero assertion, an omitted decrypted-stream guard, and an omitted
private Router guard. The runner took 4.872 seconds; the complete validation
driver took 6.14 seconds. The frozen two-file manifest has SHA-256
`8ae1d5e822da2536a7001f9d1409d955e39402abd9a3e0d33a6d5bea7e5dafb4`;
the runner receipt has SHA-256
`b439e1188dc1caf868721c9211ba27d73a38d7851195d92d3a104d042c05f681`.
These focused counter tests do not establish OpenVPN authentication or the
fourteen full encrypted native cases. Wrong-password constructor observation
remains a separately bounded fixture correction.

## Captured wrong-password construction observation

At `04d3d3a0`, both hosted architectures passed all six TCP/UDP and
Off/AES/AES+XOR positive cases. Each required Ready, selected DNS, UDP traffic,
zero unused-prefix counters and joined worker/provider retirement. ARM64 job
`133200131385` and AMD64 job `133200131914` then reached the wrong-provider-password
case. Authentication was refused, but the fixture requested an IPC snapshot
while the original constructor still awaited its captured bootstrap deadline.
The ordinary ten-second response limit expired before that constructor returned.

That negative case now observes only the original worker's fixed-vocabulary
construction diagnostic, at or after its captured deadline, with the existing
ten-second response-observation allowance. It requires the exact OpenVPN-owner
deadline failure, no cancellation, a refused snapshot with no receipt, refused
bootstrap and private Router front, a real positive authentication-refusal
counter and zero decrypted application/proof/DNS counters. The original partial
owner must then pass the existing Stop and terminal-join checks. Every other
case retains its existing Pending/bootstrap path and fifteen-second readiness
observation. Production construction, authentication and IPC timeouts are unchanged.

All eighteen runner tests passed in 8.642 seconds. Deterministic refusals cover
early or absent captured deadlines, wrong diagnostic stage or operation,
malformed/missing/cancelled/nondeadline diagnostics, absent or negative
authentication counters and forbidden decrypted destinations. Three compiled
controls separately remove the deadline, authentication or closed-destination
requirement and must fail with their exact witnesses. The frozen source
manifest has SHA-256
`6d044154458cf1f3f6878f5dce292ae4db7ca1732acd5059f94bb788c68a43bb`;
the runner receipt has SHA-256
`1dda830b1d7640e7ab3df2878eda2e83e6384b2628b6b0baa7bdde4a88c784db`.
These helper tests repair the observed fixture ordering; the two wrong-password
and six remaining negative/retirement cases still require native execution on
the published source before the fourteen-case gate can be called complete.

## Acceptance still required

Local compilation and source cases do not establish encrypted network
acceptance. This environment's network namespace setup is denied, so the
local result explicitly has scope `compile-and-source-only` and an empty
native-case receipt list. The required hosted AMD64 and ARM64 jobs must execute
all fourteen encrypted cases on the published source. Actual entry API lease
acquisition, public client adoption, installed-device behavior, private
deployment and physical off-LAN acceptance remain separate requirements.
