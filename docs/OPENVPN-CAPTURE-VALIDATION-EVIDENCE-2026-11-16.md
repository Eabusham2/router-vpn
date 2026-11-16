# Fresh OpenVPN graph validation — November 16, 2026

The current desktop four/eight-member Server/Compare lifecycle test reproduced
an eight-member Compare failure during capture of the original saved choice.
The failure occurred under its unchanged twenty-second operation context, both
with a locally constrained runtime and with the published two-CPU runtime
configuration. A standalone profiled case passed narrowly; it did not erase
the complete-root failure. The profile attributed 1.75 seconds of cumulative
CPU samples to repeatedly JSON-encoding the original OpenVPN graph seal.

## Change and retained authority

Only an OpenVPN-containing `NodeChain` uses the new internal seal domain. Each
read freshly hashes the exact source JSON, configuration and metadata bytes,
with separate named fields and byte lengths. The source identity, complete
proof inventory, selected DNS, physical destinations, original configuration
identity and projection remain in the typed seal. Other graph families keep
their existing representation.

This avoids repeated escaping of already-encoded strings. It does not cache a
validation result, change a connection deadline, remove an original-pointer
check, or replace a fresh native/selected-path observation. The original
OpenVPN owner, provider pair, node identities, connected generation, capacity,
saved choice and joined retirement checks remain intact. The internal seal is
not a field of a serialized launch record; source, configuration, metadata
and public launch identities retain their original derivation.

The existing ownership test first obtains a valid physical-policy observation,
then changes each raw input and every remaining typed field. It also retains
the existing copied/equal/foreign owner, substituted source, DNS, provider pair
and canonical parser refusals. The expanded root passes all 35 records.

## Actual focused validation

Validation used the published `c7f9de2d5a44b1c4ab2012aeaa01a535cb9b49f0`
source plus this three-file code/test change. The actual Go 1.26.3 race image
compiled in 51.694 seconds under the existing 300-second ceiling. Compilation
used one CPU and a 900 MiB memory target; execution used two CPUs and an
1800 MiB target. Each root retained its 120-second test timeout and 135-second
outer bound. The inner twenty-second lifecycle and thirty-five-second saved
choice contexts were unchanged.

All ten focused roots passed **111 records**, without a skip, panic or race:

| Root | Records |
| --- | ---: |
| Desktop prefix runtime, measurement, Last and Stop | 5 |
| Desktop original owner and captured-field refusals | 35 |
| Original OpenVPN source and five-platform projection/reconstruction | 7 |
| Original prefix pointer ownership | 10 |
| Complete-prefix source refusals | 13 |
| Sealed mobile execution projection | 5 |
| Desktop saved-choice runtime reproof | 4 |
| Desktop canonical parser refusals | 13 |
| Fresh Local receipt after joined restore | 7 |
| Unjoined/foreign restore refusal | 12 |

The complete four/eight-member Server/Compare root passed in 35.57 seconds
of test-reported time. Its eight-member Compare leaf, including fixture
construction, passed in 15.18 seconds; the corresponding baseline leaf had
failed at 22.69 seconds. These are observed fixture timings, not an installed
device benchmark. The complete focused runtime phases took 196.357 seconds.

A separately compiled causal control changed only the fresh metadata capture
to an empty value. It compiled in 43.992 seconds, then the unchanged
`native-metadata` refusal case failed with the intended
`foreign physical authority admitted native-metadata` witness in 1.442 seconds.
The positive source stayed unchanged throughout both images and execution.

The positive image SHA-256 is
`e06a7c839f570566e173cbac01121047c849c9b71c033b51149a02126103121d`;
the causal-control image SHA-256 is
`48f03f25cc74344459397720228a8b96a841110e7f32f1d8d69b6b9fea06592b`.
The positive receipt is `openvpn-desktop-validation-cost/positive.json`,
SHA-256 `69fa2d24382c8a77bb0c72d5f7b817247fdded30c564799b29f87ad361903042`.
Its complete source manifest has SHA-256
`f7496747b1f5cc2724a30a1212264ea027411367e25319c5341b36d14f7bb474`.
Earlier failing receipts, unchanged source identities and the profile are
retained in `openvpn-desktop-foundation-validation`.

These are actual shared compiler/runtime results with explicit native-boundary
doubles. The separate desktop native child, installed interfaces, encrypted
provider paths, exact-current packages and physical devices still need their
own evidence. This optimization does not itself enable a new product path or
claim a green release.
