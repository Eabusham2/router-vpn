# Original encrypted Local OpenVPN owner evidence

The required Linux native build now runs `test_node_chain_openvpn_encrypted_local.py` against the canonically prepared core. Its original `TestOpenVPNExecutionEncryptedOriginalLocal` image exercises a three-member Local WG → OpenVPN → SS graph with the shipping Box, concrete OpenVPN endpoint, mutual TLS and encrypted data channel, final SS transport, selected resolver, private/public identity checks, and actual joined Box retirement. This change adds tests and required build wiring; it changes no production admission, transport or deadline.

The application TUN/default-interface monitor, the first physical tuple's loopback mapping, and the discovery advertisement are explicit component fixtures. The advertised Server source has independent provider credentials and pairing keys, but this gate does not claim an actual Server lease. It does not prove installed TUN/kernel protection, full execution Run/Last, longer Local packet prefixes, AWG, or application admission. The current real Server gates remain independently required.

## Exact native matrix

One retained race image passed all fourteen cases, with one exact root and one exact selected child per invocation (28 strict test records):

| Cases | Required observed behavior |
| --- | --- |
| TCP and UDP, each final Off/AES/AES+XOR (6) | Original connected endpoint receipt; encrypted discovery/adoption and Local selection; final private and TLS public identities; selected DNS; exactly one public HTTPS byte; retained generation and joined retirement. |
| TCP and UDP, wrong provider password (2) | Actual authentication refusal, zero decrypted stream/packet deliveries, and retained construction identity for independent candidate eligibility. |
| TCP and UDP, failed selected DNS (2) | Actual private/public final identities first, then an actual captured public-name DNS query and refusal; zero public download bytes and no selected-DNS proof. |
| TCP and UDP, foreign final identity (2) | Actual final health response with the wrong identity, no subsequent final/public origin proof or download. |
| TCP and UDP, reconnect (2) | A real endpoint reconnect produces a later generation; the engine refuses substitution for the retained connected receipt. |

The fixture reads the original resolver tag, UDP address/port and final detour from the sealed Local config. It changes only that one reference peer's physical DNS destination to a test-owned UDP responder. Both `example.com` and the captured public measurement hostname are supported. An independent query counter proves that the public lookup reached this responder through the encrypted final owner; malformed/foreign queries are refused. A/AAAA handling retains the captured IPv6 policy. The responder and original Box both have bounded joined cleanup.

Each successful traffic case recorded final-private=1, final-public=1, captured-public-DNS=2 and public-download=1 for the exercised resolver policy. Failed-DNS cases recorded actual captured DNS with no download. These are actual traffic assertions, not replacement lookup return values or ambient resolver results.

## Actual compiled controls

Each control changes exactly one retained production assertion through a Go overlay; the production files remain unmodified. A control is accepted only with its exact failure witness, complete failing root/child/package verdicts, and no race, timeout, panic or cleanup failure.

| Removed requirement | Compiler / 300 seconds | Rejection process / 75 seconds | Witness |
| --- | ---: | ---: | --- |
| Original source pointer | 64.420 | 1.433 | `equal Local source replaced original Box owner` |
| Retained connected receipt | 96.394 | 5.220 | `reconnected Local endpoint replaced retained original receipt` |
| Original Box join | 84.451 | 6.682 | `unjoined Local Box manufactured original retirement` |

The original baseline compiler passed in 120.671 seconds. All fourteen baseline processes passed in 3.695–6.362 seconds. Bounds remain 300 seconds per compiler, 60 seconds per Go test, 75 seconds per runtime process, 20 seconds for the operation, and 45 seconds for the original provider lifetime. The ten required runner tests reject omitted, duplicate, skipped, reordered, foreign, false-terminal and cleanup-contaminated evidence, as well as omitted or mis-targeted build wiring.

## Source and retained failures

The executed core was canonically prepared from `4ae6a3c4fc9a1480ba4c730cfb94a5d3891b0e9e` with pinned native commit `1ac1a339cb1223e9c70eae14c44411c75033c02d` and pinned Xray commit `50231eaff98ccc31b5cbd247a721c16e97fe5ec1`. The final fixture was frozen at private commit `be0b0e12`; baseline image SHA-256 is `2fd5b474d9dd079e68560c25ecb991c6985ba8b51a3b218ac383dab32f831319`. The full prepared-core receipt remains explicitly on that source. The original OpenVPN native owner/public/lifetime paths and shared OpenVPN source files were unchanged through `70e6b344`; later candidate/Hysteria additions do not turn this into an exact-current whole-core run.

The baseline receipt SHA-256 is `66e6673f87c4e11ce8aa0f28055377e92e55a8d539cd03d32cd2554f41566467`; the three-control receipt SHA-256 is `83b659228d1f2e53af22528df53444220a472be0582c91c17492947830bb9769`. They retain every source/overlay/image/log identity and process result under `openvpn-local-encrypted-validation`.

Earlier conservative 1-CPU/800-MiB compiler attempts reached their unchanged 300-second local bounds and produced no image; they remain recorded as failures. A quiet 2-CPU/GOGC50/1800-MiB build completed under the same bound. The first native image then correctly rejected the fixture's use of the generic parser on a sealed launch. The corrected fixture uses the actual typed launch reopener and requires a distinct pointer with identical source/config identities before testing the ownership refusal. The original image/failure and all logs remain retained. Completed causal images and the superseded image were losslessly compressed, round-trip verified and retired with ownership/terminal receipts; the successful baseline image remains available.

The required current-head native build must execute this matrix and all three controls again. This evidence is a bounded Local encrypted component proof, not a complete release verdict.
