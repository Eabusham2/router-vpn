# Imported entries with a paired PQ REALITY final

This continuation admits the existing `reality-pq-vision` runtime as a paired
**Local** final for the imported entry families already admitted to ordinary
`reality-vision`. It uses the existing in-process native Xray transport and
retains the original imported entry, paired final, credentials and independent
Start Layers. It adds no logical mode, external engine process or second system
VPN.

## Exact scope

| Imported label | Concrete wire variants in this gate |
| --- | --- |
| `socks5` | Authenticated SOCKS5 |
| `shadowsocks` | Captured Shadowsocks 2022 |
| `hysteria2` | Captured Hysteria2 |
| `http-connect` | HTTP CONNECT |
| `https-connect` | TLS-authenticated HTTPS CONNECT |
| `wireguard` | Captured WireGuard |
| `amneziawg` | Captured AmneziaWG |
| `openvpn` | TCP and UDP, independently captured |

The eight labels give nine wire variants. Each has three entry Start Layer
choices and three final Start Layer choices: Off, AES-256-GCM and
AES-256-GCM with XOR whitening. The separate PQ inventory therefore contains
**81 graphs per producer**. These entries use the same exact compiler and
capture/restore boundaries as the corresponding ordinary REALITY graphs.

The final must retain its original PQ VLESS encryption, UUID, REALITY settings,
Vision flow and complete native asset map. An ordinary asset map relabeled as
PQ, missing encryption or assets, a foreign layer/route, or a different final
mode is refused. DNS and the paired final identity/token remain owned by the
final hop. The original Vision UDP443 policy remains explicit: selecting PQ
does not grant an otherwise forbidden UDP443 flow or encrypted-DNS bootstrap.

Android's service admission now recognizes the exact
`multihop-imported-reality-pq-vision` session ID. Android and Apple builders,
selectors and temporary SpeedLab forms preserve the selected PQ final.
Desktop capture, retained launch and dynamic catalogs include the exact final;
the daily and temporary catalog contract requires the complete seven-final
set, including all six previously supported finals.

## Evidence layers

| Gate | What a passing gate proves | What remains outside that evidence |
| --- | --- | --- |
| Shared compiler | 81 exact captures, 144 source/downgrade refusals, and 90 selected-DNS/flow cases | A running network session |
| Actual Android JVM producer | Shipping Java capture, staging, restore and service admission against the real shared Go compiler; 81 exported receipts | Android VPN permission, JNI packaging and device traffic |
| Actual Apple Swift producer | Shipping Swift capture, selection and restoration against the real shared Go compiler; 81 exported graphs | Network Extension entitlement and device traffic |
| Desktop producer | Actual retained capture/launch, final DNS, physical-owner preservation, restore and source refusal; 81 exported graphs | A privileged installed native helper or OS TUN |
| Pinned native parser | All 324 graphs from four independent producers construct and close through the actual Libbox `CheckConfig` registry | Started transport, public egress or device acceptance |
| Completed/reused native bundle | All 81 desktop PQ graphs pass the actual matching bundle's `sing-box check -c`, with unchanged graph bytes and bundle receipt | Protected public startup, started transport or installed-device acceptance |
| Pinned encrypted loopback | Real native ML-KEM matching-key traffic, wrong-key refusal and restored-key traffic; TCP/UDP and retained connection-owner regressions | Imported physical entry routing or an OS TUN |
| Imported physical peers | Original imported provider, owned physical tuple, independent layers, final DNS/identity and failure/cancellation controls | Production router, signed mobile application or installed device acceptance |

The parser checks the complete separate filenames and binds each name to its
actual transport, OpenVPN TCP/UDP choice, CONNECT TLS policy and both Start
Layers. Five native negative controls copy valid graphs under incompatible
names and require rejection at those exact boundaries. Duplicate or renamed
valid graphs cannot satisfy the inventory. Missing, extra, linked, skipped,
failed or duplicate evidence is rejected.

Observed host verification in this continuation includes Android's 12,034
positive assertions across all 81 PQ captures, all six causal mutations
(including the old service allowlist), Apple's 2,078 PQ assertions and 407
isolated selector assertions, and desktop's 127 race-enabled verdicts across
four roots. The native parser passed 328 verdicts for the 324 graphs plus the
five renamed-source controls. The encrypted loopback passed 14 race-enabled
verdicts across three roots, including actual wrong-ML-KEM-key refusal and
restoration. Readiness detector controls are checked independently.

These counts refer to the bounded continuation runs. Each native gate emits
its own source/binary fingerprint; the counts are not an acceptance receipt for
every later rebased commit or release head. A complete native bundle and its
verified Rust archive were unavailable locally, so the completed/reused bundle
gate has modeled orchestration checks here and requires actual matching-host
CI execution.

These are bounded source, host-producer and reference results. Hosted physical
peer acceptance, installed desktop/mobile behavior and live router acceptance
must be tracked separately. A local interface/Netlink denial must remain a
failed physical attempt; it must never be converted into a skipped or synthetic
passing route proof.

The local imported-peer image compiled, but the physical gate failed. An
isolated original `socks5/off/off/success` witness identified the actual
boundary: `route ip+net: netlinkrib: operation not permitted`. The physical
lookup and protection checks remain mandatory in the hosted gate. This local
result supplies no physical imported-peer or packet-entry acceptance.

## Reproduction and required CI

Use Go 1.26.3 and the exact prepared desktop core. The preparers and gates bind
the sing-box revision `1ac1a339cb1223e9c70eae14c44411c75033c02d` and Xray revision
`50231eaff98ccc31b5cbd247a721c16e97fe5ec1`, check projected source bytes and record
binary/source hashes. The parser's extra reader is a declared test-only Go
overlay; no mobile runtime or replacement production source is installed by
the gate.

Create separate empty directories for each producer. With an actual JDK and
Android JSON implementation, export Android's nine explicit PQ phases:

```sh
ROUTERVPN_ANDROID_IMPORTED_PQ_XRAY_FIXTURES="$ANDROID_PQ" \
python3 android/test_android_imported_router.py \
  --phase pq-reality--socks5 --phase pq-reality--shadowsocks \
  --phase pq-reality--hysteria2 --phase pq-reality--http-connect \
  --phase pq-reality--https-connect --phase pq-reality--wireguard \
  --phase pq-reality--amneziawg --phase pq-reality--openvpn-tcp \
  --phase pq-reality--openvpn-udp
```

Export Apple with a working Swift 6/Foundation toolchain and desktop through
the shipping Go test package:

```sh
ROUTERVPN_APPLE_IMPORTED_PQ_XRAY_FIXTURES="$APPLE_PQ" \
  python3 deploy/test_ios_tor_profile.py
ROUTERVPN_DESKTOP_IMPORTED_PQ_XRAY_FIXTURES="$DESKTOP_PQ" \
  go test -race ./cmd/client -run '^TestDesktopImportedPQReality' -count=1 -timeout=180s
```

Then require all host inventories in the native parser, followed by the
separate encrypted loopback and physical imported-peer gates:

```sh
python3 deploy/test_imported_pq_workflow.py
python3 deploy/test_mobile_imported_pq_xray_runner.py
python3 deploy/test_mobile_imported_pq_xray.py "$CORE" \
  --android "$ANDROID_PQ" --apple "$APPLE_PQ" --desktop "$DESKTOP_PQ"
python3 deploy/test_mobile_imported_pq_xray.py "$CORE" --loopback-only
python3 deploy/test_mobile_imported_pq_xray.py "$CORE" --reference-only
```

The reusable `imported-pq-reality-native.yml` workflow requires the actual Swift
artifact and all nine Android phases plus desktop exports before parsing all
four inventories. The focused ordinary REALITY workflow retains its original
gates and then calls this separate PQ workflow. Release-candidate aggregation
also requires it. Native Linux builds retain the ordinary gates and add the
separate PQ contract, parser, loopback and physical-peer stages. PQ files and
counts never replace or satisfy an ordinary REALITY export set.

`build-native-runtime.py` also runs `verify_imported_desktop_pq_configs` after
both fresh completion and reuse on each matching Windows, macOS and Linux
x64/ARM64 host. This separate gate requires all 82 original desktop producer
verdicts, keeps all 81 emitted graphs unchanged while invoking the completed
bundle's actual executable, and revalidates the full bundle receipt afterward.
Existing ordinary, packet and OpenVPN bundle inventories remain mandatory.

## Remaining boundaries

Protected desktop startup and imported-source replay through the public native
command/Box path remain a separate implementation dependency at this unit's
evidence boundary. The desktop client marks imported launches with
`HOMEVPN_NODE_PHYSICAL_REQUIRED=1`, and the Windows helper invokes
`routervpn-node`; the corresponding imported native factory, source replay and
physical-policy admission are being integrated separately. This unit's desktop
results establish the producer, shared graph, native registry and protocol
extension. They do not establish a fully working protected desktop launch or
replace that native helper integration and its acceptance tests.

This unit does not complete imported **Server** or **Compare/Auto** execution,
imported XHTTP/composite finals, arbitrary hop graphs, or all original project
requirements. Unsupported combinations remain refused by the compiler.
Physical/device acceptance requires its own exact-source evidence, and live
router or production deployment still requires separate authorization.
