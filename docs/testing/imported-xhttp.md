# Imported entries with a paired XHTTP REALITY final

This continuation admits the existing `reality-xhttp` mode as a paired **Local**
final through the original imported entry. Android, Apple and desktop use the
existing shared graph compiler and in-process native Xray transport. The daily
and temporary selectors expose this exact final; desktop catalogs now require
eight finals, retaining the seven previously supported choices.

## Exact graph and policy scope

The separate XHTTP inventory contains nine concrete imported transports:
SOCKS5, Shadowsocks 2022, Hysteria2, HTTP CONNECT, HTTPS CONNECT, WireGuard,
AmneziaWG, OpenVPN TCP and OpenVPN UDP. Each transport has three entry Start
Layer choices and three independent final Start Layer choices: Off,
AES-256-GCM, and AES-256-GCM with XOR whitening. This produces **81 graphs per
producer**, with four independent producers supplying **324 native parses**.

Capture and restore retain the original imported credentials, paired final,
API/token identity, selected final DNS, MTU/protection selection, source
receipt, and both Start Layers. The final's native graph retains its complete
user settings, hybrid `mlkem768x25519plus.` encryption, REALITY settings,
XHTTP path/settings and FinalMask. Only the existing compiler's owned local
listener and final-layer endpoint adaptation is allowed. A changed path or
FinalMask under an old source receipt fails validation.

Admission remains exact. `reality-xhttp` requires an absent or empty VLESS
flow and the existing `xhttp` or `splithttp` network spelling. Its settings
require an absolute path and `auto` mode. Raw TCP, Vision flows, alternate
download endpoints, foreign settings, ordinary encryption and relabeled PQ
Vision assets are refused. The existing raw `xray.json` asset form remains
supported; absence of an optional `sing-box.json` wrapper alone is not an
error. A present malformed wrapper is refused.

The existing pinned Xray implementation chooses stream-one for auto XHTTP
with REALITY. Its server checks the normalized path prefix, so the live
negative control uses a disjoint path rather than a child of the valid path.
The empty-flow XHTTP path can carry UDP/443, including selected HTTP/3 DNS.
The ordinary and PQ Vision flow restrictions remain unchanged. Resolver
ownership, hostname bootstrap, certificate/SNI checks and the original caller
deadline still apply; adding XHTTP does not authorize a direct resolver path.

The same connection owner must complete the original public path proof,
selected final DNS proof and paired final identity proof before Connected. A failed
proof, missing DNS capability, cancellation, close, owner replacement or
network change cannot leave the captured path healthy or reusable. Server,
Compare/Auto and arbitrary additional hops remain outside this extension.

## Evidence boundaries

| Gate | What it executes | What it does not establish |
| --- | --- | --- |
| Shared compiler and retained controller | Exact independent graphs, downgrade/source refusals, selected-DNS policies, real HTTP proof endpoints and cancellation/owner controls | The controller fixture models its native engine and physical observation |
| Android producer | Shipping Java capture, service admission, staging and restoration through the real shared Go compiler; 81 original receipts | Android VPN permission, packaged JNI or device traffic |
| Apple producer | Shipping Swift capture, selection and restoration through the real shared Go compiler; 81 original graphs | Network Extension entitlement, packaged framework or device traffic |
| Desktop producer | Actual capture and retained launch graph, final DNS, physical-owner preservation, MTU restoration and source refusal | A privileged installed helper or OS TUN |
| Native parser | All four producer inventories through the pinned Libbox `CheckConfig` registry, with exact graph/name binding | A started transport or public egress |
| Encrypted protocol loopback | Matching traffic, wrong disjoint path and wrong valid ML-KEM key refusal, restored traffic, selected DNS and empty-flow UDP/443 | Physical imported-provider routing or an OS TUN |
| Imported physical peers | Original imported provider, frozen physical tuple, both real layers, final DNS/identity and cancellation/failure controls | A production router or signed installed application |
| Completed/reused native bundle | All 81 desktop graphs checked by the matching completed bundle executable, with original bytes and receipt revalidated | Protected public startup or device acceptance |

The native parser requires every separate original file once. It binds the
filename to the actual imported transport, CONNECT TLS policy, OpenVPN wire
transport and both layer axes. Five controls substitute valid graphs under
incompatible names and require refusal by the compiled native reader. Missing,
extra, duplicate, linked, skipped or failed evidence never satisfies an
inventory. XHTTP files cannot replace an ordinary or PQ inventory.

The encrypted refusal controls require traffic to reach the original owned
underlay and inspect fresh diagnostics from the same encrypted peer. Wrong
path must produce that peer's path-validation refusal, and wrong ML-KEM key
must produce its ML-KEM handshake failure. Matching traffic is restored after
each fault. Malformed key encoding separately fails native startup before an
outer socket opens. These checks use the existing caller deadlines, without
retrying under a renewed budget.

Host producer verification for this continuation includes all 81 Android
graphs and 13,262 assertions, six rejected causal mutations, all 81 Apple
graphs and 3,201 assertions, and the isolated Apple selector's 407 assertions.
Those exports preceded the clean rebase onto the published readiness and
selector repairs; the frozen producer behavior and captured bytes are checked
again by the final native parser. Their counts do not claim a packaged mobile
run or acceptance of every later commit.

The final frozen source passed 833 race-enabled shared verdicts across 14
roots, including 452 XHTTP verdicts and the retained ordinary/PQ boundaries.
Desktop passed 145 race-enabled verdicts across four roots, including its
81-graph capture and actual daily/temporary catalog checks. The final native
parser passed all 324 graphs, giving 328 verdicts across four roots, and all
five renamed-graph controls were rejected. The encrypted loopback passed all
32 verdicts across three roots, with the three readiness-detector controls
also passing. Parser and loopback retained the same source and prepared-source
receipts throughout. Each native stage emits its exact source, prepared-source
and executable fingerprints.

No local physical imported-peer or installed-device acceptance is claimed.
An interface/Netlink denial remains a failed physical attempt. No fallback,
skip, simulated route or relaxed protection check can turn it into acceptance.
The final-source imported-peer package compiled with both XHTTP roots present.
Its original `socks5/off/off/success` witness failed at
`route ip+net: netlinkrib: operation not permitted`; the source and executable
receipts stayed unchanged. This is a blocked physical witness, not a passing
reference matrix.
The completed/reused bundle orchestration has executable modeled checks for
all six matching Windows/macOS/Linux x64/ARM64 hosts; actual completed-bundle
acceptance remains a matching-host CI gate.

## Reproduction and mandatory CI

Use Go 1.26.3 and the exact prepared desktop core. The preparers pin sing-box
`1ac1a339cb1223e9c70eae14c44411c75033c02d` and Xray
`50231eaff98ccc31b5cbd247a721c16e97fe5ec1`, verify projected source bytes and
retain the original physical guards. Use separate empty export directories.

```sh
ROUTERVPN_ANDROID_IMPORTED_XHTTP_XRAY_FIXTURES="$ANDROID_XHTTP" \
python3 android/test_android_imported_router.py \
  --phase xhttp--socks5 --phase xhttp--shadowsocks \
  --phase xhttp--hysteria2 --phase xhttp--http-connect \
  --phase xhttp--https-connect --phase xhttp--wireguard \
  --phase xhttp--amneziawg --phase xhttp--openvpn-tcp \
  --phase xhttp--openvpn-udp
ROUTERVPN_APPLE_IMPORTED_XHTTP_XRAY_FIXTURES="$APPLE_XHTTP" \
  python3 deploy/test_ios_tor_profile.py
ROUTERVPN_DESKTOP_IMPORTED_XHTTP_XRAY_FIXTURES="$DESKTOP_XHTTP" \
  go test -race ./cmd/client -run '^TestDesktopImportedXHTTP' -count=1 -timeout=180s

python3 deploy/test_imported_xhttp_workflow.py
python3 deploy/test_mobile_imported_xhttp_xray_runner.py
python3 deploy/test_mobile_imported_xhttp_xray.py "$CORE" \
  --android "$ANDROID_XHTTP" --apple "$APPLE_XHTTP" --desktop "$DESKTOP_XHTTP"
python3 deploy/test_mobile_imported_xhttp_xray.py "$CORE" --loopback-only
python3 deploy/test_mobile_imported_xhttp_xray.py "$CORE" --reference-only
```

`imported-xhttp-native.yml` is a reusable mandatory workflow. Its Apple job
uploads the actual Swift exports; its Linux job requires that artifact, all
nine Android phases and the actual desktop exports before parsing all four
inventories. Separate loopback and physical reference stages must then pass.
The focused workflow retains its ordinary and PQ jobs and adds the XHTTP job.
Release aggregation independently requires the XHTTP workflow; the actual
aggregate checker rejects removed, substituted or conditional dependencies.

Matching Linux native builds require the separate XHTTP contract, parser,
loopback and physical reference stages after the original gates.
`verify_imported_desktop_xhttp_configs` also runs after both fresh completion
and reuse on every matching desktop host. It requires all 82 original
producer verdicts, exactly 81 unchanged files and the same completed bundle
receipt before and after actual `sing-box check -c` execution. The ordinary
26-file, packet 108-file, OpenVPN 108-file and PQ 81-file bundle inventories,
their verdicts and their existing deadlines remain mandatory.
