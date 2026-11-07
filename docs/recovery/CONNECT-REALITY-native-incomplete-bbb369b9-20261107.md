# Incomplete CONNECT-to-REALITY native verification recovery record

Prepared: 2026-11-07 UTC
Repository: Eabusham2/router-vpn
Agent: /root/windows_ci
Status: INCOMPLETE RECOVERY RECORD. NOT A PATCH. NOT A FINAL BYTE-VERIFIED TREE.

## 1. What this object preserves

This document preserves the exact facts, source transformation descriptions, paths, commands, and test observations retained after the executor became explicitly unavailable. It does not contain the complete final contents of the fourteen changed files, a complete patch, or every original long Python/Go edit payload. The complete file bytes and complete edit payloads were not retained in functions.store. Context compaction retained the descriptions below, rather than all original executable transformations. Missing payloads must not be invented and presented as the original implementation.

The original workspace is currently unavailable. Its path names below describe where work and evidence were recorded; they do not establish that those files are accessible now. No local executor retry, source reconstruction, or native test attempt was made to produce this record. Only this recovery text is being stored as a GitHub blob. Creating a blob does not commit the fourteen-file implementation or update main.

## 2. Git and ownership checkpoint

Uncommitted native/gate worktree:
  /workspace/scratch/efb65c817f35/connect-reality

Last actual Git checkpoint in that worktree:
  bbb369b9eb03e88c5eb088ab5220dd542b5f4607

Its parent:
  08f349d2ad06c91f01de65b5b4529e3521364463

bbb369b9 is the separate shared/compiler/Android/Swift source-and-host checkpoint owned by /root/apple_ci. It is not a checkpoint of the fourteen native/gate files in this record. There is no known local commit for this fourteen-file unit.

Root published the source-and-host unit as:
  31e4529e1e9772ddbed14682c6df51221fbed518
  tree c3d2e80da2ffc7e4e06dab0b986c536cce1ad183
  parent 6a388af (abbreviated identity retained in the messages)

Root verified fourteen source/test blobs match bbb369b9. Documentation was reconciled with newer measurement context. Root also adopted exactly the three-line Android expected-phase-union addition from the unfinished native work into that source publication. A later recovery must deduplicate that hunk and preserve newer DNS runner expectations; it must not reset current main to bbb369b9.

Apple was the sole Git/staging owner of this shared worktree. The Windows/native agent owned thirteen native/gate paths. Root owned the fourteenth path, deploy/test_desktop_native_toolchain.py, and its exact patch payload is not retained by this agent.

## 3. Complete recorded changed-path inventory

The fourteen pending native/gate paths were:

1. .github/workflows/imported-socks-reality-native.yml
2. deploy/build-native-runtime.py
3. deploy/prepare-desktop-external.py
4. deploy/test_android_multihop_pinned.py
5. deploy/test_desktop_native_toolchain.py [root-owned patch]
6. deploy/test_ios_imported_router_pinned.py
7. deploy/test_mobile_imported_entry_runner.py
8. deploy/test_mobile_imported_connect_xray.py [new]
9. deploy/test_mobile_imported_connect_xray_runner.py [new]
10. mobile/desktop/node_layer_peer_test.go.tmpl
11. mobile/desktop/node_xray_peer_test.go.tmpl
12. mobile/routervpn_imported_entry_native_test.go.tmpl
13. mobile/desktop/node_imported_connect_xray_test.go.tmpl [new]
14. mobile/desktop/node_imported_connect_xray_dns_test.go.tmpl [new]

Known root-owned final fixture SHA256:
  deploy/test_desktop_native_toolchain.py
  cd88eb633010e283ae71b9a971e010884060e7db28348196e61f16dca09c2940

Known build source SHA256 checked by root with that fixture:
  deploy/build-native-runtime.py
  2088b878235ae2d5826063d947ffa19730c8bf4700e5d23aad8bcb6ba6ce689b

These two exact hashes were reported by root after its eleven NativeSocketUIDGate tests passed in 444.603 seconds. They are not hashes for every pending path.

## 4. Retained transformation facts: incomplete, not executable restore payloads

### 4.1 New CONNECT native peer template

mobile/desktop/node_imported_connect_xray_test.go.tmpl was derived from the published mobile/desktop/node_imported_proxy_xray_test.go.tmpl. The recorded extraction began at the function named desktopImportedProxyXraySource and ended before the comment beginning "The callback counts requests only after". That body was renamed and adapted for real HTTP/HTTPS CONNECT, then combined with new header/setup/cases and a physical-owner support test.

The final template was formatted with gofmt. The complete transformation script, appended Go body, and final formatted file bytes are not retained here.

Recorded behavior:
- Both HTTP and HTTPS CONNECT use the actual native HTTP outbound and captured original credentials.
- HTTPS uses the exact captured SNI and trust choice; wrong name and wrong trust require actual typed certificate causes and independently observed TLS server rejection.
- The captured paired REALITY final is compiled by the validated shared imported-entry path. It is not recast as an ordinary imported external final.
- The compiler-only plan in the source loader is closed after validating its nine-string receipt.
- Each per-case compiled plan has registered cleanup.
- The entry stream and final source/credentials remain distinct; final proof/token and selected DNS have independent counters.
- The generic native HTTP outbound has no Close method; the fixture therefore requires lower.empty before registry close after final-engine cleanup.
- Retired owners must not admit another physical dial or authenticated entry stream, including an existing connection that could otherwise bypass a physical-dial-only witness.
- A replacement final proves its own traffic before and after original-owner retirement.
- Existing physical interface/Netlink inventory guards remain intact.

### 4.2 Separate selected-DNS native fixture

mobile/desktop/node_imported_connect_xray_dns_test.go.tmpl was derived from the published mobile/applexray/udp443_traffic_test.go.tmpl. The recorded extraction copied constants/resolver helpers up to the nativeUDP443Physical declaration, renamed them to the desktopCONNECTXrayDNS family, omitted the duplicated Home resolver by starting the resolver-kind loop at one, delegated certificate generation to the optional-SAN helper, and used desktopNodeXrayDNSRoute.

It then appended captured-source, actual pinned-transport, DNS exchange, audit, owner/cancellation, and DoT probe-admission cases. Final Go template formatting used gofmt. The complete appended Go body and final bytes are not retained in this document.

Recorded behavior:
- Both CONNECT protocols carry actual selected DoT, DoH, and DoH3 through the captured REALITY owner.
- Real DNS wire requests and validated responses are required, not merely a QUIC handshake or UDP echo.
- Exact selected server, port, name, trust, path, flow, and owner are preserved.
- Original explicit xtls-rprx-vision-udp443 is captured before compiling DoH3 cases. The ordinary Vision capture is not rewritten after compilation.
- Ordinary Vision first proves Home UDP53 and then actually refuses UDP443.
- Wrong-owner controls first prove the original owner and then remove only the captured live proxy owner, without changing selected DNS bytes.
- Wrong SNI/trust controls require typed QUIC certificate causes, not a generic timeout or refusal.
- Only exact pinned DoT reuse probes ID1/A and ID2/AAAA are separately admitted; application query ID0 remains separately required.
- Invalid probe shapes, foreign IDs, other transports, and unexpected resolver traffic remain rejected/countable.
- Inflight HTTP3 cancellation reaches and joins the original request.
- TCP-only physical entry ownership and drain-before-fixture-teardown remain required.

### 4.3 Minimal helper extensions

mobile/desktop/node_layer_peer_test.go.tmpl:
- desktopExternalInstalledPeerCertificate gained an optional extraNames ...string parameter after the existing latency argument.
- Existing two-argument behavior is preserved.
- The CONNECT fixture can include original captured proxy.example.com as a certificate SAN without changing captured HTTPS SNI.

mobile/desktop/node_xray_peer_test.go.tmpl:
- startDesktopNodeXrayServerWithProof gained an optional selectedDNS ...desktopNodeXrayDNSRoute parameter.
- The added route struct contains network and server strings, a uint16 port, and a private string.
- Optional selected-DNS routes allow only 198.51.100.53 with TCP853, TCP443, or UDP443.
- Network/port tuples must be unique; the private route endpoint must be valid, nonzero IPv4 loopback.
- Default callers keep their previous behavior and blocked default routing.
- No production credentials, private keys, or live private endpoints were substituted.

### 4.4 Native parser registration

mobile/routervpn_imported_entry_native_test.go.tmpl:
- The published tail starting at routerImportedProxyRealityNames was copied/renamed to a distinct CONNECT family.
- New parser parents require exact new inventories for shared sources, actual Android sources, and actual Apple graph objects.
- Existing primary346, CONNECT32, SOCKS, and SS/HY18 registrations remain separate and intact.
- Shared/Android captures are nine-string receipts; Apple captures are graph objects with exact unprefixed filenames.
- Pure native parser flags remain non-race as in the established parser path; actual lifecycle/reference race gates remain mandatory.

### 4.5 New aggregate gate and contracts

deploy/test_mobile_imported_connect_xray.py was derived from published deploy/test_mobile_imported_proxy_xray.py.
deploy/test_mobile_imported_connect_xray_runner.py was derived from published deploy/test_mobile_imported_proxy_xray_runner.py.

Recorded gate requirements:
- Explicitly execute all eight new shared roots and require exactly172 new verdicts.
- Export and validate eighteen distinct source names.
- Execute Android HTTP and HTTPS phases in separate empty owned directories, each with its unchanged240-second producer bound; merge only after duplicate-free exact inventory validation.
- Bind both actual producer origins and exact shared graph bytes.
- Parse shared18 and Android18 in the native mobile gate; the Apple gate independently parses its eighteen graph objects.
- Verify source files before and after preparation/execution.
- Verify exact core protocol/http source set/bytes against the pinned core.
- Verify the exact prepared Xray version/source closure, including the already-published Vision synchronization.
- Require all173 separate native/reference verdicts; preserve old reference matrices.
- Keep full imported physical-interface guards.
- Retain failed and timed-out subprocess diagnostic output before strict verdict rejection.
- Preserve unchanged process/test timeouts, image hashes, source contracts, and negative controls.

### 4.6 Shipping preparation and caller registration

deploy/prepare-desktop-external.py:
- Add both new peer templates to PEER_TEMPLATES, targeting protocol/routervpnamnezia.
- Preserve all existing Darwin/source-copy additions.

deploy/build-native-runtime.py:
- Add the new gate and runner to its source inputs.
- On Linux, run the new reference-only CONNECT gate after the SS/HY reference and before UDP443.
- Recorded new command form:
    python deploy/test_mobile_imported_connect_xray.py <source> --reference-only
- Retain its3000-second caller-stage budget and all earlier stages.

deploy/test_android_multihop_pinned.py:
- Include the two new gate/runner files in source fingerprints.
- Run the new parser stage after the existing imported/proxy stages inside the original owned fallback-JAR TemporaryDirectory.
- Preserve the1200-second caller-stage bound and actual retained JAR lifetime.

deploy/test_ios_imported_router_pinned.py:
- Add a distinct CONNECT_XRAY_PARENT/NAMES stage, exact output environment, actual producer execution, eighteen graph objects and nineteen native verdicts.
- Preserve before/after source and graph identity; clear conflicting child-role env.
- Keep original346, CONNECT32, and proxy18 stages.

deploy/test_mobile_imported_entry_runner.py:
- Add host.CONNECT_XRAY_PHASES to the exact expected default phase union.
- Require the exact new pair connect-reality--http-connect and connect-reality--https-connect.
- This three-line union hunk has already been adopted by root in31e4529e; deduplicate during recovery.

.github/workflows/imported-socks-reality-native.yml:
- Add the mandatory new CONNECT reference stage before UDP443.
- Preserve existing original stages and job60-minute/step50-minute bounds.

deploy/test_desktop_native_toolchain.py:
- Root-owned orchestration fixture adapted the exact new stage sequence, source dependencies, and failure/timeout stop behavior.
- Root reported11 passing NativeSocketUIDGate tests in444.603 seconds.
- Its original full patch is not retained by this agent; recover from root's exact record or the original workspace.

## 5. Exact new capture and verdict contracts

Derived capability:
  vless-stream

This capability does not authorize Shadowsocks UoT or turn paired final assets into a generic imported final.

Capture environments:
  ROUTERVPN_IMPORTED_CONNECT_XRAY_FIXTURES
  ROUTERVPN_ANDROID_IMPORTED_CONNECT_XRAY_FIXTURES
  ROUTERVPN_APPLE_IMPORTED_CONNECT_XRAY_FIXTURES
  ROUTERVPN_REQUIRE_IMPORTED_CONNECT_XRAY_FIXTURES=1

Eighteen exact base names are the Cartesian product:
  {http-connect,https-connect}
  x {off,aes-256-gcm,aes-256-gcm+xor-whitening}
  x {off,aes-256-gcm,aes-256-gcm+xor-whitening}

Name pattern:
  <entry protocol>--reality-vision--<entry Start Layer>--<final Start Layer>.json

Shared and Android captures contain nine original strings/receipts; Android uses its existing android- source prefix. Actual Apple output is eighteen raw compiled graph objects with the exact unprefixed filenames. The primary eighteen captures retain ordinary Vision and HomeUDP53.

Native parser parents:
  TestRouterImportedCONNECTRealitySourceGraphs:19 named verdicts
  TestRouterImportedCONNECTRealityAndroidSourceGraphs:19 named verdicts
  TestRouterImportedCONNECTRealityAppleGraphs:19 named verdicts
  Total57 required parser verdicts.

The new reference inventory records:
- HTTP parent:72 named verdicts.
- HTTPS parent:74 named verdicts.
- Base encrypted traffic:126 leaves.
- TestRouterVPNImportedCONNECTRealitySelectedDNS:25 named verdicts,22 leaves.
- TestRouterVPNImportedCONNECTRealityPhysicalOwner:1 support parent.
- TestRouterVPNImportedCONNECTRealityDoTProbeAdmission:1 support parent.
- Total173 named native/reference verdicts;148 encrypted traffic leaves.

Per-protocol selected-DNS leaves:
  dot853
  doh443
  doh3-udp443
  plain-vision-udp443
  wrong-dns-sni
  wrong-dns-trust
  wrong-dns-route
  wrong-dns-port
  wrong-dns-path
  wrong-owner
  cancel-inflight

The148 traffic leaves and the support cases have different evidence roles. A support/source/compiler pass cannot be counted as a completed encrypted path.

## 6. Verified preparation before final diagnostics correction

Validation directory:
  /workspace/scratch/efb65c817f35/connect-reality-validation

Prepared owners:
  native-desktop
  native-mobile
  native-xray

Pinned core:
  1ac1a339cb1223e9c70eae14c44411c75033c02d

Pinned Xray:
  50231eaff98ccc31b5cbd247a721c16e97fe5ec1

Exact prepared Xray module version:
  v1.260327.1-0.20260711155151-50231eaff98c

Go:
  1.26.3

Canonical desktop sequence:
  relay -> performance -> OpenVPN-close -> desktop -> buffers

Canonical mobile sequence:
  OpenVPN -> multihop -> retained strategy preparation -> Tor -> Apple Xray
  -> exact module pin/replace -> tidy -> module verification

go mod tidy and go mod verify succeeded for the recorded fresh owners; all modules verified. Source before/after identity was unchanged at that verified preparation point.

Last verified pre-correction record inventory:
  repository:2181 records
    SHA256 1b1add64725667b19a34a2c9877115031df9cd8b847e40b3d6d10219d73dd4b7
  desktop:2290 records
    SHA256 a5a1d91f86e417d1f24bd08211110d67d2f820021a0752946a4ab6cc9bfc626b
  mobile:2186 records
    SHA256 ec3c2f03ca4d854df128483c5e2b992f2544c7c63a07bbf90489482a1eb96b88
  Xray:915 records
    SHA256 82adc946efce20bd9db19b5ead92de2c06e4e87fc07bcdf204e97f159a950423

Historical evidence filenames under that validation directory:
  native-preparation.log
  native-preparation-records.json
  native-preparation-receipt.json
  native-source-before.json

These aggregate hashes apply to the recorded state BEFORE the final two-file diagnostic-output correction. They are not a verified final receipt for the corrected Python gate/runner.

## 7. Actual native parser attempt and its limit

The following exact command was recorded:

~~~
/workspace/scratch/router-vpn-toolchain-20261106/go/bin/go test -mod=readonly -json -ldflags=-checklinkname=0 -tags with_wireguard,with_gvisor,with_quic,with_utls,with_openvpn,with_naive_outbound,with_purego ./experimental/libbox -run ^(TestRouterImportedCONNECTRealitySourceGraphs|TestRouterImportedCONNECTRealityAndroidSourceGraphs|TestRouterImportedCONNECTRealityAppleGraphs)$ -count=1 -timeout=90s
~~~

This is a recorded argument sequence, not a shell-escaped recovery script. Invoke it as a structured argv list if rerunning after safe recovery.

The Python owner used the unchanged600-second outer deadline. Executor session94889 ended with exit1 after subprocess.TimeoutExpired reported that the command timed out after600 seconds.

The original helper buffered output until return. The local wrapper did not preserve TimeoutExpired.stdout. No test verdicts were returned in the recorded result. It is therefore not established whether the cutoff occurred during compilation or execution. No lost stdout/stderr has been reconstructed, and this record does not claim a specific compiler error or that zero tests executed.

All57 native parser verdicts remain unproved.

No retry was made. No desktop native compile/reference execution was attempted after that timeout. All173 native/reference verdicts remain pending hosted execution. The retained interface guard must remain; this unit did not return a new desktop Netlink refusal, so no such result should be invented.

Historical paths:
  native-parsers.log
  verify-native-parsers.py
  verify-native-reference.py

verify-native-reference.py was written but never executed. These orchestration/log files are outside the fourteen repository paths.

## 8. Final diagnostics correction: changes and validation boundary

After the timeout, only these two new Python files changed:
  deploy/test_mobile_imported_connect_xray.py
  deploy/test_mobile_imported_connect_xray_runner.py

No production/native template/host/capture, time limit, image guard, or verdict inventory changed in that correction.

The gate gained:
- print_output, handling original bytes as UTF8 with replacement and original strings, without truncation.
- print_timeout, preserving original TimeoutExpired.stdout and stderr when supplied by the helper.
- run_command, delegating to the original SOCKS command helper, printing captured timeout output, and rethrowing the same timeout.
- compile_image, retaining -race -c,600-second owner limit, tags, checklinkname flags, and image guards, while emitting full original output before error.
- execute_image, retaining test limits90/180 seconds and outer bound+15, validating image identity, and emitting full original test events before exact verdict checks.
- build_reference, temporarily wrapping only this gate's private imported SOCKS module helper to retain its result, emit failed/timeout diagnostics once, avoid duplicating successful detector events, and restore the original helper in finally.

Fifteen new runner contracts passed in0.869 seconds after this correction. The prior twelve contracts gained three focused contracts covering:
1. More than24KB of first/last failure-cause output and original timeout bytes survive unchanged.
2. Native compile/test flags, process bounds, and image hashes remain; a changed image is rejected before execution.
3. The private reference helper is restored on failure/timeout paths and diagnostics are emitted once.

Before this correction, the existing imported28, proxy11, and SOCKS16 runner contracts had passed. They were not rerun afterward.

The final read-only receipt/check call attempted to:
- verify only those two receipt input keys changed;
- write a final source receipt;
- rerun the fifteen contracts;
- perform git diff whitespace checks.

It returned no completed result before the executor became unavailable. The functions cell g3:516 was resumed once while still running and then terminated. A final receipt file/pass is NOT confirmed. Do not attach the pre-correction repository/mobile digest to the corrected Python bytes as if final source closure was verified.

## 9. Separately completed source/host evidence

The separate bbb369b9 source/host checkpoint, subsequently published by root as31e4529e, had:
-172 new +433 retained shared named verdicts passing, zero failures/skips/duplicates.
- Shared suite package elapsed62.286 seconds.
- Shared final JSON log SHA256:
  64eccd43a96b45e592940db051f83e2aa3a28eddd5e82dcfd306510e4bd2bfa7
- Actual Android:9 new captures per protocol,1184 checks each, all5 causal recompilation controls.
- Original12 CONNECT exports retained,1162 checks.
- Actual Apple:18 new graph exports,943 checks, including36 selected-DNS/flow/bootstrap cases.
- Complete Apple host suite preserved baseline3231, five112-check REALITY protocol groups including both CONNECT kinds, configured24/336, and DNS44+4.

Historical source/host evidence paths under connect-reality-validation:
  shared-final.jsonl
  shared-final-captures
  android-final-http-connect
  android-final-https-connect
  swift-selected-dns-v2
  source-host-files.json

These passes establish their recorded shared/host scope. They do not establish the pending57 native parser or173 encrypted/reference verdicts.

## 10. Existing published baseline not to redo

The synchronized Vision runtime repair was published as:
  08f349d2ad06c91f01de65b5b4529e3521364463

Pinned proxy.go original SHA256:
  a52ed3b7c16a8b1d0f63be3014454235232bca237dfda08f6a95e0244e3c0f1e

Prepared proxy.go SHA256:
  d4922b395b1396d65a8c4c0778c6fa5f80be64a80d9f5bb42705ab25812957ec

Root independently read exact08f hosted reference run42335645834/job128292447927 SUCCESS:
-37 unique UDP443 verdicts,32 traffic leaves.
- Generation13, shared flow19, native parser6, and exact original-source causal race control.
- Old SOCKS and SS/HY reference stages also passed.
- Single recorded native image:
  d12795411cbbc3f2e795a451263dc361de8d692e344a56f93638e48d3339cd5e

Root later read exact0d4 reference run42337616131/job128298006883 SUCCESS with the same required UDP443 scope and prior stages. These results do not cover the new CONNECT57/173 inventory.

## 11. Recovery and remaining work

Recover the original worktree, repository object data, or complete original edit payloads before claiming restoration of this native/gate unit. This narrative can guide comparison but cannot prove byte equivalence. Reconcile with current main and its newer DNS/proof work; do not overwrite it with the historical base.

A coherent recovery must retain:
- All fourteen paths, including root's independently validated orchestration fixture.
- The complete new57 parser and173 reference inventory.
- Existing primary346/CONNECT32/SOCKS/SS-HY/UDP443 inventories.
- Exact original source/credential/DNS/Start Layer ownership.
- Runtime race guards, negative controls, strict interface inventory, unchanged timeout bounds, and complete diagnostic output.
- Before/after source receipts for the actual final bytes.
- Explicit actual outcome from hosted/native execution before a native pass claim.

No private deployment, ASUS/router change, physical device acceptance, or signing action occurred in this recovery operation.

Root identified a separate shipping desktop gap for future work: production cmd/client has no NewImportedEntry call; the current node-to-node path rejects external entries/finals, and ordinary External Connect requires an external final. The native peer fixtures described here do not implement daily desktop imported-entry admission. That requested protected production path remains future implementation, including actual shared Controller ownership, paired private final assets, selected DNS/protection proof, restoration, and platform physical socket/filter boundaries.

End of incomplete recovery record.
