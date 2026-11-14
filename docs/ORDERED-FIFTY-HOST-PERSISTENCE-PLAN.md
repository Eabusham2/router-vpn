# Typed ordered fifty-response host integration

Status: source proposal, uncompiled. This plan records missing shipping work; it does not claim Android, iOS, desktop, persistence, device, or encrypted-native acceptance. The MTU proposal is a separate dependency. Existing failed CONNECT Run receipts remain authoritative failures until an unchanged actual rerun passes.

## API and lifetime contract

The host first obtains and retains its one `RouterHopMeasurement` from the proved typed SOCKS or CONNECT plan. Existing duplicate-owner rejection stays unchanged. It then calls `RouterNodeChainSOCKSNewLatencyBenchmark(plan, server, measurement)` or `RouterNodeChainCONNECTNewLatencyBenchmark(plan, server, measurement)`. The explicit measurement argument must contain the same service already retained by the exact plan and server. The factory never creates a service. The typed factory validates the exact host before publishing the facade attachment. Every factory error returns nil and leaves the host service unclosed and unattached, so Java gomobile may throw without hiding cleanup ownership. Swift may use its normal NSError bridge; it must not create a replacement measurement service. Once successfully returned, a failed facade Close retains that original handle for retry.

`RouterOrderedLatency.Start(request,nodeID)` selects exactly one original ordered member. `Cancel` and `Drain` retain the original admission pointer and completion channel, not merely a reusable request string. `Close` cancels/joins only that facade's request and detaches only after join. A failed close retains the same handle for retry. Closing or dismissing this view never closes the host's throughput service. The original plan/server owner closes the service during connection retirement. Another facade can attach only after the previous exact facade joined and detached.

The fifty worker and throughput worker share the original service exclusion. Native typed `BeginMeasurementContext` excludes active MTU and retains its claim through socket/worker/resource drain. Authorized MTU continuation retains the host service; its measurement engine reacquires the freshly proved typed runtime and requires the same engine, session, network, source and config identity. A paused or unproved runtime cannot admit samples. Do not rotate the service or classify a saved receipt as a proof of the new reader.

Before replacing history, obtain the final `StatusJSON`, require the requested ID, `complete=true`, `drained=true`, no failure, and one expected ready benchmark result. Then obtain `SavedJSON(nodeID)` and validate its captured identity. Publication is allowed only after the original worker and release callback have joined. Failed, stale, partial, timed-out and cancelled work preserves the prior committed receipt.

## Three separate measurement meanings

| Operation | Source and interval | Output and use |
|---|---|---|
| Existing ordered throughput | Six idle response samples plus download/upload and loaded-response observations | Current cumulative path throughput readout; not a fifty-sample ranking |
| New ordered fifty | Fifty successful original private authenticated responses, including connection, or middle public HTTPS responses after TLS | Median, min, average, 10% trimmed mean, p90, max, jitter; historical record for the exact ordered prefix |
| Existing external-final/direct-node benchmark | Existing independently admitted native external final or disconnected direct TCP scope | Existing stores and sort authority stay unchanged |

Private results use `routed-private-response-including-connection` and an empty endpoint. Public-middle results use `routed-https-response-after-tls` with the exact existing one-byte public endpoint. Require attempts=50, failed=0, samples=50, finite positive response values and coherent ordering/means. Keep credentials, private API addresses and the raw native identity out of persisted receipts. Do not relabel either interval as ICMP RTT or infer a link between individual servers.

## Host implementation points still required

### Android

`AndroidNodeChainSession.java` owns the typed native plan and `newHopMeasurement()`. Retain one `RouterOrderedLatency` beside that captured service; use the explicit three-argument factory after proof and service adoption. CONNECT host dispatch remains separately required; never send a typed input to the ordinary factory.

Extend the retained `LayeredVpnService.HopMeasurementOwner` flow with a separate ordered-fifty capture/action carrying original plan, native server/service, home/native sessions, path generation, exact source/config hashes, position and node ID. Keep `AndroidMTUMeasurementGate` held through the exact facade drain and commit. Reuse the cancellation and owned-delivery pattern in `AndroidNativeHopMeasurement`, but add a distinct typed action instead of passing the node ID into external-final `runLatency`/`startLatency`.

Add a dedicated renderer/action alongside `AndroidHopMeasurementDialog`; its throughput renderer deliberately rejects benchmark rows and should continue to do so. UI dismissal/backgrounding cancels and joins the facade and keeps retry ownership on a failed drain. It does not close the retained `RouterHopMeasurement`.

### iOS

`RouterVPNLibboxEngine.swift` and the typed host retain the native measurement object. Add a separate facade property and a distinct provider command for ordered fifty. Use the exported top-level factory with the captured measurement object and explicit NSError out parameter; factory failure leaves no facade attachment or cleanup result. `PacketTunnelProvider.swift` must dispatch a separate operation, with request/session/node/position and exact source binding, instead of broadening existing external-final `hop-measure-latency-start`.

Add a separate typed model/view path beside `IOSHopMeasurements.swift`. Its existing `Benchmark.valid` accepts the external-final public HTTPS meaning; do not broaden that guard globally to accept private ordered samples. Continue to reject benchmark payloads in the ordinary throughput summary. App/extension cancellation and app disappearance retain the original request until native drain, then release the MTU hold.

### Desktop

The current native `node_chain_socks_measurement.go.tmpl` is a throughput request/result protocol. It captures one state per request and closes that service after the request; it is not yet a durable borrowed-facade owner. Add an explicit typed ordered-fifty operation and bounded receipt schema, with generation/request/deadline and complete native Ready capture. Preserve the existing source/config file identity checks, original proof/reader/MTU capture, cancellation files, protected process/socket observer and worker drain.

Either retain one per-connection measurement service with dynamic current-state reacquisition and unchanged five-field identity, or bind a facade to the exact original per-request service until that request joins. Never reuse a service whose captured reader state was superseded by MTU. The desktop app adapter must not synthesize a generic NodeChain or external-final request from the typed policy. Linux, Windows and Darwin host commands and installed/native evidence remain separate requirements.

## Durable persistence contract still required

Introduce a distinct bounded ordered-prefix history store; do not write the direct-node `latency_*` fields, external-final ranking store, candidate results, or readiness fields. Key records by source SHA256, config SHA256, position, node ID, kind and measurement meaning. Store the complete validated `OrderedLatencyReceipt`, including request, timestamp and hashed original generation. Reconnect history remains visibly historical; current route/owner proof is always obtained independently.

For Android use the existing private bounded atomic-file and readback pattern (`AndroidPrivateFileStore`), with a separate ordered-history schema. For iOS use the existing coordinated private JSON store and app-group delivery model (`IOSPrivateJSONStore`), retaining the extension's request/session/source receipt. For desktop use the existing private application store with serialized compare-and-swap against the captured selected source/config and measurement generation. These are proposed integration points, not completed storage implementations.

The commit transaction must recheck the current host request/cancellation generation, selected source/config and original path identity under the host's existing serialization. Persist only the exact native saved payload that passed strict parsing. Write atomically, read back exact bytes, and acknowledge only after durable success. On a failed or superseded write, restore/remove only the exact bytes this transaction wrote; never overwrite another writer's newer result. A cancellation before adoption, changed source, disconnect, app restart during pending work or storage failure leaves previous history unchanged. Historical loaded records must pass size/schema/identity/numeric/timestamp checks and never grant native admission or sort eligibility in a different metric domain.

## Required validation before claiming shipping completion

- Shared tests: all fifty original responses, final-sample failure, TLS/source failure, cancellation before original release, duplicate/copied facade refusal, stale reused request IDs, close timeout/retry, repeated facade attachment, and throughput still usable after facade Cancel/Close.
- Shared typed composition: same retained measurement service after authorized reproof, unchanged five-field identity, and rejection while proof is paused. Native MTU and actual encrypted path execution remain separate gates.
- Native facade tests: exact plan/server/service pointer, foreign service refusal, failed factory validation with fresh retry, MTU exclusion, copied source and original lifetime replacement. Generated Go/Java/Objective-C symbols must compile from the frozen source.
- Host tests on each platform: distinct operation routing, exact selected member and metric, MTU hold through late socket/worker cleanup, app disappearance and stale delivery, no throughput-service close, and original owner retirement.
- Persistence tests on each platform: successful atomic adoption/reload, failed fiftieth sample, cancel before/after drain, source/config/generation changes, malformed metrics, secret exclusion, interrupted write, readback replacement, concurrent newer writer, and restart retaining previous history.
- Actual encrypted/native and installed/device evidence must retain original inventories and deadlines. No parser fixture, source plan, component double, or old failed Run is acceptance for this work.
