# Router VPN Speed Lab

Router VPN includes a dedicated **Speed Lab** for full path testing. It is separate from lightweight live telemetry and from the Auto-MTU optimizer.

Speed Lab measures real public Internet transfer performance and latency. It never converts RTT into Mbps and never copies one hop's result onto another hop.

## Results

A completed test reports:

- idle latency: min, median, average, p90, max, jitter, successful/failed probes;
- real download Mbps;
- download-loaded latency and download bufferbloat delta;
- real upload Mbps;
- upload-loaded latency and upload bufferbloat delta;
- transfer duration/rounds and whether Auto stopped after throughput stabilized;
- exact path identity used for the result;
- for supported multihop paths, independently measured entry/exit private-path RTT and independently measured entry/exit download/upload Mbps.

Public transfer measurement uses Router VPN's built-in HTTPS Speed Lab against Cloudflare's fixed speed-test edge. Requests disable caching/compression, refuse provider redirects, verify byte counts, and use multiple adaptive transfer streams so fast paths are not artificially capped by one TCP flow.

Loaded latency is sampled independently while the corresponding download or upload traffic is running. The reported Mbps value is always computed from transferred bytes and transfer time.

## Current config — default

**Current config** is the default test mode.

If Router VPN is connected, Speed Lab measures the path that is actually running. It captures the live session/node/runtime/base/multihop graph and re-validates that identity between measurement phases. Selecting another node in the UI does not relabel the current path.

If the active session or graph changes during the test, the result is discarded instead of being attributed to the wrong path.

If Router VPN is disconnected, Current config measures the raw system Internet path.

## Temporary config

Desktop platforms and Android can create a temporary test-only path while Router VPN is disconnected. Depending on the platform's real dataplane, choices can include:

- system direct;
- one Router VPN node;
- Router VPN multihop;
- direct external/custom exit;
- Router VPN entry to a supported external exit;
- logical mode including SMART AUTO, AUTO and CUSTOM;
- WireGuard/AmneziaWG base choice where applicable;
- multihop exit transport where supported;
- CUSTOM required layers;
- DAITA-like, Jumbo and AUTO encrypted/obfuscation requirements where that dataplane supports them.

Temporary tests are transactions, not profile edits. The path is built and proved, measurement runs, the path is torn down, and the previous disconnected setup is restored. Temporary Speed Lab suppresses durable ranking/startup/usage side effects. Persistence/cleanup failures are surfaced instead of being described as a successful restore.

The desktop controller also restores the previous private profile store before measurement so the test-only selection cannot become the user's saved selection.

### iPhone/iPad

iOS/iPadOS has a native Speed Lab for the actual PacketTunnel path plus supported temporary system-direct, Router VPN and external paths. It also has a private recovery journal so interrupted temporary tests can restore persistent state on next launch.

Desktop-style multihop remains unavailable in iOS Speed Lab until the Apple PacketTunnel dataplane can actually create and prove that graph. The UI explicitly shows it as unavailable; it is never simulated.

## Auto/default and custom time

Default timing is **Auto**:

```text
minimum 4 seconds / direction
maximum 12 seconds / direction
```

After the minimum, Speed Lab can stop early when recent throughput rounds are stable. Otherwise it continues to the maximum.

Choose **Custom** to set independent Min and Max sliders:

```text
1 second <= Min <= Max <= 60 seconds
```

Longer windows are useful when testing unstable high-speed paths, long multihop chains, or behavior that ramps slowly. Shorter windows reduce test traffic.

## Multihop per-hop proof

On desktop controller paths, per-hop measurements are made against each hop's authenticated private Router API/benchmark service through the **same actually launched graph**. Android performs the equivalent measurement using its process-owned active VpnService graph.

For every hop Router VPN re-checks the live session/graph identity. Entry and exit values are independent observations:

```text
ENTRY • private RTT • real down Mbps • real up Mbps
EXIT  • private RTT • real down Mbps • real up Mbps
```

Router VPN does **not**:

- subtract pings to invent hop latency;
- copy exit Mbps to the entry;
- use configured/saved preferences as proof of the running graph;
- preserve a result after session/path identity changes.

If one optional hop metric is unavailable, the UI reports the reason instead of displaying a fake zero. A valid end-to-end public Speed Lab result can remain useful while an optional private hop benchmark is unavailable.

## Relationship to other performance data

Keep these separate:

- **live RTT** — lightweight current-path telemetry;
- **durable node latency** — larger saved node benchmark;
- **Speed Lab** — dedicated public throughput + idle/loaded latency test;
- **per-hop Speed Lab metrics** — authenticated private transfer/RTT through the active multihop graph;
- **Auto-MTU optimizer throughput** — bounded candidate comparison used only for MTU selection.

None of those measurements is relabeled as another.

## Safety rules

Speed Lab must always preserve these invariants:

1. Current results belong to the exact running path, not the mutable selected node.
2. Temporary choices do not become saved preferences.
3. Temporary path cleanup is mandatory and cleanup failures are visible.
4. In-flight results are rejected if session/profile/graph identity changes.
5. Throughput is measured from real bytes/time, never inferred from latency.
6. Per-hop measurements are independent and graph-bound.
7. Unsupported platform graphs stay unavailable rather than showing cosmetic success.
