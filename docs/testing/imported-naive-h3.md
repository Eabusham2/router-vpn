# Imported entries with a paired Naive H3 final

This source unit adds the existing paired Naive H3 final to the Local imported
entry graph. It preserves the existing twenty runtime profiles and sixteen
logical choices. It does not change the default SMART AUTO, IPv6, Home AdGuard,
Start Layer, or AUTO requirement settings.

## Captured path

The shared constructor, Android daily/Speed Lab path, Apple selection and
PacketTunnel path, and desktop daily/Speed Lab preparation retain these seven
concrete imported wire variants:

| Imported entry | H3 carrier |
| --- | --- |
| SOCKS5 | Authenticated UDP association owned by the original TCP control |
| Shadowsocks 2022 | Original authenticated datagrams |
| Hysteria2 | Original authenticated QUIC path |
| WireGuard | Original captured peer, keys and packet endpoint |
| AmneziaWG | Original captured peer, keys, parameters and packet endpoint |
| OpenVPN TCP | Original native OpenVPN packet endpoint over its TCP wire |
| OpenVPN UDP | Original native OpenVPN packet endpoint over its UDP wire |

Each entry and final independently keeps Off, AES-256-GCM, or AES-256-GCM plus
XOR whitening. The seven wire variants and nine layer pairs form 63 graphs per
producer. XOR remains an obfuscation stage with authenticated encryption.

HTTP CONNECT and HTTPS CONNECT cannot carry this required lower QUIC path.
They are refused before H3 capture; adding a false UDP capability or changing
the final to H2 does not make the requested H3 path supported. Their existing
H2 support and its explicit compatible resolver policy remain available.

The final retains its exact native `naive` transport, `quic: true`, UoT-v2,
credentials, TLS identity and trust. Entry credentials never substitute for a
paired final's identity or private proof token. The original entry and final
Start Layers remain separate owners in the sealed graph.

## DNS, lifecycle and desktop protection

Home AdGuard UDP is retained. Selected DNS queries use the final's `proxy`
route. The separate bootstrap resolver uses the original entry or the final's
captured Start Layer, as appropriate. No public resolver is substituted to make
the graph compile or connect. Native graph controls reject H2 substitution,
selected TCP substitution, selected DNS through the entry, and bootstrap DNS
through the final it is supposed to resolve. The desktop fixture retains its
own captured `10.88.0.53:53`; the shared and mobile fixtures retain their
independent `192.168.50.133:53`. Reader expectations come from those fixed
producer contracts. A graph cannot authorize its own substituted resolver.

The original captured source, generation, protection, IPv6/LAN policy, physical
entry tuples and MTU restoration survive preparation and replay. The path does
not gain Server/Compare authority from an imported public entry. Wrong source,
credentials, final transport, UoT version, TLS policy or detour are refused.

The desktop producer has two distinct outputs for the same 63 captured paths:

- The portable output is the original sealed graph for the shared native parser.
- The protected output is the actual Windows launch projection containing the
  original `DesktopImportedPolicy` and its inert owned SOCKS constructor.

Every matching completed or reused desktop bundle checks all 63 portable
graphs with its own executable. A matching Windows bundle additionally checks
all 63 protected projections. Parsing does not activate a BFE owner, open an
association, or prove protected traffic; the separate Windows companion owns
that execution boundary. The Windows-only constructor guard is preserved.

## Recorded validation

The following results belong to their recorded source snapshots. Current-SHA
native builds, publication and physical-device acceptance remain separate.

| Boundary | Observed result |
| --- | --- |
| Shared compiler and ownership | 627 race verdicts across ten roots; 63 original captures; no failures or skips |
| Android H3 producer | 63 captures, 9,175 assertions and six causal refusal controls |
| Apple H3 producer | 63 graphs and 3,974 checks; surrounding saved-selector and startup suites retained |
| Desktop capture, dispatch and restoration | 188 race verdicts across eight roots, including the existing H2 producer; no failures or skips; 63 portable and 63 protected exports |
| Matching package, workflow and aggregate contracts | 76 tests passed with the original ordinary, packet, OpenVPN, PQ, XHTTP and H2 inventories retained |
| Native parser | All 252 original graphs accepted by the pinned Libbox reader; all fourteen deliberate faults rejected at their required boundaries |
| Native encrypted loopback and association ownership | 37 race verdicts passed: 24 H3 literal/credential/trust/DNS verdicts and thirteen actual SOCKS control/relay/layer/cancellation verdicts |
| Windows companion | AMD64 PE cross-compilation passed with all six required roots and the child-only peer symbol; execution remains required on Windows |
| Windows peer buffer fixture | Actual pinned Shadowsocks 2022 UDP witness passed both DNS and ordinary-datagram leaves; original zero-headroom fixture failed both at the real authenticated writer |
| Matching native build orchestration | One modeled test exercised all six host targets and passed in 132.915 seconds; this is not native compiler or WFP execution |
| Runner boundaries | Eleven corrected native-reader contracts, ten Windows companion contracts and fourteen workflow contracts passed |

The final desktop run used base `8be50dbfbd16173980ce672aa91dfba2cee65cc7`
plus the integrated H3 source. Its captured Go/configuration source bytes were
unchanged during the run, which took 157.673 seconds including compilation.
An earlier new fixture inherited IPv6 Off from the ordinary external-entry
fixture while expecting On at both ends. That assertion correctly failed;
only the new H3 fixture was corrected to select On for both captured profiles.

The native protocol run used a fresh preparation from the frozen integration
on parent `cd08371bdf17a9a598c8581e2498fd5f920e43aa`. Its source-input digest was
`7902aa16edf77218fb6eb2274f8863e962af323fd4dae4d0e461094e32fce92c`, and its
prepared-input digest was
`1d470f375b4d12c8d94810e426bc03d77a3c2c2ad91de20cd1638625f1e01160`.
The unchanged 11,915,768-byte native library had SHA-256
`23109c55b08829bb1a68682a61a64852b1bbf243753b153cbd8f6e4ea2c05294`.

The first parser attempt accepted the shared, Android and Apple inventories
but rejected every desktop graph because its test reader incorrectly required
the other producers' Home address. The correction changes the test reader and
runner; the original desktop graph and production DNS policy stay intact.
The corrected reader accepted all four original inventories, and a new control
substituting both desktop resolver rows was rejected. All 7,400 selected
protocol compiler inputs remained byte-identical, so the 37-verdict protocol
receipt remains tied to its original image; it is not a second protocol run.

The Windows AMD64 diagnostic used the original WFP test-scope overlay and
produced a 107,947,520-byte PE image with SHA-256
`d61455d0a1a3e0dd675a8b604ace655fc9913cfad039355b6f0a763aa7c8c40f`.
This Linux cross-compilation used CGO disabled and did not include the native
PQ tag. Symbol inspection is not executable inventory discovery, BFE/WFP
execution, ARM64 compilation or physical-device acceptance.

## Required native and release gates

The separate `imported-naive-h3-native.yml` workflow exports actual Android,
Apple and desktop producers and requires the pinned native reader, protocol
loopback and imported peer inventories. It is a mandatory authoritative release
dependency. Its inventory is additional to the existing H2 and other imported
families; a smaller or renamed inventory cannot replace them.

The reader checks all 252 graphs from four producers, five renamed-axis controls,
four native-library seal controls, and five QUIC/DNS-ownership controls. The
imported peer inventory requires 529 leaves, including each layer pair and
source, credential, route, DNS, cancellation and replacement controls. A separate
actual SOCKS association component exercises live control/relay ownership and
all three entry-layer settings without claiming a physical interface proof.

The unchanged physical-owner witness could not capture its interface locally:
the environment denied Netlink access. The physical peer inventory compiled,
but that attempted witness did not establish protected traffic. The first
scratch invocation also omitted its required original source seal and stopped
at source preflight; it is retained separately from the subsequent Netlink
failure. Neither attempt is counted as a passing physical test.

Windows AMD64 and ARM64 must each execute all 88 companion verdicts on their
matching host. Package gates must also use the actual shipping executable and
its original build environment. These mandatory hosted checks, the full
physical peer inventory and exact-SHA release publication remain outstanding
at source publication.

## Remaining requirements

This unit does not complete imported Server/Compare execution, additional-hop
composition, a Home UDP path through stream-only CONNECT/H2 lower transports,
or remaining Unix protected host integration. Current release publication,
physical selected-path/leak/reconnect/network-transition checks, off-LAN
interoperability, signing/distribution, private deployment and ASUS acceptance
still require their own exact-source observations.
