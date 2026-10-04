# Android native proxy multihop entries

The paired-node Android builder composes Shadowsocks and Hysteria2 entries with
WireGuard, AmneziaWG Fast/Strong, Shadowsocks and Hysteria2 exits inside the existing
Libbox/VpnService owner. Local, Server and Auto retain the exact captured modes,
independent node proofs and entry/exit private credentials. Unsupported helper,
Tor, PQ and MAX compositions are not claimed by this change.

The selected entry profile is validated by `CompileProxyEntry`. Only an owned
TCP+UDP authenticated native outbound is accepted. Entry TLS trust is inlined
from its own asset before exit files are staged, so identical certificate
filenames across nodes cannot replace either node's trust. Existing proof lanes
1098/1099 remain distinct and follow the selected entry/exit graph.

Proxy entries have no invented packet interface MTU. Fixed entry policy owns the
real shared TUN, and `MultihopMTUProfile` captures that policy for later optimizer
work. Conflicting fixed settings fail before any private session is staged.

Both Android entry pickers, pending permission restoration, active runtime
restoration, and saved/live entry identities recognize the added transports.
No source node bundle is rewritten by graph preparation.

## Reproducible source checks

Run `python3 android/test_android_multihop_graph.py` with Go, JDK 17 and the real
Android JSON implementation (`ANDROID_JSON_JAR`). It executes shipping Java and
shared Go compilers and tests all ten proxy-entry/exit pairs under three execution
choices, credential/trust separation, fixed MTU capture, source immutability and
failure-before-staging. `ROUTERVPN_ANDROID_GRAPH_FIXTURES` optionally exports the
actual prepared and execution graphs with generated test certificates, not live
node credentials, for native parser checks.

Also run saved mode, Java syntax, multihop source and session identity contracts.
These host tests do not prove APK type checking or physical Android network,
permission, lockdown, transition, public-exit or reconnect acceptance. Those gates
remain separately required on the exact release commit.
