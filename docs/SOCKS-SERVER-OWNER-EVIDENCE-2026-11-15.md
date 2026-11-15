# Typed SOCKS server suffix: source and validation boundary

This change adds the administrator-captured schema-3 server suffix for one
original SOCKS5 import followed by its independently paired SS2022 final. The
entry remains the original WG, AWG Fast or AWG Strong identity that authenticates
the separate server lease. It creates no synthetic server packet endpoint.

The generic server compiler remains restricted to its existing paired and
imported-SS families. `NewNodeChainSOCKSServerPolicy` and
`NewNodeChainSOCKSServerPlan` are distinct typed entry points. Their descriptor
and request use separate v3 digest domains. The private operator compiler,
staged-source restoration and offline validation capture select that family
explicitly. Operator plans reject reuse of the client's paired identity as the
server peer, including the final SS member's independent WG identity material.

The compiled suffix keeps the original SOCKS credentials and literal endpoint.
Its public-path proof has no invented Router node identity or private API
credentials. The final retains its own private proof, key, endpoint and selected
DNS. The physical compiler records only the fixed TCP control tuple: the UDP
relay does not exist before SOCKS negotiation and is not a firewall exception
or a guessed static endpoint.

The native worker installs a caller-local SOCKS constructor, captures the actual
Box outbound and owns its physical dialer. Only the original library operation
can acquire its permanent TCP control and one authenticated negotiated UDP
socket. The retained association owns late handles, failed closes and the
joined control/UDP retirement. A bounded adapter exposes only the same TCP
half-close through native tracking wrappers; reads, writes and full close
remain on the original tracked connection. Copied captures, reconstructed policy objects,
foreign leases and canceled observers cannot acquire or retire the original
owner. The server worker restores the typed source, checks that same owner on
observation, and drains it before the original Box close can finish.

The private authenticated client/server front keeps its existing UoT-v2 wire
contract. The independently imported SOCKS suffix uses actual SOCKS UDP
association; its SS final does not acquire CONNECT's TCP-only/UoT transport.
The existing CONNECT family remains separate.

## Local validation

The focused shared/operator race suite passed against this change:

```sh
go test -race -p=1 ./internal/mobilemultihop ./internal/multihoprelay ./cmd/router-agent \
  -run 'TestNodeChain(SOCKSServer|CONNECTServer|SOCKSCapture|CONNECTCapture)|TestOrdered(RegistryParserCapture|PrivateCompilers)' \
  -count=1
```

This includes WG/AWG Fast/AWG Strong with authenticated and anonymous SOCKS,
source/capture/family/identity refusals, independent plan keys, private compiler
rejection without secret output, restoration, and existing CONNECT regressions.
The nine `deploy/test_server_node_chain_preparation.py` tests passed. Clean
canonical native preparation succeeded at the pinned core and Go toolchain.
The actual native owner and worker race suites also passed:

- `protocol/routervpnnodesocks`: `TestOriginalSOCKS*`, including retained control
  EOF, one retirement budget, failed half-close and concurrent close. The new
  server tests use the actual `route.ConnectionManager.TrackConn` over loopback
  TCP and require its manager entry to survive until remote EOF, then disappear
  on exactly one original full close. Missing half-close, cyclic/deep wrappers,
  typed-nil wrappers and a failed tracked half-close retain refusal/cleanup
  evidence. Completed successful and failed `Capture.CloseContext` results
  remain identical across 256 already-canceled caller retries.
- `cmd/sing-box`: `TestServerChain*`, including front credentials, pending proof,
  joined close, late native returns and original worker resource ownership.

## Required hosted encrypted check

The final source compiles with the native race build. The encrypted component
suite is mandatory in the Linux branch of `deploy/build-native-runtime.py`:

```sh
go test -race -p=1 -mod=readonly -tags="$NATIVE_TAGS" \
  -ldflags=-checklinkname=0 ./protocol/routervpnamnezia \
  -run '^TestRouterVPNNodeSOCKSServer' -count=1 -timeout=120s
```

`TestRouterVPNNodeSOCKSServerEncryptedOwnership` requires the real native suffix,
actual nonloopback-bound SOCKS control and negotiated UDP sockets, original
SS2022 ciphertext, paired private proof, public proof, selected DNS and joined
close for all three entry identity modes. Its companion refusal suite covers
wrong SOCKS credentials, authentication downgrade, a domain-valued relay,
wrong final SS key, cancellation with a live association and a foreign lease.
The suffix Box uses the real native interface monitor; no fake physical dialer
or empty platform interface inventory substitutes for that construction.

These encrypted tests could not execute their path in the local command
sandbox. All nine cases stopped during host interface discovery with
`route ip+net: netlinkrib: operation not permitted`. The observed host addresses
from `/etc/hosts` also failed actual TCP and UDP binds with `EADDRNOTAVAIL`, and
a UDP connect to a documentation destination, without sending a payload,
failed with `ENETUNREACH`. No skip, fallback address, weakened production guard,
or successful encrypted result was substituted. Hosted execution must pass
before claiming encrypted suffix acceptance.

## Remaining scope

This is a server-suffix source/owner unit. It does not complete the shared client
SOCKS Server/Compare execution policy, desktop/mobile adapters, remote-worker
end-to-end acceptance, device acceptance, or any live router deployment.
Longer imported server suffixes, multiple imported members and arbitrary
imported positions remain separate unresolved work. Local source, build,
hosted execution, packaged artifacts, physical devices and live evidence remain
distinct; this document makes no project completion claim.
