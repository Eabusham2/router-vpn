# iOS mode selection inside one VPN session

The iPhone/iPad app now runs single Router VPN node AUTO, SMART, CUSTOM,
logical-mode fallback and ALL trials inside one owned PacketTunnel session.
ALL tries complete MAX TLS branches before complete MAX QUIC branches, using
the saved WG/AWG base and fallback policy. It never substitutes a partial chain.
External-node and multihop connections retain their separate captured graphs.

## Captured configuration

The app validates candidate assets and prepares native Xray endpoint addresses
before starting the VPN. It stores the bounded candidate catalog with the exact
node credentials, selected DNS policy, Start Layer assets and interface policy
in the provider configuration. Later strategy IPC contains only references to
that catalog, request identifiers and the owning provider session. It cannot
inject another node, replace credentials or mutate active policy.

Changing saved policy requires the previous connection to finish Disconnect.
SMART may prefer a remembered exact raw mode, but the provider proves that mode
again. A remembered label is never evidence that the current route works.

## Connection and teardown ownership

The provider installs nonempty full-device hold settings before reporting the
system tunnel started. Each trial closes the previous native runtime, preserves
the system VPN interface, creates a fresh runtime and verifies both the private
node identity and the selected DNS route. DNS verification uses the owned native
DNS router without its response cache. The app shows Connected only after both
proofs and final activation have succeeded.

A failed SMART reduction can restore the last proven candidate. Restoration is
reported distinctly from success of the requested reduction. Every replacement
and restoration creates a new runtime epoch, so measurements from the previous
runtime cannot remain current even when its displayed node and mode match.

The native settings queue rejects stale generations before and after asynchronous
NetworkExtension callbacks. Failed runtime teardown remains owned and blocks
another trial. The protected session remains cancellable; explicit Disconnect
revokes pending app startup, disables on-demand reconnect with readback, stops
the owned system VPN and verifies its terminal state. Unknown status does not
unlock profile mutation or become Disconnected.

## Verification boundaries

The required Apple runtime contract executes the shipping wire parser, provider
coordinator, native runtime driver and app orchestration. App/provider fixtures
substitute operating-system handles and controlled node/DNS results. Their
negative controls detect premature Connected state, reused runtime identities,
lost cancellation ownership and changed source accepted during startup.

Separate tests execute the real Swift selectors and Go graph compilers. The
pinned native-core gate exercises actual DNS routing, fresh startup, interrupted
startup and checked close errors. The complete Xcode/IPA release build checks
the real generated native bindings and Apple SDK. These checks do not establish
physical-device routing, leak behavior, network transitions or Apple signing;
those acceptance results require their own device runs.
