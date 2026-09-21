# Apple native runtime continuation — September 21, 2026

## Scope and acceptance

The user requires the requested capabilities across Windows, macOS, Linux,
Android and iOS/iPadOS. An accurate unavailable message is a safety boundary,
not delivery of that capability. This continuation preserves that requirement;
it does not redefine all-device parity as a source-marker or compilation check.

## Implemented in this continuation and its immediate predecessors

- The pinned Apple WireGuardKit fork includes the native AmneziaWG backend.
  Raw WireGuard and generated AmneziaWG Fast/Strong use that actual adapter.
  The parser passes Jc/Jmin/Jmax, S1–S4 and H1–H4 to the engine; it rejects
  incomplete AWG profiles, family-label mismatches, overflowing header ranges,
  duplicate singleton fields, duplicate peers and ambiguous interface sections.
- Logical selection honors the saved WG/AWG base and the explicit fallback
  policy. A missing preferred engine cannot silently select the other base when
  fallback is disabled. AUTO considers allowed alternatives in deterministic
  catalog/base order. Strict route-lockdown still prevents unproved runtime
  transitions; this is not claimed as full strict SMART AUTO implementation.
- CUSTOM, SMART simplification and last-good restoration pass their exact raw
  runtime to the connection function. They no longer re-resolve AWG Fast through
  the logical Raw tunnel picker and accidentally start WireGuard instead.
- Runtime replacement stops if the previous tunnel's teardown or on-demand
  preference update cannot be verified. Only Router VPN-owned configuration
  records are eligible for these operations. Node changes during asynchronous
  preparation invalidate that connection attempt.
- Fixed MTU reaches native WG/AWG, Router Libbox and external Libbox before the
  engine starts. The Start Layer composer runs first, then MTU, then the engine.
  Unvalidated saved effective-MTU history is not used as a fresh path result.
- The forwarding master is a real server control through the owned PacketTunnel:
  private literal endpoint validation, exact node/session binding, cancellation,
  bounded HTTP, and independent state readback. It is not phone-local DNAT or
  a general proxy to the Setup Center administrator interface.

## Executable evidence and its boundaries

`deploy/test_ios_native_base_selection.py` executes the shipping selector and
exact-raw strategy method. Apple CI uses the actual Network.framework DNS policy;
Linux substitutes only literal-IP parsing for that unavailable framework.

`deploy/test_ios_wireguard_parser.py` executes the actual parser with adapter data
types doubled. The required native IPA build separately checks those assignments
against the pinned Apple engine, not the doubles.

`deploy/test_ios_mtu_policy.py` executes the shipping MTU policy and verifies its
three engine call sites. The forwarding policy/UI tests execute the production
policy and model with synthetic IPC. The SDK gate type-checks the real transport.
These tests are required through the native shipping runtime contract.

The Go Start Layer contract now verifies the complete composer → MTU → engine
sequence rather than insisting on the obsolete local variable spelling. Existing
Start Layer, node proof, DNS and release checks are retained.

## Still open, not waived

The current source still lacks full iOS multihop and routed-hop telemetry parity,
mobile OpenVPN, the complete mobile helper/PQ/MAX/ALL graph set, mobile Tor
transports, iOS protected XOR-relay support, complete strict SMART transition
ownership, and complete path-measured Auto-MTU/Jumbo/padding parity. Existing
platform-specific documentation/source gates describe narrower support; those
exclusions remain work, not completed requirements or proof of OS impossibility.

Physical-device installs, reconnect/permission/leak-negative tests, visual and
screen-size acceptance, off-LAN interoperability, live private AI Board/Portainer
and ASUS validation, and Apple distribution signing require their own evidence.
A green exact-SHA release certifies its actual source/build/package gates only.
No results for those physical/private gates are asserted by this document.
