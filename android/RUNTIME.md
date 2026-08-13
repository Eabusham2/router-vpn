# Router VPN Android runtime contract

This document describes implemented Android source behavior. It is not a substitute for the final physical-device/off-LAN release gates.

## Native engines

- WireGuard uses the embedded WireGuard Android userspace backend.
- AmneziaWG 2 uses the pinned official Android userspace backend.
- Self-contained sing-box profiles use pinned sing-box libbox `v1.13.12`.
- Self-contained Xray profiles use Xray-core `v26.7.11` through pinned `XTLS/libXray` commit `294fb37343205b9b0cb7b7b1b423d3d4b60d9998`, which pins Xray-core commit `50231eaff98c`.
- Native Xray rejects composite stack/sidecar profiles instead of presenting one sidecar as the complete mode.

All embedded `VpnService` paths must pass selected-node private path proof before Router VPN reports Connected/UP.

## AUTO / SMART AUTO / CUSTOM / ALL

- AUTO tries eligible Android-native candidates and stops at the first candidate that establishes a real TUN and passes selected-node proof.
- SMART AUTO may test simpler compatible branches, but restores the last proven branch if a reduction fails.
- CUSTOM selects only a real native candidate containing every requested layer.
- ALL ranks only actually runnable Android-native candidates using the catalog's protection layers, tries strongest-to-weaker, and accepts the first branch that passes selected-node proof. If none passes, ALL fails closed.
- Desktop composite MAX sidecar chains are not relabeled as Android ALL/MAX. Unsupported composite graphs remain visibly unavailable.

## Kill switch and network changes

Strict Android embedded sessions require Android 10+ Always-on VPN plus **Block connections without VPN**. The libbox and Xray services verify those platform states before starting a strict session. Raw WireGuard/AmneziaWG remain fail-closed for strict policy until Router VPN can prove their lockdown service state.

libbox and Xray react to underlying-network transitions and revalidate the selected-node path before returning to UP. Final leak/reconnect behavior remains a physical-device release gate.

## Multihop

The implemented Android multihop subset is one real graph:

`standard WireGuard entry -> self-contained Shadowsocks or Hysteria2 exit -> Internet`

Entry and exit must be different stored node identities. The exit transport is detoured through the WireGuard endpoint inside one embedded sing-box/VpnService graph. Router VPN does not report Connected until the selected **exit node** passes private path proof. AWG-entry and mixed desktop MAX multihop combinations remain gated rather than simulated.

## Release evidence still required

Source and CI cannot replace physical Android validation. Final release requires real-device tests for permission lifecycle, Always-on/lockdown leak behavior, Wi-Fi/cellular transitions, suspend/resume, DNS/IPv4/IPv6 leakage, Xray/sing-box reconnect, multihop failure, public exit identity, and off-LAN operation.
