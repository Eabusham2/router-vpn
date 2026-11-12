# OpenVPN concrete failed-dial ownership repair — 2026-11-12

## Observed failure and boundary

Windows AMD64 WFP run 43143660168, job 130936812106, source
4477b8f1c6858ef66172289eb8a75a73d3f5e9bd failed the TCP
`successor-and-original-restore` case. The native external engine attempted normal
failed-carrier cleanup and panicked in `gonet.(*TCPConn).Close` at a nil receiver.
The pinned OpenVPN `stackDevice.DialContext` returned the concrete
`(*gonet.TCPConn, error)` pair directly as `(net.Conn, error)`. On failure this
boxes a nil pointer into a non-nil interface. The same conversion exists in its
UDP dial and packet-listen methods.

The owned preparer now tests each concrete pointer before interface conversion,
returning a nil interface and the original error when the pointer is nil. It
preserves any actual non-nil carrier and its error. No outer cleanup error is
suppressed; no production deadline, ownership check, or WFP case is relaxed.
The exact pinned source blob remains
`9a0bd5edd56c4ef64f8d8ae335e2a6dfe4d921dc` at core
`1ac1a339cb1223e9c70eae14c44411c75033c02d`. Preparation accepts only the original,
the previous owned delivery-drain projection, or the complete new projection;
partial dial patches and foreign changes are refused.

## Actual pinned-stack reproduction and validation

A copied prepared core was used without changing the released original tree.
The official OpenVPN stack policy prepared the changed source and existing owned
fixture. This is scoped evidence for this pinned source projection, not a new
whole-core current-head source receipt or Windows WFP acceptance claim.

The new native fixture uses the actual gVisor/OpenVPN stack. On the prior source:

- Cancelled TCP dial returned a non-nil `*gonet.TCPConn` interface and
  `context canceled`.
- Removing the actual NIC while retaining the original configured source made
  TCP bind return a non-nil `*gonet.TCPConn` interface and `bad local address`.
- UDP dial and packet-listen returned non-nil `*gonet.UDPConn` interfaces with
  `cannot assign requested address`.
- The live UDP carrier control passed.

All four negative cases failed the nil-interface assertion on the old source.
After preparation, all five cases passed. The existing delivery-drain and live
capacity/cancellation roots also passed unchanged: three native test roots,
`-race`, **1.025s**. Command:

```sh
go test -race -p=1 -mod=readonly -ldflags=-checklinkname=0 \
  -tags with_openvpn,with_wireguard,with_quic,with_gvisor,routervpn_openvpn_remote_test \
  ./transport/openvpn -run '^TestRouterVPNOpenVPNStack' -count=1 -timeout=30s -v
```

The three preparer tests passed, including exact-pin enforcement, upgrade and
idempotency, each partial dial-patch rejection, foreign-source drift, and symlink
refusal before mutation. The existing remote OpenVPN runner already selects all
`TestRouterVPNOpenVPNStack` roots, so this regression joins its mandatory native
execution without an optional skip.
