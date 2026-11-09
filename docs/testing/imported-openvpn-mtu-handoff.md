# Imported OpenVPN node-MTU reader handoff

The imported OpenVPN observer continues to pin its original authenticated remote,
remote generation, packet capacity, outbound identity, physical-path guard and
native owner. Ordinary DNS and measurement proof still require an inactive MTU
lease. The node-MTU command loop has a separate admission for its own captured
lease and may adopt only the reader returned by that owner’s native MTU
transaction. It validates the original lease, source, path, previous reader,
actual replacement reader, interface and packet tuple before the handoff.

A cancelled native change may return a new reader for the restored original
MTU. That reader is retained only under the transaction’s original cleanup
allowance. It cannot become a successful measured candidate, and cancellation
of the original native lifetime cannot authorize the handoff. Explicit rollback,
one-shot unconfirmed-commit revert and checked lease expiry use the same original
identity. The host/native node-MTU record now carries the exact comparable
OpenVPN packet observation; its next heartbeat reobserves that tuple after the
actual network-policy receipt. A saved pre-change observation is insufficient.

## Executed verification

On Go 1.26.3, Linux AMD64, November 9, 2026, the actual isolated native core was
prepared with the repository’s relay and external preparation functions. The
pinned core was `1ac1a339cb1223e9c70eae14c44411c75033c02d`. Preparation retained the
original inbound source guard and produced external source digest
`8044aaf4d17a630abe94203a65500e014a0c1319d93fa70ed3ce2cdce41d10bd`.

The compiled, race-instrumented prepared `cmd/sing-box` passed eight test roots
and 55 total root/subtest verdicts with this selection:

```sh
go test -race -mod=readonly -ldflags=-checklinkname=0 \
  -tags=with_wireguard,with_gvisor,with_quic,with_utls,with_openvpn,with_naive_outbound,with_purego,routervpn_openvpn_remote_test \
  ./cmd/sing-box \
  -run '^(TestRouterVPNNodeMTUImportedOpenVPN|TestRouterVPNImportedOpenVPN(Constructor|OriginalTuple|CallerContext|Mailbox|CancellationJoins))' \
  -count=1 -timeout=120s
```

The three new roots contain 14 root/subtest verdicts. They cover commit,
rollback, expiry, one-shot revert, a cancelled change returning its exact
rollback reader, and rejected foreign lease/reader/remote generation/capacity/
endpoint/path/lifetime. The existing observer tests retain their original
constructor, tuple, mailbox, deadline and joined-cancellation controls.

`deploy/test_desktop_imported_openvpn_runtime.py` passed all ten preparation,
source and native-test registration checks. The heartbeat projection executes
the extracted shipping loop and observers with explicit file, native and kernel
boundaries. Its checks distinguish the 250 ms periodic refresh from the
post-network observation inside the existing two-second heartbeat allowance;
neither phase can renew the other’s caller or publish a missing packet tuple.
Its two roots / 15 total root/subtest verdicts passed, and all five causal
controls rejected their deliberately broken deadline/freshness variants.

## Unproved physical acceptance

The broader prepared native selection compiled and recorded 31 passing roots /
134 passing root/subtest verdicts before physical cases. Native Box/heartbeat
cases reached `create netlink socket: operation not permitted`; startup cases
therefore did not enter their intended native-start wait. The actual OpenVPN TCP
provider case reached the same denied constructor and was interrupted while its
physical fixture cleanup was blocked. This run is not a passing full native
suite. The mandatory physical-provider tests and their guards remain enabled.

This change is a dependency of the imported Auto/Retest adapter. It does not by
itself enable that public control or establish physical networking, device,
release or deployment acceptance.
