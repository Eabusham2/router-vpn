# Retained-TUN MTU integration

These templates add a serialized replacement/rollback operation to the exact
sing-box `1ac1a339cb1223e9c70eae14c44411c75033c02d` inbound manager.
[prepare-retained-tun.py](../../deploy/prepare-retained-tun.py) prepares the
manager extension. [prepare-mobile-mtu.py](../../deploy/prepare-mobile-mtu.py)
integrates it with the shared MTU controller, and
[prepare-mobile-multihop.py](../../deploy/prepare-mobile-multihop.py) invokes
that preparation from the Android and Apple native build paths.

This directory is developer source, not an independently installable router
script. For app setup, use the [user guide](../../docs/CURRENT-GUIDE.md).

The transaction validates the captured inbound identity, stops the old native
reader before starting a replacement, restores a separate rollback reader on
failure, and refuses overlapping startup after unconfirmed teardown. It leaves
outbound engines, selectors and their connection ownership outside the mutation.
Concurrent stale requests cannot replace the newly adopted reader. Callers must
independently retain the OS VPN handle and reject opens after Stop/path changes.

## Integration and validation

The shared [mobile MTU controller](../../internal/mobilemtu/README.md) documents
Auto/Fixed behavior, Retest/Cancel, captured-session ownership and throughput
selection. The Android and Apple owners integrate those operations with their
existing VPN session; the manager transaction never owns the entire application.

Run the shared controller tests from the repository root:

```sh
go test -race ./internal/mobilemtu ./internal/hopmeasure ./internal/mtuprobe
```

The [native MTU workflow](../../.github/workflows/native-mtu-integration.yml)
prepares the pinned core and exercises its manager and bridge. The
[MTU contract workflow](../../.github/workflows/mtu-contract.yml) exercises the
platform ownership and UI contracts. Build, SDK, signing and physical-device
networking checks remain separate; consult the [current status](../../docs/CURRENT-STATUS.md)
for supported graphs and outstanding acceptance work.
