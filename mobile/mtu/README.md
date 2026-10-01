# Retained-TUN MTU transaction — implementation checkpoint

These templates add a serialized replacement/rollback operation to the exact
sing-box `1ac1a339cb1223e9c70eae14c44411c75033c02d` inbound manager.
`deploy/prepare-retained-tun.py` prepares that isolated manager extension. The
normal Android/iOS preparation scripts do not call it yet.

The transaction validates the captured inbound identity, stops the old native
reader before starting a replacement, restores a separate rollback reader on
failure, and refuses overlapping startup after unconfirmed teardown. It leaves
outbound engines, selectors and their connection ownership outside the mutation.
Concurrent stale requests cannot replace the newly adopted reader. Callers must
independently retain the OS VPN handle and reject opens after Stop/path changes.

The transaction and its four lifecycle tests were exercised in the actual pinned
`adapter/inbound` package with Go's race detector. These are manager tests with
controlled inbound objects, not Android/iPhone OS-interface or traffic tests.
The shared `internal/mobilemtu`, `internal/mtuprobe`, and `internal/hopmeasure`
race suites also passed in this continuation.

The broader native MTU bridge reached an upstream private-runtime linker error.
Its platform socket adapters, application integration, automatic activation and
Retest controls have not completed native validation. Attempts to continue that
work were blocked by the execution tool. They are not enabled or claimed as
complete by this checkpoint. No compiler-check bypass or temporary execution
workflow is installed here.

The full all-device requirement set remains open. In particular, this checkpoint
does not deliver end-to-end mobile Auto-MTU/Retest, mobile Tor, remaining mixed
helper/PQ/MAX graphs, physical-device acceptance, private deployment, or signing.
A green pre-existing release or passing source audit does not close those items.
