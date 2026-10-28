# Embedded Tor host

This directory supplies the C Tor lifecycle boundary and its real native
regressions. It does **not** enable the Android or iOS Tor capability by itself.
The Go controller in `internal/mobiletor` shares the existing desktop bridge
import grammar and never launches a process.

## Native ownership

The pinned native source also contains the captured last-relay `BEGIN_DIR`
prerequisite. It shares the exact final patch/source lock with circuit cover;
see [the last-relay probe contract](../../docs/TOR-LAST-RELAY-PROBE.md). Its
owner-only capability and offline native tests do not by themselves enable
public Local / Server / Compare behavior.

A mobile process starts exactly one resident Tor thread. The generated resident
arguments contain no bridge credentials, no PT bindings, no active SOCKS port,
and `DisableNetwork=1`. The caller claims one preauthenticated Unix socketpair
endpoint; no TCP control listener exists. Tor never installs process signal
handlers. Arguments stay owned until the native thread joins.

A VPN session configures only validated bridge lines and its own loopback PT
listeners. Its owner enables networking after protected transports are ready.
A session disconnect clears bridges/PT bindings, disables networking and SOCKS,
clears transient DNS answers, and reads the actual configuration and all current
OR/circuit/stream/listener inventories. The PT owner must then close and join its
listeners and protected sockets before releasing the session. Tor's control
inventories omit connections already marked for closure, so those inventories
alone are not a PT drain proof.

An unverified disconnect retires the control stream and requires native final
shutdown. Final shutdown closes the owning socket, waits boundedly, and joins
before freeing storage. If it is still stopping, the native handle remains
owned and the caller must retry. A second `tor_run_main` invocation in the same
process is forbidden, including after initialization failure. The app must use
a fresh process after a fatal native lifecycle failure.

The wrapper owns its controller endpoint and tracks the daemon endpoint's
socket identity. This handles failures before Tor adopts that descriptor
without the upstream embedding configuration's double close of a descriptor
that another app thread may already have reused.

## Pinned source and lifecycle correction

Tor is pinned to commit `4a522a3ca491c6c04d4a44cb006b92101c42efc1`
(version `0.4.9.14`) in the Guardian Android source mirror at
<https://github.com/bitmold/tor>. The build script archives committed Git content;
it does not import mutable working tree edits.

`workqueue-lifecycle.patch` replaces static cross-invocation worker counters and
cross-thread mutex ownership with per-pool startup/exit accounting and a
separate lifecycle condition. Pool storage is freed only after every created
worker has finished accessing it. The script verifies both the original and
patched source SHA-256 before accepting the correction.

`unsafe_restart_negative.c` is a diagnostic executable, never a shipping source.
Against the exact unpatched source it reproduces the mutex destruction abort.
Correcting that worker bug does not make Tor's other globals restart-safe, so
the production host still rejects repeated native invocations.

## Reproduce the native gate

The host gate needs a C compiler, make, autoconf, automake, libtool, pkg-config,
OpenSSL development headers, libevent development headers, zlib development
headers, and Go. Its system crypto/event/zlib libraries are host test
dependencies; they are not mobile release provenance.

```sh
python3 deploy/build-mobile-tor.py \
  --source /path/to/exact-pinned-tor-checkout \
  --output /tmp/routervpn-tor-native-check \
  --negative-control

python3 deploy/build-mobile-tor.py \
  --source /path/to/exact-pinned-tor-checkout \
  --output /tmp/routervpn-tor-native-sanitizers \
  --sanitize
```

Use `--go /path/to/go` when the project's Go toolchain is outside `PATH`.
Outputs must be new or empty directories. The source archive, command logs,
native binaries, and a source-bound JSON evidence record remain in that output.

The C regression runs 64 offline configure/clear cycles with stable descriptor
counts, single-owner checks, rejected restarts, failed initialization, an
immediate stop before control setup, and descriptor reuse after Tor exits. The
normal gate also runs the production
Go controller through the actual C Tor host while alternating bridge transports.
The sanitizer gate instruments the entire Tor library and wrapper with ASan and
UBSan, including leak detection. Every fixture leaves networking disabled; no
public Tor circuit or full-device VPN traffic proof is claimed.

## Remaining mobile integration boundary

Shipping still requires pinned Android/Apple native dependency builds,
protected Go PT implementations inside the existing Libbox runtime, complete PT
socket ownership (including Snowflake WebRTC/UDP), native host packaging, and
dynamic `IsTor` plus public-IP proof through the captured final VPN outbound.
A successful configuration or bootstrap is not a Connected signal. Mobile Tor
capability stays unavailable until those actual hosts and traffic proofs exist.
