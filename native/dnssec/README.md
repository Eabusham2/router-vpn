# Pinned DNSSEC validator prerequisite

This directory supplies the private Linux C ABI loaded by the authenticated
validator child. The original-daemon trust capture, namespace isolation,
loopback broker, protected parent queries and exact source/anchor lifetime
checks are separate owners. The library grants no network authority or resolver
policy by itself. Native installed acceptance remains a separate required gate.

The build uses libunbound 1.26.2 and the repository's exact pinned OpenSSL commit.
Both static archives are linked into a private shared object. Only the ten
`rvdns_*` ABI functions are exported. No ambient libunbound, OpenSSL, libevent or
expat library is permitted. The system C runtime remains dynamically linked.
The build removes one verified configure block which otherwise requires expat
for the unused `unbound-anchor` executable. No resolver or validator source is
patched. The package records the original and projected configure hashes and
ships both upstream licenses.

## ABI and ownership

`validator.h` is ABI 1. The caller serializes all calls for each opaque handle.
`create` accepts a nonzero port and constructs exactly `127.0.0.1@port`; this must
be the isolated child's owned TCP broker, never an upstream address. It enables
only TCP upstream transport, the validator/iterator modules, strict validation,
and bounded caches and outgoing connections. Pinned built-in special-use and
localhost zones are made transparent and AS112 empty zones are disabled, so
these names also require an actual broker reply. The parent still decides which
names it is authorized to query. It never calls configuration-file,
resolv.conf, hosts-file or automatic trust-anchor loaders. OpenSSL configuration
loading and external modules are disabled. Upstream `ub_ctx_set_fwd` creates a
root forward zone with `first=0`; the shim never clears it or enables fallback.
Network isolation remains the authenticated owner's responsibility.

Before `start`, the caller may supply up to 32 explicit anchors (4096 bytes each,
32768 total) and 32 explicit insecure domains. Inputs are copied synchronously;
no Go-owned pointer survives a call. Domain names must be lowercase absolute
ASCII DNS names. IN A and AAAA requests validate address answers. An exact-name
IN CNAME request validates only the original alias RRset; this also authenticates
a synthesized CNAME through its signed DNAME. It does not follow or authorize the
target's address lookup. The parent must capture the target's own route and
trust inputs before accepting its addresses. Other types remain rejected. One
query is permitted per context. Once started, the trust inputs cannot change.

`fd` supplies the library result notification descriptor. `process` consumes a
ready notification and invokes only an internal C callback. No callback enters
Go. `result` copies eight uint32 fields and the bounded original DNS answer,
avoiding a dependency on `struct ub_result` layout. Fields are ABI, state, rcode,
havedata, nxdomain, TTL, packet length and library error. Secure and bogus come
from the validator; an ordinary SERVFAIL/transport failure is an error, never an
insecure success. The caller must reject bogus and error answers. Secure negative
answers remain distinguishable through rcode/havedata/nxdomain.

`cancel` cancels the query then deletes the entire library context and joins its
worker before exposing a cancelled state; any answer is erased. `destroy` also
joins the worker. Pinned `ub_ctx_delete` calls `ub_stop_bg`, sends QUIT, consumes
the original worker acknowledgement, and calls `ub_thread_join`. The owning Go
process must retain its hard deadline and kill/join authority around C calls;
this library does not invent a second process owner or claim an uninterruptible C
call has its own bounded runtime. Do not unload the shared object before all
handles are destroyed.

## Policy caveat

Explicit libunbound anchors and `domain-insecure` inputs are not a claim of
systemd-resolved policy equivalence. In particular a positive trust anchor can
override an insecure domain in libunbound, whereas captured systemd global and
per-link negative anchors use different precedence. The parent adapter
resolves that difference for direct address answers. Alias RR proof and target
recapture must be composed separately; supporting CNAME queries in this library
does not establish that caller integration or complete allow-downgrade parity.

## Build and offline tests

Run `deploy/build-dnssec-validator.py` with the two hash-verified source archives
and a fresh output directory. The builder refuses reused output directories and
records source, license, ABI, compiler, command, ELF dependency and artifact
provenance. `deploy/verify-dnssec-validator.py --build OUTPUT --architecture
x86_64` independently checks the package, actual ELF target/dependencies/exports,
current source hashes and license bytes before another owner seals it. Run
`deploy/test_dnssec_validator.py --build OUTPUT` under the
caller's bounded process timeout with the repository Go toolchain available.
Tests create an independent offline ECDSA signed authority and exercise positive,
CNAME, denial, insecure, bogus, expired and cancelled queries through actual
libunbound. These tests are cryptographic/API evidence, not installed namespace,
original-daemon anchor or protected bootstrap evidence.
