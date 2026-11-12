# Mobile retained-prefix candidate bridge

## Public contract

`RouterNodeChainNewCandidateMeasurement(plan, server, prefixPosition, inventory,
catalog)` returns a `RouterNodeChainCandidateMeasurement` bound to the original
`RouterNodeChain`, command server and proof reader. Inventory is the shared
schema-1 `NodeChainCandidateInventory` JSON, including its monotonic host catalog
revision and exact original source inputs. The underlying shared compiler admits
only literal, unlayered SS2022 candidate transports through a paired WG/AWG
prefix. No arbitrary destination or public dial method is added.

The required `RouterNodeChainCandidateCatalog.CurrentInventorySHA256()` callback
returns SHA-256 of the exact **current** inventory bytes. The host must observe
its actual stores/source files, original connection/server ownership and catalog
revision; returning the factory's copied digest is insufficient. Every mutation
advances the revision, including changing away and back. Unavailable source or
ownership returns an empty digest. The host must check this live guard again
before displaying/adopting a result. Host callbacks must not retain store locks
across native calls or reenter native ownership locks.

The handle exposes `Metadata`, `CaptureSHA256`, `Start(request,candidateID)`,
`StatusJSON`, `Cancel`, `Drain`, `Close`, and `NetworkChanged`. Results retain the
shared explicit TCP-connect label, complete fifty-sample requirement, captured
prefix and candidate identities, and expiry. They are not ICMP measurements or
candidate credential/private-node proofs.

## Lifetime and exclusion

An idle candidate handle may coexist with an idle hop measurement handle on the
same original chain. Both acquire the existing `measuring` activity hold, which
also excludes MTU mutation. No new native Box, WG identity or TUN is constructed.
An authorized MTU proof-reader replacement invalidates the old candidate handle;
the host closes it and creates a fresh handle against the current proved owner.

Live host catalog observations have the existing 1.5-second observation bound.
Only one foreign callback can remain outstanding per handle. A timeout retains
that exact callback for joining; it cannot silently become an unowned background
request. Measurement activity release waits for the actual callback to finish.
Status cannot certify drain or expose a completed result while callback work
remains. Bounded close uses the original caller deadline and retains the failed
join handle for retry. Closing a candidate alone preserves the idle hop handle;
original chain/network retirement invalidates and joins candidate ownership.

## Validation boundary

The native bridge fixtures execute original shared source parsing, all prefix
HTTP authentication, and public TLS proof with explicit fixture trust. Their
native routing/OS boundary is doubled. The positive path connects fifty real
loopback TCP sockets through the retained route adapter. Negative cases cover
foreign command servers, duplicate handles, catalog mutation, network changes,
slow foreign callbacks, repeated observation while a callback remains pending,
and shared MTU ownership through canceled worker drain.

This unit does not claim encrypted native candidate-path, Android NDK, Xcode,
package or device acceptance. Independent native peer and host UI adoption gates
remain required.

## Failed construction and eligibility

`RouterNodeChainCloseCandidateMeasurement(plan, prefixPosition, originalInventory)`
retries cleanup after a factory error left a late host callback retained on the
original plan. The host keeps the original arguments, session and parent lease
until this cleanup acknowledges drain. Exact capture matching prevents a late
cleanup from closing a replacement candidate. A missing slot acknowledges that
no candidate remains. This API follows completion of the original factory call;
host cancellation must still retain and join its in-flight factory operation.

`RouterNodeChainCandidateInputSupported(input)` returns only a boolean from the
same shared source compiler used by plan construction. It exposes no address or
credentials. Unsupported rows stay unscored; mutations to those rows still
advance the host's complete catalog revision and invalidate captured results.

Executed validation:

- All 14 original and new `TestRouterNodeChainBridge*` roots pass in the actual
  pinned libbox package with the race detector and the shipping
  `with_quic,with_wireguard,with_gvisor` tags: 2.259 seconds.
- All seven shared candidate roots, including paired/imported three-cipher
  eligibility and hostname/layer/UDP/oversize refusals, pass under race:
  5.823 seconds.
- Seven exact native preparation/ownership regressions pass.
- Shared and native chain files use the official preparation mapping; the
  scoped source inventory has 483 records. The surrounding dependency tree is
  the previously pinned mobile preparation, not a claim that all current
  desktop/native source families were revalidated by this mobile-only unit.

Actual SagerNet gobind v0.1.12 generated Java and Objective-C bindings from the
prepared libbox package successfully. Generated Java exposes:

```java
boolean routerNodeChainCandidateInputSupported(String input);
void routerNodeChainCloseCandidateMeasurement(
    RouterNodeChain plan, int prefixPosition, String inventory) throws Exception;
RouterNodeChainCandidateMeasurement routerNodeChainNewCandidateMeasurement(
    RouterNodeChain plan, CommandServer server, int prefixPosition,
    String inventory, RouterNodeChainCandidateCatalog catalog) throws Exception;
// Catalog interface:
String currentInventorySHA256();
```

The generated Objective-C signatures use `int32_t` for position, the
`LibboxRouterNodeChainCandidateCatalog` protocol for the guard, and `NSError**`
for fallible factory/cleanup operations. Context-bearing internal owner methods
are skipped by the binder. No public dialing method is emitted. Java hosts must
use reference identity for retained handles; autogenerated fieldless proxy
`equals()` is not native ownership evidence. Binding generation is not an NDK
or Xcode package build.
