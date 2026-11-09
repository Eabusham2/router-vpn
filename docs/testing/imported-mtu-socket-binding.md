# Imported desktop MTU socket binding

The imported desktop MTU adapter must bind its own TCP transfer and UDP probe
sockets to the captured running TUN. The physical interface that carries the
outer encrypted connection is a different owner. A selected interface name or a
cached MTU does not authorize a measurement.

`bindDesktopImportedMTUSocket` requires the original context, an exact active
lease validator, native reader, interface index/name and effective MTU. It
checks that owner before, inside and after the retained raw-descriptor callback.
The production interface readback requires the same running non-loopback TUN.
Cancellation or a changed owner invalidates the socket; there is no ordinary
network fallback.

The OS adapter verifies the descriptor's real type and address family before
setting and reading back its interface. Linux uses `SO_BINDTOIFINDEX` plus the
bound name. Darwin uses `IP_BOUND_IF` / `IPV6_BOUND_IF`. Windows uses
`IP_UNICAST_IF` / `IPV6_UNICAST_IF` and obtains the unbound socket's actual
family/type/protocol through `SO_PROTOCOL_INFOW`; IPv4 preserves the native
set/get byte-order contract. Other targets explicitly reject this adapter and
retain their separate qualified platform requirement.

## Executable checks

`TestDesktopImportedMTUKernelSocketBinding` opens actual TCP/UDP IPv4/IPv6
sockets and checks original binding, changed type/family, unqualified transport,
invalid interface and cancellation. `TestDesktopImportedMTUSocketRequiresOriginalLease`
rejects missing/cancelled callers, absent/replaced lease validators, missing
reader and unqualified network before kernel entry. The Windows native contract
requires both roots on AMD64 and ARM64 under its existing 180-second per-group
limit. Its gate test rejects omission and keeps each selected native test in
exactly one invocation. macOS/Linux full controller suites also select both.

The Linux test reads its real loopback index from the kernel IPv6 table to
exercise the actual socket options without requiring a complete interface
inventory. This is a test of kernel socket binding, not a substitute for the
production TUN readback or an end-to-end physical VPN. The production adapter
still refuses loopback and requires actual native interface inventory.

The actual desktop controller package passes all 32 socket/owner race verdicts
on the integrated continuation source. A verbatim-source projection also passes
those cases and cross-compiles for Windows/Darwin on AMD64/ARM64. Those
cross-compiles are not native execution.
The shared command adapter, authenticated path probes, candidate selection,
rollback and Auto/Retest/Cancel dispatch require their separate integration
checks; these socket functions alone do not complete imported MTU support.
