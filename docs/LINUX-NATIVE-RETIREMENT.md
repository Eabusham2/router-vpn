# Linux native tunnel retirement

Linux tunnel shutdown must establish that the original tunnel and its routing
changes have retired before the service releases connection protection. Process
exit, a missing interface name, or a routing snapshot alone cannot establish
that result.

## Original resources and bounded retries

The native TUN constructor subscribes to IPv4 and IPv6 route and rule events
before creating the interface. It retains that socket, its network namespace,
the original TUN descriptor and guard, and the successfully acknowledged routing
calls. The subscription uses the kernel's named multicast group indices and
checks the actual bound groups. Readiness also checks the retained event stream;
an unchanged final snapshot cannot hide a previously observed replacement.

Cleanup uses the complete captured selectors. It refuses duplicate or overlapping
foreign matches and preserves unrelated foreign routes. It removes narrower
original rules before their wildcard siblings and retains a GOTO target until
its original dependents retire. An unacknowledged deletion remains the same
pending command across a timeout; a later request waits for that command rather
than issuing a second deletion.

Successful retirement requires original descriptor closure, complete link and
routing absence checks, and notification-reader shutdown. The bounded history
must fit its final receipt before the original TUN is closed. Partial
construction retains the same native object and dependencies, including the
network namespace manager, until their cleanup succeeds.

Every mutating cleanup operation needs a live caller with an existing deadline.
The raw command retains its ten-second shutdown operation. Controlled and legacy
Node paths preserve their established fifteen-second operation. The installed
standard child accepts an authenticated request over its original inherited
cleanup object; an initial self-cleanup attempt has a four-second ceiling.
Neither a timer nor a late result creates a fresh request budget. Completed
receipts remain idempotent.

If cleanup times out, the original owner and protection remain retained. An
explicit later Stop or command signal can request another attempt. The parent
does not substitute a killed process for a successful native cleanup result.
It requires the original child completion, a valid result from the inherited
object, and its own complete routing readback before releasing protection.

## DNS setup belongs to the same lifetime

System resolver integration uses the original private Unix connection to the
system bus. It captures the resolver's unique bus name, the broker-provided
process descriptor, and the original process and network namespace. The
resolver must belong to the same network namespace as the original TUN.

DNS changes address that captured unique owner and the original interface
index. Each outstanding call remains owned after its caller stops waiting.
Only a reply from the original destination for the original message serial, or
proved exit of that original daemon, settles an ambiguous mutation. A transport
error or a bus-generated timeout does not authorize TUN retirement. A failure
proved to precede sending is handled separately from an unknown write.

The interface DNS addresses come from the captured native configuration. The
engine's selected DNS routing policy continues to govern those queries. There
is no detached `resolvectl` process, resolver substitution, or cleanup by
interface name. Once the original pending operations have settled, closing the
original interface removes its per-interface resolver settings, as documented
by [systemd's resolver configuration documentation](https://www.freedesktop.org/software/systemd/man/latest/resolvectl.html).

An absent system-bus endpoint or an explicit negative `NameHasOwner` reply is
the non-systemd boundary. An available service with insufficient credentials is
an error, not proof that resolver integration is unnecessary.

## Supported scope and unfinished boundaries

This implementation covers retained, ordinary native Linux TUN inbounds.
Raw configurations requiring per-inbound network namespaces, auto-redirect,
platform-managed TUNs, bridge outbounds, or system-managed protocol endpoints
are refused before acquisition. A system packet stack is distinct from a
system-managed endpoint and remains supported. Whole-process namespace
ownership is also distinct from per-inbound namespace configuration. These
refusals do not close the corresponding broader product requirements.

Two ownership limits remain explicit:

- Linux routing-rule deletion selects by fields and has no atomic
  creator-generation comparison. Continuous event observation and exact
  selectors detect ambiguity and observed replacement, but cannot prevent a
  privileged writer from replacing a byte-identical rule between the final
  barrier and deletion. A racing replacement cannot produce a successful
  retirement receipt. See the kernel's
  [rule selection and deletion implementation](https://code.googlesource.com/linux/torvalds/linux/+/dfc53baae3c6a165a35735b789e3e083786271d6/net/core/fib_rules.c).
- The systemd branch requires an actual `ProcessFD` credential. Upstream
  [dbus NEWS](https://dbus.freedesktop.org/doc/NEWS) introduces it in development
  1.15.8 and stable 1.16.0; [dbus-broker NEWS](https://github.com/bus1/dbus-broker/blob/main/NEWS.md)
  introduces it in version 34. Runtime availability still depends on the build
  and kernel. Ubuntu Noble's [published dbus package](https://packages.ubuntu.com/noble-updates/dbus)
  is in the older 1.14 line. Compatibility with an available older bus that
  cannot provide original process authority remains unfinished; packet DNS
  interception alone is not evidence that this integration is redundant.

Active owned MTU changes, protected transfers between adapters, active Always
upgrades, and same-boot service-crash continuation remain separate requirements
in [the standard service contract](LINUX-STANDARD-OWNER-SERVICE.md).

## Verification boundaries

The command gate executes the actual generated command composition and requires
every named result. The routing gate checks the full transformed pinned Linux
TUN source, copied helpers, and prepared module before and after execution. Its
privileged cases create real original TUNs and test partial startup, fresh Stop
after startup cancellation, rejected additions, disjoint foreign routes,
replacement, wildcard ambiguity, and descriptor substitution. The resolver
gate exercises its actual Unix transport and descriptor transfer separately.
It requires 59 exact resolver/D-Bus parent and leaf verdicts. Five of those
exercise the fixed named Unix endpoint inside retained private namespaces:
authenticated original connection, replacement preservation, untrusted
ancestry refusal and cancellation of the original child. Original namespace
descriptors and the child's creation pidfd remain retained through join; a
wrapper's exit is not substituted for original-child retirement. The method
server in these tests is explicit and does not certify actual systemd service
compatibility.

Local tests use real processes, process descriptors, inherited memory objects,
files and cancellation, with explicit models where kernel routing is
unavailable. They establish neither native TUN acceptance nor physical-device
networking. The installed service gate retains the actual shipping DNS graph
and proves its real selected DNS exchange. Its private mount namespace supplies
an actually separate `/run`, so it does not reconfigure the host resolver.

Exact-source native builds, package publication, deployment and physical-device
acceptance remain distinct evidence requirements. No source or test result in
this document establishes completion of the full Router VPN requirement set.
