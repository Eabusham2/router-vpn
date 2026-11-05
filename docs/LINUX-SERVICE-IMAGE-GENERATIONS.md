# Linux installed service image generations

## Shipping foundation and boundary

The native installer creates a root-owned, code-only immutable generation beside
`/opt/router-vpn-client`, under `router-vpn-client.service-generations/<digest>`.
The digest identifies the canonical complete source inventory. Each generation
has a separate adjacent source lock. Private profiles, generated credentials,
state and native creator records are not copied into a code generation.

`service-generation.json` in the canonical installation selects the generation
for new service discovery. The installer verifies the package before creating
the generation, validates an existing identical generation before reusing it,
and writes the selected exact executable into the notify service's ExecStart.
The manifest uses the same UTF-8 JSON bytes as Go encoding/json, including
HTML and U+2028/U+2029 escaping. Both implementations enforce 8,192 inventory
entries, a 2 MiB manifest and a 4 KiB activation bound before discovery or
publication. Unicode filenames retain their original bytes.

Legacy installations without activation metadata retain the exact canonical
executable and control endpoint. Invalid activation never invokes that fallback.

The service holds both the original global source SH lease and its generation
SH lease for its lifetime. The global owner lock also remains unchanged. A
service still bound to its canonical state, native helpers and source tree must
not release the global lease to let an installer rename that source underneath
it. Consequently **active Always service/image upgrade remains unfinished**.
This foundation does not change the existing requirement that the original
service prove idle native absence before source promotion.

New service peers are authenticated against the selected generation's exact
image inode, fixed role, connected kernel peer pidfd and original namespace.
The service separately authenticates incoming controllers and upgrade helpers
against their canonical installed image. A retained peer holds its original
generation capability and fixed generation endpoint. Later activation does not
redirect Current, Stop, or cleanup to another process. New source selection is
not authorization to adopt a replacement peer.

Generation endpoints use distinct fixed names in the existing private service
directory. Legacy control.sock remains unchanged for old installations. The
independent service-absence observer refuses retained or foreign generation
listeners as well as the original endpoint, while retaining the original owner
lock, source/state comparisons, namespace and native absence requirements.

## Failure and rollback

Before new-service activation, existing installer rollback restores the exact
previous installation and its activation record. A failed or lost readiness
result may follow creation of real protection: the new selected generation,
previous installation and old immutable generation are all retained. No failed
readiness result authorizes source renaming underneath a possible creator.

Code generations are retained rather than garbage-collected by this foundation.
Future removal must require generation EX, absence of all captured live owners,
and the exact installer transaction; directory names or activation history are
not enough. Installation metadata and manifests describe source selection only.
They never reconstruct native creator or deletion authority.

## Required next active-upgrade unit

An active upgrade needs a shipping protocol between two live authenticated
service generations. It cannot be added by relaxing the current idle refusal.

1. Stage and verify the next immutable generation without changing selected
   source. Capture one installer transaction, original deadline, both exact
   image identities, namespace, selected Always policy and original saved-file
   token. Exclude MTU, adapter transfer, Off-save and unjoined engine work.
2. Separate the remaining canonical code/helper dependencies and stable mutable
   state from generation code. Preserve the same mutation lease and saved inode
   comparisons. Only then can generation SH replace the global source SH for a
   retained service. The immutable tree itself is never renamed or overwritten.
3. Reserve an upgrade in the old live creator. Start an authenticated next
   generation in a non-active successor role. It creates its own closed Always
   baseline and retains its actual acknowledgment/netlink endpoint. No decoded
   old receipt constructs a new creator. Overlap must be at least as restrictive
   as the captured original policy.
4. Pin both live creators and verify both actual inventories under the original
   namespace and native generation checks. The old creator alone may retire its
   original table, after the next creator proves its own retained protection.
   The existing same-process Supersede API is not a cross-process capability.
5. Persist and acknowledge the phase using the exact retained state token and
   common mutation lease. Then promote activation and require readiness from
   the exact successor, not an older active/exited systemd unit. Keep each
   generation endpoint and original pidfd available until its own settlement.
6. Lost replies resolve only against the original live peers and immutable
   transaction. Before original removal, abort may remove only the successor's
   own creation while the original baseline remains. After original removal,
   rollback requires a newly created, independently proved baseline; it cannot
   resurrect a retired creator from its saved JSON. Unknown outcomes retain
   both owners and source generations, and remain visibly incomplete.
7. Retire the old service only after exact native removal, state settlement,
   original listener retirement and pidfd join. Reboot may create fresh policy
   after native absence; same-boot owner crash reconstruction remains separate.

The initial protocol deployment cannot make an unmodified older process speak
this handoff. Its compatibility transition must use the existing proved-idle
upgrade or a genuine reboot/new-boot absence path. It must not silently select
Off or delete protection to install the new protocol.

## Evidence requirements

Installer tests cover exact code-only generation reuse, retained generation
leases across selection changes, pre-activation rollback, code tampering, and
lost readiness retaining both generations. Existing private-state, source-lock,
legacy process, original protection and rollback controls stay required.

Native tests exercise real generation source locks, executable identities,
connected Unix peer pidfds and requests to the original generation after
activation changes. They distinguish pure observation expiry from real source
loss, reject foreign generation adoption, and refuse independent absence when
a generation listener exists or appears during readback. These do not claim
that an active Always handoff has happened. That later protocol requires real
installed two-generation nft/namespace acceptance, including every interrupted
phase and lost-reply boundary, before the requirement can be marked complete.

The mandatory installed namespace gate also launches the actual service utility
from its separate immutable executable, drives the canonical controller through
real native selected DNS and Stop, then uses the canonical idle-upgrade helper
to join that original service. Both global and generation leases must remain
held before retirement and become available only after the actual join. Named
Unix listeners, nft/netlink privileges and namespace mounts are required;
missing capabilities fail this gate rather than substituting model evidence.
