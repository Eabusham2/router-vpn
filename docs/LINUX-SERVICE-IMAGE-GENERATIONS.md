# Linux installed service image generations

## Shipping generation and active-upgrade protocol

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

Ordinary service execution holds both the original global source SH lease and
its generation SH lease. The active-upgrade protocol below permits the original
global lease to be yielded only after both actual closed Always creators are
pinned and ordinary runtime/mutation admission is frozen. Each service keeps
its immutable generation lease, original root/run/mutation identities and a
separately retained descriptor for the original global lock inode. The installer
promotes only code under the original source EX lease; it never renames the
canonical installation or its private state beneath those owners.

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

## Live active-upgrade transaction

The native installer stages and verifies the immutable successor before
starting one absolute work allowance of at most 120 seconds. The authenticated
prepare captures the selected Always profile revision, both generation/image
identities, original namespace, exact native policy/endpoints, original saved
state bytes/inode and common mutation lease. It refuses unjoined engine work,
active controller ownership, pending MTU/adapter transfer and incomplete Off
operations. The 120-second work allowance and the separate, nonrenewable
30-second cleanup allowance are implementation limits, not recovered user
requirements. Repeated RPCs and observations do not create a fresh allowance.

The installer runs the old immutable executable with the sole image-upgrade
role argument and an inherited SOCK_SEQPACKET FD3. The coordinator authenticates
its original parent/process/namespace, and both services authenticate that
actual coordinator. The new service uses the same fixed ordinary service argv;
its staged image discovers and authenticates the old selection rather than
claiming authority from a manifest. The old service transfers its original
owner-lock open-file description through SCM_RIGHTS. It is never unlocked
between services.

Asynchronous successor start waits only for an initial socket ENOENT or
ECONNREFUSED before a peer was captured. Each retry rechecks the original
generation and old peer under the same deadline. Missing source, mixed failures
or loss of an already captured peer cannot become a new startup wait.

| Phase | Required retained evidence |
|---|---|
| `reserved` | Old actual native creator, immutable captured envelope and original coordinator peer. A lost internal prepare reply can recover only this same reservation through a read-only lookup. |
| `successor-prepared` | New actual creator has its own closed Always table, same HomeLAN/endpoints, a distinct session and a retained predecessor pin. Both actual inventories exist. |
| `frozen` | Both native pins remain valid; ordinary service, MTU, protection and adapter operations are fenced. Old service, new service and coordinator yield the original global SH lease and retain their original identities. The FD3 reply carries those three actual pidfds. |
| `code-verified` | Installer promoted the exact declared code inventory in place under source EX. Both services reacquired the original global SH inode and verified the new code; extra known code files or code-tree entries are rejected. |
| `source-removed` | Only the old retained creator conditionally removed its own native table after proving the exact successor. An expired later observation cannot reverse that acknowledged decision. |
| `successor-published` | New creator proved original removal and published its own receipt under the original saved-state token and common mutation lease. Activation publication is now allowed. |
| `successor-ready` | The actual new selection, captured profile, current native protection and published state passed before the successor emitted READY. |
| `settled` | Old creator finalized only its own handles, old process and listener actually joined, and successor again proved current exclusive native protection before ordinary admission resumed. Historical READY alone cannot satisfy this step. |

The code journal retains the exact old/new code inodes for promotion or rollback.
It preserves the canonical root, run directory, source/mutation locks, profiles,
credentials, node references and unrelated private files. The generation-specific
notify unit starts asynchronously; readiness compares the actual MainPID with
the retained candidate pidfd/image. Old future-boot enablement is retired only
after the actual old service has joined. Uncertain readiness retains recovery
material and both generation identities.

Identical FD3 sequence/body replay returns the retained original result and
original descriptor identities. A changed same-sequence request is rejected
without consuming another action. A receive timeout continues that original
receive instead of sending another copy before Abort. Current status rechecks
native evidence; a historical successful phase is not a current protection
claim. After a terminal result, the coordinator waits for FD3 EOF so an
acknowledgement can still be replayed and the caller can then join it.

## Failure, rollback and retained recovery

Before acknowledged source removal, Abort must freshly prove the old retained
creator remains. It yields the original source lease, restores only the exact
code journal, and then the new creator removes only its own table. Even an
unpromoted transaction performs the `code-restored` acknowledgement before the
old exclusive owner resumes. Completed cleanup stages are retained across
shorter observations and retries.

After original removal, recovery can only roll forward to that same retained
successor within the original work/cleanup allowance. An unknown result never
authorizes rollback, native deletion or a new budget. Cancellation, parent
death or exhausted allowance retain the original unresolved ownership and
recovery record; no replacement installer reconstructs native authority from
that metadata. Same-boot owner-crash continuation is still a separate gap.

Successful and aborted transactions permit another authenticated upgrade only
after terminal peers have joined and the current original native slot is
proved. Bounded terminal history keeps old generation observers until that
transition; repeated upgrades release only noncurrent observers. This is not
generation-directory garbage collection.

Code generations are retained rather than garbage-collected by this foundation.
Future removal must require generation EX, absence of all captured live owners,
and the exact installer transaction; directory names or activation history are
not enough. Installation metadata and manifests describe source selection only.
They never reconstruct native creator or deletion authority.

## Compatibility and acceptance boundary

The initial protocol deployment cannot make an unmodified older process speak
this handoff. Its compatibility transition must use the existing proved-idle
upgrade or a genuine reboot/new-boot absence path. It must not silently select
Off or delete protection to install the new protocol.

Installer tests cover exact code-only generation reuse, retained generation
leases across selection changes, pre-activation rollback, code tampering, and
lost readiness retaining both generations. Existing private-state, source-lock,
legacy process, original protection and rollback controls stay required.
Active installer cases additionally exercise the actual code journal/inodes,
systemd transaction framing, delayed reply/replay, one cleanup clock and real
SOCK_SEQPACKET/pidfd/image/argv checks. The installer also spawns an actual native
Go fixture through its production role/FD3 caller; that fixture models service
replies and does not establish native handoff or systemd host acceptance.

Native tests exercise real generation source locks, executable identities,
connected Unix peer pidfds and requests to the original generation after
activation changes. They distinguish pure observation expiry from real source
loss, reject foreign generation adoption, and refuse independent absence when
a generation listener exists or appears during readback.

Eleven separately bounded installed image scenarios require the actual native
services/coordinator, original namespace and nft inventories, shipping Python
generation builder and code journal, notifications, state and process joins:
success, abort before/after promotion, lost freeze/commit/READY replies, changed
sequence, expired preparation, a second upgrade after success/abort, and loss
of the successor guard after READY and after the old process joins. The last
case must reject both final settlement and fresh status. Each scenario retains
the existing 120-second Go / 150-second outer gate limits; repeated cycles share
one shorter fixture allowance. The watchdog kills the private process group,
and fixture children have parent-death cleanup. Every parent and code dependency
is mandatory; omissions, duplicates, substitutions and skips fail the gate.
The successful path also launches the actual canonical ordinary-upgrade helper
while frozen and requires the authenticated phase-fence refusal, then rechecks
both actual native inventories. A foreign-role rejection cannot satisfy it.

The installed scenarios drive actual service processes and notify datagrams;
systemd itself is covered by the separate installer framing and remains a real
host acceptance requirement. Local compilation and modeled transaction checks
do not claim that the eleven nft/mount/network namespace cases have passed.
They remain required privileged CI evidence, followed by actual installed-host
upgrade, reconnect and leak acceptance.

The mandatory installed namespace gate also launches the actual service utility
from its separate immutable executable, drives the canonical controller through
real native selected DNS and Stop, then uses the canonical idle-upgrade helper
to join that original service. Both global and generation leases must remain
held before retirement and become available only after the actual join. Named
Unix listeners, nft/netlink privileges and namespace mounts are required;
missing capabilities fail this gate rather than substituting model evidence.
