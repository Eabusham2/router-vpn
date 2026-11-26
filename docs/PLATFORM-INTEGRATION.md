# Platform Integration

Consolidated technical references. Existing protocol and platform restrictions remain in force; historical validation statements are not certification of current main.


---

<a id="section-controller-shutdown"></a>

# Owned controller shutdown

Portable Exit must disconnect its VPN, close its transports and controller, and
release its application directory. An installed application that attaches to an
existing background controller does not acquire permission to stop that process.

The controller handles `SIGINT` and `SIGTERM` through the same terminal cleanup
transaction used by an owning native launcher. It first refuses new connections,
settings changes, temporary Speed Lab tests, candidate measurements, and automatic
MTU work. It cancels pending startup and active operation contexts before waiting
for their serialized completion. The existing captured runtime teardown then
checks MTU rollback, server leases, native close acknowledgements, process exit,
private workspace retirement, and owned protection release.

A cleanup error retains the exact owner and is retried. Neither a repeated signal
nor an HTTP timeout authorizes force-killing a child or reporting successful
cleanup. A process that never acquired a connection does not release another
controller's persisted firewall when its own listener fails to bind.

## Launcher protocol

An owning launcher creates a fresh random launch token, represented by exactly
32 lowercase hexadecimal characters. It supplies that token only to its newly
started controller as `HOMEVPN_CONTROLLER_OWNER`, and retains the child process
object, PID, and token. The controller captures the token at startup. A reused
controller is not adopted merely because it is listening at the expected address.

The owner sends `POST /api/controller/shutdown` with this exact bounded JSON shape:

```json
{"schema":1,"process_id":12345,"owner_token":"0123456789abcdef0123456789abcdef"}
```

The request is limited to 1,024 bytes. Unknown, duplicate, case-aliased, missing,
malformed, or mismatched fields are rejected before cleanup begins. The nonce and
PID must both match this controller. CLI/service processes without a launcher
nonce still support signals; they do not enable this HTTP capability.

Only after every owned cleanup operation succeeds does the controller send HTTP
200 and this exact receipt:

```json
{"schema":1,"process_id":12345,"owner_token":"0123456789abcdef0123456789abcdef","closed":true}
```

Each request waits at most 30 seconds. HTTP 503 means cleanup remains pending;
the launcher keeps the same process and retries the same identity with a request
timeout of at least 35 seconds. Request cancellation does not cancel cleanup.
After a timeout, the completed receipt remains available until the matching
owner successfully receives a response. A failed receipt write does not retire
the controller. After flushing a successful response, graceful HTTP shutdown
joins the response handler before process exit.

The launcher checks all four receipt fields and then joins its exact child. It
must not kill the process because a response timed out, failed to parse, or named
a different owner. Process exit by itself is not a native lease or rollback
receipt. Signals are appropriate for an independently owned CLI/service process;
they do not provide a launcher with the HTTP acknowledgement above.

## Executable evidence

`cmd/client/controller_shutdown_test.go` exercises admission and startup
cancellation, temporary Speed Lab restore suppression, bounded strict owner
requests, timeout/retry and failed-response retention, actual HTTP response
delivery, and failed-listener isolation. It also runs separate controller and
native helper processes: real SIGINT/SIGTERM must obtain the native close
acknowledgement and retire the owned workspace before controller exit. A native
cleanup failure must retain its registry entry and workspace until the exact
cleanup command succeeds on retry. These are automated ownership tests; physical
device and removable-drive acceptance remain separate evidence.


---

<a id="section-darwin-race-toolchain"></a>

# Darwin native race compiler

The macOS physical-socket and installed-controller validation workflows select
the official Go 1.26.5 compiler explicitly, including `GOTOOLCHAIN`. Their
native race executables still run every original ownership case, negative
control and cleanup check under the original deadlines. The shared production
runtime/package toolchain and its exact provenance pins remain separate.

The upstream [Darwin fork regression](https://github.com/golang/go/issues/79804)
affects Go 1.26.3 race executables which fork child processes before `exec`.
The [approved backport](https://github.com/golang/go/issues/79806) adds the
missing `//go:norace` annotation in Darwin's raw syscall path and is included
in Go 1.26.5. The [official release history](https://go.dev/doc/devel/release#go1.26.5)
records that release on July 7, 2026.

At source `d58501ee1428a3bcf7fae0a8c7ff1a0cd01bb9b0`, the authoritative
[ARM64 guardian job](https://github.com/Eabusham2/router-vpn/actions/runs/43482476120/job/132082447995)
failed its eleventh sequential UDP socket admission. The captured PF grant
reported a command still in `Start` and two commands in `Wait` at the original
native deadline. After the test had exited, its original guardian and another
process carrying the same pre-exec image remained alive and retained the output
pipe. The later closed-control error and outer timeout did not establish a
successful native cleanup.

This observation matches the upstream race/fork defect, but that attribution
remains an inference until the unchanged native cases pass with the corrected
compiler. A parsed workflow, Linux test, or cross-compilation does not establish
Darwin PF, socket, process, or utun acceptance.

`deploy/darwin_race_toolchain.py` also separates native validation from product
preparation in the runtime builder, copied-source UID/PF/route gates, retirement
and lifecycle gates, pinned dependency race tests, generated ordered child, and
installed external/ordered/prefix host gates. It resolves official `go1.26.5`,
checks its native host and target, captures its absolute executable and GOROOT,
then verifies identity again with automatic dispatch disabled. A production
GOROOT is removed only from the copied validation environment. The official Go
toolchain resolver can download that exact compiler on hosts where it is absent.
Product builds, source preparation, bundle reuse, module locks and provenance
continue to use their existing `go1.26.3` contract.

Generated child receipts name `go1.26.5`, and read back the compiler version from
each exact executable before signing, hashing or running it. Their consumer
rejects a `go1.26.3` receipt, including one substituted for the original eight
cases. Installed host and source-lifecycle receipts identify the validation
compiler separately from the unchanged product bundle. Historical focused
candidate sources must adopt this compiler contract before their new native
receipt can pass; an older image is never relabeled.

Portable compiler controls reject an old compiler, wrong host/architecture,
changed captured identity, unavailable executable, and an image carrying another
compiler version. Native Intel and ARM64 re-execution remains mandatory.


---

<a id="section-durable-state"></a>

# Durable state and transaction safety

This document describes the **current source contract** for Router VPN durable/private state. It is not physical-device, production-deployment, off-LAN, or release evidence by itself. Exact-current CI/artifact/native/runtime gates remain separate.

## Core invariant

If an operation reports failure, Router VPN must not silently leave a half-adopted state across RAM, disk, live networking, or recovery metadata.

If rollback itself cannot complete, Router VPN must report that truthfully and keep enough durable recovery state to retry safely. A successful source write is not the same thing as a proven shipped/runtime result.

## Client private stores

Authoritative client JSON/state stores use a common private-store boundary:

- regular files only; symlink targets are rejected;
- bounded reads;
- existing private stores converge to mode `0600` where appropriate;
- random same-directory temporary files;
- write + file sync + close before rename;
- atomic rename as the commit point;
- no fallible post-rename permission step that could make callers roll RAM back after disk already committed.

This covers the main client config, `routers.json`, whole-connection profile storage, setup-profile metadata, and startup/last-good runtime memory.

Router profile Save/Select/Delete/Import participate in the backend mutation ownership boundary. Save/Select restore the previous in-memory selection/profile state when persistence fails.

## Session-bound result adoption

Long-running measurements or proofs that write state must capture the identity they measured and re-prove it before adoption.

Examples include:

- Fastest-node selection;
- public-exit proof;
- DNS Retest measurement fields;
- MTU Retest;
- startup/last-successful runtime memory.

MTU Retest remains explicitly two-phase: measure first, re-prove the same session/profile/path, then apply/persist. A stale result is rejected. Persistence or post-adoption freshness failure restores live MTU and the previous durable measurement fields.

## Router-agent privileged state

Privileged router-agent state uses strict private regular files with bounded reads and atomic publication. Group/world-readable, symlinked, non-regular, corrupt, or unsupported state fails closed where it is security-sensitive.

Forwarding-extension ownership and Protected DMZ use transaction semantics across RAM, durable metadata, and live nftables state. A failed live DMZ adoption attempts to restore both the previous durable intent and previous live rules. If either restoration step fails, the API reports rollback as incomplete.

Admin forwarding/LAN/ban/revoke mutations similarly surface rollback failures rather than silently discarding them.

Stop / Emergency Stop / Resume state uses the same privileged private-state primitive. Emergency Stop remains scoped to Router VPN WG/AWG peers and does not become a generic Docker or host-destructive control.

## Endpoint synchronization

Endpoint synchronization is one staged multi-file transaction.

It owns only:

- raw WireGuard/AmneziaWG `Endpoint` fields; and
- the owned home Router VPN profile endpoint (`id=home`, `node_kind=router-vpn`).

It does **not** recursively rewrite arbitrary `server` or `address` fields and does not alter linked external nodes or unrelated Router VPN profiles.

All owned changes are computed and staged before adoption. If a later replacement fails, already-adopted files are restored from captured originals. The obsolete broad endpoint rewrite script remains removed.

## DNS benchmark ownership

The server DNS benchmark is measurement-only.

It publishes private atomic `config/dns-fastest.json` measurement data and does not mutate current `routers.json` DNS policy. Fresh bundle generation may consume the benchmark as measured default metadata, but running the benchmark cannot overwrite a newer user-selected DNS host/mode/policy.

## Exact-SHA updater recovery

The update controller treats persisted recovery state as a hard transaction boundary.

Before the first Portainer mutation it requires the current production stack to resolve to one exact SHA and saves that exact compose as a private rollback snapshot.

The update sequence is:

1. persist a pre-deployment recovery checkpoint;
2. preserve the old updater while phase-one target services are applied;
3. prove core health;
4. persist `finalizing` before replacing the updater itself;
5. apply the full exact target;
6. prove full health and prove the Portainer compose is exactly the target SHA;
7. only then persist `complete` and retire the rollback snapshot.

Any Portainer mutation/health/identity failure after the rollback snapshot boundary restores the private previous compose, proves the full core health contract, and re-reads Portainer to prove the previous exact SHA again.

Terminal `failed` is written only after that prior exact stack is restored and health/identity-proved. If rollback cannot complete, durable status remains `rolling-back` so restart reconciliation retries recovery instead of forgetting a potentially mixed deployment.

Restart reconciliation handles interrupted `applying`, `rolling-back`, and `finalizing` states conservatively. A finalizing restart becomes complete only when the current stack is already exactly the target SHA and passes health verification; otherwise the previous exact snapshot is restored.

Updater state, rollback snapshots, Portainer API credentials, and TLS pin inputs are private bounded regular files and fail closed on unsafe/corrupt recovery state.

## Stable generated credentials and identities

Credential-bearing generated state follows preserve-or-fail-closed semantics:

- a genuinely missing credential family may be generated once;
- a complete valid existing family is preserved;
- partial, corrupt, inconsistent, or symlinked preserved state does not silently rotate into new credentials that linked clients do not know.

Related files are staged/validated before multi-file adoption where consistency spans more than one file.

Covered source families include:

- Setup Center access token;
- router-agent/node-proof identity;
- WG/AWG client/server configuration publication;
- Hysteria2 TLS certificate/private-key pair;
- Shadowsocks/Hysteria2 generated secrets and configs;
- REALITY/PQ/Xray identity and client/server configs;
- SS+V2Ray/Naive credentials and client metadata;
- OverTLS/SSR auxiliary credentials;
- Rosenpass server/WG-PQ/AWG-PQ identity;
- advanced XHTTP/MAX REALITY state;
- MAX Rosenpass overlays;
- derived split/MAX combined profiles;
- private `client.json`, `routers.json`, bundle JSON, and `CREDENTIALS.txt` publication.

Candidate transport/Xray/TLS/XHTTP states are validated before their authoritative files are replaced when the relevant runtime validator is available in the generation environment.

## Derived Setup Center assets

`setup-assets.json` and the generated Setup Center HTML can contain private import payloads, so they remain `0600` and are served only through the authenticated private Setup Center boundary.

They are **derived presentation data**, not stable identity or active policy. Finalization fails if required Setup assets cannot be generated, and they can be regenerated from already-transactional private source material.

Persistent unauthenticated/static node bundles and `CREDENTIALS.txt` are explicitly removed from the downloads directory. Private bundles are produced on demand by the authenticated broker and cleaned up after delivery.

## Release gate

`deploy/durable-state-transaction-audit.py` is the authoritative source gate for this safety class. It is invoked by `deploy/release-orchestration-audit.py`, which the exact-SHA release candidate already runs.

The durable-state gate checks source invariants and executes focused behavior/fault-injection tests for private publication, endpoint rollback, DNS ownership, Setup Center credential preservation, and generated-state preservation.

A green durability audit proves only the source/release-gate contract for that exact SHA. The project still requires the exact-current native/package/image chain and then physical/live/production validation before release.


---

<a id="section-linux-native-retirement"></a>

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

The Node parent waits for readiness on its original inherited channel under
that existing bounded retirement operation. Readiness consumes no message or
descriptor and supplies no cleanup evidence. Once ready, the unchanged
five-second authenticated receive checks the exact original child and frame.
Ordinary channel exchanges keep their original five-second bound. The parent
still requires the typed retirement record, original source closure, independent
network readback, final acknowledgment and actual child join. A failed or
canceled channel remains a refusal; this phase is not a replacement channel.

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

## MTU replacement transactions

The Box MTU API now admits a replacement before constructing its adapters. The
original manager retains the predecessor, candidate and rollback, including
partial constructors and failed closes. A directly owned Linux transaction
reserves space within its 32-owner pending limit before acquisition. Copied
evidence distinguishes a live Ready receipt from completed native retirement;
neither fact substitutes for the other. A retry reaches only the same retained
manager and transaction and cannot close an adapter adopted by another caller.

Construction, retirement and rollback consume the original bounded operation.
Cancellation cannot start a fresh rollback with a renewed budget. The native
TUN keeps its original Box lifetime separately so that ending an MTU operation
does not invalidate the adopted reader. Startup receipt capture still forwards
the exact startup operation, and explicit later receipt reads require their
own existing deadline. Borrowed/mobile readers and other operating systems
preserve their previous rollback and lifetime behavior.

Explicit native receipt reads carry that same operation through both link
inventories, address inventory, route and rule dumps, and the event barriers.
They do not reuse or rewrite the completed construction context. A caller
canceled after the original event barrier cannot publish a receipt from a
different read lifetime. The native MTU gate ends each candidate's construction
operation before reading its adopted adapter with the retained test operation.

Ordinary no-context projection callers still read under the Box lifetime. That
does not supply a per-request bound and can delay Stop while a native read owns
the retirement mutex. Threading their original caller operation through those
projection paths remains required; the explicit transaction and startup reads
above do not establish that behavior for every existing caller.

This is a native transaction prerequisite. Installed service Auto/Retest/Cancel
still needs the authenticated child exchange, coordinated service/controller
Trackers, actual selected-path measurement and restoration, and acknowledgment
of completed history. Partial construction must remain owned without inventing
a Ready receipt. Repeated Retests cannot append unbounded history to the
unchanged 48KiB cleanup message or discard unacknowledged owners.

Active service MTU integration, protected transfers between adapters, active
Always upgrades, and same-boot service-crash continuation remain requirements
in [the standard service contract](PLATFORM-INTEGRATION.md#section-linux-standard-owner-service).

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

Three additional mandatory native MTU cases cover the complete candidate search
and winner, a failed candidate followed by original-state restoration, and
canceled work followed by fresh owned Stop. They retain the directly created
child and creation pidfd, actual Box/TUN transactions, original namespace
capabilities, Tracker transitions, outbound identity and final retirement.
Their receipt-size assertions cover that no-auto-route fixture only. They do
not establish full-route service history sizes or public Retest integration.

Local tests use real processes, process descriptors, inherited memory objects,
files and cancellation, with explicit models where kernel routing is
unavailable. They establish neither native TUN acceptance nor physical-device
networking. The installed service gate retains the actual shipping DNS graph
and proves its real selected DNS exchange. Its private mount namespace supplies
an actually separate `/run`, so it does not reconfigure the host resolver.

Exact-source native builds, package publication, deployment and physical-device
acceptance remain distinct evidence requirements. No source or test result in
this document establishes completion of the full Router VPN requirement set.


---

<a id="section-linux-service-image-generations"></a>

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


---

<a id="section-linux-standard-owner-service"></a>

# Retained Linux standard-exit service

This unit moves the installed Linux direct stock standard-exit engine into a
fixed privileged service. The service creates and joins the actual engine and
retains the original nft creator, saved-state file capability, namespace and
workspace. A restarted GUI does not reconstruct those capabilities from a PID,
table name, receipt or JSON file.

## Shipping boundary

The existing direct stock Linux wrapper selects this path for WireGuard,
SOCKS5, HTTP, HTTPS, Shadowsocks and Hysteria2. Off, On-connect and Always use
the same original-child lifecycle. OpenVPN, custom engines/Start Layer and
hopped graphs keep their existing adapters. Uninstalled development execution
keeps the existing in-process owner.

The installed path uses the checksum-verified bundled generated native engine,
not a PATH stock executable. It captures the original catalog, executable and
Cronet descriptors before verification, checks those same objects afterward,
and seals the captured configuration and payloads. The original creation pidfd
and inherited authenticated channel bind the fixed `routervpn-standard`
command to its creating service. Missing or invalid installed assets cannot
fall back to an unrelated engine. The controller prepares only the private
request graph and workspace; it does not start a second configuration-check
child from PATH.

The installed controller authenticates the fixed service through a Unix
seqpacket channel and original `SO_PEERPIDFD`, root peer credentials, installed
image, original process directory, namespace and captured argv. The service
authenticates the fixed controller role in the same way. A separate fixed
upgrade role can request only proved-idle retirement. RPC accepts one bounded
canonical request and at most its required original workspace descriptor.
Channel loss cancels the actual request, and the reader joins before response.

The service uses the existing original creator and conditional retirement
contract. It never adopts or deletes a table because its name or saved receipt
matches. Authenticated explicit Stop joins the original engine and preserves
Always; a requested On-connect release removes only the captured original
protection. Engine failure, controller death, invalid runtime observation or a
lost Start channel joins the original engine while retaining its guard. A new
authenticated connection creates its successor before retiring that retained
creator; otherwise explicit Disconnect or Off owns release. Automatic cleanup
retains a queryable failure if it cannot complete. The controller's post-activation
monitor has its own lifetime, clears only the original Connected state, and
cannot stop or overwrite a replacement launch.

Selected-DNS proof executes in the service against the actual engine's
original listener and captured configuration. Controller reconnect does not
refresh the original physical-network snapshot or substitute ambient DNS.

The installed service opens its original native event tracker before version
or configuration-check children and initial TUN inspection. It begins the
transition before creating the engine. That exact child returns its actual
successful-call routing ledger through the authenticated channel. The service
checks the original child, capture, sources and TUN policy, then records and
ends the transition on the same tracker before DNS and public proof. A matching
TUN name or final topology cannot manufacture a startup receipt.

Original child/listener readiness and a second uncached selected-DNS exchange
must pass under that retained tracker before activation. Later public proof,
DNS observations and monitoring retain the same epoch. Unexpected link,
address, route or rule changes invalidate it permanently, including an
away-and-back change. Lost or truncated events, errors and cancelled barriers
cannot reopen the observer. The explicit uninstalled stock path retains its
separate post-readiness observer behavior.

The tracker grants no interface-name or synthetic-receipt exemptions. Its
lifetime is independent of the request that armed it. Original Stop closes and
joins the exact observer before engine teardown; failed cleanup retains its
original owner for retry. If controller request preparation fails and cleanup
cannot finish, a separate registry retains that exact unstarted private capture.
The existing Stop budget drains it before active runtime/protection cleanup;
an adopted or replacement owner cannot be put through this private cleanup.

The installed controller separately opens its own original network tracker
immediately after namespace capture, before private TUN/workspace/configuration
validation. It begins the expected transition before transmitting Start. The
authenticated service returns the exact original child's capture and canonical
startup ledger only after its own readiness transition succeeds. The controller
checks source/profile/session identity, the original authenticated RPC peer and
the locally transmitted absolute deadline before recording that receipt on its
unchanged tracker. A current topology or replacement observer cannot repair an
earlier invalid epoch. DNS/current/monitor RPCs check that same tracker before
and after the operation, and Stop joins it before requesting service teardown.
Unstarted cleanup consumes the original caller's budget. The service uses the
earlier of the transmitted absolute deadline and bounded budget; conversion to
a relative timeout cannot add time to the child's original capture.

## Explicit Off and owner composition

The protection UI observes both the retained Node parent and this service.
An explicit service-owned Off verifies the original selected profile and
revision, releases the actual creator, proves native/state absence, saves and
reads back the exact Off result, then clears the exact captured joined local
adapter. Cancellation, failed persistence and lost completion replies preserve
the accepted release/save milestone for retry. A newer local adapter, profile,
controller, table or state file cannot be cleared by stale completion.

A missing socket is insufficient evidence of absence. An independent check
holds the fixed service lifetime lock exclusively and the shared mutation
lease, verifies original directory/lock/namespace identities, and rechecks the
socket and saved state. Without a Node parent it also proves TUN and complete
native protection absence. Beside an actual authenticated Node parent, the
separate scoped observer proves the generic table and every standard-prefix
table absent; it does not claim Node-family or TUN absence. The Node's own
original transaction still performs its full final release verification.

## Protected service-to-Node succession

The controller reserves an authenticated, immutable transfer before stopping
the original installed service. The reservation captures the source session and
configuration, destination Node selection/profile revision, HomeLAN policy and
original startup deadline. The service keeps its original native creator; the
controller pins its actual prepared Node creator. After the source engine joins,
the service verifies both exact inventories in one stable native generation and
removes only its original table. Serialized receipts are comparison evidence,
not replacement creator capabilities.

The original operation and durable intent survive cancellation and lost replies.
Before removal, cleanup preserves the service guard; after removal, a failed
Node connection retains its destination guard. A known completed native Finish
is preserved across subsequent partial descriptor/state cleanup so retries join
the original remaining work. No request can lengthen admission. Native nft and
installed service-to-Node tests remain mandatory; local protocol/race results
are not privileged network acceptance.

## Captured measurements and temporary restoration

Current Speed Lab retains the actual installed service, original authenticated
peer/activation, private exit, saved policy profile and selected-DNS proof. Native
MTU and routing observations belong to that same original owner. A pending MTU
transaction, unclosed run or retained measurement socket prevents conflicting
admission. Read-only capture does not construct an optimizer run.

HTTP latency/transfer requests use the captured TUN dialer and normal TLS
verification. The original request owns a successful socket beyond its shorter
dial admission. Redirects, ambient proxies, late completions and fallback to an
ordinary-network dialer cannot install a result. Current and temporary paths
preserve their original caller through capture, validation and observation.

A temporary test preserves the complete saved profile store/selection, private
exit source, physical-network identity and actual prior MTU. Restoration uses
the ordinary shipping connection handler with the captured restore intent and
requires a fresh proved native connection. Fixed/Jumbo must read back the exact
old value. Auto restores the already-measured value under the same shared-run
protocol and original 30-second parent, waits for actual closure, then installs
its completed MTU UI after another source/readback check. Suspension prevents an
automatic optimizer from competing. Failures retain the original cleanup path;
Disconnect or a replacement connection suppresses stale restoration.

## Boot and installation

`router-vpn-standard-owner.service` is a distinct notify service so an older
oneshot's `active/exited` state cannot masquerade as new readiness. A valid
prior-boot standard marker selects fresh standard policy creation only after
complete native absence. The newly created service must receive its own native
acknowledgment; saved metadata supplies no deletion authority. Partial creation
is retained, and the lifetime watcher retries that same creator with bounded
attempts before issuing READY.

Unmarked profiles preserve the fixed installed Python `reassert` behavior.
They are not inferred to be standard graphs from a selected Home Always
preference. The service retains the original helper, creation pidfd and Wait
across deadline expiry, and waits for its mutation lease to become available.
An under-lock Python guard rejects a standard marker that appeared after
dispatch. Failed or unjoined helpers do not report READY or permit idle upgrade.

Idle/Off upgrades authenticate and join the original service before replacing
installed source. Separate installer transaction, controller and source locks
exclude competing installers/controllers while allowing the new service to
take its source lease before READY. A failed new readiness attempt retains both
installations for recovery; it does not rename source underneath a possible
creator. Partial native boot failures keep the service alive without READY.

## Validation and remaining requirements

The required Linux packaging runner inventories every service source and exact
test verdict. It runs after the actual verified native bundle is staged and
before provenance/archive publication. All eighteen app-generated combinations
of the six stock protocols and three device policies must parse in the actual
built engine. Privileged namespace cases exercise actual installed images,
the generated engine and native TUN, a real private SOCKS/DNS peer, named
sockets, peer pidfds, nft creation/readback, original service retirement,
and boot Always to explicit UI Off followed by idle upgrade. The compatibility
cases retain their explicit final public-proof model. Dedicated
`on-connect-public` and `on-connect-public-restore` cases use actual TUN-routed
HTTPS to an authenticated private SOCKS/DNS/TLS peer, real bytes and elapsed time,
the public Retest/Cancel/Speed Lab handlers, and exact native MTU readback. The
restoration case cancels after both original launch and child exit, then requires
fresh owner/proof identities, complete profile restoration and the prior measured
1280 MTU despite a different startup MTU. Bounded test shaping delays actual
payloads only under the matching kernel receipt; it synthesizes no measurement.
Physical Internet performance remains separate. An unexpected
actual engine exit must retain the original On-connect creator and saved inode
until authenticated explicit Stop, followed by proved-idle upgrade. Separate native
scope cases reject foreign standard/shared tables while preserving the
independent Node table family. Missing, renamed, skipped or duplicate required
verdicts fail the runner.

Local validation executes real children, pidfds, Unix socketpairs, descriptor
transfer, file locks, saved-file comparisons, cancellation and race tests.
Explicit fixture observers model nft/TUN where the workspace lacks NET_ADMIN.
The installed named-socket, nft/TUN and systemd acceptance gates must execute
on the native CI hosts; compilation alone does not establish those results.

Native cleanup now uses the original inherited cleanup descriptor, authenticated
absolute request deadlines, original child completion and complete routing
absence. The native implementation retains its original TUN, event socket and
successful routing calls through startup failure and explicit Stop retries.
Resolver calls retain their original connection and pending reply ownership.
See [LINUX-NATIVE-RETIREMENT.md](PLATFORM-INTEGRATION.md#section-linux-native-retirement) for the implementation,
native gate inventory and the remaining kernel and older-bus boundaries.

## Prior-boot service protection to Node

When the installed service reasserts Always protection after boot, it retains
the actual newly created guard as `s.boot`. Node preparation can capture that
creator through the authenticated service peer without inventing a source
engine launch. The fixed transfer protocol distinguishes a boot source from an
active engine source. Original peer/process identity, destination profile and
revision, request ID and deadline remain immutable through native reservation,
source removal beside the independently proved Node successor, and cleanup.

Cancellation and lost replies retain the original boot guard or its positively
acknowledged native result. Missing service or authenticated NoBoot is only
absence of this capability; normal Node native-absence checks still apply.
A retained protection-view peer stays with its original immutable generation.
After an original release closes its descriptors and removes its registry entry,
cleanup may retry the exact finished milestone without selecting another owner.
Changed peer/session/deadline requests remain rejected.

Three installed scenarios require successful public Node Connect, cancellation
with the original boot guard retained, and a lost cleanup reply followed by
retry. They use actual service reassertion, private encrypted proof, selected
DNS, Disconnect and explicit saved Off. They preserve the 429 original host
cases and nine reverse cases. These new scenarios deliberately use literal
endpoints: resolving a hostname while the boot guard is closed requires its
separate original-owner bootstrap implementation. Actual privileged installed
execution remains mandatory and has not run in this workspace.

## Protected Node-to-service succession

The reverse direction captures the original installed Node parent, selected
policy and private exit before Stop joins the old engine. It resolves transport
names and seals the exact command and private configuration while that original
connection still carries traffic. The original operation and transfer deadline
bound preparation. Bind rechecks the captured command arguments/environment,
installed-root and private-directory identities and configuration hash; it does
not repeat hostname selection after Stop. Failed preparation owns only its
original workspace cleanup handle, which is also closed after owner cleanup.
After the original engine joins, the reverse path
reserves the same closed Node creator and records a durable transfer intent.
The installed service authenticates that original parent and exact native
inventory, creates its own protected successor without starting an engine,
and returns a pinned inventory for the original controller to verify.

Only the original Node creator removes its own table, beside the exact service
successor in one stable native generation. The service independently observes
source absence before acknowledging commit. Both processes retain their original
creator capabilities; serialized journal entries and receipts only compare
identities. Normal standard Start then resumes the same prepared service owner
under the original transfer deadline, followed by the ordinary selected-DNS,
current-path and connected-state checks.

Cancellation and lost replies retain the original reservation, native result
and durable intent. Abort proves the original Node guard still exists before
releasing only the prepared service guard. Unknown aborts fence delayed prepares;
ordinary Start, release and upgrade cannot bypass an unresolved transfer. A
completed transfer's current check reobserves its retained successor. Retrying an
old native Finish cannot clear a newer reservation. Unknown native deletion
acknowledgement remains pending; a missing reply never proves removal.

Focused tests cover actual peer processes, pidfds, files and bounded admission
with explicit native-effect models. Separate mandatory nft tests exercise both
actual creators, cancellation, changed/lost successors and repeated completion.
These tests do not establish installed end-to-end or physical-device acceptance.

The installed Node runner separately requires success, lost commit/prepare/Start
responses, cancellation before source removal, changed-deadline rejection,
post-removal Start failure and two Always abort cases through the actual public
handlers and service. It reads
both original native guards, verifies source removal or abort, and checks the
durable journal and joined teardown. Successful connection must send real DNS
and private HTTP identity traffic through the captured TUN and encrypted peer;
independent direct-LAN counters reject bypass. Always abort must retain its
original protection until the public saved-Off transaction completes. These
nine namespace scenarios preserve the original 429-case inventory, compile and
are required by CI; local workspace restrictions prevent execution.

The following are still separate unfinished requirements, not closed by this
unit's refusals:

- Other adapter/generic legacy boot-owner succession. Both protected Node and
  installed standard-service directions and the service's own retained
  prior-boot guard above are implemented; protected hostname bootstrap and
  actual installed/native acceptance remain separate.
- Installed/native acceptance of active Always service/image upgrade. The
  authenticated two-generation protocol now preserves the actual creators,
  original source/private-state identities, one work/cleanup allowance and
  exact readiness/join proof; eleven installed scenarios are mandatory. See
  [the image protocol](PLATFORM-INTEGRATION.md#section-linux-service-image-generations). Local fixture and
  compilation results do not establish its actual nft/systemd/host acceptance.
- Same-boot service crash continuation for orphaned protection. A replacement
  service cannot recover the lost original creator from metadata.
- Native acceptance of active MTU/interface transitions. The fixed child,
  service and controller now retain real candidate/rollback transactions and
  both original observers, with public Auto/Retest/Cancel, selected-DNS probes,
  current interface readback and bounded durable history. Explicit Stop also
  recovers joined evidence after autonomous retirement. The actual installed
  namespace, successful TUN-bound measurement and device cases remain mandatory;
  protocol fixtures and compilation do not establish those results.
- Native retirement acceptance on the actual installed hosts and compatible
  resolver authority on older available system buses. The new exact-selector
  implementation replaces priority-range deletion, but Linux offers no atomic
  creator-generation comparison for rule deletion. A privileged replacement
  between the final barrier and kernel deletion remains a distinct ownership
  limit; it must not produce a successful cleanup receipt.

These boundaries remain truthful errors or retained pending states; they must
not be represented as successful Off, connected readiness or completed handoff.


---

<a id="section-native-desktop-delivery"></a>

# Complete native desktop runtime delivery

The native Router VPN connection paths consume `runtime/native`, alongside
the corrected Xray runtime in `runtime/xray` and the smaller compatibility AWG
runtime in `runtime/amnezia`. A package containing only the latter two cannot
deliver the complete native path even if the application itself compiles.

## Build and artifact boundary

`deploy/build-native-runtime.py` prepares disposable pinned sing-box and Xray
source trees, composes the owned protocol and concurrency changes, and links
the socket-free Rosenpass C ABI into the same process. WG/AWG, Xray, Naive,
OpenVPN, the authenticated Start Layers and the composite registrations retain
their real implementations. Native PQ has no independent socket owner.

The builder requires Go 1.26.3 and Rust 1.99.0. Windows uses the verified
LLVM-MinGW toolchain selected by `setup-desktop-native-toolchain.py` and
`install-desktop-windows-toolchain.py`. Native C libraries, CMake, Ninja and a
loadable host libclang are prepared before the build. The build policy digest
includes the desktop PQ preparation, locked Cargo inputs, ABI source, complete
native preparation, compiler setup and download pins, and transport/performance
patches. Git checks out text inputs with LF endings on every host, so Windows
and Unix producers calculate the same source identity from the same commit.

Windows also retains the pinned `oqs-sys` build's static `liboqs.a` beside the
Rust ABI archive. The builder selects it from that invocation's successful
Cargo build-script event, checks the exact locked package and owned target
directory, and validates the archive's actual x64 or ARM64 COFF code. Its size,
digest and dependency identity are part of the PQ receipt. Cargo's declared
linkage must agree with Rust's final link requirements: native Windows leaves
OQS external, while a Linux cross build bundles it. DLL import archives,
foreign-target objects, ambiguous cached copies and altered receipts fail.

The final Windows link selects static compiler runtimes. Bundle verification
also reads ordinary and delay-loaded DLL imports from both the executable and
the exact bundled Cronet library. It checks bounded PE32+ headers, target
architecture, section/RVA bounds and DLL names without executing a foreign
program or requiring a compiler on the packaging host. Only the named Windows
system libraries, versioned Windows API sets and the explicit owned Cronet
payload are accepted. A matching receipt cannot make an unstaged compiler DLL
such as `libunwind.dll` acceptable. Both pinned Cronet architectures are checked;
the producer's environment cannot stand in for a missing installed dependency.

The pinned bindgen 0.71.1 has an upstream declaration-resolution bug with
Clang 22 that can turn `OQS_SIG` into a one-byte opaque type. Windows preparation
applies the upstream fix to a private copy of the exact checksum-verified
crate archive. It verifies the original and patched file hashes, records the
backport, and permits only that one exact build-tool substitution in the
otherwise pinned Cargo lock. The shared registry cache, crypto headers and
generated layout assertions remain unchanged. A real Clang 22 / Windows ARM64
binding passes the original Rust size, alignment and offset assertions with
the backport; the original binding fails under the same target compiler.

macOS compilation uses the selected Xcode macOS SDK for both Rust bindgen and
the final Go C/C++ compilation and link. All stages use the requested target
architecture and macOS 13 minimum; the final link retains the SDK flags when
adding the verified PQ dependencies. Metadata-only inspection of a foreign
macOS bundle does not require Xcode on a Linux or Windows packaging host.

The reusable `desktop-native-runtime.yml` workflow builds each target on its
matching host architecture. It runs the executable receipt/relocation tests
and the captured WG/AWG graph tests before uploading an artifact. The graph
checks use race detection on the pinned Go toolchain's supported targets;
Windows ARM64 executes the same checks without an unsupported race flag.

Each bundle contains:

| Payload | Platforms |
| --- | --- |
| `sing-box-routervpn` or `sing-box-routervpn.exe` | All six desktop targets |
| `libcronet.so` | Linux x64 and ARM64 |
| `libcronet.dll` | Windows x64 and ARM64 |
| Six upstream license files | All six desktop targets |
| `NATIVE-RUNTIME.json` | All six desktop targets |

The receipt binds the upstream versions, exact revisions, Go/Rust toolchains,
native PQ ABI, source policy, target architecture, and every payload's length
and SHA-256. Verification also checks compiled Go metadata, all required build
tags and the embedded source marker. A receipt is an integrity check inside
the authenticated exact-SHA application package; it does not replace release
or platform trust.

`native-runtime-bundle.py` rejects missing, repeated, linked, excessive or
unexpected artifact members. Tar headers, PAX overrides, member counts and
expanded-size limits are checked before advancing over their payloads. ZIP
central-directory bounds are checked before allocating the file inventory.
Extraction occurs in a temporary directory and
becomes visible only after full verification. Reusing a staged target requires
the exact same verified receipt. An altered prebuilt bundle is rejected rather
than silently repaired by a new build.

The generic cross-compiler recreates `dist`, so CI downloads artifacts outside
that tree and stages them **after** `build-client.sh`. Packaging hosts inspect
foreign executables through metadata; the producer on the matching host owns
execution evidence. No packaging host tries to execute an unrelated platform.

## Signing and installation

The package scripts stage the complete bundle, then verify the actual bytes
inside the finished installed/Portable ZIP or Unix archive. A missing engine,
receipt, license or required Cronet library fails packaging.

macOS's sealer first verifies the original bundle. It signs a private staged
copy, verifies the code signature, updates only the signed engine's receipt
entry, checks every other payload again, and promotes the complete result.
Signing failure leaves the original intact. An engine changed before signing
cannot be blessed by resealing it. If promotion and restoration both fail, the
original backup remains available for recovery. Candidate ad-hoc signing remains distinct
from Developer ID signing and Apple notarization.

Windows and Linux install all three runtime directories with staging,
verification and runtime rollback. A failed restoration retains the previous
runtime bytes for recovery. This transaction covers the three runtime
directories; it does not claim rollback of every outer installer action.
Private linked nodes and generated credentials are preserved. An unrelated
`runtime/windows` directory remains separate. Portable
uses the runtime beside its own executable in `App/RouterVPN`, while private
state remains under `Data`.

The server's bounded Windows/Portable fallback uses the same-image native
artifacts and image-built AWG compatibility binaries. Both are verified before
optional controller compilation and again after copying. Metadata inspection
uses the installed Go toolchain with toolchain/module downloads disabled.
The private router does not compile Rust, rebuild native engines or execute a
foreign Windows engine to serve a download. The fallback also includes the
start-layer relay, update helper and Portable bootstrap/core pair.

Image preflight and registry publication consume verified artifacts from the
same source generation. Direct workflow dispatches create their own matching
inputs; the authoritative Build all chain shares the already-verified native
release artifacts. Production compose remains image-only.

## Verification and limits

Useful local gates are:

```sh
python3 deploy/test_native_runtime_delivery.py
python3 deploy/test_linux_runtime_install.py
python3 deploy/test_desktop_native_toolchain.py
python3 deploy/test_desktop_native_dependencies.py
python3 deploy/test_desktop_pq_output.py
python3 deploy/test_desktop_pq_dependencies.py
python3 deploy/test_desktop_bindgen.py
python3 deploy/test_desktop_native_bundle.py /path/to/bundle linux/amd64
python3 deploy/test_native_runtime_delivery.py --bundle /path/to/bundle --target linux/amd64
python3 deploy/test_linux_runtime_install.py --package /path/to/extracted/linux/package
```

Windows packages also carry `client/test-windows-runtime-install.ps1` for the
filesystem transaction boundary and `client/test-windows-installed-runtimes.ps1`
for actual installation and upgrade into a temporary ProgramData directory.
Both native Windows architectures run the latter in CI, including installed
engine verification, preserved private state and drivers, the Start Menu
shortcut and native launcher self-test.

Boundary fixtures double only the declared operating-system/compiler/signing
interfaces and exercise the production file, receipt, staging and rollback
logic. The `--bundle` and `--package` paths use the actual built executables.
Native graph construction and installer verification do not establish a live
router tunnel, a physical device's route policy, public interoperability,
production signing or deployment. Those require exact-source evidence in the
native release and live acceptance records.


---

<a id="section-native-vector-map"></a>

# Native Router VPN vector basemap

The iOS/iPadOS and macOS map uses Router VPN's own opaque vector renderer for
land, coastline, ocean and graticule. MapKit supplies native pan/zoom and
coordinate transforms. It is not a browser wrapper or a renamed street map.
`RouterVPNVectorMapOverlay.canReplaceMapContent()` is true, and its renderer
covers the requested rectangle before drawing the local geometry. It is
installed above stock map labels; VPN routes and node annotations remain above
the base. A status refresh removes route overlays only, preserving the custom
base even with an empty catalog or disconnected VPN.

The underlying MapKit view uses an explicit `MKStandardMapConfiguration` with
flat elevation, muted emphasis, traffic disabled and stock points of interest
excluded. Camera pitch is disabled. This uses the supported configuration API;
Apple documents that the older
[`showsBuildings` property](https://developer.apple.com/documentation/mapkit/mkmapview/showsbuildings)
has no effect with overlays on iOS 16/macOS 13 and later. Visible geography
continues to come from the opaque bundled renderer.

## Geography and coordinates

The Apple, Android, Windows and Linux application packages include the same
87,951-byte land asset: 128 closed
rings and 5,143 vertices from the pinned Natural Earth 110m land 4.1.0 archive.
It contains physical land outlines, no political borders, names or VPN nodes.
The archive checksum, public-domain notice, source URLs and deterministic
conversion command are in `client/shared/map/NATURAL-EARTH.txt`. The generator
verifies the complete archive before parsing Polygon records; builds do not
download new geography. Runtime code uses no remote tile URL or geocoder.

Android draws the land outlines with a native Canvas before drawing route lines
and node markers. The outlines and markers share the same latitude/longitude
projection. Date-line segments wrap at the two map edges. Imported nodes keep
a pink outline alongside their route-position color. Package verification
compares both the land geometry and its attribution with the release source.

Windows draws cached, frozen WPF geometry. Linux draws a cached native Cairo
path. Their existing globe projection is shared by land, node markers, route
segments, the ocean boundary and the graticule. Both maps split date-line
routes and use those same short segments for moving packets. A local route
retirement clears its packet immediately; a fresh contradictory controller
snapshot also invalidates the captured route. Expiring RTT alone does not
invent a disconnection. Installed and Portable Windows ZIPs and the native
Linux archives must contain the exact geometry and original attribution.

The source dataset is a small-scale world outline, so it is intended for VPN
path context rather than street navigation. Nodes still use only explicit
coordinates in their linked profiles. The device marker still requires the
user's location-button tap, platform permission and a fresh location fix from
the operating system. Apple uses Core Location, Android uses LocationManager,
Windows uses its location service and Linux uses GeoClue.
No node or device coordinate is inferred from the land dataset or an IP address.

The shared Apple projection clamps polar display latitude to the finite Mercator
limit. Source coordinates retain the original WGS84 range. Date-line routes
are split at the two world edges rather than crossing the long way through
the map. iOS packet motion uses the same projected short route. Its animation
requires a proved connection, while a saved disconnected path is dashed.
Packet animation is decorative: every displayed RTT comes from measurement.
iOS refreshes fit the map only when the node-coordinate set changes, preserving
the user's pan and zoom while latency and connection status update.
macOS marker selection uses the same idle-checked saved selection transaction
as its node picker. Selecting a marker never starts a connection, and a blocked
selection leaves the active path untouched. Zoom remains bounded to a useful
VPN/region view instead of trying to use the small-scale coastlines as streets.

## Validation and delivery limits

`deploy/test_apple_vector_map.py` executes the unchanged shared Swift geometry
and checks the packaged source/resource paths. It exercises malformed and
oversized geography, coordinate limits, exact endpoints, polar behavior and
both date-line directions. A changed implementation that takes the long route
must fail the same executable checks.

On Apple build hosts the same gate must compile both shared sources with the
real iOS SDK and render a bitmap with the real macOS MapKit/Core Graphics
renderer. The bitmap check requires every pixel to be opaque and checks known
inland/ocean positions using MapKit's projection, the renderer's color space
and the downward-Y map drawing transform. Vertically mirrored land must fail
the same native bitmap check. A real `MKMapView` test starts with a non-flat,
traffic-enabled configuration and verifies the installed flat/muted policy,
excluded points of interest, disabled pitch, idempotent installation and route
removal that preserves the base. Omitting the configuration assignment must
also fail. The macOS builder and iOS runtime
contract both invoke this gate; Linux explicitly reports the native portion
as unavailable rather than counting a mock renderer as SDK evidence.

`android/test_android_map_land.py` executes the shipping Android geometry with
a controlled Canvas boundary and checks inland and water positions, including
interior water. The Android SDK build and APK verifier separately check the
shipping classes and exact packaged resources.

The Linux shell fixture compiles the actual globe paint routine and checks
native Cairo pixels, date-line legs, packet movement and route retirement.
`client/test-windows-vector-map.ps1` executes the composed Windows map
functions. Its native mode uses real WPF geometry and RenderTargetBitmap;
portable PowerShell checks alone do not establish WPF rendering. The Windows
native workflow retains the rendered PNG. These fixtures use controlled route
data and do not establish a real VPN session.

Native compile/render evidence remains separate from inspection of the final
installed native layouts, gestures, accessibility and location permission
flows on installed packages. This basemap does not make a claim about all
framework network traffic; MapKit is still a system framework. The app's own
renderer needs only its bundled vector data.


---

<a id="section-startup-policy"></a>

# Captured native-app startup policy

Requirement 116 in the recovered original requirement set includes persisted
startup and auto-connect settings. The reconciled native-app contract also
requires that a delayed operation cannot connect a different node after the
user changes the selection, private source, or connection policy.

## Desktop behavior

The controller captures the selected profile when scheduling its startup delay.
For an imported node it also captures the saved entry profile, execution
preference, and a digest of any private Router-entry runtime assets. A later
selection, relink, credential edit, policy edit, Disconnect, shutdown, or manual
Connect retires that intent. A failed manual Connect still takes priority over
the older automatic attempt.

Router nodes retain their existing AUTO, SMART AUTO, and Last-mode strategies.
Imported nodes connect with their own saved protocol and complete graph through
the same owned operation used by the Connect button. Startup does not replace
an imported protocol with a Router mode. New imported nodes retain their
existing Manual / auto-connect Off default.

| Imported-node choice | Behavior |
|---|---|
| Manual | Stay disconnected. Auto-connect cannot be enabled with Manual. |
| Saved connection | Start the saved protocol and entry/exit graph, then prove its selected DNS, policy, and required exit. |
| Last proven connection | Reuse a still-matching proved Local/Server choice when available, without rerunning Compare selection; create a new owned runtime and require fresh proof. |

An existing imported `smart-auto` startup value uses its saved protocol and
graph. The native imported-node editor displays this as Saved connection.
If Last has no matching evidence, startup tries the saved graph with fresh
proof. It never treats old evidence as proof that a new session is connected.

Last-state persistence contains node references, source/policy digests, the
protocol identifier, and the proved execution choice. It does not copy imported
credentials, keys, or private Router-entry assets into another store. Changing
the startup preference to Last does not itself invalidate the proved graph;
changing its credentials, requested policy, graph, or private assets does.

## Editing startup

Windows, macOS, and Linux expose imported-node startup from their native
Settings controls. The startup-only API is `/api/profile/startup`:

- GET returns the selected node ID, a revision token, its node kind, and its two
  startup preferences. It returns no protocol credentials or private bundle.
- POST requires the captured ID and revision, the selected startup choice, and
  an explicit auto-connect boolean. Unknown fields and additional JSON objects
  are rejected.
- Saving requires an idle owned controller transaction. The handler rechecks
  selection, source revision, connection state, and shutdown before persistence.
  A failed write restores the original in-memory profile.
- A successful edit changes only `startup_mode` and `auto_connect`, preserves
  all other node records and private policy, and retires the earlier delayed
  launch. It does not immediately connect the already-open application.

Router-specific settings remain on their existing API. The imported startup
editor never sends disabled Router-mode, Start Layer, MTU, or protection fields
back as default values.

## Shipping paths and verification

`cmd/client/strategy_modes.go` and `startup_external.go` own scheduling and Last
selection. `external_profile_connect.go` and `tor_bridge_routes.go` perform the
actual owned launch/proof; they are shared with interactive Connect. Private
source checks, cancellation, cleanup, and proof rejection remain in those paths.

`profile_startup_test.go` exercises API persistence and rollback across nine
imported protocol families, rejects stale selection/credentials/policy and
unknown inputs, and checks changes arriving during request decoding.
`startup_external_test.go` exercises captured startup using compiled native
graphs and isolated child processes, including failed proofs, cancellation,
changed entry assets, and retained Compare winners. These fixtures do not
establish off-LAN or physical-device network acceptance.

`deploy/test_desktop_startup_settings.py` compiles or executes the shipping
PowerShell, Swift, and GTK JSON serializers. The tests verify that only the
captured identity and chosen startup values are submitted, and reject mutated
identity/private-field behavior. The Windows workflow runs PowerShell 7 and
5.1; macOS and Linux run their native serializer checks and actual app builds.

## iOS and iPadOS

Auto-connect runs once per app model when Router VPN opens. It captures the
exact selected bundle, entry bundle and connection generation before reading
system VPN preferences. A newer selection, credentials/policy change,
Disconnect, or temporary Speed Lab owner retires that intent. Available VPNs
must remain idle through preference save/readback; startup never adopts an
already-active VPN or replaces a newer operation. Router startup rechecks the
same intent at nested Connect/SMART admissions and retains its own generation
across a valid Last fallback. SMART also revalidates startup after refreshing
VPN status before acquiring any native MTU measurement hold.

Imported nodes keep their own saved protocol and entry/exit graph. AUTO and
SMART reconnect that graph; Last retains the previous proved Local/Server
choice only when its source and entry still match. Durable Last state stores
hashes and the execution choice, without copying credentials or old runtime
receipts. Startup preferences and historical MTU readback do not invalidate
that history; requested MTU, credentials, DNS, protection and graph changes
do. A separate source-bound launch option requests the retained choice, and
the new native runtime must complete its normal fresh proofs. Speed Lab's
restore receipt and MTU lease remain separate.

The external Settings form saves only the two startup fields transactionally
while disconnected. New imported nodes remain Manual with auto-connect Off.
Live MTU/Retest/Cancel remains accessible for Router, ordinary external and
Tor paths. App startup does not promise device-boot/background execution or
add an on-demand rule by itself; existing strict protection retains its own
system on-demand behavior.

The shipping Swift fixtures exercise 274 startup and Settings checks, 672
multihop receipt checks, 64 app/provider strategy checks and 21 ownership
checks. Twelve startup mutations and the strategy suite's five existing
negative controls are rejected. These checks cover source behavior and
integration boundaries; exact-SHA Xcode builds and physical acceptance remain
separate requirements.


---

<a id="section-unified-map-control-center"></a>


# Unified Map Control Center v2

The daily Router VPN surface is map-first on every native platform. The map or custom vector globe remains visible above a swipe-up/bottom control sheet. The fixed order is Connection, Multihop, Settings, Mode, DNS.

## Interaction contract

Node selection never starts a connection. The primary button alone changes between Connect and Disconnect. Its left menu measures/selects the fastest node; compact kill-switch and master-forwarding controls sit beside it, capability-gated. Live end-to-end RTT is visible beside Disconnect.

The default profile contains one node, uses SMART AUTO, IPv6 On and Auto MTU. AUTO requirements for encrypted and obfuscated candidates remain off until explicitly selected. Profiles support create, load, update, delete and router-bundle import. Custom mode presets support create, load, update and delete through a separate visual builder page.

Multihop uses color-coded device, bridge, entry, middle, custom and exit roles, animated packet lines, per-node/pairwise/total RTT, per-hop throughput and end-to-end throughput. Measurements are real and remain unavailable with an explanation when the active dataplane cannot prove them.

## Bridges and encryption

Supported profile forms include Router VPN, WireGuard, AmneziaWG, OpenVPN, Shadowsocks 2022, SOCKS5, HTTP CONNECT, HTTPS CONNECT and Tor bridge. Plain proxy/bridge types cannot be the final transport; they require an authenticated encrypted inner tunnel.

Authenticated transport is mandatory. Router VPN uses standard, reviewed constructions such as WireGuard/AmneziaWG Noise_IK with ChaCha20-Poly1305, TLS 1.3 AEAD, Shadowsocks 2022 BLAKE3/AEAD and Tor ntor-v3. It never invents XOR-based or custom packet encryption.

Jumbo TUN, DAITA-like padding, arbitrary forwarding and Tor are shown as enabled only when the current platform and selected path report real runtime support.


---

<a id="section-unified-native-ux"></a>

# Router VPN unified native app UX

This is the shipping interaction contract for iOS/iPadOS, Android, macOS, Windows and Linux. Platform controls may look native, but the information architecture and truth rules stay the same.

## Primary surface

- The map is the app's primary surface. It opens first and consumes the upper/main region.
- Apple platforms use the shared native [Router VPN vector basemap](PLATFORM-INTEGRATION.md#section-native-vector-map): bundled land outlines and a custom grid/palette replace the generic map content while native coordinate transforms and gestures remain available.
- Plot only coordinates explicitly stored with linked Router VPN or external/custom nodes. Never infer, geolocate, or fabricate a map pin from an IP address.
- A selected path is visually distinct. Multihop entry, intermediate and exit nodes use stable, distinct hop colors and a path overlay; custom/external hops use the same path model.
- Exactly one normal node is selected by default. The node control distinguishes `Router node` from `Custom / external`, with Add/Manage as a drill-in action rather than cluttering the primary surface.
- Desktop uses a bottom dock/control card. Touch platforms use the equivalent draggable/swipe-up bottom sheet. The sheet must never cover its own controls with a floating banner or top popup.

## Bottom control order

1. **Connect / Disconnect** — one primary button. It becomes Disconnect only for an active/proving session. A compact quick kill-switch control sits beside it.
2. **Multihop** — visible immediately below Connect when enabled and one tap away when disabled. The editor chooses each entry/exit/hop from the unified node catalog. Unsupported runtime graphs remain visibly unavailable with the exact reason; they are never simulated.
3. **Settings** — opens the detailed settings page/sheet.
4. **Mode** — compact selector plus a detailed picker. `SMART AUTO` is the default selection, `AUTO` is a first-class mode, all logical presets remain discoverable, unavailable presets remain visible with their reason, and CUSTOM opens the visual preset system.
5. **DNS** — compact selector in the sheet. Detailed DNS setup/retest is a drill-in page, not a permanent top-level tab.

Connection progress remains truthful and visible: preparing, engine, interface/TUN, handshake, route, DNS, selected-node path proof, public-exit proof, failure/fallback/rollback and winner. Connected is not asserted merely because a process started.

## Modes and CUSTOM

- `SMART AUTO` is the initial/default UI mode for a new Router VPN profile. It first obtains a proven path, remembers the last good runtime, tries simplification, validates each change and restores the last good runtime if a simplification fails.
- `AUTO` is a mode, not a separate magic action button. It chooses the first eligible path that actually passes required connection/path proof.
- Normal logical presets are shown together with readiness and exact unavailable reason.
- `CUSTOM` is a preset system, not a comma-separated text prompt. The picker shows saved custom presets and `New custom preset…`.
- The custom builder is a dedicated page/sheet with selectable layers/features, compatibility/readiness feedback, name/save/connect actions and delete for user presets. The runtime still chooses only a validated compatible stack containing every requested layer and fails closed if no such stack exists.
- Saved presets contain product choices only; private node credentials remain in the private node store.

## Settings

The detailed settings surface exposes, where supported by the selected node/runtime:

- Kill switch policy. A compact quick toggle is also beside Connect.
- IPv6, **On by default for newly normalized Router VPN profiles**.
- Full home-LAN access policy.
- WireGuard / AmneziaWG base preference and compatible fallback.
- MTU policy: Auto measured by default, Fixed/manual override, current effective MTU and Retest. Retest is path/config specific; a fixed profile MTU applies until changed. On connection, Auto uses the best valid measurement available for that path/config and remains truthful about the source.
- DAITA-like traffic padding. It stays bounded/non-amplifying and is never described as Mullvad DAITA itself.
- Jumbo TUN / jumbo packet option when supported.
- Port forwarding / Protected-DMZ entry point only for routable tunnel modes with authenticated home-node ownership; proxy-only paths never claim arbitrary DNAT.
- AUTO filters: `Require encrypted` and `Require obfuscation`. Both are Off by default. When enabled, AUTO/SMART candidate selection rejects non-matching candidates before attempting them and reports the filtering reason.

## DNS

The primary sheet can change the selected DNS policy without navigating away from the map. Detailed DNS supports Home AdGuard, Fastest measured, Custom, DoT, DoH, DoH3 and Rescue; common IPv4/IPv6 resolver choices remain available. Measurements are real DNS-query RTT, not ICMP, and the selected session's DNS proof is authoritative.

## Cross-platform consistency

- No eight-tab top navigation in the daily app.
- No PWA/browser shell as the final daily app.
- Native detail pages may use platform-standard navigation, sheets, dialogs and keyboard shortcuts.
- iPad/desktop can expose more map and side detail at once; phones collapse the same controls into the bottom sheet.
- Buttons, mode/node cards, DNS controls, progress, maps and settings must remain usable at small windows, high DPI/scaling, phone portrait/landscape and tablet/desktop sizes.
- Setup Center remains the separate authenticated deployment/admin surface.

## Truth / safety invariants

- Real coordinates only.
- Lowest-latency selection only from actually measured nodes (robust multi-sample metrics remain authoritative).
- AUTO/SMART/CUSTOM/ALL never fake runtime compatibility.
- Multihop means a real entry → exit → Internet path with distinct nodes and real exit proof.
- Actual public exit is displayed/proved separately from a local/proxy address.
- DNS choice changes the real tunnel resolver path and is session-proved.
- Kill switch, MTU, IPv6, forwarding, DAITA-like padding and jumbo controls reflect actual platform/runtime support; unsupported controls explain why.


---

<a id="section-windows-owned-sockets"></a>

# Windows owned sockets and WFP protection

Windows strict Direct Tor needs a physical socket owner inside the existing
native runtime. An application path or a process ID alone does not distinguish
its permitted transport sockets from ordinary application traffic. The native
source therefore holds a fresh disabled account token, retains the original
Winsock endpoint, and verifies the actual ALE endpoint, token statistics,
application identity, address family and bound tuple before a permission can be
installed. The separate identity gate executes those checks on Windows.

## Managed baseline

The Go WFP adapter creates one persistent managed sublayer. Its bounded,
canonical provider data records the original session, source fingerprint,
network generation, selected protection policy, captured LAN prefixes and DHCP
renewal servers. A new session reads the entire old record and complete rule
set, then replaces the old baseline and installs its new baseline in one BFE
transaction. Unknown records, extra filters and altered rules are rejected.

A separate dynamic sublayer acts as the exclusive native-session lock. It has
no traffic filters. Its fixed object key prevents concurrent owners from
adopting the same baseline, and the same dynamic BFE session owns every socket
and tunnel permit. BFE removes dynamic objects when that process/session ends.
Only the persistent baseline survives. Management ACLs on these objects grant
access to Administrators and SYSTEM; the adapter changes no foreign sublayer,
filter, Firewall profile default, route or existing account.

The baseline covers both IPv4 and IPv6. Exceptions are loopback, bounded DHCP
and neighbor discovery, and the captured Home LAN policy. Public peers receive
no endpoint-wide or all-port rule. Each physical permit requires the isolated
user SID, interface LUID, protocol, exact local address/port and exact remote
address/port. Socket descriptors remain owned until the corresponding filters
are independently absent. Late native operations retain their resources for
retryable cleanup.

The seven-second grant receipt is an application admission deadline. WFP does
not attach that timer to a filter. A separate memory-only broker monitor and
socket I/O deadlines stop new data admission if a control call stalls; the
source retains its exclusive handles while exact filter removal is pending.
Bytes already accepted by Winsock before cancellation can remain in kernel
queues. Their filters still identify the same isolated user, interface and peer;
they do not authorize another process or a replacement socket. Process death
closes the handles and BFE's dynamic session. Actual connected/queued-I/O,
blocked-control and process-death tests are required separately before Windows
dynamic admission, including the distinction between interrupting new writes
and retracting bytes the kernel already accepted.

The native Box supplies its actual TUN readback to the tunnel policy. An MTU
replacement first retires the old tunnel permit, then binds the returned native
reader, including a rollback that has a different interface index. A stale
network callback cannot acknowledge another generation's tunnel grant.

On-connect cleanup removes the exact captured baseline after all dynamic
permissions, sockets and token ownership have drained. Always retains the
baseline. Explicit recovery acquires the same exclusive session lock and
removes only a completely validated managed baseline; it refuses a live owner.
A cancelled recovery that never reached the caller cannot make a late policy
change. Closing an old owner cannot delete a replacement owner's lock.

## Verification and remaining integration

`deploy/test_desktop_windows_identity.py` is the actual Windows account/token,
Winsock and ALE proof gate. `deploy/test_desktop_windows_wfp.py` exercises the
actual BFE baseline, exclusive ownership, Always replacement, record/rule
rejection and explicit recovery. Every filter in the WFP fixtures additionally
matches the exact test executable, with the production loopback exemption
omitted. Tests do not change the host's Firewall profiles or other applications'
network policy. Production negative controls must fail their intended assertion;
a compiler error, missing capability, timeout or skipped test is not accepted.

`deploy/test_desktop_windows_traffic.py` adds the actual TCP/UDP IPv4/IPv6
transfer and renewal cases. A copied executable with a different independently
read AppID hosts the local peers; the subject's scoped rules therefore cannot
accidentally exempt its own listener. The gate also rejects ordinary-token
traffic, holds a native control operation while a real Winsock send is already
backpressured, checks independent data expiry and retained source handle/port
ownership, and kills a separate process to inspect BFE dynamic-object rundown.
The crash case deliberately exercises BFE lifecycle without creating an orphan
test account; isolated-token cleanup has its own identity and traffic cases.
These are required tests. At commit
`d6337bea2ee3c5f6d52351b0971b0c95bbc98649`, the completed identity, baseline and
traffic steps in [Windows job 123224546154](https://github.com/Eabusham2/router-vpn/actions/runs/40805819408/job/123224546154)
passed: 17 identity cases with 12 rejected production mutants; 12 baseline and
status cases with eight rejected mutants; TCP/UDP IPv4/IPv6 transfer and renewal,
blocked-control backpressure, actual process death, selected-adapter DHCP
readback, and two rejected traffic mutants. That workflow was subsequently
cancelled. These completed step results establish their named native
boundaries, not a complete release or the still-pending full shipping path.

The same runner exercises read-only DHCP capture for an actual IPv4 adapter and
rejects missing, substituted or malformed lease records. The factory helper
selects by the captured interface index, never by adapter enumeration order.
Static IPv4 adds no renewal server, and IPv6-only execution does not call this
IPv4 API. No DNS lookup, adapter change, route change or DHCP request is made.

### Generated native factory

`mobile/desktop/tor_physical_windows.go.tmpl` is registered in the same pinned
native preparation as the Linux and Darwin factories. It installs the owned
source at native Initialize, after default-interface capture and before TUN
startup. The real network monitor's selected name, index, addresses and masks
must agree with kernel readback. IPv6 Off omits that family's physical binding;
Home LAN uses the selected adapter's actual private or link-local subnets. The
factory captures only that adapter's IPv4 DHCP server and separately projects
the compiler's exact literal private destinations. No profile supplies an
account SID, token, LUID, firewall object key or helper executable.

Changes to the captured interface identity, address list, mask or up state
invalidate the in-memory generation. The WFP owner independently rechecks its
kernel LUID and local address before socket grants. A partial or late native
constructor remains owned through cancellation and Close; it cannot be
discarded while its operation is still completing.

Matching Windows native packaging runs `TestRouterVPNWindowsPhysicalFactory`.
Those wiring tests read the actual adapter, mask and DHCP lease and exercise
Initialize, replacement, partial-owner retention and teardown. They explicitly
replace only the privileged constructor and therefore do not substitute for
the real WFP gate or the final compiler-to-native selected-DNS and wrapper
composition. Public Windows strict dynamic admission remains closed until that
composition is verified.

### Prospective bootstrap composition

`deploy/test_windows_physical_bootstrap.py` verifies the exact prepared source
closure and then compiles the real Box, generated Windows factory, native
interface monitor, isolated socket owner, WFP policy and PT resolver callback.
Its explicit fixture selects Cloudflare HTTPS DNS at `1.1.1.1:443`; that is a
test profile, not a product default or a fallback. The query must receive a real
answer through the captured resolver, while an ordinary process-token socket
to that same endpoint is rejected by WFP. Independent readback checks the live
kernel endpoint and its exact resolver, local tuple, interface and capture.
The fixture also rejects a different compiler source, uncaptured context,
replacement DNS object and retired network generation, then checks exact
baseline/session-lock absence after cleanup.

Every test filter additionally matches the running test executable. The TUN is
the existing harmless Box fixture, so this gate changes no host route and does
not establish an actual TUN, Tor circuit, Connected state, full wrapper launch
or physical-device acceptance. The separate Windows diagnostic prepares the
same pinned core/Xray sources with CGO disabled and makes no package, PQ-link
or race claim. Matching Windows package builds also run the gate using their
actual shipping tags, verified PQ link environment and supported race mode.

While public Windows admission remains closed, `--prospective` overlays only
the reviewed static OS predicate in the test compilation. Additional test-only
visibility and executable scope also exist only in the Go overlay; no ordinary
binary accepts an environment, profile or request switch for those controls.
Cross-compilation alone is not an executed Windows result. Before publishing
admission, remove `--prospective` from both gates and rerun against the
unmodified admitted compiler/native source. This bootstrap evidence and the
separate remaining connection/installation evidence must remain distinct.

### Real Wintun identity and retirement

`deploy/test_windows_physical_tunnel.py` adds a separate actual Windows gate
for the shipping Wintun reader and `BindTunnel` / `RetireTunnel`. It reconstructs
the checksum-pinned sing-tun preparation in a private directory and compares
every prepared source and embedded driver byte before compiling. Extra, missing
or changed dependency files fail the gate; the subject is never repaired.

The test creates uniquely named, held native adapters with external
configuration and `AutoRoute=false`. It configures no addresses or DNS and
adds no default route. It compares the retained adapter's LUID with independent
Windows index/LUID readback, then reads the real WFP permit conditions through
a separate BFE session. IPv4-only and IPv4/IPv6 policies must have exactly their
required directions and families. A captured physical interface, wrong network
generation, duplicate binding and stale reader retirement are rejected. A
replacement reader remains authorized when its predecessor sends a late
retirement callback. Exact filter absence precedes reader close; complete
interface enumeration then proves the created adapters' names and LUIDs absent.

Three compiled production mutations must fail their intended native assertions:
allowing the physical interface as a tunnel, replacing the retained LUID in a
permit, and accepting another reader's retirement. All filters additionally
match only that test executable. There is no public OS-admission overlay in this
gate. Both native architectures run the standalone diagnostic; matching package
builds repeat it with their shipping compiler/link settings and supported race
mode. Cross-compilation is not actual Wintun acceptance. The bounded identity
and retirement result does not establish tunnel packet forwarding, selected-path
DNS through the TUN, a Tor circuit, Connected state, or physical-device behavior.

The WFP baseline gate by itself does not prove connected socket traffic or the
shipping Windows wrapper/factory composition. Those gates and the complete
native integration remain required before Windows strict Direct dynamic Tor
admission can be enabled. Cross-compilation is recorded separately from actual
Windows execution. The existing PowerShell WFP fixture is also separate from
the legacy `windows-kill-switch.ps1` production path; its success cannot certify
that legacy path or authorize changing another application's Firewall defaults.

Microsoft primary references:

- [WFP object/session lifetimes and transactions](https://learn.microsoft.com/windows/win32/fwp/object-management)
- [WFP access control](https://learn.microsoft.com/windows/win32/fwp/access-control)
- [Application and user conditions](https://learn.microsoft.com/windows/win32/fwp/permitting-and-blocking-applications-and-users)
- [User-mode ALE endpoint inspection](https://learn.microsoft.com/windows/win32/api/fwpsu/nf-fwpsu-fwpsaleendpointgetbyid0)
- [Winsock socket duplication](https://learn.microsoft.com/windows/win32/api/winsock2/nf-winsock2-wsaduplicatesocketw)
- [IPv4 adapter and DHCP lease readback](https://learn.microsoft.com/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersinfo)
- [Wintun retained adapter, session and close API](https://git.zx2c4.com/wintun/about/)


---

<a id="section-windows-tor-arm64"></a>

# Windows ARM64 Tor helpers

Windows ARM64 can use Router VPN's Tor bridge implementation with the
checksum-pinned x64 standalone Tor process under Windows 11's built-in
userspace emulation. The Router VPN client, Go pluggable transports, sing-box
packet engine and VPN kernel driver remain ARM64. No x64 driver is installed
or emulated. The connection does not launch an external Lyrebird process.

The controller and installer use Microsoft's `GetMachineTypeAttributes` API
and require `UserEnabled` for `IMAGE_FILE_MACHINE_AMD64`. A missing API, query
failure or unsupported host does not become Ready. The installer verifies the
official Expert Bundle SHA-256, archive boundaries, unique helper files, and
bounded actual Tor and bundled Lyrebird version-process execution before
adoption. The Expert Bundle still contains Lyrebird; the active connection's
transport implementation comes from the separately pinned native Go package.

The capability API reports `helper_execution` so the compatibility path is not
mislabelled as ARM64-native Tor. Source package/pid/lifecycle ownership, private
configuration, strict firewall boundaries and dynamic Tor exit proof remain in
force; the selected bridges and cryptographic protocols are not substituted.
The wrapper assigns the native command's suspended child to an unnamed,
non-breakaway, kill-on-close Job before resuming it. Native SAFECOOKIE/PID
authentication, owned worker drain and actual child exit govern shutdown;
an exit code or wrapper receipt alone cannot declare a native tunnel closed.

The same-SHA release Windows matrix runs the actual Go host query and the
shipped installer's version checks on both x64 and Windows 11 ARM64. This proves
helper execution and packaging, not a live Tor circuit, leak test or device
acceptance. No Tor connection, driver or firewall is started by the smoke test.

## Sources and immutable runtime

- Microsoft Windows on Arm emulation: https://learn.microsoft.com/en-us/windows/arm/apps-on-arm-x86-emulation
- Machine capability API: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getmachinetypeattributes
- Expert Bundle 15.0.24 / Tor 0.4.9.13: https://dist.torproject.org/torbrowser/15.0.24/sha256sums-signed-build.txt
- Windows x86_64 SHA-256: `e9dc6ccc93cd6afa507193f4de284d6424233ff5102155cd2c94b259e8a22b65`.
