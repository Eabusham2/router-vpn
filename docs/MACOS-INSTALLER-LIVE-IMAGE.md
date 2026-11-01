# macOS installer: unresolved live executable identity

Recorded from native CI on October 31, 2026. First-install and legacy inventory
remain an open installation blocker. Managed upgrades now have a separate,
bounded main-image comparison path backed by a complete original-generation
receipt. Its native acceptance is tracked separately below; neither a protected
receipt alone nor the diagnostic parent chain authorizes installation.

## Actual observation

The [installer contract run for `fb9088cc`](https://github.com/Eabusham2/router-vpn/actions/runs/41249185650)
passed its controller/supervisor ownership tests on both architectures, then
failed the actual global process inventory during installation validation.
Both jobs passed the owned copied-and-unlinked executable negative control:
the process remained live, the mapping probe found the exact owned file object,
and `proc_pidpath` returning `ENOENT` did not authorize installation.

| Native job | Host | Unresolved process start, UTC | First job log, UTC | First project test, UTC | Age at inventory refusal |
|---|---|---|---|---|---|
| [124678921752](https://github.com/Eabusham2/router-vpn/actions/runs/41249185650/job/124678921752) | Apple Silicon, macOS 15.8.2 / 24H232 | 22:39:49.706829 | 22:41:10.565279 | 22:41:39.010726 | 216.25 seconds |
| [124678921774](https://github.com/Eabusham2/router-vpn/actions/runs/41249185650/job/124678921774) | Intel, macOS 15.7.9 / 24G830 | 22:18:17.886364 | 22:41:27.415925 | 22:42:29.921879 | 1,692.53 seconds |

The observed processes were PID 927 / parent 925 and PID 973 / parent 971,
respectively. Both reported UID 0, live BSD status 2, and `proc_pidpath` result 0
with errno 2. Their later bounded probes retained the same unique ID and exec
version before and after mapping inspection. The Intel main UUID was all zero.

The first several mappings referred to an unlinked UID 501 / GID 20 file; the
probe returned eight mappings on Apple Silicon and seven on Intel. These are
mapping observations. They do not identify the main text vnode or establish
that the process cannot use the previous Router VPN installation. Process names
and file owners likewise grant no exclusion authority.

The start timestamps precede this job's fixture launches. They therefore do not
support the hypothesis that these particular processes were created by the
controller or installation fixtures later in these jobs. Hosted provisioning
is a possible explanation, but the available records do not establish the
parent chain. The [upstream runner-image report #14756](https://github.com/actions/runner-images/issues/14756)
describes another root inspection retaining `ENOENT`; it is supporting context,
not identification of these processes or permission to skip them.

Decoded log SHA256 values:

- Apple Silicon: `b03b1c9cdbdc730a0dc48147e272d7ea768d4c83c5b80a1f7714a20454155fdc`
- Intel: `7a895c74b2f645caf4f3a1c81c2c36c62cd43b7687dc9957d84a9d40f9e45de5`

## `CS_OPS_PIDPATH` does not supply an alternative

Apple XNU was inspected at the probe's pinned revision
[`43a90889846e00bfb5cf1d255cdc0a701a1e05a4`](https://github.com/apple-oss-distributions/xnu/tree/43a90889846e00bfb5cf1d255cdc0a701a1e05a4)
and the then-current main revision
[`f6217f891ac0bb64f3d375211650a4c1ff8ca1ea`](https://github.com/apple-oss-distributions/xnu/tree/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea).
At both revisions, `bsd/sys/codesign.h` leaves historical opcode 4 only in a
comment; it does not define a supported `CS_OPS_PIDPATH` operation. More
decisively, `csops_internal` in `bsd/kern/kern_proc.c` contains no handler for
opcode 4. After the normal permission, process and policy checks, its default
dispatch returns `EINVAL`. The audit-token entry point reaches that same
dispatch. Neither exposes a cached code-signature pathname through opcode 4.

Relevant file SHA256 values:

| Primary source | Pinned revision | Current revision above |
|---|---|---|
| `bsd/sys/codesign.h` | `2f416bff50c43b88e5d964316c0eee050f095d582c998b4c8c7c3d6278c51cd3` | same bytes |
| `bsd/kern/kern_proc.c` | `d0b6903e785e90822796963d00ec0434ad73e7758e60f375924986fcd7d7e4c9` | `34f745a213769ffa47b4edace6e3e158f654075def1b0fe50edf97f9bf53589d` |

## Examined native process flavors

The current public/private `proc_info` declarations and `proc_pidinfo` dispatch
were checked through the declared flavor 34. No separate text-vnode device/inode
result was found in these examined interfaces.

| Flavor or interface | Actual object described |
|---|---|
| `PROC_PIDPATHINFO` (11) | Main text-vnode path, with the same path lookup whose failure blocks this installation |
| `PROC_PIDREGIONINFO` (7), `REGIONPATHINFO` (8), `REGIONPATHINFO2` (22), `REGIONPATHINFO3` (23), `REGIONPATH` (31) | VM regions or mapped vnodes; flavor 23 filters by device, not by main executable |
| `PROC_PIDVNODEPATHINFO` (9) | Process current and root directories |
| `PROC_PIDTHREADPATHINFO` (10) | Thread information and its directory vnode |
| PID descriptor/fileport enumeration and vnode-info flavors | Files referenced by the selected descriptor or fileport; no designation as the process's text vnode |
| BSD / short BSD / unique-identity / combined BSD-and-unique flavors (3, 13, 17, 18) | Process state, start, unique identity and execution generation; no executable file object |
| Other declared task, thread, architecture, workqueue, usage, coalition, exit, fault, platform and IPC flavors | Their respective process/task metadata; no alternative text-vnode identity was found |

Sources:
[`proc_info.h`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/proc_info.h),
[`proc_info_private.h`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/proc_info_private.h),
and [`proc_info.c`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/proc_info.c).
The thread-path call also resolves through `fill_taskthreadinfo` and
`bsd_threadcdir` in
[`bsd_kern.c`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/bsd_kern.c).
This bounds the interfaces investigated; it is not a claim that the product
requirement is impossible or that all native architectures have been exhausted.

## Extended native observation

The native workflows now collect a separate diagnostic snapshot before any
project fixture. The later ordinary installer gate still runs and still fails
on unresolved identity. Its diagnostic compares the later process start,
unique ID, exec version and UUID against that saved observation. Saved data is
explicitly marked as non-authoritative and never authorizes installation.

Each refusal also captures at most three later process observations, with at
most twelve native calls and a 200 ms loop deadline. State and unique identity
are repeated around each observation. Original-parent generation fields are
compared separately, so a reused parent PID, parent exec, or reparenting is not
silently presented as the same original parent. The controller fixture logs
the actual compiled controller and AppKit file objects before launch, allowing
their device/inode pairs to be compared with the unresolved mappings.

The [Intel job for `3c45a711`](https://github.com/Eabusham2/router-vpn/actions/runs/41251802590/job/124686698217)
executed the extended diagnostics. Before fixtures at 23:18:30 UTC and at the
later refusal at 23:21:57, it retained the same PID 963, native start
22:57:34.339848, unique ID 963 and exec version 2293. The original-parent fields
matched PID 961 (`sudo`, unique ID 961 / exec version 2289), then PID 959
(`hosted-compute-agent`, unique ID 959 / exec version 2285). Both parent edges
were checked against their native original generations. This process predates
the job's first log at 23:17:23 and the later project fixtures.

The unlinked mapping's device/inode was `16777220 / 12888350633`. The actual
controller and AppKit fixture images had inodes `12888402784` and `12888408218`
on that device. The separately created copied/unlinked owner had inode
`12888417620`; its negative control and original-parent calibration passed.
These records identify a preexisting hosted-agent process chain, not a project
fixture. The mapped vnode still does not become main-image authority, and the
installer continued to refuse it. Decoded Intel log SHA256:
`5de4f3f7a131f34b225f61db6e9131c6b723f863ec92967c64173d1280ebe418`.
The companion Apple Silicon job was cancelled while pending, so this extended
observation does not establish both-architecture acceptance.

No unknown process is excluded or killed. No broad retry expansion is justified
by the persistent ages above. A future retry may accept only actual resolution
or independently proved disappearance of the same captured process; waiting
longer by itself cannot close this blocker.

## Managed original-generation comparison

`client/install-macos-image.py` captures every CodeDirectory alternative from
every slice of an original retained Mach-O descriptor. It rejects unsupported,
unsigned, truncated and overlapping signature structures, and reads the file
identity back after hashing. This capture supplies identifiers; it is not a
replacement for the package's actual runtime and codesign verification.

Apple's supported `CS_OPS_CDHASH` operation (opcode 5) is distinct from the
obsolete pathname opcode. In the examined
[`kern_proc.c`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_proc.c),
it reads the retained process's `p_textvp` and `p_textoff`.
[`ubc_cs_getcdhash`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/ubc_subr.c)
returns the corresponding cached CodeDirectory hash. The audit-token entry
point compares only the supplied PID and exec version; this code uses it as a
kernel generation fence, not a fabricated authenticated audit token. Native
BSD start and unique/exec identity are repeated around the call. Any unknown
hash, error, changed process, changed exec generation or zombie refuses this
identity path.

After the ordinary installer has captured and verified a fresh stage,
`client/install-macos-generation.py` records the exact root device/inode,
target path, fixed code scope, every immutable directory identity, every
immutable file identity and digest, and every native CodeDirectory alternative. The protected receipt is
stored beside the fixed installation as `router-vpn-client.generation.json`.
The source manifest remains ordinary captured metadata. It never substitutes
for the actual complete file inventory.

A managed upgrade retains the original installation lock and receipt. It
rechecks the full code inventory and protected receipt around the native process
inventory. Missing, added, changed or replaced code, an incomplete native image
set, executable private files, receipt replacement and changed directory
ownership all refuse the upgrade. Mutable private settings remain separate.
The owned Python wrapper uses `-B -E -s -S`, preventing generated bytecode from
changing the captured code trees while preserving interpreter isolation.

For an unresolved path, the shipping inventory can exclude a live native image
only when its actual kernel hash is outside that fully revalidated original
image set and its PID/start/exec identity matches the unresolved capture. A
matching copied/unlinked executable still blocks. This decision is explicitly
an exclusion from the captured generation, not proof of process absence.
Unknown code signatures and denied native reads continue to block.

The [Intel identity job at `b11ae8b5`](https://github.com/Eabusham2/router-vpn/actions/runs/41253535068/job/124691810048)
passed both actual kernel controls: copied/unlinked `sleep` and `cat` retained
their distinct captured CodeDirectory hashes, and a wrong exec-version token
was rejected with `ESRCH`. The preexisting unresolved PID 1038 still returned
`-1 / EBADEXEC (85)` from the main-image hash operation. Its captured UUID was
all zero. That result supplies no usable image identity and remains refused;
the later original global inventory also failed on the same live process.
Apple Silicon execution was still queued at this read. Decoded Intel log
SHA256: `c1ed351bfa3d68ca5a91af240b0960b13496dcf8704d3d67c0b97fe3c163acfe`.
This is native evidence for the identity primitive and for the remaining hosted
blocker, not native acceptance of the later generation transaction.

The new root and receipt are promoted together under the existing transaction.
Failure restores the original application, original receipt inode/bytes, private
state and launchd integration. An interrupted or failed rollback retains the
owned recovery directory. The installed generation is revalidated before the
transaction completes.

There is no retrospective receipt adoption. A missing receipt selects the
original strict legacy/first-install inventory, including an absent target
directory; it does not establish that an older deleted executable never
existed. This implementation therefore does not claim that first-install or
legacy acceptance on the affected hosted runner is complete.

The required native gates are `deploy/test_macos_image_identity.py` and
`deploy/test_macos_generation.py`. They execute real copied/unlinked signed
images, wrong exec-generation tokens, matching versus foreign original-image
comparisons, and missing-member refusal on Intel and Apple Silicon. Parser and
transaction tests also execute defective source variants for omitted member
proof, omitted receipt ownership, matching-image acceptance, stale exec
adoption, legacy empty-inventory fabrication and rollback loss. Linux test
results cover those executable filesystem/control contracts; actual Darwin
kernel and packaged-install acceptance requires the corresponding native jobs.
