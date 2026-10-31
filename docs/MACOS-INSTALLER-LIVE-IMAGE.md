# macOS installer: unresolved live executable identity

Recorded from native CI on October 31, 2026. This is an open installation
blocker, not a completed native-installation requirement. The shipping installer
still rejects a live process whose executable location it cannot establish.

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

## Next native experiment

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

The owned unlinked-child negative control calibrates these parent-generation
reads against the actual created child and its current test parent. Native
execution of the extended diagnostics remains pending until that exact source
passes on both Mac architectures.

No unknown process is excluded or killed. No broad retry expansion is justified
by the persistent ages above. A future retry may accept only actual resolution
or independently proved disappearance of the same captured process; waiting
longer by itself cannot close this blocker.
