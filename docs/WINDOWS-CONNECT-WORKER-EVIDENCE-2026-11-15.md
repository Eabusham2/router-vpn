# Windows CONNECT execution worker correction — 2026-11-15

## Scope and cause

The installed Windows CONNECT execution gate added in `4e7d631269060525396750d9930bad451f4cdbc1`
projects the original encrypted server worker onto its Windows counterparty.
The original image capture required Unix executable bits, and the worker reader
required exact `0700` directory and `0600` file modes. Those checks cannot admit
the Windows file mode representation. This prevented the gate from reaching the
encrypted provider rather than identifying a tunnel failure.

The Windows fixture now projects the shipping private-runtime DACL and file
identity checks into that original worker and peer. It captures the Windows
machine directories for `SystemRoot`, `WINDIR` and `PATH`, and retains the original
Cronet loader, absolute library resolution, and compiled library size/hash seal.
The fixture builds and hashes its separate counterparty worker. Its receipt
identifies this Windows permission/environment projection explicitly.

The installed controller, physical alias ownership, original worker IPC and
protocol bodies, and fourteen required network scenarios remain in the gate.
The production Linux server permission checks retain their existing behavior.
The three added fixture/control inputs are included in the central native build
digest and its per-input omission controls.

## Executed local evidence

The repair was independently prepared against `4e7d6312` and integrated after
`c833afd2ed7be3891aa15bef4ca644c142548932`. Focused host and workflow tests were
rerun against the integrated source, including the newer worker stop diagnostics.

| Check | Result and boundary |
|---|---|
| Host runner | 12 roots passed, including the retained 20 alias records / 3 causal controls and 15 cleanup records / 4 causal controls. |
| Workflow contract | 7 roots passed. |
| Combined controls | 26 roots passed in the preparation lane. |
| Native artifact/workflow parity | Passed in the preparation lane. |
| Fresh pinned core and Xray preparation | Module tidy, dependency verification and AWG verification passed. |
| Full Windows AMD64 peer | Crosscompiled successfully with Go 1.26.3. |
| Full Windows AMD64 worker | Crosscompiled successfully with the final native library loader and seal projection. |
| Actual private-path control module | Crosscompiled successfully for Windows AMD64 and ARM64. |

These are local source, runner and compilation results. They do not establish
native Windows DACL, IPHelper, WFP, TUN or real-device acceptance.

## Required Windows execution

Before its existing network cases, the gate now requires ten native private-path
cases: private input, Windows mode representation, public input, NULL DACL,
unknown principal, writable code, permitted public code reads, hard-linked input,
replaced input, and captured machine environment. Three separately compiled
guard-removal controls must fail at the expected original check: code writer
permissions, private input reader permissions, and captured `SystemRoot`.

The actual Windows CI jobs must execute these controls and all fourteen installed
network scenarios. Publication of this correction does not itself establish
that execution, a completed release, or physical-device acceptance.
