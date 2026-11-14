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
Darwin PF, socket, process, or utun acceptance. Other native-runtime and ordered
host gates have separately pinned compiler/provenance contracts; this scoped
change does not claim to migrate or validate them.
