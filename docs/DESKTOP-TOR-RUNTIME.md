# Bundled desktop Tor runtime

The complete desktop native bundle owns `tor-routervpn` (`tor-routervpn.exe`
on Windows), `TOR-RUNTIME.json`, `TOR-SOURCE-LOCK.json`,
`TOR-PADDING-SOURCE-LOCK.json`, and `TOR-LICENSES.json`. These five files are
included in the existing `NATIVE-RUNTIME.json` payload inventory and exact-source
package. They are installed and upgraded with the native runtime transaction;
private node/profile files remain separate.

## Build and native acceptance

`deploy/build-desktop-tor.py` uses the same four pinned upstream source archives
as the mobile and server builds. OpenSSL, libevent and zlib are linked statically.
The Tor process keeps its original standalone lifecycle, with only the captured
outgoing padding extension applied. The installed Linux executable has no ELF
interpreter or dynamic dependencies. macOS permits only its explicit system
libraries, and Windows permits only the explicit OS/API-set DLL inventory.

| Application package | Tor executable | Required execution gate |
|---|---|---|
| Linux AMD64 | Linux AMD64 | Actual native C tests and disabled-network control |
| Linux ARM64 | Linux ARM64 | Actual native C tests and disabled-network control |
| macOS Intel | macOS x86-64 | Actual native C tests and disabled-network control |
| macOS Apple Silicon | macOS ARM64 | Actual native C tests and disabled-network control |
| Windows AMD64 | Windows AMD64 | Actual native C tests and disabled-network control |
| Windows ARM64 | Windows AMD64 user-mode helper | Actual tests on Windows 11 ARM64 under supported x64 emulation |

The Windows ARM64 application and driver remain ARM64. Its Tor receipt explicitly
records `executable_target: windows/amd64` and
`execution: windows11-amd64-emulation`; it does not assert a native ARM64 Tor
build. Microsoft documents the distinction between user-mode x64 emulation and
native drivers in [Windows on Arm emulation](https://learn.microsoft.com/en-us/windows/arm/apps-on-arm-x86-emulation).

The Windows prerequisite job cross-compiles Tor and the matching C tests with
the existing checksum-pinned LLVM-MinGW toolchain on Linux. Its
`TOR-COMPILE.json` is marked `compiled-awaiting-native-execution`; this artifact
cannot be consumed as a completed package. Each actual Windows runner validates
the entire source/file closure, executes the tests, then seals its own platform
receipt. Linux and macOS compile and execute on their actual architecture.

The native test selectors are `routervpn_padding/..`, `relaycrypt/..`, and
`cellqueue/..`. The separate test executable is CI material and never enters the
installed native payload. Tor's Linux test executable may use the host C loader;
the installed Tor executable still requires fully static linkage.

## Offline owner and extension proof

Packaging starts the actual process with `DisableNetwork=1`, a fresh private
data directory, no SOCKS/DNS/transparent listeners, and one numeric loopback
control listener. The gate verifies the exact cookie path and SAFECOOKIE server
authentication, rejects incorrect authentication, checks the process ID,
listener inventory and zero traffic counters, and confirms the selected PT
socket configuration without enabling network traffic.

`ROUTERVPN_PADDING INFO` must reject a controller before `TAKEOWNERSHIP` and must
return the exact compiled outgoing-only capability afterward. An attempted
padding start must remain rejected while networking is disabled. Closing the
owning control connection must terminate the process. A stock Tor executable
passing `--version` cannot satisfy these checks.

`deploy/test_desktop_tor_package.py --package ... --target ...` repeats these
checks after relocation and verifies the package's source locks, licenses,
architecture and dependencies. `--within-native` validates the Tor files inside
the larger native inventory. Six-target object-format fixture tests exercise
negative metadata and dependency cases; those fixtures are explicitly separate
from actual C/process evidence.

The controller's `verifyBundledTor` resolver verifies the complete native
package and exact Tor payload at the fixed owned path. It does not search PATH
or an unrelated stock Tor directory. Native packaging CI also runs the actual
Go receipt/architecture verifier against the produced C executable. macOS
signing signs both native executables, updates only their controlled receipts,
and preserves the source and license records.

These build/control gates do not establish public-network bootstrap, selected
live circuit behavior, physical-device acceptance, Apple distribution signing,
or completion of every Tor graph requirement. Those retain their separate
runtime and device acceptance evidence.
