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
