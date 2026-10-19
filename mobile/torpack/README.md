# Embedded Tor C package

`deploy/build-mobile-tor-package.py` builds the exact Tor, OpenSSL, libevent and
zlib source archives in `sources.json`. Archive and license SHA-256 checks run
before source compilation. The existing worker correction and the additional
embedded-process patch apply only to their complete, pinned source bodies.

Android uses NDK `28.0.13004108`, API 24, all four app ABIs and 16 KiB compatible
ELF segments. `libroutervpn_tor.so` contains the static C dependencies and exports
only the six functions in `mobile/tor/routervpn_tor_host.h`. Local symbol binding
isolates its OpenSSL, libevent and zlib symbols from the existing Cronet runtime.
Apple builds an extension-safe dynamic `RouterVPNTor.xcframework` for iOS 17:
arm64 devices and arm64/x86_64 simulators. Its two-level namespace and export list
provide the same separation. A verified multi-target TAPI stub gives Cgo one
framework search path for both arm64 platforms; Xcode embeds the actual dynamic
framework in the containing app.

The package contains source/toolchain provenance, public headers, all four C
dependency licenses, the embedded PT source notices and module lock, and a
portable checksum list. Verification checks the complete allowed layout and each
file. Publication refuses linked paths, unrelated files and changed previously
owned files. A build also refuses to publish if its captured source inputs
changed during compilation.

## One owning Go runtime

`deploy/prepare-mobile-torpack.py` installs these templates in the already-pinned
Libbox module as `github.com/sagernet/sing-box/routervpn/nativetor`. No second Go
archive, gomobile package or Go runtime is shipped. Ordinary host graph parsers
compile the explicit unavailable backend. Android and iOS use the Cgo backend;
the `routervpn_tor_native_test` tag enables actual Linux C boundary tests.

`Start` checks the exact ABI and native version before crossing C. An instance
retains the sole control descriptor and the opaque native handle. `Control`
permits one claim; conversion always closes the original descriptor after Go
duplicates it. `Close(ctx)` starts final native retirement and bounds only the
caller's wait. A timeout keeps ownership and continues joining. Even a native
error or final shutdown cannot authorize another Tor invocation in that process.

VPN session disconnect must quiesce and reconfigure the resident controller.
Closing the owning control connection is final process-lifetime retirement.
`Status` preserves real native exit codes while the handle exists and returns
`ErrReleased` after storage is released. The ABI/version getters describe source
provenance; they do not prove a protected VPN session, circuit, DNS route or PT
worker shutdown.

## Build and executable gates

```sh
python3 deploy/build-mobile-tor-package.py --platform android \
  --output /tmp/routervpn-tor-android --source-cache /tmp/routervpn-tor-sources
python3 deploy/build-mobile-tor-package.py --platform ios \
  --output /tmp/routervpn-tor-ios --source-cache /tmp/routervpn-tor-sources
python3 deploy/prepare-mobile-torpack.py /path/to/pinned/sing-box \
  --native-package /tmp/routervpn-tor-android
```

Android requires the pinned NDK or Android SDK manager. Apple requires macOS with
the installed Xcode device and simulator SDKs. Both require a C toolchain, make,
Perl, autoconf, automake, libtool, pkg-config and patch.

The explicit Linux `--platform host-test` package exercises the same source pins,
worker/process patches and C ABI without claiming an Apple or Android SDK build.
The following tests exercise shipping functions rather than checking markers:

* `deploy/test_mobile_tor_loader.py`: unchanged Go owner/Cgo bridge, actual C ABI
  boundary doubles, races, descriptor ownership, timeouts and negative mutations.
* `deploy/test_mobile_tor_package_policy.py`: real package validators, exact-source
  patches, archive traversal rejection, no-write ownership failures and compiled
  ELF export/import/binding/stack/page-size negatives.
* `deploy/test_mobile_tor_package_runtime.py`: actual all-pinned packaged Tor,
  resident lifetime/descriptor tests, daemon rejection, incompatible-symbol
  interposition negative, and 32 network-disabled session configuration and
  quiescence cycles through the unchanged Go owner and shared controller.

Native PT packet flow, lower-route socket protection, circuit/node/DNS proof and
mobile session cancellation remain mandatory checks at the owning outbound and
platform boundaries. Package provenance never substitutes for those checks.
