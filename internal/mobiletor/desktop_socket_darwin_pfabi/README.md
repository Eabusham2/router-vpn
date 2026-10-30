# Pinned Apple private PF userland declarations

These files are unmodified copies of `apple-oss-distributions/xnu`, tag
`xnu-11417.140.69`, immutable commit
`43a90889846e00bfb5cf1d255cdc0a701a1e05a4`. `UPSTREAM.json` records each original
path, SHA-256 and Git blob identity. The Git tree at that commit was independently
read to verify all three blob identities. `deploy/darwin-pf-abi.py` verifies the
bytes and complete dependency/license closure before native source preparation.

Apple declares `net/pfvar.h` a private interface and installs it as a private
header. It is absent from the public SDK used by the native CI host. This copy
does not make the interface public or stable. The local wrapper includes the
SDK's public prerequisites before enabling only the pinned PF header's private
declarations; it does not duplicate or guess kernel structure layouts.

The native qualification targets are explicitly limited to Darwin `24.6.0`,
macOS build `24G830` on AMD64 and ARM64, and build `24H232` on ARM64 only.
The latter is the independently observed October 28 ARM runner update, from
macOS 15.7.9 to 15.8.2, recorded in the [runner image release](https://github.com/actions/runner-images/releases/tag/macos-15-arm64%2F20261028.0489).
Apple's public XNU tags were re-read on October 30: `xnu-11417.140.69` remains
the newest published Darwin-24 family source. This does not prove that a later
OS binary has the same private ABI. Each target must execute the scoped
single-FILTER commit/rollback and exact rule/namespace readback; its receipt
also records the actual `kern.version`. Selecting a target is not acceptance.
The Intel `24G830` probe passed at Router VPN commit `7c3784e9362110357e8c6af73d8db895690a4657`,
[job 124096237888](https://github.com/Eabusham2/router-vpn/actions/runs/41065656538/job/124096237888).
The ARM `24H232` probe had been rejected before `/dev/pf` by the former build
bound, so its transaction acceptance remains pending this qualification.
Other build/architecture pairs are rejected before the private adapter opens `/dev/pf`. OS updates require fresh
primary-source review and native qualification before expanding the contract.
The complete kernel rule readback and owned namespace absence assertions remain
mandatory; an empty rule listing alone cannot establish anchor retirement.

The narrow probe operates only on fresh loopback addresses and its captured
temporary anchor. The production PF loader is unchanged by this dependency
repair. Existing anchors created by a different loader are not repaired by
decrementing unknown references or flushing shared PF state.

## License and attribution

This directory contains Apple Original Code under the Apple Public Source
License 2.0; the complete license is `APPLE_LICENSE`. The headers also contain
their original third-party copyright, redistribution terms and disclaimers.
All of those notices are retained byte for byte. The repository's MIT license
does not replace these upstream terms. Source is available at the immutable
URLs in `UPSTREAM.json` and in this directory. Any distributed executable that
uses these declarations must carry this notice, the full license and the
upstream header notices with its other third-party documentation before the
native loader is activated in a shipping package.
