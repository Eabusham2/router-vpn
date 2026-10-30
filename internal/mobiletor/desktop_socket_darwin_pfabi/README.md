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

The native qualification target is explicitly limited to Darwin `24.6.0`,
macOS build `24G830`, on AMD64 and ARM64. This is the observed build whose
scoped single-FILTER commit/rollback and exact rule/namespace readback must be
tested. Selecting that target is not evidence that either architecture passed.
Other builds are rejected before the private adapter opens `/dev/pf`. OS updates require fresh
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
