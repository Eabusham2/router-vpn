# Captured iOS control identity: original source suites

The d887 hosted iOS job stopped in its source contract step before Xcode
application compilation. The mutation fixture still targeted `capture.finalProfile`
after the shipping constructor had moved to `capture.controlMember.profile`.
Both the OpenVPN and imported Shadowsocks fixtures now mutate the original
captured-control comparison. Every original rejection witness is retained.

The full OpenVPN target passed 576 actual Swift/shared-Go checks and all four
compiled rejection controls: final-control identity, latency source, complete
members, and generation. The imported Shadowsocks target passed 804 actual
Swift/shared-Go checks and its same four independent rejection controls.

The verification used local repairs 579e10e70417cd289cf92047552aa91387c5ece5
and 30c8ccd80e14c73d3a27cd64c14ead190c37cac3, based on d887. Main commits
e327a95ca and c6773e15d independently made the same two mutation-anchor
repairs. The OpenVPN fixture differs only in an additional diagnostic assertion
message in the local verification copy; the source comparison and substitutions
are identical.

The complete original success logs and hosted failure log are losslessly gzipped.
`provenance.json` records their uncompressed hashes and exact hosted job identity.
`SHA256SUMS` covers the retained files. This evidence does not claim a completed
Xcode build, signed application, installed device, or final release.
