# macOS protection for complete CONNECT execution paths

The existing macOS ordered firewall helper now accepts the complete three-to-eight-member
CONNECT execution shape already admitted by the desktop controller. It retains every
paired prefix row, the penultimate HTTP or HTTPS CONNECT member, the paired Shadowsocks
final, and the strongest captured protection and LAN policy. SOCKS execution keeps its
separate three-member bound. This changes no endpoint exception or native source authority.

The original saved-profile reconstruction, member digest, private journal, PF reference,
retirement, and receipt checks remain in the shipping call path. Local CONNECT and
CONNECT execution can now both describe a longer path; their receipts and cleanup
authority remain distinct. A valid shape alone cannot adopt or release the other owner.

## Executed validation

On source base `0b42100a1246aed3a1c08e6cca662abfccb5e305` plus this change,
all 114 tests in `modes/test_darwin_owned_pf.py` passed in 8.504 seconds. The
existing imported-execution coverage now exercises four- and eight-node CONNECT
captures as well as the original three-node captures, with WG, AWG Fast and AWG Strong.
Saved-member replacement cases still require rejection before a native mutation.
A new test checks current/readback, retirement and release with the other legal
CONNECT family's capture, with and without the original receipt, and verifies
that the actual journal and command list remain unchanged.

The complete `deploy/test_darwin_pf_journal.py` gate also passed, including all
original isolated source-defect checks and the added defect that reinstates
three-node-only CONNECT execution. That defect must fail the original saved-member
baseline assertion. The SOCKS length and Shadowsocks admission defects retain
their separate controls. Existing per-process time limits are unchanged.

These tests execute the shipping Python dispatcher, private filesystem and journal
with the suite's explicit PF/kernel model. They do not establish installed macOS
packet behavior, encrypted networking, device acceptance, or a green release.
The full gate remains required by the existing macOS workflow.

The concurrent desktop CONNECT implementation was preserved. Four overlapping
unpublished Go draft edits were retained in a recovery patch and were not replayed
over that upstream commit; this unit closes the independently observed firewall
helper gap.
