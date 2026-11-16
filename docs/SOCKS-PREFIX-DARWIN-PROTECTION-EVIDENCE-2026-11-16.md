# Complete SOCKS execution protection on macOS

The Darwin firewall dispatcher still required exactly three members for a
SOCKS Server/Compare capture. Its execution-family parser now retains three
to eight members: every original paired WG/AWG prefix, the penultimate SOCKS
import and the independent paired Shadowsocks final. The saved-profile,
member digest, strongest protection, IPv6 and LAN checks remain mandatory.

The actual dispatcher and filesystem journal tests exercise all six supported
lengths with WG, AWG Fast and AWG Strong. Four- and eight-member captures cannot
borrow a Local SOCKS receipt, change a saved member or invent additional saved
nodes. The existing malformed-role, protocol, digest, canonical encoding and
aggregate-policy refusals remain; a nine-member capture is also rejected.

Validation on parent `5020cc90f9db892450efa5e26f2be5b89eafaf51`:

- `python3 deploy/test_darwin_pf_journal.py` passed all 20 baseline and 115
  dispatcher tests, then rejected all 53 separately executed causal defects.
- Restoring the old SOCKS trio-only condition fails the original saved-member
  baseline assertion for the newly supported longer paths. The Shadowsocks
  and CONNECT omission controls still isolate their own required families.
- The source closure remained unchanged during the complete gate, and the
  existing 30-second per-process bound was preserved.

The validation log SHA-256 is
`e96567584ea53a63a9d0cfdd461b6f5a0629764513690bcf56e39d04270b09a0`.
These tests use the actual helper, capture and private journal with an explicit
PF/kernel backend model. They do not establish installed macOS PF/utun,
encrypted networking, package publication or physical-device acceptance.
The shared longer SOCKS runtime and desktop product integration have separate
source and native evidence; this helper change alone does not complete them.
