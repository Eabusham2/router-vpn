# Apple ordered profile snapshot source audit

The complete source audit at `250840cb40211f5310da7d874669bf98928e9088`
failed because it still required `record.chainPolicies = try members.map`.
The shipping snapshot now enumerates every captured member and selects its
original profile using `nodes[position].id`, including independent imported
members that share a linked record.

The audit now requires that actual implementation: equal selected/member
counts, the complete ordered enumeration, one matching identity at each
position, and each member's original proof, external identity, and preferences.
Commented copies of a complete capture cannot satisfy this source check. The
existing Load, original-record, private-data, and atomic restore checks remain.

Validation on the exact source above passed the full profile settings audit,
all 40 existing omission controls, and seven new scoped controls. The added
controls reject reordered members, incomplete selected order, duplicate or
wrong-position identities, a missing original proof, borrowed control-node
preferences, and a commented complete capture paired with a truncated map.
The original truncation control now targets the actual enumerated map.

The original failure was retained. The corrected run captured 45 input files;
their aggregate SHA-256 is
`812f8dba5b7e5ec30b34b00ef7879fab0124c4b95ecc7177dbbca433948707dc`.
This is source-audit evidence. No Swift production code changed, and this run
does not establish Swift execution, native routing, or physical-device acceptance.
