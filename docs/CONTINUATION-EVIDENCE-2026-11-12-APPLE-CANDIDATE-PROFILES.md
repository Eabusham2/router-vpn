# Apple candidate timing to a future connection profile

This unit adds explicit future-profile preparation and saving to the retained-prefix Apple candidate view. It does not load the profile, edit linked node records, or change the active connection.

## Original source and ownership

Preparation starts from the original connection's captured launch input and selected final profile. The candidate must still have the exact member input that supplied its timing. The complete proposed graph is compiled through `IOSNodeChainCapture` and the shared Go compiler. Each retained prefix member's input and private identity source must match the original launch bytes.

A paired candidate replaces the suffix after the selected WG/AWG prefix. An imported candidate is admitted only after the first packet prefix and retains the original paired final node. The latter also requires exact original final profile, selected DNS policy, Shadowsocks assets and WG identity assets; a changed saved final cannot silently substitute a new policy. All three imported SS2022 methods compile through the original paired AES-256 final.

The existing shared compiler permits only an AES-256 SS2022 paired final. A measured paired AES-128 or ChaCha20 candidate therefore retains its valid TCP score but receives a clear future-profile refusal. This unit does not widen that native graph boundary.

## Adoption and persistence

The original in-memory score token, fixed receipt expiry, current catalog/source files, original connection/session and selected prefix are rechecked before preparation, after fresh native ownership observation, and immediately before atomic profile persistence. Selection generations reject late preparation or saving callbacks. Expiry and cancellation clear prepared proposals. Concurrent idle ownership observations are serialized with a bounded wait; native deadlines and cleanup ownership are unchanged.

The persisted record uses the existing complete connection-profile schema, with all ordered references, source kinds and per-node preferences. It contains no node credentials or private assets. A stale final observation prevents the write. The normal disconnected Profiles → Load path remains responsible for source revalidation and compilation before a later connection.

## Executed verification

- `deploy/test_ios_node_candidates.py`: 67 shipping Swift/shared-Go capture, receipt and proposal checks passed; three causal source mutations were rejected. Includes all three imported methods, original prefix mutation, original final DNS mutation, measured input mutation and paired-final cipher refusal while timing remains eligible.
- `deploy/test_ios_node_chain_profiles.py`: 116 shipping Swift persistence/load checks passed; three causal mutations were rejected. Includes unchanged active selection/node records, no persisted credentials, stale atomic-write refusal, connected Load refusal and disconnected Load of complete imported profiles for all three methods.
- `deploy/test_ios_node_candidate_transaction.py`: original source/epoch/cancellation/adoption/drain controls and the foreign-owner causal control passed. The complete candidate controller typechecked with Swift 6 using explicit OS/store/UI boundary substitutes.
- Profile settings and iOS session mutation audits passed. `git diff --check` passed.

These checks execute the shipping Swift source and actual shared Go source compiler where described. They do not constitute a signed Apple SDK build, NetworkExtension installation, or physical-device candidate measurement acceptance. Existing mandatory Apple runtime-contract runners retain responsibility for those hosted build and lifecycle gates.
