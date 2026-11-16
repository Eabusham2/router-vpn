# Current SOCKS and CONNECT validator contracts — 2026-11-16

Authoritative run `43956538397` at source `a34a1b810fbfb2c77680e352d4d3b274afc714fe` exposed two stale validator contracts. SOCKS job `133612467493` stopped while constructing the `original-cancel-join` mutation because the original lifecycle now checks its self and candidate owners before cancelling proof. CONNECT child job `133612469232` stopped during source verification because its pinned physical regression inventory contained 52 records while the original gate requires 117.

The cancellation mutation now matches the current original lifecycle, preserves both owner checks, and omits only the same immediate `retireProof()` call. Its held-prefix case, failure witness, process joins and deadlines are unchanged. A new source test applies the mutation to the actual shipping template and verifies that candidate and measurement cleanup remain intact; missing, duplicated and changed-owner anchors are refused.

The shared SOCKS/CONNECT child validator now includes all 117 original physical records in their original order. The first 52 and their historical event-order replay remain unchanged. The added records cover Hysteria final layers and multiple imported positions already required by the canonical gate. The validator retains exact inventory equality, with new checks for every omitted record, duplicates, foreign records and the incomplete historical subset. No production Go/template code, native gate deadline or causal witness changed.

## Validation and remaining native evidence

The three focused Python suites passed 18, 20 and 9 tests respectively. Two separate Python counterfactuals restored the old cancellation anchor and old 52-record inventory; the new actual-source checks rejected both at their intended contracts. These checks do not compile or execute native code.

The downloaded hosted SOCKS artifact `14273366632` has SHA-256 `f82dc429161faa01f243b3dcde768393e88b7e5817955d7488bdbd13c1860977`. Its exact test events independently replayed successfully for all eight original baseline cases and the first three compiled causal controls. The fourth cancellation control never executed because its source anchor was stale. The later ordered-fifty and complete-prefix phases were not reached. The CONNECT child failure occurred before its native test images were built.

The repaired cancellation control and full 117-record physical child gate remain required native CI checks. This repair does not claim a complete native or release pass. The separate concurrent entry-candidate projection fix in parent `e8a7d9ff04bedab5b57b29fe0ba6d092a979ff2f` is preserved without alteration.
