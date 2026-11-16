# ImportedSS independent-policy causal contract — 2026-11-16

The exact-source SS2022 workflow exposed an obsolete negative-control expectation after the imported policy gained its own construction owner. Removing the outer prefix-pointer guard no longer disables the independent policy guard. The original `/policy` test correctly rejects a copied policy under that omission.

## Change

The production guards are unchanged. The source contract keeps all fourteen original pointer tests, requires the eleven applicable records to fail with the original witness when the outer guard is omitted, and adds a mandatory two-record positive phase proving that the independent policy still rejects its copied owner under the **same** omission. The validator still requires exact starts, verdicts, package completion, process joins, race checks and control witnesses.

## Focused validation

| Phase | Actual required verdicts |
| --- | --- |
| Original ownership baseline | 14 passed |
| Outer prefix-pointer guard omitted | 11 intended failures, each required witness retained |
| Independent policy under that same omission | 2 passed |

The nine Python contract-runner checks pass. Actual Go 1.26.3 execution retains `-race`, default vet, the 120-second Go timeout and 600-second process bound. All 6,295 tracked source inputs remain identical. A local session interruption occurred after the baseline completed; its complete receipt and raw log were preserved, and only the two unfinished phases were resumed with a smaller compiler memory budget.

These results cover the changed source phases. They do not claim a completed native Box gate, published release, deployment or physical-device acceptance.

Verification receipt SHA-256: `18a4ea052a00a963a000933a24532ce269a9fdcdd2f7fe7105ce7eac3bc3c4a5`.
