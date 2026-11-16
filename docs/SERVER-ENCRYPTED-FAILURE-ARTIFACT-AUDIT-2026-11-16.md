# Encrypted Server failure-artifact audit

The exact `067f17c61ae2463e8c7132abaa88901afc47e5a4` orchestration blocker failed in run `43962160327`, job `133632130331`, at `Preserve source and orchestration contracts`. The shipping artifact audit rejected the encrypted Server workflow's new `if: always()` upload with `encrypted Server native inventory/SHA became conditional or configurable`. Applying the original audit function to that same published workflow reproduces the assertion.

The audit now permits the condition only on the unique `actions/upload-artifact@v4` step inside the original `encrypted` job. It requires the exact `if: always()` spelling and retains the fixed action, artifact name, failure-on-missing configuration, and exact four-path receipt inventory: both original native receipts and both candidate-agent/terminal directories. Every proof, checkout, compilation and candidate step remains unconditional. The workflow, native programs, required proof inventory and execution bounds are unchanged.

Validation on the repaired source:

- `python3 deploy/test_native_artifact_aggregate.py`: all 34 tests passed. Added cases reject missing, commented, malformed, duplicate and conditional upload declarations; foreign or substituted actions; sibling-job relocation; conditional or failure-suppressed native/candidate steps; and missing, duplicate or substituted candidate receipt paths. All existing tests remain.
- `python3 deploy/native-artifact-workflow-parity-audit.py`: passed in 4.644 seconds, including its existing 10-, 5- and 4-test source-validation suites. The complete log SHA-256 is `90fd3dd419641c2fa7a328dcb280b6a7764c70d0aee5021f25f5650a95b3e940`.
- `git diff --check`: passed.

These are source and orchestration validation results. No Go compiler, encrypted Server runtime or native negative-control execution was run for this audit-only change. The new commit's required hosted jobs must supply that evidence independently.

## Candidate worker requiredness

A separate check on published `c79d9482a1cf26e5f341c321fbe76edccd810410` found that the audit accepted both removal of the entire candidate-worker step and changing its ten-minute bound to one minute. The actual published workflow still contained the correct required step. This follow-up adds the missing guard without changing the upload exception or workflow.

The audit now requires the exact candidate runner, agent and terminal-control commands, their architecture-specific output directories, original ten-minute bound and position between CONNECT and original native acceptance. Commands in a sibling job cannot satisfy that requirement. The existing ordering test now swaps only complete steps within the encrypted job and checks all fifteen inversions of its six required boundaries. Existing upload/spaced-key protections and tests are preserved.

The full aggregate suite passed 36 tests and 523 subtest cases. Additional cases reject omitted, duplicated, commented, substituted, reordered, nonblocking and foreign-job worker commands. Applying the old and repaired audit functions to the same two mutations confirms that only the repaired guard rejects both. The complete shipping parity script also passed in 9.498 seconds, including its existing 10-, 5- and 4-test source suites. Its log SHA-256 is `84be63f6f59d6ce83f129fdea10cf9f2593564f7c04c1b25ce603cbce4699731`. No real compiler or native runtime was executed.
