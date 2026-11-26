# Repository maintenance

- For RouterVPN specifically, work directly on the single main branch. This rule is not a policy for the owner’s other repositories. Do not create routine work branches, pull requests, or additional workflows.
- [Router VPN CI](../.github/workflows/ci.yml) is the small routine behavioral and syntax suite. [Router VPN Release](../.github/workflows/build-all.yml) is manually dispatched for a stable, CI-passing commit. Do not rerun the routine suite inside release.
- Prefer small, generalized behavioral tests; do not create per-case files, source-shape test inventories, or test-of-test runners. Preserve meaningful fail-closed, private-state, dependency, and real package verification.
- Do not track generated diagnostic logs, receipts, source snapshots or recovery patches in the current documentation tree. Use CI artifacts and immutable commit links instead. Consolidate new AI development notes into the relevant existing guide, without expanding project requirements.
- Keep user instructions and [binding requirements](CURRENT-REQUIREMENTS.md) current. Do not use historical results to certify a new release.
- Keep one active implementation per feature. Use the oldest and newest revisions in Git history to recover useful lost behavior, merge needed code into the current implementation, and delete redundant copies and unused generation scripts. Do not restore old behavior that conflicts with explicit requirements or weakens current security. Separate active feature modules are not duplicate revisions merely because their filenames include a version number.

See [development history](AI-DEVELOPMENT-HISTORY.md) for the original notes and evidence.
