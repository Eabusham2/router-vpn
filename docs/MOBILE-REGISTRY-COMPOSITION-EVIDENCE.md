# Repeated mobile protocol preparation

The Android diagnostic [43156029692](https://github.com/Eabusham2/router-vpn/actions/runs/43156029692) at `67c0097e628264288bfd50260d934c2a9fbac175` passed its first mobile source preparation, then failed when `test_mobile_sip003_pinned.sh` prepared that same core again. The ordered application gate and composite each required its own import immediately after the pinned group import. Installing the other component displaced that adjacency.

Both preparers now recognize only the other component's exact, single adjacent import. Their original registration-call boundaries, duplicate checks, pinned source checks, and ownership checks remain enforced. No runtime admission or native protocol behavior changes. Both original preparation orders remain byte-stable on repetition.

Focused verification on November 12, 2026:

- Five composite shipping tests passed, including three repeated preparations in each order and twelve malformed composed-source cases.
- Fourteen ordered-gate preparation and verdict tests passed.
- Substituting each original validator into the new repeated-preparation regression independently reproduced its intended adjacency failure.
- Both corrected validators accepted the existing complete prepared native registry without changing its bytes.
- `git diff --check` passed.

This closes the reproduced source-preparation conflict. A successful APK/IPA build and complete release still require the authoritative native jobs on the published commit.
