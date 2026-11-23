# Repository maintenance

## Public documentation

The [README](../README.md) is the public entry point. The
[installation guide](INSTALL-PORTAINER.md), [full guide](CURRENT-GUIDE.md),
[platform status](CURRENT-STATUS.md), and [build guide](BUILDS.md) cover distinct
tasks. Component READMEs explain developer interfaces and point back to the
product guides where appropriate. Network addresses in examples must be adapted
to each installation.

## Build and release workflows

| Workflow | Responsibility |
| --- | --- |
| [Repository state audit](../.github/workflows/repository-state-audit.yml) | Read-only branch inventory, generated-file checks, public README links, and source-workflow checks. |
| [Build all Router VPN release gates](../.github/workflows/build-all.yml) | The complete native release matrix, ARM64 images, generated production Compose, and exact-commit client publication. |
| [Release candidate](../.github/workflows/release-candidate.yml) | Native source, runtime and package acceptance, reused by the publishing workflow. |
| [Production Compose](../.github/workflows/production-release-compose.yml) | Produce and verify the Compose file for the exact release commit. |

The existing focused platform workflows remain available for diagnosis. A
diagnostic run does not replace the complete release matrix. Publication stays
behind the existing dependency gates; a failing native check is not converted
into a successful release by documentation or cleanup work.

Public bug reports and pull requests do not make the repository-state check
fail. The project's main-only branch policy remains checked, but CI never
deletes an unfamiliar branch or merges its work automatically.

## Completed recovery tooling retired on 2026-11-23

Three one-time workflows replayed recovery patches and committed source back
to `main`. Their source changes had already been integrated:

| Completed recovery | Integration commit |
| --- | --- |
| Android Auto-MTU ownership and controls | [71be14669ba11cdcc479fc83aeeae1873018d035](https://github.com/Eabusham2/router-vpn/commit/71be14669ba11cdcc479fc83aeeae1873018d035) |
| Apple Auto-MTU, Retest, IPC and leases | [2dc2630fb09273905c0982a2dbddf81a16fcfcf6](https://github.com/Eabusham2/router-vpn/commit/2dc2630fb09273905c0982a2dbddf81a16fcfcf6) |
| Apple adaptive-MTU runtime ownership | [09503331a1544fd7a3139ec5f5b77169f384012f](https://github.com/Eabusham2/router-vpn/commit/09503331a1544fd7a3139ec5f5b77169f384012f) |

Before removal, each integration commit was verified as an ancestor of `main`,
all paths listed by the recovery manifests were checked against current source,
and references were searched across tracked source, hidden workflow files and
documentation. The only active audit dependency on a replay workflow was
changed to retain the equivalent toolchain-order check on the native compile
workflow. No application implementation or runtime test was removed.

The retired files are the `restore-mobile-mtu-source`, `restore-ios-mtu-source`
and `finalize-apple-mtu-ownership` workflows, plus their six patch/manifest files
under `docs/continuations`. Their complete historical bytes remain in Git
history. Inspect the integration commits or an earlier revision when debugging
historical behavior; do not reapply an old recovery patch to current source.

The redundant `keep-main-only` workflow and its completed stale-branch deletion
helper were also removed. The repository-state workflow already checks the same
branch inventory, now with read-only permissions and explicit API error handling.

The legacy top-level start/install pages remain as short links to the canonical
guides so existing bookmarks keep working. Runtime modules, compatibility paths,
native tests, third-party notices, existing releases and release tags are retained.
