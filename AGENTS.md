# Contributor and coding-assistant guide

Router VPN is a self-hosted VPN/proxy platform with an ARM64 Docker server, a private Setup Center, and native desktop/mobile clients. Read [README.md](README.md), [current status](docs/CURRENT-STATUS.md), and the relevant component documentation before changing behavior. Source implementation, CI results, packaged delivery, and physical-device acceptance are separate evidence.

## Source map

| Path | Responsibility |
| --- | --- |
| `cmd/`, `internal/` | Go commands, protocol/runtime integration, state, routing, and shared contracts. |
| `client/` | Desktop application and control-center code, platform integration, and contracts. |
| `android/`, `ios/`, `mobile/` | Mobile applications, native runtimes, and platform-specific build inputs. |
| `server/` | Server services, private Setup Center, image definitions, and Compose templates. |
| `configs/client/logical-modes.json`, `configs/client/modes.json` | Canonical logical choices and raw runtime profiles. |
| `router/` | Optional Asuswrt-Merlin forwarding integration. |
| `deploy/`, `.github/workflows/` | Source audits, native build/package verification, release orchestration. |

## Checks and build environments

Run commands from the repository root. For README or installation-policy edits, these existing checks are useful:

```sh
git diff --check
```

Check Markdown links locally; keep only the two canonical workflows.

For code changes, run focused existing behavioral tests. Keep routine CI to the single CI workflow; do not add independent push or pull-request workflows, redundant source-shape tests, or test shards merely to prove the test infrastructure. Run expensive native diagnostics and the full release only when needed. Follow [docs/BUILDS.md](docs/BUILDS.md), `go.mod`, and the workflow's pinned dependency setup. Go code declares Go 1.25 with the Go 1.26.3 toolchain. Native Windows, macOS, Linux, Android, and iOS builds have different dependencies; a generic host build cannot certify all platforms. Report unavailable checks explicitly instead of weakening them.

## Behavior and deployment boundaries

- Preserve private node/profile storage and redacted public summaries. Generic installers and archives must not contain credentials, private keys, tokens, or home-linked node bundles.
- Preserve real route, DNS, selected-node, and public-exit proof. Internet reachability alone does not establish a correct VPN session. Unsupported combinations must retain a clear unavailable reason.
- Keep the 20 raw profiles and 16 logical choices aligned with the canonical catalogs; do not silently remove modes while editing presentation.
- Keep the Setup Center and private/admin ports off WAN. Preserve unrelated JFFS hooks and forwarding rules; do not substitute DMZ or Exposed Host for the documented helper.
- Use isolated fixtures for local verification. Running a server updater or router helper against a real installation is a deployment action, not a substitute for tests.
- Router-local client fallback is limited to Windows/Portable. macOS/Linux require their native build environments; Android/iOS remain same-commit artifact paths. See [download policy](docs/NATIVE-DOWNLOAD-POLICY.md).

## Releases and public documentation

The [Build all Router VPN release gates](.github/workflows/build-all.yml) workflow owns publishing and is dispatched deliberately only for a stable release candidate. Routine commits never launch release or native diagnostic workflows. Client assets, release manifests, ARM64 server images, and generated production Compose must correspond to the same complete source commit. The tracked `server/portainer-current.yaml` is a template, not a generated release deployment.

Keep the existing source, native, packaging, signing, networking, and deployment gates. A green source audit does not establish physical routing, leak protection, off-LAN interoperability, Apple signing, or live production acceptance. Do not move an existing release tag or use an older green release as evidence for newer source.

Documentation should use adaptable public examples and link to canonical guides. Preserve accurate preview/readiness labels and explain supported subsets. Avoid claims of universal router compatibility, guaranteed censorship bypass, or all-platform release readiness without the relevant evidence. Keep licensing and third-party attribution intact.

## CI and release scope

Maintain exactly two workflows: `.github/workflows/ci.yml` for routine checks and `.github/workflows/build-all.yml` for manual release. Release requires successful CI for the same commit. Do not recreate per-feature workflows, test-of-test scripts or source-score systems. Aim for roughly 20 small, generalized behavioral tests in routine CI. Extend an existing small test instead of introducing another file for a single scenario. Native builds must not rerun the full development regression inventory. Keep only necessary dependency, security and real artifact smoke checks. Keep meaningful behavioral, security, platform and artifact verification; do not duplicate routine CI in release.
