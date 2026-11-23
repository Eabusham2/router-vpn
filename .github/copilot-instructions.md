# Router VPN repository instructions

Read [AGENTS.md](../AGENTS.md) for the source map and contributor workflow, and [current status](../docs/CURRENT-STATUS.md) for supported platform/mode boundaries.

Router VPN has an ARM64 Docker server, private Setup Center, and separate native desktop/mobile clients. Keep private node data out of generic public packages. Preserve route/DNS/selected-exit proof and fail-closed behavior; source presence is not physical-device acceptance.

For documentation changes, run `git diff --check`, `python3 deploy/docs-native-fallback-policy-audit.py`, `python3 deploy/recovered-requirements-265-311-audit.py`, and `python3 deploy/binding-edge-requirements-audit.py` from the root; verify changed Markdown links. For code, use the component's existing tests and pinned native workflow dependencies.

Preserve exact-commit release matching across clients, ARM64 images, and generated production Compose. Router-local package fallback is Windows/Portable only. Keep private/admin ports off WAN and preserve unrelated router hooks. Use isolated tests; do not treat a live router/deployment action as a local check. Preserve preview labels and report missing validation rather than bypassing release gates.
