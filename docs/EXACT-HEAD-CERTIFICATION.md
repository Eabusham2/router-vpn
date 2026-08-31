# Exact-Head Certification

This file marks the authoritative Router VPN source generation that must be certified as one exact Git commit.

The certification matrix must prove, for the same SHA:

- recovered requirements 1–356 and corrections C1–C7;
- native map-first shipping composition on Windows, macOS, Linux, Android, and iOS/iPadOS;
- backend session/mutation serialization and stale-result rejection;
- private/durable state, endpoint ownership, updater rollback, and ASUS fail-open source contracts;
- Windows installed and Portable x64/ARM64 packages;
- macOS Intel/Apple Silicon and Linux x64/ARM64 packages;
- Android APK and real iOS/iPadOS build/IPA;
- ARM64 production images and exact-SHA Portainer compose;
- aggregate package provenance, checksums, licenses, and secret-free archives.

Setup Center package delivery is exact-SHA GitHub Release first, exact-SHA Actions artifact second, then only a bounded supported local desktop/Portable fallback. Generated local packages and their owned workspaces remain available for retry for 30 minutes from READY and are then deleted; explicit cancel/delete and shutdown clean them immediately. Mobile remains exact-SHA artifact-only.

Physical devices, private production infrastructure, ASUS hardware, off-LAN interoperability, live AI providers, and Apple distribution are separate evidence gates and must never be inferred from CI.
