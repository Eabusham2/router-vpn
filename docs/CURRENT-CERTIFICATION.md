# Current exact-head certification

Router VPN accepts GitHub/release completion only when one exact public `main` commit proves all of the following without borrowing evidence from an older SHA:

- reconciled requirements, recovered requirements 1–356 and C1–C7;
- real shipping composition for Windows, macOS, Linux, Android and iOS/iPadOS;
- unified map-first product, session-mutation, profile, durability and fail-open contracts;
- Windows installed and Portable x64/ARM64 packages;
- macOS Intel/Apple Silicon and Linux x64/ARM64 packages;
- Android APK and real iOS `xcodebuild`/IPA;
- ARM64 production images and Portainer preflight;
- one generated image-only production compose whose broker and custom images share the exact SHA;
- immutable exact-SHA prerelease assets, release manifest and SHA-256 checksums.

Setup Center package delivery is exact-SHA GitHub Release first, matching exact-SHA Actions artifact second, and a bounded supported desktop/Portable local build only when GitHub delivery is unavailable. Android and iOS remain artifact-only. A completed package and its owned build workspace remain retryable for 30 minutes from READY; downloading does not extend the deadline; Cancel/Delete/Shutdown removes it immediately.

Physical-device, private AI Board/Portainer, ASUS-router, off-LAN, live-provider and Apple distribution evidence remain separate and may not be inferred from source or CI.
