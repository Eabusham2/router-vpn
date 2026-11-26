# Current project status

Router VPN has a native map-first daily client and a private Setup Center. See [current requirements](CURRENT-REQUIREMENTS.md), [user guide](CURRENT-GUIDE.md), [platform documentation](NATIVE-APPS.md), and [build instructions](BUILDS.md) for the supported product and delivery paths.

## Verification and release

The routine workflow is [Router VPN CI](../.github/workflows/ci.yml). The manual [Router VPN Release](../.github/workflows/build-all.yml) workflow builds and packages the supported desktop/mobile platforms and ARM64 server images. Use the latest exact-commit [CI results](https://github.com/Eabusham2/router-vpn/actions) and [published releases](https://github.com/Eabusham2/router-vpn/releases) to determine current readiness. Passing source checks alone does not establish cross-platform packaging, physical-device operation, private router deployment, or live networking acceptance.

Do not treat older receipts as proof of a newer commit. The full prior implementation journal is [retained at its original revision](https://github.com/Eabusham2/router-vpn/blob/13b7624cda832920ce0b4f647d7552e07f0bf083/docs/CURRENT-STATUS.md); its evidence is indexed in [development history](AI-DEVELOPMENT-HISTORY.md).
