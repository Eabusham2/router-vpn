# Android third-party runtime components

## WireGuard Android tunnel

Router VPN uses the official WireGuard Android tunnel library pinned in `app/build.gradle`.

## AmneziaWG Android tunnel

Router VPN builds the reusable tunnel module from the official `amnezia-vpn/amneziawg-android` source at:

- release: `2.0.0`
- exact commit: `4116c836241f737badb99dcd4e990600d46e4c65`
- license: Apache-2.0

`build-awg-tunnel.sh` verifies the checked-out commit, initializes the exact submodule gitlinks recorded by that commit, builds `:tunnel:assembleRelease` with upstream's Gradle wrapper, verifies that the resulting AAR contains `libwg-go.so`, copies the AAR into `app/libs/`, and preserves the upstream license beside it.

The generated AAR/vendor checkout are build outputs and are not part of Router VPN's source license.
