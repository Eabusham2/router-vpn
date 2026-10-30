# Third-party engines

The installer obtains or builds these upstream projects at deployment/client-install time:

- WireGuard tools
- AmneziaWG Go and AmneziaWG tools
- sing-box
- Xray-core

Their licenses and source remain with their respective upstream projects. This repository contains the controller, configuration generator, installers, and integration code; it does not copy their source trees.

## Apple private PF header dependency

The separately bounded macOS native PF qualification fixture uses unmodified
Apple XNU userland declarations pinned to commit
`43a90889846e00bfb5cf1d255cdc0a701a1e05a4`. These are private declarations, not a
public SDK or a stable-ABI claim. The dependency identity, qualification bounds,
full Apple Public Source License 2.0, and original header notices are preserved
in `internal/mobiletor/desktop_socket_darwin_pfabi/`. Its license is separate
from the repository's MIT license. Shipping binary adoption requires carrying
those notices and passing the actual scoped native kernel/readback tests.
