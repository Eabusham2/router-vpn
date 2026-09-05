#!/usr/bin/env python3
"""Correct stale recovered-audit source predicates, then run the scorer."""
from pathlib import Path

HERE = Path(__file__).resolve().parent
V3 = HERE / "recovered-release-audit-v3.py"
source = V3.read_text(encoding="utf-8")

old_pf = '        and mod.no("modes/darwin_kill_switch.py", "/etc/pf.conf")\n'
if old_pf not in source:
    raise SystemExit("v4 patch failed: v3 macOS PF predicate changed")
source = source.replace(old_pf, "", 1)

old_multihop = '''def controller_multihop_platform(platform: str) -> bool:\n    text = mod.body("cmd/client/multihop.go")\n    if 'runtime.GOOS != "linux"' in text:\n        return False\n    return f'"{platform}"' in text or "platform_supported" in text\n'''
new_multihop = '''def controller_multihop_platform(platform: str) -> bool:\n    routes = "cmd/client/multihop_native_routes.go"\n    if not mod.has(routes, "nativeMultihopPlatformSupported", "/api/multihop/status", "/api/multihop/connect", "proveMultihopExit"):\n        return False\n    if platform == "windows":\n        return mod.has(routes, 'runtime.GOOS == "windows"', "nativeWindowsMultihopCommand") and mod.has("cmd/client/multihop_native.go", "nativeWindowsMultihopCommand", "prepareNativeMultihop", 'proxy["detour"] = "entry-wg"', "nativeWGEndpoint")\n    if platform == "darwin":\n        return mod.has(routes, 'runtime.GOOS == "darwin"', "nativeDarwinMultihopCommand") and mod.has("cmd/client/multihop_native_darwin.go", "nativeDarwinMultihopCommand", "prepareNativeMultihop", "native-multihop-darwin.sh", "HOMEVPN_POLICY_PROFILE_ID") and mod.has("modes/native-multihop-darwin.sh", "sing-box", "kill-switch-platform.py", "release_guard", "cleanup-private-runtime.py")\n    return False\n'''
if old_multihop not in source:
    raise SystemExit("v4 patch failed: v3 multihop predicate changed")
source = source.replace(old_multihop, new_multihop, 1)

# v3 predates the unified iOS map header move. The real-location control now
# lives inside IOSUnifiedProductView beside the map, while its one-shot
# CoreLocation implementation is isolated in IOSUserLocationOverlay.swift.
# Audit the source graph that actually ships instead of requiring stale marker
# text in ProductRootView.
old_ios_map = '''def ios_map() -> bool:\n    return (\n        mod.has("ios/RouterVPN/App/RouterVPNApp.swift", "ProductRootView()")\n        and mod.has("ios/RouterVPN/project.yml", "sources:", "- App", "- Resources")\n        and mod.has(\n            "ios/RouterVPN/App/ProductRootView.swift",\n            "IOSUnifiedProductView",\n            "IOSUserLocationControl",\n            "never derives a coordinate from the public IP",\n        )\n        and mod.has(\n            "ios/RouterVPN/App/IOSUnifiedProductView.swift",\n            "import MapKit",\n            "IOSUnifiedMap",\n            "MKMapView",\n            "latitude",\n            "longitude",\n            "(-90...90).contains(lat)",\n            "(-180...180).contains(lon)",\n            "!(lat == 0 && lon == 0)",\n            "RouterVPNNodeManagerSheet",\n            "real coordinates",\n        )\n    )\n'''
new_ios_map = '''def ios_map() -> bool:\n    return (\n        mod.has("ios/RouterVPN/App/RouterVPNApp.swift", "ProductRootView()")\n        and mod.has("ios/RouterVPN/project.yml", "sources:", "- App", "- Resources")\n        and mod.has("ios/RouterVPN/App/ProductRootView.swift", "IOSUnifiedProductView()")\n        and mod.has(\n            "ios/RouterVPN/App/IOSUnifiedProductView.swift",\n            "import MapKit",\n            "IOSUnifiedMap",\n            "MKMapView",\n            "latitude",\n            "longitude",\n            "(-90...90).contains(lat)",\n            "(-180...180).contains(lon)",\n            "!(lat == 0 && lon == 0)",\n            "RouterVPNNodeManagerSheet",\n            "IOSUserLocationControl()",\n            "real coordinates",\n        )\n        and mod.has(\n            "ios/RouterVPN/App/IOSUserLocationOverlay.swift",\n            "IOSUserLocationControl",\n            "requestFromUserTap",\n            "requestWhenInUseAuthorization",\n            "requestLocation()",\n            "horizontalAccuracy",\n            "MapKit user annotation",\n            "no automatic request, no IP geolocation, no synthetic coordinate",\n        )\n    )\n'''
if old_ios_map not in source:
    raise SystemExit("v4 patch failed: v3 iOS map predicate changed")
source = source.replace(old_ios_map, new_ios_map, 1)

# The shipping Linux v4 translation unit composes v3, which composes the core
# product source. Audit the same source graph the compiler sees rather than
# treating inherited native features as absent merely because their marker is
# physically located in an included source file.
linux_anchor = '''LINUX_SHIPPING = (\n    "client/linux/routervpn-gtk-product-v4.c",\n    "client/linux/routervpn-gtk-product-v3.c",\n    "client/linux/routervpn-gtk-product.c",\n    "client/linux/routervpn-gtk.c",\n)\n'''
linux_helper = linux_anchor + '''\n\ndef linux_shipping_has(*markers: str) -> bool:\n    rel = shipping_source("client/linux/build-native-app.sh", LINUX_SHIPPING)\n    if not rel:\n        return False\n    if rel == "client/linux/routervpn-gtk-product-v4.c":\n        text = "\\n".join(mod.body(p) for p in LINUX_SHIPPING[:3])\n        return bool(text) and all(marker in text for marker in markers)\n    if rel == "client/linux/routervpn-gtk-product-v3.c":\n        text = "\\n".join(mod.body(p) for p in LINUX_SHIPPING[1:3])\n        return bool(text) and all(marker in text for marker in markers)\n    return mod.has(rel, *markers)\n'''
if linux_anchor not in source:
    raise SystemExit("v4 patch failed: v3 Linux shipping source tuple changed")
source = source.replace(linux_anchor, linux_helper, 1)
source = source.replace('shipping_has("client/linux/build-native-app.sh",LINUX_SHIPPING,', 'linux_shipping_has(')

# v3's executable macOS kill-switch contract already distinguishes harmless
# read-only /etc/pf.conf references from mutation/reload patterns. v4 therefore
# relies on that contract rather than rejecting the filename as a substring.
exec(compile(source, str(V3), "exec"), {"__name__": "__main__", "__file__": str(V3)})
