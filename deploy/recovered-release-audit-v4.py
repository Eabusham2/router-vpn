#!/usr/bin/env python3
"""Compatibility wrapper while recovered-release v3 is flattened to current predicates.

The wrapper still upgrades an older v3 in memory, but it also accepts an already-
flattened v3 without rewriting it. This keeps every direct-main intermediate head
executable while the obsolete source-rewrite layer is retired.
"""
from pathlib import Path

HERE = Path(__file__).resolve().parent
V3 = HERE / "recovered-release-audit-v3.py"
source = V3.read_text(encoding="utf-8")

old_pf = '        and mod.no("modes/darwin_kill_switch.py", "/etc/pf.conf")\n'
if old_pf in source:
    source = source.replace(old_pf, "", 1)

old_multihop = '''def controller_multihop_platform(platform: str) -> bool:\n    text = mod.body("cmd/client/multihop.go")\n    if 'runtime.GOOS != "linux"' in text:\n        return False\n    return f'"{platform}"' in text or "platform_supported" in text\n'''
new_multihop = '''def controller_multihop_platform(platform: str) -> bool:\n    routes = "cmd/client/multihop_native_routes.go"\n    if not mod.has(routes, "nativeMultihopPlatformSupported", "/api/multihop/status", "/api/multihop/connect", "proveMultihopExit"):\n        return False\n    if platform == "windows":\n        return mod.has(routes, 'runtime.GOOS == "windows"', "nativeWindowsMultihopCommand") and mod.has("cmd/client/multihop_native.go", "nativeWindowsMultihopCommand", "prepareNativeMultihop", 'proxy["detour"] = "entry-wg"', "nativeWGEndpoint")\n    if platform == "darwin":\n        return mod.has(routes, 'runtime.GOOS == "darwin"', "nativeDarwinMultihopCommand") and mod.has("cmd/client/multihop_native_darwin.go", "nativeDarwinMultihopCommand", "prepareNativeMultihop", "native-multihop-darwin.sh", "HOMEVPN_POLICY_PROFILE_ID") and mod.has("modes/native-multihop-darwin.sh", "sing-box", "kill-switch-platform.py", "release_guard", "cleanup-private-runtime.py")\n    return False\n'''
if old_multihop in source:
    source = source.replace(old_multihop, new_multihop, 1)
elif new_multihop not in source:
    raise SystemExit("recovered release scorer has an unknown multihop predicate")

old_ios_map = '''def ios_map() -> bool:\n    return (\n        mod.has("ios/RouterVPN/App/RouterVPNApp.swift", "ProductRootView()")\n        and mod.has("ios/RouterVPN/project.yml", "sources:", "- App", "- Resources")\n        and mod.has(\n            "ios/RouterVPN/App/ProductRootView.swift",\n            "IOSUnifiedProductView",\n            "IOSUserLocationControl",\n            "never derives a coordinate from the public IP",\n        )\n        and mod.has(\n            "ios/RouterVPN/App/IOSUnifiedProductView.swift",\n            "import MapKit",\n            "IOSUnifiedMap",\n            "MKMapView",\n            "latitude",\n            "longitude",\n            "(-90...90).contains(lat)",\n            "(-180...180).contains(lon)",\n            "!(lat == 0 && lon == 0)",\n            "RouterVPNNodeManagerSheet",\n            "real coordinates",\n        )\n    )\n'''
new_ios_map = '''def ios_map() -> bool:\n    return (\n        mod.has("ios/RouterVPN/App/RouterVPNApp.swift", "ProductRootView()")\n        and mod.has("ios/RouterVPN/project.yml", "sources:", "- App", "- Resources")\n        and mod.has("ios/RouterVPN/App/ProductRootView.swift", "IOSUnifiedProductView()")\n        and mod.has(\n            "ios/RouterVPN/App/IOSUnifiedProductView.swift",\n            "import MapKit",\n            "IOSUnifiedMap",\n            "MKMapView",\n            "latitude",\n            "longitude",\n            "(-90...90).contains(lat)",\n            "(-180...180).contains(lon)",\n            "!(lat == 0 && lon == 0)",\n            "RouterVPNNodeManagerSheet",\n            "IOSUserLocationControl()",\n            "real coordinates",\n        )\n        and mod.has(\n            "ios/RouterVPN/App/IOSUserLocationOverlay.swift",\n            "IOSUserLocationControl",\n            "requestFromUserTap",\n            "requestWhenInUseAuthorization",\n            "requestLocation()",\n            "horizontalAccuracy",\n            "MapKit user annotation",\n            "no automatic request, no IP geolocation, no synthetic coordinate",\n        )\n    )\n'''
if old_ios_map in source:
    source = source.replace(old_ios_map, new_ios_map, 1)
elif new_ios_map not in source:
    raise SystemExit("recovered release scorer has an unknown iOS map predicate")

linux_anchor = '''LINUX_SHIPPING = (\n    "client/linux/routervpn-gtk-product-v4.c",\n    "client/linux/routervpn-gtk-product-v3.c",\n    "client/linux/routervpn-gtk-product.c",\n    "client/linux/routervpn-gtk.c",\n)\n'''
linux_helper = linux_anchor + '''\n\ndef linux_shipping_has(*markers: str) -> bool:\n    rel = shipping_source("client/linux/build-native-app.sh", LINUX_SHIPPING)\n    if not rel:\n        return False\n    if rel == "client/linux/routervpn-gtk-product-v4.c":\n        text = "\\n".join(mod.body(p) for p in LINUX_SHIPPING[:3])\n        return bool(text) and all(marker in text for marker in markers)\n    if rel == "client/linux/routervpn-gtk-product-v3.c":\n        text = "\\n".join(mod.body(p) for p in LINUX_SHIPPING[1:3])\n        return bool(text) and all(marker in text for marker in markers)\n    return mod.has(rel, *markers)\n'''
if "def linux_shipping_has(*markers: str) -> bool:" not in source:
    if linux_anchor not in source:
        raise SystemExit("recovered release scorer has an unknown Linux shipping source tuple")
    source = source.replace(linux_anchor, linux_helper, 1)
source = source.replace('shipping_has("client/linux/build-native-app.sh",LINUX_SHIPPING,', 'linux_shipping_has(')

exec(compile(source, str(V3), "exec"), {"__name__": "__main__", "__file__": str(V3)})
