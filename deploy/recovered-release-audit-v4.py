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
new_multihop = '''def controller_multihop_platform(platform: str) -> bool:\n    routes = "cmd/client/multihop_native_routes.go"\n    if not mod.has(routes, "nativeMultihopPlatformSupported", "/api/multihop/status", "/api/multihop/connect", "proveMultihopExit"):\n        return False\n    if platform == "windows":\n        return mod.has(routes, 'runtime.GOOS == "windows"', "nativeWindowsMultihopCommand") and mod.has("cmd/client/multihop_native.go", "nativeWindowsMultihopCommand", "prepareNativeMultihop", 'proxy["detour"]="entry-wg"')\n    if platform == "darwin":\n        return mod.has(routes, 'runtime.GOOS == "darwin"', "nativeDarwinMultihopCommand") and mod.has("cmd/client/multihop_native_darwin.go", "nativeDarwinMultihopCommand", "prepareNativeMultihop", "native-multihop-darwin.sh", "HOMEVPN_POLICY_PROFILE_ID") and mod.has("modes/native-multihop-darwin.sh", "sing-box", "kill-switch-platform.py", "release_guard")\n    return False\n'''
if old_multihop not in source:
    raise SystemExit("v4 patch failed: v3 multihop predicate changed")
source = source.replace(old_multihop, new_multihop, 1)

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
