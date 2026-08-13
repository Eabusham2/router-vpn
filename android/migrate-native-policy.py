#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parent
xray = ROOT / "app/src/main/java/com/eabusham/routervpn/NativeXrayController.java"
main = ROOT / "app/src/main/java/com/eabusham/routervpn/MainActivity.java"

xt = xray.read_text(encoding="utf-8")
if "AndroidNativeProfilePolicy.selectedPlainUdpDns(root)" not in xt:
    replacements = {
        "patchForAndroidTun(config, proxyTag, selectedMtu(root));":
            "patchForAndroidTun(config, proxyTag, AndroidNativeProfilePolicy.selectedMtu(root, 1380));",
        '.put("dns", selectedPlainDns(root))':
            '.put("dns", AndroidNativeProfilePolicy.selectedPlainUdpDns(root))',
        '.put("mtu", selectedMtu(root))':
            '.put("mtu", AndroidNativeProfilePolicy.selectedMtu(root, 1380))',
    }
    for old, new in replacements.items():
        if xt.count(old) != 1:
            raise SystemExit(f"NativeXrayController anchor mismatch for {old!r}: {xt.count(old)}")
        xt = xt.replace(old, new, 1)
    xray.write_text(xt, encoding="utf-8")
else:
    print("NativeXrayController native policy already wired")

mt = main.read_text(encoding="utf-8")
old = "Selected DNS is applied to embedded libbox sessions and IP-based native Xray sessions; final DNS/leak proof remains a release gate."
new = "Selected DNS transport is fully enforced by embedded libbox modes. Native WG/AWG/Xray enforce only literal-IP UDP DNS and fail closed for DoH/DoT/H3/TCP selections instead of silently downgrading them; final DNS/leak proof remains a release gate."
if new not in mt:
    if mt.count(old) != 1:
        raise SystemExit(f"MainActivity DNS truth anchor mismatch: {mt.count(old)}")
    mt = mt.replace(old, new, 1)
    main.write_text(mt, encoding="utf-8")
else:
    print("MainActivity native DNS truth already wired")
