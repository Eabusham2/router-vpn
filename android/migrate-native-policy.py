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
old_dns = "Selected DNS is applied to embedded libbox sessions and IP-based native Xray sessions; final DNS/leak proof remains a release gate."
new_dns = "Selected DNS transport is fully enforced by embedded libbox modes. Native WG/AWG/Xray enforce only literal-IP UDP DNS and fail closed for DoH/DoT/H3/TCP selections instead of silently downgrading them; final DNS/leak proof remains a release gate."
if new_dns not in mt:
    if mt.count(old_dns) != 1:
        raise SystemExit(f"MainActivity DNS truth anchor mismatch: {mt.count(old_dns)}")
    mt = mt.replace(old_dns, new_dns, 1)

old_state = '''        String ls = singBox.getState(), lm = singBox.getMode(), le = singBox.getError();
        String xs = xray.getState(), xm = xray.getMode(), xe = xray.getError();
'''
new_state = '''        String we = wireGuard.getError(), ae = amneziaWG.getError();
        String ls = singBox.getState(), lm = singBox.getMode(), le = singBox.getError();
        String xs = xray.getState(), xm = xray.getMode(), xe = xray.getError();
'''
if "String we = wireGuard.getError(), ae = amneziaWG.getError();" not in mt:
    if mt.count(old_state) != 1:
        raise SystemExit(f"MainActivity native error-state anchor mismatch: {mt.count(old_state)}")
    mt = mt.replace(old_state, new_state, 1)

old_display = '"Native Android VPN\\nWireGuard: " + w + "\\nAmneziaWG 2: " + a + "\\nNative Xray: "'
new_display = '"Native Android VPN\\nWireGuard: " + w + (we.isEmpty() ? "" : "\\nLast WireGuard error: " + we) + "\\nAmneziaWG 2: " + a + (ae.isEmpty() ? "" : "\\nLast AmneziaWG error: " + ae) + "\\nNative Xray: "'
if new_display not in mt:
    if mt.count(old_display) != 1:
        raise SystemExit(f"MainActivity native status display anchor mismatch: {mt.count(old_display)}")
    mt = mt.replace(old_display, new_display, 1)

mt = mt.replace('(automationBusy ? "\\nAUTO/SMART/CUSTOM: testing…" : "")', '(automationBusy ? "\\nAUTO/SMART/CUSTOM/ALL: testing/proving…" : "")')

open_old = '''    private void openBundlePicker() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
'''
open_new = '''    private void openBundlePicker() {
        if (rawActiveOrBusy() || layeredActiveOrBusy()) { toast("Disconnect the current VPN before adding/selecting router data"); return; }
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
'''
if "Disconnect the current VPN before adding/selecting router data" not in mt:
    if mt.count(open_old) != 1:
        raise SystemExit(f"MainActivity bundle-picker guard anchor mismatch: {mt.count(open_old)}")
    mt = mt.replace(open_old, open_new, 1)

result_old = '''        if (code != IMPORT_BUNDLE || result != RESULT_OK || data == null) return;
        Uri uri = data.getData();
'''
result_new = '''        if (code != IMPORT_BUNDLE || result != RESULT_OK || data == null) return;
        if (rawActiveOrBusy() || layeredActiveOrBusy()) { toast("VPN became active; router import was cancelled to preserve the running session identity"); return; }
        Uri uri = data.getData();
'''
if "VPN became active; router import was cancelled" not in mt:
    if mt.count(result_old) != 1:
        raise SystemExit(f"MainActivity import-result guard anchor mismatch: {mt.count(result_old)}")
    mt = mt.replace(result_old, result_new, 1)

main.write_text(mt, encoding="utf-8")
print("Applied native Android DNS/MTU/recovery/identity truth migration")
