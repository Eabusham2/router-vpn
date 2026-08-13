#!/usr/bin/env python3
from pathlib import Path

P = Path(__file__).resolve().parent / "app/src/main/java/com/eabusham/routervpn/MainActivity.java"
t = P.read_text(encoding="utf-8")
if all(x in t for x in ("private Button allButton", "private boolean pendingAll", "private void requestAll()", "orchestrator.all(")):
    print("MainActivity Android ALL already wired")
    raise SystemExit(0)

def one(old,new):
    global t
    n=t.count(old)
    if n!=1: raise SystemExit(f"expected one anchor, got {n}: {old[:100]!r}")
    t=t.replace(old,new,1)

one(
'    private Button layeredConnectButton, layeredDisconnectButton, xrayConnectButton, xrayDisconnectButton, autoButton, smartButton, customButton;\n',
'    private Button layeredConnectButton, layeredDisconnectButton, xrayConnectButton, xrayDisconnectButton, autoButton, smartButton, customButton;\n    private Button allButton;\n')
one(
'    private boolean wgBusy, awgBusy, layeredBusy, xrayBusy, automationBusy, multihopBusy, pendingSmart;\n',
'    private boolean wgBusy, awgBusy, layeredBusy, xrayBusy, automationBusy, multihopBusy, pendingSmart;\n    private boolean pendingAll;\n')
anchor='''        customButton = button("CUSTOM — choose required layers");
        customButton.setOnClickListener(v -> chooseCustomLayers());
        c.addView(customButton, margins(0, dp(8), 0, 0));
'''
one(anchor,anchor+'''        allButton = button("ALL — strongest proven Android-native branch");
        allButton.setOnClickListener(v -> requestAll());
        c.addView(allButton, margins(0, dp(8), 0, 0));
''')
for old,new in (
("AUTO/SMART/CUSTOM require selected-node private path proof.","AUTO/SMART/CUSTOM/ALL require selected-node private path proof."),
("AWG-entry multihop and composite MAX/mixed sidecar chains remain gated; native Xray is available for self-contained Xray profiles.","AWG-entry multihop and composite MAX/mixed sidecar chains remain gated; ALL ranks only real Android-native branches strongest-to-weaker and never relabels a partial MAX sidecar as ALL."),
("choose native/direct/AUTO/SMART/CUSTOM or compatible multihop","choose native/direct/AUTO/SMART/CUSTOM/ALL or compatible multihop"),
("AUTO tests native candidates; SMART tries simpler candidates and restores the last proven mode if reduction fails.","AUTO tests native candidates; SMART tries simpler candidates and restores the last proven mode if reduction fails. ALL tests the strongest available Android-native protection branch first and truthfully falls back only after a failed proof."),
):
    if old not in t: raise SystemExit(f"missing text anchor: {old}")
    t=t.replace(old,new)

one(
'''    private void requestAutomation(boolean smart, List<String> custom) {
        if (rawActiveOrBusy() || layeredActiveOrBusy()) { toast("Disconnect the current VPN before AUTO/SMART/CUSTOM"); return; }
        if (!bundleReady()) return;
        pendingSmart = smart;
''',
'''    private void requestAutomation(boolean smart, List<String> custom) {
        if (rawActiveOrBusy() || layeredActiveOrBusy()) { toast("Disconnect the current VPN before AUTO/SMART/CUSTOM"); return; }
        if (!bundleReady()) return;
        pendingAll = false;
        pendingSmart = smart;
''')

all_method='''    private void requestAll() {
        if (rawActiveOrBusy() || layeredActiveOrBusy()) { toast("Disconnect the current VPN before ALL"); return; }
        if (!bundleReady()) return;
        pendingAll = true;
        pendingSmart = false;
        pendingCustomLayers = null;
        Intent p = VpnService.prepare(this);
        if (p != null) { statusView.setText("Waiting for Android VPN permission for ALL…"); startActivityForResult(p, PREPARE_AUTO); }
        else startPendingAutomation();
    }

'''
one('    private void startPendingAutomation() {\n',all_method+'    private void startPendingAutomation() {\n')
one(
'''        final boolean smart = pendingSmart;
        final List<String> custom = pendingCustomLayers;
        pendingSmart = false;
        pendingCustomLayers = null;
''',
'''        final boolean smart = pendingSmart;
        final boolean all = pendingAll;
        final List<String> custom = pendingCustomLayers;
        pendingSmart = false;
        pendingAll = false;
        pendingCustomLayers = null;
''')
one(
'''        if (custom != null) orchestrator.custom(getFileStreamPath(BUNDLE_FILE), custom, cb);
        else orchestrator.auto(getFileStreamPath(BUNDLE_FILE), smart, cb);
''',
'''        if (all) orchestrator.all(getFileStreamPath(BUNDLE_FILE), cb);
        else if (custom != null) orchestrator.custom(getFileStreamPath(BUNDLE_FILE), custom, cb);
        else orchestrator.auto(getFileStreamPath(BUNDLE_FILE), smart, cb);
''')
one(
'''        if (code == PREPARE_AUTO) { if (result == RESULT_OK) startPendingAutomation(); else { pendingCustomLayers = null; pendingSmart = false; statusView.setText("VPN permission denied; automatic mode selection did not start."); refreshNativeState(); } return; }
''',
'''        if (code == PREPARE_AUTO) { if (result == RESULT_OK) startPendingAutomation(); else { pendingCustomLayers = null; pendingSmart = false; pendingAll = false; statusView.setText("VPN permission denied; automatic/ALL mode selection did not start."); refreshNativeState(); } return; }
''')
one(
'''        customButton.setEnabled(autoEnabled);
        multihopButton.setEnabled(autoEnabled && storedNodeCount() >= 2);
''',
'''        customButton.setEnabled(autoEnabled);
        allButton.setEnabled(autoEnabled);
        multihopButton.setEnabled(autoEnabled && storedNodeCount() >= 2);
''')
P.write_text(t,encoding="utf-8")
print("Wired truthful Android ALL UI")
