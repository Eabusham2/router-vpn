#!/usr/bin/env python3
from pathlib import Path

PATH = Path(__file__).resolve().parent / "app/src/main/java/com/eabusham/routervpn/MainActivity.java"
text = PATH.read_text(encoding="utf-8")

REQUIRED = [
    "private NativeXrayController xray;",
    "private void chooseXrayMode()",
    "PREPARE_XRAY = 1007",
    "Native Xray:",
    "xray.listDirectXrayModes",
]
if all(marker in text for marker in REQUIRED):
    print("MainActivity native Xray UI already wired")
    raise SystemExit(0)


def replace_once(old: str, new: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one MainActivity anchor, found {count}: {old[:120]!r}")
    text = text.replace(old, new, 1)

replace_once(
    '    private static final int PREPARE_MULTIHOP = 1006;\n',
    '    private static final int PREPARE_MULTIHOP = 1006;\n    private static final int PREPARE_XRAY = 1007;\n',
)
replace_once(
    '    private Button layeredConnectButton, layeredDisconnectButton, autoButton, smartButton, customButton;\n',
    '    private Button layeredConnectButton, layeredDisconnectButton, xrayConnectButton, xrayDisconnectButton, autoButton, smartButton, customButton;\n',
)
replace_once(
    '    private NativeSingBoxController singBox;\n    private AndroidModeOrchestrator orchestrator;\n',
    '    private NativeSingBoxController singBox;\n    private NativeXrayController xray;\n    private AndroidModeOrchestrator orchestrator;\n',
)
replace_once(
    '    private NativeSingBoxController.ModeInfo pendingLayeredMode;\n',
    '    private NativeSingBoxController.ModeInfo pendingLayeredMode;\n    private NativeXrayController.ModeInfo pendingXrayMode;\n',
)
replace_once(
    '    private boolean wgBusy, awgBusy, layeredBusy, automationBusy, multihopBusy, pendingSmart;\n',
    '    private boolean wgBusy, awgBusy, layeredBusy, xrayBusy, automationBusy, multihopBusy, pendingSmart;\n',
)
replace_once(
    '        singBox = new NativeSingBoxController(this);\n        orchestrator = new AndroidModeOrchestrator(this, wireGuard, amneziaWG, singBox);\n',
    '        singBox = new NativeSingBoxController(this);\n        xray = new NativeXrayController(this);\n        orchestrator = new AndroidModeOrchestrator(this, wireGuard, amneziaWG, singBox, xray);\n',
)

ui_anchor = '''        awgDisconnectButton = button("Disconnect native AmneziaWG 2");
        awgDisconnectButton.setOnClickListener(v -> disconnectNativeAmneziaWG());
        c.addView(awgDisconnectButton, margins(0, dp(8), 0, 0));

'''
ui_insert = ui_anchor + '''        xrayConnectButton = button("Connect native Xray mode");
        xrayConnectButton.setOnClickListener(v -> chooseXrayMode());
        c.addView(xrayConnectButton, margins(0, dp(8), 0, 0));
        xrayDisconnectButton = button("Disconnect native Xray");
        xrayDisconnectButton.setOnClickListener(v -> disconnectXray());
        c.addView(xrayDisconnectButton, margins(0, dp(8), 0, 0));

'''
replace_once(ui_anchor, ui_insert)

for old, new in [
    ("Self-contained generated sing-box profiles use pinned libbox through Android VpnService.", "Self-contained generated sing-box profiles use pinned libbox, and self-contained Reality/XHTTP profiles use pinned Xray-core v26.7.11 through a dedicated Android VpnService."),
    ("AWG-entry multihop, mixed local-engine profiles and unsupported ALL/MAX branches remain gated.", "AWG-entry multihop and composite MAX/mixed sidecar chains remain gated; native Xray is available for self-contained Xray profiles."),
    ("Strict embedded libbox sessions require Android 10+ Always-on plus lockdown/Block connections without VPN;", "Strict embedded libbox/Xray sessions require Android 10+ Always-on plus lockdown/Block connections without VPN;"),
    ("Network changes reset libbox, but final reconnect/leak behavior still needs real-device validation.", "Network changes reset/revalidate libbox and native Xray, but final reconnect/leak behavior still needs real-device validation."),
    ("Raw WG/AWG and self-contained libbox modes are real choices.", "Raw WG/AWG, self-contained libbox, and native self-contained Xray modes are real choices."),
    ("requires proven Android Always-on plus lockdown for embedded libbox.", "requires proven Android Always-on plus lockdown for embedded libbox/Xray."),
    ("Selected DNS is applied to normal embedded libbox sessions;", "Selected DNS is applied to embedded libbox sessions and IP-based native Xray sessions;"),
]:
    if old not in text:
        raise SystemExit(f"missing expected truth-text anchor: {old}")
    text = text.replace(old, new)

setup_anchor = '''            List<NativeSingBoxController.ModeInfo> direct = singBox.listDirectLibboxModes(getFileStreamPath(BUNDLE_FILE));
            r.append(!direct.isEmpty() ? "✓ " + direct.size() + " direct embedded libbox mode(s) available\\n" : "! No self-contained libbox profile available\\n");
'''
setup_new = setup_anchor + '''            List<NativeXrayController.ModeInfo> directXray = xray.listDirectXrayModes(getFileStreamPath(BUNDLE_FILE));
            r.append(!directXray.isEmpty() ? "✓ " + directXray.size() + " native Xray mode(s) available\\n" : "! No self-contained native Xray profile available\\n");
'''
replace_once(setup_anchor, setup_new)
text = text.replace(
    '"✓ Strict policy requested: embedded libbox requires proven Android Always-on + Block connections without VPN; raw WG/AWG fail closed.\\n"',
    '"✓ Strict policy requested: embedded libbox/Xray requires proven Android Always-on + Block connections without VPN; raw WG/AWG fail closed.\\n"',
)

replace_once(
    '''        String s = singBox == null ? "DOWN" : singBox.getState();
        return layeredBusy || automationBusy || multihopBusy || "STARTING".equals(s) || "UP".equals(s) || "STOPPING".equals(s);
''',
    '''        String s = singBox == null ? "DOWN" : singBox.getState();
        String xs = xray == null ? "DOWN" : xray.getState();
        return layeredBusy || xrayBusy || automationBusy || multihopBusy
                || "STARTING".equals(s) || "UP".equals(s) || "STOPPING".equals(s)
                || "STARTING".equals(xs) || "UP".equals(xs) || "STOPPING".equals(xs);
''',
)

methods = r'''
    private void chooseXrayMode() {
        if (rawActiveOrBusy() || layeredActiveOrBusy()) { toast("Disconnect the current VPN before starting native Xray"); return; }
        if (!bundleReady()) return;
        try {
            List<NativeXrayController.ModeInfo> modes = xray.listDirectXrayModes(getFileStreamPath(BUNDLE_FILE));
            if (modes.isEmpty()) {
                new AlertDialog.Builder(this).setTitle("No native Xray mode")
                        .setMessage("This node has no self-contained Xray profile. Composite Xray+local-sidecar profiles stay gated instead of being reported as native Xray.")
                        .setPositiveButton("OK", null).show();
                return;
            }
            CharSequence[] labels = new CharSequence[modes.size()];
            for (int i = 0; i < modes.size(); i++) labels[i] = modes.get(i).name + " [" + modes.get(i).id + "]";
            new AlertDialog.Builder(this).setTitle("Choose native Xray mode").setItems(labels, (d, which) -> requestXray(modes.get(which))).setNegativeButton("Cancel", null).show();
        } catch (Exception e) { toast("Xray mode scan failed: " + e.getMessage()); }
    }

    private void requestXray(NativeXrayController.ModeInfo mode) {
        if (rawActiveOrBusy() || layeredActiveOrBusy()) { refreshNativeState(); return; }
        pendingXrayMode = mode;
        Intent permission = VpnService.prepare(this);
        if (permission != null) {
            statusView.setText("Waiting for Android VPN permission for native Xray " + mode.name + "…");
            startActivityForResult(permission, PREPARE_XRAY);
        } else startPendingXray();
    }

    private void startPendingXray() {
        NativeXrayController.ModeInfo mode = pendingXrayMode;
        pendingXrayMode = null;
        if (mode == null) return;
        if (rawActiveOrBusy() || layeredActiveOrBusy()) { statusView.setText("Another VPN became active; native Xray start cancelled."); refreshNativeState(); return; }
        try {
            NativeXrayController.SessionInfo session = xray.prepareSession(getFileStreamPath(BUNDLE_FILE), mode.id);
            xrayBusy = true;
            statusView.setText("Starting native Xray " + mode.name + " and proving selected node…");
            xray.start(session);
            scheduleXrayRefresh();
        } catch (Exception e) {
            xrayBusy = false;
            statusView.setText("Native Xray start failed: " + e.getMessage());
            toast(e.getMessage());
            refreshNativeState();
        }
    }

    private void disconnectXray() {
        if (xray == null) return;
        xrayBusy = true;
        xray.stop();
        statusView.setText("Stopping native Xray VPN…");
        scheduleXrayRefresh();
    }

    private void scheduleXrayRefresh() {
        long[] delays = {250, 750, 1500, 3000};
        for (long delay : delays) handler.postDelayed(() -> {
            refreshNativeState();
            String state = xray.getState();
            if (!"STARTING".equals(state) && !"STOPPING".equals(state)) xrayBusy = false;
        }, delay);
    }

'''
replace_once('    private void chooseLayeredMode() {\n', methods + '    private void chooseLayeredMode() {\n')

activity_anchor = '''        if (code == PREPARE_LAYERED) { if (result == RESULT_OK) startPendingLayered(); else { pendingLayeredMode = null; statusView.setText("VPN permission denied; no layered session was created."); refreshNativeState(); } return; }
'''
replace_once(activity_anchor, activity_anchor + '''        if (code == PREPARE_XRAY) { if (result == RESULT_OK) startPendingXray(); else { pendingXrayMode = null; xrayBusy = false; statusView.setText("VPN permission denied; native Xray stayed disconnected."); refreshNativeState(); } return; }
''')

refresh_head = '''        if (nativeStatusView == null || wireGuard == null || amneziaWG == null || singBox == null) return;
        Tunnel.State w = wireGuard.getState();
        org.amnezia.awg.backend.Tunnel.State a = amneziaWG.getState();
        String ls = singBox.getState(), lm = singBox.getMode(), le = singBox.getError();
        if (!"STARTING".equals(ls) && !"STOPPING".equals(ls)) layeredBusy = false;
'''
replace_once(refresh_head, '''        if (nativeStatusView == null || wireGuard == null || amneziaWG == null || singBox == null || xray == null) return;
        Tunnel.State w = wireGuard.getState();
        org.amnezia.awg.backend.Tunnel.State a = amneziaWG.getState();
        String ls = singBox.getState(), lm = singBox.getMode(), le = singBox.getError();
        String xs = xray.getState(), xm = xray.getMode(), xe = xray.getError();
        if (!"STARTING".equals(ls) && !"STOPPING".equals(ls)) layeredBusy = false;
        if (!"STARTING".equals(xs) && !"STOPPING".equals(xs)) xrayBusy = false;
''')
replace_once(
    '''AmneziaWG 2: " + a + "\\nLayered/multihop: " + ls + (lm.isEmpty() ? "" : " — " + lm) + (le.isEmpty() ? "" : "\\nLast layered error: " + le) + (automationBusy ? "\\nAUTO/SMART/CUSTOM: testing…" : "")''',
    '''AmneziaWG 2: " + a + "\\nNative Xray: " + xs + (xm.isEmpty() ? "" : " — " + xm) + (xe.isEmpty() ? "" : "\\nLast Xray error: " + xe) + "\\nLayered/multihop: " + ls + (lm.isEmpty() ? "" : " — " + lm) + (le.isEmpty() ? "" : "\\nLast layered error: " + le) + (automationBusy ? "\\nAUTO/SMART/CUSTOM: testing…" : "")''',
)
buttons_anchor = '''        awgDisconnectButton.setEnabled(!automationBusy && !multihopBusy && !awgBusy && a == org.amnezia.awg.backend.Tunnel.State.UP);
        nativeConnectButton.setEnabled(!wgBusy && !awgBusy && !rawBlocked && a != org.amnezia.awg.backend.Tunnel.State.UP);
        awgConnectButton.setEnabled(!wgBusy && !awgBusy && !rawBlocked && w != Tunnel.State.UP);
'''
replace_once(buttons_anchor, '''        awgDisconnectButton.setEnabled(!automationBusy && !multihopBusy && !awgBusy && a == org.amnezia.awg.backend.Tunnel.State.UP);
        xrayDisconnectButton.setEnabled(!automationBusy && !multihopBusy && !xrayBusy && ("UP".equals(xs) || "STARTING".equals(xs)));
        nativeConnectButton.setEnabled(!wgBusy && !awgBusy && !rawBlocked && a != org.amnezia.awg.backend.Tunnel.State.UP);
        awgConnectButton.setEnabled(!wgBusy && !awgBusy && !rawBlocked && w != Tunnel.State.UP);
        xrayConnectButton.setEnabled(!xrayBusy && !layeredBlocked && !"UP".equals(xs) && !"STARTING".equals(xs) && !"STOPPING".equals(xs));
''')

PATH.write_text(text, encoding="utf-8")
print("Wired native Xray selection/state/onboarding into MainActivity")
