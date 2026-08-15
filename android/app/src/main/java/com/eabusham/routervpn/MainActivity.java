package com.eabusham.routervpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import com.wireguard.android.backend.Tunnel;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public final class MainActivity extends Activity {
    private static final int IMPORT_BUNDLE = 1001;
    private static final int PREPARE_NATIVE_WG = 1002;
    private static final int PREPARE_NATIVE_AWG = 1003;
    private static final int PREPARE_LAYERED = 1004;
    private static final int PREPARE_AUTO = 1005;
    private static final int PREPARE_MULTIHOP = 1006;
    private static final int PREPARE_XRAY = 1007;
    private static final String BUNDLE_FILE = AndroidNodeStore.ACTIVE_BUNDLE;
    private static final String PREFS = "router-vpn";
    private static final String ONBOARDING_DONE = "onboarding_done_v6";
    private static final String ONBOARDING_STEP = "onboarding_step_v6";
    private static final int ONBOARDING_LAST_STEP = 10;

    private TextView statusView, endpointView, socksView, modesView, nativeStatusView;
    private Button nativeConnectButton, nativeDisconnectButton, awgConnectButton, awgDisconnectButton;
    private Button layeredConnectButton, layeredDisconnectButton, xrayConnectButton, xrayDisconnectButton, autoButton, smartButton, customButton;
    private Button allButton;
    private Button manageNodesButton, multihopButton;
    private String socksAddress = "";

    private NativeWireGuardController wireGuard;
    private NativeAmneziaWGController amneziaWG;
    private NativeSingBoxController singBox;
    private NativeXrayController xray;
    private AndroidModeOrchestrator orchestrator;
    private AndroidNodeStore nodeStore;
    private AndroidMultihopRuntime multihop;

    private NativeSingBoxController.ModeInfo pendingLayeredMode;
    private NativeXrayController.ModeInfo pendingXrayMode;
    private AndroidNodeStore.Node pendingEntryNode, pendingExitNode;
    private String pendingExitMode = "";
    private boolean wgBusy, awgBusy, layeredBusy, xrayBusy, automationBusy, multihopBusy, pendingSmart;
    private boolean pendingAll;
    private List<String> pendingCustomLayers;
    private final Handler handler = new Handler(Looper.getMainLooper());

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        wireGuard = new NativeWireGuardController(this);
        amneziaWG = new NativeAmneziaWGController(this);
        singBox = new NativeSingBoxController(this);
        xray = new NativeXrayController(this);
        orchestrator = new AndroidModeOrchestrator(this, wireGuard, amneziaWG, singBox, xray);
        nodeStore = new AndroidNodeStore(this);
        multihop = new AndroidMultihopRuntime(this, singBox);
        setContentView(buildUi());
        loadSavedBundle();
        refreshNativeState();
        if (!prefs().getBoolean(ONBOARDING_DONE, false)) showOnboarding(false);
    }

    @Override protected void onResume() { super.onResume(); refreshNativeState(); }

    @Override protected void onDestroy() {
        handler.removeCallbacksAndMessages(null);
        if (multihop != null) multihop.close();
        if (orchestrator != null) orchestrator.close();
        if (wireGuard != null) wireGuard.close();
        if (amneziaWG != null) amneziaWG.close();
        super.onDestroy();
    }

    private View buildUi() {
        int pad = dp(20);
        LinearLayout c = new LinearLayout(this);
        c.setOrientation(LinearLayout.VERTICAL);
        c.setPadding(pad, pad, pad, pad);
        c.addView(text("Router VPN", 28, true));
        statusView = text("Add or pair a private Router VPN node.", 16, false);
        c.addView(statusView, margins(0, dp(12), 0, dp(12)));

        Button importButton = button("Add / import router bundle");
        importButton.setOnClickListener(v -> openBundlePicker());
        c.addView(importButton);
        manageNodesButton = button("Manage stored routers");
        manageNodesButton.setOnClickListener(v -> showStoredNodes());
        c.addView(manageNodesButton, margins(0, dp(8), 0, 0));

        nativeConnectButton = button("Connect native WireGuard");
        nativeConnectButton.setOnClickListener(v -> requestNativeWireGuard());
        c.addView(nativeConnectButton, margins(0, dp(12), 0, 0));
        nativeDisconnectButton = button("Disconnect native WireGuard");
        nativeDisconnectButton.setOnClickListener(v -> disconnectNativeWireGuard());
        c.addView(nativeDisconnectButton, margins(0, dp(8), 0, 0));

        awgConnectButton = button("Connect native AmneziaWG 2");
        awgConnectButton.setOnClickListener(v -> requestNativeAmneziaWG());
        c.addView(awgConnectButton, margins(0, dp(8), 0, 0));
        awgDisconnectButton = button("Disconnect native AmneziaWG 2");
        awgDisconnectButton.setOnClickListener(v -> disconnectNativeAmneziaWG());
        c.addView(awgDisconnectButton, margins(0, dp(8), 0, 0));

        xrayConnectButton = button("Connect native Xray mode");
        xrayConnectButton.setOnClickListener(v -> chooseXrayMode());
        c.addView(xrayConnectButton, margins(0, dp(8), 0, 0));
        xrayDisconnectButton = button("Disconnect native Xray");
        xrayDisconnectButton.setOnClickListener(v -> disconnectXray());
        c.addView(xrayDisconnectButton, margins(0, dp(8), 0, 0));

        layeredConnectButton = button("Connect embedded layered mode");
        layeredConnectButton.setOnClickListener(v -> chooseLayeredMode());
        c.addView(layeredConnectButton, margins(0, dp(8), 0, 0));
        layeredDisconnectButton = button("Disconnect embedded / multihop VPN");
        layeredDisconnectButton.setOnClickListener(v -> disconnectLayered());
        c.addView(layeredDisconnectButton, margins(0, dp(8), 0, 0));

        autoButton = button("AUTO — first proven working mode");
        autoButton.setOnClickListener(v -> requestAutomation(false, null));
        c.addView(autoButton, margins(0, dp(12), 0, 0));
        smartButton = button("SMART AUTO — simplify and restore safely");
        smartButton.setOnClickListener(v -> requestAutomation(true, null));
        c.addView(smartButton, margins(0, dp(8), 0, 0));
        customButton = button("CUSTOM — choose required layers");
        customButton.setOnClickListener(v -> chooseCustomLayers());
        c.addView(customButton, margins(0, dp(8), 0, 0));
        allButton = button("ALL — strongest proven Android-native branch");
        allButton.setOnClickListener(v -> requestAll());
        c.addView(allButton, margins(0, dp(8), 0, 0));

        multihopButton = button("Multihop — choose entry → exit");
        multihopButton.setOnClickListener(v -> chooseMultihop());
        c.addView(multihopButton, margins(0, dp(12), 0, 0));

        Button copy = button("Copy SOCKS5 IP:port");
        copy.setOnClickListener(v -> copySocks());
        c.addView(copy, margins(0, dp(12), 0, 0));
        Button settings = button("Open Android VPN settings");
        settings.setOnClickListener(v -> startActivity(new Intent(Settings.ACTION_VPN_SETTINGS)));
        c.addView(settings, margins(0, dp(8), 0, 0));
        Button checks = button("Run setup check");
        checks.setOnClickListener(v -> showSetupCheck());
        c.addView(checks, margins(0, dp(8), 0, 0));
        Button onboarding = button("Run full onboarding again");
        onboarding.setOnClickListener(v -> showOnboarding(true));
        c.addView(onboarding, margins(0, dp(8), 0, 0));

        endpointView = section("Endpoint", "Not imported");
        c.addView(endpointView, margins(0, dp(20), 0, 0));
        socksView = section("SOCKS5", "Not imported");
        c.addView(socksView, margins(0, dp(12), 0, 0));
        nativeStatusView = section("Native Android VPN", "Native engine states: checking");
        c.addView(nativeStatusView, margins(0, dp(12), 0, 0));
        modesView = section("Modes in active bundle", "Not imported");
        c.addView(modesView, margins(0, dp(12), 0, 0));
        c.addView(section("Android capability boundary",
                "Raw WireGuard and AmneziaWG 2 use embedded userspace backends. Self-contained generated sing-box profiles use pinned libbox, and self-contained Reality/XHTTP profiles use pinned Xray-core v26.7.11 through a dedicated Android VpnService. AUTO/SMART/CUSTOM/ALL require selected-node private path proof. Real Android multihop is currently limited to a standard WireGuard entry plus a different stored node using a self-contained Shadowsocks or Hysteria2 exit; the exit node must pass private path proof before Connected. AWG-entry multihop and composite MAX/mixed sidecar chains remain gated; ALL ranks only real Android-native branches strongest-to-weaker and never relabels a partial MAX sidecar as ALL. Strict embedded libbox/Xray sessions require Android 10+ Always-on plus lockdown/Block connections without VPN; raw strict WG/AWG fail closed. Multihop adds latency by design. Network changes reset/revalidate libbox and native Xray, but final reconnect/leak behavior still needs real-device validation. SOCKS5 remains tunnel/LAN-only; never expose TCP 1080 to WAN."), margins(0, dp(20), 0, dp(20)));

        ScrollView s = new ScrollView(this);
        s.addView(c);
        return s;
    }

    private SharedPreferences prefs() { return getSharedPreferences(PREFS, MODE_PRIVATE); }

    private void showOnboarding(boolean restart) {
        if (restart) prefs().edit().putBoolean(ONBOARDING_DONE, false).putInt(ONBOARDING_STEP, 0).apply();
        showOnboardingStep(Math.max(0, Math.min(ONBOARDING_LAST_STEP, prefs().getInt(ONBOARDING_STEP, 0))));
    }

    private void showOnboardingStep(final int step) {
        AlertDialog.Builder b = new AlertDialog.Builder(this)
                .setTitle("Router VPN setup — " + (step + 1) + "/" + (ONBOARDING_LAST_STEP + 1))
                .setMessage(onboardingText(step))
                .setNegativeButton("Close for now", (d, w) -> d.dismiss());
        if (step > 0) b.setNeutralButton(step == 5 ? "Add router" : step == 9 ? "Run setup check" : "Back", null);
        b.setPositiveButton(step == ONBOARDING_LAST_STEP ? "Finish" : "Next", null);
        AlertDialog d = b.create();
        d.setOnShowListener(x -> {
            d.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
                if (step == ONBOARDING_LAST_STEP) {
                    prefs().edit().putBoolean(ONBOARDING_DONE, true).putInt(ONBOARDING_STEP, 0).apply();
                    d.dismiss();
                    toast("Onboarding complete");
                } else {
                    int n = step + 1;
                    prefs().edit().putInt(ONBOARDING_STEP, n).apply();
                    d.dismiss();
                    showOnboardingStep(n);
                }
            });
            if (step > 0) d.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener(v -> {
                if (step == 5) { d.dismiss(); openBundlePicker(); }
                else if (step == 9) showSetupCheck();
                else {
                    int p = step - 1;
                    prefs().edit().putInt(ONBOARDING_STEP, p).apply();
                    d.dismiss();
                    showOnboardingStep(p);
                }
            });
        });
        d.show();
    }

    private String onboardingText(int s) {
        switch (s) {
            case 0: return "Complete path: deploy home node → authenticated Setup Center → Add Router/import or secure LAN pairing → choose active node → choose native/direct/AUTO/SMART/CUSTOM/ALL or compatible multihop → Android VPN consent → selected-node proof. Progress is saved; only Finish marks completion.";
            case 1: return "Deploy the home node from a generated exact-SHA production compose for one verified main release SHA. Require Publish ARM64 Portainer images and Exact-SHA production compose to be green for that same SHA, verify the generated RouterVPN-Portainer-RELEASE_SHA.yaml checksum plus image/broker pins, and use that YAML in Portainer. The tracked server/portainer-current.yaml is only a template/baseline; it is never silently treated as latest.";
            case 2: return "Verify init/finalize and long-running services are healthy before WAN exposure. Optional AI Board check: sudo bash server/scripts/doctor-current.sh.";
            case 3: return "On the home LAN open http://AI_BOARD_IP:8786/. Setup Center is authenticated because it can expose private node material. Keep the permanent credential router-local; pairing codes are short-lived.";
            case 4: return "ASUS forwarding exposes only intended public VPN/auxiliary ports. Never expose SOCKS5 1080, Setup Center 8786, health/admin/Portainer/AdGuard/SSH or private credentials to WAN.";
            case 5: return "Add router-vpn-bundle.json for each router. Router linking is a data operation: the app is installed once, keeps multiple node bundles in bounded Android app-private storage, and never relies on the server's repeated display id as a local filename.";
            case 6: return "Choose an active router for single-hop. Raw WG/AWG, self-contained libbox, and native self-contained Xray modes are real choices. AUTO tests native candidates; SMART tries simpler candidates and restores the last proven mode if reduction fails. ALL tests the strongest available Android-native protection branch first and truthfully falls back only after a failed proof. Strict policy excludes raw WG/AWG and requires proven Android Always-on plus lockdown for embedded libbox/Xray.";
            case 7: return "Multihop requires two different stored nodes. Current proven Android graph is standard WireGuard entry → Shadowsocks or Hysteria2 exit → Internet. The app builds one VpnService graph and requires private proof from the selected exit before Connected. AWG-entry/mixed ALL/MAX multihop stays unavailable. Expect more latency.";
            case 8: return "CUSTOM selects only a native candidate containing all requested layers. A TUN UP state alone is never AUTO or multihop success: selected-node/exit private path proof must pass. Selected DNS transport is fully enforced by embedded libbox modes. Native WG/AWG/Xray enforce only literal-IP UDP DNS and fail closed for DoH/DoT/H3/TCP selections instead of silently downgrading them; final DNS/leak proof remains a release gate.";
            case 9: return "Run setup check, server doctor, and ASUS forwarding status. Final release still requires live exit-IP, DNS, leak, reconnect, kill-switch, multihop-failure and network-transition checks on real devices and off-LAN networks.";
            default: return "Finish dismisses onboarding; reopen it any time. Router VPN deliberately greys or rejects combinations it cannot prove rather than reporting a fake Connected state.";
        }
    }

    private void showSetupCheck() {
        new AlertDialog.Builder(this).setTitle("Router VPN setup check").setMessage(setupCheckText()).setPositiveButton("OK", null).show();
    }

    private String setupCheckText() {
        StringBuilder r = new StringBuilder();
        try {
            List<AndroidNodeStore.Node> nodes = nodeStore.list();
            r.append("✓ Stored routers: ").append(nodes.size()).append('/').append(AndroidNodeStore.MAX_NODES).append('\n');
            if (nodes.size() >= 2) r.append("✓ Two-node selection is available for compatible multihop\n");
            else r.append("! Add a second router to use multihop\n");
            JSONObject b = readBundle();
            validateBundle(b);
            String e = b.optString("endpoint", "").trim(), h = b.optString("socks5Host", "").trim();
            int p = b.optInt("socks5Port", 1080);
            JSONArray m = b.optJSONArray("modes");
            r.append("✓ Active router bundle loaded\n")
                    .append(e.isEmpty() ? "! Public endpoint is blank\n" : "✓ Public endpoint configured\n")
                    .append(!h.isEmpty() && p > 0 ? "✓ SOCKS5 IP + port configured\n" : "✗ SOCKS5 settings incomplete\n")
                    .append(hasRawWireGuard(b) ? "✓ Raw WireGuard profile available\n" : "! Raw WireGuard profile missing\n")
                    .append(hasRawAmneziaWG(b) ? "✓ Raw AmneziaWG 2 profile available\n" : "! Raw AmneziaWG 2 profile missing\n");
            List<NativeSingBoxController.ModeInfo> direct = singBox.listDirectLibboxModes(getFileStreamPath(BUNDLE_FILE));
            r.append(!direct.isEmpty() ? "✓ " + direct.size() + " direct embedded libbox mode(s) available\n" : "! No self-contained libbox profile available\n");
            List<NativeXrayController.ModeInfo> directXray = xray.listDirectXrayModes(getFileStreamPath(BUNDLE_FILE));
            r.append(!directXray.isEmpty() ? "✓ " + directXray.size() + " native Xray mode(s) available\n" : "! No self-contained native Xray profile available\n");
            boolean utilities = hasMode(m, "all") && hasMode(m, "smart-auto") && hasMode(m, "custom");
            r.append(utilities ? "✓ Bundle catalogs ALL / SMART AUTO / CUSTOM\n" : "! Utility mode catalog incomplete\n");
            boolean strict = AndroidKillSwitchPolicy.strictRequested(b);
            r.append(strict ? "✓ Strict policy requested: embedded libbox/Xray requires proven Android Always-on + Block connections without VPN; raw WG/AWG fail closed.\n" : "ℹ Strict kill switch is not requested for the active node.\n");
        } catch (Exception x) {
            r.append("✗ Add/link a Router VPN node first: ").append(x.getMessage()).append('\n');
        }
        Tunnel.State w = wireGuard == null ? Tunnel.State.DOWN : wireGuard.getState();
        org.amnezia.awg.backend.Tunnel.State a = amneziaWG == null ? org.amnezia.awg.backend.Tunnel.State.DOWN : amneziaWG.getState();
        String ls = singBox == null ? "DOWN" : singBox.getState(), lm = singBox == null ? "" : singBox.getMode(), le = singBox == null ? "" : singBox.getError();
        r.append("ℹ WireGuard: ").append(w).append("\nℹ AmneziaWG: ").append(a).append("\nℹ Layered/multihop: ").append(ls).append(lm.isEmpty() ? "" : " (" + lm + ")").append('\n');
        if (!le.isEmpty()) r.append("! Last layered error: ").append(le).append('\n');
        r.append("ℹ AUTO/SMART/CUSTOM and multihop require private path proof, not only VPN UP.\nℹ Server: server/scripts/doctor-current.sh\nℹ ASUS: /jffs/scripts/router-vpn-forward.sh status");
        return r.toString();
    }

    private boolean hasRawWireGuard(JSONObject b) {
        JSONObject p = b.optJSONObject("profiles"), w = p == null ? null : p.optJSONObject("wg");
        return w != null && !w.optString("wg.conf", "").trim().isEmpty();
    }

    private boolean hasRawAmneziaWG(JSONObject b) {
        JSONObject p = b.optJSONObject("profiles");
        if (p == null) return false;
        JSONObject a = p.optJSONObject("awg2-fast");
        if (a == null) a = p.optJSONObject("awg2-strong");
        return a != null && !a.optString("awg.conf", "").trim().isEmpty();
    }

    private boolean hasMode(JSONArray a, String id) {
        if (a == null) return false;
        for (int i = 0; i < a.length(); i++) {
            JSONObject m = a.optJSONObject(i);
            if (m != null && id.equals(m.optString("id", ""))) return true;
        }
        return false;
    }

    private boolean layeredActiveOrBusy() {
        String s = singBox == null ? "DOWN" : singBox.getState();
        String xs = xray == null ? "DOWN" : xray.getState();
        return layeredBusy || xrayBusy || automationBusy || multihopBusy
                || "STARTING".equals(s) || "UP".equals(s) || "STOPPING".equals(s)
                || "STARTING".equals(xs) || "UP".equals(xs) || "STOPPING".equals(xs);
    }

    private boolean rawActiveOrBusy() {
        return wgBusy || awgBusy || automationBusy || multihopBusy || wireGuard.getState() == Tunnel.State.UP || amneziaWG.getState() == org.amnezia.awg.backend.Tunnel.State.UP;
    }

    private void requestNativeWireGuard() {
        if (layeredActiveOrBusy()) { toast("Disconnect/finish the current automatic, layered or multihop VPN first"); return; }
        if (awgBusy || amneziaWG.getState() == org.amnezia.awg.backend.Tunnel.State.UP) { toast("Disconnect AmneziaWG before starting WireGuard"); return; }
        if (!bundleReady()) return;
        Intent p = VpnService.prepare(this);
        if (p != null) { statusView.setText("Waiting for Android VPN permission…"); startActivityForResult(p, PREPARE_NATIVE_WG); }
        else connectNativeWireGuard();
    }

    private void requestNativeAmneziaWG() {
        if (layeredActiveOrBusy()) { toast("Disconnect/finish the current automatic, layered or multihop VPN first"); return; }
        if (wgBusy || wireGuard.getState() == Tunnel.State.UP) { toast("Disconnect WireGuard before starting AmneziaWG"); return; }
        if (!bundleReady()) return;
        Intent p = VpnService.prepare(this);
        if (p != null) { statusView.setText("Waiting for Android VPN permission…"); startActivityForResult(p, PREPARE_NATIVE_AWG); }
        else connectNativeAmneziaWG();
    }

    private void connectNativeWireGuard() {
        setWgBusy(true, "WireGuard connecting…");
        wireGuard.connect(getFileStreamPath(BUNDLE_FILE), (s, m, e) -> runOnUiThread(() -> {
            setWgBusy(false, "WireGuard: " + s);
            statusView.setText(e == null && s == Tunnel.State.UP ? "Native Android WireGuard connected." : m);
            if (e != null) toast(m);
            refreshNativeState();
        }));
    }

    private void connectNativeAmneziaWG() {
        setAwgBusy(true, "AmneziaWG connecting…");
        amneziaWG.connect(getFileStreamPath(BUNDLE_FILE), (s, m, e) -> runOnUiThread(() -> {
            setAwgBusy(false, "AmneziaWG: " + s);
            statusView.setText(e == null && s == org.amnezia.awg.backend.Tunnel.State.UP ? "Native Android AmneziaWG 2 connected." : m);
            if (e != null) toast(m);
            refreshNativeState();
        }));
    }

    private void disconnectNativeWireGuard() {
        setWgBusy(true, "WireGuard disconnecting…");
        wireGuard.disconnect((s, m, e) -> runOnUiThread(() -> { setWgBusy(false, "WireGuard: " + s); statusView.setText(m); if (e != null) toast(m); refreshNativeState(); }));
    }

    private void disconnectNativeAmneziaWG() {
        setAwgBusy(true, "AmneziaWG disconnecting…");
        amneziaWG.disconnect((s, m, e) -> runOnUiThread(() -> { setAwgBusy(false, "AmneziaWG: " + s); statusView.setText(m); if (e != null) toast(m); refreshNativeState(); }));
    }


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

    private void chooseLayeredMode() {
        if (rawActiveOrBusy()) { toast("Disconnect WireGuard/AmneziaWG or finish AUTO/multihop first"); return; }
        if (layeredActiveOrBusy()) { toast("Disconnect the current layered mode first"); return; }
        if (!bundleReady()) return;
        try {
            List<NativeSingBoxController.ModeInfo> m = singBox.listDirectLibboxModes(getFileStreamPath(BUNDLE_FILE));
            if (m.isEmpty()) {
                new AlertDialog.Builder(this).setTitle("No direct embedded layered mode").setMessage("No self-contained sing-box full-device profile is available. Mixed local-engine profiles remain gated.").setPositiveButton("OK", null).show();
                return;
            }
            CharSequence[] labels = new CharSequence[m.size()];
            for (int i = 0; i < m.size(); i++) labels[i] = m.get(i).name + " [" + m.get(i).id + "]";
            new AlertDialog.Builder(this).setTitle("Choose embedded layered mode").setItems(labels, (d, w) -> requestLayered(m.get(w))).setNegativeButton("Cancel", null).show();
        } catch (Exception e) {
            statusView.setText("Layered mode scan failed: " + e.getMessage());
            toast(e.getMessage());
        }
    }

    private void requestLayered(NativeSingBoxController.ModeInfo m) {
        if (rawActiveOrBusy() || layeredActiveOrBusy()) { refreshNativeState(); return; }
        pendingLayeredMode = m;
        Intent p = VpnService.prepare(this);
        if (p != null) { statusView.setText("Waiting for Android VPN permission for " + m.name + "…"); startActivityForResult(p, PREPARE_LAYERED); }
        else startPendingLayered();
    }

    private void startPendingLayered() {
        NativeSingBoxController.ModeInfo m = pendingLayeredMode;
        pendingLayeredMode = null;
        if (m == null) return;
        if (rawActiveOrBusy() || layeredActiveOrBusy()) { statusView.setText("Another native VPN became active; layered start cancelled."); refreshNativeState(); return; }
        try {
            NativeSingBoxController.SessionInfo s = singBox.prepareSession(getFileStreamPath(BUNDLE_FILE), m.id);
            layeredBusy = true;
            statusView.setText("Starting embedded " + m.name + "…");
            singBox.start(s);
            scheduleLayeredRefresh();
        } catch (Exception e) {
            layeredBusy = false;
            statusView.setText("Layered start failed: " + e.getMessage());
            toast(e.getMessage());
            refreshNativeState();
        }
    }

    private void disconnectLayered() {
        if (singBox == null) return;
        layeredBusy = true;
        if (multihopBusy && multihop != null) multihop.disconnect();
        else singBox.stop();
        multihopBusy = false;
        statusView.setText("Stopping embedded layered / multihop VPN…");
        scheduleLayeredRefresh();
    }

    private void scheduleLayeredRefresh() {
        long[] delays = {250, 750, 1500, 3000};
        for (long x : delays) handler.postDelayed(() -> {
            refreshNativeState();
            String s = singBox.getState();
            if (!"STARTING".equals(s) && !"STOPPING".equals(s)) layeredBusy = false;
        }, x);
    }

    private void requestAutomation(boolean smart, List<String> custom) {
        if (rawActiveOrBusy() || layeredActiveOrBusy()) { toast("Disconnect the current VPN before AUTO/SMART/CUSTOM"); return; }
        if (!bundleReady()) return;
        pendingAll = false;
        pendingSmart = smart;
        pendingCustomLayers = custom == null ? null : new ArrayList<>(custom);
        Intent p = VpnService.prepare(this);
        if (p != null) { statusView.setText("Waiting for Android VPN permission for " + (custom != null ? "CUSTOM" : smart ? "SMART AUTO" : "AUTO") + "…"); startActivityForResult(p, PREPARE_AUTO); }
        else startPendingAutomation();
    }

    private void requestAll() {
        if (rawActiveOrBusy() || layeredActiveOrBusy()) { toast("Disconnect the current VPN before ALL"); return; }
        if (!bundleReady()) return;
        pendingAll = true;
        pendingSmart = false;
        pendingCustomLayers = null;
        Intent p = VpnService.prepare(this);
        if (p != null) { statusView.setText("Waiting for Android VPN permission for ALL…"); startActivityForResult(p, PREPARE_AUTO); }
        else startPendingAutomation();
    }

    private void startPendingAutomation() {
        final boolean smart = pendingSmart;
        final boolean all = pendingAll;
        final List<String> custom = pendingCustomLayers;
        pendingSmart = false;
        pendingAll = false;
        pendingCustomLayers = null;
        automationBusy = true;
        refreshNativeState();
        AndroidModeOrchestrator.Callback cb = new AndroidModeOrchestrator.Callback() {
            public void progress(String m) { runOnUiThread(() -> { statusView.setText(m); refreshNativeState(); }); }
            public void finished(boolean ok, String id, String m) { runOnUiThread(() -> { automationBusy = false; statusView.setText(m); if (!ok) toast(m); refreshNativeState(); }); }
        };
        if (all) orchestrator.all(getFileStreamPath(BUNDLE_FILE), cb);
        else if (custom != null) orchestrator.custom(getFileStreamPath(BUNDLE_FILE), custom, cb);
        else orchestrator.auto(getFileStreamPath(BUNDLE_FILE), smart, cb);
    }

    private void chooseCustomLayers() {
        if (!bundleReady()) return;
        try {
            List<String> layers = allCatalogLayers();
            if (layers.isEmpty()) { toast("No mode layers are present in the imported bundle"); return; }
            CharSequence[] labels = layers.toArray(new CharSequence[0]);
            boolean[] checked = new boolean[labels.length];
            new AlertDialog.Builder(this).setTitle("CUSTOM required layers")
                    .setMultiChoiceItems(labels, checked, (d, w, on) -> checked[w] = on)
                    .setPositiveButton("Connect", (d, w) -> {
                        List<String> selected = new ArrayList<>();
                        for (int i = 0; i < checked.length; i++) if (checked[i]) selected.add(layers.get(i));
                        if (selected.isEmpty()) { toast("CUSTOM requires at least one layer"); return; }
                        requestAutomation(false, selected);
                    }).setNegativeButton("Cancel", null).show();
        } catch (Exception e) { toast("CUSTOM catalog failed: " + e.getMessage()); }
    }

    private List<String> allCatalogLayers() throws Exception {
        JSONObject b = readBundle();
        JSONArray modes = b.optJSONArray("modes");
        Set<String> s = new LinkedHashSet<>();
        if (modes != null) for (int i = 0; i < modes.length(); i++) {
            JSONObject m = modes.optJSONObject(i);
            JSONArray l = m == null ? null : m.optJSONArray("layers");
            if (l != null) for (int j = 0; j < l.length(); j++) {
                String v = l.optString(j, "").trim().toLowerCase();
                if (!v.isEmpty()) s.add(v);
            }
        }
        return new ArrayList<>(s);
    }

    private void chooseMultihop() {
        if (rawActiveOrBusy() || layeredActiveOrBusy()) { toast("Disconnect the current VPN before starting multihop"); return; }
        try {
            List<AndroidNodeStore.Node> nodes = nodeStore.list();
            if (nodes.size() < 2) {
                new AlertDialog.Builder(this).setTitle("Two routers required").setMessage("Add at least two different Router VPN node bundles. Android multihop currently supports standard WireGuard entry → Shadowsocks/Hysteria2 exit.").setPositiveButton("Add router", (d, w) -> openBundlePicker()).setNegativeButton("Cancel", null).show();
                return;
            }
            CharSequence[] labels = nodeLabels(nodes, null);
            new AlertDialog.Builder(this).setTitle("Choose multihop entry node").setMessage("Entry currently must contain standard WireGuard. AWG entry remains gated.").setItems(labels, (d, which) -> chooseMultihopExit(nodes.get(which))).setNegativeButton("Cancel", null).show();
        } catch (Exception e) { toast("Multihop node scan failed: " + e.getMessage()); }
    }

    private void chooseMultihopExit(AndroidNodeStore.Node entry) {
        try {
            List<AndroidNodeStore.Node> all = nodeStore.list();
            List<AndroidNodeStore.Node> exits = new ArrayList<>();
            for (AndroidNodeStore.Node node : all) if (!node.id.equals(entry.id)) exits.add(node);
            CharSequence[] labels = nodeLabels(exits, null);
            new AlertDialog.Builder(this).setTitle("Choose multihop exit node").setMessage("The selected exit must have a self-contained Shadowsocks or Hysteria2 profile. Entry and exit are always different nodes.").setItems(labels, (d, which) -> chooseMultihopExitMode(entry, exits.get(which))).setNegativeButton("Cancel", null).show();
        } catch (Exception e) { toast("Multihop exit scan failed: " + e.getMessage()); }
    }

    private void chooseMultihopExitMode(AndroidNodeStore.Node entry, AndroidNodeStore.Node exit) {
        try {
            List<NativeSingBoxController.ModeInfo> modes = multihop.listSupportedExitModes(exit.file);
            if (modes.isEmpty()) {
                new AlertDialog.Builder(this).setTitle("Exit is not compatible").setMessage("This exit node has no self-contained Shadowsocks or Hysteria2 Android profile. Mixed/Xray/ALL/MAX exits remain gated rather than being faked.").setPositiveButton("OK", null).show();
                return;
            }
            CharSequence[] labels = new CharSequence[modes.size()];
            for (int i = 0; i < modes.size(); i++) labels[i] = modes.get(i).name + " [" + modes.get(i).id + "]";
            new AlertDialog.Builder(this).setTitle("Choose exit transport").setMessage("Path: " + entry.name + " → " + exit.name + " → Internet. Multihop normally adds latency.").setItems(labels, (d, which) -> requestMultihop(entry, exit, modes.get(which).id)).setNegativeButton("Cancel", null).show();
        } catch (Exception e) { toast("Exit compatibility check failed: " + e.getMessage()); }
    }

    private void requestMultihop(AndroidNodeStore.Node entry, AndroidNodeStore.Node exit, String mode) {
        if (rawActiveOrBusy() || layeredActiveOrBusy()) { toast("Another VPN became active; multihop start cancelled"); return; }
        pendingEntryNode = entry;
        pendingExitNode = exit;
        pendingExitMode = mode;
        Intent p = VpnService.prepare(this);
        if (p != null) {
            statusView.setText("Waiting for Android VPN permission for multihop…");
            startActivityForResult(p, PREPARE_MULTIHOP);
        } else startPendingMultihop();
    }

    private void startPendingMultihop() {
        AndroidNodeStore.Node entry = pendingEntryNode, exit = pendingExitNode;
        String mode = pendingExitMode;
        pendingEntryNode = null; pendingExitNode = null; pendingExitMode = "";
        if (entry == null || exit == null || mode.isEmpty()) return;
        if (rawActiveOrBusy() || layeredActiveOrBusy()) { statusView.setText("Another VPN became active; multihop start cancelled."); refreshNativeState(); return; }
        multihopBusy = true;
        refreshNativeState();
        multihop.connect(entry.file, exit.file, mode, new AndroidMultihopRuntime.Callback() {
            @Override public void progress(String message) { runOnUiThread(() -> { statusView.setText(message); refreshNativeState(); }); }
            @Override public void finished(boolean ok, String message) { runOnUiThread(() -> { multihopBusy = false; statusView.setText(message); if (!ok) toast(message); refreshNativeState(); }); }
        });
    }

    private void refreshNativeState() {
        if (nativeStatusView == null || wireGuard == null || amneziaWG == null || singBox == null || xray == null) return;
        Tunnel.State w = wireGuard.getState();
        org.amnezia.awg.backend.Tunnel.State a = amneziaWG.getState();
        String we = wireGuard.getError(), ae = amneziaWG.getError();
        String ls = singBox.getState(), lm = singBox.getMode(), le = singBox.getError();
        String xs = xray.getState(), xm = xray.getMode(), xe = xray.getError();
        if (!"STARTING".equals(ls) && !"STOPPING".equals(ls)) layeredBusy = false;
        if (!"STARTING".equals(xs) && !"STOPPING".equals(xs)) xrayBusy = false;
        nativeStatusView.setText("Native Android VPN\nWireGuard: " + w + (we.isEmpty() ? "" : "\nLast WireGuard error: " + we) + "\nAmneziaWG 2: " + a + (ae.isEmpty() ? "" : "\nLast AmneziaWG error: " + ae) + "\nNative Xray: " + xs + (xm.isEmpty() ? "" : " — " + xm) + (xe.isEmpty() ? "" : "\nLast Xray error: " + xe) + "\nLayered/multihop: " + ls + (lm.isEmpty() ? "" : " — " + lm) + (le.isEmpty() ? "" : "\nLast layered error: " + le) + (automationBusy ? "\nAUTO/SMART/CUSTOM/ALL: testing/proving…" : "") + (multihopBusy ? "\nMultihop: starting/proving exit…" : ""));
        boolean rawBlocked = layeredActiveOrBusy(), layeredBlocked = rawActiveOrBusy();
        nativeDisconnectButton.setEnabled(!automationBusy && !multihopBusy && !wgBusy && w == Tunnel.State.UP);
        awgDisconnectButton.setEnabled(!automationBusy && !multihopBusy && !awgBusy && a == org.amnezia.awg.backend.Tunnel.State.UP);
        xrayDisconnectButton.setEnabled(!automationBusy && !multihopBusy && !xrayBusy && ("UP".equals(xs) || "STARTING".equals(xs)));
        nativeConnectButton.setEnabled(!wgBusy && !awgBusy && !rawBlocked && a != org.amnezia.awg.backend.Tunnel.State.UP);
        awgConnectButton.setEnabled(!wgBusy && !awgBusy && !rawBlocked && w != Tunnel.State.UP);
        xrayConnectButton.setEnabled(!xrayBusy && !layeredBlocked && !"UP".equals(xs) && !"STARTING".equals(xs) && !"STOPPING".equals(xs));
        layeredConnectButton.setEnabled(!layeredBusy && !layeredBlocked && !"UP".equals(ls) && !"STARTING".equals(ls) && !"STOPPING".equals(ls));
        layeredDisconnectButton.setEnabled(!automationBusy && (multihopBusy || "UP".equals(ls) || "STARTING".equals(ls)));
        boolean autoEnabled = !rawActiveOrBusy() && !layeredActiveOrBusy();
        autoButton.setEnabled(autoEnabled);
        smartButton.setEnabled(autoEnabled);
        customButton.setEnabled(autoEnabled);
        allButton.setEnabled(autoEnabled);
        multihopButton.setEnabled(autoEnabled && storedNodeCount() >= 2);
    }

    private void setWgBusy(boolean b, String t) { wgBusy = b; nativeStatusView.setText("Native Android VPN\n" + t); if (!b) refreshNativeState(); }
    private void setAwgBusy(boolean b, String t) { awgBusy = b; nativeStatusView.setText("Native Android VPN\n" + t); if (!b) refreshNativeState(); }

    private int storedNodeCount() {
        try { return nodeStore == null ? 0 : nodeStore.list().size(); }
        catch (Exception ignored) { return 0; }
    }

    private void showStoredNodes() {
        try {
            List<AndroidNodeStore.Node> nodes = nodeStore.list();
            if (nodes.isEmpty()) {
                new AlertDialog.Builder(this).setTitle("No stored routers").setMessage("Add a Router VPN node bundle. The generic app is installed once; router linking only adds private node data.").setPositiveButton("Add router", (d, w) -> openBundlePicker()).setNegativeButton("Cancel", null).show();
                return;
            }
            String active = nodeStore.activeId();
            CharSequence[] labels = nodeLabels(nodes, active);
            new AlertDialog.Builder(this).setTitle("Stored routers").setMessage("Choose the active router for single-hop. Multihop selects entry/exit separately without changing this active choice.")
                    .setItems(labels, (d, which) -> selectStoredNode(nodes.get(which)))
                    .setPositiveButton("Add router", (d, w) -> openBundlePicker())
                    .setNeutralButton("Remove inactive", (d, w) -> showRemoveStoredNode())
                    .setNegativeButton("Close", null).show();
        } catch (Exception e) { toast("Stored router list failed: " + e.getMessage()); }
    }

    private void showRemoveStoredNode() {
        try {
            String active = nodeStore.activeId();
            List<AndroidNodeStore.Node> removable = new ArrayList<>();
            for (AndroidNodeStore.Node node : nodeStore.list()) if (!node.id.equals(active)) removable.add(node);
            if (removable.isEmpty()) { toast("The active router is protected. Select another router first, then remove this one."); return; }
            CharSequence[] labels = nodeLabels(removable, null);
            new AlertDialog.Builder(this).setTitle("Remove inactive router").setItems(labels, (d, which) -> {
                AndroidNodeStore.Node node = removable.get(which);
                new AlertDialog.Builder(this).setTitle("Remove " + node.name + "?").setMessage("This deletes only this app-private node bundle. It does not uninstall Router VPN or change the router/server.")
                        .setPositiveButton("Remove", (confirm, w) -> {
                            try { nodeStore.remove(node.id); toast("Removed " + node.name); refreshNativeState(); }
                            catch (Exception e) { toast("Remove failed: " + e.getMessage()); }
                        }).setNegativeButton("Cancel", null).show();
            }).setNegativeButton("Cancel", null).show();
        } catch (Exception e) { toast("Remove list failed: " + e.getMessage()); }
    }

    private CharSequence[] nodeLabels(List<AndroidNodeStore.Node> nodes, String active) {
        CharSequence[] labels = new CharSequence[nodes.size()];
        for (int i = 0; i < nodes.size(); i++) {
            AndroidNodeStore.Node n = nodes.get(i);
            labels[i] = (n.id.equals(active) ? "✓ " : "") + n.name + (n.endpoint.isEmpty() ? "" : " — " + n.endpoint) + "\n" + n.id.substring(0, 8);
        }
        return labels;
    }

    private void selectStoredNode(AndroidNodeStore.Node node) {
        if (rawActiveOrBusy() || layeredActiveOrBusy()) { toast("Disconnect the current VPN before changing the active router"); return; }
        try {
            nodeStore.select(node.id);
            JSONObject b = readBundle();
            validateBundle(b);
            renderBundle(b);
            toast("Active router: " + node.name);
        } catch (Exception e) { toast("Router selection failed: " + e.getMessage()); }
    }

    private boolean bundleReady() {
        if (getFileStreamPath(BUNDLE_FILE).isFile()) return true;
        toast("Add/link a Router VPN node first");
        return false;
    }

    private JSONObject readBundle() throws Exception {
        try (FileInputStream in = openFileInput(BUNDLE_FILE)) {
            return new JSONObject(new String(readLimited(in, 32 * 1024 * 1024), StandardCharsets.UTF_8));
        }
    }

    private void openBundlePicker() {
        if (rawActiveOrBusy() || layeredActiveOrBusy()) { toast("Disconnect the current VPN before adding/selecting router data"); return; }
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("application/json");
        startActivityForResult(i, IMPORT_BUNDLE);
    }

    @Override protected void onActivityResult(int code, int result, Intent data) {
        super.onActivityResult(code, result, data);
        if (code == PREPARE_NATIVE_WG) { if (result == RESULT_OK) connectNativeWireGuard(); else statusView.setText("VPN permission denied; WireGuard stayed disconnected."); return; }
        if (code == PREPARE_NATIVE_AWG) { if (result == RESULT_OK) connectNativeAmneziaWG(); else statusView.setText("VPN permission denied; AmneziaWG stayed disconnected."); return; }
        if (code == PREPARE_LAYERED) { if (result == RESULT_OK) startPendingLayered(); else { pendingLayeredMode = null; statusView.setText("VPN permission denied; no layered session was created."); refreshNativeState(); } return; }
        if (code == PREPARE_XRAY) { if (result == RESULT_OK) startPendingXray(); else { pendingXrayMode = null; xrayBusy = false; statusView.setText("VPN permission denied; native Xray stayed disconnected."); refreshNativeState(); } return; }
        if (code == PREPARE_AUTO) { if (result == RESULT_OK) startPendingAutomation(); else { pendingCustomLayers = null; pendingSmart = false; pendingAll = false; statusView.setText("VPN permission denied; automatic/ALL mode selection did not start."); refreshNativeState(); } return; }
        if (code == PREPARE_MULTIHOP) { if (result == RESULT_OK) startPendingMultihop(); else { pendingEntryNode = null; pendingExitNode = null; pendingExitMode = ""; multihopBusy = false; statusView.setText("VPN permission denied; multihop stayed disconnected."); refreshNativeState(); } return; }
        if (code != IMPORT_BUNDLE || result != RESULT_OK || data == null) return;
        if (rawActiveOrBusy() || layeredActiveOrBusy()) { toast("VPN became active; router import was cancelled to preserve the running session identity"); return; }
        Uri uri = data.getData();
        if (uri == null) return;
        try (InputStream in = getContentResolver().openInputStream(uri)) {
            if (in == null) throw new IllegalStateException("Unable to open selected file");
            byte[] bytes = readLimited(in, AndroidNodeStore.MAX_BUNDLE);
            JSONObject b = new JSONObject(new String(bytes, StandardCharsets.UTF_8));
            validateBundle(b);
            AndroidNodeStore.Node node = nodeStore.importBundle(bytes);
            renderBundle(b);
            toast("Router stored and selected: " + node.name);
            if (!prefs().getBoolean(ONBOARDING_DONE, false)) showOnboarding(false);
        } catch (Exception e) { statusView.setText("Import failed: " + e.getMessage()); }
    }

    private void loadSavedBundle() {
        try {
            File active = getFileStreamPath(BUNDLE_FILE);
            List<AndroidNodeStore.Node> nodes = nodeStore.list();
            if (nodes.isEmpty() && active.isFile()) {
                try (FileInputStream in = new FileInputStream(active)) { nodeStore.importBundle(readLimited(in, AndroidNodeStore.MAX_BUNDLE)); }
                nodes = nodeStore.list();
            }
            if (!nodes.isEmpty()) {
                String wanted = nodeStore.activeId();
                AndroidNodeStore.Node chosen = nodes.get(0);
                for (AndroidNodeStore.Node node : nodes) if (node.id.equals(wanted)) { chosen = node; break; }
                nodeStore.select(chosen.id);
            }
            JSONObject b = readBundle();
            validateBundle(b);
            renderBundle(b);
        } catch (Exception ignored) { statusView.setText("No private Router VPN node linked yet."); }
    }

    private void validateBundle(JSONObject b) { AndroidNodeStore.validateBundle(b); }

    private void renderBundle(JSONObject b) {
        String e = b.optString("endpoint", "").trim(), h = b.optString("socks5Host", "10.77.0.1").trim();
        int p = b.optInt("socks5Port", 1080);
        socksAddress = h + ":" + p;
        endpointView.setText("Endpoint\n" + (e.isEmpty() ? "Choose/configure in client" : e));
        socksView.setText("SOCKS5\n" + socksAddress + "\nAuthentication: none (tunnel/LAN only)");
        JSONArray modes = b.optJSONArray("modes");
        StringBuilder names = new StringBuilder();
        if (modes != null) for (int i = 0; i < modes.length(); i++) {
            JSONObject m = modes.optJSONObject(i);
            if (m == null) continue;
            if (names.length() > 0) names.append('\n');
            names.append(m.optString("name", m.optString("id", "unknown")));
        }
        modesView.setText("Modes in active bundle\n" + (names.length() == 0 ? "None" : names));
        int direct = 0;
        try { direct = singBox.listDirectLibboxModes(getFileStreamPath(BUNDLE_FILE)).size(); }
        catch (Exception ignored) { }
        statusView.setText("Active node selected from " + storedNodeCount() + " app-private stored router(s). Native raw WG/AWG plus " + direct + " direct libbox mode(s) are available; AUTO/SMART/CUSTOM and multihop require path proof before success.");
        refreshNativeState();
    }

    private void copySocks() {
        if (socksAddress.isEmpty()) { toast("Import the router bundle first"); return; }
        ClipboardManager c = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        c.setPrimaryClip(ClipData.newPlainText("Router VPN SOCKS5", socksAddress));
        toast("Copied " + socksAddress);
    }

    private void toast(String m) { Toast.makeText(this, m, Toast.LENGTH_LONG).show(); }

    private static byte[] readLimited(InputStream in, int max) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] b = new byte[8192];
        int total = 0, n;
        while ((n = in.read(b)) != -1) {
            total += n;
            if (total > max) throw new IllegalArgumentException("Bundle is larger than 32 MB");
            out.write(b, 0, n);
        }
        return out.toByteArray();
    }

    private TextView text(String v, int sp, boolean bold) {
        TextView x = new TextView(this);
        x.setText(v); x.setTextSize(sp);
        if (bold) x.setTypeface(x.getTypeface(), android.graphics.Typeface.BOLD);
        return x;
    }

    private TextView section(String h, String v) {
        TextView x = text(h + "\n" + v, 16, false);
        x.setPadding(dp(14), dp(14), dp(14), dp(14));
        x.setBackgroundColor(0xffeeeeee);
        return x;
    }

    private Button button(String l) {
        Button b = new Button(this);
        b.setText(l); b.setAllCaps(false); b.setGravity(Gravity.CENTER);
        return b;
    }

    private LinearLayout.LayoutParams margins(int l, int t, int r, int b) {
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        p.setMargins(l, t, r, b);
        return p;
    }

    private int dp(int v) { return Math.round(v * getResources().getDisplayMetrics().density); }
}
