package com.eabusham.routervpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.os.Bundle;
import android.provider.Settings;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** Native daily-use product shell. The engine-heavy MainActivity remains the Connect surface. */
public final class ProductActivity extends Activity {
    private AndroidNodeStore nodeStore;
    private RouterVpnNodeMapView mapView;
    private TextView summaryView;

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        nodeStore = new AndroidNodeStore(this);
        setContentView(buildUi());
        refreshNodes();
    }

    @Override protected void onResume() { super.onResume(); refreshNodes(); }

    private View buildUi() {
        int pad = dp(18);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(pad, pad, pad, pad);

        TextView title = text("Router VPN", 28, true);
        root.addView(title);
        TextView subtitle = text("Native Android product dashboard — install once, link many private nodes", 14, false);
        root.addView(subtitle, margins(0, dp(4), 0, dp(12)));

        HorizontalScrollView navScroll = new HorizontalScrollView(this);
        navScroll.setHorizontalScrollBarEnabled(false);
        LinearLayout nav = new LinearLayout(this);
        nav.setOrientation(LinearLayout.HORIZONTAL);
        nav.addView(navButton("Home / Connect", v -> openConnect()));
        nav.addView(navButton("Nodes / Map", v -> showNodes()));
        nav.addView(navButton("Modes", v -> showModes()));
        nav.addView(navButton("DNS", v -> showDns()));
        nav.addView(navButton("Advanced", v -> showAdvanced()));
        nav.addView(navButton("Forwarding", v -> showForwarding()));
        nav.addView(navButton("Settings", v -> openSettings()));
        nav.addView(navButton("Help", v -> showHelp()));
        navScroll.addView(nav);
        root.addView(navScroll, margins(0, 0, 0, dp(12)));

        summaryView = text("No active Router VPN node.", 16, true);
        root.addView(summaryView, margins(0, dp(4), 0, dp(10)));

        TextView mapTitle = text("Nodes & Map", 20, true);
        root.addView(mapTitle);
        TextView mapTruth = text("Only latitude/longitude already stored in a linked node bundle is plotted. Router VPN never guesses a location.", 13, false);
        root.addView(mapTruth, margins(0, dp(2), 0, dp(8)));
        mapView = new RouterVpnNodeMapView(this);
        root.addView(mapView, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(300)));

        Button connect = button("Open Connect — native WG/AWG/libbox/Xray/AUTO/SMART/CUSTOM/ALL");
        connect.setOnClickListener(v -> openConnect());
        root.addView(connect, margins(0, dp(14), 0, 0));
        Button nodes = button("Choose active node");
        nodes.setOnClickListener(v -> showNodes());
        root.addView(nodes, margins(0, dp(8), 0, 0));

        TextView footer = text("Forwarding/server administration stays on the authenticated private Setup Center surface; the Android client never pretends a proxy-only mode can perform arbitrary DNAT.", 13, false);
        root.addView(footer, margins(0, dp(18), 0, dp(16)));

        ScrollView scroll = new ScrollView(this);
        scroll.addView(root);
        return scroll;
    }

    private void refreshNodes() {
        if (nodeStore == null || mapView == null || summaryView == null) return;
        try {
            List<AndroidNodeStore.Node> nodes = nodeStore.list();
            String activeId = nodeStore.activeId();
            List<RouterVpnNodeMapView.Marker> markers = new ArrayList<>();
            AndroidNodeStore.Node active = null;
            for (AndroidNodeStore.Node node : nodes) {
                if (node.id.equals(activeId)) active = node;
                JSONObject profile = selectedProfile(node.file);
                if (profile == null || !profile.has("latitude") || !profile.has("longitude")) continue;
                double latitude = profile.optDouble("latitude", Double.NaN);
                double longitude = profile.optDouble("longitude", Double.NaN);
                if (!Double.isFinite(latitude) || !Double.isFinite(longitude)) continue;
                if (latitude < -90 || latitude > 90 || longitude < -180 || longitude > 180) continue;
                markers.add(new RouterVpnNodeMapView.Marker(node.id, node.name, latitude, longitude, node.id.equals(activeId)));
            }
            mapView.setMarkers(markers);
            if (active == null) {
                summaryView.setText(nodes.isEmpty() ? "No linked Router VPN nodes — open Connect to import one." : "Choose an active node from Nodes / Map.");
            } else {
                JSONObject p = selectedProfile(active.file);
                String location = p == null ? "" : p.optString("location", "").trim();
                String latency = p == null ? "" : numericText(p, "latency_median_ms", " ms median");
                summaryView.setText(active.name + "\n" + active.endpoint + (location.isEmpty() ? "" : "\n" + location) + (latency.isEmpty() ? "" : " · " + latency));
            }
        } catch (Exception error) {
            summaryView.setText("Node store unavailable: " + error.getMessage());
            mapView.setMarkers(new ArrayList<>());
        }
    }

    private void showNodes() {
        try {
            List<AndroidNodeStore.Node> nodes = nodeStore.list();
            if (nodes.isEmpty()) {
                dialog("Nodes / Map", "No linked nodes yet. Open Connect and use Add / import router bundle. Linking is data; it never reinstalls the app.");
                return;
            }
            String[] names = new String[nodes.size()];
            for (int i = 0; i < nodes.size(); i++) names[i] = nodes.get(i).toString();
            new AlertDialog.Builder(this).setTitle("Nodes / Map — choose active node")
                    .setItems(names, (d, which) -> {
                        try { nodeStore.select(nodes.get(which).id); refreshNodes(); toast("Selected " + nodes.get(which).name); }
                        catch (Exception error) { toast(error.getMessage()); }
                    }).setNegativeButton("Close", null).show();
        } catch (Exception error) { toast(error.getMessage()); }
    }

    private void showModes() {
        dialog("Modes", "Open Connect for truthful runtime readiness plus WireGuard, AmneziaWG, embedded libbox/Xray, AUTO, SMART AUTO, CUSTOM, ALL, and compatible multihop. Unavailable combinations remain unavailable instead of being CSS-forced ready.");
    }

    private void showDns() {
        JSONObject p = activeProfile();
        if (p == null) { dialog("DNS", "Choose/link an active node first."); return; }
        String mode = p.optString("dns_mode", "home");
        String host = p.optString("dns_host", "");
        String latency = numericText(p, "fastest_dns_latency_ms", " ms");
        dialog("DNS", "Selected mode: " + mode + "\nResolver: " + (host.isEmpty() ? "profile/default" : host) + "\nMeasured DNS RTT: " + (latency.isEmpty() ? "not measured" : latency) + "\n\nConnected status still requires runtime DNS enforcement/proof; a saved selection alone is not proof.");
    }

    private void showAdvanced() {
        JSONObject p = activeProfile();
        if (p == null) { dialog("Advanced", "Choose/link an active node first."); return; }
        String mtu = p.optString("mtu_mode", "default");
        int customMtu = p.optInt("custom_mtu", 0);
        String kill = p.optString("kill_switch_policy", "off");
        boolean lan = p.optBoolean("home_lan_access", true);
        boolean multihop = p.optBoolean("multihop_enabled", false);
        dialog("Advanced", "LAN access: " + (lan ? "On" : "Off") + "\nKill switch: " + kill + "\nMTU: " + mtu + (customMtu > 0 ? " / " + customMtu : "") + "\nMultihop profile: " + (multihop ? "Enabled" : "Off") + "\n\nRuntime support remains fail-closed when Android cannot enforce a requested policy.");
    }

    private void showForwarding() {
        dialog("Forwarding", "Incoming forwarding is owned by the authenticated private home-node Setup Center/router-agent surface. This client does not expose an admin token or Docker/Portainer authority and does not fake DNAT in proxy-only modes. Use Setup Center Forwarding to manage master state and TCP/UDP/both rules, then validate them off-LAN.");
    }

    private void openSettings() { startActivity(new Intent(Settings.ACTION_VPN_SETTINGS)); }

    private void showHelp() {
        new AlertDialog.Builder(this).setTitle("Help")
                .setMessage("Install Router VPN once, link node data separately, select the intended node, then open Connect. Connected means selected-node private path proof passed — generic Internet access is not enough. Use the Connect screen's Run full onboarding again for the complete Android setup tutorial.")
                .setPositiveButton("Open Connect", (d, w) -> openConnect()).setNegativeButton("Close", null).show();
    }

    private void openConnect() { startActivity(new Intent(this, MainActivity.class)); }

    private JSONObject activeProfile() {
        try {
            String active = nodeStore.activeId();
            if (active.isEmpty()) return null;
            return selectedProfile(nodeStore.file(active));
        } catch (Exception ignored) { return null; }
    }

    private static JSONObject selectedProfile(File file) throws Exception {
        if (file == null || !file.isFile() || file.length() <= 0 || file.length() > AndroidNodeStore.MAX_BUNDLE) return null;
        byte[] raw;
        try (FileInputStream in = new FileInputStream(file); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buf = new byte[8192]; int n, total = 0;
            while ((n = in.read(buf)) != -1) {
                total += n;
                if (total > AndroidNodeStore.MAX_BUNDLE) throw new IllegalArgumentException("node bundle is too large");
                out.write(buf, 0, n);
            }
            raw = out.toByteArray();
        }
        JSONObject bundle = new JSONObject(new String(raw, StandardCharsets.UTF_8));
        JSONArray profiles = bundle.optJSONArray("routerProfiles");
        if (profiles == null || profiles.length() == 0) return null;
        String wanted = bundle.optString("selectedRouterID", "").trim();
        for (int i = 0; i < profiles.length(); i++) {
            JSONObject p = profiles.optJSONObject(i);
            if (p != null && wanted.equals(p.optString("id", ""))) return p;
        }
        return profiles.optJSONObject(0);
    }

    private static String numericText(JSONObject p, String key, String suffix) {
        if (p == null || !p.has(key)) return "";
        double value = p.optDouble(key, Double.NaN);
        return Double.isFinite(value) ? String.format(java.util.Locale.US, "%.2f%s", value, suffix) : "";
    }

    private void dialog(String title, String message) { new AlertDialog.Builder(this).setTitle(title).setMessage(message).setPositiveButton("OK", null).show(); }
    private void toast(String message) { Toast.makeText(this, message == null ? "Router VPN" : message, Toast.LENGTH_LONG).show(); }
    private TextView text(String value, int sp, boolean bold) {
        TextView v = new TextView(this); v.setText(value); v.setTextSize(sp); v.setTextColor(0xff14213d); if (bold) v.setTypeface(v.getTypeface(), android.graphics.Typeface.BOLD); return v;
    }
    private Button button(String value) { Button b = new Button(this); b.setText(value); b.setAllCaps(false); return b; }
    private Button navButton(String value, View.OnClickListener listener) { Button b = button(value); b.setOnClickListener(listener); return b; }
    private LinearLayout.LayoutParams margins(int l, int t, int r, int b) { LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT); p.setMargins(l, t, r, b); return p; }
    private int dp(int value) { return Math.round(value * getResources().getDisplayMetrics().density); }
}
