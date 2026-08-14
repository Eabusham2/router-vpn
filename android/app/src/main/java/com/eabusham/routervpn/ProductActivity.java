package com.eabusham.routervpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.os.Bundle;
import android.provider.Settings;
import android.view.View;
import android.widget.Button;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/** Native daily-use product shell. The engine-heavy MainActivity remains the Router VPN Connect surface. */
public final class ProductActivity extends Activity {
    private AndroidNodeStore nodeStore;
    private AndroidStandardExitStore exitStore;
    private AndroidUnifiedNodeCatalog catalog;
    private RouterVpnNodeMapView mapView;
    private TextView summaryView;

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        nodeStore = new AndroidNodeStore(this);
        exitStore = new AndroidStandardExitStore(this);
        catalog = new AndroidUnifiedNodeCatalog(nodeStore, exitStore);
        setContentView(buildUi());
        refreshNodes();
    }

    @Override protected void onResume() { super.onResume(); refreshNodes(); }

    private View buildUi() {
        int pad = dp(18);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(pad, pad, pad, pad);

        root.addView(text("Router VPN", 28, true));
        root.addView(text("Native Android dashboard — install once, link Router VPN nodes and private external exits separately", 14, false), margins(0, dp(4), 0, dp(12)));

        HorizontalScrollView navScroll = new HorizontalScrollView(this);
        navScroll.setHorizontalScrollBarEnabled(false);
        LinearLayout nav = new LinearLayout(this);
        nav.setOrientation(LinearLayout.HORIZONTAL);
        nav.addView(navButton("Home / Connect", v -> openConnect()));
        nav.addView(navButton("Nodes / Map", v -> showNodes()));
        nav.addView(navButton("Modes", v -> showModes()));
        nav.addView(navButton("DNS", v -> showDns()));
        nav.addView(navButton("Advanced", v -> showAdvanced()));
        nav.addView(navButton("Custom Exits", v -> openStandardExits()));
        nav.addView(navButton("Forwarding", v -> showForwarding()));
        nav.addView(navButton("Settings", v -> openSettings()));
        nav.addView(navButton("Help", v -> showHelp()));
        navScroll.addView(nav);
        root.addView(navScroll, margins(0, 0, 0, dp(12)));

        summaryView = text("No linked nodes yet.", 16, true);
        root.addView(summaryView, margins(0, dp(4), 0, dp(10)));

        root.addView(text("Nodes & Map", 20, true));
        root.addView(text("Router VPN and external nodes share one list. Only real latitude/longitude stored with a node is plotted; Router VPN never geolocates or guesses an address from an IP.", 13, false), margins(0, dp(2), 0, dp(8)));
        mapView = new RouterVpnNodeMapView(this);
        root.addView(mapView, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(300)));

        Button connect = button("Open Router VPN Connect — WG / AWG / libbox / Xray / AUTO / SMART / CUSTOM / ALL");
        connect.setOnClickListener(v -> openConnect());
        root.addView(connect, margins(0, dp(14), 0, 0));
        Button nodes = button("Choose Router VPN or external node");
        nodes.setOnClickListener(v -> showNodes());
        root.addView(nodes, margins(0, dp(8), 0, 0));
        Button customExit = button("External exits — direct or Router VPN WG entry → exit");
        customExit.setOnClickListener(v -> openStandardExits());
        root.addView(customExit, margins(0, dp(8), 0, 0));

        root.addView(text("Forwarding/server administration stays on the authenticated private Setup Center surface; the Android client never exposes an admin token and never pretends a proxy-only path can perform arbitrary DNAT.", 13, false), margins(0, dp(18), 0, dp(16)));

        ScrollView scroll = new ScrollView(this);
        scroll.addView(root);
        return scroll;
    }

    private void refreshNodes() {
        if (catalog == null || mapView == null || summaryView == null) return;
        try {
            List<AndroidUnifiedNodeCatalog.Item> items = catalog.list();
            String activeId = nodeStore.activeId();
            List<RouterVpnNodeMapView.Marker> markers = new ArrayList<>();
            AndroidUnifiedNodeCatalog.Item active = null;
            int routerCount = 0, externalCount = 0, externalWithoutCoordinates = 0;
            for (AndroidUnifiedNodeCatalog.Item item : items) {
                if (item.isRouterVpn()) routerCount++; else { externalCount++; if (!item.hasCoordinates()) externalWithoutCoordinates++; }
                if (item.isRouterVpn() && item.id.equals(activeId)) active = item;
                if (!item.hasCoordinates()) continue;
                String label = item.isRouterVpn() ? item.name : item.name + " — " + item.protocol;
                markers.add(new RouterVpnNodeMapView.Marker(item.kind + ":" + item.id, label, item.latitude, item.longitude, item.isRouterVpn() && item.id.equals(activeId)));
            }
            mapView.setMarkers(markers);
            String counts = routerCount + " Router VPN node" + (routerCount == 1 ? "" : "s") + " • " + externalCount + " external exit" + (externalCount == 1 ? "" : "s");
            if (externalWithoutCoordinates > 0) counts += " • " + externalWithoutCoordinates + " external list-only (no real coordinates)";
            if (active == null) {
                summaryView.setText(items.isEmpty() ? "No linked nodes — import a Router VPN bundle or add an external custom exit." : counts + "\nChoose a Router VPN node for normal modes, or an external exit for direct/hopped custom-exit use.");
            } else {
                summaryView.setText("Active Router VPN: " + active.name + "\n" + active.subtitle() + "\n" + counts);
            }
        } catch (Exception error) {
            summaryView.setText("Node catalog unavailable: " + safe(error));
            mapView.setMarkers(new ArrayList<>());
        }
    }

    private void showNodes() {
        try {
            List<AndroidUnifiedNodeCatalog.Item> items = catalog.list();
            if (items.isEmpty()) {
                dialog("Nodes / Map", "No nodes yet. Open Router VPN Connect to import a home-node bundle or Custom Exits to add a private external WireGuard/SOCKS5/Shadowsocks/Hysteria2 exit.");
                return;
            }
            String[] labels = new String[items.size()];
            for (int i = 0; i < items.size(); i++) {
                AndroidUnifiedNodeCatalog.Item item = items.get(i);
                labels[i] = (item.isRouterVpn() ? "Router VPN • " : "External • ") + item.toString();
            }
            new AlertDialog.Builder(this).setTitle("Nodes / Map")
                    .setMessage("Router VPN nodes become the active home node. External nodes open the direct/hopped custom-exit flow. External entries with no real coordinates remain list-only.")
                    .setItems(labels, (d, which) -> chooseCatalogItem(items.get(which)))
                    .setNegativeButton("Close", null).show();
        } catch (Exception error) { toast(safe(error)); }
    }

    private void chooseCatalogItem(AndroidUnifiedNodeCatalog.Item item) {
        if (item.isRouterVpn()) {
            try { nodeStore.select(item.id); refreshNodes(); toast("Selected " + item.name); }
            catch (Exception error) { toast(safe(error)); }
            return;
        }
        Intent intent = new Intent(this, StandardExitActivity.class);
        intent.putExtra(StandardExitActivity.EXTRA_EXIT_ID, item.id);
        startActivity(intent);
    }

    private void showModes() {
        dialog("Modes", "Router VPN nodes use truthful WG/AWG/libbox/Xray readiness plus AUTO, SMART AUTO, CUSTOM, ALL and supported multihop. External nodes use the separate direct/hopped standard-exit runtime. Unavailable combinations stay unavailable instead of being CSS-forced ready.");
    }

    private void showDns() {
        JSONObject p = activeRouterProfile();
        if (p == null) { dialog("DNS", "Choose/link a Router VPN node for Router VPN DNS policy. Direct Android external exits currently use encrypted Rescue DNS through the selected external exit; they never pretend Home AdGuard is reachable through an unrelated provider."); return; }
        String mode = p.optString("dns_mode", "home");
        String host = p.optString("dns_host", "");
        String latency = numericText(p, "fastest_dns_latency_ms", " ms");
        dialog("DNS", "Selected Router VPN mode: " + mode + "\nResolver: " + (host.isEmpty() ? "profile/default" : host) + "\nMeasured DNS RTT: " + (latency.isEmpty() ? "not measured" : latency) + "\n\nConnected status still requires runtime DNS enforcement/proof; a saved selection alone is not proof.");
    }

    private void showAdvanced() {
        JSONObject p = activeRouterProfile();
        if (p == null) { dialog("Advanced", "No active Router VPN profile. External custom exits enforce their own full-device runtime and exact public-exit proof; direct Android external exits additionally require system lockdown."); return; }
        String mtu = p.optString("mtu_policy", "default");
        int customMtu = p.optInt("manual_mtu", 0);
        int effectiveMtu = p.optInt("effective_mtu", 0);
        String kill = p.optString("kill_switch_policy", "off");
        boolean lan = p.optBoolean("home_lan_access", true);
        boolean multihop = p.optBoolean("multihop_enabled", false);
        dialog("Advanced", "LAN access: " + (lan ? "On" : "Off") + "\nKill switch: " + kill + "\nMTU policy: " + mtu + (customMtu > 0 ? " / manual " + customMtu : "") + (effectiveMtu > 0 ? " / effective " + effectiveMtu : "") + "\nRouter VPN multihop profile: " + (multihop ? "Enabled" : "Off") + "\nExternal exits: direct or via Router VPN WireGuard entry\n\nRuntime support remains fail-closed when Android cannot enforce a requested policy.");
    }

    private void showForwarding() {
        dialog("Forwarding", "Incoming forwarding is owned by the authenticated private home-node Setup Center/router-agent surface. This client does not expose an admin token or Docker/Portainer authority and does not fake DNAT in proxy-only/external modes. Use Setup Center Forwarding, then validate rules off-LAN.");
    }

    private void openSettings() { startActivity(new Intent(Settings.ACTION_VPN_SETTINGS)); }
    private void openStandardExits() { startActivity(new Intent(this, StandardExitActivity.class)); }

    private void showHelp() {
        new AlertDialog.Builder(this).setTitle("Help")
                .setMessage("Install Router VPN once and link private node data separately. Router VPN nodes provide normal modes/AUTO/SMART/CUSTOM; external nodes can connect directly or as Router VPN WireGuard entry → external exit. Every external connection requires the exact expected public exit IP before success. Direct Android external exits also require Always-on VPN plus ‘Block connections without VPN’. Generic Internet access is never treated as selected-path proof.")
                .setPositiveButton("Open Connect", (d, w) -> openConnect())
                .setNeutralButton("External exits", (d, w) -> openStandardExits())
                .setNegativeButton("Close", null).show();
    }

    private void openConnect() { startActivity(new Intent(this, MainActivity.class)); }

    private JSONObject activeRouterProfile() {
        try {
            String active = nodeStore.activeId();
            if (active.isEmpty()) return null;
            return AndroidUnifiedNodeCatalog.selectedProfile(nodeStore.file(active));
        } catch (Exception ignored) { return null; }
    }

    private static String numericText(JSONObject p, String key, String suffix) {
        if (p == null || !p.has(key)) return "";
        double value = p.optDouble(key, Double.NaN);
        return Double.isFinite(value) ? String.format(java.util.Locale.US, "%.2f%s", value, suffix) : "";
    }

    private static String safe(Throwable error) { String value=error==null?"":error.getMessage(); return value==null||value.trim().isEmpty()?"Router VPN node error":value.trim(); }
    private void dialog(String title, String message) { new AlertDialog.Builder(this).setTitle(title).setMessage(message).setPositiveButton("OK", null).show(); }
    private void toast(String message) { Toast.makeText(this, message == null ? "Router VPN" : message, Toast.LENGTH_LONG).show(); }
    private TextView text(String value, int sp, boolean bold) { TextView v = new TextView(this); v.setText(value); v.setTextSize(sp); v.setTextColor(0xff14213d); if (bold) v.setTypeface(v.getTypeface(), android.graphics.Typeface.BOLD); return v; }
    private Button button(String value) { Button b = new Button(this); b.setText(value); b.setAllCaps(false); return b; }
    private Button navButton(String value, View.OnClickListener listener) { Button b = button(value); b.setOnClickListener(listener); return b; }
    private LinearLayout.LayoutParams margins(int l, int t, int r, int b) { LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT); p.setMargins(l, t, r, b); return p; }
    private int dp(int value) { return Math.round(value * getResources().getDisplayMetrics().density); }
}
