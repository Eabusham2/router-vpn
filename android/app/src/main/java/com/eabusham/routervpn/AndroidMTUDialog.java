package com.eabusham.routervpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Handler;
import android.os.Looper;
import android.widget.ScrollView;
import android.widget.TextView;
import org.json.JSONArray;
import org.json.JSONObject;
import java.util.Locale;
import java.util.UUID;

/** Bounded current-session progress; this view never creates a VPN or socket. */
final class AndroidMTUDialog {
    private final Activity activity;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private AlertDialog dialog;
    private TextView text;
    private String session = "", request = "";
    private boolean closed;
    private AndroidMTUDialog(Activity activity) { this.activity = activity; }
    static void show(Activity activity) { new AndroidMTUDialog(activity).open(); }
    private void open() {
        text = new TextView(activity); text.setPadding(32, 24, 32, 24); text.setTextIsSelectable(true);
        ScrollView scroll = new ScrollView(activity); scroll.addView(text);
        dialog = new AlertDialog.Builder(activity).setTitle("Live Auto-MTU / Retest").setView(scroll)
                .setPositiveButton("Retest", null).setNeutralButton("Cancel test", null).setNegativeButton("Close", null).create();
        dialog.setOnShowListener(d -> {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> operate("start"));
            dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener(v -> operate("cancel"));
            refresh();
        });
        dialog.setOnDismissListener(d -> { closed = true; handler.removeCallbacks(poll); });
        dialog.show();
    }
    private final Runnable poll = () -> { if (!closed) refresh(); };
    private void operate(String operation) {
        try {
            if (session.isEmpty()) throw new IllegalStateException("Connect a proved Router VPN path first.");
            if ("start".equals(operation)) request = UUID.randomUUID().toString().replace("-", "");
            render(new JSONObject(LayeredVpnService.mtuRequest(operation, session, request)));
        } catch (Exception error) { text.setText(error.getMessage()); }
    }
    private void disable(String message) {
        text.setText(message);
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(false);
        dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setEnabled(false);
    }
    private void refresh() {
        handler.removeCallbacks(poll);
        try {
            String raw = LayeredVpnService.mtuRequest("status", session, request);
            if (raw.length() > 32768) throw new IllegalStateException("MTU status exceeded its bound.");
            JSONObject result = new JSONObject(raw); String current = result.getString("session_id");
            if (session.isEmpty()) session = current;
            if (!session.equals(current)) { closed = true; disable("VPN session changed. Reopen MTU to test the new path."); return; }
            render(result);
        } catch (Exception error) { disable(error.getMessage()); }
        if (!closed) handler.postDelayed(poll, 500);
    }
    private static double rate(JSONObject transfer) {
        if (transfer == null || transfer.optInt("bytes", 0) != 262144) return Double.NaN;
        double seconds = transfer.optDouble("seconds", Double.NaN), mbps = transfer.optDouble("mbps", Double.NaN);
        if (!Double.isFinite(seconds) || seconds <= 0 || !Double.isFinite(mbps) || mbps <= 0) return Double.NaN;
        return Math.abs(262144.0 * 8 / seconds / 1000000 - mbps) <= Math.max(0.000001, mbps * 0.000001) ? mbps : Double.NaN;
    }
    private static boolean verified(JSONObject row) {
        if (row == null) return false;
        int mtu = row.optInt("mtu", 0), bytes = row.optInt("datagram_bytes", 0);
        double rtt = row.optDouble("median_rtt_ms", Double.NaN);
        return mtu >= 1280 && mtu <= 1500 && row.optBoolean("working", false)
                && row.optInt("packets_sent", 0) == 6 && row.optInt("packets_received", 0) == 6
                && (bytes == mtu - 28 || bytes == mtu - 48) && Double.isFinite(rtt) && rtt >= 0
                && Double.isFinite(rate(row.optJSONObject("download"))) && Double.isFinite(rate(row.optJSONObject("upload")));
    }
    private void render(JSONObject result) {
        boolean running = result.optBoolean("running", false);
        String phase = result.optString("phase", "unavailable"), active = result.optString("request_id", "");
        if (!active.isEmpty()) request = active;
        int effective = result.optInt("effective_mtu", 0), original = result.optInt("original_mtu", 0);
        JSONArray rows = result.optJSONArray("candidates");
        if (rows != null && rows.length() > 5) { disable("Oversized MTU sample set was discarded."); return; }
        boolean verifiedWinner = false;
        if (rows != null) for (int i = 0; i < rows.length(); i++) {
            JSONObject row = rows.optJSONObject(i);
            if (verified(row) && row.optInt("mtu", 0) == effective) verifiedWinner = true;
        }
        StringBuilder message = new StringBuilder("Phase: ").append(phase);
        if (verifiedWinner && result.optBoolean("measured", false) && !running && result.optBoolean("complete", false)
                && "measured-private-system-tun".equals(result.optString("source", "")) && effective >= 1280 && effective <= 1500)
            message.append("\nVerified current MTU: ").append(effective);
        else message.append("\nNo current verified measurement is claimed.");
        if (original >= 1280 && original <= 9000) message.append("\nPre-test MTU: ").append(original);

        if (rows != null) for (int i = 0; i < rows.length(); i++) {
            JSONObject row = rows.optJSONObject(i); if (row == null) continue;
            message.append("\nMTU ").append(row.optInt("mtu", 0)).append(": ");
            double down = rate(row.optJSONObject("download")), up = rate(row.optJSONObject("upload"));
            double rtt = row.optDouble("median_rtt_ms", Double.NaN);
            if (verified(row))
                message.append(String.format(Locale.US, "%.1f↓ / %.1f↑ Mbps; %.2f ms", down, up, rtt));
            else message.append("rejected — ").append(row.optString("failure", "no valid sample"));
        }
        String failure = result.optString("failure", ""); if (!failure.isEmpty()) message.append("\n").append(failure);
        message.append("\n\nAuthenticated packets and private transfers use this OS VPN. Retest can interrupt existing connections while replacing its TUN reader. Cancel restores the pre-test MTU only while the same session and physical path remain valid. Cached sizes must be measured again.");
        text.setText(message.toString());
        boolean available = !"unavailable".equals(phase) && !"invalidated".equals(phase) && !"stopped".equals(phase);
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(!running && available && !result.optBoolean("measurement_hold", false));
        dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setEnabled(running);
    }
}
