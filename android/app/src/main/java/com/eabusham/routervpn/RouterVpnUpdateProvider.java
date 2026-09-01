package com.eabusham.routervpn;

import android.Manifest;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * Startup-safe exact-SHA update check.
 *
 * Android deliberately retains installation ownership: Router VPN may discover
 * an immutable exact-SHA APK and notify the user, but it never silently grants
 * itself REQUEST_INSTALL_PACKAGES or bypasses Android's install confirmation.
 */
public final class RouterVpnUpdateProvider extends ContentProvider {
    private static final String REPOSITORY = "Eabusham2/router-vpn";
    private static final String TAG_PREFIX = "router-vpn-sha-";
    private static final String CHANNEL = "router_vpn_updates";
    private static final int MAX_METADATA = 1024 * 1024;

    @Override
    public boolean onCreate() {
        Context context = getContext();
        if (context != null) {
            Thread worker = new Thread(() -> check(context.getApplicationContext()), "router-vpn-update-check");
            worker.setDaemon(true);
            worker.start();
        }
        return true;
    }

    private static void check(Context context) {
        try {
            String current = sourceSha(context);
            if (!validSha(current)) return;
            JSONObject release = newestExactRelease();
            if (release == null) return;
            String tag = release.optString("tag_name", "").toLowerCase(Locale.ROOT);
            String target = tag.startsWith(TAG_PREFIX) ? tag.substring(TAG_PREFIX.length()) : "";
            if (!validSha(target) || current.equals(target)) return;
            if (!target.equals(release.optString("target_commitish", "").toLowerCase(Locale.ROOT))) return;
            String apkUrl = null;
            JSONArray assets = release.optJSONArray("assets");
            if (assets == null) return;
            int copies = 0;
            for (int i = 0; i < assets.length(); i++) {
                JSONObject asset = assets.optJSONObject(i);
                if (asset != null && "app-debug.apk".equals(asset.optString("name"))) {
                    copies++;
                    String candidate = asset.optString("browser_download_url", "");
                    Uri uri = Uri.parse(candidate);
                    if ("https".equalsIgnoreCase(uri.getScheme()) && "github.com".equalsIgnoreCase(uri.getHost())) {
                        apkUrl = candidate;
                    }
                }
            }
            if (copies != 1 || apkUrl == null) return;
            context.getSharedPreferences("router_vpn_updates", Context.MODE_PRIVATE)
                    .edit().putString("available_sha", target).putString("apk_url", apkUrl).apply();
            notifyUpdate(context, target, apkUrl);
        } catch (Exception ignored) {
            // An update check must never interfere with VPN startup.
        }
    }

    private static String sourceSha(Context context) throws Exception {
        try (InputStream input = context.getAssets().open("ROUTER-VPN-SOURCE.json")) {
            JSONObject manifest = new JSONObject(new String(readLimited(input), StandardCharsets.UTF_8));
            if (!REPOSITORY.equals(manifest.optString("repository"))) return "";
            return manifest.optString("source_sha", "").toLowerCase(Locale.ROOT);
        }
    }

    private static JSONObject newestExactRelease() throws Exception {
        URL url = new URL("https://api.github.com/repos/" + REPOSITORY + "/releases?per_page=50");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(8000);
        connection.setInstanceFollowRedirects(false);
        connection.setRequestProperty("Accept", "application/vnd.github+json");
        connection.setRequestProperty("User-Agent", "router-vpn-android-update/1");
        try {
            if (connection.getResponseCode() / 100 != 2) return null;
            JSONArray releases = new JSONArray(new String(readLimited(connection.getInputStream()), StandardCharsets.UTF_8));
            for (int i = 0; i < releases.length(); i++) {
                JSONObject release = releases.optJSONObject(i);
                if (release == null || release.optBoolean("draft") || release.optBoolean("prerelease")) continue;
                String tag = release.optString("tag_name", "").toLowerCase(Locale.ROOT);
                String sha = tag.startsWith(TAG_PREFIX) ? tag.substring(TAG_PREFIX.length()) : "";
                if (validSha(sha) && sha.equals(release.optString("target_commitish", "").toLowerCase(Locale.ROOT))) {
                    return release;
                }
            }
            return null;
        } finally {
            connection.disconnect();
        }
    }

    private static byte[] readLimited(InputStream input) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int total = 0;
        while (true) {
            int read = input.read(buffer);
            if (read < 0) break;
            total += read;
            if (total > MAX_METADATA) throw new IllegalStateException("update metadata too large");
            output.write(buffer, 0, read);
        }
        return output.toByteArray();
    }

    private static boolean validSha(String value) {
        return value != null && value.matches("[0-9a-f]{40}");
    }

    private static void notifyUpdate(Context context, String sha, String apkUrl) {
        NotificationManager manager = context.getSystemService(NotificationManager.class);
        if (manager == null) return;
        if (Build.VERSION.SDK_INT >= 33 && context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            return;
        }
        if (Build.VERSION.SDK_INT >= 26) {
            manager.createNotificationChannel(new NotificationChannel(CHANNEL, "Router VPN updates", NotificationManager.IMPORTANCE_DEFAULT));
        }
        Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(apkUrl));
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        PendingIntent pending = PendingIntent.getActivity(context, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        android.app.Notification notification = new android.app.Notification.Builder(context, CHANNEL)
                .setSmallIcon(android.R.drawable.stat_sys_download_done)
                .setContentTitle("Router VPN update available")
                .setContentText("Verified exact release " + sha.substring(0, 12) + " is ready. Android will confirm installation.")
                .setContentIntent(pending)
                .setAutoCancel(true)
                .build();
        manager.notify(0x5256504e, notification);
    }

    @Override public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) { return null; }
    @Override public String getType(Uri uri) { return null; }
    @Override public Uri insert(Uri uri, ContentValues values) { return null; }
    @Override public int delete(Uri uri, String selection, String[] selectionArgs) { return 0; }
    @Override public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) { return 0; }
}
