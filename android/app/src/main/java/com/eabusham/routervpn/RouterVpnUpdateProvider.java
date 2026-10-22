package com.eabusham.routervpn;

import android.Manifest;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.ArrayList;
import java.util.List;

/**
 * Startup-safe exact-SHA update check.
 *
 * Android deliberately retains installation ownership: Router VPN verifies the
 * immutable exact-SHA release identity and published APK digest metadata, then
 * notifies the user. It never grants itself REQUEST_INSTALL_PACKAGES, silently
 * replaces its APK, or bypasses Android's package-signature confirmation.
 */
public final class RouterVpnUpdateProvider extends ContentProvider {
    private static final String REPOSITORY = "Eabusham2/router-vpn";
    private static final String TAG_PREFIX = "router-vpn-sha-";
    private static final String RELEASE_MANIFEST = "RouterVPN-RELEASE.json";
    private static final String APK_ASSET = "app-debug.apk";
    private static final String PRODUCER = "build-all.yml";
    private static final String CHANNEL = "router_vpn_updates";
    private static final int MAX_METADATA = 1024 * 1024;
    private static final long MAX_APK_BYTES = 768L * 1024L * 1024L;
    private static final Object CHECK_LOCK = new Object();
    private static final List<Runnable> CHECK_LISTENERS = new ArrayList<>();
    private static boolean checking;

    private static final class VerifiedUpdate {
        final String target;
        final String apkUrl;
        final long apkSize;
        final String apkSha256;

        VerifiedUpdate(String target, String apkUrl, long apkSize, String apkSha256) {
            this.target = target;
            this.apkUrl = apkUrl;
            this.apkSize = apkSize;
            this.apkSha256 = apkSha256;
        }
    }

    @Override
    public boolean onCreate() {
        Context context = getContext();
        if (context != null) requestCheck(context, null);
        return true;
    }

    static void requestCheck(Context context, Runnable completed) {
        Context app = context.getApplicationContext();
        synchronized (CHECK_LOCK) {
            if (completed != null) CHECK_LISTENERS.add(completed);
            if (checking) return;
            checking = true;
        }
        Thread worker = new Thread(() -> {
            try { check(app); }
            finally {
                List<Runnable> listeners;
                synchronized (CHECK_LOCK) {
                    checking = false;
                    listeners = new ArrayList<>(CHECK_LISTENERS);
                    CHECK_LISTENERS.clear();
                }
                for (Runnable listener : listeners) { try { listener.run(); } catch (RuntimeException ignored) { } }
            }
        }, "router-vpn-update-check");
        worker.setDaemon(true);
        worker.start();
    }

    static boolean isChecking() { synchronized (CHECK_LOCK) { return checking; } }

    static String installedSource(Context context) {
        try { String value=sourceSha(context);return validSha(value)?value:"unverified development build"; }
        catch (Exception missing) { return "source manifest unavailable"; }
    }

    static AndroidUpdateSnapshot availableUpdate(Context context) {
        try {
            SharedPreferences p=context.getSharedPreferences("router_vpn_updates",Context.MODE_PRIVATE);
            return AndroidUpdateSnapshot.verified(installedSource(context),p.getString("checked_from_sha",""),
                    p.getString("available_sha",""),p.getString("apk_url",""),p.getLong("apk_size",0),
                    p.getString("apk_sha256",""),p.getLong("verified_at_ms",0),
                    p.getBoolean("release_manifest_verified",false),System.currentTimeMillis());
        } catch (RuntimeException malformed) { return null; }
    }

    static String checkMessage(Context context) {
        try {
            return context.getSharedPreferences("router_vpn_updates",Context.MODE_PRIVATE)
                    .getString("check_message","An update check starts when the app opens. You can also check here.");
        } catch (RuntimeException malformed) { return "Check again to refresh update status."; }
    }

    static void notifyAvailableUpdate(Context context) {
        AndroidUpdateSnapshot update=availableUpdate(context);
        if(update!=null)notifyUpdate(context,new VerifiedUpdate(update.target,update.apkURL,update.apkBytes,update.apkDigest));
    }

    private static void check(Context context) {
        try {
            String current = sourceSha(context);
            if (!validSha(current)) throw new IllegalStateException("This build has no exact source manifest; install a published generic package to use updates.");
            VerifiedUpdate update = newestVerifiedUpdate(current);
            if (update == null) {
                context.getSharedPreferences("router_vpn_updates",Context.MODE_PRIVATE).edit()
                        .remove("available_sha").remove("apk_url").remove("apk_size").remove("apk_sha256")
                        .remove("verified_at_ms").putBoolean("release_manifest_verified",false)
                        .putString("checked_from_sha",current)
                        .putString("check_message","No newer exact-source release with valid APK metadata is available.").apply();
                return;
            }
            context.getSharedPreferences("router_vpn_updates", Context.MODE_PRIVATE)
                    .edit()
                    .putString("checked_from_sha",current)
                    .putLong("verified_at_ms",System.currentTimeMillis())
                    .putString("available_sha", update.target)
                    .putString("apk_url", update.apkUrl)
                    .putLong("apk_size", update.apkSize)
                    .putString("apk_sha256", update.apkSha256)
                    .putBoolean("release_manifest_verified", true)
                    .putString("check_message","A newer exact-source APK has verified published digest metadata.")
                    .apply();
            notifyAvailableUpdate(context);
        } catch (Exception error) {
            // Update discovery must never interfere with VPN startup.
            context.getSharedPreferences("router_vpn_updates",Context.MODE_PRIVATE).edit()
                    .putString("check_message","Update check unavailable. Retry when GitHub is reachable; previously verified metadata may still be shown.").apply();
        }
    }

    private static VerifiedUpdate newestVerifiedUpdate(String current) throws Exception {
        JSONObject release = newestExactRelease();
        if (release == null) return null;
        String tag = release.optString("tag_name", "").toLowerCase(Locale.ROOT);
        String target = tag.startsWith(TAG_PREFIX) ? tag.substring(TAG_PREFIX.length()) : "";
        if (!validSha(target) || current.equals(target)) return null;
        if (!target.equals(release.optString("target_commitish", "").toLowerCase(Locale.ROOT))) return null;
        if (!strictUpgrade(current, target)) return null;

        JSONObject manifestAsset = uniqueReleaseAsset(release, RELEASE_MANIFEST, MAX_METADATA);
        JSONObject apkAsset = uniqueReleaseAsset(release, APK_ASSET, MAX_APK_BYTES);
        if (manifestAsset == null || apkAsset == null) return null;
        String releaseRoot = "https://github.com/" + REPOSITORY + "/releases/download/" + TAG_PREFIX + target + "/";
        if (!(releaseRoot + RELEASE_MANIFEST).equals(manifestAsset.optString("browser_download_url", ""))
                || !(releaseRoot + APK_ASSET).equals(apkAsset.optString("browser_download_url", ""))) return null;
        byte[] manifestBytes = downloadTrustedReleaseAsset(
                manifestAsset.optString("browser_download_url", ""), MAX_METADATA);
        JSONObject manifest = parseObject(manifestBytes);
        if (manifest.optInt("schema_version", 0) != 1
                || !REPOSITORY.equals(manifest.optString("repository", ""))
                || !target.equals(manifest.optString("source_sha", "").toLowerCase(Locale.ROOT))
                || !(TAG_PREFIX + target).equals(manifest.optString("tag", "").toLowerCase(Locale.ROOT))
                || !PRODUCER.equals(manifest.optString("producer_workflow", ""))) {
            return null;
        }

        JSONArray published = manifest.optJSONArray("assets");
        if (published == null) return null;
        int copies = 0;
        long signedSize = 0;
        String signedDigest = "";
        for (int i = 0; i < published.length(); i++) {
            JSONObject item = published.optJSONObject(i);
            if (item != null && APK_ASSET.equals(item.optString("name", ""))) {
                copies++;
                signedSize = item.optLong("size", 0);
                signedDigest = item.optString("sha256", "").toLowerCase(Locale.ROOT);
            }
        }
        long apiSize = apkAsset.optLong("size", 0);
        String apkUrl = apkAsset.optString("browser_download_url", "");
        if (copies != 1 || signedSize <= 0 || signedSize > MAX_APK_BYTES
                || apiSize != signedSize || !validDigest(signedDigest)
                || !trustedReleaseAssetUrl(new URL(apkUrl))) {
            return null;
        }
        return new VerifiedUpdate(target, apkUrl, signedSize, signedDigest);
    }

    private static String sourceSha(Context context) throws Exception {
        try (InputStream input = context.getAssets().open("ROUTER-VPN-SOURCE.json")) {
            JSONObject manifest = parseObject(readLimited(input, MAX_METADATA));
            if (!REPOSITORY.equals(manifest.optString("repository"))) return "";
            return manifest.optString("source_sha", "").toLowerCase(Locale.ROOT);
        }
    }

    private static JSONObject newestExactRelease() throws Exception {
        URL url = new URL("https://api.github.com/repos/" + REPOSITORY + "/releases?per_page=50");
        JSONArray releases = parseArray(downloadApi(url));
        for (int i = 0; i < releases.length(); i++) {
            JSONObject release = releases.optJSONObject(i);
            // Build-all publishes exact-SHA mobile artifacts as prereleases only
            // after the authoritative release matrix passes. Drafts remain forbidden.
            if (release == null || release.optBoolean("draft")) continue;
            String tag = release.optString("tag_name", "").toLowerCase(Locale.ROOT);
            String sha = tag.startsWith(TAG_PREFIX) ? tag.substring(TAG_PREFIX.length()) : "";
            if (validSha(sha) && sha.equals(release.optString("target_commitish", "").toLowerCase(Locale.ROOT))) {
                return release;
            }
        }
        return null;
    }

    private static boolean strictUpgrade(String current, String target) throws Exception {
        URL url = new URL("https://api.github.com/repos/" + REPOSITORY + "/compare/" + current + "..." + target);
        JSONObject comparison = parseObject(downloadApi(url));
        JSONObject base = comparison.optJSONObject("base_commit");
        JSONObject mergeBase = comparison.optJSONObject("merge_base_commit");
        return "ahead".equalsIgnoreCase(comparison.optString("status", ""))
                && comparison.optInt("ahead_by", 0) > 0
                && comparison.optInt("behind_by", -1) == 0
                && base != null && current.equalsIgnoreCase(base.optString("sha", ""))
                && mergeBase != null && current.equalsIgnoreCase(mergeBase.optString("sha", ""));
    }

    private static JSONObject uniqueReleaseAsset(JSONObject release, String name, long maximum) {
        JSONArray assets = release.optJSONArray("assets");
        if (assets == null) return null;
        JSONObject found = null;
        int copies = 0;
        for (int i = 0; i < assets.length(); i++) {
            JSONObject item = assets.optJSONObject(i);
            if (item != null && name.equals(item.optString("name", ""))) {
                copies++;
                long size = item.optLong("size", 0);
                String rawUrl = item.optString("browser_download_url", "");
                try {
                    if (size <= 0 || size > maximum || !trustedReleaseAssetUrl(new URL(rawUrl))) return null;
                } catch (Exception error) {
                    return null;
                }
                found = item;
            }
        }
        return copies == 1 ? found : null;
    }

    private static byte[] downloadApi(URL url) throws Exception {
        if (!"https".equalsIgnoreCase(url.getProtocol()) || !"api.github.com".equalsIgnoreCase(url.getHost())
                || url.getUserInfo() != null) throw new IllegalStateException("untrusted GitHub API URL");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(8000);
        connection.setInstanceFollowRedirects(false);
        connection.setRequestProperty("Accept", "application/vnd.github+json");
        connection.setRequestProperty("User-Agent", "router-vpn-android-update/2");
        connection.setRequestProperty("X-GitHub-Api-Version", "2022-11-28");
        try {
            if (connection.getResponseCode() / 100 != 2) throw new IllegalStateException("GitHub API request failed");
            try (InputStream input = connection.getInputStream()) {
                return readLimited(input, MAX_METADATA);
            }
        } finally {
            connection.disconnect();
        }
    }

    private static byte[] downloadTrustedReleaseAsset(String rawUrl, int maximum) throws Exception {
        URL current = new URL(rawUrl);
        for (int redirects = 0; redirects <= 8; redirects++) {
            if (!trustedReleaseAssetUrl(current)) throw new IllegalStateException("untrusted release asset URL");
            HttpURLConnection connection = (HttpURLConnection) current.openConnection();
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(10000);
            connection.setInstanceFollowRedirects(false);
            connection.setRequestProperty("Accept", "application/octet-stream");
            connection.setRequestProperty("Accept-Encoding", "identity");
            connection.setRequestProperty("User-Agent", "router-vpn-android-update/2");
            try {
                int status = connection.getResponseCode();
                if (status >= 300 && status < 400) {
                    String location = connection.getHeaderField("Location");
                    if (location == null || location.isEmpty()) throw new IllegalStateException("release redirect is missing Location");
                    current = new URL(current, location);
                    continue;
                }
                if (status / 100 != 2) throw new IllegalStateException("release asset request failed");
                long length = connection.getContentLengthLong();
                if (length > maximum) throw new IllegalStateException("release metadata is oversized");
                try (InputStream input = connection.getInputStream()) {
                    return readLimited(input, maximum);
                }
            } finally {
                connection.disconnect();
            }
        }
        throw new IllegalStateException("too many release asset redirects");
    }

    private static boolean trustedReleaseAssetUrl(URL url) {
        if (!"https".equalsIgnoreCase(url.getProtocol()) || url.getUserInfo() != null
                || (url.getPort() != -1 && url.getPort() != 443) || url.getRef() != null) return false;
        String host = url.getHost().toLowerCase(Locale.ROOT);
        return "github.com".equals(host) || "release-assets.githubusercontent.com".equals(host)
                || host.endsWith(".githubusercontent.com");
    }

    private static JSONObject parseObject(byte[] data) throws Exception {
        JSONTokener tokener = new JSONTokener(new String(data, StandardCharsets.UTF_8));
        Object value = tokener.nextValue();
        if (!(value instanceof JSONObject) || tokener.nextClean() != 0) {
            throw new IllegalStateException("expected exactly one JSON object");
        }
        return (JSONObject) value;
    }

    private static JSONArray parseArray(byte[] data) throws Exception {
        JSONTokener tokener = new JSONTokener(new String(data, StandardCharsets.UTF_8));
        Object value = tokener.nextValue();
        if (!(value instanceof JSONArray) || tokener.nextClean() != 0) {
            throw new IllegalStateException("expected exactly one JSON array");
        }
        return (JSONArray) value;
    }

    private static byte[] readLimited(InputStream input, int maximum) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int total = 0;
        while (true) {
            int read = input.read(buffer);
            if (read < 0) break;
            total += read;
            if (total > maximum) throw new IllegalStateException("update metadata too large");
            output.write(buffer, 0, read);
        }
        if (total == 0) throw new IllegalStateException("update metadata is empty");
        return output.toByteArray();
    }

    private static boolean validSha(String value) {
        return value != null && value.matches("[0-9a-f]{40}");
    }

    private static boolean validDigest(String value) {
        return value != null && value.matches("[0-9a-f]{64}");
    }

    private static void notifyUpdate(Context context, VerifiedUpdate update) {
        NotificationManager manager = context.getSystemService(NotificationManager.class);
        if (manager == null) return;
        if (Build.VERSION.SDK_INT >= 33 && context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            return;
        }
        if (Build.VERSION.SDK_INT >= 26) {
            manager.createNotificationChannel(new NotificationChannel(CHANNEL, "Router VPN updates", NotificationManager.IMPORTANCE_DEFAULT));
        }
        Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(update.apkUrl));
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        PendingIntent pending = PendingIntent.getActivity(context, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        android.app.Notification.Builder builder = Build.VERSION.SDK_INT >= 26
                ? new android.app.Notification.Builder(context, CHANNEL) : new android.app.Notification.Builder(context);
        android.app.Notification notification = builder
                .setSmallIcon(android.R.drawable.stat_sys_download_done)
                .setContentTitle("Router VPN update available")
                .setContentText("Exact release " + update.target.substring(0, 12) + " has verified published APK digest metadata. Android will confirm installation.")
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
