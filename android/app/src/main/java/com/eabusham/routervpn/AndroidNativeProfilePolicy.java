package com.eabusham.routervpn;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Shared, fail-closed projection of router-profile DNS/MTU intent into native Android backends. */
final class AndroidNativeProfilePolicy {
    private AndroidNativeProfilePolicy() {}

    static String patchWireGuardLikeConfig(JSONObject bundle, String config, int fallbackMtu) throws Exception {
        if (config == null || config.length() == 0 || config.length() > 512 * 1024) {
            throw new IllegalStateException("Native tunnel config size is invalid.");
        }
        if (requiresLibbox(bundle)) throw new IllegalStateException("This saved policy requires the native Libbox WireGuard path; the address-only backend cannot silently ignore it.");
        String dns = selectedPlainUdpDns(bundle);
        int mtu = selectedMtu(bundle, fallbackMtu);
        String normalized = config.replace("\r\n", "\n").replace('\r', '\n');
        String[] lines = normalized.split("\n", -1);
        List<String> out = new ArrayList<>();
        boolean inInterface = false;
        boolean dnsWritten = false;
        boolean mtuWritten = false;
        boolean sawInterface = false;
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
                if (inInterface) {
                    if (!dnsWritten) out.add("DNS = " + dns);
                    if (!mtuWritten) out.add("MTU = " + mtu);
                }
                inInterface = "[Interface]".equalsIgnoreCase(trimmed);
                if (inInterface) {
                    if (sawInterface) throw new IllegalStateException("Multiple native interfaces make policy ownership ambiguous.");
                    sawInterface = true;
                }
                dnsWritten = false;
                mtuWritten = false;
                out.add(line);
                continue;
            }
            if (inInterface && startsKey(trimmed, "DNS")) {
                if (dnsWritten) throw new IllegalStateException("Duplicate native DNS fields are ambiguous.");
                out.add("DNS = " + dns);
                dnsWritten = true;
                continue;
            }
            if (inInterface && startsKey(trimmed, "MTU")) {
                if (mtuWritten) throw new IllegalStateException("Duplicate native MTU fields are ambiguous.");
                out.add("MTU = " + mtu);
                mtuWritten = true;
                continue;
            }
            out.add(line);
        }
        if (!sawInterface) throw new IllegalStateException("Native tunnel config has no [Interface] section.");
        if (inInterface) {
            if (!dnsWritten) out.add("DNS = " + dns);
            if (!mtuWritten) out.add("MTU = " + mtu);
        }
        return String.join("\n", out);
    }

    static String selectedPlainUdpDns(JSONObject bundle) throws Exception {
        JSONObject p = selectedProfile(bundle);
        if (p == null) throw new IllegalStateException("Node bundle has no selected router profile.");
        String mode = p.optString("dns_mode", "home").trim().toLowerCase(Locale.ROOT);
        if (mode.isEmpty()) mode = "home";
        String protocol = p.optString("dns_protocol", "udp").trim().toLowerCase(Locale.ROOT);
        if (protocol.isEmpty()) protocol = "udp";
        String host;
        if ("home".equals(mode)) {
            host = firstNonEmpty(p.optString("adguard_ipv4", ""), p.optString("adguard_ipv6", ""));
            protocol = "udp";
        } else if ("fastest".equals(mode)) {
            host = p.optString("fastest_dns_host", "").trim();
            protocol = "udp";
        } else if ("custom".equals(mode)) {
            host = p.optString("dns_host", "").trim();
        } else {
            throw new IllegalStateException("Selected DNS mode '" + mode + "' requires an encrypted/transport-aware resolver. Use an embedded libbox mode on Android; native WG/AWG/Xray address-only DNS would not enforce that protocol.");
        }
        if (!"udp".equals(protocol)) {
            throw new IllegalStateException("Selected DNS protocol '" + protocol + "' cannot be enforced by Android's address-only native VPN DNS API. Use an embedded libbox mode instead of silently downgrading DNS transport.");
        }
        if ("custom".equals(mode) && exactInteger(p, "dns_port", 53, 1, 65535) != 53) {
            throw new IllegalStateException("Native address-only DNS cannot enforce a custom port; use Libbox.");
        }
        if (!isLiteralIp(host)) throw new IllegalStateException("Native Android DNS requires a literal IPv4/IPv6 address; selected value is not an IP.");
        return host;
    }

    static int selectedMtu(JSONObject bundle, int fallback) {
        int base = validMtu(fallback) ? fallback : 1380;
        JSONObject p = selectedProfile(bundle);
        String policy = stringPolicy(p, "mtu_policy", "auto");
        if ("manual".equals(policy) || "fixed".equals(policy)) {
            return exactInteger(p, "manual_mtu", 0, 1280, 9000);
        }
        if ("auto".equals(policy) || "default".equals(policy) || policy.isEmpty()) {
            // A saved effective_mtu without a fresh path/config identity is not
            // a measurement of this session. Keep only the runtime default.
            return base;
        }
        throw new IllegalStateException("Unknown native MTU policy; it was not silently ignored.");
    }

    static JSONObject selectedProfile(JSONObject bundle) {
        return AndroidProfileSelection.selectedRouterProfile(bundle);
    }

    static boolean requiresLibbox(JSONObject bundle) throws Exception {
        JSONObject profile = selectedProfile(bundle);
        String ipv6 = stringPolicy(profile, "ipv6_mode", "on");
        if (!java.util.Arrays.asList("", "on", "auto", "off").contains(ipv6)) throw new IllegalStateException("Unknown IPv6 policy.");
        if ("off".equals(ipv6) || !booleanPolicy(profile, "home_lan_access", true)
                || booleanPolicy(profile, "daita_enabled", false) || booleanPolicy(profile, "jumbo_tun", false)) return true;
        try { selectedPlainUdpDns(bundle); return false; }
        catch (IllegalStateException needsTransport) { return true; }
    }

    static String stringPolicy(JSONObject profile, String key, String fallback) {
        Object raw = profile.opt(key);
        if (raw == null) return fallback;
        if (!(raw instanceof String)) throw new IllegalStateException(key + " must be a string.");
        return ((String) raw).trim().toLowerCase(Locale.ROOT);
    }

    static boolean booleanPolicy(JSONObject profile, String key, boolean fallback) {
        Object raw = profile.opt(key);
        if (raw == null) return fallback;
        if (!(raw instanceof Boolean)) throw new IllegalStateException(key + " must be a boolean.");
        return (Boolean) raw;
    }

    static int exactInteger(JSONObject profile, String key, int fallback, int min, int max) {
        Object raw = profile.opt(key);
        if (raw == null) raw = fallback;
        if (!(raw instanceof Number)) throw new IllegalStateException(key + " must be an exact integer.");
        double value = ((Number) raw).doubleValue();
        if (!Double.isFinite(value) || value != Math.rint(value) || value < min || value > max) {
            throw new IllegalStateException(key + " is outside the supported range " + min + "–" + max + ".");
        }
        return (int) value;
    }

    private static boolean startsKey(String line, String key) {
        int eq = line.indexOf('=');
        return eq > 0 && key.equalsIgnoreCase(line.substring(0, eq).trim());
    }

    private static boolean validMtu(int mtu) { return mtu >= 1280 && mtu <= 9000; }

    private static String firstNonEmpty(String a, String b) {
        String x = a == null ? "" : a.trim();
        return x.isEmpty() ? (b == null ? "" : b.trim()) : x;
    }

    private static boolean isLiteralIp(String value) {
        try { return value != null && AndroidNumericAddress.parse(value) != null; }
        catch (Exception invalid) { return false; }
    }
}
