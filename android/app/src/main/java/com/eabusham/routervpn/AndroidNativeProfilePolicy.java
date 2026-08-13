package com.eabusham.routervpn;

import org.json.JSONArray;
import org.json.JSONObject;

import java.net.InetAddress;
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
                if (inInterface) sawInterface = true;
                dnsWritten = false;
                mtuWritten = false;
                out.add(line);
                continue;
            }
            if (inInterface && startsKey(trimmed, "DNS")) {
                if (!dnsWritten) out.add("DNS = " + dns);
                dnsWritten = true;
                continue;
            }
            if (inInterface && startsKey(trimmed, "MTU")) {
                if (!mtuWritten) out.add("MTU = " + mtu);
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
        if (!isLiteralIp(host)) throw new IllegalStateException("Native Android DNS requires a literal IPv4/IPv6 address; selected value is not an IP.");
        return host;
    }

    static int selectedMtu(JSONObject bundle, int fallback) {
        int base = validMtu(fallback) ? fallback : 1380;
        JSONObject p = selectedProfile(bundle);
        if (p == null) return base;
        String policy = p.optString("mtu_policy", "default").trim().toLowerCase(Locale.ROOT);
        int manual = p.optInt("manual_mtu", 0);
        int effective = p.optInt("effective_mtu", 0);
        if ("manual".equals(policy)) return validMtu(manual) ? manual : base;
        if ("auto".equals(policy)) return validMtu(effective) ? effective : base;
        return base;
    }

    static JSONObject selectedProfile(JSONObject bundle) {
        if (bundle == null) return null;
        JSONArray profiles = bundle.optJSONArray("routerProfiles");
        String wanted = bundle.optString("selectedRouterID", "").trim();
        if (profiles == null) return null;
        for (int i = 0; i < profiles.length(); i++) {
            JSONObject p = profiles.optJSONObject(i);
            if (p != null && wanted.equals(p.optString("id", ""))) return p;
        }
        return profiles.length() > 0 ? profiles.optJSONObject(0) : null;
    }

    private static boolean startsKey(String line, String key) {
        int eq = line.indexOf('=');
        return eq > 0 && key.equalsIgnoreCase(line.substring(0, eq).trim());
    }

    private static boolean validMtu(int mtu) { return mtu >= 1200 && mtu <= 9000; }

    private static String firstNonEmpty(String a, String b) {
        String x = a == null ? "" : a.trim();
        return x.isEmpty() ? (b == null ? "" : b.trim()) : x;
    }

    private static boolean isLiteralIp(String value) {
        if (value == null || value.trim().isEmpty()) return false;
        String v = value.trim();
        try {
            InetAddress parsed = InetAddress.getByName(v);
            if (v.indexOf(':') >= 0) return parsed.getAddress().length == 16;
            return v.matches("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}") && parsed.getAddress().length == 4;
        } catch (Exception invalid) {
            return false;
        }
    }
}
