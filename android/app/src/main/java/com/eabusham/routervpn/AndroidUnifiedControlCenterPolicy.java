package com.eabusham.routervpn;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Canonical Android policy for the map-first daily VPN control center. */
final class AndroidUnifiedControlCenterPolicy {
    static final String DEFAULT_MODE = "smart-auto";
    static final boolean DEFAULT_IPV6 = true;
    static final String DEFAULT_MTU_POLICY = "auto";
    static final boolean DEFAULT_REQUIRE_ENCRYPTED_AUTO = false;
    static final boolean DEFAULT_REQUIRE_OBFUSCATED_AUTO = false;
    static final boolean AUTHENTICATED_TRANSPORT_ALWAYS_ON = true;
    static final List<String> BOTTOM_SHEET_ORDER = Collections.unmodifiableList(
            Arrays.asList("connection", "multihop", "settings", "mode", "dns"));
    static final List<String> PROFILE_ACTIONS = Collections.unmodifiableList(
            Arrays.asList("create", "load", "update", "delete", "import-router-bundle"));

    // Android product truth: these are encrypted final transports with a real
    // VpnService/native engine in the current app. Do not copy desktop-only
    // OpenVPN/Tor capability into this set.
    static final Set<String> FINAL_ENCRYPTED_TYPES = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "router-vpn", "wireguard", "amneziawg", "shadowsocks", "shadowsocks-2022", "hysteria2")));

    // Plain proxy transports may participate in a graph but are not themselves
    // advertised as authenticated encrypted final transports.
    static final Set<String> BRIDGE_TYPES = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "socks5", "http-connect", "https-connect", "shadowsocks-2022")));

    static final Map<String,String> UNAVAILABLE_TYPES;
    static {
        Map<String,String> unavailable = new HashMap<>();
        unavailable.put("openvpn", "OpenVPN is unavailable on Android until Router VPN ships a pinned native Android OpenVPN VpnService dataplane.");
        unavailable.put("tor-bridge", "Tor bridges are unavailable on Android until Router VPN ships a native Tor + pluggable-transport VpnService dataplane with dynamic Tor-exit proof.");
        UNAVAILABLE_TYPES = Collections.unmodifiableMap(unavailable);
    }

    static final List<String> SECURE_SUITES = Collections.unmodifiableList(Arrays.asList(
            "WireGuard Noise_IK + ChaCha20-Poly1305",
            "AmneziaWG Noise_IK + ChaCha20-Poly1305",
            "HTTPS CONNECT TLS 1.3 with certificate verification",
            "Shadowsocks 2022 BLAKE3 + AEAD",
            "Hysteria2 QUIC + TLS 1.3"));

    static String validatePath(List<String> types) {
        if (types == null || types.isEmpty()) return "Add a node before connecting.";
        String last = types.get(types.size() - 1).toLowerCase();
        String unavailable = UNAVAILABLE_TYPES.get(last);
        if (unavailable != null) return unavailable;
        if (!FINAL_ENCRYPTED_TYPES.contains(last)) {
            return last + " is a bridge only. Add an authenticated encrypted tunnel after it.";
        }
        return "";
    }

    static String handshakeLabel(boolean established) {
        return established ? "Authenticated handshake ✓" : "Authenticated handshake pending";
    }

    private AndroidUnifiedControlCenterPolicy() { }
}
