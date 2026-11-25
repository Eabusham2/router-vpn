package com.eabusham.routervpn;

import java.net.IDN;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

final class AndroidDNSResolverCatalog {
    private AndroidDNSResolverCatalog() {}

    static final class ResolverPreset {
        final String name, host, serverName;
        ResolverPreset(String name, String host, String serverName) { this.name=name; this.host=host; this.serverName=serverName; }
        @Override public String toString(){ return name + " — " + host; }
    }
    static final List<ResolverPreset> PRESETS = Collections.unmodifiableList(Arrays.asList(
            new ResolverPreset("Cloudflare IPv4","1.1.1.1","cloudflare-dns.com"),
            new ResolverPreset("Cloudflare IPv4 secondary","1.0.0.1","cloudflare-dns.com"),
            new ResolverPreset("Cloudflare IPv6","2606:4700:4700::1111","cloudflare-dns.com"),
            new ResolverPreset("Cloudflare IPv6 secondary","2606:4700:4700::1001","cloudflare-dns.com"),
            new ResolverPreset("Google IPv4","8.8.8.8","dns.google"),
            new ResolverPreset("Google IPv4 secondary","8.8.4.4","dns.google"),
            new ResolverPreset("Google IPv6","2001:4860:4860::8888","dns.google"),
            new ResolverPreset("Google IPv6 secondary","2001:4860:4860::8844","dns.google"),
            new ResolverPreset("Quad9 IPv4","9.9.9.9","dns.quad9.net"),
            new ResolverPreset("Quad9 IPv4 secondary","149.112.112.112","dns.quad9.net"),
            new ResolverPreset("Quad9 IPv6","2620:fe::fe","dns.quad9.net"),
            new ResolverPreset("Quad9 IPv6 secondary","2620:fe::9","dns.quad9.net")
    ));

    private static final Pattern DNS_NAME = Pattern.compile(
            "[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\\.?");

    private static boolean hostname(String value) {
        try {
            String ascii = IDN.toASCII(value, IDN.USE_STD3_ASCII_RULES);
            return ascii.length() <= 253 && DNS_NAME.matcher(ascii).matches() && ascii.matches(".*[A-Za-z].*");
        } catch (IllegalArgumentException invalid) {
            return false;
        }
    }

    static String tlsServerName(String host, String configured) {
        if (!configured.isEmpty()) {
            if (hostname(configured)) return configured;
            throw new IllegalArgumentException("Encrypted DNS requires a TLS certificate hostname.");
        }
        if (hostname(host)) return host;
        String address;
        try { address = AndroidNumericAddress.canonical(host); }
        catch (Exception invalid) { throw new IllegalArgumentException("DNS requires a resolver hostname or a literal IP address."); }
        for (ResolverPreset resolver : PRESETS) {
            if (resolver.host.equals(address)) return resolver.serverName;
        }
        throw new IllegalArgumentException("Encrypted DNS to an IP requires a TLS server name.");
    }
}
