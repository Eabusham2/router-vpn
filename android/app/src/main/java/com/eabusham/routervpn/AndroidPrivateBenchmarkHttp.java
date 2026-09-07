package com.eabusham.routervpn;

import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URI;
import java.net.URL;

/** Authenticated private benchmarks must stay on their exact loopback hop lane. */
final class AndroidPrivateBenchmarkHttp {
    private static final int MAX_BYTES = 16 << 20;

    private AndroidPrivateBenchmarkHttp() {}

    static String requireBase(String input) throws Exception {
        String value = input == null ? "" : input.trim();
        if (value.isEmpty() || value.length() > 4096) {
            throw new IllegalArgumentException("A private Router VPN benchmark API is required.");
        }
        URI uri = new URI(value);
        String path = uri.getRawPath();
        if (!"http".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
                || uri.getRawUserInfo() != null || uri.getRawQuery() != null
                || uri.getRawFragment() != null
                || (path != null && !path.isEmpty() && !"/".equals(path))
                || uri.getPort() == 0 || uri.getPort() > 65535
                || uri.getRawAuthority().endsWith(":")) {
            throw new IllegalArgumentException("Hop benchmarks require a private HTTP API origin without credentials, path, query or fragment.");
        }
        // No hostname lookup is allowed before the selected hop is reached.
        InetAddress address = AndroidNumericAddress.parse(uri.getHost());
        byte[] bytes = address.getAddress();
        boolean ula = bytes.length == 16 && (bytes[0] & 0xfe) == 0xfc;
        if (address.isAnyLocalAddress() || address.isMulticastAddress()
                || !(address.isLoopbackAddress() || address.isLinkLocalAddress()
                || address.isSiteLocalAddress() || ula)) {
            throw new IllegalArgumentException("Hop benchmarks refuse to send node credentials to a public address.");
        }
        return new URI("http", null, address.getHostAddress(), uri.getPort(), null, null, null).toASCIIString();
    }

    static HttpURLConnection open(String base, String route, String token, String method,
                                  int timeout, int proofPort) throws Exception {
        if (proofPort != 1098 && proofPort != 1099) {
            throw new IllegalArgumentException("Speed Lab requires a reserved multihop proof lane.");
        }
        if (timeout <= 0 || timeout > 30000) {
            throw new IllegalArgumentException("Hop benchmark timeout must be bounded.");
        }
        requireRoute(route, method);
        if (token == null || token.trim().isEmpty() || token.length() > 4096) {
            throw new IllegalArgumentException("A bounded private node token is required.");
        }
        for (int i = 0; i < token.length(); i++) {
            if (token.charAt(i) < 0x20 || token.charAt(i) == 0x7f) {
                throw new IllegalArgumentException("Node token contains a header control character.");
            }
        }
        URL target = new URL(requireBase(base) + route);
        Proxy lane = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", proofPort));
        HttpURLConnection connection = (HttpURLConnection) target.openConnection(lane);
        try {
            connection.setConnectTimeout(Math.min(timeout, 3000));
            connection.setReadTimeout(timeout);
            connection.setInstanceFollowRedirects(false);
            connection.setUseCaches(false);
            connection.setRequestMethod(method);
            connection.setRequestProperty("Authorization", "Bearer " + token);
            connection.setRequestProperty("Cache-Control", "no-store");
            connection.setRequestProperty("Accept-Encoding", "identity");
            return connection;
        } catch (Exception error) {
            connection.disconnect();
            throw error;
        }
    }

    private static void requireRoute(String route, String method) {
        if ("GET".equals(method) && "/health".equals(route)) return;
        if ("POST".equals(method) && "/api/benchmark/upload".equals(route)) return;
        String prefix = "/api/benchmark/download?bytes=";
        if ("GET".equals(method) && route != null && route.startsWith(prefix)) {
            String size = route.substring(prefix.length());
            if (size.matches("[1-9][0-9]{0,7}")) {
                int bytes = Integer.parseInt(size);
                if (bytes <= MAX_BYTES) return;
            }
        }
        throw new IllegalArgumentException("Only bounded private health/download/upload routes are allowed.");
    }
}
