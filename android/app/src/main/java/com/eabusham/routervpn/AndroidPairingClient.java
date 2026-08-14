package com.eabusham.routervpn;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * Redeems the Setup Center's short-lived LAN pairing code without enabling
 * Android-wide cleartext HTTP. The destination must resolve only to private,
 * loopback, link-local, or IPv6 ULA addresses and the response is size-bounded.
 */
final class AndroidPairingClient {
    interface Callback {
        void finished(byte[] bundle, Exception error);
    }

    private static final int PORT = 8786;
    private static final int MAX_HEADER = 64 * 1024;
    private static final int MAX_BUNDLE = AndroidNodeStore.MAX_BUNDLE;

    private AndroidPairingClient() {}

    static void redeem(String rawHost, String rawCode, Callback callback) {
        new Thread(() -> {
            try { callback.finished(redeemBlocking(rawHost, rawCode), null); }
            catch (Exception error) { callback.finished(null, error); }
        }, "routervpn-pairing").start();
    }

    static byte[] redeemBlocking(String rawHost, String rawCode) throws Exception {
        String host = normalizeHost(rawHost);
        String code = rawCode == null ? "" : rawCode.trim();
        if (!code.matches("^[0-9]{6}$")) throw new IllegalArgumentException("Enter the 6-digit one-time Setup Center pairing code");

        InetAddress[] addresses = InetAddress.getAllByName(host);
        if (addresses.length == 0) throw new IllegalArgumentException("Pairing host did not resolve");
        for (InetAddress address : addresses) {
            if (!isPrivate(address)) throw new SecurityException("LAN pairing host resolved outside the private/local network");
        }

        InetAddress target = addresses[0];
        JSONObject payload = new JSONObject().put("code", code);
        byte[] body = payload.toString().getBytes(StandardCharsets.UTF_8);
        String authority = target instanceof Inet6Address ? "[" + host + "]" : host;
        byte[] header = ("POST /api/pairing/redeem HTTP/1.1\r\n" +
                "Host: " + authority + ":" + PORT + "\r\n" +
                "Content-Type: application/json\r\n" +
                "Accept: application/json\r\n" +
                "Cache-Control: no-store\r\n" +
                "Connection: close\r\n" +
                "Content-Length: " + body.length + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII);

        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(target, PORT), 5000);
            socket.setSoTimeout(12000);
            OutputStream out = socket.getOutputStream();
            out.write(header); out.write(body); out.flush();

            InputStream in = socket.getInputStream();
            byte[] responseHeader = readHeader(in);
            String head = new String(responseHeader, StandardCharsets.ISO_8859_1);
            String[] lines = head.split("\\r\\n");
            if (lines.length == 0 || !lines[0].startsWith("HTTP/1.")) throw new IllegalArgumentException("Invalid Setup Center pairing response");
            String[] status = lines[0].split(" ", 3);
            int codeValue = status.length > 1 ? Integer.parseInt(status[1]) : 0;
            if (codeValue == 401 || codeValue == 403) throw new SecurityException("Pairing code is invalid, expired, already used, or this request is not from the home LAN");
            if (codeValue != 200) throw new IllegalStateException("Setup Center pairing failed with HTTP " + codeValue);

            int contentLength = -1;
            for (String line : lines) {
                int colon = line.indexOf(':');
                if (colon <= 0) continue;
                if ("content-length".equals(line.substring(0, colon).trim().toLowerCase(Locale.US))) {
                    contentLength = Integer.parseInt(line.substring(colon + 1).trim());
                }
            }
            if (contentLength > MAX_BUNDLE) throw new IllegalArgumentException("Pairing bundle is larger than 32 MB");
            byte[] result = readLimited(in, MAX_BUNDLE);
            if (contentLength >= 0 && result.length != contentLength) throw new IllegalStateException("Pairing response was truncated");
            return result;
        }
    }

    static String normalizeHost(String raw) {
        String host = raw == null ? "" : raw.trim();
        if (host.startsWith("http://")) host = host.substring(7);
        else if (host.startsWith("https://")) host = host.substring(8);
        while (host.endsWith("/")) host = host.substring(0, host.length() - 1);
        if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);
        if (host.isEmpty() || host.contains("/") || host.contains("?") || host.contains("#") || host.contains("@")) throw new IllegalArgumentException("Enter only the AI Board LAN IP or hostname");
        if (host.indexOf(':') >= 0 && host.indexOf(':') == host.lastIndexOf(':')) throw new IllegalArgumentException("Do not include a port; Router VPN pairing uses private port 8786");
        return host;
    }

    static boolean isPrivate(InetAddress address) {
        if (address.isLoopbackAddress() || address.isLinkLocalAddress() || address.isSiteLocalAddress()) return true;
        byte[] bytes = address.getAddress();
        return bytes.length == 16 && (bytes[0] & 0xfe) == 0xfc; // IPv6 ULA fc00::/7
    }

    private static byte[] readHeader(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int state = 0;
        while (out.size() < MAX_HEADER) {
            int value = in.read();
            if (value < 0) throw new IllegalStateException("Setup Center closed before response headers completed");
            out.write(value);
            state = (state == 0 && value == '\r') ? 1
                    : (state == 1 && value == '\n') ? 2
                    : (state == 2 && value == '\r') ? 3
                    : (state == 3 && value == '\n') ? 4 : 0;
            if (state == 4) return out.toByteArray();
        }
        throw new IllegalArgumentException("Pairing response headers are too large");
    }

    private static byte[] readLimited(InputStream in, int max) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int total = 0, read;
        while ((read = in.read(buffer)) != -1) {
            total += read;
            if (total > max) throw new IllegalArgumentException("Pairing bundle is larger than 32 MB");
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }
}
