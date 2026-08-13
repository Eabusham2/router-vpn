package com.eabusham.routervpn;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;

/** Proves traffic reached the selected private Router VPN node; a TUN UP state alone is not success. */
final class AndroidPathProbe {
    private static final int MAX_BUNDLE = 64 * 1024 * 1024;
    private static final int MAX_RESPONSE = 16 * 1024;
    private static final String PROOF_KIND = "router-vpn-private-agent-v1";

    static boolean prove(File privateBundle, int timeoutMillis) throws Exception {
        JSONObject bundle = load(privateBundle);
        JSONObject profile = selectedProfile(bundle);
        String expectedNode = bundle.optString("nodeProofId", "").trim();
        if (expectedNode.isEmpty() && profile != null) expectedNode = profile.optString("node_proof_id", "").trim();
        if (!expectedNode.matches("[0-9a-f]{64}")) throw new IllegalStateException("Router bundle is missing a valid stable node proof id.");
        String target = profile == null ? "" : profile.optString("path_probe_url", "").trim();
        if (target.isEmpty()) target = "http://10.77.0.1:8787/health";
        URI uri = new URI(target);
        if (!"http".equalsIgnoreCase(uri.getScheme())) throw new IllegalStateException("Android selected-node proof currently requires the private HTTP health endpoint.");
        String host = uri.getHost();
        if (host == null || host.trim().isEmpty()) throw new IllegalStateException("Selected-node proof URL has no host.");
        InetAddress address = InetAddress.getByName(host);
        if (!isPrivate(address)) throw new IllegalStateException("Selected-node proof host must resolve to a private/link-local/loopback address.");
        int port = uri.getPort() > 0 ? uri.getPort() : 80;
        String path = uri.getRawPath(); if (path == null || path.isEmpty()) path = "/";
        if (uri.getRawQuery() != null && !uri.getRawQuery().isEmpty()) path += "?" + uri.getRawQuery();
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(address, port), timeoutMillis);
            socket.setSoTimeout(timeoutMillis);
            OutputStream out = socket.getOutputStream();
            String request = "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\nAccept: application/json\r\n\r\n";
            out.write(request.getBytes(StandardCharsets.US_ASCII)); out.flush();
            byte[] response = readLimited(socket.getInputStream(), MAX_RESPONSE);
            String text = new String(response, StandardCharsets.UTF_8);
            int split = text.indexOf("\r\n\r\n");
            if (split < 0) return false;
            String headers = text.substring(0, split);
            if (!(headers.startsWith("HTTP/1.1 200 ") || headers.startsWith("HTTP/1.0 200 "))) return false;
            JSONObject body = new JSONObject(text.substring(split + 4).trim());
            return body.optBoolean("ok", false)
                    && expectedNode.equals(body.optString("node_id", "").trim())
                    && PROOF_KIND.equals(body.optString("proof", "").trim());
        }
    }

    private static JSONObject selectedProfile(JSONObject bundle) {
        JSONArray profiles = bundle.optJSONArray("routerProfiles");
        String wanted = bundle.optString("selectedRouterID", "").trim();
        if (profiles == null) return null;
        for (int i=0;i<profiles.length();i++) { JSONObject p=profiles.optJSONObject(i); if(p!=null && wanted.equals(p.optString("id"))) return p; }
        return profiles.length()>0 ? profiles.optJSONObject(0) : null;
    }

    private static boolean isPrivate(InetAddress value) {
        if (value.isAnyLocalAddress() || value.isLoopbackAddress() || value.isLinkLocalAddress() || value.isSiteLocalAddress()) return true;
        byte[] b=value.getAddress();
        if(b.length==16) return (b[0]&0xfe)==0xfc;
        if(b.length==4){int a=b[0]&255,c=b[1]&255;return a==10||(a==172&&c>=16&&c<=31)||(a==192&&c==168)||(a==169&&c==254);}
        return false;
    }

    private static JSONObject load(File file) throws Exception {
        if(file==null||!file.isFile()||file.length()<=0||file.length()>MAX_BUNDLE) throw new IllegalStateException("Private node bundle is missing or invalid.");
        try(FileInputStream in=new FileInputStream(file)){return new JSONObject(new String(readLimited(in,MAX_BUNDLE),StandardCharsets.UTF_8));}
    }
    private static byte[] readLimited(InputStream input,int max)throws Exception{ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] b=new byte[4096];int total=0,n;while((n=input.read(b))!=-1){total+=n;if(total>max)throw new IllegalStateException("Selected-node proof response exceeded safety limit.");out.write(b,0,n);}return out.toByteArray();}
    private AndroidPathProbe() {}
}
