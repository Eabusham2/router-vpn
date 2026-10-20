package com.eabusham.routervpn;

import android.content.Context;
import org.json.JSONArray;
import org.json.JSONObject;

/** Builds a captured direct external exit under the existing Android VPN owner. */
final class AndroidDirectStandardExitController {
    private final Context context;

    AndroidDirectStandardExitController(Context context) { this.context=context.getApplicationContext(); }

    NativeSingBoxController.SessionInfo prepare(AndroidStandardExitStore.Entry exit) throws Exception {
        AndroidStandardExitStore.validate(exit);
        if(AndroidTorProfile.isTor(exit.protocol))return AndroidTorProfile.prepare(context, null, exit, "external");
        if(AndroidExternalPolicy.supports(exit.protocol))return AndroidExternalPolicy.prepare(context, null, exit, "external");
        throw new IllegalArgumentException("The selected external protocol has no captured native policy owner.");
    }

    static JSONObject customExitJson(AndroidStandardExitStore.Entry e) throws Exception {
        if ("openvpn".equals(e.protocol)) return AndroidOpenVPN.endpoint(e, "");
        if ("amneziawg".equals(e.protocol)) return AndroidExternalAmnezia.endpoint(e);
        if ("wireguard".equals(e.protocol)) {
            JSONObject peer = new JSONObject().put("address", e.server).put("port", e.serverPort)
                    .put("public_key", e.wgPeerPublicKey).put("allowed_ips", new JSONArray(e.wgAllowedIps));
            if (!e.wgPreSharedKey.isEmpty()) peer.put("pre_shared_key", e.wgPreSharedKey);
            if (e.wgKeepalive != null) peer.put("persistent_keepalive_interval",e.wgKeepalive);
            JSONObject endpoint = new JSONObject().put("type", "wireguard").put("tag", "custom-exit")
                    .put("address", new JSONArray(e.wgAddresses)).put("private_key", e.wgPrivateKey)
                    .put("peers", new JSONArray().put(peer));
            if (e.wgMtu != 0) endpoint.put("mtu", e.wgMtu);
            return endpoint;
        }
        JSONObject out = new JSONObject().put("tag", "custom-exit").put("server", e.server).put("server_port", e.serverPort);
        if ("socks5".equals(e.protocol)) {
            out.put("type", "socks").put("version", "5");
            if (!e.username.isEmpty()) out.put("username", e.username).put("password", e.password);
        } else if ("http".equals(e.protocol) || "https".equals(e.protocol)) {
            out.put("type", "http");
            if (!e.username.isEmpty()) out.put("username", e.username).put("password", e.password);
            if ("https".equals(e.protocol)) out.put("tls", new JSONObject().put("enabled", true).put("server_name", e.tlsServerName));
        } else if ("shadowsocks".equals(e.protocol)) {
            out.put("type", "shadowsocks").put("method", e.method).put("password", e.secret);
        } else if ("hysteria2".equals(e.protocol)) {
            out.put("type", "hysteria2").put("password", e.secret)
                    .put("tls", new JSONObject().put("enabled", true).put("server_name", e.tlsServerName));
        } else {
            throw new IllegalArgumentException("Unsupported direct Android custom exit protocol: " + e.protocol);
        }
        return out;
    }

}
