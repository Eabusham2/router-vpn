package com.eabusham.routervpn;

import io.nekohasekai.libbox.Libbox;
import org.json.JSONArray;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;

/** Imported AmneziaWG retains its native endpoint and complete obfuscation policy. */
final class AndroidExternalAmnezia {
    static final String[] PARAMETERS={"jc","jmin","jmax","s1","s2","s3","s4","h1","h2","h3","h4"};

    static JSONObject parameters(JSONObject values)throws Exception{
        if(values==null||values.length()!=PARAMETERS.length)throw new IllegalArgumentException("AmneziaWG requires all eleven supplied parameters.");
        JSONObject captured=new JSONObject();
        for(String key:PARAMETERS){Object value=values.get(key);if(!(value instanceof String)||((String)value).isEmpty()||((String)value).length()>32||!value.equals(((String)value).trim()))throw new IllegalArgumentException("AmneziaWG parameters must keep their exact bounded text values.");captured.put(key,value);}
        return captured;
    }

    static JSONObject endpoint(AndroidStandardExitStore.Entry entry)throws Exception{
        if(!"amneziawg".equals(entry.protocol))throw new IllegalArgumentException("The imported endpoint is not AmneziaWG.");
        JSONObject captured=parameters(entry.awgParameters);
        StringBuilder text=new StringBuilder("[Interface]\nPrivateKey=").append(line(entry.wgPrivateKey))
                .append("\nAddress=").append(line(String.join(",",entry.wgAddresses)))
                .append("\nMTU=").append(entry.wgMtu==0?1280:entry.wgMtu).append('\n');
        for(String key:PARAMETERS)text.append(key).append('=').append(line(captured.getString(key))).append('\n');
        text.append("[Peer]\nPublicKey=").append(line(entry.wgPeerPublicKey)).append("\nEndpoint=")
                .append(entry.server.contains(":")?"["+line(entry.server)+"]":line(entry.server)).append(':').append(entry.serverPort)
                .append("\nAllowedIPs=").append(line(String.join(",",entry.wgAllowedIps))).append('\n');
        if(!entry.wgPreSharedKey.isEmpty())text.append("PresharedKey=").append(line(entry.wgPreSharedKey)).append('\n');
        if(entry.wgKeepalive!=null)text.append("PersistentKeepalive=").append(entry.wgKeepalive).append('\n');
        JSONObject result=compile(text.toString()).getJSONObject("endpoint");
        return result.put("tag","custom-exit");
    }

    static AndroidStandardExitStore.Entry fromInline(String raw,String name,String expected)throws Exception{
        JSONObject compiled=compile(raw),endpoint=compiled.getJSONObject("endpoint");
        JSONArray peers=endpoint.getJSONArray("peers");if(peers.length()!=1)throw new IllegalArgumentException("Import one complete AmneziaWG peer.");
        JSONObject peer=peers.getJSONObject(0);
        AndroidStandardExitStore.Entry entry=new AndroidStandardExitStore.Entry();
        entry.name=name;entry.protocol="amneziawg";entry.expectedPublicIp=expected;
        entry.server=peer.getString("address");entry.serverPort=peer.getInt("port");
        entry.wgPrivateKey=endpoint.getString("private_key");entry.wgPeerPublicKey=peer.getString("public_key");entry.wgPreSharedKey=peer.optString("pre_shared_key","");
        entry.wgMtu=endpoint.getInt("mtu");entry.awgParameters=parameters(endpoint.getJSONObject("amnezia"));
        if(peer.has("persistent_keepalive_interval"))entry.wgKeepalive=peer.getInt("persistent_keepalive_interval");
        JSONArray addresses=endpoint.getJSONArray("address"),routes=peer.getJSONArray("allowed_ips"),dns=compiled.optJSONArray("dns");
        for(int i=0;i<addresses.length();i++)entry.wgAddresses.add(addresses.getString(i));
        for(int i=0;i<routes.length();i++)entry.wgAllowedIps.add(routes.getString(i));
        for(int i=0;dns!=null&&i<dns.length();i++)entry.wgDns.add(dns.getString(i));
        entry.policy=new JSONObject().put("dns_mode","home");
        if(!entry.wgDns.isEmpty())entry.policy.put("dns_mode","custom").put("dns_protocol","udp").put("dns_host",entry.wgDns.get(0)).put("dns_port",53);
        AndroidStandardExitStore.validate(entry);
        return entry;
    }

    private static JSONObject compile(String raw)throws Exception{
        if(raw==null||raw.isEmpty()||raw.getBytes(StandardCharsets.UTF_8).length>1024*1024)throw new IllegalArgumentException("Import a bounded complete AmneziaWG configuration.");
        // The parser argument identifies this immutable input, not an
        // authenticated Router VPN node. The external proof separately proves
        // selected DNS and the expected public exit through the live endpoint.
        String capture=AndroidTorProfile.digest(raw.getBytes(StandardCharsets.UTF_8));
        String encoded=Libbox.routerCompileAmneziaProfile(raw,capture);
        if(encoded==null||encoded.length()>2*1024*1024)throw new IllegalStateException("The native AmneziaWG parser returned no bounded endpoint.");
        JSONObject parsed=new JSONObject(encoded);
        if(!"routervpn-amneziawg".equals(parsed.getJSONObject("endpoint").getString("type")))throw new IllegalStateException("AmneziaWG was replaced by another native protocol.");
        return parsed;
    }
    private static String line(String value){if(value==null||value.indexOf('\n')>=0||value.indexOf('\r')>=0||value.indexOf('#')>=0)throw new IllegalArgumentException("Imported AmneziaWG values must not introduce configuration directives.");return value;}
}
