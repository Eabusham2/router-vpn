package com.eabusham.routervpn;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.os.Process;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/** Real forwarding-master state through the active Router VPN private path. */
final class AndroidForwardingMaster {
    static final class Verified {
        final boolean enabled;
        private final AndroidHomeStateStore.Snapshot session;
        private final Network vpn;
        private final String api, token, profileId, proofId;

        private Verified(boolean enabled, AndroidHomeStateStore.Snapshot session, Network vpn,
                         String api, String token, String profileId, String proofId) {
            this.enabled = enabled;
            this.session = session;
            this.vpn = vpn;
            this.api = api;
            this.token = token;
            this.profileId = profileId;
            this.proofId = proofId;
        }
    }

    interface Callback { void finished(Verified verified, Throwable error); }
    private static final int MAX_REPLY=64*1024;
    private final Context context;
    private final AndroidNodeStore store;

    AndroidForwardingMaster(Context context,AndroidNodeStore store){this.context=context.getApplicationContext();this.store=store;}

    private static String nodeId(AndroidHomeStateStore.Snapshot state) {
        return "multihop".equals(state.logicalMode) ? state.activeExitId : state.activeNodeId;
    }

    boolean isCurrent(AndroidHomeStateStore.Snapshot state) {
        AndroidHomeStateStore.Snapshot after = AndroidHomeStateStore.snapshot(context);
        if (!state.connected || !after.connected || state.sessionId.isEmpty() ||
                !state.sessionId.equals(after.sessionId) || after.pathGeneration!=state.pathGeneration) return false;
        String id = nodeId(state);
        return !"external".equals(state.logicalMode) && state.logicalMode.equals(after.logicalMode) &&
                id != null && !id.isEmpty() && id.equals(nodeId(after));
    }

    boolean isCurrent(Verified verified) {
        return isCurrent(verified.session) && verified.vpn.equals(ownedVpnNetwork());
    }

    void get(AndroidHomeStateStore.Snapshot session, Callback callback) { run(session, null, callback); }
    void set(Verified displayed, Callback callback) { run(displayed.session, displayed, callback); }

    private void run(AndroidHomeStateStore.Snapshot session, Verified displayed, Callback callback) {
        new Thread(() -> {
            Verified result;
            try { result = request(session, displayed); }
            catch (Exception error) { callback.finished(null, error); return; }
            callback.finished(result, null);
        }, "routervpn-forwarding-master").start();
    }

    private static IllegalStateException changed() {
        return new IllegalStateException("The Router VPN connection or linked node changed. Refresh forwarding and confirm again.");
    }

    private Verified request(AndroidHomeStateStore.Snapshot state, Verified displayed) throws Exception {
        if (!isCurrent(state)) throw changed();
        JSONObject bundle=readBundle(store.file(nodeId(state)));
        JSONObject profile=AndroidProfileSelection.selectedRouterProfile(bundle);
        String api=profile.optString("router_api","").trim();
        if(api.isEmpty())api=bundle.optString("routerAPI","").trim();
        String token=profile.optString("api_token","").trim();
        if(token.isEmpty())token=bundle.optString("apiToken","").trim();
        if(api.isEmpty()||token.isEmpty())throw new IllegalStateException("Active Router VPN node has no authenticated private Router API.");
        String profileId = profile.optString("id", ""), proofId = profile.optString("node_proof_id", "");
        if (displayed != null && (!displayed.api.equals(api) || !displayed.token.equals(token) ||
                !displayed.profileId.equals(profileId) || !displayed.proofId.equals(proofId))) throw changed();
        URI uri=URI.create(api);
        String host=uri.getHost();
        if(host==null||host.isEmpty()||!("http".equalsIgnoreCase(uri.getScheme())||"https".equalsIgnoreCase(uri.getScheme())))throw new IllegalStateException("Private Router API URL is invalid.");
        InetAddress address;
        try{address=AndroidNumericAddress.parse(host);}catch(Exception e){throw new IllegalStateException("Forwarding master requires a literal private Router API address; hostnames are refused before any DNS lookup.",e);}
        if(!isPrivate(address))throw new IllegalStateException("Forwarding master refuses to send the node token to a non-private Router API host.");
        String base=api.endsWith("/")?api.substring(0,api.length()-1):api;
        Network vpn=ownedVpnNetwork();
        if(vpn==null)throw new IllegalStateException("Android has no active VPN network owned by Router VPN.");
        if (!isCurrent(state) || displayed != null && !displayed.vpn.equals(vpn)) throw changed();
        HttpURLConnection c=(HttpURLConnection)vpn.openConnection(new URL(base+"/api/forwarding/master"));
        try {
            c.setConnectTimeout(3000);c.setReadTimeout(5000);c.setUseCaches(false);c.setInstanceFollowRedirects(false);
            c.setRequestProperty("Authorization","Bearer "+token);c.setRequestProperty("Accept","application/json");c.setRequestProperty("Cache-Control","no-store");
            if (displayed != null) {
                byte[] body = (new JSONObject().put("enabled", !displayed.enabled).toString()+"\n").getBytes(StandardCharsets.UTF_8);
                c.setRequestMethod("PUT");c.setDoOutput(true);c.setFixedLengthStreamingMode(body.length);
                c.setRequestProperty("Content-Type","application/json");
                if (!isCurrent(displayed)) throw changed();
                try(OutputStream out=c.getOutputStream()){out.write(body);}
            }
            int code=c.getResponseCode();
            if(code<200||code>=300)throw new IllegalStateException("Forwarding master returned HTTP "+code+".");
            byte[] raw;
            try(InputStream in=c.getInputStream();ByteArrayOutputStream out=new ByteArrayOutputStream()){byte[]buf=new byte[4096];for(int n,total=0;(n=in.read(buf))!=-1;){total+=n;if(total>MAX_REPLY)throw new IllegalStateException("Forwarding-master response is too large.");out.write(buf,0,n);}raw=out.toByteArray();}
            JSONObject reply=new JSONObject(new String(raw,StandardCharsets.UTF_8));
            if(!Boolean.TRUE.equals(reply.opt("ok")) || !(reply.opt("enabled") instanceof Boolean))
                throw new IllegalStateException("Forwarding-master response could not be verified.");
            boolean enabled=reply.getBoolean("enabled");
            if(displayed!=null && enabled==displayed.enabled)throw new IllegalStateException("Forwarding master did not reach the requested state.");
            Verified result = new Verified(enabled, state, vpn, api, token, profileId, proofId);
            if (!isCurrent(result)) throw changed();
            return result;
        } finally { c.disconnect(); }
    }

    private Network ownedVpnNetwork(){ConnectivityManager cm=(ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);if(cm==null)return null;Network n=cm.getActiveNetwork();if(n==null)return null;NetworkCapabilities caps=cm.getNetworkCapabilities(n);if(caps==null||!caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN))return null;if(Build.VERSION.SDK_INT<Build.VERSION_CODES.R)return null;return caps.getOwnerUid()==Process.myUid()?n:null;}
    private static boolean isPrivate(InetAddress a){if(a.isAnyLocalAddress())return false;if(a.isLoopbackAddress()||a.isLinkLocalAddress()||a.isSiteLocalAddress())return true;byte[]b=a.getAddress();return b.length==16&&(b[0]&0xfe)==0xfc;}
    private static JSONObject readBundle(File file)throws Exception{if(file==null||!file.isFile()||file.length()<=0||file.length()>AndroidNodeStore.MAX_BUNDLE)throw new IllegalStateException("Active node bundle is invalid.");try(FileInputStream in=new FileInputStream(file);ByteArrayOutputStream out=new ByteArrayOutputStream()){byte[]buf=new byte[8192];int total=0,n;while((n=in.read(buf))!=-1){total+=n;if(total>AndroidNodeStore.MAX_BUNDLE)throw new IllegalStateException("Active node bundle exceeds safety limit.");out.write(buf,0,n);}return new JSONObject(new String(out.toByteArray(),StandardCharsets.UTF_8));}}
}
