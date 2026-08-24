package com.eabusham.routervpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Typeface;
import android.text.InputType;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

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
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Native Android product-parity views backed only by the private imported node and real engine/readiness contracts. */
final class AndroidProductParity {
    private static final int MAX_BUNDLE = AndroidNodeStore.MAX_BUNDLE;
    private static final int MAX_HTTP = 128 * 1024;

    private static final class ResolverPreset {
        final String name, host, serverName;
        ResolverPreset(String name, String host, String serverName) { this.name=name; this.host=host; this.serverName=serverName; }
        @Override public String toString(){ return name + " — " + host; }
    }
    private static final ResolverPreset[] PRESETS = new ResolverPreset[]{
            new ResolverPreset("Cloudflare IPv4","1.1.1.1","cloudflare-dns.com"),
            new ResolverPreset("Cloudflare IPv6","2606:4700:4700::1111","cloudflare-dns.com"),
            new ResolverPreset("Google IPv4","8.8.8.8","dns.google"),
            new ResolverPreset("Google IPv6","2001:4860:4860::8888","dns.google"),
            new ResolverPreset("Quad9 IPv4","9.9.9.9","dns.quad9.net"),
            new ResolverPreset("Quad9 IPv6","2620:fe::fe","dns.quad9.net")
    };

    static void showModes(Activity activity, AndroidNodeStore nodeStore) {
        try {
            JSONObject root = activeBundle(nodeStore);
            JSONArray logical = root.optJSONArray("logicalModes");
            JSONArray raw = root.optJSONArray("modes");
            if (logical == null || raw == null) throw new IllegalStateException("Selected node bundle has no logical/raw mode catalogs.");
            Map<String,JSONObject> rawById = new HashMap<>();
            for(int i=0;i<raw.length();i++){ JSONObject m=raw.optJSONObject(i); if(m!=null) rawById.put(m.optString("id",""),m); }
            Set<String> libbox = new HashSet<>(), xray = new HashSet<>();
            NativeSingBoxController sing = new NativeSingBoxController(activity);
            NativeXrayController xrayController = new NativeXrayController(activity);
            File bundleFile = nodeStore.file(nodeStore.activeId());
            for(NativeSingBoxController.ModeInfo m: sing.listDirectLibboxModes(bundleFile)) libbox.add(m.id);
            for(NativeXrayController.ModeInfo m: xrayController.listDirectXrayModes(bundleFile)) xray.add(m.id);
            JSONObject profiles = root.optJSONObject("profiles");
            boolean strict = AndroidKillSwitchPolicy.strictRequested(root);

            LinearLayout body = column(activity, 16);
            body.addView(label(activity,"Mode / layers / estimates / Android runtime readiness",20,true));
            body.addView(label(activity,"Engineering latency/traffic/speed ranges come from the shipped raw catalog. Readiness is computed from the selected private bundle and real Android WG/AWG/libbox/Xray dataplanes; unsupported graphs stay unavailable.",13,false));
            for(int i=0;i<logical.length();i++){
                JSONObject l=logical.optJSONObject(i); if(l==null) continue;
                JSONObject variants=l.optJSONObject("variants");
                List<JSONObject> candidates=new ArrayList<>();
                List<String> ready=new ArrayList<>();
                Set<String> layers=new HashSet<>();
                if(variants!=null){
                    JSONArray names=variants.names();
                    if(names!=null) for(int j=0;j<names.length();j++){
                        String runtime=variants.optString(names.optString(j),""); JSONObject m=rawById.get(runtime); if(m==null) continue; candidates.add(m);
                        JSONArray ls=m.optJSONArray("layers"); if(ls!=null) for(int k=0;k<ls.length();k++){String layer=ls.optString(k,"").trim();if(!layer.isEmpty())layers.add(layer);}
                        boolean available=false;
                        if(!strict && "wg".equals(runtime)) available=hasProfile(profiles,"wg","wg.conf");
                        else if(!strict && "awg2-fast".equals(runtime)) available=hasProfile(profiles,"awg2-fast","awg.conf");
                        else if(libbox.contains(runtime) || xray.contains(runtime)) available=true;
                        if(available) ready.add(runtime);
                    }
                }
                double pingMin=min(candidates,"ping_min_ms"), pingMax=max(candidates,"ping_max_ms"), trafficMin=min(candidates,"traffic_min_pct"), trafficMax=max(candidates,"traffic_max_pct"), speedMin=min(candidates,"speed_loss_min_pct"), speedMax=max(candidates,"speed_loss_max_pct");
                TextView card=label(activity,"",13,false); card.setPadding(0,14,0,14);
                String reason=ready.isEmpty()? (strict?"Unavailable: strict Android lockdown excludes raw WG/AWG and no imported libbox/Xray variant for this logical mode is runnable.":"Unavailable: no imported Android-native WG/AWG/libbox/Xray variant for this logical mode is runnable.") : "Ready runtimes: "+String.join(", ",ready)+". Final Connected still requires selected-node path proof.";
                card.setText(l.optString("name",l.optString("id",""))+"\n"+l.optString("description","")+"\nLayers: "+(layers.isEmpty()?"—":String.join(" • ",sorted(layers)))+String.format(Locale.US,"\nAdded latency %.1f–%.1f ms • traffic +%.1f–%.1f%% • speed loss %.1f–%.1f%%\nReadiness: %s\n%s",pingMin,pingMax,trafficMin,trafficMax,speedMin,speedMax,ready.isEmpty()?"Unavailable":"Ready",reason));
                body.addView(card);
            }
            ScrollView scroll=new ScrollView(activity); scroll.addView(body);
            new AlertDialog.Builder(activity).setTitle("Modes").setView(scroll).setPositiveButton("Close",null).show();
        } catch(Exception error){ toast(activity,"Mode details unavailable: "+safe(error)); }
    }

    static void showDNS(Activity activity, AndroidNodeStore nodeStore) {
        try {
            JSONObject bundle=activeBundle(nodeStore); JSONObject profile=selectedProfile(bundle);
            if(profile==null) throw new IllegalStateException("Choose/link a Router VPN node first.");
            final String openedProfileId=profile.optString("id","");
            final boolean policyBusy=AndroidVpnMutationGuard.isBusy(activity);
            String[] modeValues={"home","fastest","custom","dot","doh","doh3","rescue"};
            String[] modeLabels={"Home AdGuard","Fastest measured","Custom UDP/TCP","DNS-over-TLS","DNS-over-HTTPS","DNS-over-HTTP/3","DNS Rescue"};
            LinearLayout body=column(activity,12);
            Spinner mode=new Spinner(activity); mode.setAdapter(new ArrayAdapter<>(activity,android.R.layout.simple_spinner_dropdown_item,modeLabels));
            int selectedMode=indexOf(modeValues,profile.optString("dns_mode","home")); mode.setSelection(Math.max(0,selectedMode));
            Spinner protocol=new Spinner(activity); protocol.setAdapter(new ArrayAdapter<>(activity,android.R.layout.simple_spinner_dropdown_item,new String[]{"udp","tcp"})); protocol.setSelection("tcp".equalsIgnoreCase(profile.optString("dns_protocol","udp"))?1:0);
            Spinner preset=new Spinner(activity); List<String> presetLabels=new ArrayList<>();presetLabels.add("Manual/current");for(ResolverPreset p:PRESETS)presetLabels.add(p.toString());preset.setAdapter(new ArrayAdapter<>(activity,android.R.layout.simple_spinner_dropdown_item,presetLabels));
            EditText host=field(activity,"Resolver host / IPv4 / IPv6",profile.optString("dns_host",""),InputType.TYPE_CLASS_TEXT);
            EditText port=field(activity,"Port",String.valueOf(profile.optInt("dns_port",53)),InputType.TYPE_CLASS_NUMBER);
            EditText server=field(activity,"TLS server name",profile.optString("dns_server_name",""),InputType.TYPE_CLASS_TEXT);
            EditText path=field(activity,"HTTPS path",profile.optString("dns_path","/dns-query"),InputType.TYPE_CLASS_TEXT);
            preset.setOnItemSelectedListener(new android.widget.AdapterView.OnItemSelectedListener(){public void onNothingSelected(android.widget.AdapterView<?> p){} public void onItemSelected(android.widget.AdapterView<?> p,View v,int position,long id){if(position>0){ResolverPreset r=PRESETS[position-1];host.setText(r.host);server.setText(r.serverName);}}});
            body.addView(label(activity,"DNS policy",18,true));body.addView(mode);body.addView(label(activity,"Custom protocol (used only by Custom)",12,false));body.addView(protocol);body.addView(label(activity,"Common IPv4/IPv6 resolver",12,false));body.addView(preset);body.addView(host);body.addView(port);body.addView(server);body.addView(path);
            if(policyBusy){mode.setEnabled(false);protocol.setEnabled(false);preset.setEnabled(false);host.setEnabled(false);port.setEnabled(false);server.setEnabled(false);path.setEnabled(false);body.addView(label(activity,"Disconnect or let the current VPN transition finish before changing persistent DNS policy. DNS Retest remains a measurement action.",12,false));}
            TextView benchmark=label(activity,dnsResultsText(profile),12,false);body.addView(benchmark);
            Button retest=new Button(activity);retest.setText("Retest DNS RTT from home node");retest.setAllCaps(false);body.addView(retest);
            retest.setOnClickListener(v->{retest.setEnabled(false);benchmark.setText("Testing real A/AAAA DNS queries from the selected home node…");new Thread(()->{try{JSONObject result=benchmarkDNS(bundle,profile);persistBenchmark(nodeStore,openedProfileId,result);activity.runOnUiThread(()->{try{benchmark.setText(dnsResultsText(selectedProfile(activeBundle(nodeStore))));}catch(Exception e){benchmark.setText("DNS benchmark saved; reopen to refresh details.");}retest.setEnabled(true);});}catch(Exception error){activity.runOnUiThread(()->{benchmark.setText("DNS Retest failed: "+safe(error));retest.setEnabled(true);});}}).start();});
            ScrollView scroll=new ScrollView(activity);scroll.addView(body);
            AlertDialog dialog=new AlertDialog.Builder(activity).setTitle("DNS").setView(scroll).setPositiveButton("Save",null).setNeutralButton("Close",null).create();
            dialog.setOnShowListener(x->{Button save=dialog.getButton(AlertDialog.BUTTON_POSITIVE);save.setEnabled(!AndroidVpnMutationGuard.isBusy(activity));save.setOnClickListener(v->{if(AndroidVpnMutationGuard.isBusy(activity)){toast(activity,"VPN state changed; disconnect/finish before saving DNS policy.");return;}try{JSONObject fresh=activeBundle(nodeStore),freshProfile=selectedProfile(fresh);if(freshProfile==null||!openedProfileId.equals(freshProfile.optString("id","")))throw new IllegalStateException("Selected Router VPN profile changed while DNS settings were open; reopen DNS before saving.");String chosen=modeValues[mode.getSelectedItemPosition()];String proto=(String)protocol.getSelectedItem();applyDNS(nodeStore,fresh,chosen,proto,host.getText().toString(),parsePort(port.getText().toString()),server.getText().toString(),path.getText().toString());toast(activity,"DNS policy saved for the next connection: "+chosen.toUpperCase(Locale.US)+". Reconnect, then use runtime proof to confirm active DNS.");dialog.dismiss();}catch(Exception error){toast(activity,"DNS policy failed: "+safe(error));}});});
            dialog.show();
        }catch(Exception error){toast(activity,"DNS settings unavailable: "+safe(error));}
    }

    private static void applyDNS(AndroidNodeStore store,JSONObject bundle,String mode,String protocol,String host,int port,String serverName,String path)throws Exception{
        JSONObject profile=selectedProfile(bundle);if(profile==null)throw new IllegalStateException("No selected Router VPN profile.");
        if("external".equalsIgnoreCase(profile.optString("node_kind","router-vpn")))throw new IllegalStateException("External nodes own their DNS runtime.");
        mode=mode.trim().toLowerCase(Locale.US);protocol=protocol.trim().toLowerCase(Locale.US);host=host.trim();serverName=serverName.trim();path=path.trim();
        if("home".equals(mode)){host=profile.optString("adguard_ipv4",profile.optString("adguard_ipv6",""));protocol="udp";port=53;serverName="";path="";}
        else if("fastest".equals(mode)){host=profile.optString("fastest_dns_host","").trim();if(host.isEmpty())throw new IllegalStateException("Run DNS Retest before selecting Fastest.");protocol="udp";port=53;serverName="";path="";}
        else if("custom".equals(mode)){if(!"udp".equals(protocol)&&!"tcp".equals(protocol))throw new IllegalArgumentException("Custom DNS must use UDP or TCP.");if(port==0)port=53;}
        else if("dot".equals(mode)){protocol="tls";if(port==0)port=853;}
        else if("doh".equals(mode)){protocol="https";if(port==0)port=443;if(path.isEmpty())path="/dns-query";}
        else if("doh3".equals(mode)){protocol="h3";if(port==0)port=443;if(path.isEmpty())path="/dns-query";}
        else if("rescue".equals(mode)){protocol="rescue";if(host.isEmpty())host=profile.optString("fastest_dns_host","1.1.1.1");if(port==0)port=443;if(path.isEmpty())path="/dns-query";}
        else throw new IllegalArgumentException("Unsupported DNS mode.");
        if(host.isEmpty())throw new IllegalArgumentException("DNS host is required.");if(port<1||port>65535)throw new IllegalArgumentException("DNS port must be 1–65535.");
        if(("dot".equals(mode)||"doh".equals(mode)||"doh3".equals(mode))&&serverName.isEmpty()){serverName=inferServerName(host);if(serverName.isEmpty())throw new IllegalArgumentException("Encrypted DNS to an IP requires a TLS server name.");}
        if(!path.isEmpty()&&!path.startsWith("/"))throw new IllegalArgumentException("DNS HTTPS path must start with /.");
        profile.put("dns_mode",mode);profile.put("dns_protocol",protocol);profile.put("dns_host",host);profile.put("dns_port",port);profile.put("dns_server_name",serverName);profile.put("dns_path",path);
        store.importBundle(bundle.toString().getBytes(StandardCharsets.UTF_8));
    }

    private static JSONObject benchmarkDNS(JSONObject bundle,JSONObject profile)throws Exception{
        String api=profile.optString("router_api",bundle.optString("routerAPI","")).trim();String token=profile.optString("api_token",bundle.optString("apiToken","")).trim();if(api.isEmpty()||token.isEmpty())throw new IllegalStateException("Selected node has no authenticated DNS benchmark path.");
        URI base=new URI(api);if(!"http".equalsIgnoreCase(base.getScheme()))throw new IllegalStateException("Android home-node DNS benchmark requires the private tunnel HTTP router-agent.");String host=base.getHost();if(host==null||host.isEmpty())throw new IllegalStateException("Router-agent host is invalid.");InetAddress address=InetAddress.getByName(host);if(!isPrivate(address))throw new IllegalStateException("DNS benchmark router-agent must resolve to a private address.");int port=base.getPort()>0?base.getPort():80;
        try(Socket socket=new Socket()){socket.connect(new InetSocketAddress(address,port),8000);socket.setSoTimeout(45000);OutputStream out=socket.getOutputStream();String request="POST /api/dns/benchmark HTTP/1.1\r\nHost: "+host+"\r\nAuthorization: Bearer "+token+"\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";out.write(request.getBytes(StandardCharsets.US_ASCII));out.flush();byte[] response=readLimited(socket.getInputStream(),MAX_HTTP);return new JSONObject(decodeHttpBody(response));}
    }

    private static String decodeHttpBody(byte[] response)throws Exception{
        int split=findHeaderEnd(response);if(split<0)throw new IllegalStateException("DNS benchmark returned an invalid HTTP response.");
        String headers=new String(response,0,split,StandardCharsets.US_ASCII);String first=headers.split("\r\n",2)[0];if(!(first.startsWith("HTTP/1.1 200 ")||first.startsWith("HTTP/1.0 200 ")))throw new IllegalStateException("DNS benchmark failed: "+first);
        int bodyStart=split+4;String lower=headers.toLowerCase(Locale.US);
        if(lower.contains("\r\ntransfer-encoding: chunked")||lower.startsWith("transfer-encoding: chunked"))return new String(decodeChunked(response,bodyStart),StandardCharsets.UTF_8).trim();
        int contentLength=parseContentLength(headers);if(contentLength>=0){if(contentLength>MAX_HTTP)throw new IllegalStateException("DNS benchmark body exceeded safety limit.");if(bodyStart+contentLength>response.length)throw new IllegalStateException("DNS benchmark body was truncated.");return new String(response,bodyStart,contentLength,StandardCharsets.UTF_8).trim();}
        if(response.length-bodyStart>MAX_HTTP)throw new IllegalStateException("DNS benchmark body exceeded safety limit.");return new String(response,bodyStart,response.length-bodyStart,StandardCharsets.UTF_8).trim();
    }

    private static int findHeaderEnd(byte[] data){for(int i=0;i+3<data.length;i++)if(data[i]=='\r'&&data[i+1]=='\n'&&data[i+2]=='\r'&&data[i+3]=='\n')return i;return -1;}
    private static int findCrlf(byte[] data,int start){for(int i=start;i+1<data.length;i++)if(data[i]=='\r'&&data[i+1]=='\n')return i;return -1;}
    private static int parseContentLength(String headers)throws Exception{for(String line:headers.split("\r\n")){int colon=line.indexOf(':');if(colon>0&&"content-length".equalsIgnoreCase(line.substring(0,colon).trim())){long value=Long.parseLong(line.substring(colon+1).trim());if(value<0||value>Integer.MAX_VALUE)throw new IllegalStateException("Invalid DNS benchmark Content-Length.");return(int)value;}}return-1;}
    private static byte[] decodeChunked(byte[] data,int offset)throws Exception{ByteArrayOutputStream out=new ByteArrayOutputStream();int cursor=offset;while(true){int lineEnd=findCrlf(data,cursor);if(lineEnd<0)throw new IllegalStateException("DNS benchmark chunk header was truncated.");String line=new String(data,cursor,lineEnd-cursor,StandardCharsets.US_ASCII).trim();int semi=line.indexOf(';');if(semi>=0)line=line.substring(0,semi).trim();if(line.isEmpty())throw new IllegalStateException("DNS benchmark chunk size was empty.");long size=Long.parseLong(line,16);if(size<0||size>MAX_HTTP||out.size()+size>MAX_HTTP)throw new IllegalStateException("DNS benchmark chunked body exceeded safety limit.");cursor=lineEnd+2;if(size==0)return out.toByteArray();if(cursor+size+2>data.length)throw new IllegalStateException("DNS benchmark chunk body was truncated.");out.write(data,cursor,(int)size);cursor+=(int)size;if(data[cursor]!='\r'||data[cursor+1]!='\n')throw new IllegalStateException("DNS benchmark chunk framing was invalid.");cursor+=2;}}

    private static void persistBenchmark(AndroidNodeStore store,String expectedProfileId,JSONObject result)throws Exception{JSONObject bundle=activeBundle(store),profile=selectedProfile(bundle);if(profile==null||expectedProfileId==null||!expectedProfileId.equals(profile.optString("id","")))throw new IllegalStateException("Selected Router VPN profile changed during DNS Retest; measurement was not persisted.");JSONArray results=result.optJSONArray("results");JSONObject winner=result.optJSONObject("winner");if(results!=null)profile.put("dns_results",results);if(winner!=null&&!winner.optString("address","").isEmpty()){profile.put("fastest_dns_host",winner.optString("address"));profile.put("fastest_dns_name",winner.optString("name"));profile.put("fastest_dns_latency_ms",winner.optDouble("latency_ms",0));}store.importBundle(bundle.toString().getBytes(StandardCharsets.UTF_8));}
    private static String dnsResultsText(JSONObject profile){if(profile==null)return "No Router VPN DNS profile.";StringBuilder out=new StringBuilder();out.append("Selected: ").append(profile.optString("dns_mode","home")).append(" • ").append(profile.optString("dns_host","profile/default"));String fastest=profile.optString("fastest_dns_host","");if(!fastest.isEmpty())out.append(String.format(Locale.US,"\nFastest measured: %s • %.2f ms • %s",profile.optString("fastest_dns_name",fastest),profile.optDouble("fastest_dns_latency_ms",0),fastest));JSONArray values=profile.optJSONArray("dns_results");if(values!=null){List<JSONObject> rows=new ArrayList<>();for(int i=0;i<values.length();i++){JSONObject r=values.optJSONObject(i);if(r!=null)rows.add(r);}rows.sort((a,b)->{boolean aw=a.optBoolean("working"),bw=b.optBoolean("working");if(aw!=bw)return aw?-1:1;return Double.compare(a.optDouble("latency_ms",Double.MAX_VALUE),b.optDouble("latency_ms",Double.MAX_VALUE));});for(JSONObject r:rows)out.append("\n").append(r.optString("name",r.optString("address"))).append(" • ").append(r.optString("address")).append(" • ").append(r.optBoolean("working")?String.format(Locale.US,"%.2f ms",r.optDouble("latency_ms",0)):"failed");}out.append("\n\nRTT = median real A/AAAA DNS query time from the selected home node, not ICMP ping. Saved policy applies on the next connection; runtime proof still decides active DNS.");return out.toString();}

    private static JSONObject activeBundle(AndroidNodeStore store)throws Exception{String id=store.activeId();if(id==null||id.isEmpty())throw new IllegalStateException("Pair/import and select a Router VPN node first.");return new JSONObject(new String(readLimited(store.file(id),MAX_BUNDLE),StandardCharsets.UTF_8));}
    private static JSONObject selectedProfile(JSONObject bundle){JSONArray profiles=bundle.optJSONArray("routerProfiles");String wanted=bundle.optString("selectedRouterID","").trim();if(profiles==null)return null;for(int i=0;i<profiles.length();i++){JSONObject p=profiles.optJSONObject(i);if(p!=null&&wanted.equals(p.optString("id","")))return p;}return profiles.length()>0?profiles.optJSONObject(0):null;}
    private static boolean hasProfile(JSONObject profiles,String id,String file){JSONObject p=profiles==null?null:profiles.optJSONObject(id);return p!=null&&!p.optString(file,"").trim().isEmpty();}
    private static double min(List<JSONObject> values,String key){double v=Double.POSITIVE_INFINITY;for(JSONObject x:values){if(x.has(key))v=Math.min(v,x.optDouble(key,0));}return Double.isInfinite(v)?0:v;}
    private static double max(List<JSONObject> values,String key){double v=0;for(JSONObject x:values)v=Math.max(v,x.optDouble(key,0));return v;}
    private static List<String> sorted(Set<String> values){List<String> out=new ArrayList<>(values);Collections.sort(out);return out;}
    private static String inferServerName(String host){for(ResolverPreset p:PRESETS)if(p.host.equalsIgnoreCase(host))return p.serverName;return host.matches(".*[A-Za-z].*")?host:"";}
    private static int parsePort(String value){try{return Integer.parseInt(value.trim());}catch(Exception ignored){return 0;}}
    private static int indexOf(String[] values,String value){for(int i=0;i<values.length;i++)if(values[i].equalsIgnoreCase(value))return i;return 0;}
    private static LinearLayout column(Activity a,int pad){LinearLayout l=new LinearLayout(a);l.setOrientation(LinearLayout.VERTICAL);int p=dp(a,pad);l.setPadding(p,p,p,p);return l;}
    private static TextView label(Activity a,String text,int sp,boolean bold){TextView v=new TextView(a);v.setText(text);v.setTextSize(sp);v.setTextColor(0xff14213d);if(bold)v.setTypeface(v.getTypeface(),Typeface.BOLD);return v;}
    private static EditText field(Activity a,String hint,String value,int type){EditText e=new EditText(a);e.setHint(hint);e.setText(value);e.setInputType(type);e.setSingleLine(true);return e;}
    private static int dp(Activity a,int v){return Math.round(v*a.getResources().getDisplayMetrics().density);}
    private static void toast(Activity a,String value){Toast.makeText(a,value,Toast.LENGTH_LONG).show();}
    private static String safe(Throwable e){String v=e==null?"":e.getMessage();return v==null||v.trim().isEmpty()?"Router VPN error":v.trim();}
    private static byte[] readLimited(File file,int max)throws Exception{try(FileInputStream in=new FileInputStream(file)){return readLimited(in,max);}}
    private static byte[] readLimited(InputStream input,int max)throws Exception{ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] b=new byte[8192];int total=0,n;while((n=input.read(b))!=-1){total+=n;if(total>max)throw new IllegalStateException("Response/bundle exceeded safety limit.");out.write(b,0,n);}return out.toByteArray();}
    private static boolean isPrivate(InetAddress value){if(value.isAnyLocalAddress()||value.isLoopbackAddress()||value.isLinkLocalAddress()||value.isSiteLocalAddress())return true;byte[]b=value.getAddress();if(b.length==16)return(b[0]&0xfe)==0xfc;if(b.length==4){int a=b[0]&255,c=b[1]&255;return a==10||(a==172&&c>=16&&c<=31)||(a==192&&c==168)||(a==169&&c==254);}return false;}
    private AndroidProductParity(){}
}
