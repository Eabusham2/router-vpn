package com.eabusham.routervpn;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * Secret-free product catalog combining linked Router VPN nodes and custom
 * non-Router-VPN exits. The catalog copies only display/runtime-selection
 * metadata; protocol credentials never leave AndroidStandardExitStore.Entry.
 */
final class AndroidUnifiedNodeCatalog {
    static final String KIND_ROUTER_VPN = "router-vpn";
    static final String KIND_EXTERNAL = "external";
    static final String SORT_CURRENT = "current";
    static final String SORT_LAST_USED = "last-used";
    static final String SORT_LATENCY = "latency";
    static final String SORT_NAME = "name";

    static final class Item {
        final String kind, id, name, endpoint, protocol, expectedPublicIp, location, lastUsedAt;
        final Double latitude, longitude, latencyMedianMs, latencyP90Ms;
        final int latencySamples, useCount;
        final boolean current;
        final File routerBundle;
        Item(String kind,String id,String name,String endpoint,String protocol,String expectedPublicIp,String location,
             Double latitude,Double longitude,Double latencyMedianMs,Double latencyP90Ms,int latencySamples,int useCount,
             String lastUsedAt,boolean current,File routerBundle){
            this.kind=kind;this.id=id;this.name=name;this.endpoint=endpoint;this.protocol=protocol;
            this.expectedPublicIp=expectedPublicIp;this.location=location;this.latitude=latitude;this.longitude=longitude;
            this.latencyMedianMs=latencyMedianMs;this.latencyP90Ms=latencyP90Ms;this.latencySamples=latencySamples;
            this.useCount=useCount;this.lastUsedAt=lastUsedAt;this.current=current;this.routerBundle=routerBundle;
        }
        boolean isRouterVpn(){return KIND_ROUTER_VPN.equals(kind);}
        boolean hasCoordinates(){return latitude!=null&&longitude!=null&&Double.isFinite(latitude)&&Double.isFinite(longitude)&&latitude>=-90&&latitude<=90&&longitude>=-180&&longitude<=180;}
        boolean hasMeasuredLatency(){return latencySamples>0&&latencyMedianMs!=null&&Double.isFinite(latencyMedianMs)&&latencyMedianMs>0;}
        String subtitle(){
            StringBuilder s=new StringBuilder();
            if(current)s.append("current");
            if(!protocol.isEmpty()){if(s.length()>0)s.append(" • ");s.append(protocol);}
            if(!endpoint.isEmpty()){if(s.length()>0)s.append(" • ");s.append(endpoint);}
            if(hasMeasuredLatency()){if(s.length()>0)s.append(" • ");s.append(String.format(Locale.US,"%.1f ms median",latencyMedianMs));}
            if(!lastUsedAt.isEmpty()){if(s.length()>0)s.append(" • ");s.append("last used ").append(lastUsedAt);}
            if(!location.isEmpty()){if(s.length()>0)s.append(" • ");s.append(location);}
            if(KIND_EXTERNAL.equals(kind)&&!expectedPublicIp.isEmpty()){if(s.length()>0)s.append(" • ");s.append("exit ").append(expectedPublicIp);}
            return s.toString();
        }
        @Override public String toString(){String sub=subtitle();return name+(sub.isEmpty()?"":" — "+sub);}
    }

    private final AndroidNodeStore nodes;
    private final AndroidStandardExitStore exits;
    AndroidUnifiedNodeCatalog(AndroidNodeStore nodes,AndroidStandardExitStore exits){this.nodes=nodes;this.exits=exits;}

    List<Item> list() throws Exception { return list(SORT_CURRENT); }

    List<Item> list(String order) throws Exception {
        List<Item> out=new ArrayList<>();
        String active=nodes.activeId();
        for(AndroidNodeStore.Node node:nodes.list())out.add(routerItem(node,node.id.equals(active)));
        for(AndroidStandardExitStore.Entry exit:exits.list()){
            // The custom-exit store currently has no real coordinate/latency
            // metadata. Keep these nodes list-only until the user supplies real
            // coordinates or a measured value; never infer them from an IP.
            out.add(new Item(KIND_EXTERNAL,exit.id,exit.name,exit.server+":"+exit.serverPort,
                    exit.protocol,exit.expectedPublicIp,"",null,null,null,null,0,0,"",false,null));
        }
        Collections.sort(out,comparator(order));
        return out;
    }

    Item lowestLatency() throws Exception {
        List<Item> measured=new ArrayList<>();
        for(Item item:list(SORT_LATENCY))if(item.hasMeasuredLatency())measured.add(item);
        // Automatic fastest-node choice is only meaningful when at least two
        // usable nodes have real measurements; otherwise keep the current node.
        return measured.size()>=2?measured.get(0):null;
    }

    private static Comparator<Item> comparator(String requested){
        String order=requested==null?SORT_CURRENT:requested.trim().toLowerCase(Locale.ROOT);
        Comparator<Item> name=Comparator.comparing((Item i)->i.name.toLowerCase(Locale.ROOT)).thenComparing(i->i.id);
        if(SORT_NAME.equals(order))return name;
        if(SORT_LATENCY.equals(order)||"lowest-latency".equals(order))return (a,b)->{
            if(a.hasMeasuredLatency()!=b.hasMeasuredLatency())return a.hasMeasuredLatency()?-1:1;
            if(a.hasMeasuredLatency()){
                int c=Double.compare(a.latencyMedianMs,b.latencyMedianMs);if(c!=0)return c;
                double ap=a.latencyP90Ms==null?Double.POSITIVE_INFINITY:a.latencyP90Ms;
                double bp=b.latencyP90Ms==null?Double.POSITIVE_INFINITY:b.latencyP90Ms;
                c=Double.compare(ap,bp);if(c!=0)return c;
            }
            return name.compare(a,b);
        };
        if(SORT_LAST_USED.equals(order)||"recent".equals(order))return (a,b)->{
            int c=b.lastUsedAt.compareTo(a.lastUsedAt);if(c!=0)return c;
            c=Integer.compare(b.useCount,a.useCount);if(c!=0)return c;
            return name.compare(a,b);
        };
        return (a,b)->{
            if(a.current!=b.current)return a.current?-1:1;
            int c=b.lastUsedAt.compareTo(a.lastUsedAt);if(c!=0)return c;
            return name.compare(a,b);
        };
    }

    private static Item routerItem(AndroidNodeStore.Node node,boolean current) throws Exception {
        JSONObject profile=selectedProfile(node.file);
        String location=profile==null?"":profile.optString("location","").trim();
        String lastUsed=profile==null?"":profile.optString("last_used_at","").trim();
        Double latitude=number(profile,"latitude"),longitude=number(profile,"longitude"),latency=number(profile,"latency_median_ms"),p90=number(profile,"latency_p90_ms");
        int samples=profile==null?0:Math.max(0,profile.optInt("latency_samples",0));
        int useCount=profile==null?0:Math.max(0,profile.optInt("use_count",0));
        return new Item(KIND_ROUTER_VPN,node.id,node.name,node.endpoint,"Router VPN","",location,latitude,longitude,latency,p90,samples,useCount,lastUsed,current,node.file);
    }

    static JSONObject selectedProfile(File file) throws Exception {
        if(file==null||!file.isFile()||file.length()<=0||file.length()>AndroidNodeStore.MAX_BUNDLE)return null;
        byte[] raw;
        try(FileInputStream in=new FileInputStream(file);ByteArrayOutputStream out=new ByteArrayOutputStream()){
            byte[] buf=new byte[8192];int n,total=0;
            while((n=in.read(buf))!=-1){total+=n;if(total>AndroidNodeStore.MAX_BUNDLE)throw new IllegalArgumentException("node bundle is too large");out.write(buf,0,n);}raw=out.toByteArray();
        }
        JSONObject bundle=new JSONObject(new String(raw,StandardCharsets.UTF_8));
        JSONArray profiles=bundle.optJSONArray("routerProfiles");if(profiles==null||profiles.length()==0)return null;
        String wanted=bundle.optString("selectedRouterID","").trim();
        for(int i=0;i<profiles.length();i++){JSONObject p=profiles.optJSONObject(i);if(p!=null&&wanted.equals(p.optString("id","")))return p;}
        return profiles.optJSONObject(0);
    }

    private static Double number(JSONObject value,String key){if(value==null||!value.has(key))return null;double n=value.optDouble(key,Double.NaN);return Double.isFinite(n)?n:null;}
}
