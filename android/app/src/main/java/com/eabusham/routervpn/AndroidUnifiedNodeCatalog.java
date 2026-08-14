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

/**
 * Secret-free product catalog combining linked Router VPN nodes and custom
 * non-Router-VPN exits. The catalog copies only display/runtime-selection
 * metadata; protocol credentials never leave AndroidStandardExitStore.Entry.
 */
final class AndroidUnifiedNodeCatalog {
    static final String KIND_ROUTER_VPN = "router-vpn";
    static final String KIND_EXTERNAL = "external";

    static final class Item {
        final String kind, id, name, endpoint, protocol, expectedPublicIp, location;
        final Double latitude, longitude, latencyMedianMs;
        final File routerBundle;
        Item(String kind,String id,String name,String endpoint,String protocol,String expectedPublicIp,String location,
             Double latitude,Double longitude,Double latencyMedianMs,File routerBundle){
            this.kind=kind;this.id=id;this.name=name;this.endpoint=endpoint;this.protocol=protocol;
            this.expectedPublicIp=expectedPublicIp;this.location=location;this.latitude=latitude;this.longitude=longitude;
            this.latencyMedianMs=latencyMedianMs;this.routerBundle=routerBundle;
        }
        boolean isRouterVpn(){return KIND_ROUTER_VPN.equals(kind);}
        boolean hasCoordinates(){return latitude!=null&&longitude!=null&&Double.isFinite(latitude)&&Double.isFinite(longitude)&&latitude>=-90&&latitude<=90&&longitude>=-180&&longitude<=180;}
        String subtitle(){
            StringBuilder s=new StringBuilder();
            if(!protocol.isEmpty())s.append(protocol);
            if(!endpoint.isEmpty()){if(s.length()>0)s.append(" • ");s.append(endpoint);}
            if(latencyMedianMs!=null&&Double.isFinite(latencyMedianMs)){if(s.length()>0)s.append(" • ");s.append(String.format(java.util.Locale.US,"%.1f ms median",latencyMedianMs));}
            if(!location.isEmpty()){if(s.length()>0)s.append(" • ");s.append(location);}
            if(KIND_EXTERNAL.equals(kind)&&!expectedPublicIp.isEmpty()){if(s.length()>0)s.append(" • ");s.append("exit ").append(expectedPublicIp);}
            return s.toString();
        }
        @Override public String toString(){String sub=subtitle();return name+(sub.isEmpty()?"":" — "+sub);}
    }

    private final AndroidNodeStore nodes;
    private final AndroidStandardExitStore exits;
    AndroidUnifiedNodeCatalog(AndroidNodeStore nodes,AndroidStandardExitStore exits){this.nodes=nodes;this.exits=exits;}

    List<Item> list() throws Exception {
        List<Item> out=new ArrayList<>();
        for(AndroidNodeStore.Node node:nodes.list())out.add(routerItem(node));
        for(AndroidStandardExitStore.Entry exit:exits.list()){
            // The custom-exit store currently has no real coordinate/latency
            // metadata. Keep these nodes list-only until the user supplies real
            // coordinates or a measured value; never infer them from an IP.
            out.add(new Item(KIND_EXTERNAL,exit.id,exit.name,exit.server+":"+exit.serverPort,
                    exit.protocol,exit.expectedPublicIp,"",null,null,null,null));
        }
        Collections.sort(out,Comparator.comparing((Item i)->i.name.toLowerCase(java.util.Locale.ROOT)).thenComparing(i->i.kind).thenComparing(i->i.id));
        return out;
    }

    private static Item routerItem(AndroidNodeStore.Node node) throws Exception {
        JSONObject profile=selectedProfile(node.file);
        String location=profile==null?"":profile.optString("location","").trim();
        Double latitude=number(profile,"latitude"),longitude=number(profile,"longitude"),latency=number(profile,"latency_median_ms");
        String protocol="Router VPN";
        return new Item(KIND_ROUTER_VPN,node.id,node.name,node.endpoint,protocol,"",location,latitude,longitude,latency,node.file);
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
