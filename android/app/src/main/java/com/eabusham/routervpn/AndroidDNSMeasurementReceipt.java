package com.eabusham.routervpn;

import org.json.JSONArray;
import org.json.JSONObject;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/** Typed native receipt; no cache, profile writes or fabricated unavailable scores. */
final class AndroidDNSMeasurementReceipt {
    private static final String[] IDS={"cf4a","cf4b","cf6a","cf6b","g4a","g4b","g6a","g6b","q4a","q4b","q6a","q6b"};
    private static final String[] ADDRESSES={"1.1.1.1","1.0.0.1","2606:4700:4700::1111","2606:4700:4700::1001","8.8.8.8","8.8.4.4","2001:4860:4860::8888","2001:4860:4860::8844","9.9.9.9","149.112.112.112","2620:fe::fe","2620:fe::9"};
    private static final String[] SERVERS={"cloudflare-dns.com","dns.google","dns.quad9.net"};
    static JSONObject validate(String raw,String request,String node,String session,String transport,boolean finalResult)throws Exception{
        if(raw==null||raw.length()>65536)throw invalid();
        JSONObject status=new JSONObject(raw);
        if(integer(status,"schema",1,1)!=1||!request.equals(text(status,"request_id",32))||!node.equals(text(status,"node_id",128))
                ||!session.equals(text(status,"session_id",128))||!transport.equals(text(status,"public_transport",5)))throw invalid();
        boolean complete=bool(status,"complete"),drained=bool(status,"drained");
        String stage=text(status,"stage",32);
        if(!java.util.Arrays.asList("measuring","complete","cancelled","invalidated","draining").contains(stage))throw invalid();
        String failure=optional(status,"failure",256);
        JSONArray rows=status.getJSONArray("results");
        if(rows.length()!=0&&rows.length()!=13||!complete&&rows.length()!=0||!failure.isEmpty()&&rows.length()!=0)throw invalid();
        if(finalResult&&(!complete||!drained||!failure.isEmpty()||!"complete".equals(stage)||rows.length()!=13))throw invalid();
        Set<String> seen=new HashSet<>();
        for(int i=0;i<rows.length();i++){
            JSONObject row=rows.getJSONObject(i);
            String id=text(row,"id",16),kind=text(row,"kind",8),address=text(row,"address",253),protocol=text(row,"transport",5);
            text(row,"name",160);String routeLabel=text(row,"route_label",160),route=text(row,"route",128);
            int port=integer(row,"port",1,65535),samples=integer(row,"samples",0,3),failed=integer(row,"failed",0,3);
            boolean ready=bool(row,"ready");
            if(!seen.add(id)||samples+failed!=3||ready!=(samples==3&&failed==0))throw invalid();
            String name=optional(row,"server_name",253),path=optional(row,"path",2048),reason=optional(row,"failure",256);
            if(ready){Object value=row.get("median_ms");if(!(value instanceof Number)||!Double.isFinite(((Number)value).doubleValue())||((Number)value).doubleValue()<=0||((Number)value).doubleValue()>75000||!reason.isEmpty())throw invalid();}
            else if(row.has("median_ms")||reason.isEmpty())throw invalid();
            if(i==0){
                if(!"selected".equals(id)||!"selected".equals(kind)||!routeLabel.equals("Selected DNS via "+route)||!java.util.Arrays.asList("udp","tcp","tls","https","h3").contains(protocol))throw invalid();
            }else{
                int index=i-1;
                if(!IDS[index].equals(id)||!ADDRESSES[index].equals(address)||!"public".equals(kind)||!"exit".equals(route)||!java.util.Arrays.asList("Current Tor connection","Current external exit").contains(routeLabel)||!transport.equals(protocol)
                        ||port!=("tcp".equals(transport)?53:"tls".equals(transport)?853:443)
                        ||!name.equals("tcp".equals(transport)?"":SERVERS[index/4])||!path.equals("https".equals(transport)?"/dns-query":""))throw invalid();
            }
        }
        return status;
    }
    static String render(JSONObject status)throws Exception{
        if(!status.getBoolean("complete")||!status.getBoolean("drained"))return "Measuring DNS on the captured connection…\nMTU stays paused until all native queries and sockets have drained.";
        if(!status.optString("failure","").isEmpty())return "DNS comparison was discarded: "+status.getString("failure");
        StringBuilder out=new StringBuilder("Complete DNS query time · median of 3 valid answers\nPublic tests include a fresh connection and TLS setup when selected. Selected DNS uses the live captured router with its cache disabled.");
        JSONArray rows=status.getJSONArray("results");
        for(int i=0;i<rows.length();i++){
            JSONObject row=rows.getJSONObject(i);
            String transport=transportName(row.getString("transport"));
            out.append("\n\n").append(row.getString("name")).append(" · ").append(transport).append("\n").append(row.getString("address")).append(':').append(row.getInt("port"));
            out.append("\n").append(row.getString("route_label"));
            if(row.getBoolean("ready"))out.append(String.format(Locale.US,"\n%.1f ms · 3 valid answers",row.getDouble("median_ms")));
            else out.append("\nUnavailable · ").append(row.getString("failure")).append(" (").append(row.getInt("samples")).append("/3 valid answers)");
        }
        return out.toString();
    }
    static String transportName(String value){return "tls".equals(value)?"DoT":"https".equals(value)?"DoH":"h3".equals(value)?"DoH3":value.toUpperCase(Locale.US);}
    static JSONObject publicChoice(JSONObject receipt,String id)throws Exception{
        JSONArray rows=receipt.getJSONArray("results");JSONObject best=null;
        for(int i=1;i<rows.length();i++){
            JSONObject row=rows.getJSONObject(i);
            if(!"public".equals(row.getString("kind"))||!row.getBoolean("ready")||row.getInt("samples")!=3||row.getInt("failed")!=0)continue;
            if(id!=null&&id.equals(row.getString("id")))return new JSONObject(row.toString());
            if(id==null&&(best==null||row.getDouble("median_ms")<best.getDouble("median_ms")))best=row;
        }
        if(id==null&&best!=null)return new JSONObject(best.toString());
        throw new IllegalStateException("No complete public DNS measurement is available for that choice.");
    }
    private static boolean bool(JSONObject value,String key)throws Exception{Object raw=value.get(key);if(!(raw instanceof Boolean))throw invalid();return (Boolean)raw;}
    private static int integer(JSONObject value,String key,int min,int max)throws Exception{Object raw=value.get(key);if(!(raw instanceof Number))throw invalid();double n=((Number)raw).doubleValue();if(!Double.isFinite(n)||n!=Math.floor(n)||n<min||n>max)throw invalid();return (int)n;}
    private static String text(JSONObject value,String key,int max)throws Exception{Object raw=value.get(key);if(!(raw instanceof String))throw invalid();String s=(String)raw;if(s.isEmpty()||s.length()>max||s.matches("(?s).*[\\x00-\\x1f\\x7f].*"))throw invalid();return s;}
    private static String optional(JSONObject value,String key,int max)throws Exception{if(!value.has(key))return "";Object raw=value.get(key);if(!(raw instanceof String))throw invalid();String s=(String)raw;if(s.length()>max||s.matches("(?s).*[\\x00-\\x1f\\x7f].*"))throw invalid();return s;}
    private static IllegalStateException invalid(){return new IllegalStateException("Native DNS results do not match this request, transport and captured connection.");}
    private AndroidDNSMeasurementReceipt(){}
}
