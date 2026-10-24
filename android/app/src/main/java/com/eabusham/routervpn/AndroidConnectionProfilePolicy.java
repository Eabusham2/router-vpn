package com.eabusham.routervpn;

import org.json.JSONArray;
import org.json.JSONObject;
import java.util.Arrays;
import java.util.Iterator;

/** Bounded, non-secret choices saved by connection profiles, never runtime proof. */
final class AndroidConnectionProfilePolicy {
    private static final String[] EXTERNAL={"dns_mode","dns_protocol","dns_host","dns_port","dns_server_name","dns_path","fastest_dns_host","fastest_dns_latency_ms","dns_results","dns_bootstrap","ipv6_mode","home_lan_access","home_lan_cidrs","mtu_policy","manual_mtu","start_layer"};
    private static final String[] TOR={"dns_mode","dns_protocol","dns_host","dns_port","dns_server_name","dns_path","ipv6_mode","home_lan_access","home_lan_cidrs","mtu_policy","manual_mtu"};

    static JSONObject router(JSONObject source,String[] keys)throws Exception{return checked(source,keys,false);}
    static JSONObject external(JSONObject source,String protocol)throws Exception{
        if(!AndroidTorProfile.isTor(protocol)&&!AndroidExternalPolicy.supports(protocol))throw new IllegalArgumentException("Unsupported saved external protocol.");
        JSONObject copy=source==null?new JSONObject():new JSONObject(source.toString());
        // A prior path's effective MTU is not a preference or proof for this path.
        copy.remove("effective_mtu");
        JSONObject result=checked(copy,AndroidTorProfile.isTor(protocol)?TOR:EXTERNAL,true);
        if(!AndroidTorProfile.isTor(protocol))AndroidExternalPolicy.checkPolicy(result);
        return result;
    }

    private static JSONObject checked(JSONObject source,String[] allowed,boolean external)throws Exception{
        if(source==null||source.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8).length>64*1024)throw new IllegalArgumentException("Connection policy is missing or oversized.");
        only(source,allowed);
        for(Iterator<String> keys=source.keys();keys.hasNext();){
            String key=keys.next();Object value=source.get(key);
            if(Arrays.asList("home_lan_access","kill_switch","base_fallback","auto_require_encrypted","auto_require_obfuscation","daita_enabled","jumbo_tun","socks_enabled","auto_connect").contains(key)){
                if(!(value instanceof Boolean))throw new IllegalArgumentException("Saved "+key+" must be On or Off.");
            }else if("dns_port".equals(key))integer(value,0,65535,key);
            else if("manual_mtu".equals(key))integer(value,0,9000,key);
            else if("fastest_dns_latency_ms".equals(key))number(value,key);
            else if("home_lan_cidrs".equals(key))strings(value,64,128,key);
            else if("dns_results".equals(key))dnsResults(value);
            else if("dns_bootstrap".equals(key))bootstrap(value);
            else text(value,4096,key);
        }
        choice(source,"dns_mode","","home","rescue","custom","fastest","dot","doh","doh3");
        choice(source,"dns_protocol","","udp","tcp","dot","doh","doh3","tls","https","h3");
        choice(source,"ipv6_mode","","on","auto","off");
        choice(source,"kill_switch_policy","","off","on-connect","always");
        choice(source,"base_tunnel","","auto","wg","awg");
        choice(source,"start_layer","","off","aes-256-gcm","aes-256-gcm+xor-whitening");
        if(external)choice(source,"mtu_policy","auto","fixed","manual");
        else choice(source,"mtu_policy","","auto","fixed","manual","default");
        String mtu=source.optString("mtu_policy","auto");
        if("fixed".equals(mtu)||"manual".equals(mtu))integer(source.get("manual_mtu"),external?1280:576,9000,"manual_mtu");
        return new JSONObject(source.toString());
    }

    private static void dnsResults(Object value)throws Exception{
        if(!(value instanceof JSONArray)||((JSONArray)value).length()>128)throw new IllegalArgumentException("Saved DNS results must be a bounded list.");
        JSONArray rows=(JSONArray)value;
        for(int i=0;i<rows.length();i++){
            JSONObject row=rows.getJSONObject(i);only(row,new String[]{"name","address","family","latency_ms","working"});
            for(Iterator<String> keys=row.keys();keys.hasNext();){String key=keys.next();Object v=row.get(key);if("working".equals(key)){if(!(v instanceof Boolean))throw new IllegalArgumentException("DNS result status must be boolean.");}else if("latency_ms".equals(key))number(v,key);else text(v,4096,key);}
        }
    }

    private static void bootstrap(Object value)throws Exception{
        if(!(value instanceof JSONObject)||value.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8).length>16384)throw new IllegalArgumentException("Saved DNS bootstrap is invalid or oversized.");
        JSONObject bootstrap=(JSONObject)value;only(bootstrap,new String[]{"server","query"});
        JSONObject server=bootstrap.getJSONObject("server"),query=bootstrap.getJSONObject("query");
        only(server,new String[]{"type","tag","server","server_port","detour","tls","path"});
        for(Iterator<String> keys=server.keys();keys.hasNext();){String key=keys.next();Object v=server.get(key);
            if("server_port".equals(key))integer(v,1,65535,key);
            else if("tls".equals(key)){
                JSONObject tls=server.getJSONObject(key);only(tls,new String[]{"enabled","server_name","certificate"});
                if(tls.has("enabled")&&!(tls.get("enabled") instanceof Boolean))throw new IllegalArgumentException("DNS TLS enabled must be boolean.");
                if(tls.has("server_name"))text(tls.get("server_name"),4096,"server_name");
                if(tls.has("certificate")){Object cert=tls.get("certificate");if(cert instanceof String)text(cert,16384,"certificate");else strings(cert,8,16384,"certificate");}
            }else text(v,4096,key);
        }
        only(query,new String[]{"server","strategy","timeout","disable_cache","disable_optimistic_cache","rewrite_ttl","client_subnet"});
        for(Iterator<String> keys=query.keys();keys.hasNext();){String key=keys.next();Object v=query.get(key);
            if("disable_cache".equals(key)||"disable_optimistic_cache".equals(key)){if(!(v instanceof Boolean))throw new IllegalArgumentException("DNS query cache choices must be boolean.");}
            else if("rewrite_ttl".equals(key))integer(v,0,4294967295L,key);
            else text(v,4096,key);
        }
        choice(query,"strategy","","prefer_ipv4","prefer_ipv6","ipv4_only","ipv6_only");
        if(!server.has("tag")||!server.getString("tag").equals(query.getString("server")))throw new IllegalArgumentException("DNS bootstrap query lost its selected server.");
    }

    private static void only(JSONObject source,String[] allowed)throws Exception{for(Iterator<String> keys=source.keys();keys.hasNext();){String key=keys.next();if(!Arrays.asList(allowed).contains(key))throw new IllegalArgumentException("Connection profile contains non-whitelisted node data: "+key);}}
    private static void choice(JSONObject source,String key,String... values)throws Exception{if(source.has(key)&&!Arrays.asList(values).contains(source.getString(key)))throw new IllegalArgumentException("Invalid saved "+key+".");}
    private static void text(Object value,int max,String key){if(!(value instanceof String)||((String)value).length()>max||((String)value).indexOf('\0')>=0)throw new IllegalArgumentException("Saved "+key+" requires bounded text.");}
    private static void strings(Object value,int max,int length,String key)throws Exception{if(!(value instanceof JSONArray)||((JSONArray)value).length()>max)throw new IllegalArgumentException("Saved "+key+" requires a bounded list.");JSONArray values=(JSONArray)value;for(int i=0;i<values.length();i++)text(values.get(i),length,key);}
    private static void number(Object value,String key){if(!(value instanceof Number)||!Double.isFinite(((Number)value).doubleValue())||((Number)value).doubleValue()<0)throw new IllegalArgumentException("Saved "+key+" must be a finite nonnegative number.");}
    private static void integer(Object value,long min,long max,String key){number(value,key);double n=((Number)value).doubleValue();if(n<min||n>max||n!=Math.floor(n))throw new IllegalArgumentException("Saved "+key+" is outside its integer range.");}
}
