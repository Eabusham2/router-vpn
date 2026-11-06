package com.eabusham.routervpn;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Shared, fail-closed projection of router-profile DNS/MTU intent into native Android backends. */
final class AndroidNativeProfilePolicy {
    private AndroidNativeProfilePolicy() {}

    static String patchWireGuardLikeConfig(JSONObject bundle, String config, int fallbackMtu) throws Exception {
        if (config == null || config.length() == 0 || config.length() > 512 * 1024) {
            throw new IllegalStateException("Native tunnel config size is invalid.");
        }
        if (requiresLibbox(bundle)) throw new IllegalStateException("This saved policy requires the native Libbox WireGuard path; the address-only backend cannot silently ignore it.");
        String dns = selectedPlainUdpDns(bundle);
        int mtu = selectedMtu(bundle, fallbackMtu);
        String normalized = config.replace("\r\n", "\n").replace('\r', '\n');
        String[] lines = normalized.split("\n", -1);
        List<String> out = new ArrayList<>();
        boolean inInterface = false;
        boolean dnsWritten = false;
        boolean mtuWritten = false;
        boolean sawInterface = false;
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
                if (inInterface) {
                    if (!dnsWritten) out.add("DNS = " + dns);
                    if (!mtuWritten) out.add("MTU = " + mtu);
                }
                inInterface = "[Interface]".equalsIgnoreCase(trimmed);
                if (inInterface) {
                    if (sawInterface) throw new IllegalStateException("Multiple native interfaces make policy ownership ambiguous.");
                    sawInterface = true;
                }
                dnsWritten = false;
                mtuWritten = false;
                out.add(line);
                continue;
            }
            if (inInterface && startsKey(trimmed, "DNS")) {
                if (dnsWritten) throw new IllegalStateException("Duplicate native DNS fields are ambiguous.");
                out.add("DNS = " + dns);
                dnsWritten = true;
                continue;
            }
            if (inInterface && startsKey(trimmed, "MTU")) {
                if (mtuWritten) throw new IllegalStateException("Duplicate native MTU fields are ambiguous.");
                out.add("MTU = " + mtu);
                mtuWritten = true;
                continue;
            }
            out.add(line);
        }
        if (!sawInterface) throw new IllegalStateException("Native tunnel config has no [Interface] section.");
        if (inInterface) {
            if (!dnsWritten) out.add("DNS = " + dns);
            if (!mtuWritten) out.add("MTU = " + mtu);
        }
        return String.join("\n", out);
    }

    static String selectedPlainUdpDns(JSONObject bundle) throws Exception {
        JSONObject p = selectedProfile(bundle);
        if (p == null) throw new IllegalStateException("Node bundle has no selected router profile.");
        String mode = p.optString("dns_mode", "home").trim().toLowerCase(Locale.ROOT);
        if (mode.isEmpty()) mode = "home";
        String protocol = p.optString("dns_protocol", "udp").trim().toLowerCase(Locale.ROOT);
        if (protocol.isEmpty()) protocol = "udp";
        String host;
        if ("home".equals(mode)) {
            HomeDNS home=homeDNS(p);
            host=home.host;protocol=home.protocol;
            if(home.port!=53)throw new IllegalStateException("Home DNS port requires the transport-aware Libbox backend.");
        } else if ("fastest".equals(mode)) {
            host = p.optString("fastest_dns_host", "").trim();
            protocol = "udp";
        } else if ("custom".equals(mode)) {
            host = p.optString("dns_host", "").trim();
        } else {
            throw new IllegalStateException("Selected DNS mode '" + mode + "' requires an encrypted/transport-aware resolver. Use an embedded libbox mode on Android; native WG/AWG/Xray address-only DNS would not enforce that protocol.");
        }
        if (!"udp".equals(protocol)) {
            throw new IllegalStateException("Selected DNS protocol '" + protocol + "' cannot be enforced by Android's address-only native VPN DNS API. Use an embedded libbox mode instead of silently downgrading DNS transport.");
        }
        if ("custom".equals(mode) && exactInteger(p, "dns_port", 53, 1, 65535) != 53) {
            throw new IllegalStateException("Native address-only DNS cannot enforce a custom port; use Libbox.");
        }
        if (!isLiteralIp(host)) throw new IllegalStateException("Native Android DNS requires a literal IPv4/IPv6 address; selected value is not an IP.");
        return host;
    }

    /** One Home policy contract for settings, saved profiles and native graphs. */
    static final class HomeDNS {
        final String protocol, host, serverName, path;
        final int port;
        HomeDNS(String protocol,String host,int port,String serverName,String path){this.protocol=protocol;this.host=host;this.port=port;this.serverName=serverName;this.path=path;}
        void apply(JSONObject profile)throws Exception{
            profile.put("dns_mode","home").put("dns_protocol",protocol).put("dns_host",host)
                    .put("dns_port",port).put("dns_server_name",serverName).put("dns_path",path);
        }
    }

    static HomeDNS homeDNS(JSONObject profile)throws Exception{
        return homeDNS(profile,text(profile,"dns_protocol","udp"),text(profile,"dns_host",""),
                exactInteger(profile,"dns_port",0,0,65535),text(profile,"dns_server_name",""),text(profile,"dns_path",""));
    }

    static HomeDNS homeDNS(JSONObject profile,String protocol,String host,int port,String serverName,String path)throws Exception{
        List<String> addresses=new ArrayList<>();
        for(String key:new String[]{"adguard_ipv4","adguard_ipv6"}){
            String value=text(profile,key,"");
            if(!value.isEmpty()){
                requireHomeAddress(value);
                if(value.contains(":")!=key.equals("adguard_ipv6"))throw new IllegalArgumentException("Home AdGuard address family is invalid.");
                addresses.add(value);
            }
        }
        if(addresses.isEmpty())throw new IllegalArgumentException("Home AdGuard address is missing from this node.");
        host=host.trim();if(host.startsWith("[")&&host.endsWith("]"))host=host.substring(1,host.length()-1);
        if(host.isEmpty())host=addresses.get(0);
        requireHomeAddress(host);
        if(!addresses.contains(host))throw new IllegalArgumentException("Home DNS belongs to a different node; choose this node's AdGuard address.");
        String ipv6=stringPolicy(profile,"ipv6_mode","on");
        if(!java.util.Arrays.asList("","on","auto","off").contains(ipv6))throw new IllegalArgumentException("Unknown IPv6 policy.");
        if(ipv6.equals("off")&&host.contains(":"))throw new IllegalArgumentException("IPv6 Home DNS cannot be used while IPv6 is Off.");
        protocol=protocol.trim().toLowerCase(Locale.ROOT);
        if(protocol.isEmpty())protocol="udp";
        if(protocol.equals("dot"))protocol="tls";else if(protocol.equals("doh"))protocol="https";else if(protocol.equals("doh3"))protocol="h3";
        if(!java.util.Arrays.asList("udp","tcp","tls","https","h3").contains(protocol))throw new IllegalArgumentException("Home DNS transport must be UDP, TCP, DoT, DoH or DoH3.");
        if(port<0||port>65535)throw new IllegalArgumentException("Home DNS port must be 1–65535 or zero for the transport default.");
        if(port==0)port=protocol.equals("tls")?853:protocol.equals("https")||protocol.equals("h3")?443:53;
        serverName=serverName.trim();path=path.trim();
        if(protocol.equals("udp")||protocol.equals("tcp")){serverName="";path="";}
        else{
            if(serverName.length()>253||!serverName.matches("(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")||!serverName.matches(".*[A-Za-z].*"))throw new IllegalArgumentException("Encrypted Home DNS requires its exact TLS certificate hostname.");
            if(protocol.equals("tls"))path="";
            else{
                if(path.isEmpty())path="/dns-query";
                if(path.length()>2048||!path.startsWith("/")||path.startsWith("//")||path.matches(".*[\\\\?#].*")||java.util.regex.Pattern.compile("%(?![0-9a-fA-F]{2})").matcher(path).find())throw new IllegalArgumentException("Home DoH requires a local resolver path without a host, query or fragment.");
                for(int i=0;i<path.length();i++)if(path.charAt(i)<=32||path.charAt(i)>=127)throw new IllegalArgumentException("Home DoH path must be ASCII and percent encoded.");
                java.net.URI uri=new java.net.URI(path);
                if(uri.getScheme()!=null||uri.getHost()!=null||uri.getRawQuery()!=null||uri.getRawFragment()!=null)throw new IllegalArgumentException("Home DoH path is invalid.");
            }
        }
        return new HomeDNS(protocol,host,port,serverName,path);
    }

    static void validateHomeDNS(JSONObject profile)throws Exception{
        String mode=stringPolicy(profile,"dns_mode","home");
        if(mode.isEmpty()||mode.equals("home"))homeDNS(profile);
    }

    private static String text(JSONObject profile,String key,String fallback){
        Object value=profile.opt(key);if(value==null)return fallback;
        if(!(value instanceof String))throw new IllegalArgumentException(key+" must be text.");
        return ((String)value).trim();
    }
    private static void requireHomeAddress(String value)throws Exception{
        if(!value.equals(AndroidNumericAddress.canonical(value)))throw new IllegalArgumentException("Home DNS requires a canonical private AdGuard IP address.");
        byte[] bytes=AndroidNumericAddress.parse(value).getAddress();int first=bytes[0]&255,second=bytes[1]&255;
        boolean owned=bytes.length==4?(first==10||first==172&&second>=16&&second<=31||first==192&&second==168):(first&254)==252;
        if(!owned)throw new IllegalArgumentException("Home DNS requires a private AdGuard IP address.");
    }

    static int selectedMtu(JSONObject bundle, int fallback) {
        int base = validMtu(fallback) ? fallback : 1380;
        JSONObject p = selectedProfile(bundle);
        String policy = stringPolicy(p, "mtu_policy", "auto");
        if ("manual".equals(policy) || "fixed".equals(policy)) {
            return exactInteger(p, "manual_mtu", 0, 1280, 9000);
        }
        if ("auto".equals(policy) || "default".equals(policy) || policy.isEmpty()) {
            // A saved effective_mtu without a fresh path/config identity is not
            // a measurement of this session. Keep only the runtime default.
            return base;
        }
        throw new IllegalStateException("Unknown native MTU policy; it was not silently ignored.");
    }

    static JSONObject selectedProfile(JSONObject bundle) {
        return AndroidProfileSelection.selectedRouterProfile(bundle);
    }

    static boolean requiresLibbox(JSONObject bundle) throws Exception {
        JSONObject profile = selectedProfile(bundle);
        if (!AndroidStartLayer.OFF.equals(AndroidStartLayer.selectedMode(bundle))) return true;
        String mtu=stringPolicy(profile,"mtu_policy","auto");
        if ((mtu.isEmpty()||"auto".equals(mtu))&&!booleanPolicy(profile,"jumbo_tun",false)) return true;
        String ipv6 = stringPolicy(profile, "ipv6_mode", "on");
        if (!java.util.Arrays.asList("", "on", "auto", "off").contains(ipv6)) throw new IllegalStateException("Unknown IPv6 policy.");
        if ("off".equals(ipv6) || !booleanPolicy(profile, "home_lan_access", true)
                || booleanPolicy(profile, "daita_enabled", false) || booleanPolicy(profile, "jumbo_tun", false)) return true;
        try { selectedPlainUdpDns(bundle); return false; }
        catch (IllegalStateException needsTransport) { return true; }
    }

    static String stringPolicy(JSONObject profile, String key, String fallback) {
        Object raw = profile.opt(key);
        if (raw == null) return fallback;
        if (!(raw instanceof String)) throw new IllegalStateException(key + " must be a string.");
        return ((String) raw).trim().toLowerCase(Locale.ROOT);
    }

    static boolean booleanPolicy(JSONObject profile, String key, boolean fallback) {
        Object raw = profile.opt(key);
        if (raw == null) return fallback;
        if (!(raw instanceof Boolean)) throw new IllegalStateException(key + " must be a boolean.");
        return (Boolean) raw;
    }

    static int exactInteger(JSONObject profile, String key, int fallback, int min, int max) {
        Object raw = profile.opt(key);
        if (raw == null) raw = fallback;
        if (!(raw instanceof Number)) throw new IllegalStateException(key + " must be an exact integer.");
        double value = ((Number) raw).doubleValue();
        if (!Double.isFinite(value) || value != Math.rint(value) || value < min || value > max) {
            throw new IllegalStateException(key + " is outside the supported range " + min + "–" + max + ".");
        }
        return (int) value;
    }

    private static boolean startsKey(String line, String key) {
        int eq = line.indexOf('=');
        return eq > 0 && key.equalsIgnoreCase(line.substring(0, eq).trim());
    }

    private static boolean validMtu(int mtu) { return mtu >= 1280 && mtu <= 9000; }

    private static String firstNonEmpty(String a, String b) {
        String x = a == null ? "" : a.trim();
        return x.isEmpty() ? (b == null ? "" : b.trim()) : x;
    }

    private static boolean isLiteralIp(String value) {
        try { return value != null && AndroidNumericAddress.parse(value) != null; }
        catch (Exception invalid) { return false; }
    }
}
