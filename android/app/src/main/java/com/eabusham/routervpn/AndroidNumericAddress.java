package com.eabusham.routervpn;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

/** Parses literal IPv4/IPv6 without consulting DNS. Compatible with minSdk 24. */
final class AndroidNumericAddress {
    private AndroidNumericAddress() {}

    static InetAddress parse(String input) throws Exception {
        String host=input==null?"":input.trim();
        if(host.startsWith("[")&&host.endsWith("]"))host=host.substring(1,host.length()-1);
        if(host.isEmpty()||host.indexOf('%')>=0)throw new IllegalArgumentException("numeric IP address is required");
        byte[] raw=host.indexOf(':')>=0?parseIPv6(host):parseIPv4(host);
        return InetAddress.getByAddress(raw);
    }

    private static byte[] parseIPv4(String value){
        String[] parts=value.split("\\.",-1);
        if(parts.length!=4)throw new IllegalArgumentException("invalid IPv4 literal");
        byte[] out=new byte[4];
        for(int i=0;i<4;i++){
            String part=parts[i];
            if(part.isEmpty()||part.length()>3)throw new IllegalArgumentException("invalid IPv4 literal");
            int n=0;
            for(int j=0;j<part.length();j++){
                char c=part.charAt(j);if(c<'0'||c>'9')throw new IllegalArgumentException("invalid IPv4 literal");
                n=n*10+(c-'0');if(n>255)throw new IllegalArgumentException("invalid IPv4 literal");
            }
            // Reject ambiguous legacy octal-looking spellings such as 001.
            if(part.length()>1&&part.charAt(0)=='0')throw new IllegalArgumentException("ambiguous IPv4 literal");
            out[i]=(byte)n;
        }
        return out;
    }

    private static byte[] parseIPv6(String value){
        if(value.indexOf('.')>=0)throw new IllegalArgumentException("embedded IPv4 IPv6 literals are not accepted");
        int marker=value.indexOf("::");
        if(marker!=value.lastIndexOf("::"))throw new IllegalArgumentException("invalid IPv6 literal");
        List<Integer> left=parseHexGroups(marker>=0?value.substring(0,marker):value);
        List<Integer> right=marker>=0?parseHexGroups(value.substring(marker+2)):new ArrayList<Integer>();
        if(marker<0&&left.size()!=8)throw new IllegalArgumentException("IPv6 literal must contain eight groups without ::");
        if(marker>=0&&left.size()+right.size()>=8)throw new IllegalArgumentException("compressed IPv6 literal has no compressed groups");
        int zeros=marker>=0?8-left.size()-right.size():0;
        byte[] out=new byte[16];int at=0;
        for(int group:left){out[at++]=(byte)(group>>>8);out[at++]=(byte)group;}
        for(int i=0;i<zeros;i++){out[at++]=0;out[at++]=0;}
        for(int group:right){out[at++]=(byte)(group>>>8);out[at++]=(byte)group;}
        if(at!=16)throw new IllegalArgumentException("invalid IPv6 literal");
        return out;
    }

    private static List<Integer> parseHexGroups(String text){
        List<Integer> out=new ArrayList<>();
        if(text.isEmpty())return out;
        String[] parts=text.split(":",-1);
        for(String part:parts){
            if(part.isEmpty()||part.length()>4)throw new IllegalArgumentException("invalid IPv6 group");
            int n=0;
            for(int i=0;i<part.length();i++){
                int digit=Character.digit(part.charAt(i),16);
                if(digit<0)throw new IllegalArgumentException("invalid IPv6 group");
                n=(n<<4)|digit;
            }
            out.add(n);
        }
        return out;
    }
}
