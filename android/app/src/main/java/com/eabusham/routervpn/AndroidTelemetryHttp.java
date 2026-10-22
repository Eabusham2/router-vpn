package com.eabusham.routervpn;

import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/** Literal private HTTP only, over the supplied captured VPN socket factory. */
final class AndroidTelemetryHttp {
    private final AndroidTelemetryIO io;
    private final InetAddress address;
    private final String host,token,expectedNode;
    private final int port;
    private final AndroidTelemetryIO.Check authorize;
    private boolean proved;

    AndroidTelemetryHttp(AndroidTelemetryIO io,String api,String token,String expectedNode)throws Exception{
        this(io,api,token,expectedNode,()->{});
    }
    AndroidTelemetryHttp(AndroidTelemetryIO io,String api,String token,String expectedNode,AndroidTelemetryIO.Check authorize)throws Exception{
        this.io=io;
        this.authorize=authorize;
        URI origin=new URI(AndroidPrivateBenchmarkHttp.requireBase(api));
        address=AndroidNumericAddress.parse(origin.getHost());host=origin.getRawAuthority();port=origin.getPort()>0?origin.getPort():80;
        if(expectedNode==null||!expectedNode.matches("[0-9a-f]{64}"))throw new IllegalStateException("The captured Router node has no exact private proof identity.");
        this.expectedNode=expectedNode;this.token=token==null?"":token;
        if(this.token.length()>4096)throw new IllegalArgumentException("The private benchmark token is too large.");
        for(int i=0;i<this.token.length();i++)if(this.token.charAt(i)<0x21||this.token.charAt(i)>0x7e)throw new IllegalArgumentException("The private benchmark token contains invalid header bytes.");
    }

    double health()throws Exception{
        long started=System.nanoTime();
        Reply reply=request("GET","/health",false,0,65536,false);
        JSONObject value=new JSONObject(new String(reply.body,StandardCharsets.UTF_8));
        if(!value.optBoolean("ok")||!expectedNode.equals(value.optString("node_id"))||!"router-vpn-private-agent-v1".equals(value.optString("proof")))
            throw new IllegalStateException("The captured private API did not prove the exact Router node; no benchmark credentials were sent.");
        io.check();proved=true;return (System.nanoTime()-started)/1000000d;
    }
    AndroidTelemetry.SpeedResult speed(int bytes)throws Exception{
        if(bytes<(1<<20)||bytes>(16<<20))throw new IllegalArgumentException("Private transfer size is outside its bound.");
        health(); // The exact API origin, before either request carries a token.
        if(token.isEmpty())throw new IllegalStateException("The captured Router node has no private benchmark token.");
        long start=System.nanoTime();Reply down=request("GET","/api/benchmark/download?bytes="+bytes,true,0,bytes,true);
        double downMs=(System.nanoTime()-start)/1000000d;
        if(down.bytes!=bytes)throw new IllegalStateException("Private download byte proof mismatch.");
        io.check();start=System.nanoTime();Reply up=request("POST","/api/benchmark/upload",true,bytes,65536,false);
        double upMs=(System.nanoTime()-start)/1000000d;
        JSONObject response=new JSONObject(new String(up.body,StandardCharsets.UTF_8));
        if(response.optLong("bytes",-1)!=bytes)throw new IllegalStateException("Private upload byte proof mismatch.");
        io.check();double mbits=bytes*8d/1000000d;
        return new AndroidTelemetry.SpeedResult(mbits/(downMs/1000d),mbits/(upMs/1000d),downMs,upMs,response.optDouble("server_receive_ms",0),bytes);
    }

    private Reply request(String method,String route,boolean authenticated,int upload,int maximum,boolean discard)throws Exception{
        io.check();if(authenticated&&!proved)throw new IllegalStateException("Private identity proof is required before sending credentials.");
        Socket socket=io.open();
        try{
            socket.connect(new InetSocketAddress(address,port),3000);socket.setSoTimeout(3000);io.check();
            if(authenticated)authorize.run();
            OutputStream out=socket.getOutputStream();
            String headers=method+" "+route+" HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\nCache-Control: no-store\r\nAccept-Encoding: identity\r\n"
                    +(authenticated?"Authorization: Bearer "+token+"\r\n":"")+(upload>0?"Content-Type: application/octet-stream\r\nContent-Length: "+upload+"\r\n":"")+"\r\n";
            out.write(headers.getBytes(StandardCharsets.US_ASCII));
            if(upload>0){byte[] chunk=new byte[65536];new SecureRandom().nextBytes(chunk);for(int remaining=upload;remaining>0;){io.check();int count=Math.min(remaining,chunk.length);out.write(chunk,0,count);remaining-=count;}}
            out.flush();InputStream in=socket.getInputStream();int[] headerBytes={0};
            String status=line(in,headerBytes,16384);if(!status.matches("HTTP/1\\.[01] 200(?: .*)?"))throw new IllegalStateException("The private API returned a non-200 response; redirects are not followed.");
            Map<String,String> fields=new HashMap<>();
            for(String value;(value=line(in,headerBytes,16384)).length()>0;){
                int colon=value.indexOf(':');if(colon<=0||value.charAt(0)==' '||value.charAt(0)=='\t')throw new IllegalStateException("Malformed private HTTP headers.");
                String key=value.substring(0,colon).toLowerCase(Locale.ROOT),content=value.substring(colon+1).trim();
                if(fields.put(key,content)!=null)throw new IllegalStateException("Duplicate private HTTP response header.");
            }
            String transfer=fields.get("transfer-encoding"),length=fields.get("content-length"),encoding=fields.get("content-encoding");
            if(encoding!=null&&!encoding.equalsIgnoreCase("identity"))throw new IllegalStateException("Compressed private benchmark responses are not accepted.");
            if(transfer!=null&&length!=null)throw new IllegalStateException("Ambiguous private HTTP framing.");
            ByteArrayOutputStream body=discard?null:new ByteArrayOutputStream();long total=0;
            if(transfer!=null){
                if(!"chunked".equalsIgnoreCase(transfer))throw new IllegalStateException("Unsupported private HTTP transfer framing.");
                while(true){
                    String size=line(in,new int[]{0},64);if(!size.matches("[0-9a-fA-F]{1,8}"))throw new IllegalStateException("Malformed private HTTP chunk.");
                    long count=Long.parseLong(size,16);if(count>maximum-total)throw new IllegalStateException("Private HTTP body exceeds its bound.");
                    if(count==0){if(!line(in,new int[]{0},16384).isEmpty())throw new IllegalStateException("Private HTTP trailers are not accepted.");break;}
                    copy(in,body,count);total+=count;
                    if(!line(in,new int[]{0},2).isEmpty())throw new IllegalStateException("Malformed private HTTP chunk terminator.");
                }
            }else if(length!=null){
                if(!length.matches("0|[1-9][0-9]{0,8}"))throw new IllegalStateException("Malformed private HTTP content length.");
                total=Long.parseLong(length);if(total>maximum)throw new IllegalStateException("Private HTTP body exceeds its bound.");copy(in,body,total);
            }else{
                byte[] buffer=new byte[65536];for(int count;(count=in.read(buffer))!=-1;){io.check();total+=count;if(total>maximum)throw new IllegalStateException("Private HTTP body exceeds its bound.");if(body!=null)body.write(buffer,0,count);}
            }
            io.check();return new Reply(body==null?null:body.toByteArray(),total);
        }finally{io.release(socket);}
    }
    private void copy(InputStream input,ByteArrayOutputStream body,long count)throws Exception{
        byte[] buffer=new byte[65536];while(count>0){io.check();int n=input.read(buffer,0,(int)Math.min(count,buffer.length));if(n<0)throw new IllegalStateException("Truncated private HTTP body.");if(n==0)continue;if(body!=null)body.write(buffer,0,n);count-=n;}
    }
    private String line(InputStream input,int[] total,int maximum)throws Exception{
        ByteArrayOutputStream out=new ByteArrayOutputStream();boolean carriage=false;
        while(true){io.check();int c=input.read();if(c<0||++total[0]>maximum)throw new IllegalStateException("Truncated or oversized private HTTP framing.");
            if(carriage){if(c!='\n')throw new IllegalStateException("Private HTTP requires CRLF framing.");return out.toString("US-ASCII");}
            if(c=='\r'){carriage=true;continue;}if(c<' '||c>126)throw new IllegalStateException("Invalid private HTTP header byte.");out.write(c);
        }
    }
    private static final class Reply{final byte[] body;final long bytes;Reply(byte[] body,long bytes){this.body=body;this.bytes=bytes;}}
}
