package com.eabusham.routervpn;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

/** Starts one libbox graph and accepts success only after public exit IP proof through its loopback proxy. */
final class AndroidStandardExitRuntime implements AutoCloseable {
    interface Callback{void progress(String message);void finished(boolean ok,String message);}
    private static final long START_TIMEOUT_MS=20000L;
    private final NativeSingBoxController singBox;
    private final AndroidStandardExitController builder;
    private final AndroidDirectStandardExitController directBuilder;
    private final ExecutorService executor=Executors.newSingleThreadExecutor();
    private final AtomicBoolean closed=new AtomicBoolean(false);
    private Future<?> active;

    AndroidStandardExitRuntime(android.content.Context context,NativeSingBoxController singBox){
        this.singBox=singBox;
        this.builder=new AndroidStandardExitController(context);
        this.directBuilder=new AndroidDirectStandardExitController(context);
    }

    synchronized void connect(File entryBundle,AndroidStandardExitStore.Entry exit,Callback cb){ submit(entryBundle,exit,false,cb); }
    synchronized void connectDirect(AndroidStandardExitStore.Entry exit,Callback cb){ submit(null,exit,true,cb); }

    private void submit(File entryBundle,AndroidStandardExitStore.Entry exit,boolean direct,Callback cb){
        if(closed.get()){cb.finished(false,"Android custom-exit runtime is closed.");return;}
        if(active!=null&&!active.isDone()){cb.finished(false,"Another Android custom-exit attempt is running.");return;}
        active=executor.submit(()->run(entryBundle,exit,direct,cb));
    }

    private void run(File entry,AndroidStandardExitStore.Entry exit,boolean direct,Callback cb){
        boolean started=false;
        try{
            String before=singBox.getState();
            if("UP".equals(before)||"STARTING".equals(before)||"STOPPING".equals(before))throw new IllegalStateException("Disconnect the current embedded VPN before custom exit.");
            cb.progress(direct?"Preparing direct "+exit.protocol+" custom exit with strict Android lockdown…":"Preparing WireGuard entry → "+exit.protocol+" custom exit…");
            NativeSingBoxController.SessionInfo session=direct?directBuilder.prepare(exit):builder.prepare(entry,exit);
            if(Thread.currentThread().isInterrupted()||closed.get())throw new InterruptedException("Custom exit cancelled.");
            cb.progress("Starting one Android VpnService custom-exit graph…");
            singBox.start(session);started=true;
            long deadline=System.currentTimeMillis()+START_TIMEOUT_MS;
            while(System.currentTimeMillis()<deadline){
                if(Thread.currentThread().isInterrupted()||closed.get())throw new InterruptedException("Custom exit cancelled.");
                String state=singBox.getState();
                if("UP".equals(state))break;
                if("FAILED".equals(state)||"REVOKED".equals(state))throw new IllegalStateException(nonEmpty(singBox.getError(),"Embedded custom-exit engine entered "+state+"."));
                Thread.sleep(250L);
            }
            if(!"UP".equals(singBox.getState()))throw new IllegalStateException("Embedded custom-exit engine did not reach UP before timeout.");
            cb.progress("Tunnel is UP; proving the exact public custom exit before Connected…");
            String observed=proveExpectedPublicIp(exit.expectedPublicIp);
            cb.finished(true,direct?"Connected: direct "+exit.protocol+" custom exit. Public exit proof passed: "+observed:"Connected: WireGuard entry → "+exit.protocol+" custom exit. Public exit proof passed: "+observed);
        } catch(InterruptedException e){
            Thread.currentThread().interrupt();if(started)singBox.stop();cb.finished(false,"Android custom exit cancelled and disconnected.");
        } catch(Exception e){
            if(started)singBox.stop();cb.finished(false,nonEmpty(e.getMessage(),"Android custom exit failed closed."));
        }
    }

    static String proveExpectedPublicIp(String expected)throws Exception{
        InetAddress wanted=InetAddress.getByName(expected);
        Proxy proxy=new Proxy(Proxy.Type.HTTP,new InetSocketAddress("127.0.0.1",1099));
        String[]providers={"https://api64.ipify.org","https://api.ipify.org"};
        Exception last=null;long deadline=System.currentTimeMillis()+10000L;
        while(System.currentTimeMillis()<deadline){
            for(String endpoint:providers){
                HttpURLConnection c=null;
                try{
                    c=(HttpURLConnection)new URL(endpoint).openConnection(proxy);c.setConnectTimeout(2000);c.setReadTimeout(2000);c.setInstanceFollowRedirects(false);c.setRequestProperty("Accept","text/plain");
                    if(c.getResponseCode()/100!=2)throw new IllegalStateException("Exit proof HTTP "+c.getResponseCode());
                    byte[]raw=readLimited(c.getInputStream(),256);String text=new String(raw,StandardCharsets.US_ASCII).trim();InetAddress seen=InetAddress.getByName(text);
                    if(seen.equals(wanted))return seen.getHostAddress();
                    last=new IllegalStateException("Custom exit reached "+seen.getHostAddress()+", expected "+wanted.getHostAddress()+".");
                }catch(Exception e){last=e;}finally{if(c!=null)c.disconnect();}
            }
            Thread.sleep(250L);
        }
        throw last==null?new IllegalStateException("Custom exit public-IP proof timed out."):last;
    }

    synchronized void disconnect(){if(active!=null&&!active.isDone())active.cancel(true);singBox.stop();}
    @Override public synchronized void close(){if(!closed.compareAndSet(false,true))return;if(active!=null&&!active.isDone())active.cancel(true);executor.shutdownNow();}
    private static byte[] readLimited(InputStream in,int max)throws Exception{try(InputStream input=in;ByteArrayOutputStream out=new ByteArrayOutputStream()){byte[]b=new byte[256];int total=0,n;while((n=input.read(b))!=-1){total+=n;if(total>max)throw new IllegalStateException("Custom exit proof response too large.");out.write(b,0,n);}return out.toByteArray();}}
    private static String nonEmpty(String v,String fallback){return v==null||v.trim().isEmpty()?fallback:v.trim();}
}
