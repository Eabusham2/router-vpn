package com.eabusham.routervpn;

import android.content.Context;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

/** Starts one libbox graph and accepts success only after public exit IP proof through its loopback proxy. */
final class AndroidStandardExitRuntime implements AutoCloseable {
    interface Callback{void progress(String message);void finished(boolean ok,String message);}
    private static final long START_TIMEOUT_MS=20000L;
    private static final long STOP_TIMEOUT_MS=8000L;
    private final Context context;
    private final NativeSingBoxController singBox;
    private final AndroidStandardExitController builder;
    private final AndroidDirectStandardExitController directBuilder;
    private final ExecutorService executor=Executors.newSingleThreadExecutor();
    private final AtomicBoolean closed=new AtomicBoolean(false);
    private Future<?> active;
    private Thread workerThread;
    private boolean disconnectRequested;
    private boolean revalidationTeardown;
    private boolean teardownInProgress;

    AndroidStandardExitRuntime(Context context,NativeSingBoxController singBox){
        this.context=context.getApplicationContext();
        this.singBox=singBox;
        this.builder=new AndroidStandardExitController(this.context);
        this.directBuilder=new AndroidDirectStandardExitController(this.context);
    }

    synchronized void connect(File entryBundle,AndroidStandardExitStore.Entry exit,Callback cb){ submit(entryBundle,exit,false,cb); }
    synchronized void connectDirect(AndroidStandardExitStore.Entry exit,Callback cb){ submit(null,exit,true,cb); }

    private void submit(File entryBundle,AndroidStandardExitStore.Entry exit,boolean direct,Callback cb){
        if(closed.get()){cb.finished(false,"Android custom-exit runtime is closed.");return;}
        if(teardownInProgress||(active!=null&&!active.isDone())){cb.finished(false,"Another Android custom-exit attempt or teardown is running.");return;}
        String blocked=startBlockedReason();if(!blocked.isEmpty()){cb.finished(false,blocked);return;}
        disconnectRequested=false;revalidationTeardown=false;teardownInProgress=false;
        active=executor.submit(()->run(entryBundle,exit,direct,cb));
    }

    private void run(File entry,AndroidStandardExitStore.Entry exit,boolean direct,Callback cb){
        boolean started=false,sessionStarted=false;
        synchronized(this){workerThread=Thread.currentThread();}
        try{
            synchronized(this){if(disconnectRequested||closed.get()||Thread.currentThread().isInterrupted())throw new InterruptedException("Custom exit cancelled.");}
            String blocked=startBlockedReason();if(!blocked.isEmpty())throw new IllegalStateException(blocked);
            String before=singBox.getState();
            if(!terminal(before))throw new IllegalStateException("Disconnect the current embedded VPN before custom exit.");
            AndroidHomeStateStore.beginExternal(context,exit.id,exit.name,exit.protocol,exit.expectedPublicIp,direct?"external":"wg");sessionStarted=true;
            cb.progress(direct?"Preparing direct "+exit.protocol+" custom exit with strict Android lockdown…":"Preparing WireGuard entry → "+exit.protocol+" custom exit…");
            NativeSingBoxController.SessionInfo session=direct?directBuilder.prepare(exit):builder.prepare(entry,exit);
            if(Thread.currentThread().isInterrupted()||closed.get())throw new InterruptedException("Custom exit cancelled.");
            cb.progress("Starting one Android VpnService custom-exit graph…");
            synchronized(this){
                if(disconnectRequested||closed.get()||Thread.currentThread().isInterrupted())throw new InterruptedException("Custom exit cancelled before engine launch.");
                // A partially published start still owns cleanup when launch throws.
                started=true;singBox.start(session);
            }
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
            synchronized(this){
                if(disconnectRequested||closed.get()||Thread.currentThread().isInterrupted())throw new InterruptedException("Custom exit cancelled before Connected adoption.");
                AndroidHomeStateStore.connectedExternal(context,exit.id,exit.name,exit.protocol,exit.expectedPublicIp,direct?"external":"wg",observed);
            }
            cb.finished(true,direct?"Connected: direct "+exit.protocol+" custom exit. Public exit proof passed: "+observed:"Connected: WireGuard entry → "+exit.protocol+" custom exit. Public exit proof passed: "+observed);
        } catch(InterruptedException error){
            boolean stopped=!started||stopEmbeddedAndProve();
            Thread.currentThread().interrupt();
            boolean suppressHome;
            synchronized(this){suppressHome=revalidationTeardown;teardownInProgress=!stopped;}
            boolean emergency=AndroidHomeStateStore.emergencyDisconnectPending(context);
            if(sessionStarted&&!suppressHome){
                if(emergency){
                    AndroidHomeStateStore.warning(context,stopped
                            ?"Emergency Disconnect requested; Android custom-exit graph stopped; awaiting remaining runtime teardown."
                            :"Emergency Disconnect requested; Android custom-exit teardown was not proved; runtime ownership retained.");
                }else if(stopped){
                    AndroidHomeStateStore.disconnected(context);
                }else{
                    AndroidHomeStateStore.warning(context,"Android custom-exit cancellation could not prove embedded engine teardown; runtime ownership retained.");
                }
            }
            cb.finished(false,stopped?"Android custom exit cancelled and disconnected.":"Android custom exit cancellation incomplete; embedded engine did not prove teardown.");
        } catch(Exception error){
            boolean stopped=!started||stopEmbeddedAndProve();
            boolean suppressHome;
            synchronized(this){suppressHome=revalidationTeardown;teardownInProgress=!stopped;}
            String message=nonEmpty(error.getMessage(),"Android custom exit failed closed.");
            if(!stopped)message+=" Embedded engine teardown was not proved; runtime ownership retained.";
            if(sessionStarted&&!suppressHome){
                boolean emergency=AndroidHomeStateStore.emergencyDisconnectPending(context);
                if(emergency) AndroidHomeStateStore.warning(context,"Emergency Disconnect requested; "+message);
                else if(stopped) AndroidHomeStateStore.failed(context,message);
                else AndroidHomeStateStore.warning(context,message);
            }
            cb.finished(false,message);
        }finally{
            synchronized(this){workerThread=null;}
        }
    }

    private String startBlockedReason(){
        AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(context);
        if(home.connected)return "Disconnect the current Router VPN or custom-exit session before starting another custom exit.";
        AndroidRuntimeRegistry engines=AndroidRuntimeRegistry.get(context);
        boolean failedMarkerOnly=AndroidVpnMutationGuard.failedSessionHasNoLiveEngine(context,engines);
        if(engines.orchestrator.isRunning()||(!failedMarkerOnly&&engines.orchestrator.isActive())||engines.multihop.isActiveOrTransitioning()
                ||engines.wireGuard.getState()!=com.wireguard.android.backend.Tunnel.State.DOWN
                ||engines.amneziaWG.getState()!=org.amnezia.awg.backend.Tunnel.State.DOWN
                ||runtimeBusy(engines.xray.getState()))return "Wait for the current Router VPN transition to finish or disconnect before starting a custom exit.";
        return "";
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
                }catch(Exception error){last=error;}finally{if(c!=null)c.disconnect();}
            }
            Thread.sleep(250L);
        }
        throw last==null?new IllegalStateException("Custom exit public-IP proof timed out."):last;
    }

    synchronized boolean isActiveOrTransitioning(){
        if(teardownInProgress)return true;
        Future<?> task=active;
        if(task!=null&&!task.isDone())return true;
        String state=singBox.getState();
        if(state==null)return true;
        String normalized=state.trim().toUpperCase(Locale.ROOT);
        if(!terminal(normalized))return true;
        AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(context);
        if(!"external".equals(home.logicalMode))return false;
        String phase=home.phase==null?"":home.phase.trim().toLowerCase(Locale.ROOT);
        return home.connected||!("off".equals(phase)||"disconnected".equals(phase)||"failed".equals(phase));
    }

    void disconnect(){
        boolean emergency=AndroidHomeStateStore.emergencyDisconnectPending(context);
        synchronized(this){
            AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(context);
            boolean owns="external".equals(home.logicalMode)||singBox.getMode().startsWith("standard-");
            if(!owns)return;
            if(!emergency)AndroidHomeStateStore.beginPathRevalidation(context,"Android custom-exit disconnect requested; retaining runtime ownership until embedded teardown is proved.");
            disconnectRequested=true;revalidationTeardown=false;teardownInProgress=true;
            if(workerThread!=null)workerThread.interrupt();
        }
        boolean stopped=stopEmbeddedAndProve();
        synchronized(this){teardownInProgress=!stopped;}
        if(!stopped){
            AndroidHomeStateStore.warning(context,emergency
                    ?"Emergency Disconnect requested; Android custom-exit teardown was not proved; runtime ownership retained."
                    :"Android custom-exit disconnect did not prove embedded engine teardown; runtime ownership retained.");
            throw new IllegalStateException("Android custom-exit teardown did not reach DOWN/FAILED/REVOKED before timeout.");
        }
        if(emergency){
            AndroidHomeStateStore.warning(context,"Emergency Disconnect requested; Android custom-exit graph stopped; awaiting remaining runtime teardown.");
        }else{
            AndroidHomeStateStore.disconnected(context);
        }
    }

    /** Tear down this owner's runtime without changing Home state; revalidation owns the failed-state adoption. */
    void failClosedForRevalidation(){
        synchronized(this){disconnectRequested=true;revalidationTeardown=true;teardownInProgress=true;if(workerThread!=null)workerThread.interrupt();}
        boolean stopped=stopEmbeddedAndProve();
        synchronized(this){teardownInProgress=!stopped;}
        if(!stopped)throw new IllegalStateException("Android custom-exit revalidation teardown did not reach a terminal state.");
    }

    @Override public void close(){
        boolean owns;
        synchronized(this){
            if(!closed.compareAndSet(false,true))return;
            disconnectRequested=true;revalidationTeardown=true;teardownInProgress=true;
            if(workerThread!=null)workerThread.interrupt();
            AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(context);
            owns="external".equals(home.logicalMode)||singBox.getMode().startsWith("standard-");
        }
        if(owns&&runtimeBusy(singBox.getState()))stopEmbeddedAndProve();
        synchronized(this){teardownInProgress=owns&&runtimeBusy(singBox.getState());}
        // Queued attempts must observe closed and complete normally; cancelling
        // their Future would claim completion before worker cleanup finished.
        executor.shutdown();
    }

    private boolean stopEmbeddedAndProve(){
        boolean interrupted=Thread.interrupted();
        try{
            singBox.stop();
            long deadline=System.currentTimeMillis()+STOP_TIMEOUT_MS;
            while(System.currentTimeMillis()<deadline){
                if(terminal(singBox.getState()))return true;
                try{Thread.sleep(150L);}catch(InterruptedException error){interrupted=true;}
            }
            return terminal(singBox.getState());
        }catch(RuntimeException error){
            // Neither a failed stop request nor a failed state read proves DOWN.
            return false;
        }finally{if(interrupted)Thread.currentThread().interrupt();}
    }

    private static boolean terminal(String state){
        if(state==null)return false;
        String normalized=state.trim().toUpperCase(Locale.ROOT);
        return "DOWN".equals(normalized)||"FAILED".equals(normalized)||"REVOKED".equals(normalized);
    }
    private static boolean runtimeBusy(String state){return !terminal(state);}
    private static byte[] readLimited(InputStream in,int max)throws Exception{try(InputStream input=in;ByteArrayOutputStream out=new ByteArrayOutputStream()){byte[]b=new byte[256];int total=0,n;while((n=input.read(b))!=-1){total+=n;if(total>max)throw new IllegalStateException("Custom exit proof response too large.");out.write(b,0,n);}return out.toByteArray();}}
    private static String nonEmpty(String value,String fallback){return value==null||value.trim().isEmpty()?fallback:value.trim();}
}
