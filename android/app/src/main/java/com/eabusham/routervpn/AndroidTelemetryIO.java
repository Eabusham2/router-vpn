package com.eabusham.routervpn;

import java.net.Socket;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CancellationException;
import javax.net.SocketFactory;

/** One bounded probe owns late sockets and failed Close calls until real drain. */
final class AndroidTelemetryIO {
    interface Check { void run() throws Exception; }
    private final Check current;
    private final SocketFactory factory;
    private final long deadline;
    private final Map<Socket,Owned> sockets=new LinkedHashMap<>();
    private volatile boolean cancelled,watchStopped;
    private volatile Throwable failure;
    private Thread worker,watcher;

    private final class Owned {
        final Socket socket;
        boolean closed;
        Owned(Socket socket){this.socket=socket;}
        synchronized void close(){
            if(closed)return;
            try{socket.close();closed=true;synchronized(AndroidTelemetryIO.this){sockets.remove(socket);}}
            catch(Exception error){failure=error;cancelled=true;}
        }
    }
    AndroidTelemetryIO(SocketFactory factory,Check current,long timeoutMs){
        if(factory==null||current==null||timeoutMs<=0||timeoutMs>180000)throw new IllegalArgumentException("A bounded captured telemetry route is required.");
        this.factory=factory;this.current=current;deadline=System.nanoTime()+timeoutMs*1000000L;
    }
    void attach(){
        worker=Thread.currentThread();
        watcher=new Thread(()->{
            while(!watchStopped){
                try{check();}catch(Exception error){if(!watchStopped)cancel(error);}
                if(cancelled)closeOwned();
                try{Thread.sleep(100);}catch(InterruptedException ignored){}
            }
        },"routervpn-telemetry-watch");
        watcher.setDaemon(true);watcher.start();
    }
    void check()throws Exception{
        if(cancelled||Thread.currentThread().isInterrupted())throw new CancellationException(failure==null?"Telemetry cancelled; captured I/O is draining.":safe(failure));
        if(System.nanoTime()>=deadline)throw new IllegalStateException("The bounded telemetry deadline expired.");
        current.run();
    }
    Socket open()throws Exception{
        check();Socket socket=factory.createSocket();
        synchronized(this){sockets.put(socket,new Owned(socket));}
        // A cancelled/late create remains owned even if its first Close fails.
        try{check();return socket;}catch(Exception error){release(socket);throw error;}
    }
    void release(Socket socket){Owned owned;synchronized(this){owned=sockets.get(socket);}if(owned!=null)owned.close();}
    void cancel(){cancel(new CancellationException("Telemetry cancelled; captured I/O is draining."));}
    private void cancel(Throwable reason){
        if(failure==null)failure=reason;cancelled=true;
        Thread root=worker;if(root!=null&&root!=Thread.currentThread())root.interrupt();
        Thread watch=watcher;if(watch!=null&&watch!=Thread.currentThread())watch.interrupt();
    }
    private void closeOwned(){ArrayList<Owned> owned;synchronized(this){owned=new ArrayList<>(sockets.values());}for(Owned socket:owned)socket.close();}
    void drain(){
        // The caller is the actual worker after all dial/read/write calls have
        // returned. Cancellation alone does not release the measurement lease.
        Thread.interrupted();
        while(true){
            closeOwned();synchronized(this){if(sockets.isEmpty())break;}
            try{Thread.sleep(100);}catch(InterruptedException ignored){}
        }
        watchStopped=true;Thread watch=watcher;if(watch!=null){watch.interrupt();while(watch.isAlive())try{watch.join();}catch(InterruptedException ignored){}}
        worker=null;Thread.interrupted();
    }
    Throwable failure(){return failure;}
    synchronized int retainedSockets(){return sockets.size();}
    private static String safe(Throwable error){String value=error.getMessage();return value==null?"Captured telemetry failed.":value;}
}
