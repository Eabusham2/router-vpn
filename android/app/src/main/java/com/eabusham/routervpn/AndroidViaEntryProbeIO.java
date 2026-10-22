package com.eabusham.routervpn;

import java.net.InetAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CancellationException;
import javax.net.SocketFactory;

/** All proof and candidate sockets belong to one captured temporary VPN path. */
final class AndroidViaEntryProbeIO implements AndroidPathProbe.Route {
    interface Check { void run() throws Exception; }
    interface Resolver { InetAddress[] resolve(String host) throws Exception; }
    private final Check current;
    private final Resolver resolver;
    private final SocketFactory factory;
    private final Set<Socket> sockets=new HashSet<>();
    private volatile boolean cancelled;
    private Thread worker;

    AndroidViaEntryProbeIO(Check current, Resolver resolver, SocketFactory factory) {
        if(current==null||resolver==null||factory==null)throw new IllegalArgumentException("A captured VPN route is required.");
        this.current=current;this.resolver=resolver;this.factory=factory;
    }
    synchronized void attach() { worker=Thread.currentThread(); }
    boolean cancelled() { return cancelled; }
    public void check() throws Exception {
        if(cancelled||Thread.currentThread().isInterrupted())throw new CancellationException("Via-entry candidate measurement cancelled.");
        current.run();
    }
    public InetAddress[] resolve(String host) throws Exception {
        check();
        InetAddress[] values=resolver.resolve(host);
        check();
        if(values==null||values.length==0||values.length>16)throw new IllegalStateException("The captured VPN resolver returned no bounded candidate addresses.");
        return values.clone();
    }
    public Socket open() throws Exception {
        check();
        Socket socket=factory.createSocket();
        synchronized(this){
            if(cancelled){socket.close();throw new CancellationException("Via-entry candidate measurement cancelled.");}
            sockets.add(socket);
        }
        try{check();return socket;}catch(Exception error){release(socket);throw error;}
    }
    public void release(Socket socket) {
        if(socket==null)return;
        try{socket.close();}catch(Exception ignored){}
        synchronized(this){sockets.remove(socket);}
    }
    void cancel() {
        ArrayList<Socket> owned;Thread running;
        synchronized(this){cancelled=true;owned=new ArrayList<>(sockets);running=worker;}
        for(Socket socket:owned)release(socket);
        if(running!=null)running.interrupt();
    }
    void drain() {
        ArrayList<Socket> owned;
        synchronized(this){owned=new ArrayList<>(sockets);worker=null;}
        for(Socket socket:owned)release(socket);
        // Called by the actual worker only after its resolver/proof/connect has
        // returned. Cancelling a Future alone never authorizes entry teardown.
        Thread.interrupted();
    }
}
