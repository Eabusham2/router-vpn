package com.eabusham.routervpn;

import android.net.VpnService;
import android.util.Base64;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * App-private whitening relay for the Android AES+XOR Start Layer.
 *
 * Security remains Shadowsocks 2022 AES-256-GCM. This relay only XOR-whitens
 * the already-authenticated ciphertext with the same derived stream used by the
 * Router VPN server relay. Every upstream socket is protected by VpnService so
 * it cannot route back into the TUN it is helping establish.
 */
final class AndroidStartLayerRelay implements AutoCloseable {
    interface FatalHandler { void failed(String message); }
    interface SocketProtector {
        void protectRelaySocket(Socket socket) throws Exception;
        void protectRelaySocket(DatagramSocket socket) throws Exception;
    }

    static final String SESSION_FILE = "start-layer-relay.json";
    static final int LISTEN_PORT = 18389;
    static final int SERVER_PORT = 8389;
    private static final int MAX_METADATA = 16 * 1024;
    private static final int BUFFER = 32 * 1024;
    private static final int UDP_IDLE_MS = 120_000;
    private static final long CLOSE_TIMEOUT_MS = 1500;

    private static final class Metadata {
        final InetAddress targetAddress;
        final byte[] key;
        Metadata(InetAddress targetAddress, byte[] key) { this.targetAddress = targetAddress; this.key = key; }
    }

    private static final class UdpSession {
        final DatagramSocket upstream;
        final InetSocketAddress peer;
        UdpSession(DatagramSocket upstream, InetSocketAddress peer) { this.upstream = upstream; this.peer = peer; }
    }

    private final VpnService service;
    private final FatalHandler fatalHandler;
    private final InetAddress targetAddress;
    private final byte[] key;
    private final Object admission = new Object();
    private final Set<Socket> tcpSockets = new HashSet<>();
    private final Set<DatagramSocket> udpSockets = new HashSet<>();
    private final ExecutorService workers = Executors.newCachedThreadPool();
    private final Map<SocketAddress,UdpSession> udpSessions = new ConcurrentHashMap<>();
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final AtomicBoolean fatalDelivered = new AtomicBoolean(false);
    private ServerSocket tcpListener;
    private DatagramSocket udpListener;

    static AndroidStartLayerRelay prepareIfConfigured(VpnService service, File sessionDir, FatalHandler fatalHandler) throws Exception {
        File metadataFile = new File(sessionDir, SESSION_FILE).getCanonicalFile();
        if (!metadataFile.getParentFile().equals(sessionDir.getCanonicalFile())) throw new IllegalStateException("Android Start Layer relay metadata escaped its private session directory.");
        if (!metadataFile.exists()) return null;
        Metadata metadata = readMetadata(metadataFile);
        return new AndroidStartLayerRelay(service, fatalHandler, metadata);
    }

    private AndroidStartLayerRelay(VpnService service, FatalHandler fatalHandler, Metadata metadata) {
        this.service = service;
        this.fatalHandler = fatalHandler;
        this.targetAddress = metadata.targetAddress;
        this.key = Arrays.copyOf(metadata.key, metadata.key.length);
    }

    void start() throws Exception {
        synchronized(admission){
            if(closed.get()||tcpListener!=null)throw new IllegalStateException("Start Layer owner cannot restart.");
            InetAddress loopback = AndroidNumericAddress.parse("127.0.0.1");
            tcpListener = new ServerSocket();
            // The previous listener and workers are fully joined before a new
            // owner starts; allow its closed TCP flows to finish TIME_WAIT.
            tcpListener.setReuseAddress(true);
            tcpListener.bind(new InetSocketAddress(loopback, LISTEN_PORT), 32);
            udpListener = new DatagramSocket(new InetSocketAddress(loopback, LISTEN_PORT));
            if(!executeOwned(this::tcpLoop)||!executeOwned(this::udpLoop))throw new IllegalStateException("Start Layer owner stopped during startup.");
        }
    }

    private void tcpLoop() {
        try {
            while (!closed.get()) {
                Socket local = tcpListener.accept();
                if(!retainTCP(local)||!executeOwned(() -> handleTCP(local)))closeTCP(local);
            }
        } catch (Throwable error) {
            if (!closed.get()) fail("Android Start Layer TCP relay stopped unexpectedly: " + safe(error));
        }
    }

    private void handleTCP(Socket local) {
        Socket upstream = new Socket();
        try {
            if(!retainTCP(upstream))return;
            local.setTcpNoDelay(true);
            upstream.setTcpNoDelay(true);
            if (service instanceof SocketProtector) ((SocketProtector) service).protectRelaySocket(upstream);
            else if (!service.protect(upstream)) throw new IllegalStateException("Android refused to protect the Start Layer TCP upstream socket from the VPN loop.");
            if(closed.get())return;
            upstream.connect(new InetSocketAddress(targetAddress, SERVER_PORT), 10_000);
            final CountDownLatch done = new CountDownLatch(2);
            if(!executeOwned(() -> { try { pump(local, upstream); } finally { done.countDown(); } })
                    ||!executeOwned(() -> { try { pump(upstream, local); } finally { done.countDown(); } }))return;
            done.await();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        } catch (Throwable ignored) {
            // Per-flow connection failures are surfaced by the owning libbox
            // path proof. They do not make the listener itself untrustworthy.
        } finally {
            closeTCP(local);
            closeTCP(upstream);
        }
    }

    private void pump(Socket from, Socket to) {
        try {
            InputStream input = from.getInputStream();
            OutputStream output = to.getOutputStream();
            byte[] buffer = new byte[BUFFER];
            long offset = 0;
            for (;;) {
                int count = input.read(buffer);
                if (count < 0) break;
                for (int i = 0; i < count; i++) buffer[i] = (byte) (buffer[i] ^ key[(int) ((offset + i) % key.length)]);
                output.write(buffer, 0, count);
                output.flush();
                offset += count;
            }
            try { to.shutdownOutput(); } catch (Throwable ignored) { }
        } catch (Throwable ignored) { }
    }

    private void udpLoop() {
        byte[] buffer = new byte[65_535];
        try {
            while (!closed.get()) {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                udpListener.receive(packet);
                if (!(packet.getSocketAddress() instanceof InetSocketAddress)) continue;
                InetSocketAddress peer = (InetSocketAddress) packet.getSocketAddress();
                UdpSession session = udpSessions.get(peer);
                if (session == null || session.upstream.isClosed()) session = createUdpSession(peer);
                byte[] payload = Arrays.copyOfRange(packet.getData(), packet.getOffset(), packet.getOffset() + packet.getLength());
                whitenDatagram(payload);
                session.upstream.send(new DatagramPacket(payload, payload.length));
            }
        } catch (Throwable error) {
            if (!closed.get()) fail("Android Start Layer UDP relay stopped unexpectedly: " + safe(error));
        }
    }

    private UdpSession createUdpSession(InetSocketAddress peer) throws Exception {
        DatagramSocket upstream = new DatagramSocket();
        try {
            if(!retainUDP(upstream))throw new IllegalStateException("Start Layer owner stopped before UDP admission.");
            if (service instanceof SocketProtector) ((SocketProtector) service).protectRelaySocket(upstream);
            else if (!service.protect(upstream)) throw new IllegalStateException("Android refused to protect the Start Layer UDP upstream socket from the VPN loop.");
            if(closed.get())throw new IllegalStateException("Start Layer owner stopped during UDP protection.");
            upstream.connect(new InetSocketAddress(targetAddress, SERVER_PORT));
            upstream.setSoTimeout(UDP_IDLE_MS);
            UdpSession session = new UdpSession(upstream, peer);
            synchronized(admission){
                if(closed.get())throw new IllegalStateException("Start Layer owner stopped before UDP publication.");
                UdpSession existing = udpSessions.putIfAbsent(peer, session);
                if(existing!=null&&!existing.upstream.isClosed()){closeUDP(upstream);return existing;}
                if(existing!=null)udpSessions.put(peer,session);
                if(!executeOwned(()->readUdpReplies(peer,session)))throw new IllegalStateException("Start Layer UDP worker was not admitted.");
            }
            return session;
        } catch (Exception failed) { closeUDP(upstream); throw failed; }
    }

    private void readUdpReplies(InetSocketAddress keyPeer, UdpSession session) {
        byte[] buffer = new byte[65_535];
        try {
            while (!closed.get()) {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                session.upstream.receive(packet);
                byte[] payload = Arrays.copyOfRange(packet.getData(), packet.getOffset(), packet.getOffset() + packet.getLength());
                whitenDatagram(payload);
                DatagramPacket local = new DatagramPacket(payload, payload.length, session.peer);
                udpListener.send(local);
            }
        } catch (SocketTimeoutException idle) {
            // Normal bounded idle expiry.
        } catch (SocketException closedSocket) {
            if (!closed.get() && !session.upstream.isClosed()) fail("Android Start Layer UDP session failed: " + safe(closedSocket));
        } catch (Throwable error) {
            if (!closed.get()) fail("Android Start Layer UDP session failed: " + safe(error));
        } finally {
            udpSessions.remove(keyPeer, session);
            closeUDP(session.upstream);
        }
    }

    private void whitenDatagram(byte[] payload) {
        for (int i = 0; i < payload.length; i++) payload[i] = (byte) (payload[i] ^ key[i % key.length]);
    }

    private void fail(String message) {
        if (fatalHandler != null && fatalDelivered.compareAndSet(false, true)) fatalHandler.failed(message);
    }

    private boolean executeOwned(Runnable worker){
        synchronized(admission){
            if(closed.get())return false;
            try{workers.execute(worker);return true;}catch(RejectedExecutionException stopped){return false;}
        }
    }

    private boolean retainTCP(Socket socket){
        synchronized(admission){if(!closed.get()){tcpSockets.add(socket);return true;}}
        closeTCP(socket);return false;
    }

    private boolean retainUDP(DatagramSocket socket){
        synchronized(admission){if(!closed.get()){udpSockets.add(socket);return true;}}
        closeUDP(socket);return false;
    }

    private void closeTCP(Socket socket){
        try{socket.close();synchronized(admission){tcpSockets.remove(socket);}}
        catch(Exception failed){synchronized(admission){tcpSockets.add(socket);}}
    }

    private void closeUDP(DatagramSocket socket){
        try{socket.close();synchronized(admission){udpSockets.remove(socket);}}
        catch(RuntimeException failed){synchronized(admission){udpSockets.add(socket);}}
    }

    @Override public synchronized void close() {
        ArrayList<Socket> tcp;
        ArrayList<DatagramSocket> udp;
        synchronized(admission){
            closed.set(true);
            workers.shutdown();
            tcp=new ArrayList<>(tcpSockets);udp=new ArrayList<>(udpSockets);
        }
        try { if (tcpListener != null) tcpListener.close(); } catch (Throwable ignored) { }
        try { if (udpListener != null) udpListener.close(); } catch (Throwable ignored) { }
        for(Socket socket:tcp)closeTCP(socket);
        for(DatagramSocket socket:udp)closeUDP(socket);
        workers.shutdownNow();
        boolean interrupted=false;
        long deadline=System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(CLOSE_TIMEOUT_MS);
        try{
            while(!workers.isTerminated()){
                long remaining=deadline-System.nanoTime();
                if(remaining<=0)break;
                try{workers.awaitTermination(remaining,TimeUnit.NANOSECONDS);}catch(InterruptedException cancelled){interrupted=true;}
            }
            synchronized(admission){
                if(!workers.isTerminated()||!tcpSockets.isEmpty()||!udpSockets.isEmpty()
                        ||tcpListener!=null&&!tcpListener.isClosed()||udpListener!=null&&!udpListener.isClosed()){
                    throw new IllegalStateException("Start Layer teardown has not completed; its owner remains retained.");
                }
                udpSessions.clear();
                Arrays.fill(key,(byte)0);
            }
        }finally{if(interrupted)Thread.currentThread().interrupt();}
    }

    private static Metadata readMetadata(File file) throws Exception {
        if (!file.isFile() || file.length() <= 0 || file.length() > MAX_METADATA) throw new IllegalStateException("Android Start Layer relay metadata is missing or oversized.");
        byte[] bytes = readLimited(file, MAX_METADATA);
        JSONObject root = new JSONObject(new String(bytes, StandardCharsets.UTF_8));
        if (root.optInt("version", 0) != 1 || root.optInt("listen_port", 0) != LISTEN_PORT || root.optInt("target_port", 0) != SERVER_PORT) throw new IllegalStateException("Android Start Layer relay metadata version/ports are invalid.");
        String host = root.optString("target_host", "").trim();
        if (host.isEmpty() || host.length() > 253 || host.contains("\n") || host.contains("\r") || host.contains("\u0000") || host.contains("/") || host.contains("@")) throw new IllegalStateException("Android Start Layer relay target host is unsafe.");
        InetAddress address=AndroidNumericAddress.parse(host);
        if(address.isLoopbackAddress()||address.isAnyLocalAddress()||address.isMulticastAddress())throw new IllegalStateException("Android Start Layer relay requires a captured non-loopback literal endpoint.");
        byte[] key;
        try { key = Base64.decode(root.optString("key_b64", ""), Base64.DEFAULT); }
        catch (IllegalArgumentException invalid) { throw new IllegalStateException("Android Start Layer relay key is not valid base64.", invalid); }
        if (key.length != 32) throw new IllegalStateException("Android Start Layer relay key must be exactly 32 bytes.");
        return new Metadata(address, key);
    }

    private static byte[] readLimited(File file, int max) throws Exception {
        try (FileInputStream input = new FileInputStream(file); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int total = 0;
            for (;;) {
                int count = input.read(buffer);
                if (count < 0) break;
                total += count;
                if (total > max) throw new IllegalStateException("Android Start Layer relay metadata exceeds its safety limit.");
                output.write(buffer, 0, count);
            }
            return output.toByteArray();
        }
    }

    private static String safe(Throwable error) {
        String message = error == null ? "" : error.getMessage();
        if (message == null || message.trim().isEmpty()) return error == null ? "unknown error" : error.getClass().getSimpleName();
        message = message.replace('\n', ' ').replace('\r', ' ').trim();
        return message.length() > 240 ? message.substring(0, 240) : message;
    }

    private AndroidStartLayerRelay() { throw new AssertionError(); }
}
