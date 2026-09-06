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
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
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

    static final String SESSION_FILE = "start-layer-relay.json";
    static final int LISTEN_PORT = 18389;
    static final int SERVER_PORT = 8389;
    private static final int MAX_METADATA = 16 * 1024;
    private static final int BUFFER = 32 * 1024;
    private static final int UDP_IDLE_MS = 120_000;

    private static final class Metadata {
        final String targetHost;
        final byte[] key;
        Metadata(String targetHost, byte[] key) { this.targetHost = targetHost; this.key = key; }
    }

    private static final class UdpSession {
        final DatagramSocket upstream;
        final InetSocketAddress peer;
        UdpSession(DatagramSocket upstream, InetSocketAddress peer) { this.upstream = upstream; this.peer = peer; }
    }

    private final VpnService service;
    private final FatalHandler fatalHandler;
    private final String targetHost;
    private final byte[] key;
    private final ExecutorService workers = Executors.newCachedThreadPool();
    private final Map<SocketAddress,UdpSession> udpSessions = new ConcurrentHashMap<>();
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final AtomicBoolean fatalDelivered = new AtomicBoolean(false);
    private ServerSocket tcpListener;
    private DatagramSocket udpListener;

    static AndroidStartLayerRelay startIfConfigured(VpnService service, File sessionDir, FatalHandler fatalHandler) throws Exception {
        File metadataFile = new File(sessionDir, SESSION_FILE).getCanonicalFile();
        if (!metadataFile.getParentFile().equals(sessionDir.getCanonicalFile())) throw new IllegalStateException("Android Start Layer relay metadata escaped its private session directory.");
        if (!metadataFile.exists()) return null;
        Metadata metadata = readMetadata(metadataFile);
        AndroidStartLayerRelay relay = new AndroidStartLayerRelay(service, fatalHandler, metadata);
        try { relay.start(); return relay; }
        catch (Throwable error) { relay.close(); throw error; }
    }

    private AndroidStartLayerRelay(VpnService service, FatalHandler fatalHandler, Metadata metadata) {
        this.service = service;
        this.fatalHandler = fatalHandler;
        this.targetHost = metadata.targetHost;
        this.key = Arrays.copyOf(metadata.key, metadata.key.length);
    }

    private void start() throws Exception {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        tcpListener = new ServerSocket();
        tcpListener.setReuseAddress(false);
        tcpListener.bind(new InetSocketAddress(loopback, LISTEN_PORT), 32);
        udpListener = new DatagramSocket(new InetSocketAddress(loopback, LISTEN_PORT));
        workers.execute(this::tcpLoop);
        workers.execute(this::udpLoop);
    }

    private void tcpLoop() {
        try {
            while (!closed.get()) {
                Socket local = tcpListener.accept();
                workers.execute(() -> handleTCP(local));
            }
        } catch (Throwable error) {
            if (!closed.get()) fail("Android Start Layer TCP relay stopped unexpectedly: " + safe(error));
        }
    }

    private void handleTCP(Socket local) {
        Socket upstream = new Socket();
        try {
            local.setTcpNoDelay(true);
            upstream.setTcpNoDelay(true);
            if (!service.protect(upstream)) throw new IllegalStateException("Android refused to protect the Start Layer TCP upstream socket from the VPN loop.");
            upstream.connect(new InetSocketAddress(targetHost, SERVER_PORT), 10_000);
            final CountDownLatch done = new CountDownLatch(2);
            workers.execute(() -> { try { pump(local, upstream); } finally { done.countDown(); } });
            workers.execute(() -> { try { pump(upstream, local); } finally { done.countDown(); } });
            done.await();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        } catch (Throwable ignored) {
            // Per-flow connection failures are surfaced by the owning libbox
            // path proof. They do not make the listener itself untrustworthy.
        } finally {
            try { local.close(); } catch (Throwable ignored) { }
            try { upstream.close(); } catch (Throwable ignored) { }
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
        if (!service.protect(upstream)) { upstream.close(); throw new IllegalStateException("Android refused to protect the Start Layer UDP upstream socket from the VPN loop."); }
        upstream.connect(new InetSocketAddress(targetHost, SERVER_PORT));
        upstream.setSoTimeout(UDP_IDLE_MS);
        UdpSession session = new UdpSession(upstream, peer);
        UdpSession existing = udpSessions.putIfAbsent(peer, session);
        if (existing != null && !existing.upstream.isClosed()) { upstream.close(); return existing; }
        if (existing != null) udpSessions.put(peer, session);
        workers.execute(() -> readUdpReplies(peer, session));
        return session;
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
            session.upstream.close();
        }
    }

    private void whitenDatagram(byte[] payload) {
        for (int i = 0; i < payload.length; i++) payload[i] = (byte) (payload[i] ^ key[i % key.length]);
    }

    private void fail(String message) {
        if (fatalHandler != null && fatalDelivered.compareAndSet(false, true)) fatalHandler.failed(message);
    }

    @Override public void close() {
        if (!closed.compareAndSet(false, true)) return;
        try { if (tcpListener != null) tcpListener.close(); } catch (Throwable ignored) { }
        try { if (udpListener != null) udpListener.close(); } catch (Throwable ignored) { }
        for (UdpSession session : udpSessions.values()) try { session.upstream.close(); } catch (Throwable ignored) { }
        udpSessions.clear();
        workers.shutdownNow();
        Arrays.fill(key, (byte) 0);
    }

    private static Metadata readMetadata(File file) throws Exception {
        if (!file.isFile() || file.length() <= 0 || file.length() > MAX_METADATA) throw new IllegalStateException("Android Start Layer relay metadata is missing or oversized.");
        byte[] bytes = readLimited(file, MAX_METADATA);
        JSONObject root = new JSONObject(new String(bytes, StandardCharsets.UTF_8));
        if (root.optInt("version", 0) != 1 || root.optInt("listen_port", 0) != LISTEN_PORT || root.optInt("target_port", 0) != SERVER_PORT) throw new IllegalStateException("Android Start Layer relay metadata version/ports are invalid.");
        String host = root.optString("target_host", "").trim();
        if (host.isEmpty() || host.length() > 253 || host.contains("\n") || host.contains("\r") || host.contains("\u0000") || host.contains("/") || host.contains("@")) throw new IllegalStateException("Android Start Layer relay target host is unsafe.");
        if ("127.0.0.1".equals(host) || "::1".equals(host) || "localhost".equalsIgnoreCase(host)) throw new IllegalStateException("Android Start Layer relay target cannot be loopback.");
        byte[] key;
        try { key = Base64.decode(root.optString("key_b64", ""), Base64.DEFAULT); }
        catch (IllegalArgumentException invalid) { throw new IllegalStateException("Android Start Layer relay key is not valid base64.", invalid); }
        if (key.length != 32) throw new IllegalStateException("Android Start Layer relay key must be exactly 32 bytes.");
        return new Metadata(host, key);
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
