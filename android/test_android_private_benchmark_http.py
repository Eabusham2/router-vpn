#!/usr/bin/env python3
"""Exercise the production hop HTTP boundary with local proxy listeners, no VPN/SDK."""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
JAVA = ROOT / "app/src/main/java/com/eabusham/routervpn"
helper = (JAVA / "AndroidPrivateBenchmarkHttp.java").read_text(encoding="utf-8")
meter = (JAVA / "AndroidSpeedLabHopMeter.java").read_text(encoding="utf-8")
for marker in (
    "AndroidPrivateBenchmarkHttp.open(node.base,route,node.token,method,timeout,proofPort)",
    "AndroidPrivateBenchmarkHttp.requireBase(api)",
    "AndroidProfileSelection.selectedRouterProfile(bundle)",
    "AndroidPrivateFileStore.read(node.file,AndroidNodeStore.MAX_BUNDLE)",
):
    assert marker in meter, f"Shipping hop meter bypasses its shared private boundary: {marker}"
for forbidden in ("openConnection(", "FileInputStream", "private static JSONObject selectedProfile("):
    assert forbidden not in meter, f"Hop meter restored an unsafe duplicate boundary: {forbidden}"
for forbidden in ("InetAddress.getByName", "Proxy.NO_PROXY", "ProxySelector.getDefault"):
    assert forbidden not in helper, f"Private hop HTTP must not resolve or bypass its lane: {forbidden}"

HARNESS = r'''package com.eabusham.routervpn;
import com.sun.net.httpserver.HttpServer;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

public final class PrivateBenchmarkHttpTest {
    private static final String BASE = "http://10.77.0.1:8787";
    private static final String TOKEN = "fixture-node-token";
    private static final AtomicInteger entryCalls = new AtomicInteger();
    private static final AtomicInteger exitCalls = new AtomicInteger();
    private static final AtomicInteger escaped = new AtomicInteger();
    private static final AtomicInteger ambient = new AtomicInteger();
    private static final AtomicReference<Throwable> failure = new AtomicReference<>();
    private static volatile int redirect;
    private static volatile boolean relativeRedirect;
    private static volatile int trapPort;

    interface Checked { void run() throws Exception; }
    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
    private static void bad(Checked action, String name) throws Exception {
        try { action.run(); } catch (IllegalArgumentException | java.net.URISyntaxException expected) { return; }
        throw new AssertionError("Accepted unsafe request: " + name);
    }
    private static HttpURLConnection request(String route, String method, int port) throws Exception {
        return AndroidPrivateBenchmarkHttp.open(BASE, route, TOKEN, method, 2500, port);
    }
    private static HttpServer lane(int port, AtomicInteger calls) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.createContext("/", exchange -> {
            calls.incrementAndGet();
            try {
                String path = exchange.getRequestURI().getPath();
                if ("/escaped".equals(path)) escaped.incrementAndGet();
                check(("Bearer " + TOKEN).equals(exchange.getRequestHeaders().getFirst("Authorization")), "Node token was not sent to the selected lane");
                check("10.77.0.1:8787".equals(exchange.getRequestHeaders().getFirst("Host")), "Hop target changed");
                check("identity".equals(exchange.getRequestHeaders().getFirst("Accept-Encoding")), "Compression was enabled");
                check("no-store".equals(exchange.getRequestHeaders().getFirst("Cache-Control")), "Caching was enabled");
                byte[] uploaded;
                try (InputStream in = exchange.getRequestBody()) { uploaded = in.readAllBytes(); }
                byte[] reply;
                if ("POST".equals(exchange.getRequestMethod())) {
                    check("/api/benchmark/upload".equals(path), "Unexpected authenticated POST path");
                    check(uploaded.length == 16, "Upload bytes were not preserved");
                    reply = "{\"bytes\":16}".getBytes(StandardCharsets.UTF_8);
                } else if ("/api/benchmark/download".equals(path)) {
                    check("bytes=32".equals(exchange.getRequestURI().getRawQuery()), "Download byte limit changed");
                    reply = new byte[32];
                } else {
                    check("/health".equals(path), "Unexpected authenticated GET path");
                    reply = "{\"ok\":true}".getBytes(StandardCharsets.UTF_8);
                }
                int code = redirect == 0 ? 200 : redirect;
                if (redirect != 0) exchange.getResponseHeaders().set("Location", relativeRedirect ? "/escaped" : "http://127.0.0.1:" + trapPort + "/escaped");
                exchange.sendResponseHeaders(code, reply.length);
                exchange.getResponseBody().write(reply);
            } catch (Throwable error) {
                failure.compareAndSet(null, error);
            } finally { exchange.close(); }
        });
        server.start();
        return server;
    }
    public static void main(String[] args) throws Exception {
        for (String base : new String[]{BASE, BASE + "/", "http://192.168.50.133:8787", "http://172.16.0.1", "http://127.0.0.1", "http://[::1]", "http://[fd77:77::1]:8787", "http://[fe80::1]:8787"}) {
            check(AndroidPrivateBenchmarkHttp.requireBase(base).startsWith("http://"), "Valid private origin rejected");
        }
        for (String base : new String[]{"", "http://router.invalid:8787", "http://8.8.8.8", "http://[2001:4860:4860::8888]", "http://0.0.0.0", "http://[::]", "http://224.0.0.1", "http://[ff02::1]", "http://127.1", "http://010.0.0.1", "http://[::ffff:127.0.0.1]", "http://[fe80::1%25wlan0]", "http://user:secret@10.77.0.1", BASE + "/admin", BASE + "/%2e", BASE + "?next=public", BASE + "#fragment", "https://10.77.0.1", "http://10.77.0.1:0", "http://10.77.0.1:65536", "http://10.77.0.1:"}) {
            bad(() -> AndroidPrivateBenchmarkHttp.requireBase(base), base);
        }
        for (String route : new String[]{"/admin", "/health?next=1", "/health#fragment", "//example.invalid/health", "/api/benchmark/download?bytes=0", "/api/benchmark/download?bytes=-1", "/api/benchmark/download?bytes=16777217", "/api/benchmark/download?bytes=1&bytes=2", "/api/benchmark/download?bytes=01", "/api/benchmark/download?bytes=99999999999999", "/api/benchmark/download?bytes=1#x"}) {
            bad(() -> request(route, "GET", 1098), route);
        }
        bad(() -> request("/health", "POST", 1098), "method swap");
        bad(() -> request("/api/benchmark/upload", "GET", 1098), "upload method swap");
        for (int port : new int[]{0, 80, 1080, 1100, 65536}) bad(() -> request("/health", "GET", port), "foreign lane " + port);
        for (String token : new String[]{"", " ", "x\r\nInjected: yes", "x\u0000y", "x\u007fy", "x".repeat(4097)}) {
            bad(() -> AndroidPrivateBenchmarkHttp.open(BASE, "/health", token, "GET", 2500, 1098), "unsafe token");
        }
        for (int timeout : new int[]{0, -1, 30001}) bad(() -> AndroidPrivateBenchmarkHttp.open(BASE, "/health", TOKEN, "GET", timeout, 1098), "unbounded timeout");
        for (int bytes : new int[]{1, 16 << 20}) {
            HttpURLConnection c = request("/api/benchmark/download?bytes=" + bytes, "GET", 1098);
            c.disconnect();
        }
        System.out.println("PASS private literal origins, token headers, exact methods/routes and bounds");

        HttpServer trap = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        trapPort = trap.getAddress().getPort();
        trap.createContext("/", e -> { escaped.incrementAndGet(); e.sendResponseHeaders(200, -1); e.close(); });
        trap.start();
        HttpServer entry = null, exit = null;
        ProxySelector before = ProxySelector.getDefault();
        boolean redirectsBefore = HttpURLConnection.getFollowRedirects();
        try {
            entry = lane(1098, entryCalls); exit = lane(1099, exitCalls);
            ProxySelector.setDefault(new ProxySelector() {
                public List<Proxy> select(URI uri) { ambient.incrementAndGet(); throw new AssertionError("Ambient proxy must not be consulted"); }
                public void connectFailed(URI uri, SocketAddress address, java.io.IOException error) { throw new AssertionError(error); }
            });
            HttpURLConnection.setFollowRedirects(true);
            for (int port : new int[]{1098, 1099}) {
                AtomicInteger own = port == 1098 ? entryCalls : exitCalls;
                AtomicInteger other = port == 1098 ? exitCalls : entryCalls;
                int otherBefore = other.get();
                for (String route : new String[]{"/health", "/api/benchmark/download?bytes=32", "/api/benchmark/upload"}) {
                    String method = route.endsWith("/upload") ? "POST" : "GET";
                    int calls = own.get();
                    HttpURLConnection c = request(route, method, port);
                    try {
                        check(!c.getInstanceFollowRedirects() && !c.getUseCaches(), "Private request relaxed redirect/cache policy");
                        if ("POST".equals(method)) {
                            c.setDoOutput(true); c.setFixedLengthStreamingMode(16);
                            try (var out = c.getOutputStream()) { out.write(new byte[16]); }
                        }
                        check(c.getResponseCode() == 200, "Valid local lane request failed");
                        try (InputStream in = c.getInputStream()) {
                            byte[] body = in.readAllBytes();
                            if (route.contains("download")) check(body.length == 32, "Download bytes changed");
                            if ("POST".equals(method)) check(new String(body, StandardCharsets.UTF_8).equals("{\"bytes\":16}"), "Upload acknowledgement changed");
                        }
                    } finally { c.disconnect(); }
                    check(own.get() == calls + 1 && other.get() == otherBefore, "Request used the wrong hop lane");
                }
                for (int code : new int[]{301, 302, 303, 307, 308}) {
                    for (boolean relative : new boolean[]{false, true}) {
                        redirect = code; relativeRedirect = relative;
                        int calls = own.get();
                        HttpURLConnection c = request("/health", "GET", port);
                        try { check(c.getResponseCode() == code, "Private redirect was followed"); }
                        finally { c.disconnect(); }
                        check(own.get() == calls + 1 && other.get() == otherBefore && escaped.get() == 0, "Credentials escaped on redirect");
                    }
                }
                redirect = 0;
            }
            check(ambient.get() == 0, "Ambient proxy affected the exact hop path");
            if (failure.get() != null) throw new AssertionError(failure.get());
            System.out.println("PASS separate entry/exit listeners and real health/download/upload HTTP");
            System.out.println("PASS 20 redirect refusals, no credential forwarding or ambient proxy use");
        } finally {
            ProxySelector.setDefault(before); HttpURLConnection.setFollowRedirects(redirectsBefore);
            if (entry != null) entry.stop(0); if (exit != null) exit.stop(0); trap.stop(0);
        }
        System.out.println("Android private hop HTTP boundary: PASS");
    }
}
'''

for tool in ("javac", "java"):
    assert shutil.which(tool), f"JDK required: {tool} is missing"
with tempfile.TemporaryDirectory(prefix="rvpn-private-hop-http-") as directory:
    root = Path(directory)
    package = root / "com/eabusham/routervpn"
    package.mkdir(parents=True)
    for name in ("AndroidNumericAddress.java", "AndroidPrivateBenchmarkHttp.java"):
        shutil.copy2(JAVA / name, package / name)
    (package / "PrivateBenchmarkHttpTest.java").write_text(HARNESS, encoding="utf-8")
    subprocess.run(["javac", "--release", "17", "--add-modules", "jdk.httpserver", "-d", str(root), *map(str, package.glob("*.java"))], check=True, timeout=30)
    subprocess.run(["java", "--add-modules", "jdk.httpserver", "-cp", str(root), "com.eabusham.routervpn.PrivateBenchmarkHttpTest"], check=True, timeout=30)
