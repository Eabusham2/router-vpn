#!/usr/bin/env python3
"""Run the real Android Speed Lab HTTP methods against deterministic failure doubles.

No Android SDK, public network, VPN permission, or production profile is used.
The doubles fail before headers, during upload and during response reads, when
connection ownership is easiest to lose. The production methods are unmodified.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
JAVA = ROOT / "app/src/main/java/com/eabusham/routervpn"
HARNESS = r'''package com.eabusham.routervpn;
import android.content.Context;
import java.io.*;
import java.lang.reflect.*;
import java.net.*;
import java.util.*;

public final class SpeedLabHttpCleanupTest {
    static String method, scenario;
    static FakeConnection last;
    static final List<String> failures = new ArrayList<>();
    static int cases;

    static final class FakeConnection extends HttpURLConnection {
        int disconnects;
        final ByteArrayOutputStream uploaded = new ByteArrayOutputStream();
        FakeConnection(URL url) { super(url); }
        @Override public void connect() {}
        @Override public boolean usingProxy() { return false; }
        @Override public void disconnect() { disconnects++; }
        @Override public int getResponseCode() throws IOException {
            if ("headers-fail".equals(scenario)) throw new IOException("fixture headers failure");
            if ("http-error".equals(scenario)) return 503;
            if ("redirect".equals(scenario)) return 302;
            return 200;
        }
        @Override public OutputStream getOutputStream() throws IOException {
            if ("output-open-fail".equals(scenario)) throw new IOException("fixture output open failure");
            return new OutputStream() {
                @Override public void write(int b) throws IOException {
                    if ("output-write-fail".equals(scenario)) throw new IOException("fixture output write failure");
                    uploaded.write(b);
                }
            };
        }
        @Override public InputStream getInputStream() throws IOException {
            if ("input-open-fail".equals(scenario)) throw new IOException("fixture input open failure");
            if ("input-read-fail".equals(scenario)) return new InputStream() {
                @Override public int read() throws IOException { throw new IOException("fixture input read failure"); }
            };
            int length = "probe".equals(SpeedLabHttpCleanupTest.method) ? 1 : "download".equals(SpeedLabHttpCleanupTest.method) ? 64 : 2;
            if ("oversized".equals(scenario)) length = "upload".equals(SpeedLabHttpCleanupTest.method) ? 65537 : length + 1;
            if ("truncated".equals(scenario)) length = 0;
            return new ByteArrayInputStream(new byte[length]);
        }
    }

    static void check(boolean condition, String message) {
        if (!condition) failures.add(method + "/" + scenario + ": " + message);
    }
    static void runCase(AndroidSpeedLab engine, String operation, String failure) throws Exception {
        method = operation; scenario = failure; last = null; cases++;
        Method entry = "probe".equals(SpeedLabHttpCleanupTest.method)
            ? AndroidSpeedLab.class.getDeclaredMethod(method)
            : AndroidSpeedLab.class.getDeclaredMethod(method, int.class);
        entry.setAccessible(true);
        Throwable error = null;
        try {
            if ("probe".equals(SpeedLabHttpCleanupTest.method)) entry.invoke(engine);
            else entry.invoke(engine, 64);
        } catch (InvocationTargetException result) { error = result.getCause(); }
        boolean success = "success".equals(scenario);
        check(success ? error == null : error != null, "wrong success/failure result: " + error);
        check(last != null, "did not create a connection");
        if (last == null) return;
        check(last.disconnects == 1, "disconnect called " + last.disconnects + " times, expected exactly once");
        check(!last.getInstanceFollowRedirects(), "redirect following enabled");
        check(!last.getUseCaches(), "response caching enabled");
        check("no-store".equals(last.getRequestProperty("Cache-Control")), "missing no-store request");
        String expected = "upload".equals(SpeedLabHttpCleanupTest.method) ? "/__up" : "/__down";
        check("https".equals(last.getURL().getProtocol()) && "speed.cloudflare.com".equals(last.getURL().getHost()) && expected.equals(last.getURL().getPath()), "fixed HTTPS provider route changed");
        if (success && "upload".equals(SpeedLabHttpCleanupTest.method)) check(last.uploaded.size() == 64, "wrong upload payload size");
    }
    public static void main(String[] args) throws Exception {
        URL.setURLStreamHandlerFactory(protocol -> {
            if (!"https".equals(protocol)) throw new AssertionError("unexpected scheme: " + protocol);
            return new URLStreamHandler() {
                @Override protected URLConnection openConnection(URL url) {
                    if (!"speed.cloudflare.com".equals(url.getHost())) throw new AssertionError("unexpected provider");
                    last = new FakeConnection(url); return last;
                }
            };
        });
        AndroidSpeedLab engine = new AndroidSpeedLab(new Context());
        for (String operation : new String[]{"probe", "download", "upload"}) {
            for (String failure : new String[]{"success", "http-error", "redirect", "headers-fail", "input-open-fail", "input-read-fail", "oversized"}) {
                runCase(engine, operation, failure);
            }
            if (!"upload".equals(operation)) runCase(engine, operation, "truncated");
        }
        runCase(engine, "upload", "output-open-fail");
        runCase(engine, "upload", "output-write-fail");
        if (!failures.isEmpty()) throw new AssertionError(String.join("\n", failures));
        System.out.println("Android Speed Lab HTTP cleanup: PASS (" + cases + " production-method cases)");
    }
}
'''
CONTEXT = """package android.content;
public class Context { public Context getApplicationContext(){return this;} }
"""
JSON = """package org.json;
public class JSONObject { public JSONObject put(String key,Object value){return this;} }
"""
STATE = """package com.eabusham.routervpn;
import android.content.Context;
final class AndroidHomeStateStore {
    static final class Snapshot {
        boolean connected;
        long pathGeneration;
        String sessionId, phase, pathProof, activeNodeId, activeEntryId, activeExitId,
            activeExternalId, activeExternalProtocol, expectedExternalIp, runtimeMode,
            actualBase, logicalMode;
    }
    static Snapshot snapshot(Context context){return new Snapshot();}
}
"""

def main() -> None:
    for tool in ("javac", "java"):
        if shutil.which(tool) is None:
            raise SystemExit(f"{tool} is required for the executable Android HTTP cleanup contract")
    with tempfile.TemporaryDirectory(prefix="routervpn-speed-lab-http-") as tmp:
        root = Path(tmp)
        sources = {
            "android/content/Context.java": CONTEXT,
            "org/json/JSONObject.java": JSON,
            "com/eabusham/routervpn/AndroidHomeStateStore.java": STATE,
            "com/eabusham/routervpn/SpeedLabHttpCleanupTest.java": HARNESS,
            "com/eabusham/routervpn/AndroidSpeedLab.java": (JAVA / "AndroidSpeedLab.java").read_text(encoding="utf-8"),
        }
        for name, content in sources.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        subprocess.run(["javac", "-encoding", "UTF-8", "-d", str(root / "classes"), *map(str, root.rglob("*.java"))], check=True, timeout=60)
        subprocess.run(["java", "-cp", str(root / "classes"), "com.eabusham.routervpn.SpeedLabHttpCleanupTest"], check=True, timeout=30)

if __name__ == "__main__":
    main()
