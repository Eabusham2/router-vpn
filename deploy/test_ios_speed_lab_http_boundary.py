#!/usr/bin/env python3
"""Compile the production Swift HTTP boundary and exercise real local redirects."""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading

HARNESS = r'''
@main struct SpeedLabHTTPBoundaryTest {
    static func check(_ condition: Bool, _ message: String) {
        if !condition { fatalError(message) }
    }

    static func response(_ url: String, _ status: Int = 200, _ headers: [String: String] = [:]) -> HTTPURLResponse {
        HTTPURLResponse(url: URL(string: url)!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!
    }

    static func refused(_ response: HTTPURLResponse, _ expected: Int? = 1) {
        do {
            _ = try IOSSpeedLabHTTP.validate(response, expectedBytes: expected)
            fatalError("Accepted an unsafe benchmark response: \(response)")
        } catch { }
    }

    static func main() async throws {
        let down = "https://speed.cloudflare.com/__down?bytes=1"
        for headers in [[String: String](), ["Content-Length": "1"], ["Content-Encoding": "identity", "Content-Length": "1"], ["Content-Encoding": " IDENTITY "]] {
            _ = try IOSSpeedLabHTTP.validate(response(down, 200, headers), expectedBytes: 1)
        }
        _ = try IOSSpeedLabHTTP.validate(response("https://speed.cloudflare.com:443/__up", 200, ["Content-Length": "0"]))
        for url in ["http://speed.cloudflare.com/__down", "https://speed.cloudflare.com:444/__down", "https://foreign.invalid/__down", "https://speed.cloudflare.com.foreign.invalid/__down", "https://user:secret@speed.cloudflare.com/__down", "https://speed.cloudflare.com/__down#fragment", "https://speed.cloudflare.com/other", "https://speed.cloudflare.com/__up"] {
            refused(response(url))
        }
        refused(response(down), nil)
        for status in [206, 301, 302, 303, 307, 308, 400, 500] { refused(response(down, status)) }
        for encoding in ["gzip", "br", "deflate", "gzip, identity"] {
            refused(response(down, 200, ["Content-Encoding": encoding]))
            refused(response("https://speed.cloudflare.com/__up", 200, ["Content-Encoding": encoding]), nil)
        }
        for length in ["", "-1", "+1", "1.0", "NaN", "1,1", "999999999999999999999999999999999999", "2"] {
            refused(response(down, 200, ["Content-Length": length]))
        }
        refused(response("https://speed.cloudflare.com/__up", 200, ["Content-Length": "garbage"]), nil)
        refused(response(down, 200, ["Content-Range": "bytes 0-0/100"]))
        print("PASS exact HTTPS provider, endpoint, identity encoding and byte-length validation")

        let origin = CommandLine.arguments[1]
        let session = IOSSpeedLabHTTP.makeSession(timeout: 2)
        defer { session.invalidateAndCancel() }
        check(session.configuration.urlCache == nil, "Speed Lab restored shared caching")
        check(session.configuration.urlCredentialStorage == nil, "Speed Lab restored ambient credentials")
        check(!session.configuration.httpShouldSetCookies, "Speed Lab enabled cookies")
        let (data, ok) = try await session.data(from: URL(string: origin + "/ok")!)
        check((ok as? HTTPURLResponse)?.statusCode == 200 && data.count == 1, "Normal request failed")
        var redirects = 0
        for status in [301, 302, 303, 307, 308] {
            for location in ["relative", "absolute"] {
                for method in ["GET", "POST"] {
                    var request = URLRequest(url: URL(string: origin + "/redirect/\(status)/\(location)")!)
                    request.httpMethod = method
                    let reply: URLResponse
                    if method == "POST" {
                        (_, reply) = try await session.upload(for: request, from: Data(repeating: 7, count: 16))
                    } else {
                        (_, reply) = try await session.data(for: request)
                    }
                    check((reply as? HTTPURLResponse)?.statusCode == status, "Speed Lab followed a \(status) \(method) redirect")
                    redirects += 1
                }
            }
        }
        check(redirects == 20, "Missing redirect scenarios")
        print("PASS 20 real relative/absolute GET/upload redirect refusals")
    }
}
'''


def run(root: Path) -> None:
    source = (root / "ios/RouterVPN/App/IOSSpeedLab.swift").read_text(encoding="utf-8")
    boundary_start = source.index("private final class IOSSpeedLabHTTP:")
    engine_start = source.index("enum IOSSpeedLabEngine {", boundary_start)
    boundary = source[boundary_start:engine_start]
    engine = source[engine_start:]
    assert engine.count("IOSSpeedLabHTTP.makeSession(timeout:") == 3, "All three phases must use the production HTTP boundary"
    assert engine.count("IOSSpeedLabHTTP.validate(response") == 3, "All three phases must validate their responses"
    assert "URLSession(configuration:" not in engine, "Engine bypasses the shared session policy"
    assert "completionHandler(nil)" in boundary, "Redirect refusal missing"
    swift = shutil.which("swiftc")
    if not swift:
        raise RuntimeError("Swift 6 compiler is required for the iOS Speed Lab HTTP test")

    lock = threading.Lock()
    calls = {"redirect": 0, "escaped": 0, "upload": 0}
    failures: list[str] = []
    trap: ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def handle_request(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            if self.path.startswith("/redirect/"):
                _, _, status, kind = self.path.split("/")
                with lock:
                    calls["redirect"] += 1
                    if self.command == "POST":
                        calls["upload"] += 1
                        if body != bytes([7]) * 16:
                            failures.append("Upload payload changed before the redirect boundary")
                self.send_response(int(status))
                destination = "/escaped" if kind == "relative" else f"http://127.0.0.1:{trap.server_port}/escaped"
                self.send_header("Location", destination)
            else:
                with lock:
                    if self.path != "/ok":
                        calls["escaped"] += 1
                self.send_response(200)
            self.send_header("Content-Length", "1")
            self.end_headers()
            self.wfile.write(b"x")

        do_GET = handle_request
        do_POST = handle_request

        def log_message(self, *_args: object) -> None:
            pass

    origin = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    trap = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (origin, trap)]
    for thread in threads:
        thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="rvpn-ios-speed-http-") as directory:
            path = Path(directory)
            swift_source = path / "BoundaryTest.swift"
            swift_source.write_text("import Foundation\n#if canImport(FoundationNetworking)\nimport FoundationNetworking\n#endif\n" + boundary + HARNESS, encoding="utf-8")
            binary = path / "boundary-test"
            subprocess.run([swift, "-swift-version", "6", "-strict-concurrency=complete", "-warnings-as-errors", "-parse-as-library", str(swift_source), "-o", str(binary)], check=True, timeout=45)
            subprocess.run([str(binary), f"http://127.0.0.1:{origin.server_port}"], check=True, timeout=45)
        assert not failures, failures
        assert calls == {"redirect": 20, "escaped": 0, "upload": 10}, calls
    finally:
        for server in (origin, trap):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=3)
    print("iOS Speed Lab HTTP boundary: PASS (production Swift, local listeners; no physical VPN claim)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    run(parser.parse_args().root)
