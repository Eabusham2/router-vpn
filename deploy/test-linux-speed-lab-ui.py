#!/usr/bin/env python3
"""Exercise the shipping GTK Speed Lab against bounded loopback-only fixtures.

No VPN engine or Internet endpoint is used. Refuse an occupied controller port,
run in a private temporary HOME, and check both the actual UI heartbeat and that
Cancel/Close terminate the owned HTTP request rather than only hiding a dialog.
"""
from __future__ import annotations

import http.server
import json
import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: test-linux-speed-lab-ui.py BUILT_ROUTER_VPN_APP")
    binary = Path(sys.argv[1]).resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise SystemExit("Speed Lab test requires the executable shipping app")
    if shutil.which("xvfb-run") is None:
        raise SystemExit("Speed Lab UI test needs xvfb and xauth")
    state = {"get": 0, "post": 0, "cancelled": 0, "errors": [], "actions": [], "action_cancelled": 0}
    lock = threading.Lock()

    class Server(http.server.ThreadingHTTPServer):
        daemon_threads = True

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def wait_for_response(self, seconds: float, counter: str = "cancelled") -> bool:
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                try:
                    closed = select.select([self.connection], [], [], 0.03)[0] and not self.connection.recv(1, socket.MSG_PEEK)
                except ConnectionResetError:
                    closed = True
                if closed:
                    with lock:
                        state[counter] += 1
                    return False
            return True

        def respond(self, status: int, body: bytes) -> None:
            self.close_connection = True
            try:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                # Rejecting the oversized response deliberately closes the pipe.
                pass

        def do_GET(self):
            fixtures = {
                "/api/status": {"connected": False, "phase": "disconnected"},
                "/api/profiles": {"profiles": [], "selected_id": ""},
                "/api/logical-modes": [{"id": "smart-auto", "name": "SMART AUTO", "available": True}],
                "/api/profile/settings": {}, "/api/home-summary": {},
                "/api/session/events": {"events": [], "last_event_seq": 0},
            }
            path = self.path.split("?", 1)[0]
            if path in fixtures:
                self.respond(200, json.dumps(fixtures[path]).encode())
                return
            if self.path != "/api/speed-lab/options":
                with lock:
                    state["errors"].append(self.path)
                self.respond(404, b"{}")
                return
            with lock:
                index = state["get"]
                state["get"] += 1
            if not self.wait_for_response(6 if index == 6 else 0.35):
                return
            self.respond(200, json.dumps({
                "nodes": [],
                "logical_modes": [{"id": "smart-auto", "name": "SMART AUTO"}],
            }).encode())

        def do_POST(self):
            self.connection.settimeout(3)
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size < 65536:
                    raise ValueError("request exceeds fixture bound")
                body = json.loads(self.rfile.read(size))
            except (ValueError, OSError):
                with lock:
                    state["errors"].append("invalid request body")
                self.respond(400, b"invalid request body")
                return
            action_paths = {"/api/strategy/smart-auto", "/api/disconnect", "/api/emergency-stop", "/api/mtu/retest"}
            if self.path in action_paths and body == {}:
                with lock:
                    state["actions"].append(self.path)
                    connect_number = state["actions"].count("/api/strategy/smart-auto")
                delayed = self.path in {"/api/disconnect", "/api/mtu/retest"} or (self.path == "/api/strategy/smart-auto" and connect_number == 2)
                if self.wait_for_response(6 if delayed else .4, "action_cancelled"):
                    self.respond(200, b'{"ok":true}')
                return
            if self.path != "/api/speed-lab/run" or body != {"scope": "current", "duration_mode": "auto"}:
                with lock:
                    state["errors"].append([self.path, body])
                self.respond(400, b"unexpected test configuration")
                return
            with lock:
                index = state["post"]
                state["post"] += 1
            if not self.wait_for_response(6 if index in (4, 5) else 0.4):
                return
            if index == 1:
                self.respond(409, b"Controller rejected changed path")
            elif index == 2:
                self.respond(200, b"x" * (3 << 20))
            elif index == 3:
                self.respond(200, b"{}")
            else:
                self.respond(200, json.dumps({
                    "ok": True,
                    "summary": {
                        "idle_ms": 12, "download_mbps": 123, "upload_mbps": 45,
                        "download_loaded_ms": 30, "upload_loaded_ms": 40,
                        "download_bufferbloat_ms": 18, "upload_bufferbloat_ms": 28,
                    },
                    "measurement": {},
                }).encode())

    # Binding fails if another controller owns this port. Never stop that owner.
    server = Server(("127.0.0.1", 8788), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="router-vpn-speed-ui-") as home:
            env = dict(os.environ, HOME=home, XDG_CONFIG_HOME=home + "/config",
                       XDG_CACHE_HOME=home + "/cache", GSETTINGS_BACKEND="memory", NO_AT_BRIDGE="1")
            result = subprocess.run([
                "xvfb-run", "-a", "--server-args=-screen 0 1440x1050x24 -nolisten tcp",
                str(binary), "--speed-lab-self-test",
            ], env=env, timeout=50, check=False)
        deadline = time.monotonic() + 2
        while (state["cancelled"] < 3 or state["action_cancelled"] < 3) and time.monotonic() < deadline:
            time.sleep(0.03)
        print("Speed Lab loopback fixture:", json.dumps(state, sort_keys=True))
        if result.returncode != 0:
            return result.returncode
        if state["get"] != 7 or state["post"] != 6 or state["cancelled"] != 3 or state["errors"]:
            raise SystemExit("Speed Lab request ownership/cancellation verification failed")
        expected_actions = ["/api/strategy/smart-auto", "/api/strategy/smart-auto", "/api/disconnect", "/api/emergency-stop", "/api/mtu/retest"]
        if state["actions"] != expected_actions or state["action_cancelled"] != 3:
            raise SystemExit("Linux asynchronous action ordering/cancellation verification failed")
        print("Linux shipping Speed Lab and main-action UI responsiveness and cancellation: PASS")
        return 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


if __name__ == "__main__":
    raise SystemExit(main())
