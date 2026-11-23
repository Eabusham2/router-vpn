#!/usr/bin/env python3
"""Run the generated native GTK shell with a deferred authenticated loopback controller."""
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
LINUX = ROOT / "client/linux"
PATHS = ("/api/status", "/api/profile/settings", "/api/profile/protection", "/api/home-summary",
         "/api/session", "/api/session/events?after=0", "/api/session/events?after=3")


def build(generated, folder):
    source = generated.read_text()
    entry = "int main(int argc, char **argv) {"
    if source.count(entry) != 1:
        raise ValueError("Canonical GTK executable entry changed")
    code = folder / "periodic-shell.c"
    code.write_text(source.replace(entry, "int original_shell_main(int argc, char **argv) {") +
                    "\n" + (LINUX / "test-shell-periodic.c").read_text())
    binary = folder / "periodic-shell"
    flags = subprocess.check_output(["pkg-config", "--cflags", "--libs", "gtk+-3.0", "libcurl", "json-glib-1.0"], text=True).split()
    subprocess.run(["gcc", "-O1", "-Wall", "-Wextra", "-Werror", "-I" + str(generated.parent),
                    "-I" + str(LINUX), code, "-o", binary, *flags, "-lm", "-pthread"], check=True)
    return binary


def exercise(binary, scenario, folder):
    folder.mkdir()
    secret = secrets.token_hex(32)
    source = "bravo" if scenario == "foreign" else "alpha"
    received = Counter()
    lock = threading.Lock()
    responses = {
        PATHS[0]: {"phase": "failed", "connected": False, "stop_pending": True,
                   "router_id": "previous-connection", "stop_token": "0123456789abcdef0123456789abcdef"},
        PATHS[1]: {"profile_id": source, "auto_require_encrypted": True, "auto_require_obfuscation": True},
        PATHS[2]: {"profile_id": source, "profile_token": "immutable-protection-owner", "kill_switch_policy": "on-connect"},
        PATHS[3]: {"node_id": source, "node_name": "Source Alpha"},
        PATHS[4]: {"proof": "session proof from shell fixture"},
        PATHS[5]: {"events": [{"seq": 1, "message": "full event from shell fixture"}]},
        PATHS[6]: {"events": [{"seq": 8, "message": "incremental event"}]},
    }

    class Endpoint(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.headers.get("Authorization") != "Bearer " + secret or self.path not in responses:
                with lock:
                    received["unauthorized/foreign"] += 1
                self.send_error(403)
                return
            with lock:
                received[self.path] += 1
            if self.path == PATHS[3]:
                (folder / "entered").touch()
                timeout = time.monotonic() + 4
                while not (folder / "release").exists() and time.monotonic() < timeout:
                    time.sleep(0.005)
            body = json.dumps(responses[self.path]).encode()
            try:
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *_):
            pass

    class Controller(ThreadingHTTPServer):
        request_queue_size = 32
        daemon_threads = False
    with Controller(("127.0.0.1", 8788), Endpoint) as server:
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            command = [binary, scenario, folder, secret]
            if not os.environ.get("DISPLAY"):
                command = ["xvfb-run", "-a", *command]
            run = subprocess.run(command, capture_output=True, text=True, timeout=15)
            if run.returncode:
                raise AssertionError(run.stdout + run.stderr)
            print(run.stdout.strip(), flush=True)
        finally:
            (folder / "release").touch()
            server.shutdown()
            thread.join()
    if received != Counter(PATHS):
        raise AssertionError(f"{scenario}: unexpected missing, duplicate, synchronous or unauthorized service reads: {received}")


def main(generated):
    with tempfile.TemporaryDirectory(prefix="routervpn-gtk-periodic-") as temporary:
        folder = Path(temporary)
        binary = build(generated.resolve(), folder)
        subprocess.run([binary, "--globe", ROOT], check=True, timeout=15)
        for scenario in ("original", "foreign", "selection", "generation", "cursor", "shutdown", "destroy"):
            exercise(binary, scenario, folder / scenario)


if __name__ == "__main__":
    main(Path(sys.argv[1]))
