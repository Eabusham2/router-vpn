#!/usr/bin/env python3
"""Run shipping GTK DNS callbacks, negative controls and real loopback cleanup."""
from __future__ import annotations

import contextlib
import http.server
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import threading
import time
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "client/linux/routervpn-dns-measurement-v1.inc"
FIXTURE = ROOT / "client/linux/test-dns-measurement-v1.c"
SESSION = "a" * 32
TOKEN = "b" * 64


def run(args, *, broken=False, timeout=60):
    result = subprocess.run([str(x) for x in args], text=True, capture_output=True, timeout=timeout)
    if broken:
        if result.returncode == 0 or "DNS panel check failed:" not in result.stdout + result.stderr:
            raise AssertionError("Broken guard did not fail its executable assertion:\n" + result.stdout + result.stderr)
    elif result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    else:
        print(result.stdout.strip(), flush=True)
    return result


@contextlib.contextmanager
def controller(scenario):
    lock = threading.Lock()
    state = dict(request="", admitted=False, cancelled=False, polls=0, failures=[], cancel_ids=[])

    def view(request="", stage="idle", complete=True, drained=True):
        return dict(profile_id="exit-a", profile_token=TOKEN, session_id=SESSION, request_id=request, expires_in_ms=0,
                    status=dict(schema=1, node_id="exit-a", session_id=SESSION, request_id=request,
                                public_transport="tls" if request else "", stage=stage, complete=complete,
                                drained=drained, results=[]))

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass

        def reply(self, code, value):
            raw = json.dumps(value).encode()
            try:
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_GET(self):
            parsed = urllib.parse.urlsplit(self.path)
            if parsed.path == "/api/dns/policy":
                return self.reply(200, dict(profile_id="exit-a", node_kind="external"))
            if parsed.path != "/api/dns/measurement":
                state["failures"].append("Foreign GET")
                return self.reply(400, {})
            request = urllib.parse.parse_qs(parsed.query).get("request_id", [""])[0]
            with lock:
                if not request:
                    return self.reply(200, view())
                if request != state["request"]:
                    return self.reply(404, {"error": "not yet admitted"})
                if state["cancelled"]:
                    state["polls"] += 1
                    # Complete queries still cannot release the UI until the
                    # explicit final native drain receipt arrives.
                    return self.reply(200, view(request, "cancelled", True, state["polls"] >= 3))
                return self.reply(200, view(request, "measuring", False, False))

        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length", "0"))
                assert 0 < length < 4096
                body = json.loads(self.rfile.read(length))
                request = body["request_id"]
                assert len(request) == 32 and all(c in "0123456789abcdef" for c in request)
                assert body["profile_id"] == "exit-a" and body["profile_token"] == TOKEN and body["session_id"] == SESSION
            except (AssertionError, KeyError, ValueError) as error:
                state["failures"].append(str(error) or "Foreign request identity")
                return self.reply(400, {})
            if self.path == "/api/dns/measurement":
                assert body["public_transport"] == "tls"
                if scenario == "early":
                    time.sleep(0.4)
                with lock:
                    if state["cancelled"]:
                        return self.reply(409, {"error": "queued Start tombstoned"})
                    state["request"] = request
                    state["admitted"] = True
                return self.reply(202, view(request, "preparing", False, False))
            if self.path == "/api/dns/measurement/cancel":
                with lock:
                    state["cancel_ids"].append(request)
                    if state["request"] and request != state["request"]:
                        state["failures"].append("Cancellation crossed owners")
                        return self.reply(409, {})
                    state["request"] = request
                    state["cancelled"] = True
                    if not state["admitted"]:
                        return self.reply(200, view(request, "cancelled", True, True))
                    return self.reply(202, view(request, "invalidated", True, False))
            state["failures"].append("Foreign POST")
            return self.reply(400, {})

    class Server(http.server.ThreadingHTTPServer):
        allow_reuse_address = True
        daemon_threads = False

    server = Server(("127.0.0.1", 8788), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
        if state["failures"]:
            raise AssertionError(state["failures"])


def main():
    source = SOURCE.read_text()
    build = (ROOT / "client/linux/build-native-app.sh").read_text()
    product = (ROOT / "client/linux/routervpn-gtk-product-v5.c").read_text()
    composer = (ROOT / "client/linux/apply-async-actions.py").read_text()
    assert 'DNS_INC="$ROOT/client/linux/routervpn-dns-measurement-v1.inc"' in build
    assert '#include "routervpn-dns-measurement-v1.inc"\\n' in build
    assert 'G_CALLBACK(linux_dns_parent_delete_v1)' in build
    assert '    linux_dns_retest_v1(app);' in product
    assert 'linux_dns_retest_v1((App *)data);' in composer
    assert 'post_and_log(s->app, "/api/dns/retest"' in source
    assert 'Retest DNS RTT' not in product
    flags = shlex.split(subprocess.check_output(["pkg-config", "--cflags", "--libs", "gtk+-3.0", "libcurl", "json-glib-1.0"], text=True))
    with tempfile.TemporaryDirectory(prefix="routervpn-gtk-dns-") as temp:
        directory = Path(temp)

        def compile_to(name, text=None, live=False):
            args = ["cc", "-O1", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function", "-I" + str(SOURCE.parent)]
            if text is not None:
                target = directory / (name + ".inc")
                target.write_text(text)
                args.append('-DROUTERVPN_DNS_SOURCE="' + str(target) + '"')
            if live:
                args.append("-DROUTERVPN_DNS_LIVE")
            binary = directory / name
            run([*args, FIXTURE, "-o", binary, *flags, "-lm", "-pthread"])
            return binary

        binary = compile_to("shipping")
        run(["xvfb-run", "-a", binary])
        mutants = {
            "drain": source.replace('(!s->owned || (s->complete && s->drained))', '(!s->owned || s->complete)'),
            "saved-idle": source.replace('if (!routervpn_require_mutation_idle(s->app, "saving measured DNS")) {', 'if (FALSE) {'),
            "profile-owner": source.replace('g_strcmp0(profile, s->profile) != 0 ||', 'FALSE ||'),
            "expiry": source.replace('!s->closing && g_get_monotonic_time() < s->expires_at && linux_dns_settled_v1(s)', '!s->closing && linux_dns_settled_v1(s)'),
            "samples": source.replace('linux_dns_number_v1(row, "samples", &samples) && samples == 3 &&', 'linux_dns_number_v1(row, "samples", &samples) && samples >= 2 &&'),
            "resolver-draft": source.replace('g_strcmp0(linux_dns_string_v1(draft, "host"), linux_dns_string_v1(row, "address")) != 0 ||', 'FALSE ||'),
        }
        for name, altered in mutants.items():
            if altered == source:
                raise AssertionError("Negative did not apply: " + name)
            broken = compile_to(name, altered)
            run(["xvfb-run", "-a", broken], broken=True)
            print("Rejected broken GTK DNS guard: " + name, flush=True)
        live = compile_to("live", live=True)
        for scenario in ("early", "accepted"):
            with controller(scenario) as state:
                run(["xvfb-run", "-a", live, scenario], timeout=25)
                assert state["cancel_ids"] and len(set(state["cancel_ids"])) == 1
                if scenario == "accepted":
                    assert state["admitted"] and state["polls"] >= 3
            print("Real GTK/libcurl cancellation scenario: " + scenario, flush=True)


if __name__ == "__main__":
    main()
