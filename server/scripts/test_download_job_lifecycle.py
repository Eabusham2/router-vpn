#!/usr/bin/env python3
"""Exercise the production delivery, process group and retained workspace."""
import importlib.util
import hashlib
import http.client
import io
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("product_download_lifecycle", HERE / "setup-center-product-server.py")
product = importlib.util.module_from_spec(spec)
spec.loader.exec_module(product)
broker = product._ai._core._broker
NAME = "router-vpn-windows-amd64.zip"


class JobLifecycleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.work = None

    def manager(self, build=None):
        def file_builder(base, name, work, progress=None):
            self.work = work
            package = work / name
            package.write_bytes(b"x" * (1 << 20))
            return package, "fixture"
        manager = broker._jobs.DownloadJobManager(self.base, build or file_builder, lambda _: "application/zip",
                                                   threading.BoundedSemaphore(1), {NAME})
        self.addCleanup(manager.close)
        return manager

    def wait_for(self, check):
        until = time.monotonic() + 10
        while not check():
            if time.monotonic() >= until:
                self.fail("original operation did not reach its expected state")
            time.sleep(0.01)

    def ready(self, manager):
        job = manager.create(NAME)["id"]
        self.wait_for(lambda: manager.status(job)["status"] == "ready")
        return job

    def test_blocked_socket_is_joined_on_expiry_delete_and_shutdown(self):
        for action, result in (("expire", "expired"), ("delete", "cancelled"), ("close", "cancelled")):
            with self.subTest(action=action):
                manager = self.manager()
                job = self.ready(manager)
                sender, receiver = socket.socketpair()
                with sender, receiver:
                    sender.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
                    entered = threading.Event()
                    def write(chunk):
                        entered.set()
                        sender.sendall(chunk)
                    handler = SimpleNamespace(
                        connection=sender, server=SimpleNamespace(jobs=manager), wfile=SimpleNamespace(write=write),
                        send_response=lambda *args: None, send_header=lambda *args: None, end_headers=lambda: None)
                    thread = threading.Thread(target=product.Handler._job_file, args=(handler, job))
                    thread.start()
                    self.assertTrue(entered.wait(2))
                    self.assertTrue(thread.is_alive())
                    self.assertEqual(manager.status(job)["status"], "delivering")
                    if action == "expire":
                        with manager.lock:
                            deadline = manager.jobs[job]["retention_deadline_epoch"]
                        self.assertEqual(manager.reap_expired(deadline), 1)
                    elif action == "delete":
                        manager.cancel(job)
                    else:
                        manager.close()
                    thread.join(1)
                    self.assertFalse(thread.is_alive())
                    self.assertFalse(self.work.exists())
                    manager.update_delivery(job, 1, 10, 1)
                    manager.finish_delivery(job, True, 1)
                    self.assertEqual(manager.status(job)["status"], result)

    def test_reaper_uses_original_deadline_during_unpolled_stream(self):
        manager = self.manager()
        with patch.object(broker._jobs, "PACKAGE_RETENTION_SECONDS", 0.4):
            job = self.ready(manager)
        stream, meta = manager.begin_delivery(job)
        stream.close()
        manager.update_delivery(job, 1, 2, meta["delivery_attempts"])
        # No status call or explicit reap can drive the timer in this interval.
        self.wait_for(lambda: not self.work.exists())
        manager.finish_delivery(job, True, meta["delivery_attempts"])
        self.assertEqual(manager.status(job)["status"], "expired")

    def test_delivery_start_failures_leave_no_unjoinable_writer(self):
        manager = self.manager()
        job = self.ready(manager)
        with patch.object(manager, "content_type_func", side_effect=ValueError("fixture metadata failure")):
            with self.assertRaisesRegex(ValueError, "fixture metadata failure"):
                manager.begin_delivery(job, lambda: None)
        self.assertEqual(manager.status(job)["delivery_attempts"], 0)
        self.assertEqual(manager.status(job)["status"], "ready")
        self.assertFalse(manager.deliveries)

        class BrokenConnection:
            def gettimeout(self):
                raise OSError("fixture closed socket")
        handler = SimpleNamespace(connection=BrokenConnection(), server=SimpleNamespace(jobs=manager))
        product.Handler._job_file(handler, job)
        self.assertEqual(manager.status(job)["status"], "delivery-interrupted")
        self.assertFalse(manager.deliveries)
        self.assertEqual(manager.cancel(job)["status"], "cancelled")
        self.assertFalse(self.work.exists())

    def test_retries_require_the_ready_file_and_headers_keep_the_original_stream(self):
        manager = self.manager()
        job = self.ready(manager)
        output = self.work / NAME
        original = output.read_bytes()
        alternate = self.work / "alternate"
        alternate.write_bytes(b"y" * len(original))
        os.utime(alternate, ns=(output.stat().st_atime_ns, output.stat().st_mtime_ns))
        responses, refusals = [], []
        sender, receiver = socket.socketpair()
        with sender, receiver:
            sink = io.BytesIO()
            handler = SimpleNamespace(connection=sender, server=SimpleNamespace(jobs=manager), wfile=sink,
                send_response=responses.append, send_header=lambda *args: None,
                end_headers=lambda: os.replace(alternate, output), _json=lambda status, _: refusals.append(status))
            product.Handler._job_file(handler, job)
            self.assertEqual(responses, [200])
            self.assertEqual(sink.getvalue(), original)
            self.assertEqual(manager.status(job)["status"], "delivered")
            product.Handler._job_file(handler, job)
            self.assertEqual(responses, [200])
            self.assertEqual(refusals, [409])
            self.assertEqual(manager.status(job)["delivery_attempts"], 1)
            self.assertFalse(manager.deliveries)

    def test_changed_stream_size_cannot_exceed_headers_or_complete_delivery(self):
        for change in ("truncate", "append", "same-length"):
            with self.subTest(change=change):
                manager = self.manager()
                job = self.ready(manager)
                path = self.work / NAME
                original = path.read_bytes()
                def change_size():
                    if change == "truncate":
                        with path.open("r+b") as f:
                            f.truncate(17)
                    elif change == "append":
                        with path.open("ab") as f:
                            f.write(b"extra bytes")
                    else:
                        before = path.stat()
                        with path.open("r+b") as f:
                            f.write(b"z")
                        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
                sender, receiver = socket.socketpair()
                with sender, receiver:
                    sink, headers = io.BytesIO(), {}
                    handler = SimpleNamespace(connection=sender, server=SimpleNamespace(jobs=manager), wfile=sink,
                        send_response=lambda _: None, send_header=headers.__setitem__, end_headers=change_size)
                    product.Handler._job_file(handler, job)
                    self.assertEqual(int(headers["Content-Length"]), len(original))
                    expected = {"truncate": b"", "append": original, "same-length": b""}
                    self.assertEqual(sink.getvalue(), expected[change])
                    self.assertEqual(manager.status(job)["status"], "delivery-interrupted")
                    with self.assertRaisesRegex(RuntimeError, "output changed"):
                        manager.begin_delivery(job)

    def test_browser_receives_only_the_verified_prefix_before_a_changed_chunk(self):
        original = b"first block" * (broker.CHUNK // 11 + 1) + b"second block"
        def build(base, name, work, progress):
            self.work = work
            path = work / name
            path.write_bytes(original)
            progress.verified_output(path, broker._owned_temp.package_file_identity(path.stat()), hashlib.sha256(original).hexdigest())
            return path, "fixture"
        manager = self.manager(build)
        manager.require_verified_output = True
        job = self.ready(manager)
        path = self.work / NAME

        class Download(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(handler):
                product.Handler._job_file(handler, job)

            def end_headers(handler):
                super().end_headers()
                before = path.stat()
                with path.open("r+b") as package:
                    package.seek(broker.CHUNK + 1)
                    package.write(b"Z")
                os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Download)
        server.jobs = manager
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
        thread.start()
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        try:
            connection.request("GET", "/package")
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(int(response.getheader("Content-Length")), len(original))
            with self.assertRaises(http.client.IncompleteRead) as short:
                response.read()
            self.assertEqual(short.exception.partial, original[:broker.CHUNK])
            self.assertEqual(manager.status(job)["status"], "delivery-interrupted")
            self.assertEqual(manager.status(job)["bytes_sent"], broker.CHUNK)
        finally:
            connection.close()
            server.shutdown()
            thread.join()
            server.server_close()

    def test_cancel_during_ready_chunk_verification_releases_the_original_file(self):
        manager = self.manager()
        entered, resume = threading.Event(), threading.Event()
        open_package = manager._open_package
        def pause_on_read(job, path):
            stream, identity = open_package(job, path)
            class Delayed:
                def read(self, length):
                    entered.set()
                    if not resume.wait(3):
                        raise TimeoutError("Cancel did not enter while the original file was being verified")
                    return stream.read(length)
                fileno = stream.fileno
                close = stream.close
            return Delayed(), identity

        with patch.object(manager, "_open_package", side_effect=pause_on_read):
            job = manager.create(NAME)["id"]
            try:
                self.assertTrue(entered.wait(2))
                manager.cancel(job)
                self.assertTrue(manager.cancel_requested(job))
            finally:
                resume.set()
            self.wait_for(lambda: manager.status(job)["status"] == "cancelled")
            self.assertFalse(self.work.exists())

    def test_ready_refuses_a_changed_or_absent_producer_identity(self):
        for result in ("changed", "absent", "wrong digest"):
            with self.subTest(result=result):
                def build(base, name, work, progress):
                    self.work = work
                    path = work / name
                    path.write_bytes(b"original")
                    if result == "changed":
                        progress.verified_output(path, broker._owned_temp.package_file_identity(path.stat()), hashlib.sha256(b"original").hexdigest())
                        different = work / "second"
                        different.write_bytes(b"retained")
                        os.replace(different, path)
                    elif result == "wrong digest":
                        progress.verified_output(path, broker._owned_temp.package_file_identity(path.stat()), hashlib.sha256(b"another").hexdigest())
                    return path, "fixture"
                manager = self.manager(build)
                manager.require_verified_output = True
                job = manager.create(NAME)["id"]
                self.wait_for(lambda: manager.status(job)["status"] in ("ready", "failed"))
                state = manager.status(job)
                self.assertEqual(state["status"], "failed")
                self.assertNotIn("download_url", state)
                self.assertFalse(self.work.exists())

    def test_retained_job_accepts_only_its_allocated_workspace(self):
        for replacement in ("same-broker", "dead-owner", "copied-marker"):
            with self.subTest(replacement=replacement):
                manager = self.manager()
                job = self.ready(manager)
                original, displaced = self.work, self.base / "displaced"
                alternate = broker._owned_temp.create_owned_temp("router-vpn-job-")
                marker = broker._owned_temp.MARKER_NAME
                if replacement == "copied-marker":
                    (alternate / marker).write_bytes((original / marker).read_bytes())
                elif replacement == "dead-owner":
                    body = (alternate / marker).read_bytes()
                    (alternate / marker).write_bytes(body.replace(f"pid={os.getpid()}".encode(), b"pid=2147483647"))
                (alternate / NAME).write_bytes(b"another job")
                original.rename(displaced)
                alternate.rename(original)
                try:
                    with self.assertRaisesRegex(RuntimeError, "workspace changed"):
                        manager.begin_delivery(job)
                    self.assertEqual(manager.cancel(job)["status"], "cleanup-pending")
                    manager.reap_expired()
                    self.assertEqual((original / NAME).read_bytes(), b"another job")
                    self.assertTrue((original / marker).is_file())
                    self.assertTrue((displaced / NAME).is_file())
                finally:
                    original.rename(alternate)
                    displaced.rename(original)
                    manager.reap_expired()
                    self.assertTrue(broker._owned_temp.cleanup_owned_temp(alternate))
                self.assertEqual(manager.status(job)["status"], "cancelled")
                self.assertFalse(original.exists())

    @unittest.skipUnless(hasattr(os, "O_DIRECTORY"), "pinned directory descriptor")
    def test_removed_original_workspace_does_not_authorize_the_new_directory(self):
        manager = self.manager()
        job = self.ready(manager)
        path = self.work
        self.assertTrue(broker._owned_temp.cleanup_owned_temp(path))
        path.mkdir()
        (path / "unrelated").write_bytes(b"preserve")
        try:
            self.assertEqual(manager.cancel(job)["status"], "cancelled")
            self.assertEqual((path / "unrelated").read_bytes(), b"preserve")
        finally:
            (path / "unrelated").unlink()
            path.rmdir()

    def test_finish_from_previous_attempt_cannot_finish_a_new_stream(self):
        manager = self.manager()
        job = self.ready(manager)
        stream, first = manager.begin_delivery(job)
        stream.close()
        manager.finish_delivery(job, False, first["delivery_attempts"])
        stream, second = manager.begin_delivery(job)
        stream.close()
        manager.update_delivery(job, 3, 4, first["delivery_attempts"])
        manager.finish_delivery(job, True, first["delivery_attempts"])
        self.assertEqual(manager.status(job)["status"], "delivering")
        self.assertEqual(manager.status(job)["bytes_sent"], 0)
        manager.finish_delivery(job, True, second["delivery_attempts"])
        self.assertEqual(manager.status(job)["status"], "delivered")

    def test_failed_shutdown_keeps_retry_owner_and_closes_admission(self):
        manager = self.manager()
        job = self.ready(manager)
        with patch.object(manager, "_cleanup_dir", return_value=False):
            with self.assertRaisesRegex(RuntimeError, "cleanup pending"):
                manager.close(timeout=0.05)
            self.assertTrue(manager.reaper.is_alive())
            self.assertTrue(self.work.is_dir())
            self.assertEqual(manager.status(job)["status"], "cleanup-pending")
            with self.assertRaisesRegex(RuntimeError, "closing"):
                manager.create(NAME)
        manager.close()
        self.assertFalse(manager.reaper.is_alive())
        self.assertFalse(self.work.exists())
        self.assertEqual(manager.status(job)["status"], "cancelled")

    def test_cancelled_upstream_cannot_start_another_package_source(self):
        cancellation = broker._jobs.DownloadCancelled("fixture stopped")
        for name in (NAME, "router-vpn-android.apk"):
            release_call = "_release_desktop_package" if name == NAME else "_release_mobile_package"
            with self.subTest(name=name):
                with patch.object(product._exact_release, release_call, side_effect=cancellation), \
                        patch.object(broker, "fetch_artifact_member") as actions, patch.object(broker, "_run_builder") as local:
                    with self.assertRaises(broker._jobs.DownloadCancelled):
                        broker.build_package(self.base, name, self.base)
                    actions.assert_not_called()
                    local.assert_not_called()
                with patch.dict(os.environ, {"ROUTER_VPN_GITHUB_SHA": "a" * 40}), \
                        patch.object(product._exact_release, release_call, side_effect=RuntimeError("fixture release unavailable")), \
                        patch.object(broker, "fetch_artifact_member", side_effect=cancellation) as actions, \
                        patch.object(broker, "_run_builder") as local:
                    with self.assertRaises(broker._jobs.DownloadCancelled):
                        broker.build_package(self.base, name, self.base)
                    self.assertEqual(actions.call_count, 1)
                    local.assert_not_called()

    @unittest.skipUnless(Path("/proc/self/fd").is_dir(), "Linux descriptor ownership")
    def test_failed_source_open_closes_only_its_descriptor_and_preserves_replacement(self):
        for mode in ("release", "actions"):
            with self.subTest(mode=mode):
                output = self.base / mode
                captured = []
                def replace_before_headers(*args, **kwargs):
                    for candidate in Path("/proc/self/fd").iterdir():
                        try:
                            if candidate.readlink() == output:
                                captured.append(int(candidate.name))
                        except FileNotFoundError:
                            pass
                    self.assertEqual(len(captured), 1)
                    output.rename(self.base / (mode + "-original"))
                    output.write_bytes(b"foreign contents")
                    raise TimeoutError("fixture stalled open")
                with self.assertRaisesRegex(TimeoutError, "fixture stalled open"):
                    if mode == "release":
                        asset = ("generic", {"url": "https://api.github.com/fixture"}, 3, "a" * 64)
                        with patch.object(product._exact_release, "_release_asset", return_value=asset), \
                                patch.object(broker._GITHUB_OPENER, "open", replace_before_headers):
                            product._release_download(broker, NAME, self.base, mode)
                    else:
                        with patch.object(broker, "_urlopen", replace_before_headers):
                            broker._download_limited("https://api.github.com/fixture", output)
                with self.assertRaises(OSError):
                    os.fstat(captured[0])
                self.assertEqual(output.read_bytes(), b"foreign contents")

    def test_unknown_length_sources_check_cancellation_on_each_chunk(self):
        class Response(io.BytesIO):
            headers = {}
        body = b"abcdef"
        def stop_on_chunk(phase, value):
            if phase == "downloading":
                sizes.append(value)
                if len(sizes) == 3:
                    raise broker._jobs.DownloadCancelled("fixture cancelled")
        for mode in ("release", "actions"):
            sizes = []
            output = self.base / mode
            with self.subTest(mode=mode), patch.object(broker, "CHUNK", 2), \
                    self.assertRaisesRegex(broker._jobs.DownloadCancelled, "fixture cancelled"):
                if mode == "release":
                    asset = ("generic", {"url": "https://api.github.com/fixture"}, len(body), hashlib.sha256(body).hexdigest())
                    with patch.object(product._exact_release, "_release_asset", return_value=asset), \
                            patch.object(broker._GITHUB_OPENER, "open", return_value=Response(body)):
                        product._release_download(broker, NAME, self.base, mode, stop_on_chunk)
                else:
                    with patch.object(broker, "_urlopen", return_value=Response(body)):
                        broker._download_limited("https://api.github.com/fixture", output, stop_on_chunk)
            self.assertEqual(len(sizes), 3)
            self.assertFalse(output.exists())

    @unittest.skipUnless(os.name == "posix", "POSIX process retirement")
    def test_owned_release_and_actions_transport_interrupts_blocked_open_and_read(self):
        worker = self.base / "loopback-worker.py"
        worker.write_text("""import hashlib, importlib.util, json, os, sys, urllib.request
from pathlib import Path
from types import SimpleNamespace
s = importlib.util.spec_from_file_location("loopback_product", os.environ["FIXTURE_PRODUCT"])
p = importlib.util.module_from_spec(s); s.loader.exec_module(p)
b = p._ai._core._broker
mode, workspace, out = sys.argv[2:5]
folder = Path(os.environ["FIXTURE_SOURCE"])
path = folder / mode
size = path.stat().st_size
digest = hashlib.sha256(path.read_bytes()).hexdigest()
asset_url = "https://api.github.com/repos/fixture/source"
sha = os.environ["ROUTER_VPN_GITHUB_SHA"]
def metadata(url):
    if "/releases/tags/" in url:
        return {"tag_name": "router-vpn-sha-" + sha, "target_commitish": sha, "assets": [
            {"name": "RouterVPN-Windows-amd64.zip", "size": size, "url": asset_url, "digest":"sha256:"+digest}]}
    if "/git/ref/" in url: return {"object": {"type":"commit", "sha":sha}}
    run = {"id":3,"status":"completed","conclusion":"success","head_sha":sha,"head_branch":"main"}
    if "/workflows/" in url: return {"workflow_runs":[run]}
    return {"artifacts":[{"name": sys.argv[5], "id":1, "workflow_run":run,
                          "digest":"sha256:"+digest, "archive_download_url":asset_url}]}
def open_fixture(request, timeout):
    assert request.full_url == asset_url
    (Path(workspace)/"transfer-pid").write_text(str(os.getpid()))
    return urllib.request.urlopen(os.environ["FIXTURE_ENDPOINT"], timeout=timeout)
b._read_limited_json = metadata
b._GITHUB_OPENER = SimpleNamespace(open=open_fixture)
p._fetch_job_source(*sys.argv[2:])
""")
        plain = b"original package"
        (self.base / "release").write_bytes(plain)
        with zipfile.ZipFile(self.base / "actions", "w") as archive:
            archive.writestr("RouterVPN-Windows-amd64.zip", plain)
        for mode in ("release", "actions"):
            body = (self.base / mode).read_bytes()
            for outcome in ("success", "blocked-open", "blocked-read"):
                with self.subTest(mode=mode, outcome=outcome):
                    entered, resume = threading.Event(), threading.Event()
                    class Upstream(BaseHTTPRequestHandler):
                        def do_GET(self):
                            if outcome == "blocked-open":
                                entered.set()
                                resume.wait(4)
                                return
                            self.send_response(200)
                            self.end_headers()  # deliberately no Content-Length
                            self.wfile.write(body[:1])
                            if outcome == "blocked-read":
                                entered.set()
                                resume.wait(4)
                                return
                            self.wfile.write(body[1:])
                        def log_message(self, *_):
                            pass

                    server = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
                    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
                    thread.start()
                    def build(base, name, work, progress):
                        self.work = work
                        if mode == "release":
                            output = product._job_release_asset(broker, name, work, name, progress)
                        else:
                            output = product._job_actions_member("RouterVPN-generic-release-candidate",
                                      "RouterVPN-Windows-amd64.zip", work, name, progress)
                        return output, mode

                    manager = self.manager(build)
                    manager.require_verified_output = True
                    try:
                        env = {"FIXTURE_PRODUCT": str(HERE / "setup-center-product-server.py"),
                               "FIXTURE_ENDPOINT": f"http://127.0.0.1:{server.server_port}/source",
                               "FIXTURE_SOURCE": str(self.base), "ROUTER_VPN_GITHUB_SHA": "a"*40}
                        with patch.dict(os.environ, env), patch.object(product, "__file__", str(worker)):
                            job = manager.create(NAME)["id"]
                            if outcome == "success":
                                self.wait_for(lambda: manager.status(job)["status"] in ("ready", "failed"))
                                self.assertEqual(manager.status(job)["status"], "ready", manager.status(job))
                                self.assertEqual((self.work / NAME).read_bytes(), plain)
                                self.assertIn("downloading", manager.status(job)["phase_history"])
                            else:
                                self.assertTrue(entered.wait(3))
                                pid = int((self.work / "transfer-pid").read_text())
                                start = time.monotonic()
                                if outcome == "blocked-open":
                                    manager.cancel(job)
                                else:
                                    manager.close(timeout=2)
                                self.wait_for(lambda: manager.status(job)["status"] == "cancelled")
                                self.assertLess(time.monotonic() - start, 2)
                                self.assertFalse(self.work.exists())
                                with self.assertRaises(ProcessLookupError):
                                    os.kill(pid, 0)
                    finally:
                        resume.set()
                        server.shutdown()
                        thread.join()
                        server.server_close()

    def test_actual_packager_retains_extracted_source_until_original_deadline(self):
        generic = self.base / "RouterVPN"
        generic.mkdir()
        broker._builder.write_blank_routers(generic / "routers.json")
        (generic / "LICENSE").write_text("MIT")
        sha = "a" * 40
        broker._builder._provenance.write_manifest(generic, sha, "windows-amd64")
        source = self.base / "generic.zip"
        with zipfile.ZipFile(source, "w") as output:
            for item in generic.iterdir():
                output.write(item, item.relative_to(self.base))

        def build(base, name, work, progress):
            self.work = work
            return product._cancellable_run_builder(base, name, work, source, progress), "fixture-exact-source"
        manager = self.manager(build)
        manager.require_verified_output = True
        # The child packages this fixture archive, whose provenance belongs to its own source revision.
        with patch.dict(os.environ, {"ROUTER_VPN_SOURCE_SHA": sha, "ROUTER_VPN_GITHUB_SHA": sha}):
            job = self.ready(manager)
        trees = list(self.work.glob("package-build-*/github/RouterVPN"))
        self.assertEqual(len(trees), 1)
        self.assertTrue((trees[0] / "LICENSE").is_file())
        stream, first = manager.begin_delivery(job)
        with stream:
            self.assertTrue(zipfile.is_zipfile(stream))
        manager.finish_delivery(job, True)
        stream, second = manager.begin_delivery(job)
        stream.close()
        manager.finish_delivery(job, False)
        self.assertEqual(first["retained_until"], second["retained_until"])
        self.assertTrue(trees[0].is_dir())
        with manager.lock:
            deadline = manager.jobs[job]["retention_deadline_epoch"]
        manager.reap_expired(deadline)
        self.assertFalse(self.work.exists())

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux production SIGTERM")
    def test_sigterm_of_product_entrypoint_retires_its_ready_workspace(self):
        # Bind only loopback in this subprocess. Use the shipping main,
        # server_close and signal handler, with a tiny package producer.
        config = self.base / "config"
        config.mkdir(mode=0o700)
        (self.base / "downloads").mkdir(mode=0o700)
        token = config / "setup-center.token"
        token.write_text("a" * 48)
        token.chmod(0o600)
        child = """import hashlib, importlib.util, sys, time
from pathlib import Path
base, script = Path(sys.argv[1]), Path(sys.argv[2])
spec = importlib.util.spec_from_file_location("product_term", script)
product = importlib.util.module_from_spec(spec); spec.loader.exec_module(product)
class Server(product.Server):
    def serve_forever(self, **kwargs):
        def build(base, name, work, progress=None):
            package = work / name
            package.write_bytes(b"ready")
            progress.verified_output(package, product._ai._core._broker._owned_temp.package_file_identity(package.stat()), hashlib.sha256(b"ready").hexdigest())
            return package, "fixture"
        self.jobs.build_func = build
        job = self.jobs.create("router-vpn-windows-amd64.zip")["id"]
        while self.jobs.status(job)["status"] != "ready": time.sleep(.01)
        with self.jobs.lock: path = self.jobs.jobs[job]["work_dir"]
        (base/"owned-path").write_text(path)
        super().serve_forever(**kwargs)
product.Server = Server
sys.argv = [str(script), "--base", str(base), "--bind", "127.0.0.1", "--port", "0"]
sys.exit(product.main())
"""
        private_tmp = self.base / "tmp"
        private_tmp.mkdir()
        proc = subprocess.Popen([sys.executable, "-c", child, str(self.base), str(HERE / "setup-center-product-server.py")],
                                env={**os.environ, "TMPDIR": str(private_tmp)}, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True)
        try:
            marker = self.base / "owned-path"
            self.wait_for(lambda: marker.exists() or proc.poll() is not None)
            if not marker.exists():
                self.fail(proc.communicate(timeout=1)[0])
            original = Path(marker.read_text())
            self.assertTrue(original.is_dir())
            proc.send_signal(signal.SIGTERM)
            output, _ = proc.communicate(timeout=5)
            self.assertEqual(proc.returncode, 0, output)
            self.assertFalse(original.exists())
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.communicate(timeout=2)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux production process groups")
    def test_cancel_joins_stubborn_compiler_group_and_preserves_other_process(self):
        builder = self.base / "builder.py"
        builder.write_text("""import json, os, signal, subprocess, sys, time
from pathlib import Path
base = Path(sys.argv[sys.argv.index('--base')+1])
output = Path(sys.argv[sys.argv.index('--output')+1])
assert '--job-workspace' in sys.argv
scratch = Path(os.environ['GOTMPDIR'])
assert scratch.parent == output.parent and all(os.environ[k] == str(scratch) for k in ('TMP', 'TEMP', 'TMPDIR'))
(scratch/'compiler-object').write_bytes(b'partial')
child_code = "import os,signal,sys,time; from pathlib import Path; signal.signal(signal.SIGTERM,signal.SIG_IGN); Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(60)"
child = subprocess.Popen([sys.executable, '-c', child_code, str(base/'compiler.pid')])
(base/'builder.json').write_text(json.dumps([os.getpid(), str(output.parent)]))
time.sleep(60)
""")
        def build(base, name, work, progress):
            return product._cancellable_run_builder(base, name, work, None, progress), "fixture"
        manager = self.manager(build)
        unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)
        try:
            with patch.object(broker, "BUILDER_PATH", builder):
                job = manager.create(NAME)["id"]
                self.wait_for(lambda: (self.base / "compiler.pid").is_file())
                leader, work = json.loads((self.base / "builder.json").read_text())
                compiler = int((self.base / "compiler.pid").read_text())
                self.assertEqual(os.getpgid(compiler), leader)
                manager.cancel(job)
                self.wait_for(lambda: manager.status(job)["status"] == "cancelled")
                self.assertFalse(Path(work).exists())
                with self.assertRaises(ProcessLookupError):
                    os.killpg(leader, 0)
                with self.assertRaises(ProcessLookupError):
                    os.kill(compiler, 0)
                self.assertIsNone(unrelated.poll())
        finally:
            unrelated.terminate()
            unrelated.wait(timeout=2)


if __name__ == "__main__":
    unittest.main()
