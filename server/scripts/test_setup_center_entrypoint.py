#!/usr/bin/env python3
from pathlib import Path

here = Path(__file__).resolve().parent
entry = (here / "run-setup-center.sh").read_text(encoding="utf-8")
product = (here / "setup-center-product-server.py").read_text(encoding="utf-8")

for marker in (
    "setup-center-product-server.py",
    "setup-center-ai-server.py",
    "ROUTER_VPN_BASE",
    "ROUTER_VPN_SETUP_BIND",
    "ROUTER_VPN_SETUP_PORT",
    'exec python3 "$SCRIPT"',
):
    assert marker in entry, marker
for forbidden in ("OPENAI_API_KEY=", "--api-key", "sk-", "eval ", "sh -c"):
    assert forbidden not in entry, forbidden

for marker in (
    "def _cancellable_run_builder(",
    "start_new_session=(os.name == \"posix\")",
    "progress(\"building\", 58)",
    "os.killpg(proc.pid, sig)",
    "os.waitpid(-proc.pid, os.WNOHANG)",
    "signal.signal(signal.SIGTERM, terminate)",
    "broker.PACKAGE_TIMEOUT",
    "_ai._core._broker._run_builder = _cancellable_run_builder",
):
    assert marker in product, marker
broker = (here / "download-broker.py").read_text(encoding="utf-8")
for marker in (
    "def _job_file(self, job_id: str)", "self.server.jobs.cancel_requested(job_id)",
    "self.server.jobs.update_delivery(job_id, sent, size, attempt)",
    "self.server.jobs.finish_delivery(job_id, success, attempt)", "self.connection.shutdown(socket.SHUT_RDWR)",
    "self.wfile.write(chunk)", "self.connection.settimeout(",
):
    assert marker in broker, marker
assert broker.index("cancel_requested(job_id)") < broker.index("f.read(length)", broker.index("def _job_file"))
assert product.index("proc = subprocess.Popen(") < product.index("time.sleep(0.20)")

print("Setup Center product entrypoint + cancellable build/streaming contract: PASS")
