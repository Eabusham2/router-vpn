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
    "def _job_file(self, job_id: str)",
    "self.server.jobs.cancel_requested(job_id)",
    "self.server.jobs.update_delivery(job_id, sent, size)",
    "self.server.jobs.finish_delivery(job_id, success)",
    "_ai._core._broker.CHUNK",
):
    assert marker in product, marker
assert product.index("cancel_requested(job_id)") < product.index("f.read(_ai._core._broker.CHUNK)")

print("Setup Center product entrypoint + cancellable streaming contract: PASS")
