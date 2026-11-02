#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("routervpn_verified_onboarding_tested", HERE / "setup_center_verified_onboarding.py")
assert SPEC is not None and SPEC.loader is not None
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)

sample = '''
<button onclick="startWizard(true)">Start / resume setup</button>
<section class="panel active" data-tab="start"><div class="card hero"><h2>Choose the easiest path</h2><div class="grid3"><div>old app-first cards</div></div></div><div class="card"><h2>Full setup at a glance</h2><div id="quickSteps"></div></div></section>
<section class="panel" data-tab="downloads"><div>downloads</div></section>
The mode table explains all 20 modes and their expected overhead.
<p class="small">Multi-hop is intentionally not labeled ready here yet. A real multi-hop feature must route one validated self-hosted node through another without leaking DNS or bypassing kill-switch policy; the UI must not pretend that exists before the chain adapter is tested.</p>
<p>The desktop controller has <b>Off</b> and an emergency local transport stop. A strict firewall kill switch and remote “kick every peer” control are not advertised as ready until their platform-specific firewall/peer implementations are tested. This avoids a cosmetic switch that could leak traffic.</p>
Router VPN is a real native app. Raw WireGuard uses the PacketTunnel engine today; unsupported layered/AWG/multihop combinations stay visibly unavailable instead of being faked.
if(localStorage.getItem(WIZKEY)!=='1')startWizard(false);
'''
fixed = MOD.reconcile_setup_text(sample)

lanes = ["1. Simple / native", "2. Router VPN app — recommended", "3. Universal third-party", "4. Manual / custom"]
positions = [fixed.index(x) for x in lanes]
assert positions == sorted(positions), positions
assert 'onclick="routerVpnOpenVerifiedOnboarding()"' in fixed
assert "legacy generated wizard is superseded" in fixed
assert "16 logical user modes" in fixed and "20 raw runtimes internally" in fixed
assert "Multi-hop is intentionally not labeled ready" not in fixed
assert "strict firewall kill switch" not in fixed
assert "WireGuard and AmneziaWG" in fixed and "system VPN" in fixed

# Exercise the actual generator seam, not just the old hand-written sample.
# A previous generator revision changed the iOS sentence without updating the
# reconciler, leaving the obsolete AWG/multihop claims in the shipped page.
with tempfile.TemporaryDirectory(prefix="router-vpn-setup-guidance-") as temporary:
    base = Path(temporary)
    subprocess.run(
        [sys.executable, str(HERE / "generate-setup-assets.py"), str(base),
         "router.invalid", "192.168.50.133"],
        check=True, capture_output=True, timeout=15,
    )
    generated = json.loads((base / "client-bundle/setup-assets.json").read_text())
    current = generated["devices"]["ios"]["customApp"]
    page = (base / "client-bundle/router-vpn-device-setup.html").read_text()
    rendered = MOD.reconcile_setup_text(page)
    packed = rendered.split("const DATA=", 1)[1].split(";const $=", 1)[0]
    assert json.loads(packed)["devices"]["ios"]["customApp"] == current
    assert current in fixed, "the generator and legacy-page repair disagree about iOS support"
    for obsolete in (
        "Router VPN is a real native app. Raw WireGuard uses the PacketTunnel engine today; supported Libbox paths are source-wired; unsupported AWG/OpenVPN/full desktop-equivalent multihop combinations stay visibly unavailable instead of being faked.",
        "Router VPN is a real native app. Raw WireGuard uses WireGuardKit; compatible imported sing-box profiles use the pinned Libbox PacketTunnel with exact selected-node proof. AWG/Xray-only, ALL/MAX and unsupported multihop combinations stay visibly unavailable instead of being faked.",
    ):
        legacy = page.replace(current, obsolete)
        assert legacy != page, "fixture did not exercise the generated data"
        repaired = MOD.reconcile_setup_text(legacy)
        packed = repaired.split("const DATA=", 1)[1].split(";const $=", 1)[0]
        assert json.loads(packed)["devices"]["ios"]["customApp"] == current
        assert obsolete not in repaired

panel = MOD.VERIFIED_ONBOARDING_PANEL
for endpoint in (
    "/api/admin/status",
    "/api/admin/clients",
    "/api/admin/forwarding-extension",
    "/api/release-status",
):
    assert endpoint in panel, endpoint
for marker in (
    "Run onboarding again",
    "Complete verified onboarding",
    "Protected DMZ",
    "Owner / client",
    "routervpn.verified-onboarding.v1",
    "stopImmediatePropagation",
):
    assert marker in panel, marker
for lane in lanes:
    assert lane in panel, lane
assert "Authorization" not in panel
assert "setup-center.token" not in panel

try:
    MOD.reconcile_setup_text("<html>changed generator</html>")
except RuntimeError:
    pass
else:
    raise AssertionError("reconciliation must fail closed when the generated start-section seam changes")

print("Verified Setup Center onboarding contract: OK")
