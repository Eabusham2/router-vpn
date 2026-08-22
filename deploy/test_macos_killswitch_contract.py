#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def text(rel: str) -> str:
    p = ROOT / rel
    assert p.is_file(), f"missing {rel}"
    return p.read_text(encoding="utf-8", errors="strict")


# Scoped PF backend. Reading /etc/pf.conf to verify Apple's existing anchor
# namespace is allowed; rewriting/reloading the global configuration is not.
darwin = text("modes/darwin_kill_switch.py")
assert 'PF_ANCHOR = "com.apple/router-vpn"' in darwin
assert "pfctl" in darwin and "utun" in darwin
assert "darwin_baseline_utun" in darwin and "darwin_tunnel_interfaces" in darwin
assert "darwin_physical_interfaces" in darwin and "public_route_interfaces" in darwin
assert "newly-created Router VPN utun" in darwin
assert "-X" in darwin and "-E" in darwin
assert 'run_pf(["-i", interface, "-F", "states"])' in darwin, "macOS strict mode must invalidate old states only on proven public interfaces"
for forbidden in (
    'Path("/etc/pf.conf").write_text',
    "Path('/etc/pf.conf').write_text",
    'open("/etc/pf.conf", "w")',
    "open('/etc/pf.conf', 'w')",
    'open("/etc/pf.conf","w")',
    "open('/etc/pf.conf','w')",
    'pfctl(), "-f", "/etc/pf.conf"',
    "pfctl(), '-f', '/etc/pf.conf'",
    'run_pf(["-F", "states"])',
):
    assert forbidden not in darwin, forbidden

# Platform dispatcher preserves Linux and owns Darwin apply/watch/release/always.
dispatch = text("modes/kill-switch-platform.py")
for marker in ("darwin_apply", "darwin_watch", "darwin_release", "darwin_reassert", "apply_darwin", "remove_darwin", "status_darwin"):
    assert marker in dispatch, marker
assert 'state.get("policy") == "always"' in dispatch
assert "Fail closed" in dispatch or "fail-closed" in dispatch

# Established MTU logic is imported and only its pre-connect protection callback
# is replaced; the mature Linux MTU implementation itself is not duplicated.
mtu = text("modes/mtu-policy-platform.py")
assert 'HERE / "mtu-policy.py"' in mtu
assert "CORE.enforce_kill_switch = enforce_platform_kill_switch" in mtu
assert 'kill-switch-platform.py' in mtu

runner = text("modes/run-platform.sh")
for allowed in ("run-mode.sh", "run-combined.sh", "run-max.sh", "run-xhttp.sh", "run-all.sh"):
    assert allowed in runner, allowed
assert 'mtu-policy-platform.py' in runner
assert 'stop-mode-platform.sh' in runner
assert 'run-platform.sh" run-max.sh' in runner
assert "mktemp" in runner and "chmod 700" in runner

stop = text("modes/stop-mode-platform.sh")
assert 'bash "$SCRIPT_DIR/stop-mode.sh"' in stop
assert 'kill-switch-platform.py" release' in stop

# Shared catalog uses the platform runner for every concrete mode. SMART/CUSTOM
# are rewritten only on Darwin by common.Mode.UnmarshalJSON.
modes = json.loads(text("configs/client/modes.json"))
concrete = [m for m in modes if m["id"] not in {"smart-auto", "custom"}]
assert len(concrete) == 20
for mode in concrete:
    command = mode.get("command") or []
    assert command and command[0] == "./run-platform.sh", (mode["id"], command)
    assert mode.get("stop_command") == ["./stop-mode-platform.sh"], mode["id"]
for mode in modes:
    assert mode.get("stop_command") == ["./stop-mode-platform.sh"], mode["id"]

compat = text("internal/common/mode_platform.go")
assert 'platform != "darwin"' in compat
assert '"./orchestrate.py"' in compat and '"./orchestrate-platform.py"' in compat
assert '"./stop-mode.sh"' in compat and '"./stop-mode-platform.sh"' in compat
orchestrate = text("modes/orchestrate-platform.py")
assert 'stop-mode.sh' in orchestrate and 'stop-mode-platform.sh' in orchestrate

print("macOS strict kill-switch scoped PF/state source contract: OK")
