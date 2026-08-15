#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")

stop = text("modes/stop-mode.sh")
platform_stop = text("modes/stop-mode-platform.sh")
run_all = text("modes/run-all.sh")
orch = text("modes/orchestrate.py")
main = text("cmd/client/main.go")
logical = text("cmd/client/logical_modes.go")
helper = text("cmd/client/kill_switch_transition.go")

for required in (
    "HOMEVPN_KILLSWITCH_HOLD",
    'if [[ ${HOMEVPN_KILLSWITCH_HOLD:-0} != 1 ]]',
    'kill-switch.py" release',
):
    assert required in stop, f"stop-mode.sh missing transition/manual distinction: {required}"

assert 'HOMEVPN_KILLSWITCH_HOLD:-0} != 1' in platform_stop
assert 'kill-switch-platform.py" release' in platform_stop
assert 'HOMEVPN_KILLSWITCH_HOLD=1' in run_all and 'stop-mode.sh' in run_all

for required in (
    "def stop_current(hold_kill_switch: bool = False)",
    'extra = {"HOMEVPN_KILLSWITCH_HOLD": "1"} if hold_kill_switch else None',
    "stop_current(True)",
    "stop_current(False)",
):
    assert required in orch, f"SMART/CUSTOM orchestrator missing transition intent: {required}"

for required in (
    "func (a *app) startModeAttempt(id string, holdOnFailure bool) error",
    "a.stopModeWithIntent(true)",
    "a.stopModeWithIntent(holdOnFailure)",
    "func (a *app) stopModeWithIntent(holdKillSwitch bool) error",
    "c.Env = a.stopCommandEnv(holdKillSwitch)",
    "a.startModeAttempt(m.ID, true)",
    "a.releaseTransitionKillSwitch()",
):
    assert required in main, f"controller missing protected transition state: {required}"

assert "a.startModeAttempt(candidate.RuntimeID, true)" in logical
assert "a.releaseTransitionKillSwitch()" in logical
# Only the actual WG/AWG/native logical fallback loop must use the held-attempt
# API. Other terminal wrappers (for example ALL, which implements its own held
# internal branch transitions) may legitimately call startMode().
try:
    candidate_loop = logical.split("for _, candidate := range candidates {", 1)[1].split("if err := a.releaseTransitionKillSwitch()", 1)[0]
except IndexError as exc:
    raise AssertionError("logical candidate fallback loop could not be located") from exc
assert "a.startModeAttempt(candidate.RuntimeID, true)" in candidate_loop
assert "a.startMode(candidate.RuntimeID)" not in candidate_loop, "ordinary logical fallback still uses terminal/manual start path"

for required in (
    'runtime.GOOS != "linux" && runtime.GOOS != "darwin"',
    'exec.Command("python3", helper, "release")',
    'envWithValue(os.Environ(), killSwitchHoldEnv, "0")',
):
    assert required in helper, f"controller release helper missing platform/manual release boundary: {required}"

print("Kill-switch transition state-machine contract: OK")
