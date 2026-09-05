#!/usr/bin/env python3
"""Release-lock graceful ownership/teardown for Windows VPN dataplanes."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def need(path: str, *markers: str) -> str:
    target = ROOT / path
    if not target.is_file():
        errors.append(f"missing Windows runtime source: {path}")
        return ""
    body = target.read_text(encoding="utf-8", errors="replace")
    for marker in markers:
        if marker not in body:
            errors.append(f"{path}: missing Windows teardown marker {marker!r}")
    return body


# The Go controller publishes phase=stopping before its bounded wrapper wait.
# Windows cannot rely on os.Interrupt delivery, so long-lived PowerShell owners
# must observe that loopback-only state and return through their own cleanup.
need(
    "cmd/client/main.go",
    'a.state.Phase = "stopping"',
    "cmd.Process.Signal(os.Interrupt)",
    "time.After(3 * time.Second)",
)
need(
    "client/Private-RouterVPN-State.ps1",
    "function Test-RouterVPNControllerStopping",
    "http://127.0.0.1:8788/api/status",
    "$request.Proxy=$null",
    "[string]$status.phase-eq'stopping'",
)

# Every long-running Windows owner must leave its loop before the controller's
# hard-kill fallback and let its finally/down path restore firewall/runtime.
need(
    "client/native-tor-bridge-windows.ps1",
    "Test-RouterVPNControllerStopping",
    "$controllerStopping=$true;break",
    "Stop-Owned",
    "Kill 'release'",
    "Close()",
    "Remove-PrivateRuntime",
)
need(
    "client/native-openvpn-windows.ps1",
    "Test-RouterVPNControllerStopping",
    "$controllerStopping=$true;break",
    "Stop-Owned",
    "Kill 'release'",
    "Remove-PrivateRuntime",
)
need(
    "client/native-multihop-windows.ps1",
    "Test-RouterVPNControllerStopping",
    "$controllerStopping=$true;break",
    "Stop-Owned",
    "Kill 'release'",
    "Remove-PrivateRuntime",
)
mode = need(
    "client/native-windows-mode.ps1",
    "$SingBoxProcessFile",
    "Write-RouterVPNProcessRecord $SingBoxProcessFile $sing",
    "function Stop-ChildrenOwned",
    "Test-RouterVPNControllerStopping",
    "$controllerStopping=$true;break",
    "Remove-WrapperRecord",
    "Invoke-KillSwitch 'release'",
)
if "&$SingBox run -D $RunDir -c $SingConfig" in mode:
    errors.append("client/native-windows-mode.ps1: sing-box reverted to an unowned synchronous child")

# Raw WireGuard is intentionally different: `up` installs a Windows service and
# returns, while the controller's StopCommand calls explicit service teardown.
need(
    "client/native-wireguard-windows.ps1",
    "/installtunnelservice",
    "/uninstalltunnelservice",
    "Stop-DnsProxy",
    "Remove-PrivateRuntime",
    "Invoke-KillSwitch 'release'",
)

if errors:
    print("WINDOWS RUNTIME STOP AUDIT: FAIL")
    for error in errors:
        print(" - " + error)
    raise SystemExit(1)
print("WINDOWS RUNTIME STOP AUDIT: PASS")
