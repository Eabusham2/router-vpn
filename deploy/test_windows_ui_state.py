#!/usr/bin/env python3
"""Exercise captured Windows UI preference storage and its actual consumers.

The filesystem tests use real regular files, hardlinks and directory links in an
owned temporary layout. Only the transport module's private owner record is a
fixture: real process/pipe authentication is covered by the native GUI gates.
"""
from pathlib import Path
import argparse
import hashlib
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / "client/RouterVPN-Windows-UIState.psm1"
TRANSPORT = ROOT / "client/RouterVPN-Windows-ControllerTransport.psm1"
HARNESS = ROOT / "client/test-windows-ui-state.ps1"


def replace_once(source, before, after):
    if source.count(before) != 1:
        raise ValueError("UI state negative control lost its shipping boundary")
    return source.replace(before, after, 1)


def execute(shell, state=STATE, transport=TRANSPORT, witness=None):
    result = subprocess.run(
        [shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(HARNESS), "-Root", str(ROOT), "-StateModule", str(state),
         "-TransportModule", str(transport)],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace", timeout=90, check=False)
    if witness is not None:
        if result.returncode == 0 or "CONTROL " + witness not in result.stdout:
            raise ValueError("UI state defect missed its semantic rejection:\n" + result.stdout)
    else:
        found = re.findall(r"^PASS Windows UI state checks=(\d+)$", result.stdout, re.MULTILINE)
        if result.returncode or len(found) != 1 or int(found[0]) < 51:
            raise ValueError("UI state fixture did not execute its boundaries:\n" + result.stdout)
        print(result.stdout.strip(), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shell", default="pwsh")
    args = parser.parse_args()
    paths = [STATE, TRANSPORT, HARNESS, Path(__file__), *(
        ROOT / "client" / ("RouterVPN-Windows-" + name + ".ps1")
        for name in ("App", "ProfileSettings", "UnifiedShell", "Product-v2"))]
    if any(path.is_symlink() or not path.is_file() for path in paths):
        raise ValueError("UI state gate requires regular shipping sources")
    before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    execute(args.shell)
    state = STATE.read_text(encoding="utf-8")
    transport = TRANSPORT.read_text(encoding="utf-8")
    variants = (
        ("package-root-writes", "state", "owned read did not migrate into captured Data",
         replace_once(state,
                      "$Root=if($Owned){Assert-RouterVPNUIStateDirectory $Captured}else{Assert-RouterVPNUIStateDirectory $LegacyDirectory}",
                      "$Root=Assert-RouterVPNUIStateDirectory $LegacyDirectory")),
        ("migration-reencoding", "state", "migration changed the exact saved bytes",
         replace_once(state, "$Bytes=Read-RouterVPNUIStateBytes $Old.FullName",
                      "$Bytes=Read-RouterVPNUIStateBytes $Old.FullName;$Bytes=[byte[]]$Bytes[3..($Bytes.Length-1)]")),
        ("working-directory-state", "state", "dynamic shipping functions lost package-relative legacy state",
         replace_once(state,
                      "if([string]::IsNullOrEmpty($LegacyDirectory)){$LegacyDirectory=$PSScriptRoot}",
                      "if([string]::IsNullOrEmpty($LegacyDirectory)){$LegacyDirectory=[IO.Directory]::GetCurrentDirectory()}")),
        ("linked-file-admission", "state", "linked destination read was accepted",
         replace_once(state,
                      "if([bool]$Item.PSIsContainer-ne$Directory-or($Item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0-or\n"
                      "       ($null-ne$Link-and-not[string]::IsNullOrEmpty([string]$Link.Value))){",
                      "if($false){")),
        ("linked-ancestor-admission", "state", "linked ancestor was accepted",
         replace_once(state, "while($Cursor){", "while($false){")),
        ("arbitrary-state-filenames", "state", "UI writer accepted a controller private filename",
         replace_once(state, "if($Name-cnotin$script:UIStateNames){", "if($false){")),
        ("mutable-data-root", "transport", "later environment replaced the captured state owner",
         replace_once(transport, "return $script:ControllerDataRoot", "return [string]$env:HOMEVPN_ROOT")),
        ("retired-state-owner", "transport", "retired UI owner retained state access",
         replace_once(transport,
                      "function Get-RouterVPNControllerDataRoot {\n"
                      "    if($script:ControllerMode-ceq'legacy'){return $null}\n"
                      "    if($script:ControllerMode-cne'owned'-or$null-eq$script:ControllerChannel){",
                      "function Get-RouterVPNControllerDataRoot {\n"
                      "    if($script:ControllerMode-ceq'legacy'){return $null}\n"
                      "    if($false){")),
    )
    with tempfile.TemporaryDirectory(prefix="routervpn-ui-state-defects-") as directory:
        for name, kind, witness, changed in variants:
            path = Path(directory) / (name + ".psm1")
            path.write_text(changed, encoding="utf-8")
            execute(args.shell, state=path if kind == "state" else STATE,
                    transport=path if kind == "transport" else TRANSPORT, witness=witness)
            print("Rejected executable UI state defect:", name, flush=True)
    if any(hashlib.sha256(path.read_bytes()).hexdigest() != digest for path, digest in before.items()):
        raise ValueError("UI state shipping sources changed during execution")
    print("Captured UI state migration, exact-byte preservation, ownership, linked-path rejection and actual App/Profile/Unified consumers passed; eight production defects rejected. Native process authentication remains a separate gate.", flush=True)


if __name__ == "__main__":
    main()
