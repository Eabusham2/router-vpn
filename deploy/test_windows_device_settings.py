#!/usr/bin/env python3
"""Exercise the shipping Windows device serializer, composed callback and WPF form."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def run(command, rejection=None):
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=90)
    output = result.stdout + result.stderr
    if rejection:
        if result.returncode == 0 or rejection not in output:
            raise RuntimeError(f"Defect did not fail its intended control: {rejection}\n{output}")
    elif result.returncode:
        raise RuntimeError(output)
    else:
        print(result.stdout.strip(), flush=True)


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise AssertionError("Mutation seam missing or duplicated: " + old)
    return source.replace(old, new, 1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--shell", default="pwsh")
    parser.add_argument("--shipping-only", action="store_true")
    args = parser.parse_args()
    helper = ROOT / "client/RouterVPN-Windows-ProfileSettings.ps1"
    unified = ROOT / "client/RouterVPN-Windows-UnifiedShell.ps1"
    source, shell_source = helper.read_text(encoding="utf-8"), unified.read_text(encoding="utf-8")
    match = re.search(r"\[xml\]\$xaml = @'\n(.*?)\n'@", source, re.S)
    if match is None:
        raise AssertionError("Shipping Settings XAML missing")
    window = ET.fromstring(match.group(1))
    controls = {element.attrib.get("Name"): element for element in window.iter() if element.attrib.get("Name")}
    for name in ("LAN", "Kill", "IPv6", "MTUPolicy", "ManualMTU", "Effective"):
        if controls[name] not in list(controls["NodeSettings"].iter()):
            raise AssertionError("Common device field moved out of its owned form: " + name)
    for name in ("Base", "Fallback", "RequireEncrypted", "RequireObfuscation", "StartLayer"):
        if controls[name] not in list(controls["RouterTransportSettings"].iter()):
            raise AssertionError("Router-only transport field escaped its container: " + name)
    for name in ("DAITA", "Jumbo", "Socks", "Forwarding"):
        if controls[name] not in list(controls["RouterFeatureSettings"].iter()):
            raise AssertionError("Router-only feature escaped its container: " + name)
    for name in ("Startup", "AutoConnect"):
        if controls[name] not in list(controls["StartupSettings"].iter()) or controls[name] in list(controls["NodeSettings"].iter()):
            raise AssertionError("Independent startup field moved into unsupported common settings")
    command = [args.shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ROOT / "client/test-windows-device-settings.ps1"), "-Root", str(ROOT)]
    if os.name == "nt":
        command.append("-WPF")
    run(command)
    if args.shipping_only:
        return
    mutations = [
        ("copied-private", "helper", "home_lan_access=$HomeLANAccess;kill_switch_policy", "home_lan_access=$HomeLANAccess;password=$Captured.password;kill_switch_policy", "CONTROL device payload copied unrelated or private fields"),
        ("wrong-token", "helper", "profile_token=[string]$Captured.profile_token;home_lan_access", "profile_token=('f'*64);home_lan_access", "CONTROL device payload replaced captured identity"),
        ("wrong-kill", "helper", "kill_switch_policy=$KillSwitchPolicy;ipv6_mode", "kill_switch_policy='off';ipv6_mode", "CONTROL device payload changed selected protection policy"),
        ("wrong-ipv6", "helper", "ipv6_mode=$IPv6Mode;mtu_policy", "ipv6_mode='on';mtu_policy", "CONTROL device payload changed selected protection policy"),
        ("wrong-mtu", "helper", "manual_mtu=$manualValue}", "manual_mtu=0}", "CONTROL device payload changed requested MTU"),
        ("startup-alias", "helper", "if($modeChanged -or $AutoConnect -ne $Captured.auto_connect)", "if($true)", "CONTROL unchanged smart-auto display alias was overwritten"),
        ("manual-autoconnect", "helper", "$body.auto_connect=$AutoConnect", "$body.auto_connect=$true", "CONTROL explicit startup edit did not form one atomic device payload"),
        ("coerced-lan", "helper", "if($HomeLANAccess -isnot [bool])", "if($false)", "CONTROL invalid device field accepted HomeLANAccess"),
        ("unsupported", "helper", "if(-not $Captured.device_policy_supported)", "if($false)", "CONTROL unsupported runtime received device policy"),
        ("wrong-get-owner", "helper", "$Captured.profile_id -cne $DisplayedProfileID", "$false", "CONTROL invalid device field accepted DisplayedProfileID"),
        ("wrong-post-route", "helper", "'/api/profile/device') -Method Post", "'/api/profile/settings') -Method Post", "CONTROL device save did not use its own endpoint"),
        ("busy-save", "helper", "if(Test-RouterVPNConnectionProfileBusy -BaseUrl $BaseUrl){throw 'Disconnect Router VPN before saving device settings.'}", "if($false){throw 'Disconnect Router VPN before saving device settings.'}", "CONTROL active device policy was submitted"),
        ("displayed-capture", "unified", "-Owner $Window -DisplayedProfileID $DisplayedProfileID -DisplayedNodeKind $DisplayedNodeKind", "-Owner $Window -DisplayedProfileID 'replacement' -DisplayedNodeKind $DisplayedNodeKind", "CONTROL composed callback lost displayed external identity"),
        ("malformed-source", "helper", "Saved connection uses the selected protocol", "Saved connection uses this node’s protocol", "CONTROL whole-source parse"),
    ]
    if os.name == "nt":
        mutations.append(("unsupported-form", "helper", "$nodeSettings.IsEnabled=[bool]$externalDevice.device_policy_supported", "$nodeSettings.IsEnabled=$true", "unsupported WPF form enabled common device fields or disabled startup"))
    with tempfile.TemporaryDirectory(prefix="routervpn-windows-device-") as temp:
        for name, kind, old, new, rejection in mutations:
            variant = replace_once(source if kind == "helper" else shell_source, old, new)
            path = Path(temp) / (name + ".ps1")
            path.write_text(variant, encoding="utf-8")
            run(command + (["-Source"] if kind == "helper" else ["-UnifiedSource"]) + [str(path)], rejection=rejection)
            print("Rejected executable defect: " + name, flush=True)
    print(f"Windows device settings: {len(mutations)} executable defect controls passed", flush=True)


if __name__ == "__main__":
    main()
