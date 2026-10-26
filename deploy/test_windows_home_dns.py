#!/usr/bin/env python3
"""Execute the shipping Windows Home DNS policies and their real runtime writers."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(command: list[str], rejection: str | None = None) -> None:
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=90)
    output = result.stdout + result.stderr
    if rejection:
        if result.returncode == 0 or rejection not in output:
            raise RuntimeError(f"Defect did not fail its intended control: {rejection}\n{output}")
    elif result.returncode:
        raise RuntimeError(output)
    else:
        print(result.stdout.strip(), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--shell", default="pwsh")
    parser.add_argument("--shipping-only", action="store_true")
    args = parser.parse_args()
    files = {
        "private": ROOT / "client/Private-RouterVPN-State.ps1",
        "layered": ROOT / "client/native-windows-mode.ps1",
        "wireguard": ROOT / "client/native-wireguard-windows.ps1",
    }
    source = {key: path.read_text(encoding="utf-8") for key, path in files.items()}
    command = [args.shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ROOT / "client/test-windows-home-dns.ps1"), "-Root", str(ROOT)]
    run(command)
    if args.shipping_only:
        return
    mutations = [
        ("forced-udp", "private", "protocol=$protocol; host=$dnsHost", "protocol='udp'; host=$dnsHost", "CONTROL Home transport overwritten"),
        ("forced-port", "private", "host=$dnsHost; port=$port", "host=$dnsHost; port=53", "CONTROL Home port overwritten"),
        ("other-node", "private", "if ($addresses -cnotcontains $dnsHost)", "if ($false)", "CONTROL invalid Home policy accepted wrong-node"),
        ("public-home", "private", "$bytes[0] -eq 10 -or", "$true -or", "CONTROL invalid Home policy accepted public-node"),
        ("ipv6-off", "private", "if ($ipv6 -eq 'off' -and $dnsHost.Contains(':'))", "if ($false)", "CONTROL invalid Home policy accepted ipv6-off-explicit"),
        ("lost-tls", "private", "server_name=$serverName; path=$path", "server_name=''; path=$path", "CONTROL Home TLS name overwritten"),
        ("lost-path", "private", "server_name=$serverName; path=$path", "server_name=$serverName; path=''", "CONTROL Home path overwritten"),
        ("ambient-override", "private", "# Never consult ambient HOMEVPN_DNS_*", "if($env:HOMEVPN_DNS_HOST){$dnsHost=$env:HOMEVPN_DNS_HOST}\n  # Never consult ambient HOMEVPN_DNS_*", "CONTROL Home address replaced"),
        ("public-default", "layered", "'dns_mode' 'home'", "'dns_mode' 'fastest'", "CONTROL Home mode replaced"),
        ("legacy-port-return", "layered", "return $n}};return $Default", "return$n}};return$Default", "CONTROL explicit custom DNS execution failed"),
        ("legacy-tls-return", "layered", "{return $Explicit}", "{return$Explicit}", "CONTROL explicit custom DNS execution failed"),
        ("direct-dns", "layered", "detour=$detour};if($dns.protocol", "detour='direct'};if($dns.protocol", "CONTROL layered Home DNS bypassed tunnel"),
        ("missing-detour-guard", "layered", "if($detour -eq 'direct' -or $owned.Count -ne 1 -or -not(Has-Property $owned[0] 'type') -or [string]$owned[0].type -in @('direct','block','dns'))", "if($false)", "CONTROL layered Home accepted missing tunnel owner"),
        ("readiness", "layered", "  [void](Get-DnsSelection)\n", "  # Defect: DNS readiness skipped.\n", "CONTROL layered readiness skipped Home validation"),
        ("raw-h3-downgrade", "wireguard", "protocol=$homeDNS.protocol;dns_host", "protocol=$(if($homeDNS.protocol -eq 'h3'){'https'}else{$homeDNS.protocol});dns_host", "CONTROL Home transport overwritten"),
        ("raw-h3-launch", "wireguard", "'-protocol',[string]$Dns.protocol", "'-protocol',$(if($Dns.protocol -eq 'h3'){'https'}else{[string]$Dns.protocol})", "CONTROL raw proxy arguments changed Home transport"),
        ("raw-h3-tls", "wireguard", "$protocol -in @('tls','https','h3')", "$protocol -in @('tls','https')", "CONTROL raw H3 accepted missing TLS identity"),
        ("raw-tls-arguments", "wireguard", "@('-server-name',[string]$Dns.server_name)", "@('-server-name','other.invalid')", "CONTROL raw proxy arguments lost Home TLS identity"),
        ("raw-proof-fields", "wireguard", "server_name=$($Dns.server_name)`npath=$($Dns.path)", "server_name=other.invalid`npath=/other", "CONTROL raw DNS hint lost TLS or HTTPS proof fields"),
        ("wrong-profile-case", "wireguard", "if ([string]$profile.id -cne $profileId)", "if ($false)", "CONTROL wrong captured profile case accepted"),
    ]
    parameters = {"private": "-PrivateSource", "layered": "-LayeredSource", "wireguard": "-WireGuardSource"}
    with tempfile.TemporaryDirectory(prefix="routervpn-home-dns-defects-") as temp:
        for name, kind, old, new, rejection in mutations:
            if source[kind].count(old) != 1:
                raise AssertionError("Mutation seam missing or duplicated: " + name)
            path = Path(temp) / (name + ".ps1")
            path.write_text(source[kind].replace(old, new, 1), encoding="utf-8")
            run(command + [parameters[kind], str(path)], rejection)
            print("Rejected executable defect: " + name, flush=True)
    print(f"Windows Home DNS: {len(mutations)} executable defect controls passed", flush=True)


if __name__ == "__main__":
    main()
