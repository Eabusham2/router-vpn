#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd);DIST="$ROOT/dist";OUT="$DIST/packages";rm -rf "$OUT";mkdir -p "$OUT"
write_blank_routers(){ cat >"$1" <<'JSON'
{"schema_version":2,"selected_id":"","profiles":[]}
JSON
}
copy_runtime(){ local dir=$1;mkdir -p "$dir/modes" "$dir/generated";cp "$ROOT/configs/client/client.json.example" "$dir/client.json";cp "$ROOT/configs/client/modes.json" "$dir/modes.json";cp "$ROOT/configs/client/logical-modes.json" "$dir/logical-modes.json";cp -a "$ROOT/modes/." "$dir/modes/";write_blank_routers "$dir/routers.json";cp "$ROOT/docs/MODES.md" "$dir/MODES.md";cp "$ROOT/docs/CLIENT.md" "$dir/CLIENT.md";cp "$ROOT/SECURITY.md" "$dir/SECURITY.md";cp "$ROOT/LICENSE" "$dir/LICENSE";}
package_zip(){ local name=$1 dir=$2;(cd "$(dirname "$dir")"&&zip -qr "$OUT/$name.zip" "$(basename "$dir")");}
package_tgz(){ local name=$1 dir=$2;tar -C "$(dirname "$dir")" -czf "$OUT/$name.tar.gz" "$(basename "$dir")";}
write_windows_app_launcher(){ local file=$1;cat >"$file" <<'PS1'
$ErrorActionPreference='Stop';$Root=Split-Path -Parent $MyInvocation.MyCommand.Path;$env:HOMEVPN_ROOT=$Root;$env:HOMEVPN_CLIENT_CONFIG=Join-Path $Root 'client.json';$client=Join-Path $Root 'router-vpn-client.exe'
function Test-RouterVPNReady{try{$r=Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:8788/api/status' -TimeoutSec 1;return $r.StatusCode-ge 200-and$r.StatusCode-lt 300}catch{return$false}}
if(-not(Test-RouterVPNReady)){Start-Process $client -WorkingDirectory $Root};$deadline=(Get-Date).AddSeconds(12);while((Get-Date)-lt$deadline-and-not(Test-RouterVPNReady)){Start-Sleep -Milliseconds 200};if(-not(Test-RouterVPNReady)){throw'Router VPN controller did not become ready on 127.0.0.1:8788'}
$url='http://127.0.0.1:8788/';$candidates=@("$env:ProgramFiles(x86)\Microsoft\Edge\Application\msedge.exe","$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe","$env:ProgramFiles\Google\Chrome\Application\chrome.exe","$env:ProgramFiles(x86)\Google\Chrome\Application\chrome.exe","$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe","$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe","$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\Application\brave.exe");foreach($browser in $candidates){if($browser-and(Test-Path $browser)){Start-Process $browser -ArgumentList "--app=$url";exit 0}};Start-Process $url
PS1
}
for arch in amd64 arm64;do dir="$OUT/work/RouterVPN-Windows-$arch";mkdir -p "$dir";copy_runtime "$dir";cp "$DIST/client/router-vpn-client-windows-$arch.exe" "$dir/router-vpn-client.exe";cp "$DIST/dnsproxy/router-vpn-dns-windows-$arch.exe" "$dir/router-vpn-dns.exe";cp -a "$ROOT/client" "$dir/client";cp "$ROOT/client/install-windows.ps1" "$dir/install-windows.ps1";cp "$ROOT/client/Setup-Windows-Runtime.ps1" "$dir/Setup-Windows-Runtime.ps1";write_windows_app_launcher "$dir/Start-RouterVPN.ps1";cat >"$dir/README-WINDOWS.txt" <<'TXT'
Run Start-RouterVPN.ps1 for the current Router VPN controller/app window.
Run Setup-Windows-Runtime.ps1 once for native full-device layered TUN modes. It installs pinned,
hash-verified native Windows sing-box/Xray engines. Raw WireGuard uses the official WireGuard for
Windows tunnel service. Modes whose Windows engine is not implemented stay unavailable with an
exact readiness reason rather than being substituted with a compatibility-layer engine.
Raw WireGuard/AmneziaWG profiles can also be imported into compatible third-party native apps.
This generic application package contains no linked home/server node; link nodes separately.
Router VPN is MIT-licensed open-source software; see LICENSE.
TXT
package_zip "RouterVPN-Windows-$arch" "$dir";done
for arch in amd64 arm64;do root="$OUT/work/RouterVPNPortable-$arch";app="$root/App/RouterVPN";data="$root/Data";mkdir -p "$app" "$data/generated";copy_runtime "$app";cp -a "$ROOT/client" "$app/client";cp "$DIST/client/router-vpn-client-windows-$arch.exe" "$app/router-vpn-client.exe";cp "$DIST/dnsproxy/router-vpn-dns-windows-$arch.exe" "$app/router-vpn-dns.exe";cp "$DIST/client/RouterVPNPortable-$arch.exe" "$root/RouterVPNPortable.exe";cp "$DIST/client/RouterVPNSetupRuntime-$arch.exe" "$root/RouterVPNSetupRuntime.exe";cp "$ROOT/client/Setup-Windows-Runtime.ps1" "$root/Setup-Windows-Runtime.ps1";write_blank_routers "$data/routers.json";cat >"$root/README.txt" <<'TXT'
Double-click RouterVPNPortable.exe.
App/RouterVPN contains immutable binaries/catalogs/scripts. Data contains writable settings,
private linked node data, generated profiles, native Windows engines and app-window state.
The ZIP is generic and contains no linked node. Add nodes separately by import/pairing. Run
Setup-Windows-Runtime.ps1 once for native layered TUN modes; the pinned sing-box/Xray runtime is
stored under Data and moves with the Portable folder. Unsupported engines stay grey with an exact
reason rather than being substituted with a compatibility-layer engine. Move the whole folder.
Router VPN is MIT-licensed open-source software; see App/RouterVPN/LICENSE.
TXT
package_zip "RouterVPN-Portable-Windows-$arch" "$root";done
while IFS= read -r binary;do file=$(basename "$binary");target=${file#router-vpn-client-};os=${target%%-*};rest=${target#*-};arch=${rest%.exe};case "$os" in windows)continue;;esac;name="RouterVPN-${os}-${arch}";dir="$OUT/work/$name";mkdir -p "$dir";copy_runtime "$dir";cp "$binary" "$dir/router-vpn-client";cp "$DIST/dnsproxy/router-vpn-dns-${os}-${arch}" "$dir/router-vpn-dns";chmod +x "$dir/router-vpn-client" "$dir/router-vpn-dns" "$dir/modes/"*.sh;cat >"$dir/start-router-vpn.sh" <<'SH2'
#!/usr/bin/env sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd);export HOMEVPN_ROOT="$ROOT";export HOMEVPN_CLIENT_CONFIG="$ROOT/client.json";cd "$ROOT";exec ./router-vpn-client
SH2
chmod +x "$dir/start-router-vpn.sh";package_tgz "$name" "$dir";done < <(find "$DIST/client" -maxdepth 1 -type f -name 'router-vpn-client-*'|sort)
python3 "$ROOT/deploy/check-generic-package-secrets.py" "$OUT";cp "$DIST/SHA256SUMS" "$OUT/BINARY-SHA256SUMS";(cd "$OUT";find . -maxdepth 1 -type f ! -name 'SHA256SUMS' -print0|sort -z|xargs -0 sha256sum>SHA256SUMS);rm -rf "$OUT/work";printf 'Packaged MIT-licensed secret-free generic artifacts in %s\n' "$OUT"
