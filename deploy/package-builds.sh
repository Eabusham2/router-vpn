#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd);DIST="$ROOT/dist";OUT="$DIST/packages";rm -rf "$OUT";mkdir -p "$OUT"
write_blank_routers(){ cat >"$1" <<'JSON'
{"schema_version":4,"selected_id":"","profiles":[]}
JSON
}
copy_runtime(){ local dir=$1;mkdir -p "$dir/modes" "$dir/generated";cp "$ROOT/configs/client/client.json.example" "$dir/client.json";cp "$ROOT/configs/client/modes.json" "$dir/modes.json";cp "$ROOT/configs/client/logical-modes.json" "$dir/logical-modes.json";cp -a "$ROOT/modes/." "$dir/modes/";write_blank_routers "$dir/routers.json";cp "$ROOT/docs/MODES.md" "$dir/MODES.md";cp "$ROOT/docs/CLIENT.md" "$dir/CLIENT.md";cp "$ROOT/SECURITY.md" "$dir/SECURITY.md";cp "$ROOT/LICENSE" "$dir/LICENSE";}
materialize_icons(){ python3 "$ROOT/deploy/materialize-desktop-icons.py" --png "$1/RouterVPN.png" --ico "$1/RouterVPN.ico"; }
# Every native package carries exact-source metadata in ROUTER-VPN-SOURCE.json.
write_provenance(){ python3 "$ROOT/server/scripts/source_provenance.py" "$1" --family "$2"; }
package_zip(){ local name=$1 dir=$2;(cd "$(dirname "$dir")"&&zip -qr "$OUT/$name.zip" "$(basename "$dir")");}
package_tgz(){ local name=$1 dir=$2;tar -C "$(dirname "$dir")" -czf "$OUT/$name.tar.gz" "$(basename "$dir")";}
write_windows_app_launcher(){ local file=$1;cat >"$file" <<'PS1'
$ErrorActionPreference='Stop'
$Root=Split-Path -Parent $MyInvocation.MyCommand.Path
$env:HOMEVPN_ROOT=$Root
$env:HOMEVPN_CLIENT_CONFIG=Join-Path $Root 'client.json'
$client=Join-Path $Root 'router-vpn-client.exe'
$app=Join-Path $Root 'client\RouterVPN-Windows-App.ps1'
if(-not(Test-Path -LiteralPath $app)){throw'Native Router VPN Windows app is missing from this package.'}
function Test-RouterVPNReady{try{$r=Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:8788/api/status' -TimeoutSec 1;return $r.StatusCode-ge 200-and$r.StatusCode-lt 300}catch{return$false}}
$owned=$false;$controller=$null
try{
  if(-not(Test-RouterVPNReady)){$controller=Start-Process $client -WorkingDirectory $Root -PassThru -WindowStyle Hidden;$owned=$true}
  $deadline=(Get-Date).AddSeconds(12)
  while((Get-Date)-lt$deadline-and-not(Test-RouterVPNReady)){Start-Sleep -Milliseconds 200}
  if(-not(Test-RouterVPNReady)){throw'Router VPN controller did not become ready on 127.0.0.1:8788'}
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $app -BaseUrl 'http://127.0.0.1:8788'
  if($LASTEXITCODE-ne 0){throw"Router VPN native Windows app exited with code $LASTEXITCODE"}
}finally{
  if($owned){
    try{Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:8788/api/emergency-stop' -Method Post -ContentType 'application/json' -Body '{}' -TimeoutSec 2|Out-Null}catch{}
    if($controller-and-not$controller.HasExited){Stop-Process -InputObject $controller -Force -ErrorAction SilentlyContinue;try{$controller.WaitForExit(3000)|Out-Null}catch{}}
  }
}
PS1
}
# Package the native Windows Router VPN WPF app and its recovery launcher.
for arch in amd64 arm64;do dir="$OUT/work/RouterVPN-Windows-$arch";mkdir -p "$dir";copy_runtime "$dir";cp "$DIST/client/router-vpn-client-windows-$arch.exe" "$dir/router-vpn-client.exe";cp "$DIST/dnsproxy/router-vpn-dns-windows-$arch.exe" "$dir/router-vpn-dns.exe";cp "$DIST/app-update/router-vpn-update-windows-$arch.exe" "$dir/router-vpn-update.exe";cp "$DIST/client/RouterVPN-$arch.exe" "$dir/RouterVPN.exe";cp -a "$ROOT/client" "$dir/client";cp "$ROOT/client/install-windows.ps1" "$dir/install-windows.ps1";cp "$ROOT/client/Setup-Windows-Runtime.ps1" "$dir/Setup-Windows-Runtime.ps1";materialize_icons "$dir";write_windows_app_launcher "$dir/Start-RouterVPN.ps1";cat >"$dir/README-WINDOWS.txt" <<'TXT'
Double-click RouterVPN.exe for the normal native Windows Router VPN app. install-windows.ps1 can
install the package and create a Start Menu entry with the Router VPN icon. Start-RouterVPN.ps1
remains a recovery launcher for the same WPF product. The app talks only to the local 127.0.0.1
controller API; it does not launch Edge/Chrome and does not embed a website/WebView.
A short-lived router-vpn-update.exe helper checks immutable exact-SHA releases when the app starts,
verifies RouterVPN-RELEASE.json plus the package SHA-256, and stages a newer package without
replacing a running app. The staged package is installed only through the normal restart/handoff.
Run Setup-Windows-Runtime.ps1 once for native full-device layered TUN modes. It installs pinned,
hash-verified native Windows sing-box/Xray engines. Raw WireGuard uses the official WireGuard for
Windows tunnel service. Modes whose Windows engine is not implemented stay unavailable with an
exact readiness reason rather than being substituted with a compatibility-layer engine.
This generic application package contains no linked home/server node; link nodes separately.
Router VPN is MIT-licensed open-source software; see LICENSE.
TXT
write_provenance "$dir" "windows-$arch";package_zip "RouterVPN-Windows-$arch" "$dir";done
for arch in amd64 arm64;do root="$OUT/work/RouterVPNPortable-$arch";app="$root/App/RouterVPN";data="$root/Data";mkdir -p "$app" "$data/generated";copy_runtime "$app";cp -a "$ROOT/client" "$app/client";cp "$DIST/client/router-vpn-client-windows-$arch.exe" "$app/router-vpn-client.exe";cp "$DIST/dnsproxy/router-vpn-dns-windows-$arch.exe" "$app/router-vpn-dns.exe";cp "$DIST/app-update/router-vpn-update-windows-$arch.exe" "$app/router-vpn-update.exe";cp "$DIST/client/RouterVPNPortable-$arch.exe" "$root/RouterVPNPortable.exe";cp "$DIST/client/RouterVPNPortableCore-$arch.exe" "$root/RouterVPNPortableCore.exe";cp "$DIST/client/RouterVPNSetupRuntime-$arch.exe" "$root/RouterVPNSetupRuntime.exe";cp "$ROOT/client/Setup-Windows-Runtime.ps1" "$root/Setup-Windows-Runtime.ps1";materialize_icons "$app";cat >"$root/README.txt" <<'TXT'
Double-click RouterVPNPortable.exe. It supervises a short-lived exact-SHA updater and the mature
Portable runtime owner in RouterVPNPortableCore.exe. Closing Router VPN always terminates an updater
that is still running, so no process can keep the Portable folder or USB mounted.
App/RouterVPN contains immutable binaries/catalogs/scripts and the Router VPN window icon. Data
contains writable settings, private linked node data, generated profiles and native Windows engines.
A verified newer Portable ZIP is staged only after immutable release identity + package SHA-256
verification and is applied by replacing the whole Portable folder while Router VPN is stopped.
No Router VPN state is written to AppData or the registry by the portable launcher/app; move the
whole folder. The ZIP is generic and contains no linked node. Add nodes separately by import/pairing.
Router VPN is MIT-licensed open-source software; see App/RouterVPN/LICENSE.
TXT
write_provenance "$root" "windows-portable-$arch";package_zip "RouterVPN-Portable-Windows-$arch" "$root";done
while IFS= read -r binary;do file=$(basename "$binary");target=${file#router-vpn-client-};os=${target%%-*};rest=${target#*-};arch=${rest%.exe};case "$os" in windows)continue;;esac;name="RouterVPN-${os}-${arch}";dir="$OUT/work/$name";mkdir -p "$dir";copy_runtime "$dir";cp "$binary" "$dir/router-vpn-client";cp "$DIST/dnsproxy/router-vpn-dns-${os}-${arch}" "$dir/router-vpn-dns";updater="$DIST/app-update/router-vpn-update-${os}-${arch}";if [[ -f "$updater" ]];then cp "$updater" "$dir/router-vpn-update";chmod +x "$dir/router-vpn-update";fi;chmod +x "$dir/router-vpn-client" "$dir/router-vpn-dns" "$dir/modes/"*.sh;cat >"$dir/start-router-vpn.sh" <<'SH2'
#!/usr/bin/env sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd);export HOMEVPN_ROOT="$ROOT";export HOMEVPN_CLIENT_CONFIG="$ROOT/client.json";cd "$ROOT"
if [ -x "$ROOT/router-vpn-update" ]; then "$ROOT/router-vpn-update" --download --json >/dev/null 2>&1 & fi
exec ./router-vpn-client
SH2
chmod +x "$dir/start-router-vpn.sh";write_provenance "$dir" "$os-$arch";package_tgz "$name" "$dir";done < <(find "$DIST/client" -maxdepth 1 -type f -name 'router-vpn-client-*'|sort)
python3 "$ROOT/deploy/check-generic-package-secrets.py" "$OUT";cp "$DIST/SHA256SUMS" "$OUT/BINARY-SHA256SUMS";(cd "$OUT";find . -maxdepth 1 -type f ! -name 'SHA256SUMS' -print0|sort -z|xargs -0 sha256sum>SHA256SUMS);rm -rf "$OUT/work";printf 'Packaged MIT-licensed secret-free generic artifacts in %s\n' "$OUT"