#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import re
import textwrap


def replace_between(text: str, start: str, end: str, replacement: str, label: str) -> str:
    a = text.find(start)
    if a < 0:
        raise SystemExit(f"{label}: start marker not found")
    b = text.find(end, a)
    if b < 0:
        raise SystemExit(f"{label}: end marker not found")
    return text[:a] + textwrap.dedent(replacement).lstrip("\n") + text[b:]


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if text.count(old) != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {text.count(old)}")
    return text.replace(old, new, 1)


# ---------------------------------------------------------------------------
# Download broker: surface actual locating/downloading/validating/building/
# packaging and streaming-byte progress to DownloadJobManager.
# ---------------------------------------------------------------------------
p = Path("server/scripts/download-broker.py")
s = p.read_text(encoding="utf-8")

s = replace_between(
    s,
    "def _download_limited(url: str, path: Path) -> None:\n",
    "def _safe_artifact_name",
    r'''
def _download_limited(url: str, path: Path, progress=None) -> None:
    total = 0
    if progress:
        progress("downloading", 28)
    with _urlopen(url, timeout=25) as r, path.open("wb") as w:
        try:
            expected = int(r.headers.get("Content-Length", "0") or 0)
        except ValueError:
            expected = 0
        while True:
            chunk = r.read(CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_GITHUB_ARTIFACT:
                raise RuntimeError("GitHub artifact exceeds safety limit")
            w.write(chunk)
            if progress and expected > 0:
                progress("downloading", min(39, 28 + int(11 * total / expected)))
    if total == 0:
        raise RuntimeError("GitHub returned an empty artifact")


''',
    "download byte progress",
)

s = replace_between(
    s,
    "def fetch_artifact_member(artifact_name: str, wanted: str, temp: Path, output_name: str) -> Path:\n",
    "def _run_builder",
    r'''
def fetch_artifact_member(artifact_name: str, wanted: str, temp: Path, output_name: str, progress=None) -> Path:
    if os.environ.get("ROUTER_VPN_GITHUB_DISABLE", "").lower() in ("1", "true", "yes"):
        raise RuntimeError("GitHub artifact use disabled")
    if progress:
        progress("locating", 15)
    repo, branch, head_sha = _github_scope()
    if not artifact_name:
        raise RuntimeError("invalid GitHub artifact name")
    q = urllib.parse.urlencode({"name": artifact_name, "per_page": 100})
    meta = _read_limited_json(f"https://api.github.com/repos/{repo}/actions/artifacts?{q}")
    candidates = _artifact_candidates(meta, artifact_name, branch, head_sha)
    if not candidates:
        scope = branch or "any branch"
        if head_sha:
            scope += f" at {head_sha}"
        raise RuntimeError(f"no unexpired {artifact_name} artifact for {scope}")
    outer = temp / (artifact_name + "-artifact.zip")
    _download_limited(candidates[0]["archive_download_url"], outer, progress=progress)
    if progress:
        progress("validating", 42)
    selected = temp / output_name
    with zipfile.ZipFile(outer) as zf:
        item = _pick_member(zf, wanted)
        with zf.open(item) as r, selected.open("wb") as w:
            shutil.copyfileobj(r, w, CHUNK)
    outer.unlink(missing_ok=True)
    if not selected.is_file() or selected.stat().st_size == 0:
        raise RuntimeError("selected GitHub package is empty")
    return selected


def _fetch_first_artifact(sources, temp: Path, output_name: str, progress=None) -> Path:
    failures = []
    for artifact_name, wanted in sources:
        try:
            return fetch_artifact_member(str(artifact_name), str(wanted), temp, output_name, progress=progress)
        except Exception as exc:
            failures.append(f"{artifact_name}: {type(exc).__name__}: {exc}")
    raise RuntimeError("; ".join(failures) if failures else "no GitHub artifact sources configured")


def fetch_github_package(home_name: str, temp: Path, progress=None) -> Path:
    generic = _builder.generic_name(home_name)
    if not generic:
        raise RuntimeError("this download has no generic GitHub package")
    override = os.environ.get("ROUTER_VPN_GITHUB_ARTIFACT", "").strip()
    if override:
        sources = ((override, generic),)
    else:
        sources = NATIVE_PACKAGE_ARTIFACTS.get(home_name, (("RouterVPN-client-desktop-unix-ci", generic),))
    return _fetch_first_artifact(sources, temp, generic, progress=progress)


def fetch_direct_mobile(name: str, temp: Path, progress=None) -> Path:
    spec = DIRECT_ARTIFACTS[name]
    try:
        return _fetch_first_artifact(spec["sources"], temp, name, progress=progress)
    except Exception as exc:
        raise RuntimeError(
            f"{name} requires its same-SHA GitHub mobile artifact; the Linux home node does not fake a platform-specific mobile build fallback: {exc}"
        ) from exc


''',
    "artifact progress",
)

s = replace_between(
    s,
    "def _run_builder(base: Path, name: str, temp: Path, source: Path | None) -> Path:\n",
    "@contextmanager",
    r'''
def _run_builder(base: Path, name: str, temp: Path, source: Path | None, progress=None) -> Path:
    output = temp / name
    args = [
        "python3", str(BUILDER_PATH), "--base", str(base),
        "--source-root", os.environ.get("ROUTER_VPN_FALLBACK_ROOT", "/src"),
        "--name", name, "--output", str(output),
    ]
    if source is not None:
        args += ["--source-archive", str(source)]
    if progress:
        progress("building", 58)
    subprocess.run(args, check=True, timeout=PACKAGE_TIMEOUT, stdout=subprocess.DEVNULL)
    if progress:
        progress("packaging", 84)
    return output


def build_package(base: Path, name: str, temp: Path, progress=None) -> tuple[Path, str]:
    if progress:
        progress("locating", 15)
    if name in DIRECT_ARTIFACTS:
        result = fetch_direct_mobile(name, temp, progress=progress)
        if progress:
            progress("validating", 90)
        return result, "github"
    if name == "router-vpn-client-bundle.zip":
        if progress:
            progress("packaging", 70)
        return _run_builder(base, name, temp, None, progress=progress), "private-node-bundle"
    source = None
    try:
        source = fetch_github_package(name, temp, progress=progress)
    except Exception as exc:
        print(f"download broker: GitHub build unavailable for {name}: {type(exc).__name__}: {exc}; compiling requested generic package locally", flush=True)
    if source is not None:
        try:
            if progress:
                progress("validating", 48)
            return _run_builder(base, name, temp, source, progress=progress), "github"
        except Exception as exc:
            print(f"download broker: GitHub package validation/repack failed for {name}: {type(exc).__name__}: {exc}; compiling requested generic package locally", flush=True)
    if progress:
        progress("building", 58)
    return _run_builder(base, name, temp, None, progress=progress), "router-local-generic-build"


''',
    "builder progress",
)

pattern = re.compile(
    r'(?P<indent>\s+)with package\.open\("rb"\) as f:\n'
    r'(?P=indent)    shutil\.copyfileobj\(f, self\.wfile, CHUNK\)\n'
    r'(?P=indent)success = True'
)
m = pattern.search(s)
if not m:
    raise SystemExit("job delivery streaming block not found")
indent = m.group("indent")
stream = (
    f'{indent}sent = 0\n'
    f'{indent}with package.open("rb") as f:\n'
    f'{indent}    while True:\n'
    f'{indent}        chunk = f.read(CHUNK)\n'
    f'{indent}        if not chunk:\n'
    f'{indent}            break\n'
    f'{indent}        self.wfile.write(chunk)\n'
    f'{indent}        sent += len(chunk)\n'
    f'{indent}        self.server.jobs.update_delivery(job_id, sent, size)\n'
    f'{indent}success = True'
)
s = s[:m.start()] + stream + s[m.end():]
p.write_text(s, encoding="utf-8")


# ---------------------------------------------------------------------------
# Setup Center Methods: only simple, interoperable protocol lanes live here.
# Complex 16-logical-mode stacks remain in the native Router VPN app.
# ---------------------------------------------------------------------------
p = Path("server/scripts/generate-setup-assets.py")
s = p.read_text(encoding="utf-8")

methods = r'''
def build_methods(gen: pathlib.Path, endpoint: str, socks_host: str) -> list[dict]:
    methods: list[dict] = []
    methods.append(asset(
        "wireguard", "WireGuard Raw", "Simple VPN", config=read_text(gen/"wg"/"wg.conf"),
        apps=["WireGuard", "Router VPN"],
        note="Fastest and simplest full-tunnel profile. Recommended first independent-client connectivity test.",
        native="WireGuard app: add/import a tunnel, choose the generated .conf or scan its QR, approve the OS VPN permission, then connect.", simple=True,
    ))
    methods.append(asset(
        "amneziawg2", "AmneziaWG 2", "Simple obfuscated VPN", config=read_text(gen/"awg2-fast"/"awg.conf"),
        apps=["AmneziaVPN / AmneziaWG", "Router VPN"],
        note="WireGuard-family tunnel with packet/header obfuscation.",
        native="Amnezia-compatible app: import the generated AWG config, approve VPN permission, then connect.", simple=True,
    ))

    ss = outbound(gen/"shadowsocks"/"sing-box.json"); ss_url=""
    if endpoint and endpoint != "router.invalid" and ss:
        ui=urllib.parse.quote(str(ss.get("method") or ""),safe="")+":"+urllib.parse.quote(str(ss.get("password") or ""),safe="")
        ss_url=f"ss://{ui}@{hostport(endpoint,int(ss.get('server_port') or 8388))}/#Router%20VPN%20Shadowsocks"
    methods.append(asset(
        "shadowsocks", "Shadowsocks 2022", "Simple proxy", url=ss_url,
        config=read_text(gen/"shadowsocks"/"sing-box.json"),
        apps=["Shadowsocks/SIP002-compatible client", "sing-box", "Router VPN"],
        note="Uses the public node endpoint. If a public endpoint is not known yet, Setup Center keeps the config available but does not fabricate a public QR.",
        native="Import the SIP002 URL/QR in a client that explicitly supports its Shadowsocks 2022 method.", simple=True,
    ))

    hy=outbound(gen/"hysteria2"/"sing-box.json"); hy_url=""
    if endpoint and endpoint != "router.invalid" and hy:
        tls=hy.get("tls") if isinstance(hy.get("tls"),dict) else {}; obfs=hy.get("obfs") if isinstance(hy.get("obfs"),dict) else {}; q=[]
        if tls.get("server_name"): q.append(("sni",str(tls["server_name"])))
        pin=cert_sha256(gen/"hysteria2"/"cert.pem")
        if pin:q.append(("pinSHA256",pin))
        if obfs.get("type"):q.append(("obfs",str(obfs["type"])))
        if obfs.get("password"):q.append(("obfs-password",str(obfs["password"])))
        hy_url="hysteria2://"+urllib.parse.quote(str(hy.get("password") or ""),safe="")+"@"+hostport(endpoint,int(hy.get("server_port") or 8443))+"/?"+urllib.parse.urlencode(q)+"#Router%20VPN%20Hysteria2"
    methods.append(asset(
        "hysteria2", "Hysteria2 + QUIC", "Simple QUIC VPN/proxy", url=hy_url,
        config=read_text(gen/"hysteria2"/"sing-box.json"), apps=["Hysteria2", "sing-box", "Router VPN"],
        note="Public-endpoint Hysteria2 import URL plus full config.", native="Import into a Hysteria2/sing-box-compatible client.", simple=True,
    ))

    overtls=read_text(gen/"overtls"/"overtls-client.json")
    methods.append(asset(
        "overtls", "SOCKS5 + TLS (OverTLS)", "Simple compatibility proxy", config=overtls,
        apps=["OverTLS-compatible client"],
        note="Public TLS terminates on the home node; backend 14444 stays loopback-only. This is separate from Router VPN's logical-mode catalog.",
        native="Import the generated OverTLS client config in an explicitly compatible client.", simple=True,
    ))
    ssr=read_text(gen/"shadowsocksr"/"ssr-client.json")
    methods.append(asset(
        "shadowsocksr", "ShadowsocksR", "Legacy compatibility", config=ssr,
        apps=["ShadowsocksR-compatible client"],
        note="Legacy compatibility only; prefer WireGuard, Shadowsocks 2022, Hysteria2, or Router VPN.", native="Import only into an SSR-compatible client.", simple=True,
    ))

    # SOCKS5 is intentionally private and only useful after the device already
    # has a route home. Never turn its LAN host into a WAN QR or expose 1080.
    socks=f"SOCKS5 host: {socks_host}\nPort: 1080\nAuthentication: none\nUse only after the device already reaches home through Router VPN/WireGuard/AmneziaWG."
    item=asset(
        "socks5", "SOCKS5 (inside VPN)", "Private app proxy", config=socks,
        apps=["Potatso (manual SOCKS5 profile)", "Apps with SOCKS5 support", "Router VPN"],
        note="Private in-tunnel proxy only. Never WAN-forward TCP 1080. The private host is intentional and is not the public VPN exit IP.",
        native=f"Potatso/manual client: add SOCKS5 host {socks_host}, port 1080, no authentication, only after the device is already connected home through a VPN tunnel.", simple=True,
    )
    item["qrPayload"]=""; item["qrPngBase64"]=""
    methods.append(item)
    return methods


'''
s = replace_between(s, "def build_methods(gen: pathlib.Path, endpoint: str, socks_host: str) -> list[dict]:\n", "def build_html", methods, "simple methods")

# The Methods picker itself must never re-surface arbitrary advanced stacks.
old_picker = "const availableMethods=(DATA.methods||[]).filter(x=>x.available);availableMethods.sort((a,b)=>(b.simple?1:0)-(a.simple?1:0)||a.label.localeCompare(b.label));for(const m of availableMethods){const o=document.createElement('option');o.value=m.id;o.textContent=(m.simple?'Easy — ':'Advanced — ')+m.label;$('method').appendChild(o)}"
new_picker = "const availableMethods=(DATA.methods||[]).filter(x=>x.available&&x.simple);availableMethods.sort((a,b)=>a.label.localeCompare(b.label));for(const m of availableMethods){const o=document.createElement('option');o.value=m.id;o.textContent=m.label;$('method').appendChild(o)}"
s = replace_once(s, old_picker, new_picker, "simple Methods picker")

old_downloads = "const downloads=[['Router profile only','router-vpn-bundle.json','For an already-installed Router VPN app/controller'],['ASUS forwarding helper','asus-merlin-router-vpn-forwards.sh','Persistent Merlin NAT/FORWARD helper'],['macOS Apple Silicon','router-vpn-macos-arm64.zip','M1/M2/M3/M4 and later arm64 Macs'],['macOS Intel','router-vpn-macos-amd64.zip','Intel Macs'],['Linux ARM64','router-vpn-linux-arm64.zip','ARM64 Linux'],['Linux x86-64','router-vpn-linux-amd64.zip','x86-64 Linux'],['Complete private fallback','router-vpn-client-bundle.zip','All platforms/profiles; largest download'],['Checksums','SHA256SUMS','Verify direct downloads before bypassing OS security warnings']];"
new_downloads = "const downloads=[['Node data only','router-vpn-bundle.json','Private node data for an already-installed Router VPN app'],['Windows x64','router-vpn-windows-amd64.zip','Native installed app'],['Windows ARM64','router-vpn-windows-arm64.zip','Native installed app'],['Windows Portable x64','router-vpn-windows-portable-amd64.zip','Normal portable app; no PAF/PortableApps wrapper'],['Windows Portable ARM64','router-vpn-windows-portable-arm64.zip','Normal portable app; no PAF/PortableApps wrapper'],['macOS Apple Silicon','router-vpn-macos-arm64.zip','Native AppKit app'],['macOS Intel','router-vpn-macos-amd64.zip','Native AppKit app'],['Linux ARM64','router-vpn-linux-arm64.zip','Native GTK app'],['Linux x86-64','router-vpn-linux-amd64.zip','Native GTK app'],['Android','router-vpn-android.apk','Native Android VpnService app'],['iPhone / iPad','router-vpn-ios.ipa','Native iOS/iPadOS app; signing may be required'],['ASUS forwarding helper','asus-merlin-router-vpn-forwards.sh','Persistent Merlin NAT/FORWARD helper'],['Private recovery bundle','router-vpn-client-bundle.zip','Explicit private fallback/recovery bundle'],['Checksums','SHA256SUMS','Verify downloads before bypassing OS security warnings']];"
s = replace_once(s, old_downloads, new_downloads, "native download list")

# Replace the stale device block in one bounded operation.
devices_start = "    devices={\n"
devices_end = "    modes = read_json"
new_devices = r'''
    devices={
      "ios":{"label":"iPhone / iPad","customApp":"Router VPN is a real native app. Raw WireGuard uses the PacketTunnel engine today; unsupported layered/AWG/multihop combinations stay visibly unavailable instead of being faked.","steps":["Install Router VPN or a simple compatible protocol app.","Import/pair router-vpn-bundle.json to add this node without reinstalling Router VPN.","For independent WireGuard, import/scan the generated profile in the WireGuard app.","Only choose a Setup Center Method whose client explicitly supports that protocol."]},
      "android":{"label":"Android","customApp":"Router VPN Android is a native VpnService app with native WireGuard/AmneziaWG and supported layered engines. Unsupported combinations fail closed with a reason.","steps":["Install the Router VPN APK.","Import/pair router-vpn-bundle.json to add this node; add later nodes the same way.","Approve Android VPN permission on first connection.","For an independent simple client, import the matching WireGuard/AWG/Shadowsocks/Hysteria2 method below."]},
      "macos":{"label":"macOS","customApp":"Router VPN is a native AppKit application. Install once, then import/pair one or many Router VPN nodes.","steps":["Download the package matching Apple Silicon or Intel.","Install/launch Router VPN and grant required network permissions.","Import/pair router-vpn-bundle.json.","Use Nodes/Map, Modes, DNS, Advanced, Forwarding, Settings and Help inside the native app."]},
      "windows":{"label":"Windows","customApp":"Router VPN is a native Windows application; WSL is not part of the product path. Installed and normal Portable packages are available for x64 and ARM64.","steps":["Download the matching Installed or Portable package.","Launch Router VPN with the privileges required for full-device tunnel/firewall operations and approve Windows network prompts.","Import/pair router-vpn-bundle.json; add more nodes later without reinstalling.","Use WireGuard separately only when you intentionally want the simplest independent profile."]},
      "linux":{"label":"Linux","customApp":"Router VPN is a native GTK application on x86-64 and ARM64.","steps":["Download the matching Linux package.","Install/launch Router VPN and grant the required TUN/firewall privileges.","Import/pair router-vpn-bundle.json.","Use the native app for complex modes/stacks; Methods below are only simple external-client options."]},
      "manual":{"label":"Other / manual","customApp":"Use only a simple generated protocol that another client explicitly supports. Complex Router VPN stacks are not exported as fake universal imports.","steps":["Choose a simple Method below.","Follow its exact client/import guidance.","If no compact interoperable QR exists, use the config/manual fields instead.","Never expose Setup Center, admin, SSH or private SOCKS5 ports to WAN."]},
    }
'''
s = replace_between(s, devices_start, devices_end, new_devices, "native device guidance")

# Remove stale browser/controller/WSL language elsewhere in generated onboarding.
for old, new in {
    "Router VPN app/controller + router-vpn-bundle.json": "Router VPN native app + router-vpn-bundle.json or one-time pairing",
    "app/controller": "native app",
    "local app/PWA": "native app",
    "controller surfaces": "native apps",
    "full multi-engine controller": "full native multi-engine app",
    "Windows build and WSL2 transport environment described in repository docs": "native Windows build; WSL is not required or supported for the product path",
}.items():
    s = s.replace(old, new)

# Explicitly teach the architecture in the wizard.
s = s.replace(
    "This wizard covers the complete path without requiring the huge ZIP.",
    "Install the generic native Router VPN app once, then link one or many private nodes by bundle/pairing. This wizard covers the complete path without requiring the huge ZIP.",
)
p.write_text(s, encoding="utf-8")


# Finalizer credential text must agree with the real bundle default: Home AdGuard.
p = Path("server/finalize/finalize.sh")
s = p.read_text(encoding="utf-8")
s = s.replace(
    "Default DNS policy: fastest (changeable to Home AdGuard, custom, DoT, DoH, DoH3, or rescue in client)",
    "Default DNS policy: Home AdGuard (changeable to Fastest measured, common/custom UDP/TCP, DoT, DoH, DoH3, or Rescue in the client)",
)
p.write_text(s, encoding="utf-8")


# The source patch is one-shot. Remove it and all obsolete reconciliation jobs
# so final main contains product source, not maintenance scaffolding.
for name in (
    ".github/workflows/product-reconciliation-patch.yml",
    ".github/workflows/product-reconciliation-patch-v2.yml",
    ".github/workflows/product-reconciliation-patch-v3.yml",
    ".github/workflows/product-reconciliation-patch-v4.yml",
    ".github/workflows/product-reconciliation-patch-v5.yml",
    ".github/workflows/final-gap-reconciliation.yml",
    "server/scripts/_final_gap_patch.py",
):
    Path(name).unlink(missing_ok=True)
