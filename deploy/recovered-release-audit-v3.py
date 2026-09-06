#!/usr/bin/env python3
"""Recovered-contract scorer: current direct source/shipping predicates."""
from __future__ import annotations
import importlib.util
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "deploy" / "recovered-release-audit.py"
spec = importlib.util.spec_from_file_location("routervpn_recovered_release_base", BASE)
if spec is None or spec.loader is None:
    raise SystemExit("cannot load recovered-release-audit.py")
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def shipping_source(build_rel: str, candidates: tuple[str, ...]) -> str:
    build = mod.body(build_rel)
    for rel in candidates:
        if rel in build or Path(rel).name in build:
            return rel
    return ""


def shipping_has(build_rel: str, candidates: tuple[str, ...], *markers: str) -> bool:
    rel = shipping_source(build_rel, candidates)
    return bool(rel) and mod.has(rel, *markers)


def windows_shipping_has(*markers: str) -> bool:
    package = mod.body("deploy/package-builds.sh")
    entry = "client/RouterVPN-Windows-App.ps1"
    product = "client/RouterVPN-Windows-Product-v2.ps1"
    return (
        Path(entry).name in package
        and 'cp -a "$ROOT/client"' in package
        and mod.has(entry, Path(product).name, "PresentationFramework", "ShowDialog()")
        and mod.has(product, *markers)
    )


def release_gate() -> bool:
    return (
        mod.has("server/scripts/setup-center-product-server.py", "setup-center-ai-server.py", "setup_center_release_status.py", "/api/release-status", "_require_auth()")
        and mod.has("server/scripts/setup_center_release_status.py", "exact-sha-image-only", "self_update_available", "safe_sequence")
        and mod.has("server/scripts/run-setup-center.sh", "/src/server/scripts/setup-center-product-server.py")
        and mod.has("server/portainer-current.yaml", "/src/server/scripts/setup-center-product-server.py", "/opt/router-vpn:/opt/router-vpn:ro")
        and mod.no("server/portainer-current.yaml", "build:", "/var/run/docker.sock")
        and mod.has(".github/workflows/setup-release-status-ci.yml", "test_setup_center_release.py", "/var/run/docker.sock")
    )


def macos_killswitch_gate() -> bool:
    structural = (
        mod.has("modes/darwin_kill_switch.py", "com.apple/router-vpn", "pfctl", "utun", "darwin_baseline_utun", "darwin_tunnel_interfaces")
        and mod.has("modes/kill-switch-platform.py", "darwin_apply", "darwin_watch", "darwin_release", "darwin_reassert", "apply_darwin", "remove_darwin")
        and mod.has("modes/mtu-policy-platform.py", 'HERE / "mtu-policy.py"', "CORE.enforce_kill_switch", "kill-switch-platform.py")
        and mod.has("modes/run-platform.sh", "run-mode.sh", "run-combined.sh", "run-max.sh", "run-xhttp.sh", "run-all.sh", "mtu-policy-platform.py", "stop-mode-platform.sh")
        and mod.has("modes/stop-mode-platform.sh", "stop-mode.sh", "kill-switch-platform.py", "release")
        and mod.has("modes/orchestrate-platform.py", "stop-mode.sh", "stop-mode-platform.sh")
        and mod.has("internal/common/mode_platform.go", 'platform != "darwin"', "orchestrate-platform.py", "stop-mode-platform.sh")
        and mod.has("deploy/test_macos_killswitch_contract.py", "macOS strict kill-switch scoped PF/state source contract: OK")
    )
    if not structural:
        return False
    try:
        proc = subprocess.run(
            [sys.executable, str(ROOT / "deploy" / "test_macos_killswitch_contract.py")],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20,
            check=False,
        )
    except Exception:
        return False
    return proc.returncode == 0 and "macOS strict kill-switch scoped PF/state source contract: OK" in proc.stdout


def controller_multihop_platform(platform: str) -> bool:
    routes = "cmd/client/multihop_native_routes.go"
    if not mod.has(routes, "nativeMultihopPlatformSupported", "/api/multihop/status", "/api/multihop/connect", "proveMultihopExit"):
        return False
    if platform == "windows":
        return mod.has(routes, 'runtime.GOOS == "windows"', "nativeWindowsMultihopCommand") and mod.has(
            "cmd/client/multihop_native.go",
            "nativeWindowsMultihopCommand",
            "prepareNativeMultihop",
            'proxy["detour"] = "entry-wg"',
            "nativeWGEndpoint",
        )
    if platform == "darwin":
        return mod.has(routes, 'runtime.GOOS == "darwin"', "nativeDarwinMultihopCommand") and mod.has(
            "cmd/client/multihop_native_darwin.go",
            "nativeDarwinMultihopCommand",
            "prepareNativeMultihop",
            "native-multihop-darwin.sh",
            "HOMEVPN_POLICY_PROFILE_ID",
        ) and mod.has(
            "modes/native-multihop-darwin.sh",
            "sing-box",
            "kill-switch-platform.py",
            "release_guard",
            "cleanup-private-runtime.py",
        )
    return False


def android_map() -> bool:
    return (
        mod.has("android/app/src/main/AndroidManifest.xml", 'android:name=".ProductActivity"', "android.intent.category.LAUNCHER")
        and mod.has(
            "android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java",
            "RouterVpnNodeMapView",
            "Add / select node",
            "Details / proof",
            "⚡ Fastest",
            "Connect",
            "Multihop",
            'controlRow("Settings")',
            'controlRow("Mode")',
            'controlRow("DNS")',
            'smallButton("Forward")',
            'smallButton("Nodes")',
            'smallButton("Profiles")',
            "showHelp",
        )
        and mod.has(
            "android/app/src/main/java/com/eabusham/routervpn/RouterVpnNodeMapView.java",
            "Canvas",
            "Marker",
            "latitude",
            "longitude",
            "Double.isFinite",
            "No real node coordinates in linked profiles",
            "Only real coordinates",
            "LOCATE ME",
            "no first-launch prompt",
        )
    )


def ios_map() -> bool:
    return (
        mod.has("ios/RouterVPN/App/RouterVPNApp.swift", "ProductRootView()")
        and mod.has("ios/RouterVPN/project.yml", "sources:", "- App", "- Resources")
        and mod.has("ios/RouterVPN/App/ProductRootView.swift", "IOSUnifiedProductView()")
        and mod.has(
            "ios/RouterVPN/App/IOSUnifiedProductView.swift",
            "import MapKit",
            "IOSUnifiedMap",
            "MKMapView",
            "latitude",
            "longitude",
            "(-90...90).contains(lat)",
            "(-180...180).contains(lon)",
            "!(lat == 0 && lon == 0)",
            "RouterVPNNodeManagerSheet",
            "IOSUserLocationControl()",
            "real coordinates",
        )
        and mod.has(
            "ios/RouterVPN/App/IOSUserLocationOverlay.swift",
            "IOSUserLocationControl",
            "requestFromUserTap",
            "requestWhenInUseAuthorization",
            "requestLocation()",
            "horizontalAccuracy",
            "MapKit user annotation",
            "no automatic request, no IP geolocation, no synthetic coordinate",
        )
    )


def selected_dns_proof() -> bool:
    return (
        mod.has(
            "cmd/client/dns_proof.go",
            "proveSelectedDNS",
            "verifyKernelDNSRuntime",
            "verifySingBoxDNSRuntime",
            "net.DefaultResolver.LookupHost",
            "selected-dns",
            "hijack-dns",
            'result.Status = "passed"',
        )
        and mod.has(
            "cmd/client/session_state.go",
            "proveDNSAsync",
            "DNSProof",
            'DNSProof.Status = "checking"',
            '"dns-proof"',
            "t.session.DNSProof = proof",
        )
    )


LINUX_SHIPPING = (
    "client/linux/routervpn-gtk-product-v5.c",
    "client/linux/routervpn-product-onboarding-v6.inc",
    "client/linux/routervpn-home-summary-v1.inc",
    "client/linux/routervpn-profile-settings-v1.inc",
    "client/linux/routervpn-auto-requirements-v11.inc",
    "client/linux/routervpn-unified-shell-v8.inc",
    "client/linux/routervpn-telemetry-v9.inc",
    "client/linux/routervpn-speed-lab-v12.inc",
    "client/linux/routervpn-globe-v10.inc",
    "client/linux/routervpn-gtk-product-v4.c",
    "client/linux/routervpn-gtk-product-v3.c",
    "client/linux/routervpn-gtk-product.c",
)


def linux_shipping_has(*markers: str) -> bool:
    build = mod.body("client/linux/build-native-app.sh")
    if not build or not all(Path(rel).name in build for rel in LINUX_SHIPPING):
        return False
    text = "\n".join(mod.body(rel) for rel in LINUX_SHIPPING)
    return bool(text) and all(marker in text for marker in markers)


mod.RECOVERED = [
    {"name":"strict macOS kill-switch enforcement","weight":1.0,"pass":macos_killswitch_gate,"note":"scoped fail-closed PF backend plus platform launch/stop/SMART/ALL wiring must pass the non-mutating recovered contract"},
    {"name":"authenticated release/update status and safe recovery surface","weight":0.5,"pass":release_gate,"note":"read-only exact-SHA recovery/status composed over existing auth; no Docker socket/build path"},
    {"name":"Windows native typed connection progress","weight":0.17,"pass":lambda: windows_shipping_has("/api/session/events"),"note":"shipping WPF app must consume typed session attempt/fallback/rollback events"},
    {"name":"macOS native typed connection progress","weight":0.17,"pass":lambda: shipping_has("client/macos/build-native-app.sh",("client/macos/RouterVPNMacProduct.swift",),"/api/session/events"),"note":"shipping AppKit source selected by build-native-app.sh must consume typed session events"},
    {"name":"Linux native typed connection progress","weight":0.16,"pass":lambda: linux_shipping_has("/api/session/events"),"note":"shipping GTK app must consume typed session events"},
    {"name":"selected DNS end-to-end proof plumbing","weight":0.5,"pass":selected_dns_proof,"note":"active runtime enforcement plus live OS resolver success is required; home-node benchmarking alone earns no credit"},
    {"name":"Windows desktop real multihop parity","weight":0.25,"pass":lambda: controller_multihop_platform("windows") and windows_shipping_has("/api/multihop/status","/api/multihop/connect"),"note":"Windows must run and expose a real entry->exit dataplane, not only display config"},
    {"name":"macOS desktop real multihop parity","weight":0.25,"pass":lambda: controller_multihop_platform("darwin") and shipping_has("client/macos/build-native-app.sh",("client/macos/RouterVPNMacProduct.swift",),"/api/multihop/status","/api/multihop/connect"),"note":"macOS must run and expose a real entry->exit dataplane"},
    {"name":"Windows native IA + real-coordinate map","weight":0.2,"pass":lambda: windows_shipping_has("MapCanvas","latitude","longitude","No real node coordinates","Forwarding","Settings","Help"),"note":"shipping WPF app needs requested product IA and functional real-coordinate node map"},
    {"name":"macOS native IA + real-coordinate map","weight":0.2,"pass":lambda: shipping_has("client/macos/build-native-app.sh",("client/macos/RouterVPNMacProduct.swift",),"MapKit","MKMapView","latitude","longitude","Forwarding","Settings","Help"),"note":"shipping AppKit app needs product IA and only real stored coordinates"},
    {"name":"Linux native IA + real-coordinate map","weight":0.2,"pass":lambda: linux_shipping_has("Map","latitude","longitude","Forwarding","Settings","Help"),"note":"shipping GTK app needs product IA and real-coordinate map"},
    {"name":"Android native IA + real-coordinate map","weight":0.2,"pass":android_map,"note":"Android needs native node/map product surface using stored coordinates"},
    {"name":"iOS native IA + real-coordinate map","weight":0.2,"pass":ios_map,"note":"iOS/iPadOS needs native node/map product surface using stored coordinates while unsupported modes stay truthful"},
]

assert abs(sum(float(g["weight"]) for g in mod.RECOVERED) - 4.0) < 0.001
raise SystemExit(mod.main())
