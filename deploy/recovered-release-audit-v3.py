#!/usr/bin/env python3
"""Recovered-contract scorer v3: score explicit source gaps by shipping platform."""
from __future__ import annotations
import importlib.util
from pathlib import Path
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
    rel = "client/RouterVPN-Windows-App.ps1"
    return Path(rel).name in package and mod.has(rel, *markers)


def release_gate() -> bool:
    return (
        mod.has("server/scripts/setup-center-product-server.py", "setup-center-ai-server.py", "setup_center_release_status.py", "/api/release-status", "_require_auth()")
        and mod.has("server/scripts/setup_center_release_status.py", "exact-sha-image-only", "self_update_available", "safe_sequence")
        and mod.has("server/scripts/run-setup-center.sh", "/src/server/scripts/setup-center-product-server.py")
        and mod.has("server/portainer-current.yaml", "/src/server/scripts/setup-center-product-server.py", "/opt/router-vpn:/opt/router-vpn:ro")
        and mod.no("server/portainer-current.yaml", "build:", "/var/run/docker.sock")
        and mod.has(".github/workflows/setup-release-status-ci.yml", "test_setup_center_release.py", "/var/run/docker.sock")
    )


def controller_multihop_platform(platform: str) -> bool:
    text = mod.body("cmd/client/multihop.go")
    if 'runtime.GOOS != "linux"' in text:
        return False
    return f'"{platform}"' in text or "platform_supported" in text


def android_map() -> bool:
    return (
        mod.has("android/app/src/main/AndroidManifest.xml", 'android:name=".ProductActivity"', "android.intent.category.LAUNCHER")
        and mod.has(
            "android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java",
            "RouterVpnNodeMapView",
            "latitude",
            "longitude",
            "Home / Connect",
            "Nodes / Map",
            "Modes",
            "DNS",
            "Advanced",
            "Forwarding",
            "Settings",
            "Help",
            "never guesses a location",
        )
        and mod.has(
            "android/app/src/main/java/com/eabusham/routervpn/RouterVpnNodeMapView.java",
            "Canvas",
            "Marker",
            "latitude",
            "longitude",
            "No real node coordinates",
        )
    )


def ios_map() -> bool:
    return (
        mod.has("ios/RouterVPN/App/RouterVPNApp.swift", "ProductRootView()")
        and mod.has("ios/RouterVPN/project.yml", "sources: [App, Resources]")
        and mod.has("ios/RouterVPN/App/ProductRootView.swift", "RouterVPNNodeMapSheet", "Nodes & Map")
        and mod.has(
            "ios/RouterVPN/App/NodeMapSheet.swift",
            "import MapKit",
            "Map {",
            "latitude",
            "longitude",
            "No real node coordinates",
            "never invents map locations",
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


mod.RECOVERED = [
    {"name":"strict macOS kill-switch enforcement","weight":1.0,"pass":lambda: mod.has("modes/kill-switch.py","darwin","apply_darwin") and mod.has("modes/darwin_kill_switch.py","com.apple/router-vpn","pfctl","utun") and mod.has("cmd/client/main.go","HOMEVPN_KILLSWITCH_REFRESH=1"),"note":"scoped fail-closed PF enforcement must be wired into the shipping controller/runtime"},
    {"name":"authenticated release/update status and safe recovery surface","weight":0.5,"pass":release_gate,"note":"read-only exact-SHA recovery/status composed over existing auth; no Docker socket/build path"},
    {"name":"Windows native typed connection progress","weight":0.17,"pass":lambda: windows_shipping_has("/api/session/events"),"note":"shipping WPF app must consume typed session attempt/fallback/rollback events"},
    {"name":"macOS native typed connection progress","weight":0.17,"pass":lambda: shipping_has("client/macos/build-native-app.sh",("client/macos/RouterVPNMacProduct.swift","client/macos/RouterVPNMacNative.swift","client/macos/RouterVPNMacApp.swift"),"/api/session/events"),"note":"shipping AppKit source selected by build-native-app.sh must consume typed session events"},
    {"name":"Linux native typed connection progress","weight":0.16,"pass":lambda: shipping_has("client/linux/build-native-app.sh",("client/linux/routervpn-gtk-product.c","client/linux/routervpn-gtk.c"),"/api/session/events"),"note":"shipping GTK app must consume typed session events"},
    {"name":"selected DNS end-to-end proof plumbing","weight":0.5,"pass":selected_dns_proof,"note":"active runtime enforcement plus live OS resolver success is required; home-node benchmarking alone earns no credit"},
    {"name":"Windows desktop real multihop parity","weight":0.25,"pass":lambda: controller_multihop_platform("windows") and windows_shipping_has("/api/multihop/status","/api/multihop/connect"),"note":"Windows must run and expose a real entry->exit dataplane, not only display config"},
    {"name":"macOS desktop real multihop parity","weight":0.25,"pass":lambda: controller_multihop_platform("darwin") and shipping_has("client/macos/build-native-app.sh",("client/macos/RouterVPNMacProduct.swift","client/macos/RouterVPNMacNative.swift","client/macos/RouterVPNMacApp.swift"),"/api/multihop/status","/api/multihop/connect"),"note":"macOS must run and expose a real entry->exit dataplane"},
    {"name":"Windows native IA + real-coordinate map","weight":0.2,"pass":lambda: windows_shipping_has("Map","latitude","longitude","Forwarding","Settings","Help"),"note":"shipping WPF app needs requested product IA and functional real-coordinate node map"},
    {"name":"macOS native IA + real-coordinate map","weight":0.2,"pass":lambda: shipping_has("client/macos/build-native-app.sh",("client/macos/RouterVPNMacProduct.swift","client/macos/RouterVPNMacNative.swift","client/macos/RouterVPNMacApp.swift"),"MapKit","MKMapView","latitude","longitude","Forwarding","Settings","Help"),"note":"shipping AppKit app needs product IA and only real stored coordinates"},
    {"name":"Linux native IA + real-coordinate map","weight":0.2,"pass":lambda: shipping_has("client/linux/build-native-app.sh",("client/linux/routervpn-gtk-product.c","client/linux/routervpn-gtk.c"),"Map","latitude","longitude","Forwarding","Settings","Help"),"note":"shipping GTK app needs product IA and real-coordinate map"},
    {"name":"Android native IA + real-coordinate map","weight":0.2,"pass":android_map,"note":"Android needs native node/map product surface using stored coordinates"},
    {"name":"iOS native IA + real-coordinate map","weight":0.2,"pass":ios_map,"note":"iOS/iPadOS needs native node/map product surface using stored coordinates while unsupported modes stay truthful"},
]

assert abs(sum(float(g["weight"]) for g in mod.RECOVERED) - 4.0) < 0.001
raise SystemExit(mod.main())
