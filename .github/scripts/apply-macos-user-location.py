#!/usr/bin/env python3
from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GLOBE_REL = "client/macos/RouterVPNMacGlobeChrome.swift"
BUILD_REL = "client/macos/build-native-app.sh"
GLOBE = ROOT / GLOBE_REL
BUILD = ROOT / BUILD_REL


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=ROOT, text=True, check=check)


def commit(paths: list[str], message: str) -> None:
    run("git", "add", "-A", "--", *paths)
    status = run("git", "diff", "--cached", "--quiet", check=False)
    if status.returncode == 0:
        return
    if status.returncode != 1:
        raise SystemExit(f"git diff failed: {status.returncode}")
    run("git", "commit", "-m", message)


def replace_once_or_verify(text: str, old: str, new: str, label: str) -> str:
    old_count = text.count(old)
    new_count = text.count(new)
    if old_count == 1 and new_count == 0:
        return text.replace(old, new, 1)
    if old_count == 0 and new_count == 1:
        return text
    raise SystemExit(f"{label} drift: old={old_count} new={new_count}")


def patch_globe() -> None:
    text = GLOBE.read_text(encoding="utf-8")
    text = replace_once_or_verify(
        text,
        "import AppKit\nimport Foundation\nimport MapKit\n",
        "import AppKit\n@preconcurrency import CoreLocation\nimport Foundation\nimport MapKit\n",
        "macOS CoreLocation import",
    )
    text = replace_once_or_verify(
        text,
        "private var unifiedMapChromeRefreshTimerKey: UInt8 = 0\n",
        "private var unifiedMapChromeRefreshTimerKey: UInt8 = 0\nprivate var unifiedMapLocationControllerKey: UInt8 = 0\n",
        "macOS location controller key",
    )
    text = replace_once_or_verify(
        text,
        "    private var pathMs: Double = 0\n    private var phase: CGFloat = 0",
        "    private var pathMs: Double = 0\n    private var userLocation: CLLocationCoordinate2D?\n    private var phase: CGFloat = 0",
        "macOS user coordinate state",
    )
    text = replace_once_or_verify(
        text,
        "    func advance() {\n        guard routeConnected else { return }",
        "    func updateUserLocation(_ coordinate: CLLocationCoordinate2D?) {\n        userLocation = coordinate\n        needsDisplay = true\n    }\n\n    func advance() {\n        guard routeConnected else { return }",
        "macOS user coordinate update",
    )
    text = replace_once_or_verify(
        text,
        '''        truth.draw(at: NSPoint(x: 22, y: 18), withAttributes: [
            .font: NSFont.systemFont(ofSize: 9, weight: .regular),
            .foregroundColor: NSColor.secondaryLabelColor.withAlphaComponent(0.78)
        ])

        guard routeConnected, let entry, let exit else { return }
''',
        '''        truth.draw(at: NSPoint(x: 22, y: 18), withAttributes: [
            .font: NSFont.systemFont(ofSize: 9, weight: .regular),
            .foregroundColor: NSColor.secondaryLabelColor.withAlphaComponent(0.78)
        ])

        if let userLocation {
            let point = mapView.convert(userLocation, toPointTo: self)
            if point.x.isFinite, point.y.isFinite {
                let halo = NSBezierPath(ovalIn: NSRect(x: point.x - 9, y: point.y - 9, width: 18, height: 18))
                NSColor.systemGreen.withAlphaComponent(0.22).setFill(); halo.fill()
                let marker = NSBezierPath(ovalIn: NSRect(x: point.x - 5, y: point.y - 5, width: 10, height: 10))
                NSColor.systemGreen.setFill(); marker.fill()
                NSColor.white.setStroke(); marker.lineWidth = 1.5; marker.stroke()
                ("YOU" as NSString).draw(
                    at: NSPoint(x: point.x + 8, y: point.y - 6),
                    withAttributes: [
                        .font: NSFont.systemFont(ofSize: 9, weight: .bold),
                        .foregroundColor: NSColor.systemGreen,
                        .backgroundColor: NSColor.windowBackgroundColor.withAlphaComponent(0.78),
                    ]
                )
            }
        }

        guard routeConnected, let entry, let exit else { return }
''',
        "macOS green user marker drawing",
    )

    controller = '''
@MainActor
private final class RouterVPNMacUserLocationController: NSObject, CLLocationManagerDelegate {
    private weak var chrome: RouterVPNMacRouteChromeView?
    private weak var button: NSButton?
    private let manager = CLLocationManager()
    private var shown = false
    private var requestedByUser = false

    init(chrome: RouterVPNMacRouteChromeView, button: NSButton) {
        self.chrome = chrome
        self.button = button
        super.init()
        manager.delegate = self
        manager.desiredAccuracy = kCLLocationAccuracyHundredMeters
    }

    @objc func toggle(_ sender: NSButton) {
        if shown {
            requestedByUser = false
            manager.stopUpdatingLocation()
            chrome?.updateUserLocation(nil)
            shown = false
            sender.title = "Show my location"
            sender.toolTip = "Show a fresh real macOS location fix. Router VPN never infers a device pin from IP."
            return
        }
        requestedByUser = true
        switch manager.authorizationStatus {
        case .notDetermined:
            sender.title = "Location permission…"
            manager.requestWhenInUseAuthorization()
        case .authorizedAlways, .authorizedWhenInUse:
            requestFix()
        case .denied, .restricted:
            sender.title = "Location unavailable"
        @unknown default:
            sender.title = "Location unavailable"
        }
    }

    nonisolated func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        let authorization = manager.authorizationStatus
        Task { @MainActor [weak self] in
            guard let self, self.requestedByUser else { return }
            switch authorization {
            case .authorizedAlways, .authorizedWhenInUse: self.requestFix()
            case .denied, .restricted: self.button?.title = "Location unavailable"
            case .notDetermined: break
            @unknown default: self.button?.title = "Location unavailable"
            }
        }
    }

    nonisolated func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        let sample = locations.last.map { location in
            (location.coordinate, location.horizontalAccuracy, abs(location.timestamp.timeIntervalSinceNow))
        }
        Task { @MainActor [weak self] in
            guard let self, self.requestedByUser, let sample else { return }
            guard sample.1 >= 0, sample.1 <= 10_000, sample.2 <= 30,
                  CLLocationCoordinate2DIsValid(sample.0) else {
                self.button?.title = "No fresh location fix"
                return
            }
            self.chrome?.updateUserLocation(sample.0)
            self.shown = true
            self.button?.title = "Hide my location"
            self.button?.toolTip = "Hide the real device marker from the Router VPN map."
        }
    }

    nonisolated func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        Task { @MainActor [weak self] in
            guard let self, self.requestedByUser else { return }
            self.button?.title = "Location fix unavailable"
        }
    }

    private func requestFix() {
        button?.title = "Locating…"
        manager.requestLocation()
    }
}

'''
    anchor = "extension ProductWindowController {\n"
    if controller not in text:
        if text.count(anchor) != 1:
            raise SystemExit("macOS location-controller insertion anchor drifted")
        text = text.replace(anchor, controller + anchor, 1)

    text = replace_once_or_verify(
        text,
        '''        unifiedMapChromeView = chrome

        let animation = Timer.scheduledTimer''',
        '''        unifiedMapChromeView = chrome

        let locationButton = NSButton(title: "Show my location", target: nil, action: nil)
        locationButton.bezelStyle = .rounded
        locationButton.controlSize = .small
        locationButton.toolTip = "Show a fresh real macOS location fix. Router VPN never infers a device pin from IP."
        locationButton.translatesAutoresizingMaskIntoConstraints = false
        map.addSubview(locationButton, positioned: .above, relativeTo: chrome)
        NSLayoutConstraint.activate([
            locationButton.trailingAnchor.constraint(equalTo: map.trailingAnchor, constant: -18),
            locationButton.topAnchor.constraint(equalTo: map.topAnchor, constant: 16),
        ])
        let locationController = RouterVPNMacUserLocationController(chrome: chrome, button: locationButton)
        locationButton.target = locationController
        locationButton.action = #selector(RouterVPNMacUserLocationController.toggle(_:))
        objc_setAssociatedObject(self, &unifiedMapLocationControllerKey, locationController, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)

        let animation = Timer.scheduledTimer''',
        "macOS location control composition",
    )

    GLOBE.write_text(text, encoding="utf-8")
    commit([GLOBE_REL], "Add opt-in real location to macOS VPN map [skip ci]")


def patch_build() -> None:
    text = BUILD.read_text(encoding="utf-8")
    text = replace_once_or_verify(
        text,
        "xcrun swiftc -O -sdk \"$SDK\" -target \"$TARGET\" -framework AppKit -framework Foundation -framework MapKit \\\n",
        "xcrun swiftc -O -sdk \"$SDK\" -target \"$TARGET\" -framework AppKit -framework CoreLocation -framework Foundation -framework MapKit \\\n",
        "macOS CoreLocation linker",
    )
    text = replace_once_or_verify(
        text,
        "  <key>LSMinimumSystemVersion</key><string>13.0</string><key>NSHighResolutionCapable</key><true/><key>NSPrincipalClass</key><string>NSApplication</string>\n",
        "  <key>LSMinimumSystemVersion</key><string>13.0</string><key>NSHighResolutionCapable</key><true/><key>NSPrincipalClass</key><string>NSApplication</string>\n  <key>NSLocationUsageDescription</key><string>Router VPN shows your real Mac location on the VPN map only after you press Show my location. It never infers a device pin from your IP address.</string>\n",
        "macOS location usage description",
    )
    BUILD.write_text(text, encoding="utf-8")
    commit([BUILD_REL], "Ship macOS CoreLocation map support [skip ci]")


def cleanup() -> None:
    paths = [
        ".github/workflows/one-shot-macos-user-location.yml",
        ".github/scripts/apply-macos-user-location.py",
    ]
    for rel in paths:
        path = ROOT / rel
        if path.exists():
            path.unlink()
    commit(paths, "Remove completed macOS location automation [skip ci]")


def main() -> int:
    patch_globe()
    patch_build()
    run("git", "diff", "--check")
    cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
