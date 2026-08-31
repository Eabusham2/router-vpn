import AppKit
@preconcurrency import CoreLocation
import Foundation
import MapKit
import ObjectiveC

private var unifiedMapChromeViewKey: UInt8 = 0
private var unifiedMapChromeAnimationTimerKey: UInt8 = 0
private var unifiedMapChromeRefreshTimerKey: UInt8 = 0
private var unifiedMapLocationControllerKey: UInt8 = 0

private final class RouterVPNMacRouteChromeView: NSView {
    weak var mapView: MKMapView?
    private var entry: CLLocationCoordinate2D?
    private var exit: CLLocationCoordinate2D?
    private var pathMs: Double = 0
    private var userLocation: CLLocationCoordinate2D?
    private var phase: CGFloat = 0
    private var routeConnected = false

    init(mapView: MKMapView) {
        self.mapView = mapView
        super.init(frame: .zero)
        wantsLayer = true
        layer?.backgroundColor = NSColor.clear.cgColor
    }

    required init?(coder: NSCoder) { nil }
    override var isOpaque: Bool { false }
    override func hitTest(_ point: NSPoint) -> NSView? { nil }

    func update(entry: CLLocationCoordinate2D?, exit: CLLocationCoordinate2D?, pathMs: Double, connected: Bool) {
        self.entry = entry
        self.exit = exit
        self.pathMs = max(0, pathMs)
        routeConnected = connected && entry != nil && exit != nil
        needsDisplay = true
    }

    func updateUserLocation(_ coordinate: CLLocationCoordinate2D?) {
        userLocation = coordinate
        needsDisplay = true
    }

    func advance() {
        guard routeConnected else { return }
        phase += 0.012
        if phase >= 1 { phase -= 1 }
        needsDisplay = true
    }

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        guard let mapView else { return }

        // The MapKit map remains the real-coordinate interaction engine. This
        // overlay adds Router VPN-specific chrome without inventing geography.
        let border = NSBezierPath(roundedRect: bounds.insetBy(dx: 8, dy: 8), xRadius: 24, yRadius: 24)
        NSColor(calibratedRed: 0.16, green: 0.31, blue: 0.49, alpha: 0.55).setStroke()
        border.lineWidth = 1.2
        border.stroke()

        let title = "ROUTER VPN • LIVE ROUTE" as NSString
        title.draw(at: NSPoint(x: 22, y: bounds.height - 34), withAttributes: [
            .font: NSFont.systemFont(ofSize: 10.5, weight: .semibold),
            .foregroundColor: NSColor(calibratedRed: 0.73, green: 0.82, blue: 0.94, alpha: 0.88)
        ])
        let truth = "Only linked real coordinates • no IP geolocation or fabricated device pin" as NSString
        truth.draw(at: NSPoint(x: 22, y: 18), withAttributes: [
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
        let a = mapView.convert(entry, toPointTo: self)
        let b = mapView.convert(exit, toPointTo: self)
        guard a.x.isFinite, a.y.isFinite, b.x.isFinite, b.y.isFinite else { return }

        let c1 = NSPoint(x: a.x + (b.x - a.x) * 0.34, y: min(bounds.height - 30, max(a.y, b.y) + 44))
        let c2 = NSPoint(x: a.x + (b.x - a.x) * 0.66, y: min(bounds.height - 30, max(a.y, b.y) + 44))
        let route = NSBezierPath()
        route.move(to: a)
        route.curve(to: b, controlPoint1: c1, controlPoint2: c2)
        route.lineCapStyle = .round
        route.lineJoinStyle = .round
        NSColor.systemBlue.withAlphaComponent(0.30).setStroke()
        route.lineWidth = 9
        route.stroke()
        NSColor.systemCyan.withAlphaComponent(0.92).setStroke()
        route.lineWidth = 3.2
        route.stroke()

        // Cubic Bézier interpolation for a packet moving over the same visible
        // path. This is visual motion only; RTT remains separately measured.
        let t = phase, u = 1 - t
        let packet = NSPoint(
            x: u*u*u*a.x + 3*u*u*t*c1.x + 3*u*t*t*c2.x + t*t*t*b.x,
            y: u*u*u*a.y + 3*u*u*t*c1.y + 3*u*t*t*c2.y + t*t*t*b.y
        )
        let glow = NSBezierPath(ovalIn: NSRect(x: packet.x - 7, y: packet.y - 7, width: 14, height: 14))
        NSColor.systemCyan.withAlphaComponent(0.24).setFill(); glow.fill()
        let dot = NSBezierPath(ovalIn: NSRect(x: packet.x - 3.5, y: packet.y - 3.5, width: 7, height: 7))
        NSColor.white.setFill(); dot.fill()

        let mid = NSPoint(x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 + 28)
        let label = (pathMs > 0 ? String(format: "PATH %.1f ms", pathMs) : "LIVE MULTIHOP") as NSString
        let attrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.monospacedDigitSystemFont(ofSize: 10.5, weight: .semibold),
            .foregroundColor: NSColor.white,
            .backgroundColor: NSColor(calibratedRed: 0.04, green: 0.09, blue: 0.18, alpha: 0.82)
        ]
        let size = label.size(withAttributes: attrs)
        label.draw(at: NSPoint(x: mid.x - size.width / 2, y: mid.y - size.height / 2), withAttributes: attrs)
    }
}


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

extension ProductWindowController {
    private var unifiedMapChromeView: RouterVPNMacRouteChromeView? {
        get { objc_getAssociatedObject(self, &unifiedMapChromeViewKey) as? RouterVPNMacRouteChromeView }
        set { objc_setAssociatedObject(self, &unifiedMapChromeViewKey, newValue, .OBJC_ASSOCIATION_RETAIN_NONATOMIC) }
    }

    func installUnifiedMapChrome() {
        guard unifiedMapChromeView == nil else { return }
        map.mapType = .mutedStandard
        map.showsBuildings = false
        map.showsTraffic = false
        map.pointOfInterestFilter = .excludingAll
        map.wantsLayer = true
        map.layer?.backgroundColor = NSColor(calibratedRed: 0.03, green: 0.07, blue: 0.13, alpha: 1).cgColor

        let chrome = RouterVPNMacRouteChromeView(mapView: map)
        chrome.translatesAutoresizingMaskIntoConstraints = false
        map.addSubview(chrome, positioned: .above, relativeTo: nil)
        NSLayoutConstraint.activate([
            chrome.leadingAnchor.constraint(equalTo: map.leadingAnchor),
            chrome.trailingAnchor.constraint(equalTo: map.trailingAnchor),
            chrome.topAnchor.constraint(equalTo: map.topAnchor),
            chrome.bottomAnchor.constraint(equalTo: map.bottomAnchor)
        ])
        unifiedMapChromeView = chrome

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

        let animation = Timer.scheduledTimer(withTimeInterval: 0.05, repeats: true) { [weak self, weak chrome] timer in
            guard self != nil, let chrome else { timer.invalidate(); return }
            chrome.advance()
        }
        objc_setAssociatedObject(self, &unifiedMapChromeAnimationTimerKey, animation, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)

        let refresh = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] timer in
            guard let self else { timer.invalidate(); return }
            self.refreshUnifiedMapChrome()
        }
        objc_setAssociatedObject(self, &unifiedMapChromeRefreshTimerKey, refresh, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)
        refreshUnifiedMapChrome()
    }

    func refreshUnifiedMapChrome(pathMs: Double? = nil) {
        let explicitPathMs = pathMs
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            do {
                guard let status = try self.api.json("/api/multihop/status", timeout: 4) as? [String: Any],
                      (status["connected"] as? Bool) == true,
                      let entryID = status["entry_id"] as? String, !entryID.isEmpty,
                      let exitID = status["exit_id"] as? String, !exitID.isEmpty,
                      entryID != exitID else {
                    DispatchQueue.main.async { self.unifiedMapChromeView?.update(entry: nil, exit: nil, pathMs: 0, connected: false) }
                    return
                }
                let store = try self.api.json("/api/profiles", timeout: 4) as? [String: Any] ?? [:]
                let profiles = store["profiles"] as? [[String: Any]] ?? []
                func coordinate(_ id: String) -> CLLocationCoordinate2D? {
                    guard let p = profiles.first(where: { ($0["id"] as? String) == id }),
                          let lat = (p["latitude"] as? NSNumber)?.doubleValue,
                          let lon = (p["longitude"] as? NSNumber)?.doubleValue else { return nil }
                    let c = CLLocationCoordinate2D(latitude: lat, longitude: lon)
                    return CLLocationCoordinate2DIsValid(c) && !(lat == 0 && lon == 0) ? c : nil
                }
                guard let entry = coordinate(entryID), let exit = coordinate(exitID) else {
                    DispatchQueue.main.async { self.unifiedMapChromeView?.update(entry: nil, exit: nil, pathMs: 0, connected: false) }
                    return
                }
                var measured = explicitPathMs ?? 0
                if explicitPathMs == nil,
                   let data = try? self.api.request("/api/multihop/live-latency", method: "POST", body: ["entry_id": entryID, "exit_id": exitID, "samples": 2], timeout: 7),
                   let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let current = root["current_path"] as? [String: Any],
                   let value = (current["median_ms"] as? NSNumber)?.doubleValue {
                    measured = value
                }
                DispatchQueue.main.async { self.unifiedMapChromeView?.update(entry: entry, exit: exit, pathMs: measured, connected: true) }
            } catch {
                DispatchQueue.main.async { self.unifiedMapChromeView?.update(entry: nil, exit: nil, pathMs: 0, connected: false) }
            }
        }
    }
}
