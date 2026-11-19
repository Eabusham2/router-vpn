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
    private(set) var activeIDs: [String]?
    private(set) var coordinates: [CLLocationCoordinate2D?] = []
    private var routeID = ""
    var refreshing = false
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

    func update(ids: [String]?, coordinates: [CLLocationCoordinate2D?], routeID: String, pathMs: Double) {
        if self.routeID != routeID { phase = 0 }
        self.routeID = routeID
        self.activeIDs = ids
        self.coordinates = coordinates
        self.pathMs = pathMs.isFinite ? max(0, pathMs) : 0
        routeConnected = coordinates.count >= 2 && !routeID.isEmpty
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

        // The shared opaque vector base owns geography; MapKit remains the
        // coordinate/gesture engine. This chrome draws only VPN route state.
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

        guard routeConnected else { return }
        let mid = NSPoint(x: bounds.midX, y: bounds.minY + 34)
        let label = (pathMs > 0 ? String(format: "PATH %.1f ms", pathMs) : "LIVE MULTIHOP") as NSString
        let attrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.monospacedDigitSystemFont(ofSize: 10.5, weight: .semibold),
            .foregroundColor: NSColor.white,
            .backgroundColor: NSColor(calibratedRed: 0.04, green: 0.09, blue: 0.18, alpha: 0.82)
        ]
        let size = label.size(withAttributes: attrs)
        label.draw(at: NSPoint(x: mid.x - size.width / 2, y: mid.y - size.height / 2), withAttributes: attrs)

        let step = Double(phase) * Double(coordinates.count - 1)
        let index = min(Int(step), coordinates.count - 2)
        guard let from = coordinates[index], let to = coordinates[index + 1],
              let a = RouterVPNMapGeometry.project(latitude: from.latitude, longitude: from.longitude),
              let b = RouterVPNMapGeometry.project(latitude: to.latitude, longitude: to.longitude) else { return }
        // Follow the same projected segment (including the dateline split) as
        // the MKPolyline underneath the packet. A missing hop leaves a gap.
        let point = RouterVPNMapGeometry.routePoint(from: a, to: b, fraction: step - Double(index))
        let world = MKMapRect.world.size.width
        let packet = mapView.convert(MKMapPoint(x: point.x * world, y: point.y * world).coordinate, toPointTo: self)
        guard packet.x.isFinite, packet.y.isFinite else { return }
        let glow = NSBezierPath(ovalIn: NSRect(x: packet.x - 7, y: packet.y - 7, width: 14, height: 14))
        NSColor.systemCyan.withAlphaComponent(0.24).setFill(); glow.fill()
        let dot = NSBezierPath(ovalIn: NSRect(x: packet.x - 3.5, y: packet.y - 3.5, width: 7, height: 7))
        NSColor.white.setFill(); dot.fill()


    }
}


@MainActor
private final class RouterVPNMacUserLocationController: NSObject, CLLocationManagerDelegate {
    private weak var chrome: RouterVPNMacRouteChromeView?
    private weak var button: NSButton?
    private let manager = CLLocationManager()
    private var expiry: Timer?
    private var requestedByUser = false

    init(chrome: RouterVPNMacRouteChromeView, button: NSButton) {
        self.chrome = chrome
        self.button = button
        super.init()
        manager.delegate = self
        manager.desiredAccuracy = kCLLocationAccuracyHundredMeters
    }

    @objc func toggle(_ sender: NSButton) {
        if requestedByUser {
            clearFix("Show my location")
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
            clearFix("Location unavailable")
        @unknown default:
            clearFix("Location unavailable")
        }
    }

    nonisolated func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        let authorization = manager.authorizationStatus
        Task { @MainActor [weak self] in
            guard let self, self.requestedByUser else { return }
            switch authorization {
            case .authorizedAlways, .authorizedWhenInUse: self.requestFix()
            case .denied, .restricted: self.clearFix("Location unavailable")
            case .notDetermined: break
            @unknown default: self.clearFix("Location unavailable")
            }
        }
    }

    nonisolated func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        let sample = locations.last.map { location in
            (location.coordinate, location.horizontalAccuracy, -location.timestamp.timeIntervalSinceNow)
        }
        Task { @MainActor [weak self] in
            guard let self, self.requestedByUser, let sample else { return }
            guard sample.1 >= 0, sample.1 <= 10_000, sample.2 >= 0, sample.2 < 30,
                  CLLocationCoordinate2DIsValid(sample.0) else {
                self.clearFix("No fresh location fix")
                return
            }
            self.chrome?.updateUserLocation(sample.0)
            self.expiry?.invalidate()
            self.expiry = Timer.scheduledTimer(withTimeInterval: 30 - sample.2, repeats: false) { [weak self] _ in
                Task { @MainActor in self?.clearFix("Show my location") }
            }
            self.button?.title = "Hide my location"
            self.button?.toolTip = "Hide the real device marker from the Router VPN map."
        }
    }

    nonisolated func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        Task { @MainActor [weak self] in
            guard let self, self.requestedByUser else { return }
            self.clearFix("Location fix unavailable")
        }
    }

    private func clearFix(_ title: String) {
        expiry?.invalidate()
        requestedByUser = false
        manager.stopUpdatingLocation()
        chrome?.updateUserLocation(nil)
        button?.title = title
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
        RouterVPNVectorMap.install(on: map)
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

    var activeMapNodeIDs: [String]? { unifiedMapChromeView?.activeIDs }

    func activeMapCoordinate(_ id: String) -> CLLocationCoordinate2D? {
        guard let chrome = unifiedMapChromeView, let index = chrome.activeIDs?.firstIndex(of: id),
              chrome.coordinates.indices.contains(index) else { return nil }
        return chrome.coordinates[index]
    }

    func refreshUnifiedMapChrome() {
        guard let chrome = unifiedMapChromeView, !chrome.refreshing else { return }
        chrome.refreshing = true
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            let status = try? self.api.json("/api/multihop/status", timeout: 4) as? [String: Any]
            let connected = status?["connected"] as? Bool
            let ids = status?["active_node_ids"] as? [String] ?? []
            let token = status?["active_route_id"] as? String ?? ""
            let valid = connected == true && (2...8).contains(ids.count) && Set(ids).count == ids.count &&
                !ids.contains("") && token.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil &&
                ids.first == (status?["actual_entry_id"] as? String) && ids.last == (status?["actual_exit_id"] as? String)
            let nodes = status?["nodes"] as? [[String: Any]] ?? []
            let coordinates: [CLLocationCoordinate2D?] = valid ? ids.map { id in
                guard let node = nodes.first(where: { $0["id"] as? String == id }) else { return nil }
                return Self.unifiedMapCoordinate(node)
            } : []
            var measured = 0.0
            if valid, let entry = ids.first, let exit = ids.last,
               let response = try? self.api.request("/api/multihop/live-latency", method: "POST",
                                                    body: ["entry_id": entry, "exit_id": exit, "samples": 2], timeout: 7),
               let receipt = try? JSONSerialization.jsonObject(with: response) as? [String: Any],
               receipt["active_route_id"] as? String == token,
               let path = receipt["current_path"] as? [String: Any] {
                measured = (path["median_ms"] as? NSNumber)?.doubleValue ?? 0
            }
            DispatchQueue.main.async {
                chrome.refreshing = false
                chrome.update(ids: valid ? ids : (connected == false ? nil : []),
                              coordinates: coordinates, routeID: valid ? token : "", pathMs: measured)
                self.refreshUnifiedHopOverlay()
            }
        }
    }
}
