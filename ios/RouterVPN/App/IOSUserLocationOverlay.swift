@preconcurrency import CoreLocation
import MapKit
import SwiftUI
import UIKit

@MainActor
final class IOSUserLocationController: NSObject, ObservableObject, CLLocationManagerDelegate {
    @Published private(set) var state = "off"
    @Published private(set) var detail = "Show my real location"
    private let manager = CLLocationManager()
    private var requestedByUser = false

    override init() {
        super.init()
        manager.delegate = self
        manager.desiredAccuracy = kCLLocationAccuracyHundredMeters
    }

    func requestFromUserTap() {
        requestedByUser = true
        switch manager.authorizationStatus {
        case .notDetermined:
            state = "requesting"; detail = "Location permission…"
            manager.requestWhenInUseAuthorization()
        case .authorizedAlways, .authorizedWhenInUse:
            requestRealFix()
        case .denied, .restricted:
            state = "denied"; detail = "Location unavailable"
        @unknown default:
            state = "unavailable"; detail = "Location unavailable"
        }
    }

    nonisolated func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        let authorization = manager.authorizationStatus
        Task { @MainActor [weak self] in
            guard let self, self.requestedByUser else { return }
            switch authorization {
            case .authorizedAlways, .authorizedWhenInUse: self.requestRealFix()
            case .denied, .restricted: self.state = "denied"; self.detail = "Location unavailable"
            case .notDetermined: break
            @unknown default: self.state = "unavailable"; self.detail = "Location unavailable"
            }
        }
    }

    nonisolated func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        let sample = locations.last.map { location in
            (
                latitude: location.coordinate.latitude,
                longitude: location.coordinate.longitude,
                accuracy: location.horizontalAccuracy,
                age: abs(location.timestamp.timeIntervalSinceNow)
            )
        }
        Task { @MainActor [weak self] in
            guard let self, self.requestedByUser, let sample else { return }
            let coordinate = CLLocationCoordinate2D(latitude: sample.latitude, longitude: sample.longitude)
            guard sample.accuracy >= 0,
                  sample.accuracy <= 10_000,
                  sample.age <= 30,
                  CLLocationCoordinate2DIsValid(coordinate) else {
                self.state = "unavailable"; self.detail = "No fresh location fix"
                return
            }
            self.state = "shown"
            self.detail = "You • real device fix"
            self.attachRealUserLocation(to: coordinate)
        }
    }

    nonisolated func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        Task { @MainActor [weak self] in
            guard let self, self.requestedByUser else { return }
            self.state = "unavailable"
            self.detail = "Location fix unavailable"
        }
    }

    private func requestRealFix() {
        state = "locating"; detail = "Locating…"
        manager.requestLocation()
    }

    private func attachRealUserLocation(to coordinate: CLLocationCoordinate2D) {
        guard CLLocationCoordinate2DIsValid(coordinate), let map = activeMapView() else {
            state = "unavailable"; detail = "Map not ready"
            return
        }
        map.showsUserLocation = true
        map.userTrackingMode = .none
        // MapKit owns the actual user annotation. Entry/exit/custom nodes remain
        // the app's explicit markers; the real device marker gets its own green tint.
        Task { @MainActor in
            try? await Task.sleep(for: .milliseconds(150))
            map.view(for: map.userLocation)?.tintColor = .systemGreen
        }
    }

    private func activeMapView() -> MKMapView? {
        for case let scene as UIWindowScene in UIApplication.shared.connectedScenes where scene.activationState == .foregroundActive {
            for window in scene.windows where !window.isHidden {
                if let root = window.rootViewController?.view, let map = findMap(in: root) { return map }
            }
        }
        return nil
    }

    private func findMap(in view: UIView) -> MKMapView? {
        if let map = view as? MKMapView { return map }
        for child in view.subviews { if let map = findMap(in: child) { return map } }
        return nil
    }
}

@MainActor
struct IOSUserLocationControl: View {
    @StateObject private var controller = IOSUserLocationController()

    var body: some View {
        Button { controller.requestFromUserTap() } label: {
            HStack(spacing: 5) {
                Image(systemName: controller.state == "shown" ? "location.fill" : "location")
                    .foregroundStyle(controller.state == "shown" ? .green : .primary)
                Text(controller.detail).lineLimit(1)
            }
            .font(.caption.bold())
            .padding(.horizontal, 9).padding(.vertical, 7)
            .background(.regularMaterial, in: Capsule())
        }
        .buttonStyle(.plain)
        .accessibilityLabel("Show my real device location on the Router VPN map")
    }
}

// Location contract: no automatic request, no IP geolocation, no synthetic coordinate.
// CoreLocation is imported with @preconcurrency because its Objective-C delegate callbacks
// cross the Swift 6 isolation boundary; all mutable controller/UI state stays @MainActor.
// A user tap -> When-In-Use permission -> fresh Core Location fix -> MapKit user annotation only.
