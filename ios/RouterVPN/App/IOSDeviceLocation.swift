import CoreLocation
import Foundation

@MainActor
final class IOSDeviceLocation: NSObject, ObservableObject, CLLocationManagerDelegate {
    @Published private(set) var coordinate: CLLocationCoordinate2D?
    @Published private(set) var statusText = "Location is off"
    @Published private(set) var isRequesting = false

    private let manager = CLLocationManager()
    private let freshnessLimit: TimeInterval = 60

    override init() {
        super.init()
        manager.delegate = self
        manager.desiredAccuracy = kCLLocationAccuracyHundredMeters
        manager.distanceFilter = kCLDistanceFilterNone
    }

    func requestCurrentLocation() {
        guard !isRequesting else { return }
        switch manager.authorizationStatus {
        case .notDetermined:
            statusText = "Requesting location permission…"
            isRequesting = true
            manager.requestWhenInUseAuthorization()
        case .authorizedAlways, .authorizedWhenInUse:
            requestOneFix()
        case .denied:
            coordinate = nil
            statusText = "Location permission is denied"
        case .restricted:
            coordinate = nil
            statusText = "Location is restricted on this device"
        @unknown default:
            coordinate = nil
            statusText = "Location permission is unavailable"
        }
    }

    func clear() {
        manager.stopUpdatingLocation()
        isRequesting = false
        coordinate = nil
        statusText = "Location marker hidden"
    }

    private func requestOneFix() {
        statusText = "Finding your real location…"
        isRequesting = true
        manager.requestLocation()
    }

    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        switch manager.authorizationStatus {
        case .authorizedAlways, .authorizedWhenInUse:
            requestOneFix()
        case .denied:
            isRequesting = false
            coordinate = nil
            statusText = "Location permission is denied"
        case .restricted:
            isRequesting = false
            coordinate = nil
            statusText = "Location is restricted on this device"
        case .notDetermined:
            break
        @unknown default:
            isRequesting = false
            coordinate = nil
            statusText = "Location permission is unavailable"
        }
    }

    func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        isRequesting = false
        guard let location = locations
            .filter({ $0.horizontalAccuracy >= 0 })
            .sorted(by: { $0.timestamp > $1.timestamp })
            .first,
              Date().timeIntervalSince(location.timestamp) <= freshnessLimit else {
            coordinate = nil
            statusText = "No fresh location fix was available"
            return
        }
        coordinate = location.coordinate
        statusText = "Showing your real device location"
    }

    func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        isRequesting = false
        coordinate = nil
        if let clError = error as? CLError, clError.code == .denied {
            statusText = "Location permission is denied"
        } else {
            statusText = "A real location fix was not available"
        }
    }
}
