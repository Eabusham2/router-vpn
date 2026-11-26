@preconcurrency import CoreLocation
import SwiftUI

// Each one-shot manager has its own delegate. Queued callbacks from a hidden
// request cannot publish a fix into a later tap, including in another scene.
@MainActor
private final class IOSDeviceLocationRequest: NSObject, CLLocationManagerDelegate {
    let manager = CLLocationManager()
    weak var owner: IOSUserLocationController?

    init(owner: IOSUserLocationController) {
        self.owner = owner
        super.init()
        manager.desiredAccuracy = kCLLocationAccuracyHundredMeters
        manager.delegate = self
    }

    nonisolated func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        Task { @MainActor [weak self] in
            guard let self else { return }
            owner?.authorizationChanged(self)
        }
    }

    nonisolated func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        let sample = locations.last.map { ($0.coordinate.latitude, $0.coordinate.longitude, $0.horizontalAccuracy, $0.timestamp) }
        Task { @MainActor [weak self] in
            guard let self else { return }
            owner?.receive(self, sample: sample)
        }
    }

    nonisolated func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        Task { @MainActor [weak self] in
            guard let self else { return }
            owner?.failed(self)
        }
    }
}

@MainActor
final class IOSUserLocationController: ObservableObject {
    @Published private(set) var state = "off"
    @Published private(set) var detail = "Show my real location"
    @Published private(set) var coordinate: CLLocationCoordinate2D?
    private var request: IOSDeviceLocationRequest?
    private var expiry: Task<Void, Never>?
    var requestedByUser: Bool { request != nil }

    func toggleFromUserTap() {
        if requestedByUser { hideRealLocation() }
        else { requestFromUserTap() }
    }

    private func requestFromUserTap() {
        let next = IOSDeviceLocationRequest(owner: self)
        request = next
        if next.manager.authorizationStatus == .notDetermined {
            state = "requesting"
            detail = "Location permission…"
            next.manager.requestWhenInUseAuthorization()
        } else {
            authorizationChanged(next)
        }
    }

    fileprivate func authorizationChanged(_ sender: IOSDeviceLocationRequest) {
        guard request === sender else { return }
        switch sender.manager.authorizationStatus {
        case .authorizedAlways, .authorizedWhenInUse:
            guard state != "locating", state != "shown" else { return }
            state = "locating"
            detail = "Locating…"
            sender.manager.requestLocation()
        case .notDetermined where state == "requesting":
            break
        default:
            clear(state: "denied", detail: "Location unavailable")
        }
    }

    fileprivate func receive(_ sender: IOSDeviceLocationRequest, sample: (Double, Double, Double, Date)?) {
        guard request === sender, state == "locating" else { return }
        guard [.authorizedWhenInUse, .authorizedAlways].contains(sender.manager.authorizationStatus) else {
            clear(state: "denied", detail: "Location unavailable")
            return
        }
        guard let (latitude, longitude, accuracy, timestamp) = sample else {
            clear(state: "unavailable", detail: "No fresh location fix")
            return
        }
        let age = -timestamp.timeIntervalSinceNow
        let fix = CLLocationCoordinate2D(latitude: latitude, longitude: longitude)
        guard (0..<30).contains(age), (0...10_000).contains(accuracy), CLLocationCoordinate2DIsValid(fix) else {
            clear(state: "unavailable", detail: "No fresh location fix")
            return
        }

        coordinate = fix
        state = "shown"
        detail = "You • real device fix"
        let deadline = ContinuousClock.now + .seconds(30 - age)
        expiry = Task { @MainActor [weak self, weak sender] in
            do { try await Task.sleep(until: deadline, clock: .continuous) } catch { return }
            guard let self, let sender, self.request === sender else { return }
            self.hideRealLocation()
        }
    }

    fileprivate func failed(_ sender: IOSDeviceLocationRequest) {
        guard request === sender else { return }
        clear(state: "unavailable", detail: "Location fix unavailable")
    }

    func hideRealLocation() {
        clear(state: "off", detail: "Show my real location")
    }

    private func clear(state: String, detail: String) {
        expiry?.cancel()
        expiry = nil
        request?.manager.delegate = nil
        request?.manager.stopUpdatingLocation()
        request = nil
        coordinate = nil
        self.state = state
        self.detail = detail
    }
}

@MainActor
struct IOSUserLocationControl: View {
    @EnvironmentObject private var controller: IOSUserLocationController

    var body: some View {
        Button { controller.toggleFromUserTap() } label: {
            HStack(spacing: 5) {
                Image(systemName: controller.state == "shown" ? "location.fill" : "location")
                    .foregroundStyle(controller.state == "shown" ? .green : .primary)
                Text(controller.detail)
                    .multilineTextAlignment(.leading)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .font(.caption.bold())
            .padding(.horizontal, 9).padding(.vertical, 7)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16))
        }
        .buttonStyle(.plain)
        .accessibilityLabel(controller.requestedByUser ? "Hide or cancel my real device location on the Router VPN map" : "Show my real device location on the Router VPN map")
    }
}

// Location contract: no automatic request, no IP geolocation, no synthetic coordinate.
// After When-In-Use permission and a fresh one-shot fix, only the owning map displays the MapKit user annotation.
