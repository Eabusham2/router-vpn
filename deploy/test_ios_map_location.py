#!/usr/bin/env python3
"""Execute the iOS one-shot location controller at controlled OS/UI boundaries."""
from pathlib import Path
import platform
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "ios/RouterVPN/App"

BOUNDARY = r'''
import Foundation
protocol ObservableObject {}
@propertyWrapper struct Published<T> { var wrappedValue: T }
enum CLAuthorizationStatus { case notDetermined, authorizedWhenInUse, authorizedAlways, denied, restricted }
let kCLLocationAccuracyHundredMeters = 100.0
struct CLLocationCoordinate2D: Equatable { let latitude: Double, longitude: Double }
func CLLocationCoordinate2DIsValid(_ c: CLLocationCoordinate2D) -> Bool {
    (-90...90).contains(c.latitude) && (-180...180).contains(c.longitude)
}
struct CLLocation { let coordinate: CLLocationCoordinate2D, horizontalAccuracy: Double, timestamp: Date }
protocol CLLocationManagerDelegate: AnyObject {
    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager)
    func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation])
    func locationManager(_ manager: CLLocationManager, didFailWithError error: Error)
}
@MainActor final class CLLocationManager {
    static var initialAuthorization = CLAuthorizationStatus.authorizedWhenInUse
    static var instances: [CLLocationManager] = []
    weak var delegate: CLLocationManagerDelegate?
    var desiredAccuracy = 0.0, authorizationStatus = initialAuthorization
    var fixes = 0, permissions = 0, stops = 0
    init() { Self.instances.append(self) }
    func requestWhenInUseAuthorization() { permissions += 1 }
    func requestLocation() { fixes += 1 }
    func stopUpdatingLocation() { stops += 1 }
}
'''

TESTS = r'''
@main @MainActor struct Tests {
    static var checks = 0
    static func check(_ valid: @autoclosure () -> Bool, _ label: String) {
        guard valid() else { fatalError(label) }
        checks += 1
    }
    static func settle() async {
        for _ in 0..<12 { await Task.yield() }
    }
    static func sample(_ age: Double = 0.5, accuracy: Double = 2, latitude: Double = 49) -> [CLLocation] {
        [.init(coordinate: .init(latitude: latitude, longitude: -127), horizontalAccuracy: accuracy,
               timestamp: Date(timeIntervalSinceNow: -age))]
    }
    static func main() async throws {
        let first = IOSUserLocationController(), other = IOSUserLocationController()
        check(CLLocationManager.instances.isEmpty && first.coordinate == nil, "no location request at launch")
        CLLocationManager.initialAuthorization = .notDetermined
        first.toggleFromUserTap()
        let initial = CLLocationManager.instances.last!, old = initial.delegate!
        check(initial.permissions == 1 && initial.fixes == 0, "permission request precedes OS fix")
        initial.authorizationStatus = .authorizedWhenInUse
        old.locationManagerDidChangeAuthorization(initial)
        old.locationManagerDidChangeAuthorization(initial)
        await settle()
        check(initial.fixes == 1, "one fix after authorization")
        old.locationManager(initial, didUpdateLocations: sample())
        first.toggleFromUserTap()
        check(initial.stops == 1 && initial.delegate == nil && first.state == "off", "tap cancels a pending fix")
        CLLocationManager.initialAuthorization = .authorizedAlways
        first.toggleFromUserTap()
        let current = CLLocationManager.instances.last!, callback = current.delegate!
        old.locationManager(initial, didUpdateLocations: sample(1, latitude: 22))
        old.locationManager(initial, didFailWithError: CancellationError())
        await settle()
        check(first.state == "locating" && first.coordinate == nil, "old callback cannot publish or retire replacement")
        callback.locationManager(current, didUpdateLocations: sample())
        await settle()
        check(first.coordinate == .init(latitude: 49, longitude: -127) && other.coordinate == nil, "validated sample belongs to owning scene")
        callback.locationManager(current, didUpdateLocations: sample(1, latitude: 55))
        await settle()
        check(first.coordinate?.latitude == 49 && current.fixes == 1, "one-shot marker cannot follow subsequent updates")
        current.authorizationStatus = .restricted
        callback.locationManagerDidChangeAuthorization(current)
        await settle()
        check(first.state == "denied" && first.coordinate == nil && current.stops == 1, "revocation removes the marker")
        for value in [sample(-10), sample(31), sample(1, accuracy: -1), sample(1, accuracy: 10_001),
                      sample(1, latitude: .nan), []] {
            first.toggleFromUserTap()
            let manager = CLLocationManager.instances.last!
            manager.delegate!.locationManager(manager, didUpdateLocations: value)
            await settle()
            check(first.coordinate == nil && !first.requestedByUser && first.state == "unavailable", "reject invalid or stale fix")
        }
        first.toggleFromUserTap()
        let revoked = CLLocationManager.instances.last!
        revoked.delegate!.locationManager(revoked, didUpdateLocations: sample())
        revoked.authorizationStatus = .denied
        await settle()
        check(first.coordinate == nil && first.state == "denied", "recheck permission before publishing")
        first.toggleFromUserTap()
        let expiring = CLLocationManager.instances.last!
        expiring.delegate!.locationManager(expiring, didUpdateLocations: sample(29))
        await settle()
        check(first.state == "shown", "remaining fresh interval admitted")
        try await Task.sleep(for: .milliseconds(1200))
        check(first.coordinate == nil && !first.requestedByUser && expiring.stops == 1, "expiry from sample time clears marker")
        first.toggleFromUserTap()
        let pending = CLLocationManager.instances.last!, late = pending.delegate!
        first.hideRealLocation()
        late.locationManager(pending, didUpdateLocations: sample())
        await settle()
        check(first.state == "off" && first.coordinate == nil && pending.stops == 1, "hidden view discards queued fixes")
        print("iOS one-shot map location: PASS (\(checks) ownership, authorization, freshness and cancellation checks)")
    }
}
'''


def main():
    location = (APP / "IOSUserLocationOverlay.swift").read_text()
    controller = location[location.index("@MainActor"):location.index("@MainActor\nstruct IOSUserLocationControl")]
    with tempfile.TemporaryDirectory(prefix="ios-map-location-") as directory:
        work = Path(directory)
        source = work / "Test.swift"
        source.write_text(BOUNDARY + controller + TESTS)
        executable = work / "test"
        subprocess.run(["swiftc", "-swift-version", "6", "-parse-as-library", source, "-o", executable],
                       check=True, timeout=60)
        subprocess.run([executable], check=True, timeout=20)
        if platform.system() == "Darwin":
            sdk = subprocess.check_output(["xcrun", "--sdk", "iphoneos", "--show-sdk-path"], text=True).strip()
            subprocess.run(["xcrun", "--sdk", "iphoneos", "swiftc", "-swift-version", "6", "-typecheck",
                            "-target", "arm64-apple-ios17.0", "-sdk", sdk, "-module-cache-path", work / "modules",
                            APP / "IOSUserLocationOverlay.swift"], check=True, timeout=90)


if __name__ == "__main__":
    main()
