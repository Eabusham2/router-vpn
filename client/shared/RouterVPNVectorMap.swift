import CoreGraphics
import Foundation
import MapKit

/// An opaque, locally rendered VPN basemap. MapKit supplies coordinate
/// transforms and gestures; every visible land/grid shape is ours, with no
/// remote tile URL, geocoder or synthetic node/device position.
final class RouterVPNVectorMapOverlay: NSObject, MKOverlay {
    let coordinate = CLLocationCoordinate2D(latitude: 0, longitude: 0)
    let boundingMapRect = MKMapRect.world
    let geometry: RouterVPNMapGeometry?

    init(geometry: RouterVPNMapGeometry?) { self.geometry = geometry; super.init() }
    func canReplaceMapContent() -> Bool { true }
}

final class RouterVPNVectorMapRenderer: MKOverlayRenderer {
    private let geometry: RouterVPNMapGeometry?
    static let ocean = CGColor(red: 9.0 / 255, green: 17.0 / 255, blue: 31.0 / 255, alpha: 1)
    static let land = CGColor(red: 27.0 / 255, green: 51.0 / 255, blue: 68.0 / 255, alpha: 1)
    private static let coastline = CGColor(red: 64.0 / 255, green: 100.0 / 255, blue: 124.0 / 255, alpha: 1)
    private static let graticule = CGColor(red: 25.0 / 255, green: 43.0 / 255, blue: 62.0 / 255, alpha: 1)

    init(overlay: RouterVPNVectorMapOverlay) {
        geometry = overlay.geometry
        super.init(overlay: overlay)
    }

    override func draw(_ mapRect: MKMapRect, zoomScale: MKZoomScale, in context: CGContext) {
        guard zoomScale.isFinite, zoomScale > 0, !mapRect.isNull, !mapRect.isEmpty else { return }
        context.saveGState()
        defer { context.restoreGState() }
        context.setFillColor(Self.ocean)
        context.fill(rect(for: mapRect))

        let world = MKMapRect.world.size.width
        let grid = CGMutablePath()
        for longitude in stride(from: -180, through: 180, by: 30) {
            let x = Double(longitude + 180) / 360 * world
            grid.move(to: point(for: MKMapPoint(x: x, y: 0)))
            grid.addLine(to: point(for: MKMapPoint(x: x, y: world)))
        }
        for latitude in stride(from: -60, through: 60, by: 30) {
            guard let p = RouterVPNMapGeometry.project(latitude: Double(latitude), longitude: 0) else { continue }
            grid.move(to: point(for: MKMapPoint(x: 0, y: p.y * world)))
            grid.addLine(to: point(for: MKMapPoint(x: world, y: p.y * world)))
        }
        context.addPath(grid)
        context.setStrokeColor(Self.graticule)
        context.setLineWidth(0.75 / zoomScale)
        context.strokePath()

        guard let geometry else { return }
        let land = CGMutablePath()
        for ring in geometry.rings {
            let bounds = MKMapRect(x: ring.minX * world, y: ring.minY * world,
                                   width: (ring.maxX - ring.minX) * world,
                                   height: (ring.maxY - ring.minY) * world)
            guard bounds.intersects(mapRect), let first = ring.points.first else { continue }
            land.move(to: point(for: MKMapPoint(x: first.x * world, y: first.y * world)))
            for p in ring.points.dropFirst() {
                land.addLine(to: point(for: MKMapPoint(x: p.x * world, y: p.y * world)))
            }
            land.closeSubpath()
        }
        context.addPath(land)
        context.setFillColor(Self.land)
        context.setStrokeColor(Self.coastline)
        context.setLineWidth(0.8 / zoomScale)
        context.setLineJoin(.round)
        context.drawPath(using: .eoFillStroke)
    }
}

enum RouterVPNVectorMap {
    static let geometry: RouterVPNMapGeometry? = {
        guard let url = Bundle.main.url(forResource: "routervpn-land-110m", withExtension: "json"),
              let data = try? Data(contentsOf: url) else { return nil }
        return try? RouterVPNMapGeometry(data: data)
    }()

    @MainActor
    static func install(on map: MKMapView) {
        guard !map.overlays.contains(where: { $0 is RouterVPNVectorMapOverlay }) else { return }
        // With overlays, showsBuildings is ignored on iOS 16/macOS 13 and
        // later. Configure the supported flat presentation explicitly; the
        // opaque base below supplies all visible land, water and grid content.
        let configuration = MKStandardMapConfiguration(elevationStyle: .flat, emphasisStyle: .muted)
        configuration.showsTraffic = false
        configuration.pointOfInterestFilter = .excludingAll
        map.preferredConfiguration = configuration
        map.isPitchEnabled = false
        map.setCameraZoomRange(MKMapView.CameraZoomRange(minCenterCoordinateDistance: 350_000,
                                                        maxCenterCoordinateDistance: 40_000_000), animated: false)
        // Above labels is intentional: opaque vector content replaces streets,
        // labels and POIs as well as terrain. Routes/annotations are added later.
        map.addOverlay(RouterVPNVectorMapOverlay(geometry: geometry), level: .aboveLabels)
    }

    @MainActor
    static func clearRoutes(on map: MKMapView) {
        // Data/status refresh must never remove the custom base and reveal the
        // generic map underneath it, including a disconnected or empty catalog.
        map.removeOverlays(map.overlays.filter { !($0 is RouterVPNVectorMapOverlay) })
    }

    static func routes(from a: CLLocationCoordinate2D, to b: CLLocationCoordinate2D) -> [MKPolyline] {
        guard let start = RouterVPNMapGeometry.project(latitude: a.latitude, longitude: a.longitude),
              let end = RouterVPNMapGeometry.project(latitude: b.latitude, longitude: b.longitude) else { return [] }
        let world = MKMapRect.world.size.width
        return RouterVPNMapGeometry.routeSegments(from: start, to: end).map { segment in
            var points = segment.map { MKMapPoint(x: $0.x * world, y: $0.y * world) }
            return MKPolyline(points: &points, count: points.count)
        }
    }

    static func packetCoordinate(from a: CLLocationCoordinate2D, to b: CLLocationCoordinate2D,
                                 fraction: Double) -> CLLocationCoordinate2D? {
        guard let start = RouterVPNMapGeometry.project(latitude: a.latitude, longitude: a.longitude),
              let end = RouterVPNMapGeometry.project(latitude: b.latitude, longitude: b.longitude) else { return nil }
        let p = RouterVPNMapGeometry.routePoint(from: start, to: end, fraction: fraction)
        return MKMapPoint(x: p.x * MKMapRect.world.size.width, y: p.y * MKMapRect.world.size.height).coordinate
    }
}
