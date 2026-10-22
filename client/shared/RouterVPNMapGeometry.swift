import Foundation

/// Geography only. Node/device coordinates always come from the explicit saved
/// profile or a fresh, user-authorized Core Location fix, never from this file.
struct RouterVPNMapGeometry: Sendable {
    struct Point: Equatable, Sendable {
        let x: Double
        let y: Double
    }
    struct Ring: Sendable {
        let points: [Point]
        let minX: Double
        let minY: Double
        let maxX: Double
        let maxY: Double
    }
    private struct Document: Decodable {
        let schema: Int
        let scale: Int
        let source: String
        let source_sha256: String
        let rings: [[[Int]]]
    }
    enum Invalid: Error { case geometry }

    static let sourceSHA256 = "1926c621afd6ac67c3f36639bb1236134a48d82226dc675d3e3df53d02d2a3de"
    static let latitudeLimit = 85.0511287798066
    let rings: [Ring]

    init(data: Data) throws {
        guard data.count <= 512 * 1024 else { throw Invalid.geometry }
        let document = try JSONDecoder().decode(Document.self, from: data)
        guard document.schema == 1, document.scale == 10_000,
              document.source == "Natural Earth 110m land 4.1.0",
              document.source_sha256 == Self.sourceSHA256,
              !document.rings.isEmpty, document.rings.count <= 1024 else { throw Invalid.geometry }
        var total = 0
        var projected: [Ring] = []
        for ring in document.rings {
            total += ring.count
            guard ring.count >= 4, total <= 30_000, ring.first == ring.last else { throw Invalid.geometry }
            var points: [Point] = []
            for value in ring {
                guard value.count == 2, (-1_800_000...1_800_000).contains(value[0]),
                      (-900_000...900_000).contains(value[1]),
                      let point = Self.project(latitude: Double(value[1]) / 10_000,
                                               longitude: Double(value[0]) / 10_000) else { throw Invalid.geometry }
                points.append(point)
            }
            projected.append(Ring(points: points,
                                  minX: points.map(\.x).min()!, minY: points.map(\.y).min()!,
                                  maxX: points.map(\.x).max()!, maxY: points.map(\.y).max()!))
        }
        rings = projected
    }

    /// Unit Web Mercator coordinates match MapKit's world rectangle. Dateline
    /// endpoints remain on their own edge; polygons must not bridge the world.
    static func project(latitude: Double, longitude: Double) -> Point? {
        guard latitude.isFinite, longitude.isFinite,
              (-90...90).contains(latitude), (-180...180).contains(longitude) else { return nil }
        let phi = max(-latitudeLimit, min(latitudeLimit, latitude)) * .pi / 180
        let x = (longitude + 180) / 360
        let y = 0.5 - log(tan(.pi / 4 + phi / 2)) / (2 * .pi)
        return Point(x: x, y: max(0, min(1, y)))
    }

    /// Packet motion follows the same short, projected segment as the visible
    /// route. It is decorative motion; it never supplies a measured RTT value.
    static func routePoint(from a: Point, to b: Point, fraction: Double) -> Point {
        let t = max(0, min(1, fraction.isFinite ? fraction : 0))
        if t == 0 { return a }
        if t == 1 { return b }
        var dx = b.x - a.x
        if dx > 0.5 { dx -= 1 }
        if dx < -0.5 { dx += 1 }
        let rawX = a.x + dx * t
        let x = rawX < 0 ? rawX + 1 : rawX > 1 ? rawX - 1 : rawX
        return Point(x: x, y: a.y + (b.y - a.y) * t)
    }

    static func routeSegments(from a: Point, to b: Point) -> [[Point]] {
        let delta = b.x - a.x
        guard abs(delta) > 0.5 else { return [[a, b]] }
        let endX = b.x + (delta > 0 ? -1 : 1)
        // +180 and -180 name the same meridian. Their wrapped delta is zero,
        // so crossing interpolation would otherwise divide by zero.
        if endX == a.x { return [[a, Point(x: a.x, y: b.y)]] }
        let edgeX = endX < 0 ? 0.0 : 1.0
        let fraction = (edgeX - a.x) / (endX - a.x)
        let edgeY = a.y + (b.y - a.y) * fraction
        return [[a, Point(x: edgeX, y: edgeY)], [Point(x: 1 - edgeX, y: edgeY), b]]
    }
}
