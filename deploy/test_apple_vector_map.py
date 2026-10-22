#!/usr/bin/env python3
"""Execute shared vector geometry; native lanes also render with real MapKit.

Linux is not a substitute for the Apple SDK. The shipping macOS builder and
iOS runtime gate invoke this file, including its mandatory native branch.
"""
from pathlib import Path
import hashlib
import json
import platform
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SHARED = ROOT / "client/shared"
GEOMETRY = SHARED / "RouterVPNMapGeometry.swift"
RENDERER = SHARED / "RouterVPNVectorMap.swift"
ASSET = SHARED / "map/routervpn-land-110m.json"

CORE = r'''
import Foundation
@main struct Test {
 static func main() throws {
  var count = 0
  func check(_ label: String, _ valid: Bool) { precondition(valid, label); count += 1 }
  let data = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
  let geometry = try RouterVPNMapGeometry(data: data)
  check("real pinned coastline rings", geometry.rings.count == 128)
  check("no invented or dropped land points", geometry.rings.reduce(0) { $0 + $1.points.count } == 5143)
  for ring in geometry.rings {
   check("rings remain closed", ring.points.first == ring.points.last)
   check("finite projected bounds", ring.minX >= 0 && ring.maxX <= 1 && ring.minY >= 0 && ring.maxY <= 1)
  }
  let origin = RouterVPNMapGeometry.project(latitude: 0, longitude: 0)!
  check("coordinate origin is geographic center", abs(origin.x - 0.5) < 1e-12 && abs(origin.y - 0.5) < 1e-12)
  check("north pole projection is finite", RouterVPNMapGeometry.project(latitude: 90, longitude: 0)!.y < 1e-12)
  check("south pole projection is finite", RouterVPNMapGeometry.project(latitude: -90, longitude: 0)!.y > 1 - 1e-12)
  for (lat, lon) in [(91.0, 0.0), (-91, 0), (0, 181), (0, -181), (.nan, 0), (0, .infinity)] {
   check("invalid coordinates cannot become map points", RouterVPNMapGeometry.project(latitude: lat, longitude: lon) == nil)
  }
  for (start, end) in [(179.0, -179.0), (-179, 179)] {
   let a = RouterVPNMapGeometry.project(latitude: 20, longitude: start)!
   let b = RouterVPNMapGeometry.project(latitude: 40, longitude: end)!
   let pieces = RouterVPNMapGeometry.routeSegments(from: a, to: b)
   check("date line creates two local edge segments", pieces.count == 2 && pieces.allSatisfy { abs($0[1].x - $0[0].x) < 0.01 })
   check("seam has continuous latitude", pieces[0][1].y == pieces[1][0].y)
   let mid = RouterVPNMapGeometry.routePoint(from: a, to: b, fraction: 0.5)
   check("packet follows short date-line crossing", mid.x < 1e-12 || mid.x > 1 - 1e-12)
   check("packet retains projected latitude", abs(mid.y - (a.y + b.y) / 2) < 1e-12)
   check("route starts at exact node", RouterVPNMapGeometry.routePoint(from: a, to: b, fraction: 0) == a)
   let last = RouterVPNMapGeometry.routePoint(from: a, to: b, fraction: 1)
   check("route ends at exact node", abs(last.x - b.x) < 1e-12 && abs(last.y - b.y) < 1e-12)
  }
  for (start, end) in [(180.0, -180.0), (-180, 180)] {
   let a = RouterVPNMapGeometry.project(latitude: -20, longitude: start)!
   let b = RouterVPNMapGeometry.project(latitude: 40, longitude: end)!
   let pieces = RouterVPNMapGeometry.routeSegments(from: a, to: b)
   check("identical date-line meridians stay finite", pieces.count == 1 && pieces[0].allSatisfy { $0.x.isFinite && $0.y.isFinite })
   check("identical date-line meridians form a vertical route", pieces[0][0].x == pieces[0][1].x && pieces[0][1].y == b.y)
   check("exact date-line start survives wrapping", RouterVPNMapGeometry.routePoint(from: a, to: b, fraction: 0) == a)
   check("exact date-line destination survives wrapping", RouterVPNMapGeometry.routePoint(from: a, to: b, fraction: 1) == b)
  }
  let b = RouterVPNMapGeometry.project(latitude: 45, longitude: 35)!
  check("ordinary route stays one segment", RouterVPNMapGeometry.routeSegments(from: origin, to: b).count == 1)
  check("invalid animation phase starts at node", RouterVPNMapGeometry.routePoint(from: origin, to: b, fraction: .nan) == origin)
  check("phase is bounded", RouterVPNMapGeometry.routePoint(from: origin, to: b, fraction: 4) == b)
  let base = try JSONSerialization.jsonObject(with: data) as! [String: Any]
  for (key, value) in [("schema", 2 as Any), ("scale", 0), ("source_sha256", "unverified"), ("rings", []), ("rings", [[[0,0],[1,1],[2,2]]]), ("rings", [[[0,0],[2_000_000,0],[0,1],[0,0]]]), ("rings", [[[0,0],[1,1],[2,2],[3,3]]])] {
   var bad = base; bad[key] = value
   do { _ = try RouterVPNMapGeometry(data: JSONSerialization.data(withJSONObject: bad)); fatalError("accepted invalid geography: " + key) }
   catch { count += 1 }
  }
  do { _ = try RouterVPNMapGeometry(data: Data(repeating: 32, count: 512 * 1024 + 1)); fatalError("unbounded geography") }
  catch { count += 1 }
  print("Apple VPN map geometry: PASS (\(count) checks)")
 }
}
'''

SELECTION = r'''
import Foundation
final class Popup {
 var indexOfSelectedItem = 0
 func selectItem(at index: Int) { indexOfSelectedItem = index }
}
final class Product {
 let routerIDs = ["first", "second", "external"]
 let routerPopup = Popup(), nodePopup = Popup()
 var idle = true, saves = 0, guards = 0
 func ensureMutationIdle(_ action: String) -> Bool { guards += 1; return idle }
 func selectRouter() { precondition(idle); saves += 1 }
 __SHIPPING_SELECTION__
}
@main struct Test {
 static func main() {
  let p = Product()
  precondition(!p.selectUnifiedMapNode("unknown") && p.saves == 0 && p.guards == 0)
  precondition(p.selectUnifiedMapNode("first") && p.saves == 0 && p.guards == 0)
  p.idle = false
  precondition(!p.selectUnifiedMapNode("second") && p.routerPopup.indexOfSelectedItem == 0 && p.nodePopup.indexOfSelectedItem == 0 && p.saves == 0 && p.guards == 1)
  p.idle = true
  precondition(p.selectUnifiedMapNode("second") && p.routerPopup.indexOfSelectedItem == 1 && p.nodePopup.indexOfSelectedItem == 1 && p.saves == 1 && p.guards == 2)
  precondition(p.selectUnifiedMapNode("external") && p.routerPopup.indexOfSelectedItem == 2 && p.nodePopup.indexOfSelectedItem == 2 && p.saves == 2 && p.guards == 3)
  print("macOS map selection: PASS (shipping callback, unknown/current/busy/Router/external nodes; selection only)")
 }
}
'''

NATIVE = r'''
import AppKit
import CoreGraphics
import Foundation
import MapKit
@main struct Test {
 @MainActor static func main() throws {
  let data = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
  let geometry = try RouterVPNMapGeometry(data: data)
  let overlay = RouterVPNVectorMapOverlay(geometry: geometry)
  precondition(overlay.canReplaceMapContent())
  let renderer = RouterVPNVectorMapRenderer(overlay: overlay)
  let size = 1024
  // The shipping palette is Generic RGB. A DeviceRGB bitmap may convert
  // those colors, so its raw bytes are not the palette's component values.
  let space = RouterVPNVectorMapRenderer.land.colorSpace!
  let bitmap = CGBitmapInfo.byteOrder32Big.rawValue | CGImageAlphaInfo.premultipliedLast.rawValue
  let context = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8,
                          bytesPerRow: size * 4, space: space, bitmapInfo: bitmap)!
  let drawingBounds = renderer.rect(for: .world)
  let scale = CGFloat(size) / drawingBounds.width
  // A standalone Quartz bitmap starts at the lower left, unlike the
  // downward-Y map drawing context. Reproduce MapKit's drawing transform.
  context.translateBy(x: 0, y: CGFloat(size))
  context.scaleBy(x: scale, y: -scale)
  context.translateBy(x: -drawingBounds.minX, y: -drawingBounds.minY)
  renderer.draw(.world, zoomScale: scale, in: context)
  context.flush()
  let bytes = context.data!.assumingMemoryBound(to: UInt8.self)
  for pixel in stride(from: 3, to: size * size * 4, by: 4) { precondition(bytes[pixel] == 255, "basemap must cover stock geography opaquely") }
  func rgb(_ latitude: Double, _ longitude: Double) -> [UInt8] {
   // Use MapKit's own coordinate projection, independently of the shipping
   // geometry projector, to locate the expected geographic sample.
   let p = renderer.point(for: MKMapPoint(CLLocationCoordinate2D(latitude: latitude, longitude: longitude)))
   let x = min(size - 1, max(0, Int((p.x - drawingBounds.minX) * scale)))
   let y = min(size - 1, max(0, Int((p.y - drawingBounds.minY) * scale)))
   let offset = (y * size + x) * 4
   return [bytes[offset], bytes[offset + 1], bytes[offset + 2]]
  }
  func near(_ actual: [UInt8], _ expected: [Int]) -> Bool {
   zip(actual, expected).allSatisfy { abs(Int($0.0) - $0.1) <= 2 }
  }
  for (latitude, longitude) in [(40.0,-105.0), (50,10), (-25,135), (5,25)] {
   let actual = rgb(latitude, longitude)
   precondition(near(actual, [27,51,68]), "known inland coordinate \(latitude),\(longitude) missing from native vector rendering: \(actual)")
  }
  for (latitude, longitude) in [(10.0,-35.0), (-15,-135)] {
   let actual = rgb(latitude, longitude)
   precondition(near(actual, [9,17,31]), "known ocean coordinate \(latitude),\(longitude) was fabricated as land: \(actual)")
  }
  let map = MKMapView(frame: CGRect(x: 0, y: 0, width: 640, height: 480))
  RouterVPNVectorMap.install(on: map)
  RouterVPNVectorMap.install(on: map)
  precondition(map.overlays.filter { $0 is RouterVPNVectorMapOverlay }.count == 1)
  let routes = RouterVPNVectorMap.routes(from: .init(latitude: 20, longitude: 179), to: .init(latitude: 40, longitude: -179))
  precondition(routes.count == 2)
  map.addOverlays(routes, level: .aboveLabels)
  RouterVPNVectorMap.clearRoutes(on: map)
  precondition(map.overlays.count == 1 && map.overlays[0] is RouterVPNVectorMapOverlay,
               "status refresh must not reveal stock map underneath")
  precondition(!map.showsBuildings && !map.showsTraffic && !map.isPitchEnabled)
  print("Apple VPN map native renderer: PASS (opaque bitmap, land/ocean pixels, date line, refresh persistence)")
 }
}
'''


def main():
    assert hashlib.sha256(ASSET.read_bytes()).hexdigest() == "95a1ce95491a21e7623ffc4a0a0e302244d3196f6e553b31b828ff148e51d503", "bundled land asset changed without pinned source conversion review"
    value = json.loads(ASSET.read_text())
    assert len(value["rings"]) == 128 and sum(map(len, value["rings"])) == 5143
    assert value["source_sha256"] in GEOMETRY.read_text()
    project = (ROOT / "ios/RouterVPN/project.yml").read_text().split("  RouterVPNPacketTunnel:", 1)[0]
    builder = (ROOT / "client/macos/build-native-app.sh").read_text()
    for name in (GEOMETRY.name, RENDERER.name, ASSET.name, "NATURAL-EARTH.txt"):
        assert name in project and name in builder, f"unshipped vector map source/resource: {name}"
    for path in (ROOT / "ios/RouterVPN/App/IOSUnifiedProductView.swift", ROOT / "client/macos/RouterVPNMacUnifiedShell.swift"):
        source = path.read_text()
        assert "RouterVPNVectorMap.clearRoutes(on: map)" in source
        assert "RouterVPNVectorMapRenderer(overlay: base)" in source
        assert "map.removeOverlays(map.overlays)" not in source
    for path in (ROOT / "ios/RouterVPN/App/IOSUnifiedProductView.swift", ROOT / "client/macos/RouterVPNMacGlobeChrome.swift"):
        assert "RouterVPNVectorMap.install(on: map)" in path.read_text(), "shipping Apple screen must install the custom base"
    for path in (ROOT / "ios/RouterVPN/test_runtime_selection_contract.py", ROOT / "client/macos/build-native-app.sh"):
        assert "test_apple_vector_map.py" in path.read_text(), "native map gate is not wired into the shipping lane"
    renderer = RENDERER.read_text()
    assert "func canReplaceMapContent() -> Bool { true }" in renderer
    for forbidden in ("URLSession", "CLGeocoder", "http://", "https://", "MKTileOverlay"):
        assert forbidden not in renderer, f"custom native vector rendering gained a remote/geocoding path: {forbidden}"
    swift = shutil.which("swiftc")
    if not swift:
        raise SystemExit("Swift compiler is required for vector map geometry")
    with tempfile.TemporaryDirectory(prefix="routervpn-map-") as temporary:
        work = Path(temporary)
        source = work / "main.swift"
        source.write_text(CORE)
        binary = work / "geometry"
        subprocess.run([swift, "-swift-version", "6", "-parse-as-library", str(GEOMETRY), str(source), "-o", str(binary)], check=True, timeout=90)
        subprocess.run([str(binary), str(ASSET)], check=True, timeout=15)
        # A mutation that draws the long route across the world must fail the
        # same executable checks, rather than passing a token-only UI audit.
        mutated = work / "RouterVPNMapGeometry.swift"
        original = GEOMETRY.read_text()
        changed = original.replace("guard abs(delta) > 0.5 else { return [[a, b]] }", "guard false else { return [[a, b]] }")
        assert changed != original
        mutated.write_text(changed)
        negative = work / "wrong-route"
        subprocess.run([swift, "-swift-version", "6", "-parse-as-library", str(mutated), str(source), "-o", str(negative)], check=True, timeout=90, capture_output=True)
        rejected = subprocess.run([str(negative), str(ASSET)], capture_output=True, timeout=15)
        assert rejected.returncode != 0, "long-world-route negative control was not rejected"
        ui = (ROOT / "client/macos/RouterVPNMacUnifiedShell.swift").read_text()
        selection = ui.split("    func selectUnifiedMapNode(", 1)[1].split("    func mapView(", 1)[0]
        selection = "    func selectUnifiedMapNode(" + selection
        assert "connectUnified(" not in selection and "/api/connect" not in selection
        source.write_text(SELECTION.replace("__SHIPPING_SELECTION__", selection))
        binary = work / "selection"
        subprocess.run([swift, "-swift-version", "6", "-parse-as-library", str(source), "-o", str(binary)], check=True, timeout=90)
        subprocess.run([str(binary)], check=True, timeout=15)
        unsafe = selection.replace('guard ensureMutationIdle("selecting a map node") else { return false }', "")
        assert unsafe != selection
        source.write_text(SELECTION.replace("__SHIPPING_SELECTION__", unsafe))
        subprocess.run([swift, "-swift-version", "6", "-parse-as-library", str(source), "-o", str(binary)], check=True, timeout=90)
        assert subprocess.run([str(binary)], capture_output=True, timeout=15).returncode != 0, "unguarded selection negative control was not rejected"
        if platform.system() == "Darwin":
            sdk = subprocess.check_output(["xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True).strip()
            source.write_text(NATIVE)
            binary = work / "native-renderer"
            subprocess.run(["xcrun", "swiftc", "-swift-version", "6", "-strict-concurrency=complete", "-parse-as-library", "-sdk", sdk,
                            "-framework", "AppKit", "-framework", "MapKit", str(GEOMETRY), str(RENDERER), str(source), "-o", str(binary)], check=True, timeout=120)
            subprocess.run([str(binary), str(ASSET)], check=True, timeout=30)
            # The same real bitmap must reject vertically mirrored shipping
            # land. This guards against accidentally sampling our own wrong
            # projection or compensating for a production rendering error.
            mirrored = renderer.replace("y: first.y * world", "y: (1 - first.y) * world").replace("y: p.y * world", "y: (1 - p.y) * world")
            assert mirrored != renderer
            wrong_renderer = work / "RouterVPNVectorMap.swift"
            wrong_renderer.write_text(mirrored)
            negative = work / "mirrored-native-renderer"
            subprocess.run(["xcrun", "swiftc", "-swift-version", "6", "-strict-concurrency=complete", "-parse-as-library", "-sdk", sdk,
                            "-framework", "AppKit", "-framework", "MapKit", str(GEOMETRY), str(wrong_renderer), str(source), "-o", str(negative)], check=True, timeout=120)
            rejected = subprocess.run([str(negative), str(ASSET)], capture_output=True, text=True, timeout=30)
            assert rejected.returncode != 0 and "known inland coordinate" in rejected.stderr, "vertically mirrored native land negative control was not rejected"
            print("Apple VPN map native renderer: vertically mirrored land negative control rejected")
            ios_sdk = subprocess.check_output(["xcrun", "--sdk", "iphoneos", "--show-sdk-path"], text=True).strip()
            subprocess.run(["xcrun", "swiftc", "-typecheck", "-swift-version", "6", "-strict-concurrency=complete",
                            "-target", "arm64-apple-ios17.0", "-sdk", ios_sdk, str(GEOMETRY), str(RENDERER)], check=True, timeout=120)
        else:
            print("Apple vector renderer SDK/bitmap: SKIP locally (mandatory Darwin shipping gate)")
    print("Apple vector map shipping/resources + short-route negative control: PASS; asset SHA256 " + hashlib.sha256(ASSET.read_bytes()).hexdigest())


if __name__ == "__main__":
    main()
