# Native Router VPN vector basemap

The iOS/iPadOS and macOS map uses Router VPN's own opaque vector renderer for
land, coastline, ocean and graticule. MapKit supplies native pan/zoom and
coordinate transforms. It is not a browser wrapper or a renamed street map.
`RouterVPNVectorMapOverlay.canReplaceMapContent()` is true, and its renderer
covers the requested rectangle before drawing the local geometry. It is
installed above stock map labels; VPN routes and node annotations remain above
the base. A status refresh removes route overlays only, preserving the custom
base even with an empty catalog or disconnected VPN.

The underlying MapKit view uses an explicit `MKStandardMapConfiguration` with
flat elevation, muted emphasis, traffic disabled and stock points of interest
excluded. Camera pitch is disabled. This uses the supported configuration API;
Apple documents that the older
[`showsBuildings` property](https://developer.apple.com/documentation/mapkit/mkmapview/showsbuildings)
has no effect with overlays on iOS 16/macOS 13 and later. Visible geography
continues to come from the opaque bundled renderer.

## Geography and coordinates

Both application packages include the same 87,951-byte land asset: 128 closed
rings and 5,143 vertices from the pinned Natural Earth 110m land 4.1.0 archive.
It contains physical land outlines, no political borders, names or VPN nodes.
The archive checksum, public-domain notice, source URLs and deterministic
conversion command are in `client/shared/map/NATURAL-EARTH.txt`. The generator
verifies the complete archive before parsing Polygon records; builds do not
download new geography. Runtime code uses no remote tile URL or geocoder.

The source dataset is a small-scale world outline, so it is intended for VPN
path context rather than street navigation. Nodes still use only explicit
coordinates in their linked profiles. The device marker still requires the
user's location-button tap, platform permission and a fresh Core Location fix.
No node or device coordinate is inferred from the land dataset or an IP address.

The shared projection clamps polar display latitude to the finite Mercator
limit. Source coordinates retain the original WGS84 range. Date-line routes
are split at the two world edges rather than crossing the long way through
the map. iOS packet motion uses the same projected short route. Its animation
requires a proved connection, while a saved disconnected path is dashed.
Packet animation is decorative: every displayed RTT comes from measurement.
iOS refreshes fit the map only when the node-coordinate set changes, preserving
the user's pan and zoom while latency and connection status update.
macOS marker selection uses the same idle-checked saved selection transaction
as its node picker. Selecting a marker never starts a connection, and a blocked
selection leaves the active path untouched. Zoom remains bounded to a useful
VPN/region view instead of trying to use the small-scale coastlines as streets.

## Validation and delivery limits

`deploy/test_apple_vector_map.py` executes the unchanged shared Swift geometry
and checks the packaged source/resource paths. It exercises malformed and
oversized geography, coordinate limits, exact endpoints, polar behavior and
both date-line directions. A changed implementation that takes the long route
must fail the same executable checks.

On Apple build hosts the same gate must compile both shared sources with the
real iOS SDK and render a bitmap with the real macOS MapKit/Core Graphics
renderer. The bitmap check requires every pixel to be opaque and checks known
inland/ocean positions using MapKit's projection, the renderer's color space
and the downward-Y map drawing transform. Vertically mirrored land must fail
the same native bitmap check. A real `MKMapView` test starts with a non-flat,
traffic-enabled configuration and verifies the installed flat/muted policy,
excluded points of interest, disabled pitch, idempotent installation and route
removal that preserves the base. Omitting the configuration assignment must
also fail. The macOS builder and iOS runtime
contract both invoke this gate; Linux explicitly reports the native portion
as unavailable rather than counting a mock renderer as SDK evidence.

Native compile/render evidence remains separate from inspection of the final
iPhone, iPad and Mac layouts, gestures, accessibility and location permission
flows on installed packages. This basemap does not make a claim about all
framework network traffic; MapKit is still a system framework. The app's own
renderer needs only its bundled vector data.
