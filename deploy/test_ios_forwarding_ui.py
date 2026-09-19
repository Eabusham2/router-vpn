#!/usr/bin/env python3
"""Execute the shipping forwarding model with deterministic fake NetworkExtension IPC.

Only SwiftUI view code and Apple imports are omitted from the executable harness.
The entire production model (including its async request/cancellation code) is
compiled unchanged. No VPN, credentials, filesystem state or server is modified.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "ios/RouterVPN/App/IOSForwardingMasterView.swift"
STUBS = r'''
import Foundation
@propertyWrapper struct Published<Value> { var wrappedValue: Value }
protocol ObservableObject: AnyObject {}
enum NEVPNStatus { case connected, disconnected }
@MainActor class NEVPNConnection {
    var status = NEVPNStatus.connected
    var connectedDate: Date? = Date(timeIntervalSince1970: 1000)
}
@MainActor final class NETunnelProviderSession: NEVPNConnection {
    var messages: [Data] = []
    var replies: [((Data?) -> Void)] = []
    func sendProviderMessage(_ data: Data, responseHandler: @escaping (Data?) -> Void) throws {
        messages.append(data); replies.append(responseHandler)
    }
}
class NEVPNProtocol {}
final class NETunnelProviderProtocol: NEVPNProtocol {
    var providerBundleIdentifier = "com.eabusham.routervpn.PacketTunnel"
    var providerConfiguration: [String: Any]?
}
@MainActor final class NETunnelProviderManager {
    static var loads: [CheckedContinuation<[NETunnelProviderManager], Error>] = []
    var protocolConfiguration: NEVPNProtocol?
    let connection: NEVPNConnection
    init(node: String = "home", session: NETunnelProviderSession, engine: String = "wireguard") {
        connection = session
        let proto = NETunnelProviderProtocol()
        proto.providerConfiguration = ["engine": engine, "bundle": try! JSONEncoder().encode(
            ClientBundle(selectedRouterID: node, routerProfiles: [RouterProfile(id: node, name: node, nodeKind: "router-vpn")]))]
        protocolConfiguration = proto
    }
    static func loadAllFromPreferences() async throws -> [NETunnelProviderManager] {
        try await withCheckedThrowingContinuation { loads.append($0) }
    }
}
struct RouterProfile: Codable { let id: String; let name: String; let nodeKind: String
    var normalizedNodeKind: String { nodeKind }
}
struct ClientBundle: Codable { let selectedRouterID: String; let routerProfiles: [RouterProfile] }
@MainActor final class RouterVPNModel {
    var connected = true
    var tunnelTransitioning = false
    var unifiedSelectedProfile: RouterProfile? = RouterProfile(id: "home", name: "Home", nodeKind: "router-vpn")
}
'''
TEST = r'''
@main struct ForwardingUITests {
    @MainActor static var checks = 0
    @MainActor static func check(_ name: String, _ value: @autoclosure () -> Bool) {
        precondition(value(), "FAIL: " + name); checks += 1
    }
    @MainActor static func wait(_ predicate: () -> Bool) async {
        for _ in 0..<2000 {
            if predicate() { return }
            try? await Task.sleep(for: .milliseconds(1))
        }
        fatalError("Test timed out waiting for deterministic IPC boundary")
    }
    static func data(node: String = "home", lease: String, enabled: Bool) -> Data {
        try! JSONSerialization.data(withJSONObject: ["version":1, "ok":true, "node_id":node, "session_id":lease, "enabled":enabled])
    }
    @MainActor static func read(_ master: IOSForwardingMaster, _ model: RouterVPNModel,
                                node: String = "home", lease: String, enabled: Bool = true) async {
        let session = NETunnelProviderSession()
        let actual = NETunnelProviderManager(node: node, session: session)
        let task = Task { await master.request(model: model) }
        await wait { !NETunnelProviderManager.loads.isEmpty }
        NETunnelProviderManager.loads.removeFirst().resume(returning: [actual])
        await wait { !session.replies.isEmpty }
        session.replies.removeFirst()(data(node: node, lease: lease, enabled: enabled))
        await task.value
        check("read accepted for \(node)", master.enabled == enabled && !master.busy)
    }
    @MainActor static func main() async {
        let model = RouterVPNModel(), master = IOSForwardingMaster(), lease = UUID().uuidString
        check("unknown initially", master.enabled == nil && !master.busy)
        check("no confirmation without readback", master.intent(model: model, enabled: true) == nil)
        await read(master, model, lease: lease)
        let confirmation = master.intent(model: model, enabled: false)!
        let session = NETunnelProviderSession()
        let set = Task { await master.request(model: model, intent: confirmation) }
        await wait { !NETunnelProviderManager.loads.isEmpty }
        NETunnelProviderManager.loads.removeFirst().resume(returning: [NETunnelProviderManager(session: session)])
        await wait { !session.replies.isEmpty }
        let message = try! JSONSerialization.jsonObject(with: session.messages[0]) as! [String: Any]
        check("set uses captured node", message["node_id"] as? String == "home")
        check("set uses captured lease", message["session_id"] as? String == lease)
        check("set remains boolean", message["enabled"] as? Bool == false && message["action"] as? String == "set")
        session.replies.removeFirst()(data(lease: lease, enabled: false))
        await set.value
        check("verified mutation applied", master.enabled == false && !master.busy)

        // A dialog survives a same-node reconnect. Its old lease must never be
        // silently replaced with the newest lease at the time of confirmation.
        let stale = master.intent(model: model, enabled: true)!
        master.invalidate()
        await read(master, model, lease: UUID().uuidString)
        await master.request(model: model, intent: stale)
        check("same-node stale confirmation sends nothing", NETunnelProviderManager.loads.isEmpty && !master.busy)
        check("stale confirmation explains retry", master.detail.contains("confirm again"))
        let staleNode = master.intent(model: model, enabled: false)!
        master.invalidate()
        model.unifiedSelectedProfile = RouterProfile(id: "second", name: "Second", nodeKind: "router-vpn")
        await read(master, model, node: "second", lease: UUID().uuidString)
        await master.request(model: model, intent: staleNode)
        check("different-node stale confirmation sends nothing", NETunnelProviderManager.loads.isEmpty)

        // Change selection while loadAllFromPreferences is suspended without
        // relying on SwiftUI to run its invalidation task in time.
        master.invalidate(); model.unifiedSelectedProfile = RouterProfile(id: "home", name: "Home", nodeKind: "router-vpn")
        let beforeSend = NETunnelProviderSession()
        let switching = Task { await master.request(model: model) }
        await wait { !NETunnelProviderManager.loads.isEmpty }
        model.unifiedSelectedProfile = RouterProfile(id: "second", name: "Second", nodeKind: "router-vpn")
        NETunnelProviderManager.loads.removeFirst().resume(returning: [NETunnelProviderManager(session: beforeSend)])
        await switching.value
        check("selection changed before IPC blocks send", beforeSend.messages.isEmpty)
        model.unifiedSelectedProfile = RouterProfile(id: "home", name: "Home", nodeKind: "router-vpn")

        // Invalidation releases busy immediately; the old operation completing
        // later cannot clear a replacement operation's busy flag or task handle.
        let oldSession = NETunnelProviderSession(), newSession = NETunnelProviderSession()
        let old = Task { await master.request(model: model) }
        await wait { !NETunnelProviderManager.loads.isEmpty }
        let oldLoad = NETunnelProviderManager.loads.removeFirst()
        master.invalidate()
        check("invalidation releases busy", !master.busy && master.enabled == nil)
        let newer = Task { await master.request(model: model) }
        await wait { !NETunnelProviderManager.loads.isEmpty }
        let newLoad = NETunnelProviderManager.loads.removeFirst()
        oldLoad.resume(returning: [NETunnelProviderManager(session: oldSession)])
        await old.value
        check("old completion does not clear new busy", master.busy)
        check("cancelled preference load sends nothing", oldSession.messages.isEmpty)
        newLoad.resume(returning: [NETunnelProviderManager(session: newSession)])
        await wait { !newSession.replies.isEmpty }
        newSession.replies.removeFirst()(data(lease: lease, enabled: true))
        await newer.value
        check("replacement operation completes", !master.busy && master.enabled == true)

        // Parent-task cancellation while waiting for the OS must stop the child
        // before it calls sendProviderMessage (which can itself launch an extension).
        let cancelSession = NETunnelProviderSession()
        let cancelledLoad = Task { await master.request(model: model) }
        await wait { !NETunnelProviderManager.loads.isEmpty }
        cancelledLoad.cancel()
        NETunnelProviderManager.loads.removeFirst().resume(returning: [NETunnelProviderManager(session: cancelSession)])
        await cancelledLoad.value
        check("parent cancellation prevents IPC", cancelSession.messages.isEmpty && !master.busy)

        let lateSession = NETunnelProviderSession()
        let cancelledReply = Task { await master.request(model: model) }
        await wait { !NETunnelProviderManager.loads.isEmpty }
        NETunnelProviderManager.loads.removeFirst().resume(returning: [NETunnelProviderManager(session: lateSession)])
        await wait { !lateSession.replies.isEmpty }
        let late = lateSession.replies.removeFirst()
        cancelledReply.cancel(); await cancelledReply.value
        check("IPC cancellation settles without reply", master.enabled == nil && !master.busy)
        await read(master, model, lease: UUID().uuidString, enabled: false)
        late(data(lease: lease, enabled: true)); late(nil)
        await Task.yield()
        check("late and duplicate callbacks cannot overwrite new state", master.enabled == false)

        // Same NETunnelProviderSession object can reconnect: object identity and
        // .connected alone are not evidence it is the original connection.
        let reconnectSession = NETunnelProviderSession()
        let reconnect = Task { await master.request(model: model) }
        await wait { !NETunnelProviderManager.loads.isEmpty }
        NETunnelProviderManager.loads.removeFirst().resume(returning: [NETunnelProviderManager(session: reconnectSession)])
        await wait { !reconnectSession.replies.isEmpty }
        reconnectSession.connectedDate = Date(timeIntervalSince1970: 2000)
        reconnectSession.replies.removeFirst()(data(lease: UUID().uuidString, enabled: true))
        await reconnect.value
        check("same-object reconnect rejected", master.enabled == nil && !master.busy)

        for kind in ["wrong-node", "wrong-lease", "wrong-state", "oversized", "refused"] {
            master.invalidate(); await read(master, model, lease: lease)
            let intent = master.intent(model: model, enabled: false)!
            let badSession = NETunnelProviderSession()
            let task = Task { await master.request(model: model, intent: intent) }
            await wait { !NETunnelProviderManager.loads.isEmpty }
            NETunnelProviderManager.loads.removeFirst().resume(returning: [NETunnelProviderManager(session: badSession)])
            await wait { !badSession.replies.isEmpty }
            let reply: Data
            switch kind {
            case "wrong-node": reply = data(node: "second", lease: lease, enabled: false)
            case "wrong-lease": reply = data(lease: UUID().uuidString, enabled: false)
            case "wrong-state": reply = data(lease: lease, enabled: true)
            case "oversized": reply = Data(repeating: 32, count: 4097)
            default: reply = Data("{\"version\":1,\"ok\":false,\"error\":\"Refused\"}".utf8)
            }
            badSession.replies.removeFirst()(reply); await task.value
            check("\(kind) fails unknown", master.enabled == nil && !master.busy)
        }
        for kind in ["duplicate", "external-engine", "wrong-bundle", "missing-start"] {
            let s = NETunnelProviderSession()
            if kind == "missing-start" { s.connectedDate = nil }
            let m = NETunnelProviderManager(node: kind == "wrong-bundle" ? "second" : "home", session: s,
                                            engine: kind == "external-engine" ? "external-libbox" : "wireguard")
            let task = Task { await master.request(model: model) }
            await wait { !NETunnelProviderManager.loads.isEmpty }
            NETunnelProviderManager.loads.removeFirst().resume(returning: kind == "duplicate" ? [m, m] : [m])
            await task.value
            check("\(kind) cannot send", s.messages.isEmpty && master.enabled == nil)
        }
        model.connected = false; await master.request(model: model)
        check("disconnected is unavailable", NETunnelProviderManager.loads.isEmpty && master.enabled == nil)
        model.connected = true; model.unifiedSelectedProfile = RouterProfile(id:"external",name:"External",nodeKind:"external")
        await master.request(model: model)
        check("external-only is not this server", NETunnelProviderManager.loads.isEmpty)
        print("iOS forwarding shipping-model tests: PASS (\(checks) checks)")
    }
}
'''


def main():
    swift = shutil.which("swiftc")
    if not swift:
        raise SystemExit("swiftc is required for executable forwarding UI tests")
    source = SOURCE.read_text()
    boundary = "struct IOSForwardingMasterButton: View {"
    if source.count(boundary) != 1:
        raise SystemExit("Shipping forwarding model/view boundary changed; review the test extraction")
    model = source.split(boundary, 1)[0]
    model = "\n".join(line for line in model.splitlines() if not line.startswith(("import ", "@preconcurrency import ")))
    required = ["@State private var proposed: IOSForwardingMaster.Intent?", "intent: proposed",
                ".NEVPNStatusDidChange", "model.unifiedSelectedProfile?.id", ".onDisappear { master.invalidate() }"]
    for marker in required:
        if marker not in source:
            raise SystemExit(f"Shipping view lost forwarding lifetime binding: {marker}")
    with tempfile.TemporaryDirectory(prefix="routervpn-forwarding-ui-") as tmp:
        src = Path(tmp) / "ForwardingUITests.swift"
        exe = Path(tmp) / "forwarding-ui-tests"
        src.write_text(STUBS + "\n" + model + "\n" + TEST)
        subprocess.run([swift, "-swift-version", "6", "-parse-as-library", str(src), "-o", str(exe)], check=True, timeout=90)
        subprocess.run([str(exe)], check=True, timeout=30)
    subprocess.run([swift, "-frontend", "-parse", str(SOURCE)], check=True, timeout=30)
    print("Full SwiftUI file parses; state-machine tests use fake IPC, not a live VPN.")


if __name__ == "__main__":
    main()
