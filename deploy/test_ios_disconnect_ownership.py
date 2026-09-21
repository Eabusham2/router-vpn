#!/usr/bin/env python3
"""Run the actual disconnect methods with system-manager doubles, offline."""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'
SHIM = r'''
import Foundation

enum IOSRuntimeSelectionError: LocalizedError {
    case unsupportedMode(String)
    var errorDescription: String? { switch self { case .unsupportedMode(let text): return text } }
}
enum Status { case invalid, disconnected, connecting, connected, reasserting, disconnecting }
@MainActor final class NETunnelProviderProtocol { var providerBundleIdentifier: String? }
@MainActor final class Connection {
    var status: Status = .connected
    var stops = 0
    var finishStop = true
    func stopVPNTunnel() { stops += 1; status = finishStop ? .disconnected : .disconnecting }
}
@MainActor final class NETunnelProviderManager {
    static var stored: [NETunnelProviderManager] = []
    static var failLoad = false
    var protocolConfiguration: Any?
    var isOnDemandEnabled = true
    var onDemandRules: [String]? = ["reconnect"]
    let connection = Connection()
    var failSave = false
    var failRead = false
    var ignoreSave = false
    var replaceOwnerOnRead = false
    var reconnectOnFinalRead = false
    var saves = 0
    var reads = 0
    init(_ owner: String = "com.eabusham.routervpn.PacketTunnel") {
        let proto = NETunnelProviderProtocol(); proto.providerBundleIdentifier = owner
        protocolConfiguration = proto
    }
    static func loadAllFromPreferences() async throws -> [NETunnelProviderManager] {
        await Task.yield()
        if failLoad { throw IOSRuntimeSelectionError.unsupportedMode("preference enumeration failed") }
        return stored
    }
    func saveToPreferences() async throws {
        saves += 1; await Task.yield()
        if failSave { throw IOSRuntimeSelectionError.unsupportedMode("preference save failed") }
    }
    func loadFromPreferences() async throws {
        reads += 1; await Task.yield()
        if failRead { throw IOSRuntimeSelectionError.unsupportedMode("preference read failed") }
        if ignoreSave { isOnDemandEnabled = true; onDemandRules = ["reconnect"] }
        if replaceOwnerOnRead { (protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier = "different.provider" }
        if reconnectOnFinalRead && reads == 2 { connection.status = .connecting }
    }
}
@MainActor final class RouterVPNModel {
    var connected = true
    var tunnelTransitioning = false
    var activeSessionIdentity: String? = "old-session"
    var activeEngine = "multihop-libbox"
    var activeRawProfile = "hysteria2"
    var message = "Connected"
    private var userDisconnectInProgress = false
    var profileMutationBlocked: Bool { connected || tunnelTransitioning || userDisconnectInProgress }
    func finishTask() async { while userDisconnectInProgress { await Task.yield() } }
    // SHIPPING_METHODS
}
@main struct Tests {
    @MainActor static func main() async throws {
        var checks = 0
        func check(_ name: String, _ value: @autoclosure () -> Bool) {
            guard value() else { fatalError("FAIL " + name) }; checks += 1
        }
        func fresh(_ managers: [NETunnelProviderManager]) -> RouterVPNModel {
            NETunnelProviderManager.stored = managers; NETunnelProviderManager.failLoad = false
            return RouterVPNModel()
        }
        let foreign = NETunnelProviderManager("foreign.provider")
        var model = fresh([foreign]); model.disconnect(); await model.finishTask()
        check("no owned manager is a verified absence", model.message == "Disconnected" && !model.profileMutationBlocked)
        check("foreign manager never saved or stopped", foreign.saves == 0 && foreign.connection.stops == 0)
        let owned = NETunnelProviderManager(); model = fresh([foreign, owned])
        model.disconnect()
        check("identity invalidated before asynchronous teardown", model.activeSessionIdentity == nil)
        check("mutations locked through teardown", model.profileMutationBlocked)
        model.disconnect(); await model.finishTask()
        check("only owned manager stops", owned.connection.stops == 1 && foreign.connection.stops == 0)
        check("duplicate Disconnect is serialized", owned.saves == 1)
        check("save and final state read back", owned.reads == 2 && !owned.isOnDemandEnabled && owned.onDemandRules == [])
        check("verified stop clears active runtime", !model.connected && model.activeEngine == "none" && model.activeRawProfile == "" && model.activeSessionIdentity == nil)
        check("verified stop unlocks UI", !model.profileMutationBlocked && model.message == "Disconnected")
        model = fresh([owned]); NETunnelProviderManager.failLoad = true
        model.disconnect(); await model.finishTask()
        check("enumeration error is unknown not absence", model.message.hasPrefix("Disconnect is unverified:") && model.connected && model.profileMutationBlocked)
        check("unknown enumeration cannot stop a foreign owner", owned.connection.stops == 1)
        for failure in ["save", "read", "ignored-save", "owner-changed", "reconnected"] {
            let manager = NETunnelProviderManager(); model = fresh([manager])
            manager.failSave = failure == "save"; manager.failRead = failure == "read"
            manager.ignoreSave = failure == "ignored-save"; manager.replaceOwnerOnRead = failure == "owner-changed"
            manager.reconnectOnFinalRead = failure == "reconnected"
            model.disconnect(); await model.finishTask()
            check("\(failure) cannot claim disconnected", model.message.hasPrefix("Disconnect is unverified:") && model.profileMutationBlocked && model.activeSessionIdentity == nil)
            check("\(failure) preserves owner boundary", manager.connection.stops == (failure == "owner-changed" ? 0 : 1))
        }
        let first = NETunnelProviderManager(), second = NETunnelProviderManager()
        model = fresh([first, second]); model.disconnect(); await model.finishTask()
        check("ambiguous ownership cannot pick first", first.connection.stops == 0 && second.connection.stops == 0 && model.profileMutationBlocked)
        let slow = NETunnelProviderManager(); slow.connection.finishStop = false
        model = fresh([slow]); model.disconnect(); await model.finishTask()
        check("stop timeout never fabricates disconnected", model.message.hasPrefix("Disconnect is unverified:") && model.connected && model.profileMutationBlocked)
        model = fresh([owned]); model.tunnelTransitioning = true
        let before = owned.connection.stops; model.disconnect(); await model.finishTask()
        check("existing transition is not overlapped", owned.connection.stops == before)
        print("iOS shipping disconnect ownership/readback: PASS (\(checks) executable checks)")
    }
}
'''


def main():
    swift = shutil.which('swiftc')
    if not swift:
        raise SystemExit('swiftc required to execute the shipping disconnect methods')
    source = (APP / 'RouterVPNModel.swift').read_text()
    begin = source.index('    func disconnect() {')
    end = source.index('    func applyForward(dmz:', begin)
    methods = source[begin:end]
    refresh = source[source.index('    func refreshTunnelStatus() async {'):begin]
    assert refresh.count('guard !userDisconnectInProgress else { return }') == 3, 'status readback must not race an owned user disconnect'
    assert 'connected || tunnelTransitioning || userDisconnectInProgress' in source
    with tempfile.TemporaryDirectory(prefix='routervpn-disconnect-') as tmp:
        path = Path(tmp) / 'Tests.swift'; binary = Path(tmp) / 'test'
        path.write_text(SHIM.replace('    // SHIPPING_METHODS', methods))
        subprocess.run([swift, '-swift-version', '6', '-parse-as-library', str(path), '-o', str(binary)], check=True, timeout=90)
        subprocess.run([str(binary)], check=True, timeout=25)
    print('Manager doubles verify ownership and error handling; this is not physical NetworkExtension acceptance.')


if __name__ == '__main__':
    main()
