#!/usr/bin/env python3
"""Execute the shipping Apple MTU client against a captured provider boundary.

SwiftUI observation and the already separately tested NetworkExtension control
transport are doubled. The production client, native-result decoder and shared
measurement gate run unchanged; no VPN or device networking is started.
"""
from pathlib import Path
import resource
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'

HARNESS = r'''
import Foundation

protocol ObservableObject: AnyObject {}
@propertyWrapper struct Published<Value> {
    var wrappedValue: Value
    init(wrappedValue: Value) { self.wrappedValue = wrappedValue }
}
@MainActor final class Connection {
    enum State { case connected, disconnected }
    var status = State.connected
    var connectedDate: Date? = Date()
    var cancelled: [[String: String]] = []
    func sendProviderMessage(_ data: Data, responseHandler: @escaping (Data?) -> Void) throws {
        cancelled.append(try JSONSerialization.jsonObject(with: data) as! [String: String])
        responseHandler(nil)
    }
}
@MainActor final class RouterVPNModel {
    var connection = Connection()
    var session = "413c0c39-6641-4cec-b13c-76c2e0d24139"
}
@MainActor enum IOSMTUControl {
    struct Binding {
        let connection: Connection
        let connectedDate: Date
        let session: String
    }
    static var allowed = false
    static var readback = true
    static var capacity = 9000
    static var reject = false
    static var running = false
    static var started: [String] = []
    static var holdStatus = false
    static var pending: CheckedContinuation<Void, Never>?
    static func failure(_ message: String) -> NSError {
        NSError(domain: "CapturedProvider", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
    static func retestTimeout(_ binding: Binding) -> TimeInterval { 2 }
    static func capture(_ model: RouterVPNModel) async throws -> Binding {
        guard model.connection.status == .connected, let date = model.connection.connectedDate else { throw CancellationError() }
        return Binding(connection: model.connection, connectedDate: date, session: model.session)
    }
    static func message(_ binding: Binding, model: RouterVPNModel, operation: String, request: String) async throws -> Data {
        guard model.connection === binding.connection, model.session == binding.session,
              binding.connection.status == .connected, binding.connection.connectedDate == binding.connectedDate else { throw CancellationError() }
        let sourceAllowed = allowed, sourceReadback = readback, sourceCapacity = capacity
        if holdStatus && operation == "mtu-status" {
            holdStatus = false
            await withCheckedContinuation { pending = $0 }
        }
        if reject { throw failure("Captured native policy rejected Retest") }
        if operation == "mtu-start" {
            started.append(request)
            guard sourceAllowed && sourceReadback else { throw failure("Native MTU authority forbids this request") }
        }
        return try JSONSerialization.data(withJSONObject: [
            "session_id": binding.session, "request_id": request,
            "phase": running ? "proving" : "idle", "running": running,
            "complete": !running, "measured": false, "effective_mtu": sourceCapacity,
            "source": "configured-unmeasured", "interface_readback_valid": sourceReadback,
            "optimization_allowed": sourceAllowed, "tor_connection": true, "candidates": []
        ])
    }
}

@MainActor @main struct Tests {
    static var checks = 0
    static func check(_ value: @autoclosure () -> Bool, _ label: String) {
        precondition(value(), label); checks += 1
    }
    static func wait(_ label: String, _ value: () -> Bool) async throws {
        for _ in 0..<200 {
            if value() { return }
            try await Task.sleep(for: .milliseconds(10))
        }
        preconditionFailure(label)
    }
    static func main() async throws {
        let model = RouterVPNModel(), client = IOSMTUClient()
        client.start(model: model)
        check(!client.running && IOSMTUControl.started.isEmpty, "unread policy admitted Retest")
        await client.refresh(model: model)
        check(!client.optimizationAllowed && client.text.contains("9000") && client.text.contains("not a measured path MTU"), "configured Tor capacity lost truthful UI state")
        client.start(model: model)
        check(!client.running && IOSMTUControl.started.isEmpty, "configured capacity admitted Retest")

        IOSMTUControl.allowed = true; IOSMTUControl.capacity = 1280
        await client.refresh(model: model)
        check(client.optimizationAllowed, "proved Auto authority did not enable Retest")
        IOSMTUControl.readback = false
        await client.refresh(model: model)
        check(!client.optimizationAllowed && !client.text.contains("Configured interface capacity"), "missing reader enabled a configured claim")
        IOSMTUControl.readback = true; IOSMTUControl.reject = true
        await client.refresh(model: model)
        check(!client.optimizationAllowed, "provider failure retained Retest authority")
        IOSMTUControl.reject = false
        await client.refresh(model: model)

        let hold = IOSMTUMeasurementGate.acquire()
        client.start(model: model)
        check(!client.running && IOSMTUControl.started.isEmpty, "measurement hold admitted Retest")
        _ = IOSMTUMeasurementGate.release(hold)

        IOSMTUControl.running = true
        client.start(model: model)
        try await wait("captured Auto request did not start") { !IOSMTUControl.started.isEmpty }
        let old = model.connection, request = IOSMTUControl.started.last!
        check(client.running, "running native request was called complete")
        client.cancel()
        check(!client.running && !client.optimizationAllowed, "Cancel retained stale UI authority")
        check(old.cancelled.last == ["operation": "mtu-cancel", "request_id": request, "session_id": model.session], "Cancel did not use its captured native session/request")
        try await Task.sleep(for: .milliseconds(20))

        // A delayed status reply must not grant a retired panel or connection
        // the previous owner's optimization permission.
        IOSMTUControl.running = false; IOSMTUControl.holdStatus = true
        let delayed = Task { await client.refresh(model: model) }
        try await wait("status callback did not enter capture") { IOSMTUControl.pending != nil }
        client.cancel(); IOSMTUControl.allowed = false; IOSMTUControl.capacity = 9000
        let pending = IOSMTUControl.pending; IOSMTUControl.pending = nil; pending?.resume()
        await delayed.value
        check(!client.optimizationAllowed && !client.text.contains("1280"), "late status revived cancelled MTU authority")
        await client.refresh(model: model)
        check(!client.optimizationAllowed && client.text.contains("9000"), "replacement configured owner lost its current readback")

        IOSMTUControl.allowed = true; IOSMTUControl.capacity = 1280; IOSMTUControl.running = true
        await client.refresh(model: model)
        let before = IOSMTUControl.started.count
        client.start(model: model)
        try await wait("second native request did not start") { IOSMTUControl.started.count == before + 1 }
        let replaced = model.connection
        model.connection = Connection(); model.session = UUID().uuidString
        let replacement = model.connection
        client.cancel()
        check(replacement.cancelled.isEmpty && replaced.cancelled.count == 2, "Cancel touched a replacement provider")
        check(!client.optimizationAllowed, "replacement session inherited a stale optimization flag")
        print("Apple MTU client: PASS (\(checks) actual client/decoder/gate checks; provider boundary doubled)")
    }
}
'''


def main():
    swift = shutil.which('swiftc')
    if not swift:
        raise RuntimeError('Swift is required; MTU client ownership cannot be skipped')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    full = (APP / 'IOSMTUClient.swift').read_text()
    source = full[:full.index('\nstruct IOSMTUCard: View')]
    source = source.replace('import SwiftUI\n', '').replace('@preconcurrency import NetworkExtension\n', '')
    assert '!probe.optimizationAllowed || IOSMTUMeasurementGate.held' in full, 'live card must honor retained native authority'
    with tempfile.TemporaryDirectory(prefix='ios-mtu-client-') as directory:
        work = Path(directory)
        harness = work / 'Tests.swift'; harness.write_text(HARNESS)
        client = work / 'IOSMTUClient.swift'; client.write_text(source)
        binary = work / 'test'
        command = [swift, '-swift-version', '6', '-module-cache-path', str(work / 'modules'),
                   str(client), str(APP / 'IOSMTUStatus.swift'), str(APP / 'IOSMTUMeasurementGate.swift'),
                   str(harness), '-o', str(binary)]
        def run(broken=None):
            subprocess.run(command, check=True, timeout=90)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=15)
            if broken:
                assert result.returncode != 0 and broken in result.stdout + result.stderr, result.stdout + result.stderr
            else:
                if result.returncode: raise RuntimeError(result.stdout + result.stderr)
                print(result.stdout, end='')
        run()
        for name, before, after, expected in (
            ('unread-authority', 'guard !running, optimizationAllowed, !IOSMTUMeasurementGate.held', 'guard !running, !IOSMTUMeasurementGate.held', 'unread policy admitted Retest'),
            ('late-status', 'guard generation == round, !running else { return }', 'guard !running else { return }', 'late status revived cancelled MTU authority'),
            ('readback-authority', 'status.optimization_allowed == true && status.interface_readback_valid == true', 'status.optimization_allowed == true', 'missing reader enabled a configured claim'),
        ):
            assert before in source, name
            client.write_text(source.replace(before, after))
            run(expected)
            print('Apple MTU client defect rejected: ' + name)


if __name__ == '__main__':
    main()
