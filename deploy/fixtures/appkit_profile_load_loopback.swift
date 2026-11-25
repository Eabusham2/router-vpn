import FoundationNetworking

final class TransportResult: @unchecked Sendable {
    var data: Data?
    var response: URLResponse?
    var error: Error?
}
func post(_ url: URL, body: [String: Any]) throws -> Data {
    let transfer = TransportResult()
    let finished = DispatchSemaphore(value: 0)
    var request = URLRequest(url: url, timeoutInterval: 8)
    request.httpMethod = "POST"
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.httpBody = try JSONSerialization.data(withJSONObject: body)
    let task = URLSession.shared.dataTask(with: request) { data, response, error in
        transfer.data = data; transfer.response = response; transfer.error = error
        finished.signal()
    }
    task.resume()
    guard finished.wait(timeout: .now() + 10) == .success else { task.cancel(); throw MacProfileLoadTransaction.issue("loopback timed out") }
    if let error = transfer.error { throw error }
    guard let response = transfer.response as? HTTPURLResponse, let data = transfer.data else { throw MacProfileLoadTransaction.issue("missing loopback response") }
    guard response.statusCode == 200 else { throw MacProfileLoadTransaction.issue("HTTP \(response.statusCode): " + String(decoding: data, as: UTF8.self)) }
    return data
}
@main struct RunLiveAppKitLoad {
    static func main() throws {
        typealias Tx = MacProfileLoadTransaction
        let args = CommandLine.arguments
        guard args.count == 5, let base = URL(string: args[1]), base.host == "127.0.0.1", base.scheme == "http",
              let body = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: args[2]))) as? [String: Any],
              let originalNode = body["expected_selected_node_id"] as? String,
              let originalTokens = body["expected_profile_tokens"] as? [String:String] else { throw Tx.issue("Pass an isolated loopback URL and request JSON") }
        let fault = args[3]
        let domain = "router-appkit-live-" + UUID().uuidString
        let defaults = UserDefaults(suiteName:domain)!, store = Tx.Store(directory: URL(fileURLWithPath:args[4],isDirectory:true))
        defer { defaults.removePersistentDomain(forName:domain); _ = defaults.synchronize() }
        defaults.set("smart-auto", forKey:Tx.modeKey)
        let original = RouterVPNConnectionProfileSelection(selectedNodeID:originalNode, profileTokens:originalTokens)
        let previous = try Tx.Local(defaults:defaults, selection:original)
        var shown = original, stages = [String](), lost = false, success = false, op = ""
        var target: RouterVPNConnectionProfileSelection?
        do {
            _ = try Tx.load(body:body, previous:previous, store:store, defaults:defaults, send:{ phase, payload in
                stages.append(phase)
                if let seen = payload["operation_id"] as? String { if !op.isEmpty && seen != op { throw Tx.issue("operation changed") }; op = seen }
                if phase == "commit" {
                    guard let target, shown == target, let journal = try store.read(), journal.phase == .applying,
                          let desired = journal.desired else { throw Tx.issue("commit preceded native graph adoption") }
                    try desired.verify(in: defaults)
                }
                let data = try post(base.appendingPathComponent("api/connection-profile/setup/load/"+phase), body:payload)
                if fault == "after-"+phase && !lost { lost = true; throw Tx.issue("simulated lost reply after real controller phase") }
                return data
            }, validate:{ value in
                let restored = try Validator().validatedLoadedConnectionProfileSelection(value)
                target = restored
                if fault == "reject" { throw Tx.issue("simulated checked local restore failure") }
                return restored
            }, checkPath:{ record in
                if shown != record.previous.selection && shown != record.desired?.selection { throw Tx.issue("unexpected visible graph") }
            }, adopt:{ shown = $0 })
            success = true
        } catch {
            if !["after-prepare", "reject"].contains(fault) { throw error }
        }
        let expectedSuccess = !["after-prepare","reject"].contains(fault)
        let terminal = try Tx.Reply(post(base.appendingPathComponent("api/connection-profile/setup/load/status"),body:["operation_id":op]), operation:op)
        guard success == expectedSuccess, terminal.finished, terminal.state == (expectedSuccess ? "committed" : "aborted"),
              expectedSuccess ? shown == target : shown == original, try store.read() == nil else { throw Tx.issue("unsettled controller/native outcome") }
        if expectedSuccess {
            guard let name = macCustomPresetName(in: body["expected_mode"] as? String ?? ""),
                  let layers = terminal.snapshot?["custom_layers"] as? [String],
                  defaults.string(forKey: Tx.modeKey) == body["expected_mode"] as? String else { throw Tx.issue("lost original CUSTOM mode") }
            let catalog = try MacConnectionCustomPreset.catalog(defaults.data(forKey: Tx.presetsKey))
            guard let index = try MacConnectionCustomPreset.target(name, in: catalog), catalog[index].layers == layers else {
                throw Tx.issue("native CUSTOM layers differ from the controller's original snapshot")
            }
        } else {
            try previous.verify(in: defaults)
        }
        print("AppKit + live Go controller \(fault): \(terminal.state), revision \(terminal.revision), phases \(stages.joined(separator: " → "))")
    }
}
