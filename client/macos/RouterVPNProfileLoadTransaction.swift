import Foundation
import CoreFoundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

// Only the public path/mode and native CUSTOM menu belong in this journal.
// The controller is the sole owner of private profiles and their rollback.
enum MacProfileLoadTransaction {
    static let base = "/api/connection-profile/setup/load/"
    static let modeKey = "routervpn.unified.selected-mode.v1"
    static let presetsKey = "routervpn.unified.custom-presets.v1"
    static let multihopKey = "routervpn.unified.multihop-enabled.v1"
    static let executionKey = "routervpn.multihop.execution.v1"
    static let pathKey = "routervpn.appkit.profile-load-path.v1"

    static func issue(_ description: String) -> NSError {
        NSError(domain: "RouterVPN.ProfileLoad", code: 1, userInfo: [NSLocalizedDescriptionKey: description])
    }
    static func token(_ value: String, count: Int) -> Bool {
        value.utf8.count == count && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    static func boolean(_ value: Any?) -> Bool? {
        guard let value = value as? NSNumber, CFGetTypeID(value) == CFBooleanGetTypeID() else { return nil }
        return value.boolValue
    }
    static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(value)
    }
    struct Owner: Equatable, Codable {
        let operationID: String, generation: String, receipt: String
        var body: [String: Any] { ["operation_id":operationID, "generation":generation, "receipt_sha256":receipt] }
    }
    struct Reply {
        let owner: Owner?, state: String, finished: Bool, revision: String, snapshot: [String: Any]?
        init(_ data: Data, operation: String, expected: Owner? = nil, cancelling: Bool = false) throws {
            guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  boolean(root["ok"]) == true, let revision = root["revision"] as? String,
                  let number = UInt64(revision), String(number) == revision,
                  root["snapshot"] is [String:Any] || root["snapshot"] is NSNull, let fields = root["transaction"] as? [String: Any],
                  fields["operation_id"] as? String == operation, let state = fields["state"] as? String,
                  let finished = boolean(fields["finished"]) else { throw issue("The controller returned an incomplete Load receipt.") }
            self.revision = revision; self.state = state; self.finished = finished; snapshot = root["snapshot"] as? [String: Any]
            if state == "absent" || state == "superseded" {
                guard (state == "absent" && !finished || state == "superseded" && cancelling && finished), root["snapshot"] is NSNull, fields["generation"] == nil, fields["receipt_sha256"] == nil else {
                    throw issue("The controller returned an ambiguous absent Load receipt.")
                }
                owner = nil; return
            }
            guard ["prepared","committed","aborted"].contains(state), !finished || state != "prepared",
                  let generation = fields["generation"] as? String, token(generation, count: 32),
                  let digest = fields["receipt_sha256"] as? String, token(digest, count: 64) else { throw issue("The controller returned an invalid Load owner.") }
            let actual = Owner(operationID: operation, generation: generation, receipt: digest)
            guard expected == nil || expected == actual else { throw issue("A different controller generation owns this Load.") }
            owner = actual
        }
    }
    struct Local: Codable {
        var mode: String?, presets: Data?, multihop: Bool?, execution: String?, path: Data?
        var selection: RouterVPNConnectionProfileSelection
        init(defaults: UserDefaults, selection: RouterVPNConnectionProfileSelection) throws {
            guard defaults.synchronize() else { throw issue("Could not read durable AppKit profile preferences.") }
            self.selection = selection
            path = defaults.data(forKey: pathKey)
            if let path { _ = try JSONDecoder().decode(RouterVPNConnectionProfileSelection.self, from: path) }
            mode = defaults.string(forKey: modeKey); presets = defaults.data(forKey: presetsKey)
            multihop = boolean(defaults.object(forKey: multihopKey)); execution = defaults.string(forKey: executionKey)
            // Reject unfamiliar legacy shapes before copying anything into the public journal.
            if let presets {
                guard presets.count <= 512 * 1024, let rows = try JSONSerialization.jsonObject(with: presets) as? [[String:Any]],
                      rows.allSatisfy({ Set($0.keys) == ["name","layers"] && $0["name"] is String && $0["layers"] is [String] }) else {
                    throw issue("The saved CUSTOM menu could not be captured for Load.")
                }
            }
            for (key, valid) in [(modeKey,mode != nil),(presetsKey,presets != nil),(multihopKey,multihop != nil),(executionKey,execution != nil),(pathKey,path != nil)]
                where defaults.object(forKey: key) != nil && !valid { throw issue("A saved AppKit profile preference has an unexpected type.") }
        }
        func projected(snapshot: [String: Any], selection: RouterVPNConnectionProfileSelection) throws -> Self {
            var next = self
            guard let mode = snapshot["mode"] as? String else { throw issue("The prepared profile omitted its saved mode.") }
            next.mode = mode; next.selection = selection; next.path = try MacProfileLoadTransaction.encode(selection); next.multihop = selection.multihopEnabled; next.execution = selection.execution
            if let name = macCustomPresetName(in: mode) {
                guard let layers = snapshot["custom_layers"] as? [String], !layers.isEmpty else { throw issue("The saved CUSTOM profile has no captured layers.") }
                var catalog = try MacConnectionCustomPreset.catalog(presets)
                let item = MacConnectionCustomPreset(name: name, layers: layers)
                if let index = try MacConnectionCustomPreset.target(name, in: catalog) { catalog[index] = item }
                else { catalog.append(item); catalog.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending } }
                next.presets = try MacProfileLoadTransaction.encode(catalog)
            }
            return next
        }
        func install(in defaults: UserDefaults, from original: Self, allowingPartial: Bool) throws {
            let current = try Self(defaults: defaults, selection: selection)
            // Before the first coordinated Load a draft graph may exist only
            // in the native controls. Persist that original graph on rollback so
            // a subsequent launch can restore it after the journal is finished.
            let desiredPath = try path ?? (allowingPartial ? MacProfileLoadTransaction.encode(selection) : nil)
            func allowed<T: Equatable>(_ value: T?, _ previous: T?, _ desired: T?) -> Bool {
                value == previous || allowingPartial && value == desired
            }
            guard allowed(current.mode.map { Data($0.utf8) }, original.mode.map { Data($0.utf8) }, mode.map { Data($0.utf8) }),
                  allowed(current.presets, original.presets, presets),
                  allowed(current.multihop, original.multihop, multihop),
                  allowed(current.execution, original.execution, execution), (allowed(current.path, original.path, desiredPath) || allowingPartial && path == nil && current.path == nil) else { throw issue("AppKit profile choices changed outside this Load. Refresh before resolving it.") }
            for (key, value) in [(modeKey, mode as Any?), (presetsKey, presets as Any?),
                                 (multihopKey, multihop as Any?), (executionKey, execution as Any?), (pathKey, desiredPath as Any?)] {
                if let value { defaults.set(value, forKey: key) } else { defaults.removeObject(forKey: key) }
            }
            try verify(in: defaults)
        }
        func verify(in defaults: UserDefaults) throws {
            var actual = try Self(defaults: defaults, selection: selection)
            if path == nil, actual.path == (try MacProfileLoadTransaction.encode(selection)) { actual.path = nil }
            guard try MacProfileLoadTransaction.encode(actual) == MacProfileLoadTransaction.encode(self) else { throw issue("AppKit could not confirm the saved profile choices.") }
        }
    }
    enum Phase: String, Codable { case preparing, applying, complete, rolledBack }
    struct Journal: Codable {
        let operation: String
        var phase: Phase = .preparing
        let previous: Local
        var owner: Owner?
        var desired: Local?
        var prepareRequest: Data?
        var mayHaveSent = false
    }
    struct Store {
        let directory: URL
        static var standard: Store {
            Store(directory: FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
                    .appendingPathComponent("RouterVPN/ProfileLoad", isDirectory: true))
        }
        var file: URL { directory.appendingPathComponent("pending.json") }
        var pending: Bool {
            var info = stat()
            return lstat(file.path, &info) == 0 || errno != ENOENT
        }
        func permitsRequest(_ method: String?, path: String) -> Bool {
            if method == "GET" || !pending { return true }
            if ["/api/disconnect", "/api/emergency-stop"].contains(path) { return true }
            return ["prepare","status","commit","abort","cancel","finish"].contains { path == base + $0 }
        }
        func locked<T>(_ work: () throws -> T) throws -> T {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let fd = open(directory.appendingPathComponent("lock").path, O_CREAT | O_RDWR | O_NOFOLLOW, 0o600)
            guard fd >= 0 else { throw issue("AppKit could not open the profile Load lock.") }
            defer { _ = close(fd) }
            guard flock(fd, LOCK_EX | LOCK_NB) == 0 else { throw issue("Another AppKit window is completing profile Load.") }
            defer { _ = flock(fd, LOCK_UN) }
            return try work()
        }
        func read() throws -> Journal? {
            let bytes: Data
            do { bytes = try Data(contentsOf: file) }
            catch let error as NSError where error.domain == NSCocoaErrorDomain && error.code == NSFileReadNoSuchFileError { return nil }
            guard bytes.count <= 4 * 1024 * 1024 else { throw issue("The AppKit profile Load journal is too large.") }
            let item = try JSONDecoder().decode(Journal.self, from: bytes)
            guard token(item.operation, count:32) else { throw issue("The AppKit profile Load operation is invalid.") }
            if let owner = item.owner {
                guard owner.operationID == item.operation, token(owner.generation,count:32), token(owner.receipt,count:64) else {
                    throw issue("The AppKit profile Load receipt is invalid.")
                }
            }
            switch item.phase {
            case .preparing:
                guard item.owner == nil, item.desired == nil, !item.mayHaveSent || item.prepareRequest != nil else { throw issue("The original AppKit Load intent is incomplete.") }
            case .applying, .complete:
                guard item.owner != nil, item.desired != nil, item.mayHaveSent else { throw issue("The AppKit profile Load is missing its captured choices.") }
            case .rolledBack:
                guard item.owner != nil, item.mayHaveSent else { throw issue("The aborted AppKit profile Load receipt is missing.") }
            }
            return item
        }
        func replace(_ original: Journal?, with next: Journal?) throws {
            guard try encode(read()) == encode(original) else { throw issue("Another AppKit profile Load owns this journal.") }
            if let next {
                let data = try encode(next)
                guard data.count <= 4 * 1024 * 1024 else { throw issue("The AppKit profile Load exceeds its durable journal limit.") }
                let temp = directory.appendingPathComponent(UUID().uuidString + ".tmp")
                defer { try? FileManager.default.removeItem(at: temp) }
                try data.write(to: temp, options: .withoutOverwriting)
                guard chmod(temp.path, 0o600) == 0 else { throw issue("Could not protect the AppKit Load journal.") }
                let handle = try FileHandle(forWritingTo: temp)
                do { try handle.synchronize(); try handle.close() } catch { try? handle.close(); throw error }
                guard rename(temp.path,file.path) == 0 else { throw issue("Could not publish the AppKit Load journal.") }
            } else { try FileManager.default.removeItem(at: file) }
            let fd = open(directory.path, O_RDONLY | O_DIRECTORY)
            guard fd >= 0 else { throw issue("Could not open the AppKit Load journal directory.") }
            defer { _ = close(fd) }
            guard fsync(fd) == 0, try encode(read()) == encode(next) else { throw issue("Could not verify the durable AppKit Load journal.") }
        }
    }
    typealias Send = (String, [String: Any]) throws -> Data
    typealias Adopt = (RouterVPNConnectionProfileSelection) throws -> Void
    typealias CheckPath = (Journal) throws -> Void

    static func finish(_ record: Journal, reply: Reply, store: Store, send: Send) throws {
        guard record.phase == .complete || record.phase == .rolledBack else { throw issue("The local profile Load has not reached a durable decision.") }
        if reply.state != "absent" {
            let terminal = record.phase == .complete ? "committed" : "aborted"
            guard reply.state == terminal, let owner = reply.owner, owner == record.owner else { throw issue("The durable profile Load decisions disagree.") }
            if !reply.finished {
                let final = try Reply(send("finish",owner.body), operation:record.operation, expected:owner)
                guard final.state == terminal, final.finished else { throw issue("The controller has not acknowledged Load completion.") }
            }
        }
        try store.replace(record, with:nil)
    }
    @discardableResult static func recover(_ record: Journal, store: Store, defaults: UserDefaults, send: Send, checkPath: CheckPath, adopt: Adopt) throws -> Bool {
        var reply = try Reply(send("status", ["operation_id":record.operation]), operation:record.operation, expected:record.owner)
        if record.phase == .complete || record.phase == .rolledBack {
            try finish(record, reply:reply, store:store, send:send); return record.phase == .complete
        }
        if reply.state == "absent" && record.phase == .preparing && record.mayHaveSent {
            // An absent status can overtake the original network request. Only
            // cancellation at its recorded revision can rule out a later prepare.
            guard let bytes = record.prepareRequest, let body = try JSONSerialization.jsonObject(with:bytes) as? [String:Any],
                  body["operation_id"] as? String == record.operation, let revision = body["expected_revision"] as? String,
                  let expected = UInt64(revision), String(expected) == revision else { throw issue("The original AppKit prepare revision is missing.") }
            reply = try Reply(send("cancel",["operation_id":record.operation, "expected_revision":revision]), operation:record.operation, cancelling:true)
            if reply.state == "superseded", UInt64(reply.revision)! > expected {
                try store.replace(record, with:nil); return false
            }
            guard reply.owner != nil else { throw issue("The controller has not settled the original prepare request.") }
        }
        guard let owner = reply.owner else {
            guard record.phase == .preparing && !record.mayHaveSent else { throw issue("The controller no longer has the original profile Load receipt. AppKit kept its recovery journal.") }
            try store.replace(record, with:nil); return false
        }
        if record.phase == .applying {
            guard reply.snapshot != nil else { throw issue("The controller lost the staged profile Load snapshot.") }
            try checkPath(record)
        }
        var next = record; next.owner = owner
        if reply.state == "committed" {
            guard let desired = record.desired, record.phase == .applying else { throw issue("The controller committed a profile before AppKit staged its choices.") }
            try desired.verify(in:defaults); try adopt(desired.selection)
            next.phase = .complete
            try store.replace(record, with:next); try finish(next, reply:reply, store:store, send:send); return true
        }
        if let desired = record.desired {
            try record.previous.install(in:defaults, from:desired, allowingPartial:true)
            try adopt(record.previous.selection)
            // Adoption only updates native controls. Restore absent preference keys exactly too.
            try record.previous.verify(in:defaults)
        }
        var stopped = reply
        if reply.state == "prepared" { stopped = try Reply(send("abort",owner.body), operation:record.operation, expected:owner) }
        guard stopped.state == "aborted" else { throw issue("The controller did not abort the original Load.") }
        next.phase = .rolledBack
        try store.replace(record, with:next); try finish(next, reply:stopped, store:store, send:send)
        return false
    }
    static func load(body: [String: Any], previous: Local, store: Store, defaults: UserDefaults, send: Send,
                     validate: ([String: Any]) throws -> RouterVPNConnectionProfileSelection, checkPath: CheckPath, adopt: Adopt) throws -> [String: Any] {
        try store.locked {
            guard try store.read() == nil else { throw issue("Recover the pending AppKit profile Load before starting another.") }
            let op = UUID().uuidString.replacingOccurrences(of:"-",with:"").lowercased()
            let before = try Reply(send("status", ["operation_id":op]), operation:op)
            guard before.state == "absent" else { throw issue("The proposed AppKit profile Load operation was already used.") }
            var payload = body
            payload["operation_id"] = op
            payload["expected_revision"] = before.revision
            let allowed: Set<String> = ["id","expected_mode","expected_selected_node_id","expected_profile_tokens","operation_id","expected_revision"]
            guard Set(payload.keys) == allowed, payload["id"] is String, payload["expected_mode"] is String,
                  payload["expected_selected_node_id"] is String, payload["expected_profile_tokens"] is [String:String] else {
                throw issue("The original AppKit profile Load expectations could not be captured.")
            }
            var record = Journal(operation:op,previous:previous)
            record.prepareRequest = try JSONSerialization.data(withJSONObject:payload,options:.sortedKeys)
            try store.replace(nil, with:record)
            var snapshot: [String: Any]?
            do {
                var sending = record; sending.mayHaveSent = true
                try store.replace(record, with:sending); record = sending
                let prepared = try Reply(send("prepare",payload), operation:op)
                guard prepared.state == "prepared", !prepared.finished, let owner = prepared.owner, let result = prepared.snapshot else {
                    throw issue("The controller did not prepare an owned connection profile.")
                }
                snapshot = result
                let selection = try validate(result)
                let next = try previous.projected(snapshot:result, selection:selection)
                var staged = record; staged.phase = .applying; staged.owner = owner; staged.desired = next
                try store.replace(record, with:staged); record = staged
                try checkPath(record)
                try next.install(in:defaults, from:previous, allowingPartial:false)
                try adopt(selection)
                try next.verify(in:defaults)
                // All native durable fields must agree before asking the controller to commit.
                let committed = try Reply(send("commit", owner.body), operation:op, expected:owner)
                guard committed.state == "committed" else { throw issue("The controller did not commit the owned profile Load.") }
                try next.verify(in:defaults)
                var done = record; done.phase = .complete
                try store.replace(record, with:done); record = done
                try finish(done, reply:committed, store:store, send:send)
                return result
            } catch {
                let initialError = error
                guard let retained = try store.read(), retained.operation == op else { throw initialError }
                // The receipt determines whether a timed-out commit actually succeeded.
                do {
                    let committed = try recover(retained, store:store, defaults:defaults, send:send, checkPath:checkPath, adopt:adopt)
                    if committed, let snapshot { return snapshot }
                } catch { throw issue("Profile Load needs recovery: " + error.localizedDescription) }
                throw initialError
            }
        }
    }
}
