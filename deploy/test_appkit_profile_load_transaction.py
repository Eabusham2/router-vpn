#!/usr/bin/env python3
"""Execute AppKit's durable profile Load with real private files and isolated defaults around a simulated owning controller."""
from pathlib import Path
import subprocess
import tempfile
from test_ios_startup_policy import member

ROOT = Path(__file__).resolve().parents[1]
MAC = ROOT / "client/macos"
SWIFT = r'''
import Foundation
enum RouterVPNOrderedNodes { static func issue(_ text: String) -> NSError { MacProfileLoadTransaction.issue(text) } }
typealias Tx = MacProfileLoadTransaction
func check(_ value: Bool, _ why: String) { if !value { print("Rejected: " + why); exit(1) } }
final class Preferences: UserDefaults {
    var dropNextPresetWrite = false
    override func set(_ value: Any?, forKey key: String) {
        if key == Tx.presetsKey && dropNextPresetWrite { dropNextPresetWrite = false; return }
        super.set(value, forKey:key)
    }
}
final class Controller {
    let gen = String(repeating: "a",count:32), digest = String(repeating:"b",count:64)
    var operation = "", state = "absent", finished = false, active = "A", phases = [String]()
    var revision = UInt64(0), tombstone = false
    var fail = "", once = true, snapshot: [String:Any] = ["mode":"custom:Night","custom_layers":["wg","pq"]]
    var beforeAction: ((String) throws -> Void)?
    func send(_ phase:String,_ body:[String:Any]) throws -> Data {
        phases.append(phase)
        guard let op = body["operation_id"] as? String, Tx.token(op,count:32) else { throw Tx.issue("operation identity missing") }
        try beforeAction?(phase)
        if !["prepare","status","cancel"].contains(phase) {
            guard op == operation, body["generation"] as? String == gen, body["receipt_sha256"] as? String == digest else { throw Tx.issue("foreign controller receipt") }
        }
        if fail == "before-" + phase && once { once = false; throw Tx.issue("request did not reach controller") }
        var superseded = false
        switch phase {
        case "cancel":
            if operation == op { break }
            guard body["expected_revision"] as? String == String(revision) else { superseded = true; break }
            guard state == "absent" || finished else { throw Tx.issue("a different operation is still pending") }
            revision += 1; operation = op; state = "aborted"; finished = false; tombstone = true
        case "prepare":
            if operation == op { break }
            guard body["expected_revision"] as? String == String(revision) else { throw Tx.issue("stale revision") }
            guard state == "absent" || finished, body["expected_mode"] as? String == "custom:Night" else { throw Tx.issue("already reserved") }
            revision += 1; operation = op; state = "prepared"; finished = false; tombstone = false
        case "status": break
        case "commit": guard state == "prepared" else { throw Tx.issue("not prepared") }; active = "B"; state = "committed"
        case "abort": guard state == "prepared" else { throw Tx.issue("not prepared") }; active = "A"; state = "aborted"
        case "finish": guard ["aborted","committed"].contains(state) else { throw Tx.issue("not terminal") }; finished = true
        default: throw Tx.issue("unexpected API action")
        }
        if fail == "after-" + phase && once { once = false; throw Tx.issue("reply lost") }
        let absent = state == "absent" || op != operation
        var fields: [String:Any] = ["operation_id":op,"state":superseded ? "superseded" : absent ? "absent" : state,"finished":superseded ? true : absent ? false : finished]
        if !absent { fields["generation"] = gen; fields["receipt_sha256"] = digest }
        return try JSONSerialization.data(withJSONObject:["ok":true,"revision":String(revision),"transaction":fields,"snapshot":absent || tombstone ? NSNull() as Any : snapshot])
    }
}
@main struct Tests {
    static func main() throws {
        let directory = URL(fileURLWithPath:CommandLine.arguments[1],isDirectory:true), store = Tx.Store(directory:directory)
        let domain = "router-load-" + UUID().uuidString, defaults = Preferences(suiteName:domain)!
        defer { defaults.removePersistentDomain(forName:domain) }
        let a = RouterVPNConnectionProfileSelection(selectedNodeID:"A", multihopEnabled:false)
        let b = RouterVPNConnectionProfileSelection(selectedNodeID:"B", multihopEnabled:true, execution:"server",
                  profileTokens:["B":String(repeating:"c",count:64)], orderedNodes:[["id":"C","mode":"wg"],["id":"B","mode":"shadowsocks"]])
        let body: [String:Any] = ["id":"saved","expected_mode":"custom:Night","expected_selected_node_id":"A","expected_profile_tokens":["A":String(repeating:"f",count:64)]]
        let old = try Tx.encode([MacConnectionCustomPreset(name:"Other",layers:["x"]),MacConnectionCustomPreset(name:"Night",layers:["old"])])
        func reset() {
            defaults.removePersistentDomain(forName:domain); defaults.set("smart-auto",forKey:Tx.modeKey)
            defaults.set(old,forKey:Tx.presetsKey); _ = defaults.synchronize()
        }
        for fault in ["none","before-prepare","after-prepare","bad-path","preset-write","adopt-failure","before-commit","after-commit","before-finish","after-finish"] {
            reset(); let server = Controller(); server.fail = fault
            let previous = try Tx.Local(defaults:defaults,selection:a)
            defaults.dropNextPresetWrite = fault == "preset-write"
            var applied = a, adopted = false, success = false
            server.beforeAction = { phase in
                if phase == "commit" {
                    check(applied == b, "commit preceded checked AppKit path adoption")
                    let staged = try store.read()!
                    check(staged.phase == .applying && staged.desired?.selection == b, "commit preceded durable AppKit graph capture")
                    try staged.desired!.verify(in:defaults)
                    check(server.active == "A","prepared state prematurely changed controller")
                } else if phase == "finish" {
                    let phase = try store.read()?.phase
                    check(phase == .complete || phase == .rolledBack, "finish preceded durable local outcome")
                }
            }
            do {
                _ = try Tx.load(body:body,previous:previous,store:store,defaults:defaults,send:server.send,validate:{_ in
                    if fault == "bad-path" {throw Tx.issue("bad referenced path")}
                    return b
                },checkPath:{ _ in },adopt:{selection in
                    if fault == "adopt-failure" && !adopted {adopted=true;throw Tx.issue("native projection could not be applied")}
                    applied = selection
                }); success = true
            } catch {}
            let committed = ["none","after-commit","before-finish","after-finish"].contains(fault)
            check(success == committed && server.active == (committed ? "B" : "A") && applied == (committed ? b : a), "owner or native path differs after " + fault)
            check(try store.read() == nil,"journal remained after resolvable " + fault)
            if fault == "before-prepare" {
                check(server.phases == ["status","prepare","status","cancel","finish"], "unknown sent prepare was discarded before its owned receipt")
            }
            if committed { check(defaults.string(forKey:Tx.modeKey) == "custom:Night" && defaults.array(forKey:"unexpected") == nil,"committed menu mismatch") }
            else { try previous.verify(in:defaults) }
        }
        // A new process can recover every durable interruption without the old
        // window, including a partly written defaults domain.
        for fault in ["prepared-partial","committed","terminal-newer","rolledback-newer","foreign-local","missing-receipt","foreign-generation","lost-status","foreign-window"] {
            reset(); let server=Controller(), op=String(repeating:"c",count:32)
            let previous=try Tx.Local(defaults:defaults,selection:a), next=try previous.projected(snapshot:server.snapshot,selection:b)
            let prepared=try Tx.Reply(server.send("prepare",["operation_id":op,"expected_mode":"custom:Night","expected_revision":"0"]),operation:op)
            var journal=Tx.Journal(operation:op,previous:previous); journal.owner=prepared.owner; journal.desired=next;journal.phase = .applying;journal.mayHaveSent=true
            if fault == "terminal-newer" { journal.phase = .complete }
            if fault == "rolledback-newer" { journal.phase = .rolledBack }
            try store.locked { try store.replace(nil,with:journal) }
            check(!store.permitsRequest("POST",path:"/api/auto") && !store.permitsRequest("POST",path:"/api/connect-logical") &&
                  store.permitsRequest("POST",path:"/api/disconnect") && store.permitsRequest("POST",path:"/api/emergency-stop") &&
                  store.permitsRequest("POST",path:Tx.base+"status"),"recovery must gate native Connect and preserve Stop")

            if fault == "prepared-partial" { defaults.set(next.mode,forKey:Tx.modeKey) }
            else { try next.install(in:defaults,from:previous,allowingPartial:false) }
            if ["committed","terminal-newer"].contains(fault) { _ = try server.send("commit",prepared.owner!.body) }
            if fault == "rolledback-newer" { _ = try server.send("abort",prepared.owner!.body) }
            if ["terminal-newer","rolledback-newer"].contains(fault) { _ = try server.send("finish",prepared.owner!.body); server.operation=String(repeating:"d",count:32); defaults.set("newer",forKey:Tx.modeKey) }
            if fault == "foreign-local" { defaults.set("newer",forKey:Tx.modeKey) }
            if fault == "missing-receipt" { server.operation=String(repeating:"d",count:32) }
            if fault == "foreign-generation" { journal.owner = .init(operationID:op,generation:String(repeating:"8",count:32),receipt:server.digest); try store.locked { try store.replace(try store.read(),with:journal) } }
            if fault == "lost-status" { server.fail="before-status" }
            var adopted=[String](), failed=false
            do { try store.locked { _ = try Tx.recover(try store.read()!,store:store,defaults:defaults,send:server.send,checkPath:{ _ in if fault=="foreign-window" {throw Tx.issue("another window selected a different path")} },adopt:{adopted.append($0.selectedNodeID)}) } }
            catch { failed=true }
            let conflict=["foreign-local","missing-receipt","foreign-generation","lost-status","foreign-window"].contains(fault)
            check(failed==conflict && store.pending==conflict, "unexpected recovery verdict " + fault)
            if fault == "prepared-partial" { try previous.verify(in:defaults); check(adopted==["A"] && (try? JSONDecoder().decode(RouterVPNConnectionProfileSelection.self,from:defaults.data(forKey:Tx.pathKey)!)) == a && server.state=="aborted" && server.finished,"partial native defaults not restored") }
            if fault == "committed" { try next.verify(in:defaults); check(adopted==["B"] && server.finished,"lost receipt did not adopt original committed path") }
            if conflict || ["terminal-newer","rolledback-newer"].contains(fault) { check(adopted.isEmpty,"foreign or complete operation replayed native path") }
            if ["foreign-local","terminal-newer","rolledback-newer"].contains(fault) { check(defaults.string(forKey:Tx.modeKey)=="newer","recovery overwrote newer local choice") }
            if store.pending { try store.locked { try store.replace(try store.read(),with:nil) } }
        }
        for fault in ["never-sent","delayed","newer-owner","won-cancel-race"] {
            reset()
            let server = Controller(), op = String(repeating:"d", count:32), newer = String(repeating:"e",count:32)
            let previous = try Tx.Local(defaults:defaults,selection:a)
            var payload = body; payload["operation_id"] = op; payload["expected_revision"] = "0"
            var journal = Tx.Journal(operation:op,previous:previous)
            journal.prepareRequest = try JSONSerialization.data(withJSONObject:payload)
            journal.mayHaveSent = fault != "never-sent"
            try store.locked { try store.replace(nil,with:journal) }
            if fault == "newer-owner" {
                var other = payload; other["operation_id"] = newer
                _ = try server.send("prepare",other)
            }
            if fault == "won-cancel-race" {
                server.beforeAction = { stage in
                    if stage == "cancel" { server.beforeAction = nil; _ = try server.send("prepare",payload) }
                }
            }
            try store.locked {
                _ = try Tx.recover(journal,store:store,defaults:defaults,send:server.send,checkPath:{ _ in check(false,"untouched intent checked native updates") },
                                   adopt:{ _ in check(false,"untouched preparing intent changed native path") })
            }
            try previous.verify(in:defaults)
            check(!store.pending,"settled preparing intent left a journal")
            if fault == "never-sent" {
                check(server.phases == ["status"] && server.revision == 0,"never-sent intent changed controller")
            } else if fault == "newer-owner" {
                check(server.operation == newer && server.state == "prepared" && !server.finished && !server.phases.contains("abort"),"superseded intent touched newer controller owner")
            } else {
                check(server.state == "aborted" && server.finished && server.operation == op,"delayed prepare did not retire original ownership")
                let same = try Tx.Reply(server.send("prepare",payload),operation:op)
                check(same.state == "aborted" && same.finished,"late retry revived a finished operation")
                var next = payload; next["operation_id"]=newer; next["expected_revision"]=String(server.revision)
                let other = try Tx.Reply(server.send("prepare",next),operation:newer)
                _ = try server.send("abort",other.owner!.body); _ = try server.send("finish",other.owner!.body)
                var rejected = false
                do { _ = try server.send("prepare",payload) } catch { rejected = true }
                check(rejected && server.operation == newer,"stale delayed prepare reacquired ownership after its receipt was replaced")
            }
        }
        print("AppKit durable profile Load passed 23 same-owner, interrupted, partial-write and foreign-owner paths")
    }
}
'''


def program():
    profiles = (MAC/'RouterVPNConnectionProfiles.swift').read_text()
    support = '\n'.join(member(profiles,mark) for mark in ('func macCustomPresetName(', 'struct MacConnectionCustomPreset:', 'struct RouterVPNConnectionProfileSelection:'))
    return (MAC/'RouterVPNProfileLoadTransaction.swift').read_text() + '\n' + support + '\n' + SWIFT


def main():
    with tempfile.TemporaryDirectory(prefix='appkit-profile-load-') as raw:
        root = Path(raw); path = root/'Load.swift'; binary = root/'Load'
        source = program()
        compile_command = ['swiftc','-swift-version','6','-parse-as-library',str(path),'-o',str(binary)]
        path.write_text(source)
        subprocess.run(compile_command,check=True,timeout=90)
        subprocess.run([binary,root/'private'],check=True,timeout=30)
        for tag, old, new, witness in (
            ('premature-commit', 'try adopt(selection)\n                try next.verify', 'try next.verify',
             'commit preceded checked AppKit path adoption'),
            ('unsafe-recovery', 'if record.phase == .complete || record.phase == .rolledBack {',
             'if (record.phase == .complete || record.phase == .rolledBack) && reply.state != "absent" {', 'unexpected recovery verdict terminal-newer' ),
        ):
            assert source.count(old) == 1, tag
            path.write_text(source.replace(old,new))
            subprocess.run(compile_command,check=True,timeout=90)
            run = subprocess.run([binary,root/tag],capture_output=True,text=True,timeout=30)
            assert run.returncode==1 and 'Rejected: '+witness in run.stdout, (tag,run)
            print('Rejected '+tag,flush=True)

if __name__=='__main__':
    main()
