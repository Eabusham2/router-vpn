#!/usr/bin/env python3
"""Execute native macOS candidate receipt/ownership policy and parse UI wiring."""
from pathlib import Path
import importlib.util
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MAC = ROOT / "client/macos"

SWIFT = r'''
import Foundation

func json(_ object: [String: Any]) throws -> Data { try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) }
let now = Date(timeIntervalSince1970: 1_790_000_000)
let nonce = String(repeating: "a", count: 32)
func receipt(_ request: String = nonce) -> [String: Any] {
 let formatter = ISO8601DateFormatter(); formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
 return ["schema": 1, "request_id": request, "entry_id": "entry", "entry_mode": "wg", "entry_base": "wg", "drained": true,
  "measured_at": formatter.string(from: now), "expires_at": formatter.string(from: now.addingTimeInterval(120)),
  "results": [
   ["id": "slow", "node_kind": "router-vpn", "samples": 5, "failed": 0, "median_ms": 27.125],
   ["id": "fast", "node_kind": "router-vpn", "samples": 5, "failed": 0, "median_ms": 11.25]],
  "errors": [["id": "offline", "error": "unavailable routed TCP response through selected entry"]], "fastest_id": "fast"]
}
func validation(_ request: String = nonce, exit: String = "fast") -> [String: Any] {
 ["ok": true, "request_id": request, "entry_id": "entry", "exit_id": exit, "entry_base": "wg", "entry_mode": "wg", "measured": true]
}
func drained(_ request: String = nonce) -> [String: Any] { ["ok": true, "request_id": request, "drained": true] }

@MainActor @main struct Tests {
 static var checks = 0
 static func check(_ name: String, _ predicate: @autoclosure () throws -> Bool) throws {
  guard try predicate() else { throw NSError(domain: "MacViaEntry", code: 1, userInfo: [NSLocalizedDescriptionKey: name]) }
  checks += 1
 }
 static func reject(_ name: String, _ body: () throws -> Void) throws {
  do { try body() } catch { checks += 1; return }
  throw NSError(domain: "MacViaEntryRejection", code: 1, userInfo: [NSLocalizedDescriptionKey: name])
 }
 static let candidates = ["slow", "offline", "fast"]
 static func decode(_ value: [String: Any]) throws -> MacViaEntryCandidateReceipt {
  try MacViaEntryCandidateReceipt(data: json(value), requestID: nonce, entryID: "entry", candidates: candidates, now: now)
 }
 static func main() throws {
  let accepted = try decode(receipt())
  try check("sorted by measured routed response", accepted.rows.map(\.id) == ["fast", "slow", "offline"])
  try check("fastest is measured in this exact path", accepted.fastestID == "fast" && accepted.eligible("fast", now: now))
  try check("unavailable is not fabricated zero latency", accepted.rows.last?.medianMS == nil && !accepted.eligible("offline", now: now))
  try check("expiry disables all measured choices", !accepted.eligible("fast", now: now.addingTimeInterval(120)))
  let savedJSON = try json(receipt())
  for (key, value) in [("schema", 2 as Any), ("request_id", String(repeating: "b", count: 32)), ("entry_id", "changed"), ("entry_mode", "auto"), ("entry_base", "awg"), ("drained", false), ("drained", 1), ("expires_at", "2026-01-01T00:00:00Z"), ("expires_at", "2099-01-01T00:00:00Z"), ("measured_at", "2099-01-01T00:00:00Z"), ("measured_at", "not-a-date"), ("fastest_id", "slow"), ("fastest_id", "offline"), ("fastest_id", ""), ("fastest_id", "entry")] {
   var changed = receipt(); changed[key] = value
   try reject("invalid receipt \(key) \(value)") { _ = try decode(changed) }
  }
  for missing in ["schema", "request_id", "entry_id", "entry_mode", "entry_base", "drained", "measured_at", "expires_at", "fastest_id"] {
   var changed = receipt(); changed.removeValue(forKey: missing)
   try reject("missing ownership field " + missing) { _ = try decode(changed) }
  }
  for fault in ["duplicate", "foreign", "external", "too-many-samples", "negative-samples", "negative-failed", "combined-count", "missing-row", "error-duplicates-result", "foreign-error", "nan-string"] {
   var changed = receipt(), rows = changed["results"] as! [[String: Any]]
   switch fault {
   case "duplicate": rows[1]["id"] = "slow"
   case "foreign": rows[1]["id"] = "unrequested"
   case "external": rows[1]["node_kind"] = "external"
   case "too-many-samples": rows[1]["samples"] = 6
   case "negative-samples": rows[1]["samples"] = -1
   case "negative-failed": rows[1]["failed"] = -1
   case "combined-count": rows[1]["failed"] = 1
   case "missing-row": rows.removeLast()
   case "error-duplicates-result": changed["errors"] = [["id": "fast", "error": "unavailable"]]
   case "foreign-error": changed["errors"] = [["id": "unrequested", "error": "unavailable"]]
   default: rows[1]["median_ms"] = "NaN"
   }
   changed["results"] = rows
   try reject("invalid measurement " + fault) { _ = try decode(changed) }
  }
  for (samples, failed, median) in [(2, 0, 10.0), (4, 1, 1.0), (5, 0, 0.0), (5, 0, -1.0)] {
   var changed = receipt(), rows = changed["results"] as! [[String: Any]]
   rows[1]["samples"] = samples; rows[1]["failed"] = failed; rows[1]["median_ms"] = median
   changed["results"] = rows; changed["fastest_id"] = "slow"
   let result = try decode(changed)
   try check("failed or incomplete row is never eligible", result.fastestID == "slow" && !result.eligible("fast", now: now) && result.rows.first(where: { $0.id == "fast" })?.medianMS == nil)
  }
  for samples in 3...5 {
   var changed = receipt(), rows = changed["results"] as! [[String: Any]]; rows[1]["samples"] = samples; changed["results"] = rows
   try check("at least three zero-failure samples qualifies", decode(changed).eligible("fast", now: now))
  }
  var allUnavailable = receipt(); allUnavailable["results"] = NSNull(); allUnavailable["errors"] = candidates.map { ["id": $0, "error": "unavailable"] }; allUnavailable["fastest_id"] = ""
  try check("all unavailable has no fastest fallback", decode(allUnavailable).fastestID == nil)
  try reject("bounded receipt") { _ = try MacViaEntryCandidateReceipt(data: Data(repeating: 65, count: 256 * 1024 + 1), requestID: nonce, entryID: "entry", candidates: candidates, now: now) }
  try check("parser did not mutate source bytes", json(receipt()) == savedJSON)

  let session = MacViaEntryCandidateSession()
  let first = try session.begin(entryID: "entry", candidates: candidates, nonce: nonce)
  try reject("parallel test cannot replace active nonce") { _ = try session.begin(entryID: "entry", candidates: candidates) }
  try reject("selection before result forbidden") { _ = try session.beginValidation(exitID: "fast", now: now) }
  try check("captured result accepted only while measuring", session.accept(json(receipt()), for: first, now: now))
  try reject("unavailable row remains a manual-only picker choice") { _ = try session.beginValidation(exitID: "offline", now: now) }
  try reject("unknown row cannot become measured") { _ = try session.beginValidation(exitID: "other", now: now) }
  try reject("expired receipt cannot select") { _ = try session.beginValidation(exitID: "fast", now: now.addingTimeInterval(121)) }
  let verifying = try session.beginValidation(exitID: "fast", now: now)
  try check("selection waits for server validation", session.phase == .validating && verifying == first)
  for (key, value) in [("ok", false as Any), ("request_id", String(repeating: "b", count: 32)), ("entry_id", "changed"), ("exit_id", "slow"), ("entry_base", "awg"), ("entry_mode", "awg2-fast"), ("measured", false), ("measured", 1)] {
   var changed = validation(); changed[key] = value
   try reject("invalid selection acknowledgement " + key) { _ = try session.acceptValidation(json(changed), for: verifying, exitID: "fast", now: now) }
   try check("invalid validation retains ownership", session.phase == .validating)
  }
  try check("exact validation is the only adoption gate", session.acceptValidation(json(validation()), for: verifying, exitID: "fast", now: now))
  try check("duplicate validation cannot adopt twice", !session.acceptValidation(json(validation()), for: verifying, exitID: "fast", now: now))
  try check("Retest captures exact old owner for cancel", session.beginDrain(.retest) == first)
  try reject("Retest waits for cancel acknowledgement") { _ = try session.begin(entryID: "entry", candidates: candidates) }
  try check("late result during cancel ignored", !session.accept(json(receipt()), for: first, now: now))
  try check("cleanup invalidates selectable receipt", session.receipt == nil)
  for (key, value) in [("ok", false as Any), ("request_id", String(repeating: "b", count: 32)), ("drained", false), ("drained", 1)] {
   var changed = drained(); changed[key] = value
   try reject("invalid cleanup acknowledgement " + key) { _ = try session.acceptDrain(json(changed), for: first) }
  }
  session.failedDrain(first)
  try check("failed cleanup reserves ownership", session.phase == .cleanupFailed && session.ticket == first)
  try reject("cleanup failure cannot release modal") { try session.closeIdle() }
  try reject("cleanup failure cannot start another path") { _ = try session.begin(entryID: "entry", candidates: candidates) }
  try check("retry cleanup still uses same nonce", session.beginDrain(.retest) == first)
  try check("exact acknowledgement permits Retest", session.acceptDrain(json(drained()), for: first) == .retest)
  try reject("Retest never reuses a nonce") { _ = try session.begin(entryID: "entry", candidates: candidates, nonce: nonce) }
  let second = try session.begin(entryID: "entry", candidates: candidates)
  try check("new test has a new nonce", second.requestID != first.requestID)
  try check("old callback cannot replace new test", !session.accept(json(receipt()), for: first, now: now))
  try check("cancel-before-start has an exact nonce", session.beginDrain(.stay) == second)
  try check("close upgrades in-flight cleanup without a second request", session.beginDrain(.close) == nil)
  try check("Retest cannot override a pending close", session.beginDrain(.retest) == nil)
  try check("old cleanup cannot release replacement", session.acceptDrain(json(drained()), for: first) == nil)
  try check("current cancel acknowledgement permits close", session.acceptDrain(json(drained(second.requestID)), for: second) == .close)
  try session.closeIdle()
  try check("retired modal cannot restart", session.phase == .closed)
  try reject("closed transaction remains retired") { _ = try session.begin(entryID: "entry", candidates: candidates) }

  for (entry, ids, badNonce) in [("", ["a"], nonce), ("a", ["a"], nonce), ("entry", [], nonce), ("entry", ["a", "a"], nonce), ("entry", [""], nonce), ("entry", (1...65).map(String.init), nonce), ("entry", ["a"], "bad"), ("entry", ["a"], String(repeating: "A", count: 32))] {
   try reject("invalid capture rejected before request") { _ = try MacViaEntryCandidateSession().begin(entryID: entry, candidates: ids, nonce: badNonce) }
  }
  for (base, mode) in [("wg", "wg"), ("awg", "awg2-fast"), ("awg", "awg2-strong")] {
   for requested in ["auto", base] {
    var value = receipt(); value["entry_base"] = base; value["entry_mode"] = mode
    let routed = MacViaEntryCandidateSession()
    let ticket = try routed.begin(entryID: "entry", candidates: candidates, base: requested, nonce: nonce)
    try check("ticket freezes selected entry base", ticket.base == requested)
    try check("exact WG/AWG receipt accepted", routed.accept(json(value), for: ticket, now: now))
    try check("actual raw mode retained", routed.receipt?.entryBase == base && routed.receipt?.entryMode == mode)
    try check("AWG not mislabeled WG", routed.receipt?.entryLabel == (mode == "wg" ? "WireGuard" : mode == "awg2-fast" ? "AmneziaWG Fast" : "AmneziaWG Strong"))
    _ = try routed.beginValidation(exitID: "fast", now: now)
    var echo = validation(); echo["entry_base"] = base; echo["entry_mode"] = mode == "awg2-fast" ? "awg2-strong" : "awg2-fast"
    try reject("selection refuses another valid raw mode") { _ = try routed.acceptValidation(json(echo), for: ticket, exitID: "fast", now: now) }
    echo["entry_mode"] = mode
    try check("selection accepts exact measured raw mode", routed.acceptValidation(json(echo), for: ticket, exitID: "fast", now: now))
    _ = routed.beginDrain(.close); _ = try routed.acceptDrain(json(drained()), for: ticket); try routed.closeIdle()
    try reject("opposite explicit base cannot borrow receipt") {
     _ = try MacViaEntryCandidateReceipt(data: json(value), requestID: nonce, entryID: "entry", candidates: candidates, base: base == "wg" ? "awg" : "wg", now: now)
    }
   }
  }
  for (base, mode) in [("wg", "awg2-fast"), ("awg", "wg"), ("awg", "auto"), ("auto", "wg"), ("AWG", "awg2-fast")] {
   var value = receipt(); value["entry_base"] = base; value["entry_mode"] = mode
   try reject("Auto never authorizes a mismatched base/mode") { _ = try MacViaEntryCandidateReceipt(data: json(value), requestID: nonce, entryID: "entry", candidates: candidates, base: "auto", now: now) }
  }
  try reject("unsupported requested base") { _ = try MacViaEntryCandidateSession().begin(entryID: "entry", candidates: candidates, base: "unknown") }
  let reservation = MacViaEntryCandidateReservation.shared, lease = reservation.acquire()!
  try check("modal holds shared native mutation reservation", reservation.active && reservation.acquire() == nil)
  reservation.release(UUID()); try check("foreign cleanup cannot unlock UI", reservation.active)
  reservation.release(lease); try check("exact retirement releases editing", !reservation.active)
  print("macOS via-entry candidates: PASS (\(checks) shipping Swift receipt/lifecycle checks)")
 }
}
'''


def main():
    swift = shutil.which("swiftc")
    if not swift:
        raise SystemExit("swiftc required")
    policy = MAC / "RouterVPNMacViaEntryPolicy.swift"
    ui = MAC / "RouterVPNMacViaEntryCandidates.swift"
    with tempfile.TemporaryDirectory(prefix="mac-via-entry-") as folder:
        work = Path(folder)
        test = work / "Test.swift"
        test.write_text(SWIFT)
        subprocess.run([swift, "-swift-version", "6", "-module-cache-path", str(work / "module-cache"), str(policy), str(test), "-o", str(work / "test")], check=True, timeout=90)
        subprocess.run([str(work / "test")], check=True, timeout=30)
        spec = importlib.util.spec_from_file_location("mac_candidate_mutation", MAC / "macos-session-mutation-transform.py")
        transform = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(transform)
        product = transform.transform((MAC / "RouterVPNMacProduct.swift").read_text(), "product")
        unified = transform.transform((MAC / "RouterVPNMacUnifiedShell.swift").read_text(), "unified")
        (work / "Product.swift").write_text(product)
        (work / "Unified.swift").write_text(unified)
        subprocess.run([swift, "-frontend", "-parse", str(work / "Product.swift")], check=True, timeout=30)
        subprocess.run([swift, "-frontend", "-parse", str(work / "Unified.swift"), str(ui)], check=True, timeout=30)
    body = ui.read_text()
    for marker in [
        '"/api/multihop/candidates"', '"/api/multihop/candidates/validate"', '"/api/multihop/candidates/cancel"',
        'transaction.begin(entryID:', 'transaction.acceptValidation(', 'transaction.acceptDrain(',
        'guard adopt(id)', 'transaction.failedDrain(captured)', 'NSApp.runModal(for: panel)',
        'while !controller.retired', 'MacViaEntryCandidateReservation.shared.release(lease)',
        'contextCurrent()', 'WireGuard', 'TCP response', 'Use Connect separately.',
        '"samples": 5', '"base": captured.base', 'timeout: 180', 'timeout: 15', 'windowShouldClose',
    ]:
        assert marker in body, marker
    assert body.index('transaction.acceptValidation(') < body.index('guard adopt(id)')
    for forbidden in ['"/api/connect', '"/api/profile/select', '"/api/multihop/connect', '"/api/multihop/live-latency', 'latency_median_ms', 'UserDefaults.standard.set']:
        assert forbidden not in body, forbidden
    assert 'multihopEntryPopup.action = #selector(connectionProfileEntryChanged)' in product
    profile_ui = (MAC / "RouterVPNConnectionProfiles.swift").read_text()
    entry_action = profile_ui[profile_ui.index('    @objc func connectionProfileEntryChanged()'):]
    entry_action = entry_action[:entry_action.index('\n    }')]
    assert 'ensureMutationIdle("changing multihop entry")' in entry_action
    assert entry_action.index('recordVisibleConnectionProfileSelection()') < entry_action.index('unifiedEntryCandidatesChanged()')
    assert 'self.recordVisibleConnectionProfileSelection()' in body
    assert 'MacViaEntryCandidateReservation.shared.active { return true }' in product
    assert 'Retest exits via entry' in unified
    assert 'baseRow.addArrangedSubview(basePopup)' in unified
    assert 'self.multihopBaseChoice() == base' in body
    assert '"base": base' in product
    build = (MAC / "build-native-app.sh").read_text()
    assert '"$VIA_ENTRY_POLICY_SRC" "$VIA_ENTRY_UI_SRC"' in build
    assert 'python3 "$ROOT/deploy/test_macos_via_entry_candidates.py"' in build
    print("macOS candidate modal, automatic user-entry action, exact validation and native-build wiring: PASS")


if __name__ == "__main__":
    main()
