#!/usr/bin/env python3
"""Execute the shipping Apple ordered final picker and selection callback.

This Swift-only fixture compiles the actual profile models, draft and visible
choice logic. SwiftUI rendering, native graph admission and persistence are
outside this focused boundary and remain covered by their existing gates.
"""
from pathlib import Path
import argparse
import contextlib
import hashlib
import json
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'


def block(source, anchor):
    start = source.index(anchor)
    opening = source.index('{', start)
    depth = 1
    for end in range(opening + 1, len(source)):
        depth += (source[end] == '{') - (source[end] == '}')
        if depth == 0:
            return source[start:end + 1], source[opening + 1:end]
    raise AssertionError('Unclosed shipping block: ' + anchor)


TESTS = r'''
@MainActor @main struct Tests {
 static var checks = 0
 static func check(_ label: String, _ value: @autoclosure () -> Bool) throws {
  guard value() else { throw IOSMultihopNodeSelection.issue("FAIL " + label) }; checks += 1
 }
 static func reject(_ label: String, _ body: () throws -> Void) throws {
  do { try body() } catch { checks += 1; return }
  throw IOSMultihopNodeSelection.issue("ACCEPTED " + label)
 }
 static func profile(_ layer: String? = nil) -> RouterProfile {
  var result = RouterProfile(id: "final", name: "Original final", endpoint: "198.51.100.9",
   routerAPI: "http://10.81.0.1:8787", apiToken: "original-private-token",
   adGuardIPv4: "10.81.0.53", adGuardIPv6: "fd00::53", socksHost: "127.0.0.1",
   socksPort: 1080, socksUsername: "original-user", socksPassword: "original-password")
  result.startLayer = layer; result.dnsMode = "custom"; result.dnsProtocol = "tcp"
  result.dnsHost = "10.81.0.54"; result.dnsPort = 5353
  result.mtuPolicy = "manual"; result.manualMTU = 1380
  result.killSwitch = true; result.killSwitchPolicy = "always"
  return result
 }
 static func nodes(_ prefix: String, _ middle: String? = nil) -> [IOSMultihopNodeSelection] {
  var result = [IOSMultihopNodeSelection(id: "entry", mode: prefix)]
  if let middle { result.append(.init(id: "middle", mode: middle)) }
  result.append(.init(id: "final", mode: "shadowsocks")); return result
 }
 static func main() {
  do { try run(); print("Apple ordered final chooser: \(checks) checks PASS; shipping Swift models/callback, SwiftUI rendering excluded") }
  catch { FileHandle.standardError.write(Data((error.localizedDescription + "\n").utf8)); exit(1) }
 }
 static func run() throws {
  for prefix in IOSMultihopNodeSelection.nativePrefixModes {
   for layer in [nil, "", "off"] as [String?] {
    let original = profile(layer), path = nodes(prefix)
    var view = ChoiceSurface(draft: IOSNodeChainDraft(saved: path, finalID: "final"), available: [original])
    try check("paired Off final picker", view.choices == ["shadowsocks", "hysteria2"] && view.unavailableChoice == nil)
    try view.choose("hysteria2")
    try check("paired final callback preserves original prefix", view.draft.nodes == [path[0], .init(id: "final", mode: "hysteria2")])
    try view.choose("shadowsocks")
    try check("explicit final choice restores exact path", view.draft.nodes == path && view.available == [original])
    for foreign in ["Hysteria2", "hysteria2 ", "wg", "http-connect", "https-connect", "socks5", ""] {
     try reject("unsupported exact final callback") { try view.choose(foreign) }
     try check("rejected final preserves complete draft and source", view.draft.nodes == path && view.available == [original])
    }
   }
   for middle in ["shadowsocks", "socks5", "http-connect", "https-connect"] {
    let original = profile("off"), path = nodes(prefix, middle)
    var view = ChoiceSurface(draft: IOSNodeChainDraft(saved: path, finalID: "final"), available: [original])
    try check("imported final picker exposes unsupported transport " + middle, view.choices == ["shadowsocks"])
    try reject("imported final callback") { try view.choose("hysteria2") }
    try view.choose("shadowsocks")
    try check("imported final retains exact middle mode and private policies", view.draft.nodes == path && view.available == [original])
   }
   for layer in ["aes-256-gcm", "aes-256-gcm+xor-whitening", "OFF", "unknown"] {
    let original = profile(layer), path = nodes(prefix)
    var view = ChoiceSurface(draft: IOSNodeChainDraft(saved: path, finalID: "final"), available: [original])
    try check("layered final picker", view.choices == ["shadowsocks"])
    try reject("layered final callback") { try view.choose("hysteria2") }
    try check("layered refusal retains original DNS MTU credentials and draft", view.available == [original] && view.draft.nodes == path)
   }
  }
  let path = nodes("wg")
  for fault in ["missing", "changed-id", "external-kind", "foreign-external"] {
   var original = profile("off")
   if fault == "changed-id" { original.id = "replacement" }
   if fault == "external-kind" { original.nodeKind = "external" }
   if fault == "foreign-external" {
    original.external = try JSONDecoder().decode(ExternalNodeConfig.self,
     from: Data(#"{"protocol":"http-connect","expected_public_ip":"203.0.113.8","http_connect":{"host":"198.51.100.8","port":8080}}"#.utf8))
   }
   var view = ChoiceSurface(draft: IOSNodeChainDraft(saved: path, finalID: "final"), available: fault == "missing" ? [] : [original])
   try check("unavailable original final picker " + fault, view.choices.isEmpty)
   // Exercise the helper's independent identity check, even if a caller hands
   // it a profile outside the captured visible catalog.
   if fault != "missing" { try check("direct final provenance " + fault, IOSNodeChainEditorVisible.finalModes(original, nodes: path).isEmpty) }
   try reject("unavailable original final callback " + fault) { try view.choose("shadowsocks") }
   try check("unavailable original final retains draft", view.draft.nodes == path)
  }
  var stale = ChoiceSurface(draft: IOSNodeChainDraft(saved: path, finalID: "final"), available: [profile("off")])
  try check("original callback offered Hysteria2", stale.choices.contains("hysteria2"))
  stale.available = [profile("aes-256-gcm")]
  try reject("source changed before final callback") { try stale.choose("hysteria2") }
  stale.available = []
  try reject("source removed before final callback") { try stale.choose("shadowsocks") }
  try check("stale callback never substitutes final", stale.draft.nodes == path)
  var invalid = path; invalid[1].mode = "hysteria2"
  var retained = ChoiceSurface(draft: IOSNodeChainDraft(saved: invalid, finalID: "final"), available: [profile("aes-256-gcm")])
  try check("unavailable saved mode remains explicit", retained.choices == ["shadowsocks"] && retained.draft.nodes == invalid)
  try check("unavailable saved row remains disabled", retained.unavailableChoice?.mode == "hysteria2" && retained.unavailableChoice?.disabled == true)
  try reject("unavailable saved mode cannot become eligible") { try retained.choose("hysteria2") }
  try check("unavailable saved row never rewrites source", retained.draft.nodes == invalid && retained.available == [profile("aes-256-gcm")])
 }
}
'''


def source(editor, view):
    draft, _ = block(editor, 'struct IOSNodeChainDraft')
    visible, _ = block(editor, 'enum IOSNodeChainEditorVisible')
    _, choices = block(view, 'private var finalModes: [String]')
    section = view[view.index('Picker("Final transport"'):view.index('Picker("Node \\(position + 1)"')]
    _, callback = block(section, 'set: { mode in change ')
    # The outer setter contains the real change closure; execute its body with
    # throwing semantics so a refused UI action cannot be mistaken for success.
    _, callback = block(callback, 'mode in change ')
    match = re.search(r'ForEach\(([^\n]+), id: \\\.self\)', section)
    assert match, 'Shipping final picker expression changed'
    unavailable, unavailable_body = block(section, 'if !finalModes.contains(node.mode)')
    assert 'Text("Unavailable: \\(IOSMultihopNodeSelection.transportName(node.mode))")' in unavailable_body
    disabled = re.search(r'\.tag\(node.mode\)\.disabled\(([^)]+)\)', unavailable_body)
    assert disabled, 'Shipping unavailable final tag or disabled expression changed'
    unavailable_condition = unavailable[:unavailable.index('{')].strip()[3:]
    return 'import Foundation\n' + draft + '\n' + visible + '''
struct ChoiceSurface {
 var draft: IOSNodeChainDraft
 var available: [RouterProfile]
 var finalModes: [String] {''' + choices + '''}
 var choices: [String] {''' + match.group(1) + '''}
 var unavailableChoice: (mode: String, disabled: Bool)? {
  let node = draft.nodes.last!
  if ''' + unavailable_condition + ''' { return (node.mode, ''' + disabled.group(1) + ''') }
  return nil
 }
 mutating func choose(_ mode: String) throws {
  let node = draft.nodes.last!
''' + callback + '''
 }
}
''' + TESTS


def main(output=None):
    paths = [APP / 'Models.swift', APP / 'IOSNodeChainEditor.swift', APP / 'IOSNodeChainEditorView.swift']
    before = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    editor, view = paths[1].read_text(), paths[2].read_text()
    edits = [
        ('unfiltered-picker', editor, view.replace('ForEach(finalModes,', 'ForEach(IOSMultihopNodeSelection.nativeFinalModes,', 1), 'FAIL imported final picker exposes unsupported transport'),
        ('layer-policy', editor.replace('[nil, "", "off"].contains(profile.startLayer) &&', 'true &&', 1), view, 'FAIL layered final picker'),
        ('imported-prefix', editor.replace('nodes.dropLast().allSatisfy({ IOSMultihopNodeSelection.supportsNativePrefix($0.mode) }) {', 'true {', 1), view, 'FAIL imported final picker exposes unsupported transport'),
        ('original-final', editor.replace('nodes.last?.id == profile.id else', 'true else', 1), view, 'FAIL direct final provenance changed-id'),
        ('callback-policy', editor, view.replace('                                    try IOSNodeChainEditorVisible.requireFinalMode(mode,\n                                        profile: available.first(where: { $0.id == node.id }), nodes: draft.nodes)\n', '', 1), 'ACCEPTED layered final callback'),
        ('unavailable-enabled', editor, view.replace('.tag(node.mode).disabled(true)', '.tag(node.mode).disabled(false)', 1), 'FAIL unavailable saved row remains disabled'),
    ]
    for name, changed_editor, changed_view, _ in edits:
        assert (changed_editor, changed_view) != (editor, view), 'Unchanged control: ' + name
    manager = contextlib.nullcontext(str(output)) if output else tempfile.TemporaryDirectory(prefix='ios-final-choices-')
    with manager as folder:
        work = Path(folder); work.mkdir(parents=True, exist_ok=True)
        receipt = {'source': before, 'phases': []}
        for name, changed_editor, changed_view, witness in [('shipping', editor, view, None)] + edits:
            code, binary = work / (name + '.swift'), work / name
            code.write_text(source(changed_editor, changed_view))
            args = ['swiftc', '-j', '1', '-swift-version', '6', '-module-cache-path', str(work / 'modules'), str(paths[0]), str(code), '-o', str(binary)]
            compiled = subprocess.run(args, capture_output=True, text=True, timeout=90)
            (work / (name + '-compile.log')).write_text(compiled.stdout + compiled.stderr)
            if compiled.returncode:
                raise RuntimeError('Swift compilation failed: ' + name + '\n' + compiled.stderr)
            ran = subprocess.run([str(binary)], capture_output=True, text=True, timeout=15)
            log = ran.stdout + ran.stderr; (work / (name + '.log')).write_text(log)
            valid = ran.returncode == 0 if witness is None else ran.returncode != 0 and witness in log
            assert valid, 'Unexpected final chooser result: ' + name + '\n' + log
            assert not any(x in log for x in ('Fatal error:', 'Signal ', 'Stack dump:')), log
            receipt['phases'].append({'name': name, 'compile': args, 'compile_exit': compiled.returncode,
                'run_exit': ran.returncode, 'witness': witness, 'joined': True,
                'image_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                'log_sha256': hashlib.sha256(log.encode()).hexdigest()})
            print(log.strip() if witness is None else 'Apple final chooser causal control ' + name + ': rejected', flush=True)
        receipt['source_unchanged'] = all(hashlib.sha256(Path(p).read_bytes()).hexdigest() == h for p, h in before.items())
        assert receipt['source_unchanged']
        receipt['status'] = 'passed'
        (work / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--output', type=Path)
    main(parser.parse_args().output)
