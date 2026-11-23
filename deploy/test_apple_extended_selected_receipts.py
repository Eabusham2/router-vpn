#!/usr/bin/env python3
"""Replay privately exported native selected-path receipts through shipping Apple parsers."""
import argparse
import json
from pathlib import Path
import struct
import subprocess
import tempfile

import test_ios_node_chain_execution_capture as compiler
import test_ios_ordered_latency as components

ROOT = compiler.ROOT
APP = compiler.APP

SWIFT = r'''
@main struct SelectedReceiptReplay {
    static func check(_ value: Bool) throws { if !value { throw CancellationError() } }
    static func rejects(_ operation: () throws -> Void) throws {
        do { try operation() } catch { return }
        throw NSError(domain: "Accepted mismatched selected receipt", code: 1)
    }
    @MainActor static func main() async throws {
        let input = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
        let cases = try JSONSerialization.jsonObject(with: input) as! [[String: Any]]
        for item in cases {
            let directory = URL(fileURLWithPath: item["directory"] as! String)
            func read(_ name: String) throws -> String {
                try String(contentsOf: directory.appendingPathComponent(name), encoding: .utf8).trimmingCharacters(in: .newlines)
            }
            let identity = try IOSSessionIdentity(connectedAt: Date(), engine: "multihop-libbox", rawProfile: "shadowsocks",
                bundleData: Data([1]), entryBundleData: nil, nodeChainExecutionSource: Data((item["launch"] as! String).utf8))
            guard let original = identity.selectedMeasurementSource else { throw CancellationError() }
            let ids = original.ids, count = ids.count
            let kinds = ids.indices.map { IOSOrderedLatencyExtendedLocal.kind($0, count) }
            let ext = try IOSOrderedLatencyExtendedLocal(source: original.source, config: original.config, ids: ids,
                kinds: kinds, provedCount: item["count"] as! Int)
            if item["sourceOnly"] as? Bool == true {
                try check(count == 96 && identity.hopMeasurementRows == count)
                print("Apple original source capacity: 96 native-compiled original members retained in exact order for " + original.requested)
                continue
            }
            let raw = try read("selected.json")
            let binding = IOSOrderedLatencyExecution.Binding(preparation_source_sha256: original.source,
                preparation_config_sha256: original.config, requested_execution: original.requested, capture: raw)
            let execution = try IOSOrderedLatencyExecution(binding, extended: ext)
            try check(execution.ids == ids && execution.kinds == kinds)
            try rejects { _ = try IOSOrderedLatencyExecution(binding) }
            if item["bulk"] as? Bool == true {
                let native = try JSONSerialization.jsonObject(with: Data(try read("throughput.json").utf8)) as! [String: Any]
                var reply = native
                reply["session_id"] = UUID().uuidString
                func status(_ value: [String: Any]) throws -> IOSHopMeasurementStatus {
                    try JSONDecoder().decode(IOSHopMeasurementStatus.self, from: JSONSerialization.data(withJSONObject: value))
                }
                try status(reply).validateSelectedThroughput(ids: ids, winner: execution.selected)
                var foreign = ids
                foreign.swapAt(1, 2)
                try rejects { try status(reply).validateSelectedThroughput(ids: foreign, winner: execution.selected) }
                try rejects { try status(reply).validateSelectedThroughput(ids: ids, winner: execution.selected == "local" ? "server" : "local") }
                var rows = reply["results"] as! [[String: Any]]
                var down = rows[1]["download"] as! [String: Any]
                down["bytes"] = 65536; rows[1]["download"] = down; reply["results"] = rows
                try rejects { try status(reply).validateSelectedThroughput(ids: ids, winner: execution.selected) }
                print("Apple selected throughput: \(count) exact native 8 MiB bidirectional rows and foreign source, winner and size refusals")
                continue
            }
            let profile = String(repeating: "a", count: 64)
            IOSPrivateJSONStore.files = [:]
            for position in ids.indices {
                let saved = try read("saved-\(position).json"), status = try read("status-\(position).json")
                let object = try JSONSerialization.jsonObject(with: Data(saved.utf8)) as! [String: Any]
                let request = object["request_id"] as! String
                let transaction = IOSOrderedLatencyTransaction(request: request, source: original.source,
                    config: original.config, node: ids[position], position: position, requested: original.requested,
                    ids: ids, kinds: kinds, extended: ext, validateExecution: {
                        try check($0.binding.capture == raw && $0.originalSource == execution.originalSource)
                    }, send: { operation in
                        switch operation {
                        case "ordered-latency-open": return ["opened": true, "closed": false, "execution_capture": raw]
                        case "ordered-latency-start": return ["status": status, "saved": saved]
                        case "ordered-latency-close": return ["closed": true, "execution_capture": raw]
                        default: throw CancellationError()
                        }
                    })
                let record = try await transaction.run(current: {}, update: { _ in })
                try IOSOrderedLatencyHistory.save(record, profile: profile, current: {})
            }
            let history = try IOSOrderedLatencyHistory.selected(profile: profile, source: original.source, config: original.config,
                requested: original.requested, ids: ids, kinds: kinds, extended: ext)
            let ordered = history.sorted { $0.position < $1.position }
            try check(ordered.map { $0.node } == ids && ordered.allSatisfy { $0.detail.contains("50 successful responses, 0 failed") })
            var foreign = ids
            foreign.swapAt(1, 2)
            try rejects { _ = try IOSOrderedLatencyHistory.selected(profile: profile, source: original.source, config: original.config,
                requested: original.requested, ids: foreign, kinds: kinds, extended: ext) }
            print("Apple selected latency: \(count) original nodes, \(50 * count) measured responses, transaction, save, reopen and copied order refusal")
        }
    }
}
'''


def query(executable, **request):
    raw = json.dumps(request).encode()
    result = subprocess.run([executable], input=struct.pack('>I', len(raw)) + raw,
                            capture_output=True, check=True, timeout=30).stdout
    if len(result) < 4 or struct.unpack('>I', result[:4])[0] != len(result) - 4:
        raise ValueError('Incomplete private compiler response')
    reply = json.loads(result[4:])
    if reply['error']:
        raise ValueError('The original native compiler refused the supplied fixture')
    return reply['value']


def run(directories, capacity_original=None):
    with tempfile.TemporaryDirectory(prefix='apple-selected-native-') as tmp, tempfile.TemporaryDirectory(dir=ROOT, prefix='.ios-extended-selected-go-') as gd:
        work = Path(tmp)
        go = Path(gd) / 'main.go'
        go.write_text(compiler.GO)
        executable = work / 'original-compiler'
        subprocess.run(['go', 'build', '-p', '1', '-o', str(executable), str(go)], cwd=ROOT, check=True, timeout=180)
        cases = []
        for directory in directories:
            directory = directory.resolve(strict=True)
            local = (directory/'local-launch.json').read_text().rstrip('\n')
            selected = (directory/'selected.json').read_text().rstrip('\n')
            preparation = (directory/'preparation.json').read_text().rstrip('\n')
            mode = json.loads(preparation)['execution']
            compiled = json.loads(query(executable, Op='multiple-execution-new', Source=local, Mode=mode))
            count = int(compiled['extended_count'])
            if count < 9 or compiled['source'] != preparation:
                raise ValueError('Reopened preparation differs from the recorded original')
            query(executable, Op='multiple-execution-latency', Source=local, Policy=selected)
            bulk = (directory/'throughput.json').is_file()
            if not bulk and not all((directory/f'{kind}-{position}.json').is_file()
                                    for position in range(count) for kind in ('status', 'saved')):
                raise ValueError('The native run has not completed its original receipt inventory')
            cases.append(dict(directory=str(directory), launch=compiled['launch'], count=count, bulk=bulk))
        if capacity_original is not None:
            directory = capacity_original.resolve(strict=True)
            local = (directory/'launch.json').read_text().rstrip('\n')
            for mode in ('server', 'auto'):
                compiled = json.loads(query(executable, Op='multiple-execution-new', Source=local, Mode=mode))
                if int(compiled['extended_count']) != 96 or compiled['source'] != (directory/f'{mode}-preparation.json').read_text().rstrip('\n'):
                    raise ValueError('The 96-member original differs from its complete native preparation')
                cases.append(dict(directory=str(directory), launch=compiled['launch'], count=96, sourceOnly=True))
        manifest = work/'private-fixtures.json'
        manifest.write_text(json.dumps(cases))
        manifest.chmod(0o600)
        tx = (APP/'IOSOrderedLatency.swift').read_text().split('@MainActor final class IOSOrderedLatencyTransaction', 1)[1]
        tx = '@MainActor final class IOSOrderedLatencyTransaction' + tx.split('@MainActor final class IOSOrderedLatency:', 1)[0]
        hops = (APP/'IOSHopMeasurements.swift').read_text().split('// HOP_RESULT_TYPES_BEGIN', 1)[1].split('// HOP_RESULT_TYPES_END', 1)[0]
        harness = work/'Tests.swift'
        harness.write_text(components.BOUNDARY.split('final class LibboxRouterOrderedLatency:', 1)[0]
                           + (APP/'IOSSessionIdentity.swift').read_text() + (APP/'IOSOrderedLatencyHistory.swift').read_text()
                           + tx + hops + SWIFT)
        binary = work/'swift-replay'
        subprocess.run(['swiftc', '-j', '1', '-swift-version', '6', '-parse-as-library', '-module-cache-path',
                        str(work/'modules'), str(harness), '-o', str(binary)], check=True, timeout=180)
        subprocess.run([binary, manifest], check=True, timeout=180)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path, nargs='+')
    parser.add_argument('--capacity-original', type=Path, help='96-member privately compiled source, without traffic observations')
    args = parser.parse_args()
    run(args.directory, args.capacity_original)
