#!/usr/bin/env python3
"""Execute the actual Swift MTU decoder and reject forged/stale measurements."""
from pathlib import Path
import json
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'ios/RouterVPN/App/IOSMTUStatus.swift'
HARNESS = r'''
import Foundation

@main struct Main {
    static func main() throws {
        let path = CommandLine.arguments[1]
        let samples = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: path))) as! [[String: Any]]
        for (index, row) in samples.enumerated() {
            let expected = row["verified"] as! Bool
            let data = try JSONSerialization.data(withJSONObject: row["status"]!)
            let decoded = try JSONDecoder().decode(IOSMTUStatus.self, from: data)
            guard decoded.verified == expected else { fatalError("MTU sample \(index) verification changed") }
            guard decoded.summary.contains("Verified current MTU:") == expected else { fatalError("Unverified measurement was labelled current") }
        }
        print("Swift MTU status: \(samples.count) actual-decoder checks passed")
    }
}
'''

def cases():
    transfer = {'bytes': 262144, 'seconds': .25, 'mbps': 8.388608}
    candidate = {'mtu': 1420, 'working': True, 'packets_sent': 6, 'packets_received': 6,
                 'datagram_bytes': 1392, 'median_rtt_ms': 9.3,
                 'download': transfer, 'upload': transfer}
    original = {'session_id': '413c0c39-6641-4cec-b13c-76c2e0d24139', 'request_id': 'a' * 32,
                'phase': 'complete', 'complete': True, 'running': False, 'measured': True,
                'effective_mtu': 1420, 'original_mtu': 1280, 'source': 'measured-private-system-tun',
                'candidates': [candidate]}
    samples = [{'status': original, 'verified': True}]
    for key, value in [('source', 'cached'), ('source', 'restored-unmeasured'), ('measured', False),
                       ('complete', False), ('running', True), ('effective_mtu', 1280),
                       ('session_id', 'not-a-session'), ('candidates', [])]:
        data = json.loads(json.dumps(original)); data[key] = value
        samples.append({'status': data, 'verified': False})
    for key, value in [('packets_received', 5), ('packets_sent', 5), ('working', False),
                       ('datagram_bytes', 1380), ('median_rtt_ms', -1), ('mtu', 9000),
                       ('upload', None), ('download', None)]:
        data = json.loads(json.dumps(original)); data['candidates'][0][key] = value
        samples.append({'status': data, 'verified': False})
    for key, value in [('bytes', 262143), ('seconds', 0), ('seconds', -1), ('mbps', -1), ('mbps', 999), ('mbps', 0)]:
        for direction in ['download', 'upload']:
            data = json.loads(json.dumps(original)); data['candidates'][0][direction][key] = value
            samples.append({'status': data, 'verified': False})
    data = json.loads(json.dumps(original)); data['candidates'] *= 6
    samples.append({'status': data, 'verified': False})
    data = json.loads(json.dumps(original)); data['candidates'][0]['datagram_bytes'] = 1372
    samples.append({'status': data, 'verified': True})
    return samples


def main():
    swift = shutil.which('swiftc')
    if swift is None:
        raise RuntimeError('Swift is required; MTU decoder validation cannot be skipped')
    with tempfile.TemporaryDirectory(prefix='routervpn-mtu-status-') as directory:
        root = Path(directory)
        (root / 'Main.swift').write_text(HARNESS)
        (root / 'cases.json').write_text(json.dumps(cases(), allow_nan=False))
        subprocess.run([swift, '-swift-version', '6', str(SOURCE), str(root / 'Main.swift'), '-o', str(root / 'verify')], check=True, timeout=90)
        subprocess.run([str(root / 'verify'), str(root / 'cases.json')], check=True, timeout=15)

if __name__ == '__main__':
    main()
