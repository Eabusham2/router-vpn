#!/usr/bin/env python3
"""Execute shared hop result validation and check native shipping integration."""
from pathlib import Path
import json
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
class Tests(unittest.TestCase):
    def test_both_platforms_build_the_same_tested_service(self):
        copier=(ROOT/'deploy/prepare-mobile-multihop.py').read_text()
        for marker in ('hopmeasure','routervpn_hop_measurement.go.tmpl','routervpn_hop_measurement.go'):
            self.assertIn(marker,copier)
        for path in ('ios/RouterVPN/prepare-libbox.sh','android/build-sing-box-libbox.sh'):
            source=(ROOT/path).read_text()
            self.assertIn('test ./experimental/libbox/routervpn/...',source)
            self.assertIn('prepare-mobile-multihop.py',source)
            self.assertIn("-run 'TestRouter(Multihop|NativeWireGuard|NativeAmnezia)' -count=1",source)
            self.assertNotIn('-run TestRouterMultihop -count=1',source)

        bridge=(ROOT/'mobile/routervpn_hop_measurement.go.tmpl').read_text()
        for marker in ('e.core.Selected()', 'outbound.DialContext(ctx', 'service.Invalidate()', 'hopmeasure.New(engine'):
            self.assertIn(marker,bridge)
        self.assertNotIn('net.Dial(',bridge)
        self.assertNotIn('http.DefaultClient',bridge)
    def test_ios_real_provider_gate_and_saved_graph(self):
        provider=(ROOT/'ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift').read_text()
        start=provider.index('private func startMultihop')
        gate=provider.index('enableHopMeasurement(metadata: hopMetadata)',start)
        self.assertLess(provider.index('if let exitError',start),gate)
        self.assertLess(provider.index('guard self.currentPathProofGuard() === comparisonGuard',start),gate)
        self.assertIn('messageData.count <= 256',provider)
        self.assertIn('request.count == 2',provider)
        engine=(ROOT/'ios/RouterVPN/PacketTunnel/RouterVPNLibboxEngine.swift').read_text()
        self.assertIn('try? probe?.close()',engine)
        self.assertIn('probe?.networkChanged()',engine)
        ui=(ROOT/'ios/RouterVPN/App/IOSHopMeasurements.swift').read_text()
        for marker in ('connectedDate == date','self.generation == round','status.request_id == id','hop-measure-cancel','16384','CheckedContinuation<Data, Error>'):
            self.assertIn(marker,ui)
        view=(ROOT/'ios/RouterVPN/App/IOSSpeedLabView.swift').read_text()
        self.assertIn('.disabled(runDisabled || hopProbe.running)',view)
    def test_android_real_service_owns_callbacks_and_metadata(self):
        service=(ROOT/'android/app/src/main/java/com/eabusham/routervpn/LayeredVpnService.java').read_text()
        self.assertLess(service.index('ownedExecution.run(ownedServer)'),service.index('hopMeasurement=Libbox.newRouterHopMeasurement'))
        for marker in ('probe.networkChanged()', 'hopMeasurement.close()', 'synchronized(service.lock)', '"UP".equals(service.state)', 'response.length()>16384'):
            self.assertIn(marker,service)
        ui=(ROOT/'android/app/src/main/java/com/eabusham/routervpn/AndroidHopMeasurementDialog.java').read_text()
        for marker in ('setOnDismissListener','handler.removeCallbacks(poll)','id.equals(status.optString("request_id"))','Double.isFinite(rate)'):
            self.assertIn(marker,ui)
    def test_shipping_apple_result_renderer_rejects_fabricated_metrics(self):
        if not shutil.which('swiftc'):self.skipTest('Swift compiler runs on the Apple build host')
        source=(ROOT/'ios/RouterVPN/App/IOSHopMeasurements.swift').read_text().split('// HOP_RESULT_TYPES_BEGIN\n')[1].split('// HOP_RESULT_TYPES_END')[0]
        sample={'node_id':'exit-id','role':'exit','ready':True,'idle':{'samples':6,'min_ms':1,'median_ms':2,'average_ms':2,'p90_ms':3,'max_ms':3,'jitter_ms':1},'download':{'bytes':65536,'seconds':.5,'mbps':1.048576,'loaded_reason':'short transfer'},'upload':{'bytes':65536,'seconds':.5,'mbps':1.048576,'loaded_reason':'short transfer'}}
        text=json.dumps(sample,separators=(',',':'))
        test='''
let raw = #"'''+text+'''"#.data(using: .utf8)!
let decoder=JSONDecoder()
let value=try decoder.decode(IOSHopMeasurementResult.self,from:raw)
precondition(value.summary.contains("Download 1.05 Mbps"))
precondition(value.summary.contains("loaded latency: unavailable"))
var object=try JSONSerialization.jsonObject(with: raw) as! [String:Any]
for invalid in [0.0, 999.0, -1.0] {
    var d=object["download"] as! [String:Any];d["mbps"]=invalid;object["download"]=d
    let bytes=try JSONSerialization.data(withJSONObject:object)
    precondition(try decoder.decode(IOSHopMeasurementResult.self,from:bytes).summary.contains("unavailable"))
}
object["ready"]=false;object["download"]=NSNull();object["upload"]=NSNull();object["failure"]="wrong-node"
let bytes=try JSONSerialization.data(withJSONObject:object)
let failed=try decoder.decode(IOSHopMeasurementResult.self,from:bytes)
precondition(failed.summary.contains("wrong-node") && !failed.summary.contains("Mbps"))
print("Shipping hop renderer: real rates, missing samples and rejected results PASS")
'''
        # precondition's autoclosure cannot throw; evaluate decoding first.
        test=test.replace('precondition(try decoder.decode(IOSHopMeasurementResult.self,from:bytes).summary.contains("unavailable"))','let invalidResult=try decoder.decode(IOSHopMeasurementResult.self,from:bytes)\n    precondition(invalidResult.summary.contains("unavailable"))')
        with tempfile.TemporaryDirectory() as tmp:
            file=Path(tmp)/'main.swift';exe=Path(tmp)/'tests'
            file.write_text('import Foundation\n'+source+test)
            subprocess.run(['swiftc','-swift-version','6',str(file),'-o',str(exe)],check=True,timeout=60)
            subprocess.run([str(exe)],check=True,timeout=10)
if __name__=='__main__':unittest.main()
