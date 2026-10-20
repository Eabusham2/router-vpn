#!/usr/bin/env python3
"""Execute shared hop result validation and check native shipping integration."""
from pathlib import Path
import json
import re
import shlex
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
            selectors=[]
            for line in source.splitlines():
                if line.lstrip().startswith('#') or './experimental/libbox ' not in line or '-run ' not in line:continue
                words=shlex.split(line)
                if './experimental/libbox' in words and 'test' in words and '-run' in words:
                    self.assertIn('-count=1',words)
                    selectors.append(re.compile(words[words.index('-run')+1]))
            for family in ('Multihop','NativeWireGuard','NativeAmnezia','NativePerformance','MTU'):
                self.assertTrue(any(p.search('TestRouter'+family) for p in selectors),path+' omits '+family)
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
        self.assertIn('request.count == 3',provider)
        self.assertIn('UUID(uuidString: session) != nil',provider)
        engine=(ROOT/'ios/RouterVPN/PacketTunnel/RouterVPNLibboxEngine.swift').read_text()
        self.assertIn('measurementCloseFailure',engine)
        self.assertIn('do { try probe?.close()',engine)
        self.assertIn('session == settingsEpoch',engine)
        self.assertIn('Self.retiredMeasurements.start',engine)
        self.assertIn('probe?.networkChanged()',engine)
        ui=(ROOT/'ios/RouterVPN/App/IOSHopMeasurements.swift').read_text()
        for marker in ('connectedDate == date','self.generation == round','status.request_id == id','hop-measure-cancel','16384','CheckedContinuation<Data, Error>'):
            self.assertIn(marker,ui)
        for marker in ('status.session_id == session', 'result.complete && result.drained',
                       'await cleanup.value', '["multihop-libbox", "external-libbox"]'):
            self.assertIn(marker,ui)
        view=(ROOT/'ios/RouterVPN/App/IOSSpeedLabView.swift').read_text()
        self.assertIn('.disabled(runDisabled || hopProbe.running)',view)
    def test_android_real_service_owns_callbacks_and_metadata(self):
        service=(ROOT/'android/app/src/main/java/com/eabusham/routervpn/LayeredVpnService.java').read_text()
        self.assertLess(service.index('ownedExecution.run(ownedServer)'),service.index('adoptHopMeasurement(Libbox.newRouterHopMeasurement'))
        for marker in ('probe.networkChanged()', 'hopMeasurement.close()', 'synchronized(service.lock)', '"UP".equals(service.state)', 'response.length()>16384',
                       'adoptHopMeasurement(capturedExternal.newHopMeasurement()', 'adoptHopMeasurement(capturedTor.newHopMeasurement()',
                       'static final class HopMeasurementOwner', 'service.hopMeasurement!=probe', 'service.commandServer!=server',
                       'generation!=service.lifecycle.get()', 'network.equals(service.executionNetworkIdentity())', 'probe.drain(request)',
                       'Hop measurement cleanup is still pending; its native owner is retained.'):
            self.assertIn(marker,service)
        worker=(ROOT/'android/app/src/main/java/com/eabusham/routervpn/AndroidNativeHopMeasurement.java').read_text()
        for marker in ('LayeredVpnService.captureHopMeasurement(job.id)', 'AndroidMTUMeasurementGate.owns(job.lease)',
                       'job.owner.drain();joined=true;', 'if(job.releaseLease)AndroidMTUMeasurementGate.release(job.lease)',
                       'id.equals(status.optString("request_id"))', 'status.getBoolean("drained")'):
            self.assertIn(marker,worker)
        self.assertLess(worker.index('job.owner.drain();joined=true;'),worker.index('if(job.releaseLease)AndroidMTUMeasurementGate.release(job.lease)'))
        ui=(ROOT/'android/app/src/main/java/com/eabusham/routervpn/AndroidHopMeasurementDialog.java').read_text()
        for marker in ('setOnDismissListener','measurement.cancel()','measurement.run(null,','Double.isFinite(rate)',
                       '"private-node".equals(kind)', '"public-path".equals(kind)', 'bytes*8.0/seconds/1000000.0-rate'):
            self.assertIn(marker,ui)
        runner=(ROOT/'android/test_android_runtime_contract.py').read_text()
        for test in ('test_android_native_hop_request.py','test_android_external_hop_measurement.py'):
            self.assertIn(test,runner)
    def test_shipping_apple_result_renderer_rejects_fabricated_metrics(self):
        if not shutil.which('swiftc'):self.skipTest('Swift compiler runs on the Apple build host')
        source=(ROOT/'ios/RouterVPN/App/IOSHopMeasurements.swift').read_text().split('// HOP_RESULT_TYPES_BEGIN\n')[1].split('// HOP_RESULT_TYPES_END')[0]
        sample={'node_id':'exit-id','role':'exit','kind':'private-node','label':'Router VPN exit private API','ready':True,'idle':{'samples':6,'min_ms':1,'median_ms':2,'average_ms':2,'p90_ms':3,'max_ms':3,'jitter_ms':1},'download':{'bytes':65536,'seconds':.5,'mbps':1.048576,'loaded_reason':'short transfer'},'upload':{'bytes':65536,'seconds':.5,'mbps':1.048576,'loaded_reason':'short transfer'}}
        text=json.dumps(sample,separators=(',',':'))
        test='''
let raw = #"'''+text+'''"#.data(using: .utf8)!
let decoder=JSONDecoder()
let value=try decoder.decode(IOSHopMeasurementResult.self,from:raw)
precondition(value.summary.contains("Download 1.05 Mbps"))
precondition(value.summary.contains("loaded latency: unavailable"))
var object=try JSONSerialization.jsonObject(with: raw) as! [String:Any]
object["kind"]="public-path";object["label"]="Tor circuit → Cloudflare edge"
let publicBytes=try JSONSerialization.data(withJSONObject:object)
let publicPath=try decoder.decode(IOSHopMeasurementResult.self,from:publicBytes)
precondition(publicPath.summary.contains("HTTPS response") && publicPath.summary.contains("Cloudflare edge") && !publicPath.summary.contains("private API"))
for field in ["kind","label"] {
 var invalid=object;invalid[field]=field=="kind" ? "invented-hop":"bad\\nlabel"
 let bytes=try JSONSerialization.data(withJSONObject:invalid)
 let decoded=try decoder.decode(IOSHopMeasurementResult.self,from:bytes)
 precondition(decoded.summary.contains("unavailable") && !decoded.summary.contains("Mbps"))
}
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
            subprocess.run(['swiftc','-swift-version','6',str(file),'-o',str(exe)],check=True,timeout=120)
            subprocess.run([str(exe)],check=True,timeout=10)
if __name__=='__main__':unittest.main()
