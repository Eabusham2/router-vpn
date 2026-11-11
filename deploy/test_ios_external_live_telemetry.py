#!/usr/bin/env python3
"""Execute the shipping Apple live-response owner against explicit native IPC.

The real TLS worker is covered by internal/hopmeasure. This fixture executes
capture, drain, MTU exclusion, result validation and UI delivery ownership.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile

import test_ios_external_node_benchmark as benchmark

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "ios/RouterVPN/App"

CASES = r'''
  for paired in [false,true] {for tor in [false,true] {for (requested,selected) in (paired ? [("local","local"),("server","server"),("auto","local"),("auto","server")]:[("local","local")]) {
   let(model,native)=try fixture(paired:paired,tor:tor,requested:requested,selected:selected),client=IOSExternalLiveTelemetry()
   let before=try encoded(model.bundle!)
   let value=try await client.measure(model:model)
   check("live response delivers only measured median",value==4 && client.milliseconds==4 && native.starts==1)
   check("live response never writes saved50 or node statistics",IOSPrivateJSONStore.writes==0 && (try! encoded(model.bundle!))==before)
   check("live response retains then releases native and MTU owners",native.releases==1 && !native.held && !IOSMTUMeasurementGate.held && !model.iosSpeedLabOwnership.active)
   check("live response verifies actual execution before and after",native.informationCalls==2)
   model.bundle!.routerProfiles[0].dnsHost="192.0.2.54";client.invalidate(model:model)
   check("changed selected DNS clears displayed response",client.milliseconds==nil)
  }}}
  for mode in ["partial","wrong-endpoint","wrong-metric","zero","unordered","wrong-node","not-ready","private-kind","mixed-benchmark","entry-role","foreign-session","foreign-request","failed-status","invalidated","missing-execution","winner-changed","config-changed","epoch-changed"] {
   let(model,native)=try fixture(paired:true,requested:"auto"),client=IOSExternalLiveTelemetry();native.mode=mode
   var failed=false;do{_ = try await client.measure(model:model)}catch{failed=true}
   check("invalid live result rejected: "+mode,failed && client.milliseconds==nil && IOSPrivateJSONStore.writes==0)
   check("invalid live response still joins its owners: "+mode,!client.running && !native.held && !IOSMTUMeasurementGate.held && !model.iosSpeedLabOwnership.active)
  }
  for drift in ["saved-source","selected-source","network","decision","disconnect"] {
   let(model,native)=try fixture(paired:true),client=IOSExternalLiveTelemetry()
   native.drained=false
   let operation=Task{@MainActor in try await client.measure(model:model)}
   await wait("native request entered"){native.starts==1}
   check("complete but undrained live response cannot publish",client.milliseconds==nil && client.running && native.held && IOSMTUMeasurementGate.held)
   switch drift {
    case "saved-source":var changed=model.bundle!;changed.routerProfiles[0].dnsHost="192.0.2.57";IOSNodeBundleStore.shared.records["external-node"]=try encoded(changed)
    case "selected-source":model.bundle!.routerProfiles[0].dnsHost="192.0.2.58"
    case "network":IOSViaEntryNetwork.shared.current=2
    case "decision":model.iosConnectGeneration=UUID()
    default:model.connected=false
   }
   await wait("stale request cancels native work"){native.cancels>0}
   check("stale request retains MTU until original worker drain",client.running && native.held && IOSMTUMeasurementGate.held)
   native.drained=true
   let result=await operation.result
   if case .success = result {check("stale live result cannot succeed: "+drift,false)}
   check("stale result cannot replace displayed response: "+drift,client.milliseconds==nil && !client.running && !IOSMTUMeasurementGate.held && !model.iosSpeedLabOwnership.active)
   // A disconnected tunnel owns its own final teardown. The app must not
   // recapture another tunnel merely to release the retired session's MTU.
   check("MTU release preserves connection ownership: "+drift,drift=="disconnect" ? native.releases==0 : !native.held)
  }
  do {
   let(model,native)=try fixture(),client=IOSExternalLiveTelemetry();native.drained=false
   let operation=Task{@MainActor in try await client.measure(model:model)}
   await wait("cancel request entered"){native.starts==1}
   client.cancel();await wait("explicit cancel reaches original worker"){native.cancels>0}
   let other=IOSExternalLiveTelemetry();var failed=false;do{_ = try await other.measure(model:model)}catch{failed=true}
   check("another sheet cannot borrow draining original owner",failed && native.starts==1 && client.running && native.held)
   native.drained=true;_ = await operation.result
   check("cancel clears result after original drain",client.milliseconds==nil && !client.running && !native.held && !IOSMTUMeasurementGate.held)
  }
  do {
   let(model,native)=try fixture(),client=IOSExternalLiveTelemetry()
   client.showPerformance(true);await client.refresh(model:model)
   check("background live response does not interfere with Performance",native.starts==0)
   client.showPerformance(false);await client.refresh(model:model);await client.refresh(model:model)
   check("background refresh is throttled",native.starts==1 && client.milliseconds==4)
   model.connected=false;client.invalidate(model:model)
   check("disconnect removes live response",client.milliseconds==nil)
  }
  print("PASS: \(checks) Apple live external response capture/drain checks")
 }
}
'''


def source():
    text = benchmark.source().split(benchmark.TESTS, 1)[0]
    native = benchmark.NATIVE.replace('"samples":50', '"samples":3').replace('distribution["samples"]=49', 'distribution["samples"]=2')
    native = native.replace('case "hop-measure-latency-start":', 'case "hop-measure-response-start":')
    native = native.replace('case "partial":', 'case "mixed-benchmark":result["benchmark"]=benchmark\n    case "partial":')
    native = native.replace('result["benchmark"]=benchmark;', '''result["response"]=["schema":benchmark["schema"]!,"measurement":benchmark["measurement"]!,"endpoint":benchmark["endpoint"]!,"attempts":3,"distribution":benchmark["distribution"]!];''')
    text = text.replace(benchmark.NATIVE, native)
    text += (APP / "IOSExternalLiveTelemetry.swift").read_text().replace("import Combine\n", "").replace("@preconcurrency import NetworkExtension\n", "")
    setup = benchmark.TESTS.split("  for paired in [false,true]", 1)[0]
    return text + setup + CASES


def main():
    swift = shutil.which("swiftc")
    if not swift:
        raise SystemExit("swiftc required for shipping live external telemetry")
    text = source()
    with tempfile.TemporaryDirectory(prefix="routervpn-ios-live-response-") as directory:
        work = Path(directory)
        code, binary = work / "Fixture.swift", work / "fixture"
        command = [swift, "-swift-version", "6", "-strict-concurrency=complete", "-parse-as-library",
                   "-module-cache-path", str(work / "modules"), str(code), "-o", str(binary)]
        code.write_text(text)
        subprocess.run(command, check=True, timeout=180)
        subprocess.run([str(binary)], check=True, timeout=70)
        controls = [
            ("complete native drain", "if result.complete && result.drained { return }", "if result.complete { return }", "complete but undrained live response cannot publish"),
            ("exact live sample count", "attempts == 3 && d.samples == 3", "attempts == 3 && d.samples >= 1", "invalid live result rejected: partial"),
            ("original exit", "result.node_id == captured.nodeID, result.role", "result.role", "invalid live result rejected: wrong-node"),
            ("proved execution", "try IOSExternalNodeStatistics.PathReceipt(binding: final, requested: requested, network: network) == path,", "true,", "invalid live result rejected: winner-changed"),
        ]
        for name, before, after, witness in controls:
            # The saved50 controller is also in the source fixture; only the
            # live controller is mutated when a validation phrase is shared.
            at = text.index("@MainActor final class IOSExternalLiveTelemetry") if name == "original exit" else 0
            prefix, tail = text[:at], text[at:]
            if tail.count(before) != 1:
                raise AssertionError("live control lost exact source boundary: " + name)
            code.write_text(prefix + tail.replace(before, after, 1))
            subprocess.run(command, check=True, timeout=180)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=70)
            if result.returncode == 0 or witness not in result.stderr:
                raise AssertionError(name + " did not reject intended defect: " + result.stderr[-1800:])
            print("PASS live negative control:", name, flush=True)


if __name__ == "__main__":
    main()
