#!/usr/bin/env python3
"""Exercise real outer-runtime startup timing against captured native budgets.

The whole shipping Runtime is compiled unchanged; Android/service/PQ completion
are explicit boundaries. The delayed native UP is 21s, beyond the old 20s host
deadline and within the actual native PQ owner's 30s initial-key budget. No
public network, system VPN, production timer rewriting or physical-device
acceptance is involved. The independent Go owner reproduction also demonstrated
a valid authenticated startup after 20.25s with its production timer unchanged.
"""
from pathlib import Path
import importlib.util
import os
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / 'android/app/src/main/java/com/eabusham/routervpn'
spec = importlib.util.spec_from_file_location('multihop_deadline_sources', ROOT / 'android/test_android_multihop_startup_last.py')
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)

TESTS = r'''
 static final long PQ_BUDGET=ACTUAL_PQ_BUDGET_MS,EXECUTION_BUDGET=ACTUAL_EXECUTION_BUDGET_MS;
 static void deadlineBudgets()throws Exception{
  String[] modes={"wg","awg2-fast","awg2-strong","wg-pq","awg2-pq","shadowsocks","hysteria2","naive-h2","naive-h3","reality-vision","reality-pq-vision","reality-xhttp","max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg","ss-v2ray","split","max"};
  for(String entry:modes)for(String exit:modes)for(String execution:new String[]{"local","server","auto"}){
   check(NativeSingBoxController.nativeMultihopEntry(entry)&&NativeSingBoxController.nativeMultihopEntry(exit),"deadline fixture listed an unsupported private transport");
   int initialKeys=(NativeSingBoxController.nativePQFamily(entry)||AndroidNativeMAXProfile.isMode(entry)?1:0)+(NativeSingBoxController.nativePQFamily(exit)||AndroidNativeMAXProfile.isMode(exit)?1:0);
   long nativeBudget=PQ_BUDGET*initialKeys,budget=AndroidMultihopRuntime.startTimeoutMillis(execution,entry,exit);
   long executionMinimum=execution.equals("local")?7500L:EXECUTION_BUDGET;
   check(budget>nativeBudget+executionMinimum,"host deadline undercuts sequential native work: "+entry+"/"+exit+"/"+execution);
   check(budget<=180000L,"startup deadline lost its bound");
   if(initialKeys==0)check(budget==(execution.equals("local")?20000L:120000L),"ordinary non-PQ startup budget changed");cases++;
  }
  rejected("unknown execution deadline",()->AndroidMultihopRuntime.startTimeoutMillis("invented","wg","wg"));
 }
 static void awaitWithin(Callback c,long seconds)throws Exception{check(c.done.await(seconds,TimeUnit.SECONDS),"bounded native startup did not complete");check(c.completions==1,"startup callback was not one-shot");}
 static void delayedNativeReady()throws Exception{
  try(Fixture f=new Fixture()){
   f.engine.readyDelayMillis=21000L;LayeredVpnService.selected="local";Callback c=new Callback();long start=System.nanoTime();f.runtime.connect(f.entry,f.exit,"wg-pq","local","max-quic-awg",c);awaitWithin(c,35);
   long elapsed=TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-start);
   check(c.ok&&f.engine.starts==1&&f.engine.stops==0&&elapsed>=21000L,"legitimate delayed native PQ startup was cut off by the outer deadline");
   check(AndroidPathProbe.proofs==1&&LayeredVpnService.mtu==1&&AndroidHomeStateStore.current.connected,"delayed startup skipped fresh proof/adoption");
   System.out.println("Actual shipping runtime accepted delayed native UP after "+elapsed+"ms with fresh private proof");cases++;
  }
 }
 static void cancelledAndTerminal()throws Exception{
  for(String terminal:new String[]{"cancel","FAILED","REVOKED"})try(Fixture f=new Fixture()){
   f.engine.readyDelayMillis=100000L;LayeredVpnService.selected="local";Callback c=new Callback();f.runtime.connect(f.entry,f.exit,"max-quic-wg","local","wg-pq",c);
   long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(3);while((f.engine.starts==0||!f.engine.getState().equals("STARTING"))&&System.nanoTime()<end)Thread.yield();check(f.engine.starts==1&&f.engine.getState().equals("STARTING"),"native startup was not reached");long start=System.nanoTime();
   if(terminal.equals("cancel"))f.runtime.disconnect();else f.engine.state=terminal;
   awaitWithin(c,4);check(!c.ok&&f.engine.stops>=1&&AndroidPathProbe.proofs==0&&LayeredVpnService.mtu==0&&!AndroidHomeStateStore.current.connected,"long startup budget suppressed cancellation or terminal failure: "+terminal);
   check(System.nanoTime()-start<TimeUnit.SECONDS.toNanos(3),"cancellation waited for the expanded startup timeout");cases++;
  }
 }
 static void actualDeadlineExpiry()throws Exception{
  try(Fixture f=new Fixture()){
   f.engine.readyDelayMillis=100000L;LayeredVpnService.selected="local";Callback c=new Callback();long start=System.nanoTime();f.runtime.connect(f.entry,f.exit,"shadowsocks","local","wg",c);awaitWithin(c,30);
   long elapsed=TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-start);
   check(!c.ok&&elapsed>=19000L&&elapsed<26000L&&f.engine.stops==1,"ordinary native deadline did not expire and drain");
   check(AndroidPathProbe.proofs==0&&LayeredVpnService.mtu==0&&!AndroidHomeStateStore.current.connected,"timed-out native owner reached proof/Connected");
   System.out.println("Actual shipping runtime stopped unready ordinary graph after "+elapsed+"ms");cases++;
  }
 }
 public static void main(String[] args)throws Exception{
  deadlineBudgets();delayedNativeReady();cancelledAndTerminal();actualDeadlineExpiry();
  System.out.println("Android captured multihop startup deadlines: "+checks+" checks / "+cases+" cases; native phase budget, delayed UP, cancellation, terminal failure and expiry");
 }
}
'''


def main():
    jar = Path(os.environ.get('ANDROID_JSON_JAR', '/usr/share/java/com.android.json.jar'))
    if not jar.is_file():
        raise RuntimeError('Actual Android JSON library required')
    pq_source = (ROOT / 'internal/mobilepq/controller.go').read_text()
    pq_budget = re.search(r'timeout\s*:\s*(\d+)\s*\*\s*time.Second', pq_source)
    execution_source = (ROOT / 'internal/mobilemultihop/runtime.go').read_text()
    execution_budget = re.search(r'context.WithTimeout\(parent,\s*(\d+)\s*\*\s*time.Second\)', execution_source)
    assert pq_budget and execution_budget, 'shared native startup budget changed'
    # Verify the actual ordering that makes these budgets sequential. MAX's
    # Java hostname preflight occurs before submission and is not added here.
    peer = (ROOT / 'internal/mobilepq/peer.go').read_text()
    assert peer.index('if err := p.controller.Start()') < peer.index('err := p.peer.Start(false)'), 'native PQ initial-key ownership moved'
    assert 'return e.owner.Start(false)' in (ROOT / 'mobile/pq/endpoint.go.tmpl').read_text(), 'native PQ endpoint startup changed'
    layered = (JAVA / 'LayeredVpnService.java').read_text()
    launch = layered[layered.index('commandServer.startOrReloadService(config, new OverrideOptions());'):]
    assert launch.index('ownedExecution.run(ownedServer)') < launch.index('executionProved=true;publish("UP"'), 'shared execution/UP sequencing changed'
    assert 'context.startForegroundService(intent)' in (JAVA / 'NativeSingBoxController.java').read_text(), 'Android launch boundary changed'

    controller = (JAVA / 'AndroidMultihopController.java').read_text()
    native = (JAVA / 'NativeSingBoxController.java').read_text()
    source_members = '\n'.join(P.member(controller, marker) for marker in (
        '    static final class Source {', '    private static final class LoadedBundle {',
        '    static Source captureSource(', '    static String validatedServerIdentityPins(',
        '    private static String sourceDigest(', '    private static byte[] readBundleBytes('))
    predicates = '\n'.join(P.member(native, '    static boolean ' + name + '(') for name in
                           ('nativeWireGuardFamily', 'nativePQFamily', 'nativeNaiveFamily', 'nativeMultihopEntry'))
    max_source = (JAVA / 'AndroidNativeMAXProfile.java').read_text()
    max_modes = re.search(r'(?s)    private static final (?:java\.util\.)?Set<String> MODES\s*=.*?;', max_source)
    assert max_modes, 'missing actual MAX transport set'
    max_predicate = max_modes[0] + '\n' + P.member(max_source, '    static boolean isMode(')
    composite = P.member((JAVA / 'AndroidNativeCompositeProfile.java').read_text(), '    static boolean isMode(')
    stubs = P.STUBS.replace('// REAL_SOURCE_MEMBERS', source_members).replace('// NATIVE_PREDICATES', predicates)
    stubs = stubs.replace('// MAX_PREDICATE', max_predicate).replace('// COMPOSITE_PREDICATE', composite)
    before = 'volatile String state="DOWN";int starts,stops,leases;'
    assert stubs.count(before) == 1
    stubs = stubs.replace(before, 'volatile String state="DOWN";volatile int starts;int stops,leases;volatile long readyDelayMillis,readyAt;')
    before = 'state="UP";LayeredVpnService.nativeGeneration++;'
    assert stubs.count(before) == 1
    stubs = stubs.replace(before, 'readyAt=System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(readyDelayMillis);state=readyDelayMillis>0?"STARTING":"UP";LayeredVpnService.nativeGeneration++;')
    before = 'String getState(){return state;}'
    assert stubs.count(before) == 1
    stubs = stubs.replace(before, 'String getState(){if(state.equals("STARTING")&&System.nanoTime()-readyAt>=0)state="UP";return state;}')
    tests = TESTS.replace('ACTUAL_PQ_BUDGET_MS', str(int(pq_budget[1]) * 1000) + 'L')
    tests = tests.replace('ACTUAL_EXECUTION_BUDGET_MS', str(int(execution_budget[1]) * 1000) + 'L')
    harness = P.HARNESS[:P.HARNESS.index(' public static void main(String[] args)')] + tests

    with tempfile.TemporaryDirectory(prefix='routervpn-multihop-deadlines-') as directory:
        root = Path(directory)
        app = root / 'com/eabusham/routervpn'
        app.mkdir(parents=True)
        target = app / 'AndroidMultihopRuntime.java'
        shutil.copyfile(JAVA / target.name, target)
        shutil.copyfile(JAVA / 'AndroidMTUMeasurementGate.java', app / 'AndroidMTUMeasurementGate.java')
        (app / 'HistoricalBoundaries.java').write_text(stubs)
        (app / 'MultihopStartupLastTest.java').write_text(harness)
        context = root / 'android/content/Context.java'
        context.parent.mkdir(parents=True)
        context.write_text('package android.content;public class Context{public Context getApplicationContext(){return this;}}')
        base64 = root / 'android/util/Base64.java'
        base64.parent.mkdir(parents=True)
        base64.write_text('package android.util;public class Base64{public static final int DEFAULT=0,NO_WRAP=2;public static byte[] decode(String s,int f){return java.util.Base64.getMimeDecoder().decode(s);}public static String encodeToString(byte[] b,int f){return java.util.Base64.getEncoder().encodeToString(b);}}')
        compile = ['javac', '--release', '17', '-encoding', 'UTF-8', '-cp', str(jar), '-d', str(root / 'classes'), *map(str, root.rglob('*.java'))]
        run = ['java', '-cp', os.pathsep.join((str(root / 'classes'), str(jar))), 'com.eabusham.routervpn.MultihopStartupLastTest']
        subprocess.run(compile, check=True, timeout=45)
        subprocess.run(run, check=True, timeout=100)
        original = target.read_text()
        controls = (
            ('premature outer deadline', 'startTimeoutMillis(execution,entryMode,prepared.exitMode)', '("local".equals(execution)?START_TIMEOUT_MS:EXECUTION_TIMEOUT_MS)', 'legitimate delayed native PQ startup was cut off by the outer deadline'),
            ('second native dependency', 'new String[]{entryMode,exitMode}', 'new String[]{entryMode}', 'host deadline undercuts sequential native work'),
        )
        for label, before, after, expected in controls:
            assert original.count(before) == 1, (label, 'mutation anchor drift')
            target.write_text(original.replace(before, after))
            subprocess.run(compile, check=True, timeout=45, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            result = subprocess.run(run, capture_output=True, text=True, timeout=100)
            target.write_text(original)
            assert result.returncode and 'AssertionError' in result.stderr and expected in result.stdout + result.stderr, (label, 'did not reach intended runtime assertion', result.stdout, result.stderr)
            print('Android startup-deadline mutation rejected:', label)
        print('Android actual multihop startup timing: delayed-UP regression and both premature-budget controls passed')


if __name__ == '__main__':
    main()
