#!/usr/bin/env python3
"""Exercise shipping OpenVPN execution host/Last/restore with native doubles.

The sealed source family and original construction owner are explicit here.
Actual shared compilation, native provider traffic and Android OS acceptance are
separate gates; these controlled native handles do not prove those boundaries.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import test_android_node_chain_execution_runtime as HOST
import test_android_node_chain_execution_restore as RESTORE


def once(value, before, after):
    if value.count(before) != 1:
        raise AssertionError('OpenVPN host boundary changed: ' + before)
    return value.replace(before, after)


def sources():
    result = RESTORE.sources()
    app, native = HOST.APP, HOST.NATIVE
    result[app + 'AndroidNodeStore.java'] = once(result[app + 'AndroidNodeStore.java'],
        'selected.add(i==count-1?finalMode:prefixMode);',
        'selected.add(i==count-1?finalMode:i==count-2?"openvpn":prefixMode);')
    capture = result[app + 'AndroidNodeChainCapture.java']
    capture = once(capture, 'final boolean openVPN=false;', 'final boolean openVPN=true;')
    capture = once(capture, 'source.imported&&i==source.members.size()-2', 'i==source.members.size()-2')
    capture = once(capture, '.put("schema",source.imported?2:1)', '.put("schema",5)')
    result[app + 'AndroidNodeChainCapture.java'] = capture
    result[native + 'CommandServer.java'] = once(result[native + 'CommandServer.java'],
        'public void start(){started++;}',
        'public boolean typed,bound;public void start(){if(typed&&!bound)throw new IllegalStateException("typed OpenVPN execution started before binding");started++;}')
    value = result[native + 'RouterNodeChainExecution.java']
    value = once(value, 'localSHA=original.getString("source_sha256");',
        'localSHA=original.getString("source_sha256");int count=original.getJSONArray("nodes").length();if(!"routervpn-node-chain-launch-input".equals(original.getString("kind"))||original.getInt("schema")!=5||count<3||count>8||original.getJSONArray("identity_sources").length()!=count)throw new IllegalStateException("OpenVPN lost sealed original Local authority");for(int i=0;i<count;i++)if(original.getJSONArray("identity_sources").getString(i).isEmpty()!=(i==count-2))throw new IllegalStateException("OpenVPN lost original private identity position");')
    value = once(value, 'source=new JSONObject().put("schema",1).put("execution",requested).put("local_source",local.toString()).toString();',
        'source=new JSONObject().put("schema",5).put("execution",requested).put("local_source",local.toString()).put("openvpn_local_launch",input).toString();')
    value = once(value, '"routervpn-node-chain-execution-preparation-input"', '"routervpn-node-chain-openvpn-execution-preparation-input"')
    value = once(value, 'public void bindNative(CommandServer captured){binds++;',
        'public CommandServer factory;public int factories;public CommandServer openVPNCommandServer(CommandServerHandler h,PlatformInterface p)throws Exception{if(factory!=null||closed||cancelled)throw new IllegalStateException("typed OpenVPN factory retired");factories++;factory=new CommandServer(h,p);factory.typed=true;return factory;}\n public void bindNative(CommandServer captured){binds++;if(captured!=factory||captured==null)throw new IllegalStateException("foreign typed OpenVPN execution factory");captured.bound=true;')
    result[native + 'RouterNodeChainExecution.java'] = value
    lib = result[native + 'Libbox.java']
    for before, after in (
        ('throw new IllegalStateException("No typed OpenVPN preparation in ordinary fixture");', 'RouterNodeChainExecution.ordinaryPreparations++;return new RouterNodeChainExecution(source,requested);'),
        ('throw new IllegalStateException("No typed OpenVPN Last in ordinary fixture");', 'RouterNodeChainExecution.lastPreparations++;return new RouterNodeChainExecution(source,requested,last);'),
        ('throw new IllegalStateException("No typed OpenVPN factory in ordinary fixture");', 'return plan.openVPNCommandServer(h,p);'),
        ('RouterNodeChainExecution.ordinaryPreparations++;return new RouterNodeChainExecution(launch,requested);', 'throw new IllegalStateException("Generic preparation cannot own OpenVPN execution");'),
        ('RouterNodeChainExecution.lastPreparations++;return new RouterNodeChainExecution(launch,requested,last);', 'throw new IllegalStateException("Generic Last cannot own OpenVPN execution");'),
    ):
        lib = once(lib, before, after)
    result[native + 'Libbox.java'] = lib
    return result


def complete_counts(value):
    return value.replace('new boolean[]{false,true}', 'new boolean[]{false}').replace('new int[]{2,3,4,8}', 'new int[]{3,4,5,6,7,8}').replace('new int[]{3,4,8}', 'new int[]{3,4,5,6,7,8}').replace('new int[]{3}', 'new int[]{3,4,5,6,7,8}').replace('new Fixture(2,', 'new Fixture(3,')


def runtime_harness():
    value = complete_counts(HOST.HARNESS)
    value = once(value, 'localSource.getInt("schema")== (imported?2:1)', 'localSource.getInt("schema")==5')
    value = once(value, 'original.capture.plan.runs==0', 'original.capture.plan.runs==0&&plan.factories==1&&plan.factory==server&&server.typed&&server.bound')
    value = once(value, 'String last=original.captureLastRecord();', 'String last;try{last=original.captureLastRecord();}catch(Exception error){throw new AssertionError("OpenVPN Last lost its typed factory",error);}')
    value = once(value, 'var capture=f.runtime.captureRestore();',
        'check(new org.json.JSONObject(original.execution.source).getString("openvpn_local_launch").equals(original.capture.launchInput),"OpenVPN replaced its sealed Local capture");var capture=f.runtime.captureRestore();')
    value = once(value, 'public static void main(String[] args)throws Exception{', r'''static void factoryControl()throws Exception {
  try(Fixture f=new Fixture(3,"server")) {
   CountDownLatch constructed=new CountDownLatch(1);CommandServer.afterConstruction=constructed::countDown;
   Result result=f.start();check(constructed.await(4,TimeUnit.SECONDS),"OpenVPN original constructor did not enter");
   check(RouterNodeChainExecution.latest.factories==1,"typed OpenVPN factory borrowed ordinary owner");
   result.finished();check(result.ok,"typed OpenVPN construction failed");f.stop();
  }
 }
 public static void main(String[] args)throws Exception{if(args.length>0&&args[0].equals("factory")){factoryControl();return;}
''')
    return value


def main():
    jar = Path(os.environ.get('ANDROID_JSON_JAR', '/usr/share/java/com.android.json.jar'))
    if not jar.is_file() or not shutil.which('javac'):
        raise RuntimeError('Actual JDK and Android JSON required')
    with tempfile.TemporaryDirectory(prefix='routervpn-openvpn-execution-host-') as directory:
        work = Path(directory); src = work / 'src'
        for path, value in sources().items():
            target = src / path; target.parent.mkdir(parents=True, exist_ok=True); target.write_text(value)
        app = src / HOST.APP
        names = ('AndroidHomeStateStore', 'AndroidConnectionSelection', 'AndroidNodeChainExecutionCapture', 'AndroidNodeChainSession', 'AndroidNodeChainMTUPlatform', 'AndroidNodeChainRuntime', 'LayeredVpnService')
        original = {name: (HOST.JAVA / (name + '.java')).read_text() for name in names}
        for name, value in original.items():
            (app / (name + '.java')).write_text(value)
        (app / 'OrderedExecutionRuntimeTest.java').write_text(runtime_harness())
        (app / 'OrderedExecutionRestoreTest.java').write_text(complete_counts(RESTORE.HARNESS))
        classes = work / 'classes'
        subprocess.run(['javac', '--release', '17', '-encoding', 'UTF-8', '-proc:none', '-cp', str(jar), '-d', str(classes), *map(str, src.rglob('*.java'))], check=True, timeout=60)
        cp = os.pathsep.join((str(classes), str(jar)))
        for root in ('OrderedExecutionRuntimeTest', 'OrderedExecutionRestoreTest'):
            subprocess.run(['java', '-cp', cp, 'com.eabusham.routervpn.' + root], check=True, timeout=120)
        controls = (
            ('AndroidNodeChainSession', 'if(execution!=null&&capture.openVPN)return Libbox.routerNodeChainOpenVPNExecutionNewCommandServer(execution.plan,handler,platform);', 'if(execution!=null&&capture.openVPN)return new CommandServer(handler,platform);', 'OrderedExecutionRuntimeTest', 'factory', 'typed OpenVPN factory borrowed ordinary owner'),
            ('AndroidNodeChainExecutionCapture', 'Libbox.routerNodeChainOpenVPNExecutionFromLaunch(local.launchInput, requested)', 'Libbox.routerNodeChainExecutionFromLaunch(local.launchInput, requested)', 'OrderedExecutionRuntimeTest', 'success', 'execution did not connect'),
            ('AndroidNodeChainExecutionCapture', 'Libbox.routerNodeChainOpenVPNExecutionFromLast(local.launchInput,requested,raw)', 'Libbox.routerNodeChainExecutionFromLast(local.launchInput,requested,raw)', 'OrderedExecutionRuntimeTest', 'last', 'OpenVPN Last lost its typed factory'),
            ('AndroidNodeChainExecutionCapture', 'if (restore != null) plan.requireRestore(restore.nativeCapture);', '', 'OrderedExecutionRestoreTest', 'foreign', 'foreign typed restore reached native startup: object'),
        )
        for n, (name, before, after, root, phase, witness) in enumerate(controls):
            if before not in original[name]:
                raise AssertionError('OpenVPN causal source boundary changed: ' + before)
            target = work / ('mutant-' + str(n)) / (name + '.java'); target.parent.mkdir(); target.write_text(original[name].replace(before, after))
            out = work / ('negative-' + str(n)); shutil.copytree(classes, out); mutantcp = os.pathsep.join((str(out), str(jar)))
            subprocess.run(['javac', '--release', '17', '-proc:none', '-cp', mutantcp, '-d', str(out), str(target)], check=True, timeout=60)
            result = subprocess.run(['java', '-cp', mutantcp, 'com.eabusham.routervpn.' + root, phase], text=True, capture_output=True, timeout=120)
            if result.returncode != 1 or witness not in result.stderr or 'java.lang.AssertionError' not in result.stderr:
                raise AssertionError('OpenVPN causal witness missing: ' + witness + '\n' + result.stdout + result.stderr)
            print('OpenVPN execution host causal refusal: ' + witness, flush=True)


if __name__ == '__main__':
    main()
