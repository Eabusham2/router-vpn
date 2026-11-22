#!/usr/bin/env python3
"""Exercise shipping OpenVPN and independently imported Shadowsocks execution hosts.

The sealed source family and original construction owner are explicit here.
The fixture verifies typed command-server dispatch, cold Last and restoration.
Separate gates run the shared compiler and the encrypted native provider path.
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


def sources(*, multiple=False):
    family = 'MultipleImported' if multiple else 'OpenVPN'
    schema = 6 if multiple else 5
    wire = 'multiple-imported' if multiple else 'openvpn'
    launch = 'multiple_imported_local_launch' if multiple else 'openvpn_local_launch'
    mode = 'shadowsocks' if multiple else 'openvpn'
    public = '(i==1||i==count-2)' if multiple else '(i==count-2)'
    field = 'multipleImported' if multiple else 'openVPN'
    minimum = 4 if multiple else 3
    result = RESTORE.sources()
    app, native = HOST.APP, HOST.NATIVE
    result[app + 'AndroidNodeStore.java'] = once(result[app + 'AndroidNodeStore.java'],
        'selected.add(i==count-1?finalMode:prefixMode);',
        f'selected.add(i==count-1?finalMode:{public}?"{mode}":prefixMode);')
    capture = result[app + 'AndroidNodeChainCapture.java']
    capture = once(capture, f'final boolean {field}=false;', f'final boolean {field}=true;')
    capture = once(capture, 'source.imported&&i==source.members.size()-2', public.replace('count','source.members.size()'))
    capture = once(capture, '.put("schema",source.imported?2:1)', '.put("schema",'+str(schema)+')')
    result[app + 'AndroidNodeChainCapture.java'] = capture
    result[native + 'CommandServer.java'] = once(result[native + 'CommandServer.java'],
        'public void start(){started++;}',
        'public boolean typed,bound;public void start(){if(typed&&!bound)throw new IllegalStateException("typed OpenVPN execution started before binding");started++;}')
    value = result[native + 'RouterNodeChainExecution.java']
    value = once(value, 'localSHA=original.getString("source_sha256");',
        f'''localSHA=original.getString("source_sha256");
  int count=original.getJSONArray("nodes").length();
  if(!"routervpn-node-chain-launch-input".equals(original.getString("kind")) || original.getInt("schema")!={schema} ||
     count<{minimum} || count>8 || original.getJSONArray("identity_sources").length()!=count)
      throw new IllegalStateException("{family} lost sealed original Local authority");
  for(int i=0;i<count;i++)if(original.getJSONArray("identity_sources").getString(i).isEmpty()!={public})
      throw new IllegalStateException("{family} lost original private identity position");''')
    value = once(value, 'source=new JSONObject().put("schema",1).put("execution",requested).put("local_source",local.toString()).toString();',
        f'source=new JSONObject().put("schema",{schema}).put("execution",requested).put("local_source",local.toString()).put("{launch}",input).toString();')
    value = once(value, '"routervpn-node-chain-execution-preparation-input"', f'"routervpn-node-chain-{wire}-execution-preparation-input"')
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
        lib = once(lib, before.replace('No typed OpenVPN', 'No typed '+family), after)
    result[native + 'Libbox.java'] = lib
    return result


def complete_counts(value, *, multiple=False):
    if multiple:
        value = value.replace('Fixture(3,', 'Fixture(5,')
    value = value.replace('new boolean[]{false,true}', 'new boolean[]{false}').replace('new int[]{2,3,4,8}', 'new int[]{3,4,5,6,7,8}').replace('new int[]{3,4,8}', 'new int[]{3,4,5,6,7,8}').replace('new int[]{3}', 'new int[]{3,4,5,6,7,8}').replace('new Fixture(2,', 'new Fixture(3,')
    return value.replace('new int[]{3,4,5,6,7,8}', 'new int[]{4,5,8}') if multiple else value


def runtime_harness(*, multiple=False):
    value = complete_counts(HOST.HARNESS, multiple=multiple)
    value = once(value, 'localSource.getInt("schema")== (imported?2:1)', 'localSource.getInt("schema")=='+('6' if multiple else '5'))
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
    if multiple:
        value = once(value, '(!imported||localSource.getJSONArray("identity_sources").getString(count-2).isEmpty())', 'localSource.getJSONArray("identity_sources").getString(1).isEmpty()&&localSource.getJSONArray("identity_sources").getString(count-2).isEmpty()')
        value = value.replace('getString("openvpn_local_launch")', 'getString("multiple_imported_local_launch")')
        value = value.replace('new Fixture(3,"server")', 'new Fixture(5,"server")')
        value = value.replace('OpenVPN ', 'multiple-import ')
    return value


def main(*, multiple=False):
    jar = Path(os.environ.get('ANDROID_JSON_JAR', '/usr/share/java/com.android.json.jar'))
    if not jar.is_file() or not shutil.which('javac'):
        raise RuntimeError('Actual JDK and Android JSON required')
    with tempfile.TemporaryDirectory(prefix='routervpn-openvpn-execution-host-') as directory:
        work = Path(directory); src = work / 'src'
        for path, value in sources(multiple=multiple).items():
            target = src / path; target.parent.mkdir(parents=True, exist_ok=True); target.write_text(value)
        app = src / HOST.APP
        names = ('AndroidHomeStateStore', 'AndroidConnectionSelection', 'AndroidNodeChainExecutionCapture', 'AndroidNodeChainSession', 'AndroidNodeChainMTUPlatform', 'AndroidNodeChainRuntime', 'LayeredVpnService')
        original = {name: (HOST.JAVA / (name + '.java')).read_text() for name in names}
        for name, value in original.items():
            (app / (name + '.java')).write_text(value)
        (app / 'OrderedExecutionRuntimeTest.java').write_text(runtime_harness(multiple=multiple))
        (app / 'OrderedExecutionRestoreTest.java').write_text(complete_counts(RESTORE.HARNESS, multiple=multiple))
        classes = work / 'classes'
        subprocess.run(['javac', '--release', '17', '-encoding', 'UTF-8', '-proc:none', '-cp', str(jar), '-d', str(classes), *map(str, src.rglob('*.java'))], check=True, timeout=60)
        cp = os.pathsep.join((str(classes), str(jar)))
        for root in ('OrderedExecutionRuntimeTest', 'OrderedExecutionRestoreTest'):
            phases = ('success', 'last', 'factory') if multiple and root == 'OrderedExecutionRuntimeTest' else ('foreign',) if multiple else ('all',)
            for phase in phases:
                subprocess.run(['java', '-cp', cp, 'com.eabusham.routervpn.' + root, phase], check=True, timeout=120)

        controls = (
            ('AndroidNodeChainSession', 'if(execution!=null&&capture.openVPN)return Libbox.routerNodeChainOpenVPNExecutionNewCommandServer(execution.plan,handler,platform);', 'if(execution!=null&&capture.openVPN)return new CommandServer(handler,platform);', 'OrderedExecutionRuntimeTest', 'factory', 'typed OpenVPN factory borrowed ordinary owner'),
            ('AndroidNodeChainExecutionCapture', 'Libbox.routerNodeChainOpenVPNExecutionFromLaunch(local.launchInput, requested)', 'Libbox.routerNodeChainExecutionFromLaunch(local.launchInput, requested)', 'OrderedExecutionRuntimeTest', 'success', 'execution did not connect'),
            ('AndroidNodeChainExecutionCapture', 'Libbox.routerNodeChainOpenVPNExecutionFromLast(local.launchInput,requested,raw)', 'Libbox.routerNodeChainExecutionFromLast(local.launchInput,requested,raw)', 'OrderedExecutionRuntimeTest', 'last', 'OpenVPN Last lost its typed factory'),
            ('AndroidNodeChainExecutionCapture', 'if (restore != null) plan.requireRestore(restore.nativeCapture);', '', 'OrderedExecutionRestoreTest', 'foreign', 'foreign typed restore reached native startup: object'),
        )
        for n, (name, before, after, root, phase, witness) in enumerate(controls):
            if multiple:
                before = before.replace('capture.openVPN', 'capture.multipleImported').replace('routerNodeChainOpenVPNExecution', 'routerNodeChainMultipleImportedExecution')
                after = after.replace('capture.openVPN', 'capture.multipleImported')
                witness = witness.replace('OpenVPN ', 'multiple-import ')
            if original[name].count(before) != (2 if phase == 'foreign' else 1):
                raise AssertionError('Typed host causal source boundary changed: ' + before)
            target = work / ('mutant-' + str(n)) / (name + '.java'); target.parent.mkdir(); target.write_text(original[name].replace(before, after))
            out = work / ('negative-' + str(n)); shutil.copytree(classes, out); mutantcp = os.pathsep.join((str(out), str(jar)))
            subprocess.run(['javac', '--release', '17', '-proc:none', '-cp', mutantcp, '-d', str(out), str(target)], check=True, timeout=60)
            result = subprocess.run(['java', '-cp', mutantcp, 'com.eabusham.routervpn.' + root, phase], text=True, capture_output=True, timeout=120)
            if result.returncode != 1 or witness not in result.stderr or 'java.lang.AssertionError' not in result.stderr:
                raise AssertionError('Typed host causal witness missing: ' + witness + '\n' + result.stdout + result.stderr)
            print(('Multiple-import' if multiple else 'OpenVPN')+' execution host causal refusal: ' + witness, flush=True)


if __name__ == '__main__':
    main()
    main(multiple=True)
