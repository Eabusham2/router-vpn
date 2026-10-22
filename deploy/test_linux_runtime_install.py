#!/usr/bin/env python3
"""Execute Linux runtime promotion, rollback, and real packaged verification."""
from pathlib import Path
import argparse
import json
import os
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/'client/install-bundled-desktop-runtime.sh'
checks=0


def check(value, label):
    global checks
    assert value, label
    checks+=1


def run(source, destination, env=None, succeeds=True):
    result=subprocess.run(['bash',str(SCRIPT),str(source),str(destination)], env=env,
                          text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90)
    check((result.returncode==0)==succeeds, result.stdout)
    return result


def write(path, text, executable=False):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text)
    if executable:path.chmod(0o755)


def contents(root):
    return {p.relative_to(root).as_posix():p.read_bytes() for p in root.rglob('*') if p.is_file()}


def boundaries():
    with tempfile.TemporaryDirectory(prefix='linux-runtime-install-') as temporary:
        root=Path(temporary);source=root/'source';destination=root/'installed';destination.mkdir()
        # OS processes are doubled; the production shell owns all real files,
        # staging, promotion and rollback. --package runs actual verifiers.
        write(source/'router-vpn-client', '''#!/usr/bin/env python3
import pathlib,sys
engine={'--verify-native-runtime':'native','--verify-amnezia-runtime':'amnezia'}[sys.argv[1]]
assert (pathlib.Path(sys.argv[2])/'runtime'/engine/'payload').read_text()=='verified '+engine
''',True)
        write(source/'client/verify-bundled-xray.py', '''import pathlib,sys
assert (pathlib.Path(sys.argv[1])/'payload').read_text()=='verified xray'
''')
        for engine in ('xray','amnezia','native'):
            write(source/'runtime'/engine/'payload','verified '+engine)
            write(destination/'runtime'/engine/'payload','previous '+engine)
        write(destination/'runtime/windows/sentinel','keep installed Windows tools')
        write(destination/'routers.json','private routers')
        write(destination/'generated/private-key','private key')
        run(source,destination)
        for engine in ('xray','amnezia','native'):
            check((destination/'runtime'/engine/'payload').read_text()=='verified '+engine,'missing installed '+engine)
        check((destination/'runtime/windows/sentinel').read_text()=='keep installed Windows tools','unrelated runtime changed')
        check((destination/'routers.json').read_text()=='private routers','private node store changed')
        check((destination/'generated/private-key').read_text()=='private key','generated keys changed')
        before=contents(destination)
        write(source/'runtime/native/payload','corrupt')
        run(source,destination,succeeds=False)
        check(contents(destination)==before,'source rejection modified installation')
        write(source/'runtime/native/payload','verified native')
        tools=root/'tools';tools.mkdir()
        real_cp=shutil.which('cp');real_mv=shutil.which('mv')
        write(tools/'cp', '''#!/usr/bin/env python3
import pathlib,subprocess,sys
subprocess.run([REAL,*sys.argv[1:]],check=True)
out=pathlib.Path(sys.argv[-1])
if out.name=='native':(out/'payload').write_text('changed during copy')
'''.replace('REAL',repr(real_cp)),True)
        env=dict(os.environ,PATH=str(tools)+os.pathsep+os.environ['PATH'])
        run(source,destination,env,succeeds=False)
        check(contents(destination)==before,'copy corruption modified installation')
        (tools/'cp').unlink()
        write(tools/'mv', '''#!/usr/bin/env python3
import pathlib,subprocess,sys
source=pathlib.Path(sys.argv[-2])
if source.name=='amnezia' and source.parent.name=='runtime' and source.parent.parent.name=='new':sys.exit(19)
sys.exit(subprocess.run([REAL,*sys.argv[1:]]).returncode)
'''.replace('REAL',repr(real_mv)),True)
        run(source,destination,env,succeeds=False)
        check(contents(destination)==before,'promotion failure did not roll back all engines')
        (tools/'mv').unlink()
        shutil.rmtree(destination/'runtime/native')
        (destination/'runtime/native').symlink_to(source/'runtime/native',target_is_directory=True)
        run(source,destination,succeeds=False)
        check((source/'runtime/native/payload').read_text()=='verified native','linked destination modified source')
    print(f'{checks} Linux runtime installation boundary checks passed',flush=True)


def real_package(package):
    package=package.absolute()
    with tempfile.TemporaryDirectory(prefix='linux-real-runtime-install-') as temporary:
        destination=Path(temporary)
        write(destination/'routers.json','private node sentinel')
        write(destination/'generated/keep','private generated sentinel')
        write(destination/'runtime/windows/keep','unrelated runtime sentinel')
        run(package,destination)
        for engine in ('xray','amnezia','native'):
            check(contents(package/'runtime'/engine)==contents(destination/'runtime'/engine),'installed real engine differs')
        run(package,destination)
        check((destination/'routers.json').read_text()=='private node sentinel','upgrade lost nodes')
        check((destination/'generated/keep').read_text()=='private generated sentinel','upgrade lost private files')
        check((destination/'runtime/windows/keep').read_text()=='unrelated runtime sentinel','upgrade lost separate engine')
    print('Actual packaged Linux engines verified after first install and upgrade',flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--package',type=Path)
    args=parser.parse_args();boundaries()
    if args.package:real_package(args.package)
