#!/usr/bin/env python3
"""Actual package verification plus exact metadata/artifact refusal controls."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
SPEC=importlib.util.spec_from_file_location('verifier',Path(__file__).with_name('verify-dnssec-validator.py'))
V=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(V)
def main():
    p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);args=p.parse_args()
    architecture=json.loads((args.build/'manifest.json').read_text())['architecture']
    V.verify(args.build,architecture)
    with tempfile.TemporaryDirectory(prefix='dnssec-package-') as tmp:
        root=Path(tmp)
        for name in ('manifest.json','libroutervpn_dnssec.so'):shutil.copyfile(args.build/name,root/name)
        shutil.copytree(args.build/'licenses',root/'licenses')
        original=(root/'manifest.json').read_bytes()
        def refuse():
            try:V.verify(root,architecture)
            except ValueError:return
            raise AssertionError('mutated package admitted')
        for key,value in [('artifact_sha256','0'*64),('artifact_size',1),('elf_machine',0),('needed',['libunbound.so']),('exports',['ub_ctx_create']),('abi',2),('shim_sha256','0'*64)]:
            manifest=json.loads(original);manifest[key]=value
            (root/'manifest.json').write_text(json.dumps(manifest));refuse()
            (root/'manifest.json').write_bytes(original)
        license=root/'licenses/unbound-LICENSE';saved=license.read_bytes();license.write_bytes(b'changed');refuse();license.write_bytes(saved)
        artifact=root/'libroutervpn_dnssec.so';saved=artifact.read_bytes();artifact.write_bytes(saved+b'changed');refuse();artifact.unlink()
        artifact.symlink_to((args.build/'libroutervpn_dnssec.so').resolve());refuse()
    print('PASS original package and 10 tamper/target/identity controls')
if __name__=='__main__':main()
