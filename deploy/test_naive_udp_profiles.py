#!/usr/bin/env python3
"""Run the shipping TLS generator with private fixtures and a parser test double.

This checks real generator/preservation/atomic-adoption code, not native UDP
traffic. The pinned Naive server image's native tests remain a separate gate.
"""
from pathlib import Path
import json
import os
import subprocess
import tempfile
import shlex
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]

class NaiveProfiles(unittest.TestCase):
    def setup(self, directory):
        root=Path(directory)
        base=root/'private deployment'
        profile=base/'client-bundle/generated/hysteria2';profile.mkdir(parents=True)
        (profile/'sing-box.json').write_text(json.dumps({'outbounds':[{'tag':'proxy','type':'hysteria2','server':'192.0.2.4','server_port':2443,'password':'test-only-hy2-credential','tls':{'enabled':True,'server_name':'fixture.example.test','certificate_path':'cert.pem'}}]}))
        (profile/'cert.pem').write_text('test-only existing certificate bytes\n')
        for f in profile.iterdir():f.chmod(0o600)
        # Only relocate the generator's repository helper paths; its policy,
        # credential generator, output writer and shell flow execute unchanged.
        shell=(ROOT/'server/scripts/generate-tls-alternates.sh').read_text()
        shell=shell.replace('/src/server/scripts/',str(ROOT/'server/scripts')+'/')
        script=root/'generator.sh';script.write_text(shell)
        tools=root/'bin';tools.mkdir()
        # All generator helpers use the standard library. Isolate this test
        # from workstation sitecustomize/pip startup hooks, not from production
        # validation or file ownership checks.
        python=tools/'python3';python.write_text('#!/bin/sh\nexec '+shlex.quote(sys.executable)+' -I -S "$@"\n');python.chmod(0o755)
        parser=tools/'sing-box';parser.write_text('''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
if sys.argv[1]=='version':
 print('test-only parser boundary with_naive_outbound')
else:
 path=Path(sys.argv[sys.argv.index('-c')+1]);value=json.loads(path.read_text())
 with open(os.environ['TEST_PARSER_CALLS'],'a') as log:log.write(path.parent.name+'\\n')
 if os.environ.get('TEST_REJECT_PROFILE')==path.parent.name:sys.exit(1)
''');parser.chmod(0o755)
        env=dict(os.environ,PATH=str(tools)+os.pathsep+os.environ['PATH'],ROUTER_VPN_TLS_NAME='fixture.example.test',TEST_PARSER_CALLS=str(root/'calls'))
        return base,script,env

    def run_generator(self, base, script, env, dns='192.168.50.133'):
        return subprocess.run(['bash',str(script),str(base),'192.0.2.4',dns],env=env,capture_output=True,text=True,timeout=25)

    def snapshot(self, base):
        return {str(f.relative_to(base)):f.read_bytes() for f in base.rglob('*') if f.is_file()}

    def test_h2_and_h3_keep_udp_dns_and_exact_shared_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            base,script,env=self.setup(tmp)
            result=self.run_generator(base,script,env)
            self.assertEqual(result.returncode,0,result.stderr)
            credentials=[]
            for mode,quic,mtu in [('naive-h2',False,1320),('naive-h3',True,1300)]:
                path=base/'client-bundle/generated'/mode/'sing-box.json'
                graph=json.loads(path.read_text());out=graph['outbounds'][0]
                self.assertEqual(out['type'],'naive');self.assertIs(out['quic'],quic)
                self.assertEqual(out['udp_over_tcp'],{'enabled':True,'version':2})
                self.assertEqual(out['server'],'192.0.2.4');self.assertEqual(out['tls'],{'enabled':True,'server_name':'fixture.example.test'})
                self.assertEqual(graph['dns']['servers'][0],{'type':'udp','tag':'home-dns','server':'192.168.50.133','server_port':53,'detour':'proxy'})
                self.assertEqual(graph['route']['final'],'proxy');self.assertEqual(graph['inbounds'][0]['mtu'],mtu)
                self.assertEqual(path.stat().st_mode&0o777,0o600)
                credentials.append((out['username'],out['password']))
            self.assertEqual(credentials[0],credentials[1])
            self.assertEqual(Path(env['TEST_PARSER_CALLS']).read_text().splitlines(),['ss-v2ray','naive-h2','naive-h3'])
            self.assertIn('FROM pocat/naiveproxy:v2.11.4-uot\n',(ROOT/'server/naive/Dockerfile').read_text())

    def test_upgrade_repairs_udp_without_rotating_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            base,script,env=self.setup(tmp)
            self.assertEqual(self.run_generator(base,script,env).returncode,0)
            settings=(base/'config/tls/settings.env').read_bytes()
            path=base/'client-bundle/generated/naive-h3/sing-box.json'
            graph=json.loads(path.read_text());out=graph['outbounds'][0]
            identity=(out['username'],out['password']);out['udp_over_tcp']=False
            path.write_text(json.dumps(graph))
            result=self.run_generator(base,script,env)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('Preserving existing',result.stderr)
            self.assertEqual((base/'config/tls/settings.env').read_bytes(),settings)
            repaired=json.loads(path.read_text())['outbounds'][0]
            self.assertEqual((repaired['username'],repaired['password']),identity)
            self.assertEqual(repaired['udp_over_tcp'],{'enabled':True,'version':2})

    def test_rejected_candidate_does_not_change_any_private_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            base,script,env=self.setup(tmp)
            self.assertEqual(self.run_generator(base,script,env).returncode,0)
            before=self.snapshot(base)
            env['TEST_REJECT_PROFILE']='naive-h3'
            result=self.run_generator(base,script,env,'192.168.50.200')
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(self.snapshot(base),before)
            self.assertFalse(list((base/'config/tls').glob('.generate.*')))

    def test_corrupt_existing_identity_is_not_regenerated(self):
        with tempfile.TemporaryDirectory() as tmp:
            base,script,env=self.setup(tmp)
            self.assertEqual(self.run_generator(base,script,env).returncode,0)
            path=base/'config/tls/settings.env';path.write_text("NAIVE_USER='old-user'\n")
            before=self.snapshot(base)
            result=self.run_generator(base,script,env)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(self.snapshot(base),before)
            self.assertIn('refusing silent credential rotation',result.stderr)

if __name__=='__main__':unittest.main()
