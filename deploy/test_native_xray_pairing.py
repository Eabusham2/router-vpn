#!/usr/bin/env python3
"""Native pairing invokes the shipping offline agent compiler; no server starts."""
from pathlib import Path
from unittest import mock
import base64
import copy
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('pairing',ROOT/'server/scripts/provision-multihop-relays.py')
PAIR=importlib.util.module_from_spec(spec);spec.loader.exec_module(PAIR)
class NativePairing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='router-native-pairing-')
        cls.agent=Path(cls.temp.name)/'agent'
        subprocess.run(['go','build','-buildvcs=false','-o',str(cls.agent),'./cmd/router-agent'],cwd=ROOT,check=True,timeout=90)
        raw=subprocess.check_output(['go','run','./deploy/testfixtures/xray-entry'],cwd=ROOT,timeout=90)
        cls.entries=json.loads(raw)
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def bundle(self,mode):
        raw=self.entries[mode]['config_json'];port=json.loads(raw)['inbounds'][0]['port']
        wrapper={'inbounds':[{'type':'tun','auto_route':True,'strict_route':True}],
                 'outbounds':[{'type':'socks','tag':'proxy','server':'127.0.0.1','server_port':port,'version':'5'}],
                 'route':{'final':'proxy'}}
        profile={'id':'paired','node_kind':'router-vpn','endpoint':'192.0.2.11','adguard_ipv4':'10.88.0.1','node_proof_id':'b'*64}
        return {'selectedRouterID':'paired','routerProfiles':[profile],'profiles':{mode:{'xray.json':base64.b64encode(raw.encode()).decode(),
                  'sing-box.json':base64.b64encode(json.dumps(wrapper).encode()).decode()}}}
    def execute(self,source):
        run=subprocess.run
        def exact(command,**kwargs):
            self.assertEqual(command[:2],['/usr/local/bin/router-vpn-agent','compile-native-relay-profile'])
            self.assertTrue(kwargs['check']);self.assertEqual(kwargs['stderr'],subprocess.DEVNULL)
            return run([str(self.agent),*command[1:]],**kwargs)
        with mock.patch.object(PAIR.subprocess,'run',side_effect=exact):return PAIR.pair(source,'owned-exit')
    def test_preserves_authentication_and_private_identity_for_all_native_modes(self):
        for mode in self.entries:
            source=self.bundle(mode);before=copy.deepcopy(source);result=self.execute(source)
            self.assertEqual(source,before);self.assertEqual(len(result),1)
            out=result[0];self.assertEqual(out['id'],'owned-exit');self.assertEqual(out['node_id'],'b'*64)
            self.assertEqual(out['dns_server'],'10.88.0.1');self.assertEqual(out['mode'],mode)
            expected=dict(self.entries[mode],tag='exit');self.assertEqual(out['transport'],expected)
    def test_foreign_peer_split_routes_and_extra_assets_are_not_rewritten(self):
        for kind in ('peer','routes','helper','auth','missing'):
            source=self.bundle('reality-pq-vision');assets=source['profiles']['reality-pq-vision']
            if kind=='peer':source['routerProfiles'][0]['endpoint']='192.0.2.12'
            if kind=='routes':
                graph=json.loads(base64.b64decode(assets['sing-box.json']));graph['route']['rules']=[{'outbound':'direct','network':'tcp'}]
                assets['sing-box.json']=base64.b64encode(json.dumps(graph).encode()).decode()
            if kind=='helper':assets['unowned.conf']='e30='
            if kind=='auth':
                raw=json.loads(base64.b64decode(assets['xray.json']));raw['outbounds'][0]['streamSettings']['security']='none'
                assets['xray.json']=base64.b64encode(json.dumps(raw).encode()).decode()
            if kind=='missing':assets.pop('xray.json')
            before=copy.deepcopy(source)
            with self.assertRaises((ValueError,subprocess.CalledProcessError)):self.execute(source)
            self.assertEqual(source,before)
    def test_only_a_requested_offline_command_can_reach_the_new_compiler(self):
        main=(ROOT/'cmd/router-agent/main.go').read_text()
        self.assertLess(main.index('compile-native-relay-profile'),main.index('path := getenv'))
        self.assertIn('compileNativeRelayProfile(os.Stdin, os.Stdout, os.Args[2])',main)
if __name__=='__main__':unittest.main()
