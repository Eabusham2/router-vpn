#!/usr/bin/env python3
"""Exercise the actual Linux graph patcher and private relay pairing CLI offline."""
import base64
import copy
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'modes'))
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
linux = module('linux_execution', ROOT/'modes/multihop-execution.py')
pairing = module('relay_pairing', ROOT/'server/scripts/provision-multihop-relays.py')

def fixture():
    transport = dict(type='shadowsocks',tag='proxy',server='192.0.2.2',server_port=8388,
                     method='2022-blake3-aes-128-gcm',password='AAAAAAAAAAAAAAAAAAAAAA==')
    profile = dict(id='exit',node_kind='router-vpn',endpoint='192.0.2.2',adguard_ipv4='10.88.0.1',node_proof_id='b'*64)
    return dict(selectedRouterID='exit',routerProfiles=[profile],profiles={'shadowsocks':{
        'sing-box.json':base64.b64encode(json.dumps({'outbounds':[transport]}).encode()).decode()}})

class ExecutionTests(unittest.TestCase):
    def graph(self):
        return dict(dns={'servers':[{'tag':'selected','detour':'proxy','type':'https','server':'1.1.1.1'}]},
                    outbounds=[{'type':'shadowsocks','tag':'proxy'},{'type':'socks','tag':'entry-socks'}],
                    route={'final':'proxy','rules':[{'inbound':['multihop-entry-proof'],'outbound':'entry-socks'},
                                                    {'inbound':['multihop-exit-proof'],'outbound':'proxy'}]})
    def descriptor(self):
        return dict(execution='server',lease={'host':'10.77.0.1','port':26240,'username':'a'*48,'password':'b'*48})
    def test_graph_preserves_dns_and_exit_proof(self):
        original = self.graph();value=linux.patch(original,self.descriptor(),'wg')
        self.assertEqual(value['dns'],original['dns']);self.assertNotEqual(value,original)
        self.assertEqual(value['route']['rules'][1],original['route']['rules'][1])
        self.assertEqual(value['route']['rules'][0]['outbound'],'entry-control')
        self.assertEqual(value['outbounds'][0]['bind_interface'],'wg')
        self.assertEqual(value['outbounds'][0]['type'],'socks')
        self.assertNotIn('network',value['outbounds'][0]) # not silently TCP-only
        self.assertEqual(original,self.graph())
    def test_bad_graphs_and_descriptors(self):
        for field,bad in [('host','8.8.8.8'),('host','0.0.0.0'),('host','127.0.0.1'),('host','fe80::1%wg'),
                          ('port',True),('port',26272),('port',26239),('username','secret'),('password','A'*48)]:
            with self.subTest(field=field,bad=bad):
                desc=self.descriptor();desc['lease'][field]=bad
                with self.assertRaises(ValueError):linux.patch(self.graph(),desc,'wg')
        for interface in ['wg;touch /bad','', 'x'*16]:
            with self.assertRaises(ValueError):linux.patch(self.graph(),self.descriptor(),interface)
        graph=self.graph();graph['route']['rules'][0]['inbound'].append('tun')
        with self.assertRaises(ValueError):linux.patch(graph,self.descriptor(),'wg')
    def test_pair_only_private_frozen_credentials(self):
        source=fixture();out=pairing.pair(source,'client-exit-id')
        self.assertEqual(out[0]['node_id'],'b'*64);self.assertEqual(out[0]['id'],'client-exit-id')
        self.assertEqual(out[0]['transport']['server'],'192.0.2.2')
        self.assertEqual(source,fixture())
    def test_rejects_mismatched_or_unowned_pairs(self):
        for alias in ['../x','bad id','']:
            with self.assertRaises(ValueError):pairing.pair(fixture(),alias)
        source=fixture();source['routerProfiles'][0]['node_kind']='external'
        with self.assertRaises(ValueError):pairing.pair(source,'exit')
        with self.assertRaises(ValueError):pairing.decode(b'{"secret":1,"secret":2}')
    def test_wireguard_pair_preserves_peer_and_refuses_wrong_identity(self):
        public=base64.b64encode(b'p'*32).decode();private=base64.b64encode(b'k'*32).decode()
        proof=hashlib.sha256(('router-vpn-node-proof-v1\n'+public).encode()).hexdigest()
        text=f"[Interface]\nPrivateKey = {private}\nAddress = 10.88.0.2/32\nMTU = 1380\n[Peer]\nPublicKey = {public}\nEndpoint = 192.0.2.2:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n"
        profile=fixture()['routerProfiles'][0];profile['node_proof_id']=proof
        value=pairing.native_wireguard(base64.b64encode(text.encode()).decode(),profile["node_proof_id"],"192.0.2.2")
        self.assertEqual(value['private_key'],private)
        self.assertEqual(value['peers'][0]['public_key'],public)
        self.assertEqual(value['mtu'],1380)
        for invalid in [text+'PostUp = evil\n',text.replace('0.0.0.0/0','10.0.0.0/8'),text.replace('MTU = 1380','MTU = 1200'),text.replace('[Peer]','ListenPort = 51820\n[Peer]'),text.replace('PrivateKey = '+private,'PrivateKey = '+private+'\nPrivateKey = '+private)]:
            with self.assertRaises(ValueError):pairing.native_wireguard(base64.b64encode(invalid.encode()).decode(),profile["node_proof_id"],"192.0.2.2")
        profile['node_proof_id']='c'*64
        with self.assertRaises(ValueError):pairing.native_wireguard(base64.b64encode(text.encode()).decode(),profile["node_proof_id"],"192.0.2.2")

    def test_private_registry_roundtrip_and_foreign_preservation(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);read,write,_=pairing.helpers()
            bundle=root/'exit.json';agent=root/'agent.json';registry=root/'relays.json'
            write(bundle,json.dumps(fixture()).encode());write(agent,json.dumps({'node_id':'a'*64,'tunnel_cidrs':['10.77.0.0/24']}).encode())
            write(registry,json.dumps({'listen_ip':'10.77.0.1','first_port':26240,'last_port':26271,'ttl_seconds':90,
                                      'exits':[dict(id='foreign',mode='shadowsocks',node_id='c'*64)]}).encode())
            argv=['pair','--bundle',str(bundle),'--exit-id','owned','--agent-config',str(agent),'--registry',str(registry),'--listen-ip','10.77.0.1']
            with patch.object(sys,'argv',argv),patch.object(pairing.subprocess,'run') as run:
                pairing.main();self.assertEqual(run.call_count,1)
                args=run.call_args.args[0];self.assertEqual(args[:2],['/usr/local/bin/router-vpn-agent','check-multihop-registry'])
            value=pairing.decode(read(registry,1<<20))
            self.assertEqual([e['id'] for e in value['exits']],['foreign','owned'])
            self.assertEqual(registry.stat().st_mode & 0o777,0o600)
            self.assertFalse(list(root.glob('.relay-pair-*')))
    def test_symlink_ancestor_and_lock_refused(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);real=root/'real';real.mkdir();link=root/'link';link.symlink_to(real,target_is_directory=True)
            with self.assertRaises(RuntimeError),pairing.registry_lock(link/'registry.json'):pass
            lock=real/'.registry.json.lock';target=real/'other';target.write_text('unchanged');lock.symlink_to(target)
            with self.assertRaises(OSError),pairing.registry_lock(real/'registry.json'):pass
            self.assertEqual(target.read_text(),'unchanged')
    def test_core_rejection_does_not_publish(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);_,write,_=pairing.helpers();bundle=root/'exit.json';agent=root/'agent.json';registry=root/'registry.json'
            write(bundle,json.dumps(fixture()).encode());write(agent,json.dumps({'node_id':'a'*64,'tunnel_cidrs':['10.77.0.0/24']}).encode())
            argv=['pair','--bundle',str(bundle),'--exit-id','owned','--agent-config',str(agent),'--registry',str(registry),'--listen-ip','10.77.0.1']
            with patch.object(sys,'argv',argv),patch.object(pairing.subprocess,'run',side_effect=RuntimeError('core rejected')):
                with self.assertRaises(RuntimeError):pairing.main()
            self.assertFalse(registry.exists())

if __name__=='__main__':unittest.main()
