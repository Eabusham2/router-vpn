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

def external_fixture():
    profile = dict(id='external-exit',node_kind='external',external=dict(
        protocol='shadowsocks',expected_public_ip='203.0.113.88',
        shadowsocks=dict(server='203.0.113.20',port=8388,method='aes-256-gcm',password='captured-private-key'),
        response_probe=dict(url='https://203.0.113.20/response',server_name='node.example')))
    return dict(selectedRouterID=profile['id'],routerProfiles=[profile])

def external_proxy_fixture(protocol, layer=''):
    source = external_fixture();profile = source['routerProfiles'][0]
    ext = profile['external'];del ext['shadowsocks'];ext['protocol'] = protocol
    if protocol == 'shadowsocks':
        proxy = dict(server='203.0.113.20',port=8388,method='aes-256-gcm',password='captured-private-key')
    elif protocol == 'hysteria2':
        proxy = dict(server='203.0.113.20',port=443,password='captured-private-key',tls_server_name='node.example')
    else:
        proxy = dict(host='203.0.113.20',port=1080,username='private-proxy-user',password='captured-private-key')
        if protocol == 'https-connect':proxy['tls_server_name']='node.example'
    ext[protocol.replace('-','_')]=proxy
    if layer:
        profile['start_layer']=layer
        ext['start_layer']=dict(mode=layer,api='http://10.88.0.1:8787',transport=dict(
            type='shadowsocks',tag='saved-layer',server='203.0.113.20',server_port=8388,
            method='2022-blake3-aes-256-gcm',password=base64.b64encode(b's'*32).decode()))
    return source

class ExecutionTests(unittest.TestCase):
    def test_all_external_proxy_and_exit_layer_pairings_preserve_private_capture(self):
        for protocol in ('shadowsocks','hysteria2','socks5','http-connect','https-connect'):
            for layer in ('','aes-256-gcm','aes-256-gcm+xor-whitening'):
                with self.subTest(protocol=protocol,layer=layer):
                    source=external_proxy_fixture(protocol,layer);before=copy.deepcopy(source)
                    paired=pairing.pair(source,'external-exit')
                    self.assertEqual(source,before);self.assertEqual(len(paired),1)
                    result=paired[0];transport=result['transport']
                    self.assertEqual(result['mode'],protocol)
                    self.assertEqual(result['node_id'],'');self.assertEqual(result['dns_server'],'')
                    self.assertEqual(result['external']['expected_public_ip'],'203.0.113.88')
                    self.assertEqual(transport['password'],'captured-private-key')
                    self.assertEqual(transport['server'],'203.0.113.20')
                    if protocol in ('socks5','http-connect','https-connect'):
                        self.assertEqual(transport['username'],'private-proxy-user')
                        self.assertEqual(transport['type'],'socks' if protocol=='socks5' else 'http')
                    if protocol in ('hysteria2','https-connect'):
                        self.assertEqual(transport['tls'],dict(enabled=True,server_name='node.example'))
                    else:self.assertNotIn('tls',transport)
                    if layer:
                        self.assertEqual(result['start_layer'],source['routerProfiles'][0]['external']['start_layer'])
                        result['start_layer']['transport']['password']='changed-after-pairing'
                    else:self.assertNotIn('start_layer',result)
                    result['external']['response_probe']['url']='changed-after-pairing'
                    transport['password']='changed-after-pairing'
                    self.assertEqual(source,before)

    def test_external_proxy_pairing_refuses_empty_or_malformed_authentication(self):
        for protocol in ('shadowsocks','hysteria2','socks5','http-connect','https-connect'):
            for secret in ('','a\x00b','a\nb','a\rb','x'*4097,'\ud800',None,True):
                source=external_proxy_fixture(protocol)
                source['routerProfiles'][0]['external'][protocol.replace('-','_')]['password']=secret
                with self.subTest(protocol=protocol),self.assertRaises(ValueError):pairing.pair(source,'external-exit')
        for protocol in ('socks5','http-connect','https-connect'):
            source=external_proxy_fixture(protocol)
            proxy=source['routerProfiles'][0]['external'][protocol.replace('-','_')]
            del proxy['username'];del proxy['password']
            with self.assertRaises(ValueError):pairing.pair(source,'external-exit')
        for protocol in ('hysteria2','https-connect'):
            for value in ('','localhost','node.example.','node.example\n','fe80::1%en0'):
                source=external_proxy_fixture(protocol)
                source['routerProfiles'][0]['external'][protocol.replace('-','_')]['tls_server_name']=value
                with self.assertRaises(ValueError):pairing.pair(source,'external-exit')
        for protocol in ('socks5','http-connect','https-connect'):
            for field,value in [('username','x'*256),('password','x'*256 if protocol=='socks5' else 'bad\nsecret'),('detour','direct'),('tls_server_name','node.example' if protocol=='http-connect' else None)]:
                source=external_proxy_fixture(protocol)
                source['routerProfiles'][0]['external'][protocol.replace('-','_')][field]=value
                with self.assertRaises(ValueError):pairing.pair(source,'external-exit')

    def test_external_pairing_refuses_unselected_or_foreign_exit_layers(self):
        for protocol in ('shadowsocks','hysteria2','socks5','http-connect','https-connect'):
            for mutate in (
                lambda p:p.update(start_layer='off'),
                lambda p:p.update(start_layer='aes-256-gcm+xor-whitening'),
                lambda p:p['external'].update(start_layer=None),
                lambda p:p['external']['start_layer'].update(helper='opaque'),
                lambda p:p['external']['start_layer'].update(api='http://203.0.113.20:8787'),
                lambda p:p['external']['start_layer']['transport'].update(server='203.0.113.21'),
                lambda p:p['external']['start_layer']['transport'].update(password='not-a-captured-aes-key'),
                lambda p:p['external']['start_layer']['transport'].update(detour='foreign'),
            ):
                source=external_proxy_fixture(protocol,'aes-256-gcm');mutate(source['routerProfiles'][0])
                with self.subTest(protocol=protocol),self.assertRaises(ValueError):pairing.pair(source,'external-exit')

    def test_external_pair_keeps_transport_credentials_and_independent_identity(self):
        source=external_fixture();before=copy.deepcopy(source)
        result=pairing.pair(source,'external-exit')
        self.assertEqual(source,before)
        self.assertEqual(len(result),1)
        value=result[0]
        self.assertEqual(value['node_id'],'')
        self.assertEqual(value['dns_server'],'')
        self.assertEqual(value['transport'],dict(type='shadowsocks',tag='exit',server='203.0.113.20',server_port=8388,method='aes-256-gcm',password='captured-private-key'))
        self.assertEqual(value['external']['expected_public_ip'],'203.0.113.88')
        self.assertEqual(value['external']['response_probe'],source['routerProfiles'][0]['external']['response_probe'])
        value['external']['response_probe']['url']='https://203.0.113.20/changed'
        self.assertEqual(source,before)

    def test_external_pair_refuses_router_identity_unowned_fields_and_private_targets(self):
        for field,value in [('node_proof_id','b'*64),('router_api','http://10.77.0.1:8787'),('api_token','must-not-echo'),('start_layer','aes')]:
            source=external_fixture();source['routerProfiles'][0][field]=value
            with self.assertRaises(ValueError) as failed:pairing.pair(source,'external-exit')
            self.assertNotIn('must-not-echo',str(failed.exception))
        for field,value in [('protocol','hysteria2'),('dns_server','1.1.1.1'),('response_probe',None)]:
            source=external_fixture();source['routerProfiles'][0]['external'][field]=value
            with self.assertRaises(ValueError):pairing.pair(source,'external-exit')
        for host in ['must-not-echo','192.168.50.1','127.0.0.1','100.64.0.1','::ffff:203.0.113.20']:
            source=external_fixture();source['routerProfiles'][0]['external']['shadowsocks']['server']=host
            with self.assertRaises(ValueError) as failed:pairing.pair(source,'external-exit')
            self.assertNotIn('must-not-echo',str(failed.exception))
        for field,value in [('plugin','opaque-helper'),('port',True),('password','')]:
            source=external_fixture();source['routerProfiles'][0]['external']['shadowsocks'][field]=value
            with self.assertRaises(ValueError):pairing.pair(source,'external-exit')

    def test_external_registry_is_private_atomic_and_must_pass_native_check(self):
        for reject in (False,True):
            with self.subTest(reject=reject),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);read,write,_=pairing.helpers()
                bundle=root/'external.json';agent=root/'agent.json';registry=root/'registry.json'
                write(bundle,json.dumps(external_fixture()).encode())
                write(agent,json.dumps(dict(node_id='a'*64,tunnel_cidrs=['10.77.0.0/24'])).encode())
                original=dict(listen_ip='10.77.0.1',first_port=26240,last_port=26271,ttl_seconds=90,exits=[dict(id='foreign',mode='shadowsocks',node_id='b'*64)])
                write(registry,json.dumps(original).encode());before=registry.read_bytes()
                argv=['pair','--bundle',str(bundle),'--exit-id','external-exit','--agent-config',str(agent),'--registry',str(registry),'--listen-ip','10.77.0.1']
                def native_check(command,**kwargs):
                    self.assertEqual(command[:2],['/usr/local/bin/router-vpn-agent','check-multihop-registry'])
                    self.assertTrue(kwargs['check']);self.assertEqual(kwargs['timeout'],60)
                    staged=pairing.decode(read(Path(command[2]),1<<20))
                    self.assertEqual(staged['exits'][0],original['exits'][0])
                    self.assertEqual(staged['exits'][1]['external']['response_probe']['server_name'],'node.example')
                    self.assertEqual(Path(command[2]).stat().st_mode&0o777,0o600)
                    if reject:raise RuntimeError('native validation rejected')
                with patch.object(sys,'argv',argv),patch.object(pairing.subprocess,'run',side_effect=native_check) as check:
                    if reject:
                        with self.assertRaises(RuntimeError):pairing.main()
                    else:pairing.main()
                    self.assertEqual(check.call_count,1)
                if reject:self.assertEqual(registry.read_bytes(),before)
                else:
                    self.assertEqual(registry.stat().st_mode&0o777,0o600)
                    self.assertEqual([e['id'] for e in pairing.decode(read(registry,1<<20))['exits']],['foreign','external-exit'])
                self.assertFalse(list(root.glob('.relay-pair-*')))

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


    def test_native_awg_pairing_preserves_strength_and_independent_node_proof(self):
        source=fixture();params={'jc':'3','jmin':'40','jmax':'900','s1':'56','s2':'48','s3':'24','s4':'32',
            'h1':'10-19','h2':'20-29','h3':'30-39','h4':'40-49'}
        private=base64.b64encode(b'a'*32).decode();public=base64.b64encode(b'b'*32).decode()
        text=f'[Interface]\nPrivateKey={private}\nAddress=10.88.0.2/32,fd88::2/128\nMTU=1380\n'+''.join(k.upper()+'='+v+'\n' for k,v in params.items())+f'[Peer]\nPublicKey={public}\nAllowedIPs=0.0.0.0/0,::/0\nEndpoint=exit.example:51820\nPersistentKeepalive=25\n'
        for mode in ['awg2-fast','awg2-strong']:
            raw=text if mode.endswith('fast') else text.replace('S4=32','S4=80')
            source['profiles'][mode]={'awg.conf':base64.b64encode(raw.encode()).decode()}
        before=copy.deepcopy(source);paired=pairing.pair(source,'owned');self.assertEqual(source,before)
        for mode,padding in [('awg2-fast','32'),('awg2-strong','80')]:
            out=next(x for x in paired if x['mode']==mode)
            self.assertEqual(out['node_id'],'b'*64);self.assertEqual(out['transport']['type'],'routervpn-amneziawg')
            self.assertEqual(out['transport']['amnezia']['s4'],padding);self.assertEqual(len(out['transport']['amnezia']),11)
            self.assertEqual(out['transport']['peers'][0]['public_key'],public)
            self.assertEqual(out['transport']['peers'][0]['address'],'192.0.2.2')
        for bad in [text.replace('S4=32\n',''),text.replace('H2=20-29','H2=10-19'),text.replace('JC=3','JC=129'),text.replace('[Peer]','PostUp=touch /tmp/no\n[Peer]')]:
            with self.assertRaises(ValueError):pairing.native_wireguard(base64.b64encode(bad.encode()).decode(),'b'*64,'192.0.2.2',amnezia=True)
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
    def test_large_private_registry_roundtrip_and_capacity_rejection(self):
        self.assertEqual(pairing.MAX_REGISTRY_BYTES,32<<20)
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);read,write,_=pairing.helpers()
            bundle=root/'bundle.json';agent=root/'agent.json';registry=root/'registry.json'
            write(bundle,json.dumps(fixture()).encode())
            write(agent,json.dumps({'node_id':'a'*64,'tunnel_cidrs':['10.77.0.0/24']}).encode())
            # Size-policy sentinel, not native credential validation. The real
            # compiler/parser gate has separate valid PQ key-fixture coverage.
            original={'listen_ip':'10.77.0.1','first_port':26240,'last_port':26271,'ttl_seconds':90,
                      'exits':[dict(id='foreign',mode='wg-pq',node_id='c'*64,private_fixture='k'*(2<<20))]}
            write(registry,pairing.registry_bytes(original))
            argv=['pair','--bundle',str(bundle),'--exit-id','owned','--agent-config',str(agent),'--registry',str(registry),'--listen-ip','10.77.0.1']
            with patch.object(sys,'argv',argv),patch.object(pairing.subprocess,'run') as check:
                pairing.main();self.assertEqual(check.call_count,1)
            updated=pairing.decode(read(registry,pairing.MAX_REGISTRY_BYTES))
            self.assertEqual(updated['exits'][0],original['exits'][0])
            saved=registry.read_bytes()
            with patch.object(pairing,'MAX_REGISTRY_BYTES',len(saved)-1),patch.object(sys,'argv',argv),patch.object(pairing.subprocess,'run') as check:
                with self.assertRaises((ValueError,RuntimeError)):pairing.main()
                check.assert_not_called()
            self.assertEqual(registry.read_bytes(),saved)
            with patch.object(pairing,'MAX_REGISTRY_BYTES',64):
                with self.assertRaisesRegex(ValueError,'bound'):pairing.registry_bytes(updated)
            with self.assertRaises(ValueError):pairing.registry_bytes({'invalid':float('nan')})

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
