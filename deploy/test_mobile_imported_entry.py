#!/usr/bin/env python3
"""Execute captured imported-entry/paired-final compiler and actual native gates."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
PIN='1ac1a339cb1223e9c70eae14c44411c75033c02d'
LAYERS=('', 'aes-256-gcm', 'aes-256-gcm+xor-whitening')
BASE_FILES={f'{a or "off"}--{b or "off"}.json' for a in LAYERS for b in LAYERS}|{'cipher-aes128.json','cipher-chacha20.json'}|{f'hysteria2--{a or "off"}--{b or "off"}.json' for a in LAYERS for b in LAYERS}
PACKET_FILES={f'packet-{protocol}--final-{final}--{a or "off"}--{b or "off"}.json' for protocol in ("wireguard","amneziawg") for final in ("shadowsocks","hysteria2") for a in LAYERS for b in LAYERS}
PACKET_FINAL_FILES={"final-"+mode+"--"+name for mode in ("wg","awg2-fast","awg2-strong") for name in BASE_FILES}
NESTED_FILES={f'packet-{protocol}--final-{final}--{a or "off"}--{b or "off"}.json' for protocol in ("wireguard","amneziawg") for final in ("wg","awg2-fast","awg2-strong") for a in LAYERS for b in LAYERS}
SOCKS_FILES={"socks5--final-"+mode+".json" for mode in ("shadowsocks","hysteria2","wg","awg2-fast","awg2-strong")}
FILES=SOCKS_FILES|NESTED_FILES|PACKET_FINAL_FILES|PACKET_FILES|BASE_FILES|{"final-hysteria2--"+name for name in BASE_FILES}
CORE={
 'TestImportedEntrySOCKSPacketFinalGraphs':["wg","awg2-fast","awg2-strong"],
 'TestImportedEntrySOCKSPacketAuthorityAndMTU':["missing-proof","wrong-wg-peer","wrong-final-kind","final-jumbo","entry-jumbo","fixed-entry-conflict","fixed-final","retained-source"],
 'TestImportedEntrySOCKSRuntimeDistinctProofsAndSelectedDNS':["success","wrong-public-ip","wrong-paired-final","dns-failure","cancel-during-dns","missing-dns-capability","changed-owner"],
 'TestImportedEntrySOCKSPairedFinalGraphs':["shadowsocks","hysteria2"],
 'TestImportedEntrySOCKSRejectsChangedSource':["username","password","server","port","version","paired-identity","unsupported-final","server-execution","entry-layer","final-layer"],
 'TestImportedEntryNestedPacketCompleteGraphs':sorted(name.removesuffix(".json") for name in NESTED_FILES),
 'TestImportedEntryNestedPacketRefusesInsufficientEntry':[],
 'TestImportedEntryPacketFinalCompleteGraphs':sorted(name.removesuffix(".json") for name in PACKET_FINAL_FILES),
 'TestImportedEntryPacketFinalOwnershipAndMTU':["packet-wg","packet-awg","missing-start","wrapped-start","foreign-start","missing-proof","wrong-wg-peer","wrong-final-kind","final-jumbo","entry-jumbo","fixed-final","fixed-entry-conflict","retained-source"],
 'TestImportedEntryPacketCompleteGraphs':sorted(name.removesuffix(".json") for name in PACKET_FILES),
 'TestImportedEntryPacketSourceAndMTUOwnership':["private-key","public-key","psk","address","allowed-ips","endpoint","keepalive","awg-parameter","system","foreign-endpoint","entry-fixed","entry-jumbo","retained-source"],
 'TestImportedEntryHysteriaFinalCompleteGraphs':sorted(name.removesuffix(".json") for name in BASE_FILES),
 'TestImportedEntryHysteriaFinalRejectsUnownedLayerAndTrust':["missing-start","wrapped-start","foreign-start","insecure-final","missing-cert","wrong-final-kind","unused-start"],
 'TestImportedEntryHysteriaPairedFinalCompleteLayers':[ (a or "off")+"/"+(b or "off") for a in LAYERS for b in LAYERS],
 'TestImportedEntryHysteriaRejectsChangedSource':["password","server","tls-name","tls-disabled","tls-insecure","foreign-protocol","missing-layer","changed-layer","paired-identity","server-execution"],
 'TestImportedEntryRuntimeLocalSelectionRetiresWithOriginalOwner':[],
 'TestImportedEntryLegacyPairedFinalKeepsOriginalSource':['absent','empty','null','number','external','unpaired'],
 'TestImportedEntryPairedFinalCompleteLayers': [a+'/'+b for a in LAYERS for b in LAYERS],
 'TestImportedEntryPairedFinalRejectsChangedAuthority': ['fake-entry-proof','fake-entry-api','server','same-id','final-not-paired','wrong-entry-public-ip','conflicting-mtu'],
 'TestImportedEntryRuntimeDistinctProofsAndSelectedDNS': ['success','wrong-public-ip','wrong-paired-final','dns-failure','cancel-during-dns','missing-dns-capability','changed-owner'],
 'TestImportedEntryPairedFinalPolicyAndCipherOwnership': ['2022-blake3-aes-128-gcm','2022-blake3-aes-256-gcm','2022-blake3-chacha20-poly1305','entry-fixed','entry-jumbo','entry-cover-refused','paired-final-cover'],
}
SOCKS_PACKET_PEERS=[mode+"/"+fault for mode in ("wg","awg2-fast","awg2-strong") for fault in ("success","entry-key","auth-downgrade","relay-route","control-eof","final-private-key","final-public-key","final-psk","final-route","dns-route","final-identity","entry-public-ip")] + [mode+"/final-awg-parameter" for mode in ("awg2-fast","awg2-strong")] + ["wg","awg2-fast","awg2-strong"]
SOCKS_PEERS=[mode+'/'+fault for mode in ('shadowsocks','hysteria2') for fault in ('success','wrong-entry-ip','entry-auth','auth-downgrade','relay-route','control-eof','final-key','final-route','dns-route','final-identity')] + ['shadowsocks','hysteria2']
NESTED_PEERS=['success-ipv6-carrier','success-wg-wg','success-awg-fast-wg','success-awg-strong-awg','success-final-layer','success-entry-layer','success-both-layers','final-private-key','final-public-key','final-psk','final-awg-parameter','entry-key','entry-public-key','entry-psk','entry-awg-parameter','entry-layer-key','outer-layer-key','final-route','dns-route','final-identity','entry-public-ip']
PACKET_FINAL_PEERS=['success-wg-ss','success-awg-fast-ss','success-awg-strong-hy2','success-final-layer','final-private-key','final-public-key','final-psk','final-awg-parameter','entry-key','entry-sni','entry-trust','outer-layer-key','final-route','dns-route','final-identity','entry-public-ip']
PACKET_PEERS=['success-wg-ss','success-awg-hy2','success-entry-layer','private-key','public-key','psk','awg-parameter','entry-route','outer-layer-key','final-key','final-route','dns-route','final-identity','entry-public-ip']
FINAL_HYSTERIA_PEERS=['success-ss','success-hysteria','success-final-layer','final-password','final-sni','final-trust','outer-layer-key','final-route','dns-route','final-identity']
HYSTERIA_PEERS=['success','password','sni','trust','final-key','final-route','dns-route','final-identity']
PEERS=['success','entry-key','final-key','final-route','dns-route','final-identity']
def names(groups):
 return {name for parent,leaves in groups.items() for name in [parent,*[parent+'/'+leaf for leaf in leaves]]}
def require_verdicts(raw, expected):
 starts={};passes={}
 for line in raw.splitlines():
  try:event=json.loads(line)
  except json.JSONDecodeError:continue
  name=event.get('Test');action=event.get('Action')
  if not name:continue
  if name not in expected:raise ValueError('Foreign native verdict: '+name)
  if action in ('fail','skip'):raise ValueError('Required native case did not pass: '+name)
  if action=='run':starts[name]=starts.get(name,0)+1
  if action=='pass':passes[name]=passes.get(name,0)+1
 if starts!={n:1 for n in expected} or passes!={n:1 for n in expected}:raise ValueError('Missing or duplicated exact native verdict')
def checked_sources(vendor,peers):
 files={'mobile/routervpn_imported_entry.go.tmpl':'experimental/libbox/routervpn_imported_entry.go','mobile/routervpn_imported_entry_native_test.go.tmpl':'experimental/libbox/routervpn_imported_entry_native_test.go','mobile/strategy/box.go.tmpl':'routervpn_strategy_dns.go','mobile/mtu/bridge.go.tmpl':'experimental/libbox/routervpn_mtu_bridge.go'}
 if peers:files={'mobile/desktop/node_imported_socks_packet_test.go.tmpl':'protocol/routervpnamnezia/routervpn_imported_socks_packet_test.go','mobile/desktop/node_imported_socks_entry_test.go.tmpl':'protocol/routervpnamnezia/routervpn_imported_socks_entry_test.go','mobile/desktop/node_imported_nested_packet_test.go.tmpl':'protocol/routervpnamnezia/routervpn_imported_nested_packet_test.go','mobile/desktop/node_imported_packet_final_test.go.tmpl':'protocol/routervpnamnezia/routervpn_imported_packet_final_test.go','mobile/desktop/node_imported_packet_test.go.tmpl':'protocol/routervpnamnezia/routervpn_imported_packet_test.go','mobile/desktop/node_external_wireguard_installed_test.go.tmpl':'protocol/routervpnamnezia/routervpn_desktop_external_wireguard_installed_test.go','mobile/desktop/node_external_amnezia_installed_test.go.tmpl':'protocol/routervpnamnezia/routervpn_desktop_external_amnezia_installed_test.go','mobile/desktop/node_imported_hysteria_final_test.go.tmpl':'protocol/routervpnamnezia/routervpn_imported_hysteria_final_test.go','mobile/desktop/node_imported_router_entry_test.go.tmpl':'protocol/routervpnamnezia/routervpn_imported_router_entry_test.go','mobile/desktop/node_imported_hysteria_entry_test.go.tmpl':'protocol/routervpnamnezia/routervpn_imported_hysteria_entry_test.go','mobile/desktop/node_layer_peer_test.go.tmpl':'protocol/routervpnamnezia/routervpn_desktop_node_layer_peer_test.go','mobile/desktop/node_external_ss_entry_test.go.tmpl':'protocol/routervpnamnezia/routervpn_desktop_external_ss_entry_test.go'}
 for source,target in files.items():
  path=vendor/target
  if path.is_symlink() or not path.is_file() or path.read_bytes()!=(ROOT/source).read_bytes():raise ValueError('Changed native imported-entry source: '+target)
 # The native core must run the same source compiler, not an old matching-name implementation.
 import importlib.util
 spec=importlib.util.spec_from_file_location('imported_mobile_projection',ROOT/'deploy/prepare-mobile-multihop.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 for source in (ROOT/'internal/mobilemultihop').glob('*.go'):
  if source.name=='core_config_test.go':continue
  raw=m.OBSERVATION.rewrite(source.read_bytes())
  for package in m.PACKAGES:raw=raw.replace(('"router-vpn/internal/'+package+'"').encode(),('"github.com/sagernet/sing-box/experimental/libbox/routervpn/'+package+'"').encode())
  path=vendor/'experimental/libbox/routervpn/mobilemultihop'/source.name
  if path.is_symlink() or not path.is_file() or path.read_bytes()!=raw:raise ValueError('Changed native imported-entry compiler: '+source.name)
def execute(command,cwd,env,expected,timeout=600):
 result=subprocess.run(command,cwd=cwd,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout)
 if result.returncode:
  events=[]
  for line in result.stdout.splitlines():
   try:events.append(json.loads(line))
   except json.JSONDecodeError:pass
  failed={event.get('Test') for event in events if event.get('Action')=='fail' and event.get('Test')}
  detail='\n'.join(event.get('Output','') for event in events if event.get('Test') in failed or event.get('Action')=='build-output')
  raise ValueError('Required imported-entry execution failed:\n'+(detail or result.stdout)[-24000:])
 require_verdicts(result.stdout,expected)
 return result.stdout
def run(vendor,peers=False,android=False):
 vendor=vendor.resolve(strict=True)
 if subprocess.check_output(['git','-C',str(vendor),'rev-parse','HEAD'],text=True).strip()!=PIN:raise ValueError('Wrong native source pin')
 checked_sources(vendor,peers)
 subprocess.run([sys.executable,str(ROOT/'deploy/test_mobile_imported_entry_runner.py')],cwd=ROOT,check=True,timeout=30)
 env=dict(os.environ,GOTOOLCHAIN='go1.26.3',GOWORK='off')
 for key in ('GOOS','GOARCH'):env[key]=subprocess.check_output(['go','env','GOHOST'+key[2:]],text=True,env=env).strip()
 with tempfile.TemporaryDirectory(prefix='routervpn-imported-entry-') as temporary:
  fixtures=Path(temporary)/'sources';fixtures.mkdir();env['ROUTERVPN_IMPORTED_ENTRY_FIXTURES']=str(fixtures);env['ROUTERVPN_REQUIRE_IMPORTED_ENTRY_FIXTURES']='1'
  execute(['go','test','-mod=readonly','-race','-json','./internal/mobilemultihop','-run','^TestImportedEntry','-count=1','-timeout=60s'],ROOT,env,names(CORE))
  if {p.name for p in fixtures.iterdir()}!=FILES:raise ValueError('Incomplete captured imported source matrix')
  groups={'TestRouterImportedEntryPairedFinalNativeGraphs':sorted(FILES)}
  if android:
   folder=Path(temporary)/'android';folder.mkdir();env['ROUTERVPN_ANDROID_IMPORTED_ENTRY_FIXTURES']=str(folder)
   subprocess.run([sys.executable,str(ROOT/'android/test_android_imported_router.py')],cwd=ROOT,env=env,check=True,timeout=240)
   exported={p.name for p in folder.iterdir()}
   if exported!={'android-'+name for name in FILES} or any(p.is_symlink() or not p.is_file() for p in folder.iterdir()):raise ValueError('Incomplete actual Android source matrix')
   groups['TestRouterImportedEntryAndroidSourceGraphs']=sorted(exported)
  tags='with_wireguard,with_gvisor,with_quic,with_utls,with_openvpn,with_naive_outbound,with_purego'
  base=['go','test','-mod=readonly','-json','-ldflags=-checklinkname=0','-tags',tags]
  selector='^('+'|'.join(groups)+')$'
  if not peers:execute(base+['./experimental/libbox','-run',selector,'-count=1','-timeout=90s'],vendor,env,names(groups))
  if peers:execute(base+['-race','./protocol/routervpnamnezia','-run','^(TestRouterVPNImported(SOCKSPacketFinal|SOCKSPairedFinal|EntryPairedFinal|HysteriaPairedFinal|HysteriaFinal|Packet|PacketFinal|NestedPacket)NativeTraffic|TestRouterVPNDesktopLayerInitialPacketRetirement)$','-count=1','-timeout=90s'],vendor,env,names({'TestRouterVPNImportedSOCKSPacketFinalNativeTraffic':SOCKS_PACKET_PEERS,'TestRouterVPNDesktopLayerInitialPacketRetirement':['original-packet-and-blocked-reader-join','concurrent-initial-read-and-retirement'],'TestRouterVPNImportedSOCKSPairedFinalNativeTraffic':SOCKS_PEERS,'TestRouterVPNImportedNestedPacketNativeTraffic':NESTED_PEERS,'TestRouterVPNImportedPacketFinalNativeTraffic':PACKET_FINAL_PEERS,'TestRouterVPNImportedPacketNativeTraffic':PACKET_PEERS,'TestRouterVPNImportedEntryPairedFinalNativeTraffic':PEERS,'TestRouterVPNImportedHysteriaPairedFinalNativeTraffic':HYSTERIA_PEERS,'TestRouterVPNImportedHysteriaFinalNativeTraffic':FINAL_HYSTERIA_PEERS}))
 checked_sources(vendor,peers)
 print('Exact imported-entry source, independent layers, distinct proofs, selected DNS and native verdicts passed; no OS device grant inferred.')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('vendor',type=Path);p.add_argument('--native-peers',action='store_true');p.add_argument('--android',action='store_true');args=p.parse_args();run(args.vendor,args.native_peers,args.android)
