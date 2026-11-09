#!/usr/bin/env python3
"""Execute captured imported-entry/paired-final compiler and actual native gates."""
import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'deploy'))
import mobile_imported_openvpn_cases as OPENVPN
PIN='1ac1a339cb1223e9c70eae14c44411c75033c02d'
LAYERS=('', 'aes-256-gcm', 'aes-256-gcm+xor-whitening')
BASE_FILES={f'{a or "off"}--{b or "off"}.json' for a in LAYERS for b in LAYERS}|{'cipher-aes128.json','cipher-chacha20.json'}|{f'hysteria2--{a or "off"}--{b or "off"}.json' for a in LAYERS for b in LAYERS}
PACKET_FILES={f'packet-{protocol}--final-{final}--{a or "off"}--{b or "off"}.json' for protocol in ("wireguard","amneziawg") for final in ("shadowsocks","hysteria2") for a in LAYERS for b in LAYERS}
PACKET_FINAL_FILES={"final-"+mode+"--"+name for mode in ("wg","awg2-fast","awg2-strong") for name in BASE_FILES}
NESTED_FILES={f'packet-{protocol}--final-{final}--{a or "off"}--{b or "off"}.json' for protocol in ("wireguard","amneziawg") for final in ("wg","awg2-fast","awg2-strong") for a in LAYERS for b in LAYERS}
def socks_label(mode,a,b):
 if not a and not b:return mode
 if not a:return mode+'--'+b
 if not b:return mode+'--entry-'+a
 return mode+'--'+(a or 'off')+'--'+(b or 'off')
SOCKS_FILES={'socks5--final-'+socks_label(mode,a,b)+'.json' for mode in ('shadowsocks','hysteria2','wg','awg2-fast','awg2-strong') for a in LAYERS for b in LAYERS}
SOCKS_XRAY_FILES={'socks5--final-'+socks_label('reality-vision',a,b)+'.json' for a in LAYERS for b in LAYERS}
SOCKS_XRAY_PARSER='TestRouterImportedSOCKSRealityVisionNativeGraph'
CONNECT_LAYER_ROWS=[p+"--"+entry+"--"+final+"--"+dns for p in ("http-connect","https-connect") for entry in LAYERS[1:] for final in ("plain","off",*LAYERS[1:]) for dns in ("home","custom")]
CONNECT_LAYER_FILES={name+".json" for name in CONNECT_LAYER_ROWS}
def connect_layer_peers(protocol):
 rows=[]
 for entry in LAYERS[1:]:
  for final in ("plain","off",*LAYERS[1:]):
   for dns in ("home","custom"):
    label=protocol+"--"+entry+"--"+final+"--"+dns;faults=["success"]
    if dns=="home":
     faults.append("final-key")
     if final==LAYERS[2]:
      faults += ["entry-auth","entry-private","entry-layer-key","final-whitening","final-route","dns-route","final-identity","wrong-entry-ip","cancel","close-owner"]
      if entry==LAYERS[2]:faults.append("entry-whitening")
      if protocol=="https-connect":faults += ["sni","trust"]
    rows += [label,*[label+"/"+fault for fault in faults]]
 return rows
CONNECT_LAYER_PEERS={"TestRouterVPNImportedHTTPLayersNativeTraffic":connect_layer_peers("http-connect"),"TestRouterVPNImportedHTTPSLayersNativeTraffic":connect_layer_peers("https-connect")}
CONNECT_ROWS=[p+"--"+m+"--"+d for p in ("http-connect","https-connect") for m in ("2022-blake3-aes-128-gcm","2022-blake3-aes-256-gcm","2022-blake3-chacha20-poly1305") for d in ("home","custom")]
CONNECT_FILES={"connect--"+row+".json" for row in CONNECT_ROWS}
CONNECT_SERVICE_FILES={p+"--"+l+"--"+d+"--"+t+".json" for p in ("http-connect","https-connect") for l in ("off",*LAYERS[1:]) for d in ("home","custom") for t in ("udp","tcp")}
CONNECT_PEERS=[row+"/success" for row in CONNECT_ROWS]+CONNECT_ROWS
for protocol in ("http-connect","https-connect"):
 row=protocol+"--2022-blake3-aes-256-gcm--home"
 CONNECT_PEERS += [row+"/"+fault for fault in ("entry-auth","entry-route","final-key","final-route","dns-route","final-identity","wrong-entry-ip","cancel","close-owner","mtu-refusal","mtu-cancel","mtu-successor")]
 if protocol=="https-connect":CONNECT_PEERS += [row+"/"+fault for fault in ("sni","trust")]
CONTEXT_CORE={'TestImportedOwnerContextRetiresHeldControllerRead':['identity','selection'],'TestImportedStartupCloseJoinsAdmittedIdentityRead':[],'TestImportedProofContextUsesAdmittedReader':['entry-proof','private-proof','owner-check','measurement-proof'],'TestImportedMeasurementClosesLateOriginalConnection':['cancel','hop-owner','controller-owner'],'TestImportedHopLegacyConstructorKeepsOneObservationBudget':[],'TestImportedHopConstructorRetainsCallerAndOwner':['current','nil','cancel-before','health','capture','recheck','service','hop-replaced','controller-replaced']}
CONTEXT_NATIVE={'TestRouterNativeProofContextRetiresHeldReads':['identity','dial','dns','hop-identity','hop-dial','capture','selected','manager-dial','manager-selected'],'TestRouterNativeProofDialClosesLateConnection':['cancel','instance-replaced','outbound-replaced','connection-and-error'],'TestRouterNativeHopConstructorsRetainCaller':['paired','imported']+[kind+'/'+phase for kind in ('paired','imported') for phase in ('current','legacy','nil','cancel-before','instance-held','selector-held','instance-replaced')]}
CONTEXT_CORE.update({'TestExternalMeasurementLegacyConstructorKeepsOriginalBudget':[], 'TestExternalMeasurementConstructorRetainsCallerAndProof':['current','nil','cancel-before','proof-health','capture','service','measurement-replaced','proof-replaced'], 'TestExternalMeasurementContextOwnsActivityAndLateConnection':['activity','activity-cancel','activity-replaced','activity-error','activity-empty','dial-cancel','dial-replaced','dial-proof-replaced','dial-error','dial-empty','verify-cancel']})
CONTEXT_NATIVE['TestRouterExternalHopContextKeepsOriginalNativeOwner']=['current','legacy','nil','cancel-before','instance-held','engine-held','manager-held','instance-replaced','activity-held','unproved','source-changed','missing-observer']
CONTEXT_CORE.update({'TestExternalProofLegacyConstructorKeepsOriginalBudget':[], 'TestExternalProofConstructorRetainsCallerAndIndependentLifetime':['current','nil-caller','nil-parent','cancel-before','parent-cancel-before','capture-held','recheck-held','owner-replaced','parent-retired-late','caller-retired-late','missing-bounded-reader']})
CONTEXT_NATIVE['TestRouterExternalProofContextOwnsNativeCapture']=['current','legacy','nil','cancel-before','instance-held','tun-held','outbound-held','dns-held','instance-replaced','tun-replaced','source-changed']
CONTEXT_CORE.update({'TestExternalDNSAuthorityLegacyKeepsOriginalBudget':[], 'TestExternalDNSAuthorityContextKeepsOriginalProof':['current','nil','cancel-before','health-held','path-held','final-held','path-replaced','final-replaced','unproved','source','session']})
CONTEXT_DNS={'TestDNSConstructorRetainsOriginalCallerAndSelectedEndpoint':['current','nil','cancel-before','capture-held','recheck-held','owner-replaced','late-cancel','missing-observer','invalid-selected']}
CONTEXT_NATIVE['TestRouterExternalDNSConstructorKeepsCapturedNativeOwner']=['current','legacy','nil','cancel-before','instance-held','engine-held','dns-held','instance-replaced','unproved','source-changed','dns-policy','session-changed','missing-observer']
CONTEXT_DNS.update({'TestDNSPendingAdmissionKeepsCancellationAndScopeOwner':['identity-cancel','activity-cancel','recheck-cancel','late-scope-release','owner-replaced','close-admission','invalidate-admission'], 'TestDNSObservationKeepsOperationAndReplacementOwners':['successful-queries','watch-cancel','stale-status','cancelled-status']})
CONTEXT_NATIVE['TestRouterExternalDNSOperationsKeepOriginalNativeContext']=['identity','verify','activity','selected-dns','catalog-dial','service-start','status','instance-replaced','activity-current','scope-busy','cancel-before']
CONTEXT_CORE.update({'TestExternalProofRunRetainsOriginalCaller':['success','nil','cancel-before','identity','admission','private-entry','public-entry','dns','exit','delivery','late-entry','late-dns','late-exit','replaced-entry','replaced-dns','replaced-exit','close','owner-cancel'], 'TestExternalProofRunOwnsConnectedRemoteObservation':['success','capture-held','capture-replaced','readback-held','readback-replaced','pending-cancel'], 'TestExternalProofRunCannotAdoptReplacementComparison':['before-admission','during-capture','caller-ended-capture'], 'TestExternalProofRetainedLegacyObservationsKeepBoundedCaller':['health','path','execution']})
CONTEXT_NATIVE['TestRouterExternalProofRunKeepsOriginalNativeContext']=['current','legacy','nil','cancel-before','instance-held','engine-held','tun-held','outbound-held','dns-held','instance-replaced','tun-replaced','dns-cancel','exit-cancel','delivery-cancel','close','owner-cancel','health-held','execution-held']
CONTEXT_CORE['TestExternalProofDefaultRunKeepsCapturedLifetimeAndPhaseBudgets']=[]
CONTEXT_CORE['TestExternalProofRunCancellationOwnsAdmissionLocks']=['run-mutex-caller','run-mutex-owner','controller-admission','controller-capture']
CONTEXT_CORE.update({'TestExternalSelectionKeepsOriginalTrialAndFinalCaller':['current','nil','cancel-before','trial-cancel','trial-owner','trial-late-success','final-cancel','final-owner','final-late-success','missing-context'], 'TestExternalSelectionCancellationJoinsEnteredCommit':[]})
CONTEXT_NATIVE['TestRouterNativeProofContextRetiresHeldReads'] += ['select','manager-select']
CONTEXT_SELECTION_BOX={'TestRouterVPNExternalSelectionContextOwnsAdmission':['current','legacy','nil','cancel-before','engine-held','outbound-held','selector-held','interrupt-held','history-held','owner-replaced','candidate-refused'], 'TestRouterVPNExternalSelectionContextJoinsNativeCommit':['cache-cancel','close-cancel','cache-replaced','close-replaced','cache-error','same-candidate','close-updates-history'], 'TestRouterVPNExternalSelectionRetainsRealCacheCommit':['current','writer-joined'], 'TestRouterVPNExternalSelectionJoinsLateHistoryContention':[], 'TestRouterVPNExternalSelectionKeepsInterruptFilter':['internal-only','including-external']}
CONTEXT_DNS_BOX={'TestRouterVPNDNSNativeDialKeepsOriginalObservation':['capture-held','recheck-held','cancel-before'], 'TestRouterVPNDNSNativeDialRetainsLateSocketOnCancellationReplacementAndError':['caller','owner','native-error'], 'TestRouterVPNDNSNativeDialEnforcesFixedCatalogBeforeNativeRoute':[], 'TestRouterVPNDNSServiceRetainsActualNativeAdapterSocketAndActivityUntilCloseRetry':[], 'TestRouterVPNDNSServiceRetiresAlreadyClosedActualNativeAdapterSocket':['use_of_closed_network_connection','io:_read/write_on_closed_pipe']}
FILES=OPENVPN.FILES|CONNECT_FILES|SOCKS_FILES|SOCKS_XRAY_FILES|NESTED_FILES|PACKET_FINAL_FILES|PACKET_FILES|BASE_FILES|{"final-hysteria2--"+name for name in BASE_FILES}
CONNECT_DNS_ROWS=[p+"/"+l+"/"+t+"/"+a for p in ("http-connect","https-connect") for l in ("plain","off",*LAYERS[1:]) for t in ("tls","https","h3") for a in ("literal","hostname") if not(l=="plain" and t=="h3")]
CONNECT_DNS_FILES={row.replace("/","--")+".json" for row in CONNECT_DNS_ROWS}
CORE={
 "TestImportedEntrySOCKSRealityVisionCapturedGraphs":["default-home","explicit-off","custom-udp","custom-tcp","ipv6-off","lan-off","fixed-mtu"],
 "TestImportedEntrySOCKSRealityVisionEncryptedDNS":[p+"/"+a for p in ("tls","https","h3") for a in ("literal","hostname")],
 "TestImportedEntrySOCKSRealityVisionRejectsChangedSources":["entry-credential","entry-route","entry-version","fake-entry-proof","fake-entry-api","same-id","final-not-paired","missing-final-proof","missing-final-token","missing-xray","foreign-wrapper","xray-bypass","xray-plaintext","mode-mismatch","server","compare","unused-start","foreign-bootstrap"],
 "TestImportedEntrySOCKSRealityVisionKeepsScope":["final-"+p for p in ("reality-pq-vision","reality-xhttp","split","max")]+["entry-"+p for p in ("shadowsocks","hysteria2","wireguard","amneziawg","http-connect","https-connect","openvpn")],
 "TestImportedEntrySOCKSRealityVisionIndependentLayers":[socks_label("reality-vision",a,b) for a in LAYERS for b in LAYERS],
 "TestImportedEntrySOCKSRealityVisionLayerAuthority":["entry-missing","entry-mismatch","entry-foreign","entry-off-unused","entry-invalid","final-missing","final-foreign","final-off-unused","final-invalid","entry-detour","final-wrapper-detour","final-xray-bypass","server","compare"],
 "TestImportedEntrySOCKSRealityVisionRetainsOriginalBytes":["entry-graph","entry-capture","final-assets","final-profile"],
 "TestImportedEntrySOCKSRealityVisionRequiresBothProofsAndDNS":["success","wrong-public-ip","wrong-paired-final","dns-failure","cancel-during-dns","missing-dns-capability","changed-owner"],
 "TestImportedEntrySOCKSRealityVisionRetainedRuntime":["close","network-change","replacement"],
 "TestImportedEntryCONNECTIndependentLayers":CONNECT_LAYER_ROWS,
 "TestImportedEntryCONNECTIndependentLayerRefusals":["missing-provision","foreign-outer","public-inside","mode-mismatch","unused-provision","borrowed-final-transport","invented-entry-api","server","compare","metadata-only"],
 "TestImportedEntryCONNECTSelectedEncryptedDNS":CONNECT_DNS_ROWS,
 "TestImportedEntryCONNECTSelectedDNSRefusals":["plain-h3","plain-udp-bootstrap","missing-bootstrap","foreign-bootstrap-route","foreign-query","hostname-bootstrap","unused-bootstrap","insecure-tls","changed-home","unknown-protocol"],
 "TestImportedEntryCONNECTSelectedDNSProviders":["plain-home-tls","plain-home-https","plain-rescue","uot-home-tls","uot-home-https","uot-home-h3","uot-rescue","uot-fastest"],
 "TestImportedEntryCONNECTServiceConfiguredGraphs":[p+"/"+l+"/"+d+"/"+t for p in ("http-connect","https-connect") for l in ("off",*LAYERS[1:]) for d in ("home","custom") for t in ("udp","tcp")],
 "TestImportedEntryCONNECTServiceAuthorityRefusals":["missing","foreign-node","stale-source","wrong-key","wrong-port","wrong-image","wrong-version","extra-asset","entry-layer","unsupported-layer","inline-uot","dns-h3","wrong-home"],
 "TestImportedEntryCONNECTServiceDefaultHomeAndInvalidTCPAuthority":["default-home","tcp-foreign-node","tcp-malformed","tcp-stale-source"],
 "TestImportedEntryCONNECTGraphs":CONNECT_ROWS,
 "TestImportedEntryCONNECTBoundaries":["udp-dns","h3-dns","dot-dns","default-dns","hostname-dns","home-owner","entry-layer","final-layer","hy-final","wg-final","awg-final","legacy-cipher","uot-enabled","uot-disabled","uot-malformed","server-execution","retained-source"],
 'TestImportedEntrySOCKSBothLayerMTURetention':[mode+"/"+entry+"/"+final for mode in ("shadowsocks","hysteria2","wg","awg2-fast","awg2-strong") for entry in LAYERS[1:] for final in LAYERS[1:]],
 'TestImportedEntrySOCKSBothLayerBounds':["ipv6-carrier","port53-control","entry-eih","final-eih","invalid-key","missing-final-layer","changed-entry-owner"],
 'TestImportedEntrySOCKSEntryLayers':[mode+"/"+layer for mode in ("shadowsocks","hysteria2","wg","awg2-fast","awg2-strong") for layer in LAYERS[1:]],
 'TestImportedEntrySOCKSEntryLayerAuthority':["missing-provision","foreign-outer","public-private-target","mode-mismatch","unused-provision","both-layers","invented-proof","retained-source"],
 'TestImportedEntrySOCKSPacketFinalLayers':[mode+"/"+layer for mode in ("wg","awg2-fast","awg2-strong") for layer in LAYERS[1:]],
 'TestImportedEntrySOCKSPacketLayerAuthority':["missing-source","foreign-endpoint","private-target","final-jumbo","fixed-conflict","retained-source"],
 'TestImportedEntrySOCKSPairedFinalLayers':[mode+"/"+layer for mode in ("shadowsocks","hysteria2") for layer in LAYERS[1:]],
 'TestImportedEntrySOCKSLayerBoundaries':["missing-final-source","foreign-final-source","unused-final-source","packet-final-layer","entry-layer"],
 'TestImportedEntrySOCKSPacketFinalGraphs':[socks_label(m,a,b) for m in ('wg','awg2-fast','awg2-strong') for a in LAYERS for b in LAYERS],
 'TestImportedEntrySOCKSPacketAuthorityAndMTU':["missing-proof","wrong-wg-peer","wrong-final-kind","final-jumbo","entry-jumbo","fixed-entry-conflict","fixed-final","retained-source"],
 'TestImportedEntrySOCKSRuntimeDistinctProofsAndSelectedDNS':["success","wrong-public-ip","wrong-paired-final","dns-failure","cancel-during-dns","missing-dns-capability","changed-owner"],
 'TestImportedEntrySOCKSPairedFinalGraphs':[socks_label(m,a,b) for m in ('shadowsocks','hysteria2') for a in LAYERS for b in LAYERS],
 'TestImportedEntrySOCKSRejectsChangedSource':["username","password","server","port","version","paired-identity","unsupported-final","server-execution","entry-layer","final-layer","entry-layer-unprovisioned","entry-layer-mismatch","final-layer-unprovisioned"],
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
SOCKS_ENTRY_PROXY_PEERS=[mode+"/"+layer+"/"+fault for mode in ("shadowsocks","hysteria2") for layer in LAYERS[1:] for fault in (("success","wrong-entry-ip","entry-auth","auth-downgrade","relay-route","control-eof","final-key","final-route","dns-route","final-identity","entry-layer-key","entry-private") + (("entry-whitening",) if layer==LAYERS[2] else ()))] + [mode+"/"+layer for mode in ("shadowsocks","hysteria2") for layer in LAYERS[1:]]
SOCKS_ENTRY_PACKET_PEERS=[layer+"/"+mode+"/"+fault for layer in LAYERS[1:] for mode in ("wg","awg2-fast","awg2-strong") for fault in (("success","entry-key","auth-downgrade","relay-route","control-eof","final-private-key","final-public-key","final-psk","final-route","dns-route","final-identity","entry-public-ip","entry-layer-key","entry-private") + (("final-awg-parameter",) if mode!="wg" else ()) + (("entry-whitening",) if layer==LAYERS[2] else ()))] + [layer+"/"+mode for layer in LAYERS[1:] for mode in ("wg","awg2-fast","awg2-strong")] + list(LAYERS[1:])
SOCKS_PACKET_LAYER_PEERS=[layer+"/"+mode+"/"+fault for layer in LAYERS[1:] for mode in ("wg","awg2-fast","awg2-strong") for fault in (("success","entry-key","auth-downgrade","relay-route","control-eof","final-private-key","final-public-key","final-psk","final-route","dns-route","final-identity","entry-public-ip","layer-key") + (("final-awg-parameter",) if mode!="wg" else ()) + (("whitening",) if layer==LAYERS[2] else ()))] + [layer+"/"+mode for layer in LAYERS[1:] for mode in ("wg","awg2-fast","awg2-strong")] + list(LAYERS[1:])
SOCKS_PACKET_PEERS=[mode+"/"+fault for mode in ("wg","awg2-fast","awg2-strong") for fault in ("success","entry-key","auth-downgrade","relay-route","control-eof","final-private-key","final-public-key","final-psk","final-route","dns-route","final-identity","entry-public-ip")] + [mode+"/final-awg-parameter" for mode in ("awg2-fast","awg2-strong")] + ["wg","awg2-fast","awg2-strong"]
SOCKS_PEERS=[mode+'/'+fault for mode in ('shadowsocks','hysteria2') for fault in ('success','wrong-entry-ip','entry-auth','auth-downgrade','relay-route','control-eof','final-key','final-route','dns-route','final-identity')] + ['shadowsocks','hysteria2']
def socks_layer_peers(modes):
 result=[]
 for mode in modes:
  for a in LAYERS:
   for b in LAYERS:
    if not a and not b:continue
    label=socks_label(mode,a,b);faults=['success']
    if a:faults+=['entry-layer-key']
    if a.endswith('whitening'):faults+=['entry-layer-whitening']
    if b:faults+=['final-layer-key']
    if b.endswith('whitening'):faults+=['final-layer-whitening']
    if a and not b:faults+=['auth-downgrade','relay-route','control-eof']
    result += [label,*[label+'/'+fault for fault in faults]]
 return result
SOCKS_PEERS += socks_layer_peers(('shadowsocks','hysteria2'))
SOCKS_PACKET_PEERS += socks_layer_peers(('wg','awg2-fast','awg2-strong'))

SOCKS_LAYER_PEERS=[mode+'/'+layer+'/'+fault for mode in ('shadowsocks','hysteria2') for layer in LAYERS[1:] for fault in (('success','wrong-entry-ip','entry-auth','auth-downgrade','relay-route','control-eof','final-key','final-route','dns-route','final-identity') + (('layer-key',) if mode=='hysteria2' else ()) + (('whitening',) if layer==LAYERS[2] else ()))] + [mode+'/'+layer for mode in ('shadowsocks','hysteria2') for layer in LAYERS[1:]]

SOCKS_BOTH_PROXY_PEERS=[mode+"/"+entry+"/"+final+"/"+fault for mode in ("shadowsocks","hysteria2") for entry in LAYERS[1:] for final in LAYERS[1:] for fault in ("wrong-entry-ip","entry-auth","auth-downgrade","relay-route","control-eof","final-key","final-route","dns-route","final-identity","entry-private")] + [mode+"/"+entry+"/"+final for mode in ("shadowsocks","hysteria2") for entry in LAYERS[1:] for final in LAYERS[1:]]
def socks_both_packet_peers(entry):
 return [final+"/"+mode+"/"+fault for final in LAYERS[1:] for mode in ("wg","awg2-fast","awg2-strong") for fault in (("success","entry-key","auth-downgrade","relay-route","control-eof","final-private-key","final-public-key","final-psk","final-route","dns-route","final-identity","entry-public-ip","entry-private") + (("final-awg-parameter",) if mode!="wg" else ()))] + [final+"/"+mode for final in LAYERS[1:] for mode in ("wg","awg2-fast","awg2-strong")] + list(LAYERS[1:])
SOCKS_BOTH_GROUPS={'TestRouterVPNImportedSOCKSBothLayersProxyNativeTraffic':SOCKS_BOTH_PROXY_PEERS, 'TestRouterVPNImportedSOCKSBothLayersPacketAESNativeTraffic':socks_both_packet_peers(LAYERS[1]), 'TestRouterVPNImportedSOCKSBothLayersPacketXORNativeTraffic':socks_both_packet_peers(LAYERS[2])}

NESTED_PEERS=['success-ipv6-carrier','success-wg-wg','success-awg-fast-wg','success-awg-strong-awg','success-final-layer','success-entry-layer','success-both-layers','final-private-key','final-public-key','final-psk','final-awg-parameter','entry-key','entry-public-key','entry-psk','entry-awg-parameter','entry-layer-key','outer-layer-key','final-route','dns-route','final-identity','entry-public-ip']
PACKET_FINAL_PEERS=['success-wg-ss','success-awg-fast-ss','success-awg-strong-hy2','success-final-layer','final-private-key','final-public-key','final-psk','final-awg-parameter','entry-key','entry-sni','entry-trust','outer-layer-key','final-route','dns-route','final-identity','entry-public-ip']
PACKET_PEERS=['success-wg-ss','success-awg-hy2','success-entry-layer','private-key','public-key','psk','awg-parameter','entry-route','outer-layer-key','final-key','final-route','dns-route','final-identity','entry-public-ip']
FINAL_HYSTERIA_PEERS=['success-ss','success-hysteria','success-final-layer','final-password','final-sni','final-trust','outer-layer-key','final-route','dns-route','final-identity']
HYSTERIA_PEERS=['success','password','sni','trust','final-key','final-route','dns-route','final-identity']
PEERS=['success','entry-key','final-key','final-route','dns-route','final-identity']
# Preserve the complete phase/receipt union under the existing per-process
# budget. Each child still executes all five original causal recompilations.
ANDROID_PHASE_GROUPS=(
 tuple('openvpn--tcp--final-'+m for m in ('shadowsocks','hysteria2','wg','awg2-fast','awg2-strong')),
 tuple('openvpn--udp--final-'+m for m in ('shadowsocks','hysteria2','wg','awg2-fast','awg2-strong')),
 ('connect--http-connect','connect--https-connect','socks5--final-shadowsocks','socks5--final-hysteria2','socks5--final-reality-vision','shadowsocks','hysteria2'),
 ('socks5--final-wg','socks5--final-awg2-fast','socks5--final-awg2-strong','wg','awg2-fast','awg2-strong'),
 tuple('packet-'+entry+'--final-'+final for entry in ('wireguard','amneziawg') for final in ('shadowsocks','hysteria2','wg','awg2-fast','awg2-strong')),
 tuple('connect-entry-layers--'+protocol+'--'+layer for protocol in ('http-connect','https-connect') for layer in LAYERS[1:]),
)
def android_phase_files(phase):
 if phase.startswith('connect-entry-layers--'):
  axes=phase.split('--')
  if len(axes)!=3 or axes[1] not in ('http-connect','https-connect') or axes[2] not in LAYERS[1:]:raise ValueError('Unknown Android CONNECT layer phase')
  return set(),{'android-'+name for name in CONNECT_LAYER_FILES if name.startswith(axes[1]+'--'+axes[2]+'--')}
 if phase=='shadowsocks':selected=BASE_FILES
 elif phase in ('hysteria2','wg','awg2-fast','awg2-strong'):selected={name for name in FILES if name.startswith('final-'+phase+'--')}
 elif phase in ('connect--http-connect','connect--https-connect'):selected={name for name in CONNECT_FILES if name.startswith(phase+'--')}
 elif phase in {'socks5--final-'+m for m in ('shadowsocks','hysteria2','wg','awg2-fast','awg2-strong','reality-vision')}:selected={name for name in FILES if name==phase+'.json' or name.startswith(phase+'--')}
 elif phase in {'openvpn--'+p+'--final-'+m for p in ('tcp','udp') for m in ('shadowsocks','hysteria2','wg','awg2-fast','awg2-strong')} or phase in {'packet-'+p+'--final-'+m for p in ('wireguard','amneziawg') for m in ('shadowsocks','hysteria2','wg','awg2-fast','awg2-strong')}:selected={name for name in FILES if name.startswith(phase+'--')}
 else:raise ValueError('Unknown Android imported phase: '+phase)
 if not selected:raise ValueError('Empty Android imported phase: '+phase)
 return {'android-'+name for name in selected},set()
def android_group_inventory(groups=ANDROID_PHASE_GROUPS):
 phases=[p for group in groups for p in group]
 if len(groups)!=6 or any(not group for group in groups) or len(phases)!=37 or len(set(phases))!=len(phases):raise ValueError('Missing or duplicated Android phase owner')
 primary=set();layers=set();result=[]
 for group in groups:
  original=set();independent=set()
  for phase in group:
   a,b=android_phase_files(phase)
   if primary&a or layers&b:raise ValueError('Android phases duplicate original source receipts')
   primary.update(a);layers.update(b);original.update(a);independent.update(b)
  result.append((group,original,independent))
 if primary!={'android-'+name for name in FILES} or layers!={'android-'+name for name in CONNECT_LAYER_FILES}:raise ValueError('Incomplete Android original/layer phase union')
 return result
def merge_android_exports(source,destination,expected):
 if source.is_symlink() or not source.is_dir() or {p.name for p in source.iterdir()}!=expected:raise ValueError('Incomplete or foreign Android group exports')
 for name in sorted(expected):
  current=source/name;target=destination/name;info=current.lstat()
  if not stat.S_ISREG(info.st_mode) or not 0<info.st_size<=8*1024*1024 or target.exists() or target.is_symlink():raise ValueError('Unowned or duplicated Android group export: '+name)
 for name in sorted(expected):(source/name).rename(destination/name)
def run_android_sources(temporary,env):
 primary=temporary/'android';primary.mkdir()
 layers=temporary/'android-layers';layers.mkdir()
 for index,(phases,original,independent) in enumerate(android_group_inventory()):
  batch=temporary/('android-group-'+str(index));batch.mkdir()
  outputs=batch/'primary';outputs.mkdir()
  separate=batch/'layers';separate.mkdir()
  child_env=dict(env,ROUTERVPN_ANDROID_IMPORTED_ENTRY_FIXTURES=str(outputs),ROUTERVPN_ANDROID_CONNECT_LAYER_FIXTURES=str(separate))
  command=[sys.executable,str(ROOT/'android/test_android_imported_router.py')]
  for phase in phases:command+=['--phase',phase]
  subprocess.run(command,cwd=ROOT,env=child_env,check=True,timeout=240)
  merge_android_exports(outputs,primary,original)
  merge_android_exports(separate,layers,independent)
  print('Android source group '+str(index+1)+': '+str(len(original))+' primary and '+str(len(independent))+' independent CONNECT receipts; all original causal controls retained')
 if {p.name for p in primary.iterdir()}!={'android-'+name for name in FILES} or {p.name for p in layers.iterdir()}!={'android-'+name for name in CONNECT_LAYER_FILES}:raise ValueError('Incomplete joined Android source inventory')
 env.update(ROUTERVPN_ANDROID_IMPORTED_ENTRY_FIXTURES=str(primary),ROUTERVPN_ANDROID_CONNECT_LAYER_FIXTURES=str(layers))
 return primary,layers

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
 if peers:files={'mobile/desktop/node_imported_connect_entry_test.go.tmpl':'protocol/routervpnamnezia/routervpn_imported_connect_entry_test.go','mobile/desktop/node_external_ss_layers_test.go.tmpl':'protocol/routervpnamnezia/routervpn_desktop_node_external_ss_layers_test.go','mobile/desktop/node_imported_socks_packet_test.go.tmpl':'protocol/routervpnamnezia/routervpn_imported_socks_packet_test.go','mobile/desktop/node_imported_socks_entry_test.go.tmpl':'protocol/routervpnamnezia/routervpn_imported_socks_entry_test.go','mobile/desktop/node_imported_nested_packet_test.go.tmpl':'protocol/routervpnamnezia/routervpn_imported_nested_packet_test.go','mobile/desktop/node_imported_packet_final_test.go.tmpl':'protocol/routervpnamnezia/routervpn_imported_packet_final_test.go','mobile/desktop/node_imported_packet_test.go.tmpl':'protocol/routervpnamnezia/routervpn_imported_packet_test.go','mobile/desktop/node_external_wireguard_installed_test.go.tmpl':'protocol/routervpnamnezia/routervpn_desktop_external_wireguard_installed_test.go','mobile/desktop/node_external_amnezia_installed_test.go.tmpl':'protocol/routervpnamnezia/routervpn_desktop_external_amnezia_installed_test.go','mobile/desktop/node_imported_hysteria_final_test.go.tmpl':'protocol/routervpnamnezia/routervpn_imported_hysteria_final_test.go','mobile/desktop/node_imported_router_entry_test.go.tmpl':'protocol/routervpnamnezia/routervpn_imported_router_entry_test.go','mobile/desktop/node_imported_hysteria_entry_test.go.tmpl':'protocol/routervpnamnezia/routervpn_imported_hysteria_entry_test.go','mobile/desktop/node_layer_peer_test.go.tmpl':'protocol/routervpnamnezia/routervpn_desktop_node_layer_peer_test.go','mobile/desktop/node_external_ss_entry_test.go.tmpl':'protocol/routervpnamnezia/routervpn_desktop_external_ss_entry_test.go'}
 if peers:
  files['mobile/desktop/node_imported_openvpn_test.go.tmpl']='protocol/routervpnamnezia/routervpn_imported_openvpn_test.go'
  files['mobile/desktop/node_external_openvpn_installed_test.go.tmpl']='protocol/routervpnamnezia/routervpn_desktop_external_openvpn_installed_test.go'
 if not peers:
  files.update({'mobile/routervpn_multihop_bridge.go.tmpl':'experimental/libbox/routervpn_multihop_bridge.go','mobile/routervpn_hop_measurement.go.tmpl':'experimental/libbox/routervpn_hop_measurement.go','mobile/routervpn_multihop_context_test.go.tmpl':'experimental/libbox/routervpn_multihop_context_test.go'})
  files.update({'mobile/routervpn_external_measurement_bridge.go.tmpl':'experimental/libbox/routervpn_external_measurement_bridge.go','mobile/routervpn_external_measurement_context_test.go.tmpl':'experimental/libbox/routervpn_external_measurement_context_test.go','mobile/routervpn_external_policy_bridge.go.tmpl':'experimental/libbox/routervpn_external_policy_bridge.go','mobile/routervpn_dns_measurement.go.tmpl':'experimental/libbox/routervpn_dns_measurement.go','mobile/externalpolicy/measurement.go.tmpl':'routervpn_external_measurement.go','mobile/externalpolicy/dns_measurement.go.tmpl':'routervpn_dns_measurement.go','mobile/externalpolicy/mtu.go.tmpl':'routervpn_external_mtu.go','mobile/externalpolicy/box.go.tmpl':'routervpn_external_policy.go','mobile/daemon/instance_context.go.tmpl':'daemon/routervpn_instance_context.go','mobile/strategy/observation.go.tmpl':'adapter/routervpn_observation.go'})
  files.update({'mobile/externalpolicy/dns_dial.go.tmpl':'routervpn_dns_dial.go', 'mobile/externalpolicy/dns_dial_test.go.tmpl':'routervpn_dns_dial_test.go'})
  files.update({'mobile/externalpolicy/selector_context.go.tmpl':'protocol/group/routervpn_selector_context.go', 'mobile/externalpolicy/interrupt_context.go.tmpl':'common/interrupt/routervpn_selector_context.go', 'mobile/externalpolicy/history_context.go.tmpl':'common/urltest/routervpn_selector_context.go', 'mobile/externalpolicy/selection_context_test.go.tmpl':'routervpn_external_selection_context_test.go'})
 for source,target in files.items():
  path=vendor/target
  if path.is_symlink() or not path.is_file() or path.read_bytes()!=(ROOT/source).read_bytes():raise ValueError('Changed native imported-entry source: '+target)
 # The native core must run the same source compiler, not an old matching-name implementation.
 import importlib.util
 spec=importlib.util.spec_from_file_location('imported_mobile_projection',ROOT/'deploy/prepare-mobile-multihop.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 if not peers:m.EXTERNAL_POLICY.check_selection_sources(vendor)
 for shared in ('mobilemultihop','dnsmeasure'):
  for source in (ROOT/'internal'/shared).glob('*.go'):
   if source.name=='core_config_test.go':continue
   raw=m.OBSERVATION.rewrite(source.read_bytes())
   for package in m.PACKAGES:raw=raw.replace(('"router-vpn/internal/'+package+'"').encode(),('"github.com/sagernet/sing-box/experimental/libbox/routervpn/'+package+'"').encode())
   path=vendor/'experimental/libbox/routervpn'/shared/source.name
   if path.is_symlink() or not path.is_file() or path.read_bytes()!=raw:raise ValueError('Changed native imported-entry compiler: '+shared+'/'+source.name)
def native_parser_groups(peers):
 groups={'TestRouterImportedEntryPairedFinalNativeGraphs':sorted(FILES),'TestRouterImportedCONNECTConfiguredServiceGraphs':sorted(CONNECT_SERVICE_FILES),'TestRouterImportedCONNECTSelectedDNSGraphs':sorted(CONNECT_DNS_FILES),'TestRouterImportedCONNECTLayerGraphs':sorted(CONNECT_LAYER_FILES)}
 if not peers:groups[SOCKS_XRAY_PARSER]=[]
 return groups

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

def socks_xray_controls():
 return (
  ('original-admission','internal/mobilemultihop/imported_entry.go',
   'socksXrayFinal := selection.Protocol == "socks5" && importedVisionFinal(exitMode)',
   'socksXrayFinal := false',
   'TestImportedEntrySOCKSRealityVisionCapturedGraphs','default-home',
   'captured SOCKS REALITY/Vision graph was rejected'),
  ('bypassed-final-layer','internal/mobilemultihop/imported_entry.go',
   'outer["detour"] = "entry-wg"',
   'final["detour"] = "entry-wg"',
   'TestImportedEntrySOCKSRealityVisionIndependentLayers','reality-vision--aes-256-gcm',
   'SOCKS REALITY final layer lost its original authenticated edge'),
  ('missing-imported-proof','internal/mobilemultihop/runtime.go',
   'if err := c.verifyImportedEntry(ctx); err != nil {',
   'if err := error(nil); err != nil {',
   'TestImportedEntrySOCKSRealityVisionRequiresBothProofsAndDNS','wrong-public-ip',
   'SOCKS REALITY retained a failed or cancelled proof'),
 )

def require_socks_xray_control(raw,returncode,parent,leaf,witness):
 expected={parent,parent+'/'+leaf};starts={};failures={};observed=False
 if returncode!=1 or any(marker in raw for marker in ('panic:', 'fatal error:', 'WARNING: DATA RACE', 'original SOCKS REALITY proof worker did not join', 'original SOCKS REALITY controller did not close')):
  raise ValueError('SOCKS REALITY causal control did not retain clean bounded ownership')
 for line in raw.splitlines():
  try:event=json.loads(line)
  except json.JSONDecodeError:continue
  name=event.get('Test');action=event.get('Action')
  if not name:continue
  if name not in expected or action in ('pass','skip'):raise ValueError('Foreign or successful SOCKS REALITY causal verdict')
  if action=='run':starts[name]=starts.get(name,0)+1
  if action=='fail':failures[name]=failures.get(name,0)+1
  if name==parent+'/'+leaf and action=='output' and witness in event.get('Output',''):observed=True
 if starts!={n:1 for n in expected} or failures!={n:1 for n in expected} or not observed:
  raise ValueError('Missing exact SOCKS REALITY causal witness')

def run_socks_xray_controls(env):
 records=[]
 with tempfile.TemporaryDirectory(prefix='routervpn-socks-xray-controls-') as temporary:
  root=Path(temporary).resolve()
  for name,relative,before,after,parent,leaf,witness in socks_xray_controls():
   source=(ROOT/relative).resolve(strict=True)
   raw=source.read_text()
   if raw.count(before)!=1:raise ValueError('SOCKS REALITY causal source anchor changed: '+name)
   owned=root/name;owned.mkdir()
   changed=owned/source.name;changed.write_text(raw.replace(before,after,1))
   overlay=owned/'overlay.json';overlay.write_text(json.dumps({'Replace':{str(source):str(changed)}}))
   selector='^'+re.escape(parent)+'$/^'+re.escape(leaf)+'$'
   result=subprocess.run(['go','test','-mod=readonly','-race','-json','-overlay',str(overlay),'./internal/mobilemultihop','-run',selector,'-count=1','-timeout=30s'],cwd=ROOT,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=240)
   require_socks_xray_control(result.stdout,result.returncode,parent,leaf,witness)
   records.append({'control':name,'source':relative,'source_sha256':hashlib.sha256(raw.encode()).hexdigest(),'overlay_sha256':hashlib.sha256(changed.read_bytes()).hexdigest(),'result_sha256':hashlib.sha256(result.stdout.encode()).hexdigest(),'witness':parent+'/'+leaf})
 return records

def run(vendor,peers=False,android=False):
 vendor=vendor.resolve(strict=True)
 if subprocess.check_output(['git','-C',str(vendor),'rev-parse','HEAD'],text=True).strip()!=PIN:raise ValueError('Wrong native source pin')
 checked_sources(vendor,peers)
 subprocess.run([sys.executable,str(ROOT/'deploy/test_mobile_imported_entry_runner.py')],cwd=ROOT,check=True,timeout=30)
 env=dict(os.environ,GOTOOLCHAIN='go1.26.3',GOWORK='off')
 for key in ('GOOS','GOARCH'):env[key]=subprocess.check_output(['go','env','GOHOST'+key[2:]],text=True,env=env).strip()
 with tempfile.TemporaryDirectory(prefix='routervpn-imported-entry-') as temporary:
  fixtures=Path(temporary)/'sources';fixtures.mkdir();env['ROUTERVPN_IMPORTED_ENTRY_FIXTURES']=str(fixtures);env['ROUTERVPN_REQUIRE_IMPORTED_ENTRY_FIXTURES']='1'
  service=Path(temporary)/'configured-service';service.mkdir();env['ROUTERVPN_CONNECT_SERVICE_FIXTURES']=str(service)
  selected_dns=Path(temporary)/'selected-dns';selected_dns.mkdir();env['ROUTERVPN_CONNECT_DNS_FIXTURES']=str(selected_dns)
  layers=Path(temporary)/'independent-layers';layers.mkdir();env['ROUTERVPN_CONNECT_LAYER_FIXTURES']=str(layers)
  execute(['go','test','-mod=readonly','-race','-json','./internal/mobilemultihop','-run','^TestImportedEntry','-count=1','-timeout=60s'],ROOT,env,names(CORE))
  run_socks_xray_controls(env)
  env['ROUTERVPN_IMPORTED_OPENVPN_FIXTURES']=str(fixtures);env['ROUTERVPN_REQUIRE_IMPORTED_OPENVPN_FIXTURES']='1'
  execute(['go','test','-mod=readonly','-race','-json','./internal/mobilemultihop','-run','^TestImportedOpenVPN','-count=1','-timeout=60s'],ROOT,env,names(OPENVPN.CORE))
  execute(['go','test','-mod=readonly','-race','-json','./internal/nativeopenvpn','-run','^TestOpenVPNNativeLayerMapSingleHostKeepsOriginalIdentity$','-count=1','-timeout=20s'],ROOT,env,names(OPENVPN.POLICY_CORE))
  execute(['go','test','-mod=readonly','-race','-json','./internal/mobilemultihop','-run','^('+'|'.join(CONTEXT_CORE)+')$','-count=1','-timeout=20s'],ROOT,env,names(CONTEXT_CORE))
  execute(['go','test','-mod=readonly','-race','-json','./internal/dnsmeasure','-run','^('+'|'.join(CONTEXT_DNS)+')$','-count=1','-timeout=20s'],ROOT,env,names(CONTEXT_DNS))
  if {p.name for p in fixtures.iterdir()}!=FILES:raise ValueError('Incomplete captured imported source matrix')
  if {p.name for p in layers.iterdir()}!=CONNECT_LAYER_FILES:raise ValueError('Incomplete independent CONNECT source matrix')
  if {p.name for p in service.iterdir()}!=CONNECT_SERVICE_FILES:raise ValueError('Incomplete configured CONNECT service matrix')
  if {p.name for p in selected_dns.iterdir()}!=CONNECT_DNS_FILES:raise ValueError('Incomplete selected CONNECT DNS matrix')
  groups=native_parser_groups(peers)
  if android:
   folder,android_layers=run_android_sources(Path(temporary),env)
   exported={p.name for p in folder.iterdir()}
   if exported!={'android-'+name for name in FILES} or any(p.is_symlink() or not p.is_file() for p in folder.iterdir()):raise ValueError('Incomplete actual Android source matrix')
   groups['TestRouterImportedEntryAndroidSourceGraphs']=sorted(exported)
   exported_layers={p.name for p in android_layers.iterdir()}
   if exported_layers!={'android-'+name for name in CONNECT_LAYER_FILES} or any(p.is_symlink() or not p.is_file() for p in android_layers.iterdir()):raise ValueError('Incomplete actual Android independent CONNECT matrix')
   groups['TestRouterImportedCONNECTAndroidLayerGraphs']=sorted(exported_layers)
  tags='with_wireguard,with_gvisor,with_quic,with_utls,with_openvpn,with_naive_outbound,with_purego'
  base=['go','test','-mod=readonly','-json','-ldflags=-checklinkname=0','-tags',tags]
  selector='^('+'|'.join(groups)+')$'
  if not peers:execute(base+['./experimental/libbox','-run',selector,'-count=1','-timeout=90s'],vendor,env,names(groups))
  if not peers:execute(base+['./experimental/libbox','-run','^('+'|'.join(CONTEXT_NATIVE)+')$','-count=1','-timeout=30s'],vendor,env,names(CONTEXT_NATIVE),timeout=90)
  if not peers:execute(base+['.','-run','^('+'|'.join(CONTEXT_DNS_BOX)+')$','-count=1','-timeout=30s'],vendor,env,names(CONTEXT_DNS_BOX),timeout=90)
  if not peers:execute(base+['.','-run','^('+'|'.join(CONTEXT_SELECTION_BOX)+')$','-count=1','-timeout=30s'],vendor,env,names(CONTEXT_SELECTION_BOX),timeout=90)
  if peers:
   # Keep each expanded protocol matrix within the existing finite native
   # timeout. Exact inventories are still mandatory for every process.
   groups={'TestRouterVPNImportedCONNECTNativeTraffic':CONNECT_PEERS,'TestRouterVPNImportedSOCKSPairedFinalLayersNativeTraffic':SOCKS_LAYER_PEERS,'TestRouterVPNImportedSOCKSPacketFinalNativeTraffic':SOCKS_PACKET_PEERS,'TestRouterVPNDesktopLayerInitialPacketRetirement':['original-packet-and-blocked-reader-join','concurrent-initial-read-and-retirement'],'TestRouterVPNDesktopLayerFirstResponseRetirement':['eof','cancel'],'TestRouterVPNImportedSOCKSLayerRelayRetirement':['retiring-worker-root-close','replacement-owner','foreign-and-closed'],'TestRouterVPNImportedSOCKSPairedFinalNativeTraffic':SOCKS_PEERS,'TestRouterVPNImportedNestedPacketNativeTraffic':NESTED_PEERS,'TestRouterVPNImportedPacketFinalNativeTraffic':PACKET_FINAL_PEERS,'TestRouterVPNImportedPacketNativeTraffic':PACKET_PEERS,'TestRouterVPNImportedEntryPairedFinalNativeTraffic':PEERS,'TestRouterVPNImportedHysteriaPairedFinalNativeTraffic':HYSTERIA_PEERS,'TestRouterVPNImportedHysteriaFinalNativeTraffic':FINAL_HYSTERIA_PEERS}
   for selected in ({'TestRouterVPNImportedSOCKSPairedFinalNativeTraffic','TestRouterVPNImportedSOCKSPairedFinalLayersNativeTraffic'}, {'TestRouterVPNImportedSOCKSPacketFinalNativeTraffic'}, set(groups)-{'TestRouterVPNImportedSOCKSPairedFinalNativeTraffic','TestRouterVPNImportedSOCKSPairedFinalLayersNativeTraffic','TestRouterVPNImportedSOCKSPacketFinalNativeTraffic'}):
    subset={name:groups[name] for name in sorted(selected)}
    execute(base+['-race','./protocol/routervpnamnezia','-run','^('+'|'.join(subset)+')$','-count=1','-timeout=90s'],vendor,env,names(subset))

  if peers:
   for parent,leaves in CONNECT_LAYER_PEERS.items():
    execute(base+['-race','./protocol/routervpnamnezia','-run','^'+parent+'$','-count=1','-timeout=90s'],vendor,env,names({parent:leaves}))

  if peers:execute(base+['-race','./protocol/routervpnamnezia','-run','^TestRouterVPNImportedSOCKSPacketLayersNativeTraffic$','-count=1','-timeout=90s'],vendor,env,names({'TestRouterVPNImportedSOCKSPacketLayersNativeTraffic':SOCKS_PACKET_LAYER_PEERS}))
  if peers:execute(base+['-race','./protocol/routervpnamnezia','-run','^TestRouterVPNImportedSOCKSEntryLayers(Proxy|Packet)NativeTraffic$','-count=1','-timeout=90s'],vendor,env,names({'TestRouterVPNImportedSOCKSEntryLayersProxyNativeTraffic':SOCKS_ENTRY_PROXY_PEERS,'TestRouterVPNImportedSOCKSEntryLayersPacketNativeTraffic':SOCKS_ENTRY_PACKET_PEERS}))
  if peers:
   for parent,leaves in SOCKS_BOTH_GROUPS.items():
    execute(base+['-race','./protocol/routervpnamnezia','-run','^'+parent+'$','-count=1','-timeout=90s'],vendor,env,names({parent:leaves}))
  if peers:
   for parent,leaves in OPENVPN.PEERS.items():
    native=base.copy();native[native.index(tags)]=tags+',routervpn_openvpn_remote_test'
    execute(native+['-race','./protocol/routervpnamnezia','-run','^'+parent+'$','-count=1','-timeout=60s'],vendor,env,names({parent:leaves}),timeout=90)
 checked_sources(vendor,peers)
 print('Exact imported-entry source, independent layers, distinct proofs, selected DNS and native verdicts passed; no OS device grant inferred.')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('vendor',type=Path);p.add_argument('--native-peers',action='store_true');p.add_argument('--android',action='store_true');args=p.parse_args();run(args.vendor,args.native_peers,args.android)
