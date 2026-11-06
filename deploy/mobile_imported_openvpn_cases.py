"""Exact inventories shared by the imported OpenVPN shipping native gate."""
LAYERS = ('', 'aes-256-gcm', 'aes-256-gcm+xor-whitening')
MODES = ('shadowsocks', 'hysteria2', 'wg', 'awg2-fast', 'awg2-strong')
FILES = {f'openvpn--{network}--final-{mode}--{a or "off"}--{b or "off"}.json'
         for network in ('tcp', 'udp') for mode in MODES for a in LAYERS for b in LAYERS}
CORE = {
 'TestImportedOpenVPNCompleteLayerMatrix': [f'{n}/{m}/{a}/{b}' for n in ('tcp','udp') for m in MODES for a in LAYERS for b in LAYERS],
 'TestImportedOpenVPNRejectsUnownedSourceAndCapacity': ['system','script','remote','password','missing-layer','foreign-layer','missing-final-layer','insufficient-entry','fixed-final','entry-jumbo','final-jumbo','invented-proof'],
 'TestImportedOpenVPNRequiresOriginalConnectedCapacity': [f'{n}/{f}' for n in ('tcp','udp') for f in ('success','missing-reader','pending-cancel','foreign-host','foreign-port','foreign-network','zero-generation','zero-connected-at','small-mtu','oversized-mtu','late-cancel','late-close')],
 'TestImportedOpenVPNRetiresOriginalTupleAtEveryProofBoundary': [f'{p}/{c}' for p in ('public','dns','final','last-node','external','measurement','refresh') for c in ('generation','connected-at','remote','mtu-increase','mtu-decrease','mtu-below-capacity','read-failure')],
 'TestImportedOpenVPNObservationCancellationJoinsWatch': [],
 'TestImportedOpenVPNRefreshRequiresCapturedCapacity': [],
 'TestImportedOpenVPNMeasurementCancellationPreservesOnlyUnchangedProof': [f'{o}/{f}' for o in ('mtu','hop') for f in ('cancel','deadline','cancel-and-capacity','cancel-and-generation','cancel-and-read-failure')],
 'TestImportedOpenVPNLayeredReceiptKeepsOriginalPublicOwner': [f'{n}/{a}' for n in ('tcp','udp') for a in LAYERS[1:]],
 'TestImportedOpenVPNMultipleReceiptOwnersRemainExact': [f'{a}/mapped-{m}' for a in LAYERS[1:] for m in ('false','true')],
}
PEERS = {
 'TestRouterVPNImportedOpenVPN'+network+'NativeTraffic': [f'{m}/{a or "off"}/{b or "off"}' for m in MODES for a in LAYERS for b in LAYERS]
 for network in ('TCP','UDP')
}
PEERS['TestRouterVPNImportedOpenVPNNativeFailover'] = [a or 'off' for a in LAYERS]
REFUSALS=[]
for network in ('tcp','udp'):
 for layer in LAYERS:
  faults=['entry-auth']
  if layer:
   faults.append('entry-layer-key')
   if network=='udp':faults.append('private-target')
  if layer=='aes-256-gcm+xor-whitening':faults.append('entry-whitening')
  REFUSALS.extend(f'{network}/{layer or "off"}/{fault}' for fault in faults)
PEERS['TestRouterVPNImportedOpenVPNNativeRefusals'] = REFUSALS

POLICY_CORE = {'TestOpenVPNNativeLayerMapSingleHostKeepsOriginalIdentity': [f'{a}/{f}/{p}' for a in LAYERS[1:] for f in ('missing-layer','foreign-host','private-remote','wrong-port','wrong-network','extra-layer','foreign-layer-host') for p in ('one-port','two-ports')]}
