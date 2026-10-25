#!/usr/bin/env python3
"""Bind OpenVPN connected-remote observations to the exact native transport."""
from pathlib import Path
import hashlib
import importlib.util
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PIN = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
spec = importlib.util.spec_from_file_location('openvpn_module_generation', ROOT/'deploy/mobile_openvpn_module_policy.py')
MODULE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MODULE)
SOURCE_SHA = '03f8e07a0fb478220ad0a1860acb499dd3b797bb'
CLOSE_OLD='err := E.Errors(c.client.Close(), c.device.Close())'
CLOSE_NEW='err := E.Errors(routerVPNOpenVPNCloseError(c.client.Close()), c.device.Close())'


def inputs():
    return [Path(__file__).resolve(), ROOT/'deploy/test_external_openvpn_remote_native.py', ROOT/'deploy/test_mobile_openvpn_remote_policy.py', ROOT/'mobile/routervpn_openvpn_remote.go.tmpl',
            ROOT/'mobile/routervpn_openvpn_remote_fixture.go.tmpl', *MODULE.inputs()]


def digest():
    value = hashlib.sha256()
    for source in inputs():
        value.update(source.relative_to(ROOT).as_posix().encode()+b'\0'+source.read_bytes())
    return value.hexdigest()


CHANGES = [('type clientState struct {\n',
  'type clientState struct {\n'
  '\trouterVPNTransportGeneration uint64\n'
  '\trouterVPNTransport net.Conn\n',
  1),
 ('\tc.stateAccess.Lock()\n'
  '\tc.updateState(func(state *clientState) {\n'
  '\t\tstate.tunnelInfo.Server = address\n'
  '\t\tstate.tunnelInfo.Network = N.NetworkName(network)\n'
  '\t})\n'
  '\tc.stateAccess.Unlock()\n'
  '\treturn connection, nil\n',
  '\tc.stateAccess.Lock()\n'
  '\tif c.state.Load().routerVPNTransportGeneration >= 1<<53-1 {\n'
  '\t\tc.stateAccess.Unlock()\n'
  '\t\t_ = connection.Close()\n'
  '\t\treturn nil, E.New("OpenVPN transport generation exhausted")\n'
  '\t}\n'
  '\tc.updateState(func(state *clientState) {\n'
  '\t\tstate.routerVPNTransportGeneration++\n'
  '\t\tstate.routerVPNTransport = connection\n'
  '\t\tstate.tunnelConfigured = false\n'
  '\t\tstate.tunnelInfo.ConnectedSince = time.Time{}\n'
  '\t\tstate.tunnelInfo.Server = address\n'
  '\t\tstate.tunnelInfo.Network = N.NetworkName(network)\n'
  '\t})\n'
  '\tc.stateAccess.Unlock()\n'
  '\tc.notifyStatusUpdated()\n'
  '\treturn connection, nil\n',
  1),
 ('\t\tOnTunnelConfiguration: c.handleTunnelConfiguration,\n',
  '\t\tOnTunnelConfiguration: c.handleTunnelConfiguration,\n'
  '\t\tRouterVPNTransportGeneration: c.routerVPNTransportGenerationFor,\n',
  2),
 ('\tdefer c.notifyStatusUpdated()\n'
  '\tc.stateAccess.Lock()\n'
  '\tconfiguration := configurationFromClientEvent(event, c.logger)\n',
  '\tdefer c.notifyStatusUpdated()\n'
  '\tc.stateAccess.Lock()\n'
  '\tif event.RouterVPNTransportGeneration == 0 || event.RouterVPNTransportGeneration != '
  'c.state.Load().routerVPNTransportGeneration {\n'
  '\t\tc.stateAccess.Unlock()\n'
  '\t\treturn nil\n'
  '\t}\n'
  '\tconfiguration := configurationFromClientEvent(event, c.logger)\n',
  1)]

def unpatch(source):
    markers=[after in source for before,after,count in CHANGES]
    if not any(markers):
        if 'routerVPNTransportGeneration' in source: raise ValueError('Partial native OpenVPN generation patch')
        return source,False
    if not all(markers): raise ValueError('Partial native OpenVPN generation patch')
    for before,after,count in reversed(CHANGES):
        if source.count(after)!=count: raise ValueError('Duplicate native OpenVPN generation patch')
        source=source.replace(after,before)
    return source,True


def patch(source):
    source,_=unpatch(source)
    original=source.replace(CLOSE_NEW,CLOSE_OLD)
    blob=hashlib.sha1(b'blob '+str(len(original.encode())).encode()+b'\0'+original.encode()).hexdigest()
    if blob!=SOURCE_SHA: raise ValueError('Pinned native OpenVPN generation source changed')
    for before,after,count in CHANGES:
        if source.count(before)!=count: raise ValueError('Pinned native OpenVPN generation boundary changed')
        source=source.replace(before,after)
    return source


def prepare(vendor):
    vendor=Path(vendor).resolve()
    if subprocess.check_output(['git','-C',str(vendor),'rev-parse','HEAD'],text=True).strip()!=PIN: raise ValueError('OpenVPN remote proof requires pinned native core')
    target=vendor/'protocol/openvpn/client.go'
    if target.is_symlink(): raise ValueError('Linked native OpenVPN remote boundary')
    source=patch(target.read_text())
    MODULE.prepare(vendor)
    target.write_text(source)
    for name in ('remote','remote_fixture'):
        output=vendor/'protocol/openvpn'/('routervpn_'+name+'.go')
        if output.is_symlink(): raise ValueError('Linked native OpenVPN receipt source')
        output.write_bytes((ROOT/'mobile'/('routervpn_openvpn_'+name+'.go.tmpl')).read_bytes())
