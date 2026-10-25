#!/usr/bin/env python3
"""Install the owned per-remote OpenVPN Start Layer dialer in the pinned core."""
from pathlib import Path
import importlib.util
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PIN = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
spec = importlib.util.spec_from_file_location('openvpn_layer_whitening', ROOT/'deploy/prepare-mobile-whitening.py')
WHITENING = importlib.util.module_from_spec(spec)
spec.loader.exec_module(WHITENING)


def inputs():
    return [Path(__file__).resolve(), *sorted((ROOT/'mobile/openvpnlayers').glob('*.tmpl')),
            *sorted((ROOT/'internal/nativeopenvpn').glob('*.go')), *WHITENING.inputs()]


def write(vendor, relative, data):
    target = vendor/relative
    for parent in (target, *target.parents):
        if parent == vendor:
            break
        if parent.is_symlink():
            raise ValueError('Linked OpenVPN layer mapper destination')
    if not target.resolve().is_relative_to(vendor):
        raise ValueError('OpenVPN layer mapper escaped its owned checkout')
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def prepare(vendor):
    vendor = Path(vendor).resolve()
    if subprocess.check_output(['git','-C',str(vendor),'rev-parse','HEAD'],text=True).strip() != PIN:
        raise ValueError('OpenVPN layer mapper requires the pinned native core')
    if not (vendor/'go.mod').read_text().startswith('module github.com/sagernet/sing-box\n'):
        raise ValueError('OpenVPN layer mapper requires its owned native module')
    registry = vendor/'include/registry.go'
    if registry.is_symlink():
        raise ValueError('Linked native layer registry')
    # The mapper owns these actual authenticated children. It cannot advertise
    # XOR support merely by accepting a source label without the native engine.
    WHITENING.prepare(vendor)
    text = registry.read_text()
    old = '\t"github.com/sagernet/sing-box/protocol/routervpnwhitening"'
    text = WHITENING.replace_once(text, old, old+'\n\t"github.com/sagernet/sing-box/protocol/routervpnopenvpnlayers"')
    old = '\troutervpnwhitening.RegisterOutbound(registry)'
    text = WHITENING.replace_once(text, old, old+'\n\troutervpnopenvpnlayers.RegisterOutbound(registry)')
    for source in sorted((ROOT/'internal/nativeopenvpn').glob('*.go')):
        write(vendor, 'experimental/libbox/routervpn/nativeopenvpn/'+source.name, source.read_bytes())
    for source in sorted((ROOT/'mobile/openvpnlayers').glob('*.tmpl')):
        family = {'shadowsocks_fixture.go.tmpl':'shadowsocks', 'whitening_fixture.go.tmpl':'routervpnwhitening'}.get(source.name, 'routervpnopenvpnlayers')
        name = 'routervpn_openvpn_layers_'+source.name.removesuffix('.tmpl') if family != 'routervpnopenvpnlayers' else source.name.removesuffix('.tmpl')
        write(vendor, 'protocol/'+family+'/'+name, source.read_bytes())
    registry.write_bytes(text.encode())
