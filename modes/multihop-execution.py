#!/usr/bin/env python3
"""Patch only the owned Linux server-execution graph, after selected DNS.

No imported profile is changed. Entry control and SOCKS relay traffic bind to the
actual split WireGuard/AmneziaWG interface, never the host's default interface.
"""
from pathlib import Path
import copy
import importlib.util
import ipaddress
import json
import os
import re
import sys
from private_profile_store import read_private_json

ROOT = Path(__file__).resolve().parent

def module(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

def patch(config, descriptor, interface):
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', interface):
        raise ValueError('invalid owned entry interface')
    if descriptor.get('execution') != 'server':
        raise ValueError('unknown execution descriptor')
    lease = descriptor.get('lease', {})
    host = ipaddress.ip_address(lease.get('host', ''))
    if not host.is_private or host.is_loopback or host.is_unspecified or host.is_link_local or '%' in str(host):
        raise ValueError('relay is not a private tunnel listener')
    port = lease.get('port')
    if type(port) is not int or not 26240 <= port <= 26271:
        raise ValueError('relay port outside reserved range')
    for field in ('username', 'password'):
        if not re.fullmatch(r'[0-9a-f]{48}', lease.get(field, '')):
            raise ValueError('invalid private relay credential')
    out = copy.deepcopy(config)
    route = out.get('route', {})
    if route.get('final') != 'proxy':
        raise ValueError('unowned final route')
    old = [p for p in out.get('outbounds', []) if p.get('tag') == 'proxy']
    if len(old) != 1 or any(p.get('tag') == 'entry-control' for p in out['outbounds']):
        raise ValueError('ambiguous execution outbounds')
    # The exit remains a SOCKS5 TCP+UDP path. It is not a TCP-only HTTP tunnel.
    replacement = dict(type='socks', tag='proxy', version='5', server=str(host),
                       server_port=port, username=lease['username'], password=lease['password'],
                       bind_interface=interface)
    out['outbounds'] = [replacement if p.get('tag') == 'proxy' else p for p in out['outbounds']]
    out['outbounds'].append(dict(type='direct', tag='entry-control', bind_interface=interface))
    control = [rule for rule in route.get('rules', []) if 'multihop-entry-proof' in rule.get('inbound', [])]
    if len(control) != 1:
        raise ValueError('missing isolated control lane')
    control[0]['outbound'] = 'entry-control'
    # No ordinary TUN rule may use the control-only outbound.
    for rule in route.get('rules', []):
        if rule.get('outbound') == 'entry-control' and rule.get('inbound') != ['multihop-entry-proof']:
            raise ValueError('control route exposed to ordinary traffic')
    return out

def main():
    if len(sys.argv) != 4:
        raise SystemExit('expected owned config, execution descriptor, and entry interface')
    policy = module('dns-policy')
    path, descriptor = map(Path, sys.argv[1:3])
    config, target, parent = policy._read_runtime_json_snapshot(path)
    plan = read_private_json(descriptor, 8192)
    result = patch(config, plan, sys.argv[3])
    policy._atomic_private_runtime_json(path, result, target, parent)

if __name__ == '__main__':
    main()
