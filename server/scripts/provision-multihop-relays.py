#!/usr/bin/env python3
"""Pair a private exit bundle with this server's isolated relay registry.

This administrator command stages, core-checks, then atomically publishes the
registry. It never starts a tunnel, changes routes, restarts services or uploads
node credentials. Restart only the agent deliberately after successful pairing.
"""
from pathlib import Path
import argparse
import base64
import copy
import contextlib
import fcntl
import stat
import time
import ipaddress
import json
import hashlib
from urllib.parse import urlsplit
import os
import re
import runpy
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent

def helpers():
    writer = runpy.run_path(str(HERE/'atomic-private-write.py'))
    return (runpy.run_path(str(HERE/'verified-regular-read.py'))['read_verified_regular'],
            writer['atomic_private_write'], writer['ensure_private_parent'])

@contextlib.contextmanager
def registry_lock(path):
    """Serialize cooperative pairers without following or unlinking lock paths."""
    _, _, parent = helpers()
    path = parent(Path(path))
    lock = path.with_name('.' + path.name + '.lock')
    descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('registry lock is not an owned private regular file')
        deadline = time.monotonic() + 10
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise ValueError('another registry update is still in progress')
                time.sleep(0.05)
        if not os.path.samestat(info, lock.lstat()):
            raise ValueError('registry lock changed while acquiring ownership')
        yield path
    finally:
        os.close(descriptor)


def exact(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate private JSON member')
        result[key] = value
    return result

def decode(raw):
    return json.loads(raw.decode('utf-8'), object_pairs_hook=exact)

def literal(value):
    address = ipaddress.ip_address(value)
    if '%' in str(address) or address.is_unspecified or address.is_loopback or address.is_multicast or address.is_link_local:
        raise ValueError('unscoped literal server address required')
    return str(address)

def native_wireguard(encoded, node, server):
    raw = base64.b64decode(encoded, validate=True)
    if len(raw) > 256*1024:
        raise ValueError('WireGuard profile exceeds the safety bound')
    sections = {'interface': {}, 'peer': {}}
    allowed = {'interface': {'privatekey','address','dns','listenport','mtu'},
               'peer': {'publickey','presharedkey','endpoint','allowedips','persistentkeepalive'}}
    seen = set();section = None
    for line in raw.decode('utf-8').splitlines():
        line = line.split('#', 1)[0].strip()
        if not line: continue
        if line.startswith('[') and line.endswith(']'):
            section = line[1:-1].lower()
            if section not in allowed or section in seen or (section == 'peer' and 'interface' not in seen):
                raise ValueError('WireGuard requires one initial interface and one paired peer')
            seen.add(section);continue
        if section is None or '=' not in line: raise ValueError('Invalid WireGuard profile')
        key, value = (item.strip() for item in line.split('=', 1));key = key.lower()
        if key not in allowed[section] or key in sections[section] or not value:
            raise ValueError('Unknown or duplicated WireGuard policy; nothing was ignored')
        sections[section][key] = value
    iface, peer = sections['interface'], sections['peer']
    for field in (iface.get('privatekey',''), peer.get('publickey','')):
        if len(base64.b64decode(field, validate=True)) != 32: raise ValueError('Invalid WireGuard key')
    if hashlib.sha256(('router-vpn-node-proof-v1\n'+peer['publickey']).encode()).hexdigest() != node:
        raise ValueError('WireGuard server key does not match the paired node identity')
    endpoint = urlsplit('udp://'+peer.get('endpoint',''))
    if endpoint.username or endpoint.password or endpoint.path or not endpoint.port or not 1 <= endpoint.port <= 65535:
        raise ValueError('Invalid WireGuard peer endpoint')
    addresses = [str(ipaddress.ip_interface(a.strip())) for a in iface.get('address','').split(',') if a.strip()]
    if not addresses: raise ValueError('WireGuard client address is missing')
    routes = [str(ipaddress.ip_network(a.strip(),strict=False)) for a in peer.get('allowedips','').split(',') if a.strip()]
    for address in addresses:
        default = '0.0.0.0/0' if ipaddress.ip_interface(address).version == 4 else '::/0'
        if default not in routes: raise ValueError('Server-side WireGuard needs explicit full-route client policy')
    native_peer = dict(address=server,port=endpoint.port,public_key=peer['publickey'],allowed_ips=routes)
    if peer.get('presharedkey'):
        if len(base64.b64decode(peer['presharedkey'],validate=True)) != 32: raise ValueError('Invalid preshared key')
        native_peer['pre_shared_key'] = peer['presharedkey']
    if peer.get('persistentkeepalive'):
        interval = int(peer['persistentkeepalive'])
        if not 0 <= interval <= 65535: raise ValueError('Invalid persistent keepalive')
        native_peer['persistent_keepalive_interval'] = interval
    result = dict(type='wireguard',tag='exit',address=addresses,private_key=iface['privatekey'],peers=[native_peer])
    if iface.get('mtu'):
        mtu = int(iface['mtu'])
        if not 1280 <= mtu <= 9000: raise ValueError('Unsafe WireGuard MTU')
        result['mtu'] = mtu
    if iface.get('listenport') and int(iface['listenport']) != 0:
        raise ValueError('A fixed local WireGuard listen port cannot be shared by isolated server leases')
    return result


def pair(bundle, alias, selected=None):
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', alias):
        raise ValueError('invalid paired exit ID')
    profiles = bundle.get('routerProfiles', [])
    selected = selected or bundle.get('selectedRouterID')
    matches = [p for p in profiles if p.get('id') == selected]
    profile = matches[0] if len(matches) == 1 else None
    if not isinstance(profile, dict) or profile.get('node_kind', 'router-vpn') != 'router-vpn':
        raise ValueError('select one Router VPN exit bundle profile')
    node = profile.get('node_proof_id') or bundle.get('nodeProofId')
    if not re.fullmatch(r'[0-9a-f]{64}', str(node or '')):
        raise ValueError('paired exit has no exact node identity')
    endpoint = literal(profile.get('endpoint', ''))
    dns = literal(profile.get('adguard_ipv4') or profile.get('adguard_ipv6') or '')
    modes = bundle.get('profiles', {})
    exits = []
    if 'wg.conf' in modes.get('wg', {}):
        transport = native_wireguard(modes['wg']['wg.conf'], node, endpoint)
        exits.append(dict(id=alias,mode='wg',node_id=node,dns_server=dns,transport=transport))
    for mode in ('shadowsocks', 'hysteria2'):
        assets = modes.get(mode, {})
        encoded = assets.get('sing-box.json')
        if encoded is None:
            continue
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) > 256 * 1024:
            raise ValueError('paired transport config exceeds safety bound')
        config = decode(raw)
        candidates = [p for p in config.get('outbounds', []) if p.get('tag') == 'proxy']
        if len(candidates) != 1 or candidates[0].get('type') != mode:
            raise ValueError('paired transport does not match the selected mode')
        transport = copy.deepcopy(candidates[0])
        if transport.get('detour'):
            raise ValueError('an already-nested exit cannot be paired as a single server transport')
        transport['server'] = endpoint
        tls = transport.get('tls')
        if isinstance(tls, dict) and 'certificate_path' in tls:
            name = tls.pop('certificate_path')
            if not isinstance(name, str) or '/' in name or '\\' in name or name in ('.','..') or name not in assets:
                raise ValueError('TLS certificate must be an owned inline bundle asset')
            certificate = base64.b64decode(assets[name], validate=True)
            if len(certificate) > 128*1024:
                raise ValueError('TLS certificate exceeds safety bound')
            tls['certificate'] = [certificate.decode('utf-8')]
        exits.append(dict(id=alias, mode=mode, node_id=node, dns_server=dns, transport=transport))
    if not exits:
        raise ValueError('bundle has no supported standalone server exit transport')
    return exits

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--exit-id', required=True, help='ID used for this exit in client profiles')
    parser.add_argument('--bundle-profile')
    parser.add_argument('--agent-config', type=Path, default=Path('/etc/router-vpn/router-agent.json'))
    parser.add_argument('--registry', type=Path, default=Path('/etc/router-vpn/multihop-relays.json'))
    parser.add_argument('--listen-ip', required=True, help='entry tunnel IP used by clients for the Router API')
    args = parser.parse_args()
    read, write, _ = helpers()
    entries = pair(decode(read(args.bundle, 32 << 20)), args.exit_id, args.bundle_profile)
    agent = decode(read(args.agent_config, 1 << 20))
    listen = ipaddress.ip_address(literal(args.listen_ip))
    if not listen.is_private or not any(listen in ipaddress.ip_network(n) for n in agent.get('tunnel_cidrs', [])):
        raise ValueError('listen IP must belong to the entry tunnel ranges')
    if any(e['node_id'] == agent.get('node_id') for e in entries):
        raise ValueError('entry and exit must have distinct identities')
    with registry_lock(args.registry):
        try:
            existing_raw = read(args.registry, 1 << 20)
            registry = decode(existing_raw)
        except FileNotFoundError:
            existing_raw = None
            registry = dict(listen_ip=str(listen), first_port=26240, last_port=26271, ttl_seconds=90, exits=[])
        if registry.get('listen_ip') != str(listen):
            raise ValueError('existing registry has a different entry listener')
        registry['exits'] = [e for e in registry['exits'] if e['id'] != args.exit_id] + entries
        if len(registry['exits']) > 64:
            raise ValueError('paired exit count exceeds bound')
        body = (json.dumps(registry, indent=2)+'\n').encode()
        with tempfile.TemporaryDirectory(prefix='.relay-pair-', dir=args.registry.parent) as tmp:
            stage = Path(tmp)/'registry.json'
            write(stage, body)
            subprocess.run(['/usr/local/bin/router-vpn-agent', 'check-multihop-registry', str(stage), str(args.agent_config)],
                           check=True, timeout=60, stdout=subprocess.DEVNULL)
            try:
                now = read(args.registry, 1 << 20)
            except FileNotFoundError:
                now = None
            if now != existing_raw:
                raise ValueError('registry changed during native validation; no replacement was written')
            write(args.registry, body)
    print('Paired',len(entries),'validated transport configurations. No tunnel or service was started.')

if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # No imported payload, credentials or compiler stderr in a public error.
        raise SystemExit('Relay pairing failed: ' + str(error))
