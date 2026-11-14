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
# Match multihoprelay.MaxRegistryBytes; lease HTTP limits remain unchanged.
MAX_REGISTRY_BYTES = 32 << 20
MAX_TOR_SOURCE_BYTES = 64 << 10
MAX_NODE_CHAIN_SOURCE_BYTES = 40 << 20

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

def native_wireguard(encoded, node, server, *, amnezia=False):
    raw = base64.b64decode(encoded, validate=True)
    if len(raw) > 256*1024:
        raise ValueError('WireGuard profile exceeds the safety bound')
    sections = {'interface': {}, 'peer': {}}
    allowed = {'interface': {'privatekey','address','dns','listenport','mtu'},
               'peer': {'publickey','presharedkey','endpoint','allowedips','persistentkeepalive'}}
    awg_keys = {'jc','jmin','jmax','s1','s2','s3','s4','h1','h2','h3','h4'}
    if amnezia: allowed['interface'] |= awg_keys
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
    if not amnezia and hashlib.sha256(('router-vpn-node-proof-v1\n'+peer['publickey']).encode()).hexdigest() != node:
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
    if amnezia:
        # Node identity remains the paired standard-WG identity; AWG has its
        # own different peer key. The selected-node API proves it after startup.
        params = {key: iface[key] for key in awg_keys if key in iface}
        validate_amnezia_parameters(params)
        result['type'] = 'routervpn-amneziawg'
        result['amnezia'] = params
        result.setdefault('mtu', 1280)
    return result


def validate_amnezia_parameters(parameters):
    names = {'jc','jmin','jmax','s1','s2','s3','s4','h1','h2','h3','h4'}
    if set(parameters) != names: raise ValueError('Complete native AWG obfuscation policy is required')
    numbers = {}
    for key in ('jc','jmin','jmax','s1','s2','s3','s4'):
        text = parameters[key]
        if not isinstance(text,str) or not re.fullmatch(r'[0-9]{1,10}',text):
            raise ValueError('Invalid native AWG integer')
        n = int(text)
        if n > (128 if key == 'jc' else 1280): raise ValueError('Native AWG noise or padding exceeds its bound')
        numbers[key] = n
    if numbers['jmin'] > numbers['jmax'] or numbers['s1']+148 == numbers['s2']+92:
        raise ValueError('Inconsistent native AWG padding')
    ranges = []
    for key in ('h1','h2','h3','h4'):
        text = parameters[key]
        if not isinstance(text,str) or not re.fullmatch(r'[0-9]{1,10}(?:-[0-9]{1,10})?',text):
            raise ValueError('Invalid native AWG header range')
        parts = text.split('-');low,high = int(parts[0]),int(parts[-1])
        if not 4 < low <= high <= 4294967295 or any(low<=b and a<=high for a,b in ranges):
            raise ValueError('Overlapping, reversed or standard-WG native AWG headers')
        ranges.append((low,high))


def native_xray(assets, mode, server):
    if not isinstance(assets, dict) or not 1 <= len(assets) <= 2 or set(assets) - {'sing-box.json', 'xray.json'}:
        raise ValueError('Native Xray pairing requires its exact self-contained source assets')
    payload = json.dumps(assets, ensure_ascii=False, allow_nan=False).encode('utf-8')
    if len(payload) > 8*1024*1024:
        raise ValueError('Native Xray pairing exceeds its source bound')
    # Call the same compiler used by mobile entry/exit preparation. In
    # particular, split routes and extra helpers are rejected, never discarded.
    result = subprocess.run(['/usr/local/bin/router-vpn-agent','compile-native-relay-profile',mode],
                            input=payload, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            check=True, timeout=20)
    if not result.stdout or len(result.stdout) > 4*1024*1024:
        raise ValueError('Native relay compiler returned no bounded transport')
    value = decode(result.stdout)
    if not isinstance(value,dict) or set(value) != {'type','tag','mode','config_json'} or value.get('type') != 'routervpn-xray' or value.get('mode') != mode:
        raise ValueError('Native relay compiler returned an unowned transport')
    original = base64.b64decode(assets['xray.json'],validate=True).decode('utf-8')
    if value['config_json'] != original:
        raise ValueError('Native pairing changed the original protocol or authentication')
    raw = decode(original.encode('utf-8'))
    peers = raw['outbounds'][0]['settings']['vnext']
    if len(peers) != 1 or literal(peers[0]['address']) != server:
        raise ValueError('Native Xray transport belongs to another paired server')
    value['tag'] = 'exit'
    return value

def native_naive(assets, mode, server):
    """Pair native HTTP and UDP-over-streams without an external helper."""
    bad = ValueError('Native Naive pairing lost its exact transport or selected node')
    if mode not in ('naive-h2', 'naive-h3') or not isinstance(assets, dict) or not 1 <= len(assets) <= 2 or 'sing-box.json' not in assets:
        raise bad
    if not all(isinstance(value, str) for value in assets.values()):
        raise bad
    payload = json.dumps(assets, ensure_ascii=False, allow_nan=False).encode('utf-8')
    if len(payload) > 8 << 20:
        raise ValueError('Native Naive pairing exceeds its source bound')
    try:
        result = subprocess.run(['/usr/local/bin/router-vpn-agent', 'compile-native-relay-profile', mode],
                                input=payload, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                check=True, timeout=20)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        raise ValueError('Native Naive pairing failed offline validation') from None
    if not result.stdout or len(result.stdout) > 4 << 20:
        raise bad
    value = decode(result.stdout)
    original = decode(base64.b64decode(assets['sing-box.json'], validate=True))
    candidates = [item for item in original.get('outbounds', []) if isinstance(item, dict) and item.get('tag') == 'proxy']
    if len(candidates) != 1:
        raise bad
    expected = copy.deepcopy(candidates[0])
    expected['tag'] = 'routervpn-hop-entry'
    tls = expected.get('tls')
    if not isinstance(tls, dict):
        raise bad
    if 'certificate_path' in tls:
        name = tls.pop('certificate_path')
        if not isinstance(name, str) or name not in assets or name == 'sing-box.json' or 'certificate' in tls:
            raise bad
        tls['certificate'] = [base64.b64decode(assets[name], validate=True).decode('utf-8')]
    if not isinstance(value, dict) or value != expected or value.get('type') != 'naive' or literal(value.get('server','')) != server:
        raise bad
    if type(value.get('quic')) is not bool or value['quic'] != (mode == 'naive-h3') or value.get('detour') is not None:
        raise bad
    value['tag'] = 'exit'
    return value

def native_pq(assets, mode, node, server):
    """Pair the exact selected PQ protocol; never execute imported helper files."""
    bad = ValueError('Native PQ pairing lost its captured protocol, key material or node')
    if mode not in ('wg-pq', 'awg2-pq') or not isinstance(assets, dict):
        raise bad
    config = 'wg.conf' if mode == 'wg-pq' else 'awg.conf'
    required = {config, 'rosenpass.env', 'rosenpass.toml', 'rosenpass-client-secret',
                'rosenpass-client-public', 'rosenpass-server-public'}
    if not required.issubset(assets) or set(assets) - required - {'stack.json'}:
        raise bad
    if not all(isinstance(value, str) for value in assets.values()):
        raise bad
    payload = json.dumps(assets, allow_nan=False, separators=(',', ':')).encode('utf-8')
    maximum = 12 << 20  # same bounded asset map as compilePQRelayProfile
    if len(payload) > maximum:
        raise ValueError('Native PQ pairing exceeds its source bound')
    try:
        result = subprocess.run(['/usr/local/bin/router-vpn-agent', 'compile-pq-relay-profile', mode, node, server],
                                input=payload, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                check=True, timeout=20)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        raise ValueError('Native PQ pairing failed offline validation') from None
    if not result.stdout or len(result.stdout) > maximum:
        raise bad
    value = decode(result.stdout)
    fields = {'type', 'tag', 'mode', 'node_id', 'private_key', 'address', 'mtu', 'peers', 'pq', 'amnezia'}
    if not isinstance(value, dict) or set(value) - fields or not fields.difference({'amnezia'}).issubset(value):
        raise bad
    if value['type'] != 'routervpn-pq' or value['tag'] != 'exit' or value['mode'] != mode or value['node_id'] != node:
        raise bad
    peers, pq = value['peers'], value['pq']
    if not isinstance(peers, list) or len(peers) != 1 or not isinstance(peers[0], dict) or peers[0].get('address') != server:
        raise bad
    if not isinstance(pq, dict) or set(pq) != {'endpoint', 'version', 'secret', 'public', 'peer'}:
        raise bad
    if type(pq['version']) is not int or pq['version'] not in (2, 3):
        raise bad
    endpoint = urlsplit('udp://'+pq['endpoint'])
    if endpoint.username or endpoint.password or endpoint.path or endpoint.query or endpoint.fragment or not endpoint.port or literal(endpoint.hostname) != server:
        raise bad
    for field, asset in (('secret', 'rosenpass-client-secret'), ('public', 'rosenpass-client-public'), ('peer', 'rosenpass-server-public')):
        if not isinstance(pq[field], str) or base64.b64decode(pq[field], validate=True) != base64.b64decode(assets[asset], validate=True):
            raise bad
    if mode == 'awg2-pq':
        validate_amnezia_parameters(value.get('amnezia', {}))
    elif value.get('amnezia'):
        raise bad
    return value

def native_max(assets, mode, node, server, api):
    """Capture the full PQ/base/SS/outer chain with the shipping Go compiler."""
    bad = ValueError('Native MAX pairing lost its complete captured node graph')
    if mode not in ('max-tls-wg', 'max-tls-awg', 'max-quic-wg', 'max-quic-awg') or not isinstance(assets, dict) or not 9 <= len(assets) <= 12:
        raise bad
    if not isinstance(api, str) or not all(isinstance(value, str) for value in assets.values()):
        raise bad
    payload = json.dumps(assets, ensure_ascii=False, allow_nan=False).encode('utf-8')
    if len(payload) > 16 << 20:
        raise ValueError('Native MAX pairing exceeds its source bound')
    try:
        result = subprocess.run(['/usr/local/bin/router-vpn-agent', 'compile-max-relay-profile', mode, node, server, api],
                                input=payload, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                check=True, timeout=20)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        raise ValueError('Native MAX pairing failed offline validation') from None
    if not result.stdout or len(result.stdout) > (4 << 20) + 1:
        raise bad
    value = decode(result.stdout)
    if not isinstance(value, dict) or set(value) != {'endpoint', 'outbounds'}:
        raise bad
    base, outputs = value['endpoint'], value['outbounds']
    if not isinstance(base, dict) or not isinstance(outputs, list) or len(outputs) != 2 or not all(isinstance(item, dict) for item in outputs):
        raise bad
    expected_mode = 'awg2-pq' if mode.endswith('-awg') else 'wg-pq'
    if base.get('type') != 'routervpn-pq' or base.get('mode') != expected_mode or base.get('node_id') != node or base.get('tag') != 'exit' or base.get('detour') != 'routervpn-relay-max-ss':
        raise bad
    try:
        private = literal(urlsplit(api).hostname)
    except (ValueError, TypeError):
        raise bad from None
    peers, pq = base.get('peers'), base.get('pq')
    if not isinstance(peers, list) or len(peers) != 1 or not isinstance(peers[0], dict) or peers[0].get('address') != private or not isinstance(pq, dict):
        raise bad
    for field, asset in (('secret', 'rosenpass-client-secret'), ('public', 'rosenpass-client-public'), ('peer', 'rosenpass-server-public')):
        if pq.get(field) != assets.get(asset):
            raise bad
    owned = {item.get('tag'): item for item in outputs}
    if set(owned) != {'routervpn-relay-max-ss', 'routervpn-relay-max-outer'}:
        raise bad
    middle, outer = owned['routervpn-relay-max-ss'], owned['routervpn-relay-max-outer']
    if middle.get('type') != 'shadowsocks' or middle.get('method') != '2022-blake3-aes-256-gcm' or middle.get('server') != private or middle.get('detour') != 'routervpn-relay-max-outer' or outer.get('detour') is not None:
        raise bad
    if mode.startswith('max-tls-'):
        if outer.get('type') != 'routervpn-xray' or outer.get('mode') != 'reality-xhttp':
            raise bad
    elif outer.get('type') != 'hysteria2' or outer.get('server') != server:
        raise bad
    return value

def native_composite(assets, mode, node, server, api):
    """Pair both authenticated lanes; no imported helper is ever executed."""
    bad = ValueError('Native composite pairing lost its complete captured node graph')
    if mode not in ('ss-v2ray', 'split', 'max') or not isinstance(assets, dict) or not 1 <= len(assets) <= 8:
        raise bad
    if not isinstance(api, str) or not all(isinstance(value, str) for value in assets.values()):
        raise bad
    payload = json.dumps(assets, ensure_ascii=False, allow_nan=False).encode('utf-8')
    if len(payload) > 4 << 20:
        raise ValueError('Native composite pairing exceeds its source bound')
    try:
        result = subprocess.run(['/usr/local/bin/router-vpn-agent', 'compile-composite-relay-profile', mode, node, server, api],
                                input=payload, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                check=True, timeout=20)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        raise ValueError('Native composite pairing failed offline validation') from None
    if not result.stdout or len(result.stdout) > (4 << 20) + 1:
        raise bad
    value = decode(result.stdout)
    if not isinstance(value, dict) or set(value) != {'type', 'mode', 'node_id', 'start_layer', 'tcp', 'udp'}:
        raise bad
    if value['type'] != 'routervpn-composite-plan' or value['mode'] != mode or value['node_id'] != node or value['start_layer'] != '':
        raise bad
    tcp, udp = value['tcp'], value['udp']
    if not isinstance(tcp, dict) or not isinstance(udp, dict) or tcp.get('detour') is not None or udp.get('detour') is not None:
        raise bad
    if tcp.get('tag') != 'routervpn-composite-tcp' or udp.get('tag') != 'routervpn-composite-udp' or udp.get('type') != 'hysteria2' or udp.get('server') != server:
        raise bad
    if mode == 'ss-v2ray':
        if tcp.get('type') != 'shadowsocks' or tcp.get('server') != server or tcp.get('plugin') != 'v2ray-plugin' or tcp.get('network') != 'tcp':
            raise bad
    elif tcp.get('type') != 'routervpn-xray' or tcp.get('mode') != mode:
        raise bad
    return value

def paired_start_layer(bundle, profile, endpoint):
    raw_mode = profile.get('start_layer', 'off')
    if not isinstance(raw_mode, str):
        raise ValueError('The selected Start Layer must be a string')
    normalized = raw_mode.strip().lower().replace('_', '-').replace(' ', '')
    if normalized in ('', 'off', 'none', 'disabled'):
        return None
    assets = bundle.get('profiles', {}).get('shadowsocks')
    if not isinstance(assets, dict) or set(assets) != {'sing-box.json'}:
        raise ValueError('Selected relay encryption requires the exit-owned AES profile')
    api = profile.get('router_api')
    if not isinstance(api, str):
        raise ValueError('Selected relay encryption requires the exit private API')
    payload = json.dumps({'mode': raw_mode, 'profile': assets}, allow_nan=False).encode('utf-8')
    if len(payload) > 16384:
        raise ValueError('Selected relay encryption exceeds its private source bound')
    try:
        result = subprocess.run(['/usr/local/bin/router-vpn-agent', 'compile-relay-start-layer', endpoint, api],
                                input=payload, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                check=True, timeout=20)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        raise ValueError('Selected relay encryption failed offline native validation') from None
    if not result.stdout or len(result.stdout) > 16385:
        raise ValueError('Native layer compiler returned no bounded result')
    layer = decode(result.stdout)
    if not isinstance(layer, dict) or set(layer) != {'mode', 'api', 'transport'} or layer.get('api') != api:
        raise ValueError('Native layer compiler changed the captured private node')
    if layer.get('mode') not in ('aes-256-gcm', 'aes-256-gcm+xor-whitening'):
        raise ValueError('Native layer compiler omitted authenticated encryption')
    transport = layer.get('transport')
    if not isinstance(transport, dict) or set(transport) != {'type','tag','server','server_port','method','password'} or transport.get('server') != endpoint:
        raise ValueError('Native layer compiler changed the selected exit transport')
    return layer

def pair(bundle, alias, selected=None, server_peer_profile=None):
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', alias):
        raise ValueError('invalid paired exit ID')
    profiles = bundle.get('routerProfiles', [])
    selected = selected or bundle.get('selectedRouterID')
    matches = [p for p in profiles if p.get('id') == selected]
    profile = matches[0] if len(matches) == 1 else None
    if isinstance(profile, dict) and profile.get('node_kind') == 'external':
        return pair_external(profile, alias, server_peer_profile)
    if server_peer_profile is not None:
        raise ValueError('A separate server peer profile belongs only to an external WG/AWG/OpenVPN pairing')
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
    for mode in ('awg2-fast', 'awg2-strong'):
        assets = modes.get(mode, {})
        if 'awg.conf' not in assets: continue
        transport = native_wireguard(assets['awg.conf'], node, endpoint, amnezia=True)
        exits.append(dict(id=alias,mode=mode,node_id=node,dns_server=dns,transport=transport))
    for mode in ('wg-pq', 'awg2-pq'):
        if mode not in modes: continue
        transport = native_pq(modes[mode], mode, node, endpoint)
        exits.append(dict(id=alias, mode=mode, node_id=node, dns_server=dns, transport=transport))
    for mode in ('naive-h2', 'naive-h3'):
        if mode not in modes: continue
        transport = native_naive(modes[mode], mode, endpoint)
        exits.append(dict(id=alias, mode=mode, node_id=node, dns_server=dns, transport=transport))
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
    for mode in ('reality-vision', 'reality-pq-vision', 'reality-xhttp'):
        assets = modes.get(mode)
        if assets is None: continue
        transport = native_xray(assets, mode, endpoint)
        exits.append(dict(id=alias, mode=mode, node_id=node, dns_server=dns, transport=transport))
    for mode in ('ss-v2ray', 'split', 'max'):
        if mode not in modes: continue
        transport = native_composite(modes[mode], mode, node, endpoint, profile.get('router_api'))
        exits.append(dict(id=alias, mode=mode, node_id=node, dns_server=dns, transport=transport))
    for mode in ('max-tls-wg', 'max-tls-awg', 'max-quic-wg', 'max-quic-awg'):
        if mode not in modes: continue
        transport = native_max(modes[mode], mode, node, endpoint, profile.get('router_api'))
        exits.append(dict(id=alias, mode=mode, node_id=node, dns_server=dns, transport=transport))
    if not exits:
        raise ValueError('bundle has no supported native server exit graph')
    layer = paired_start_layer(bundle, profile, endpoint)
    if layer is not None:
        # Pair exactly the saved choice. A later client requesting another
        # encryption mode must re-pair; it cannot fall back to a bare exit.
        for item in exits: item['start_layer'] = copy.deepcopy(layer)
    return exits

def external_private_text(value, limit=4096):
    """Do not normalize authentication material or include it in an error."""
    try:
        return isinstance(value, str) and 0 < len(value.encode('utf-8')) <= limit and not any(c in value for c in '\x00\r\n')
    except UnicodeEncodeError:
        return False

def external_public_literal(value):
    if not isinstance(value, str): raise ValueError('external relay requires a public literal address')
    address = ipaddress.ip_address(literal(value))
    # Python calls documentation ranges private, unlike Go's netip.IsPrivate.
    # Match the runtime's explicit local/CGN exclusions and allow offline fixtures.
    if address in ipaddress.ip_network('10.0.0.0/8') or address in ipaddress.ip_network('172.16.0.0/12') or address in ipaddress.ip_network('192.168.0.0/16') or address in ipaddress.ip_network('100.64.0.0/10') or (address.version == 6 and (address.ipv4_mapped is not None or address in ipaddress.ip_network('fc00::/7'))):
        raise ValueError('external relay requires a public literal address')
    return str(address)

def external_tls_name(value):
    if not external_private_text(value, 253) or value != value.strip() or value.endswith('.'):
        return False
    try:
        address = ipaddress.ip_address(value)
        return '%' not in value and not (address.version == 6 and address.ipv4_mapped is not None) and not (address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified)
    except ValueError:
        return value.lower() != 'localhost' and all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label) for label in value.split('.'))

def external_start_layer(profile, ext, host):
    selected = profile.get('start_layer', 'off')
    if selected in ('', 'off'):
        if 'start_layer' in ext: raise ValueError('external Start Layer does not match its captured selection')
        return None
    bad = ValueError('external Start Layer requires exact private credentials and same-server ownership')
    layer = ext.get('start_layer')
    if selected not in ('aes-256-gcm', 'aes-256-gcm+xor-whitening') or not isinstance(layer, dict) or set(layer) != {'mode', 'api', 'transport'} or layer.get('mode') != selected:
        raise bad
    if not external_private_text(layer.get('api'), 2048): raise bad
    try:
        api = urlsplit(layer['api'])
        address = ipaddress.ip_address(literal(api.hostname))
        private = any(address in ipaddress.ip_network(network) for network in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7'))
        if not private or api.scheme not in ('http', 'https') or api.username is not None or api.password is not None or api.query or api.fragment or api.path not in ('', '/') or not api.port or not 1 <= api.port <= 65535:
            raise bad
    except (ValueError, TypeError):
        raise bad from None
    outer = layer['transport']
    if not isinstance(outer, dict) or set(outer) != {'type', 'tag', 'server', 'server_port', 'method', 'password'} or outer['type'] != 'shadowsocks' or outer['method'] != '2022-blake3-aes-256-gcm' or type(outer['server_port']) is not int or not 1 <= outer['server_port'] <= 65535:
        raise bad
    try:
        if external_public_literal(outer['server']) != host: raise bad
    except (ValueError, TypeError):
        raise bad from None
    if not isinstance(outer['tag'], str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', outer['tag']) or not external_private_text(outer['password']):
        raise bad
    try:
        for part in outer['password'].split(':'):
            key = base64.b64decode(part, validate=True)
            if len(key) != 32 or base64.b64encode(key).decode() != part: raise bad
    except (ValueError, TypeError):
        raise bad from None
    return copy.deepcopy(layer)

def pair_external_packet(profile, alias, server_peer_profile):
    """The shared Go compiler derives identities and checks key separation."""
    bad = ValueError('External packet pairing requires its separately provisioned server peer profile')
    ext = profile.get('external')
    if not isinstance(server_peer_profile, dict) or not isinstance(ext, dict) or profile.get('node_proof_id') or profile.get('router_api') or profile.get('api_token'):
        raise bad
    payload = json.dumps(dict(alias=alias, external=ext, server_peer_profile=server_peer_profile,
                              selected_layer=profile.get('start_layer', 'off')), allow_nan=False).encode('utf-8')
    if len(payload) > 256 << 10: raise bad
    try:
        result = subprocess.run(['/usr/local/bin/router-vpn-agent', 'compile-external-packet-pair'],
                                input=payload, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                check=True, timeout=20)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        raise bad from None
    if not result.stdout or len(result.stdout) > (256 << 10) + 1: raise bad
    paired = decode(result.stdout)
    if not isinstance(paired, dict) or paired.get('id') != alias or paired.get('mode') != ext.get('protocol') or paired.get('node_id') != '' or paired.get('dns_server') != '': raise bad
    external = paired.get('external')
    if not isinstance(external, dict) or not isinstance(external.get('packet'), dict) or external['packet'].get('owner') != 'server': raise bad
    # The native registry validator subsequently parses the actual engine graph
    # before atomic publication. No input profile or new client key is persisted.
    return [paired]

def pair_external_openvpn(profile, alias, server_peer_profile):
    """Compile independent owned TLS/provider identities through the native parser."""
    bad = ValueError('External OpenVPN pairing requires its independent private provider profile and dedicated pairing key')
    ext = profile.get('external')
    if not isinstance(server_peer_profile, dict) or not isinstance(ext, dict) or profile.get('node_proof_id') or profile.get('router_api') or profile.get('api_token'):
        raise bad
    payload = json.dumps(dict(alias=alias, external=ext, server_peer_profile=server_peer_profile,
                              selected_layer=profile.get('start_layer', 'off')), allow_nan=False).encode('utf-8')
    if len(payload) > 2 << 20: raise bad
    try:
        result = subprocess.run(['/usr/local/bin/router-vpn-agent', 'compile-external-openvpn-pair'],
                                input=payload, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                check=True, timeout=20)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        raise bad from None
    if not result.stdout or len(result.stdout) > (2 << 20) + 1: raise bad
    paired = decode(result.stdout)
    if not isinstance(paired, dict) or paired.get('id') != alias or paired.get('mode') != 'openvpn' or paired.get('node_id') != '' or paired.get('dns_server') != '': raise bad
    external = paired.get('external')
    if not isinstance(external, dict) or not isinstance(external.get('openvpn'), dict) or external['openvpn'].get('owner') != 'server': raise bad
    return [paired]

def pair_external(profile, alias, server_peer_profile=None):
    """Privately pair native exit credentials and the exact selected layer."""
    ext = profile.get('external')
    bad = ValueError('external server execution requires an exact authenticated proxy and public response endpoint')
    if not isinstance(ext, dict): raise bad
    protocol = ext.get('protocol')
    if protocol in ('wireguard', 'amneziawg'):
        return pair_external_packet(profile, alias, server_peer_profile)
    if protocol == 'openvpn':
        return pair_external_openvpn(profile, alias, server_peer_profile)
    if server_peer_profile is not None: raise bad
    if protocol not in ('shadowsocks', 'hysteria2', 'socks5', 'http-connect', 'https-connect'):
        raise bad
    block = protocol.replace('-', '_')
    if set(ext) - {'protocol', 'expected_public_ip', block, 'response_probe', 'start_layer'} or not {'protocol', 'expected_public_ip', block, 'response_probe'} <= set(ext):
        raise bad
    if profile.get('node_proof_id') or profile.get('router_api') or profile.get('api_token'):
        raise bad
    proxy, probe = ext[block], ext['response_probe']
    if not isinstance(probe, dict) or set(probe) - {'url', 'server_name'} or not external_private_text(probe.get('url'), 2048) or not isinstance(probe.get('server_name', ''), str):
        raise bad
    fields = {'server', 'port', 'password'} if protocol in ('shadowsocks', 'hysteria2') else {'host', 'port', 'username', 'password'}
    if protocol == 'shadowsocks': fields.add('method')
    if protocol in ('hysteria2', 'https-connect'): fields.add('tls_server_name')
    optional = {'tls_server_name'} if protocol == 'http-connect' else set()
    if not isinstance(proxy, dict) or not fields <= set(proxy) or set(proxy) - fields - optional or type(proxy.get('port')) is not int or not 1 <= proxy['port'] <= 65535 or not external_private_text(proxy.get('password'), 255 if protocol == 'socks5' else 4096):
        raise bad
    host_key = 'server' if protocol in ('shadowsocks', 'hysteria2') else 'host'
    try:
        host, expected = external_public_literal(proxy[host_key]), external_public_literal(ext['expected_public_ip'])
    except (ValueError, TypeError):
        raise bad from None
    transport = dict(type=protocol, tag='exit', server=host, server_port=proxy['port'], password=proxy['password'])
    if protocol == 'shadowsocks':
        if proxy['method'] not in ('2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305', 'aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305'): raise bad
        transport['method'] = proxy['method']
    elif protocol in ('socks5', 'http-connect', 'https-connect'):
        if not external_private_text(proxy['username'], 255) or protocol != 'socks5' and ':' in proxy['username']: raise bad
        transport['username'] = proxy['username']
        transport['type'] = 'socks' if protocol == 'socks5' else 'http'
        if protocol == 'socks5': transport['version'] = '5'
    if protocol in ('hysteria2', 'https-connect'):
        if not external_tls_name(proxy['tls_server_name']): raise bad
        transport['tls'] = dict(enabled=True, server_name=proxy['tls_server_name'])
    if protocol == 'http-connect' and proxy.get('tls_server_name', '') != '': raise bad
    layer = external_start_layer(profile, ext, host)
    # The actual native registry checker repeats cipher, TLS, response-probe and
    # layer ownership validation before atomic publication. Selected DNS stays
    # in the client; no resolver or global tunnel is installed by this command.
    result = dict(id=alias, mode=protocol, node_id='', dns_server='', transport=transport,
                  external=dict(expected_public_ip=expected, response_probe=copy.deepcopy(probe)))
    if layer is not None: result['start_layer'] = layer
    return [result]

def registry_bytes(registry):
    body = (json.dumps(registry, indent=2, allow_nan=False)+'\n').encode('utf-8')
    if len(body) > MAX_REGISTRY_BYTES:
        raise ValueError('paired registry exceeds its private source bound')
    return body

def compile_tor_source(raw, alias, node):
    """Only the shared worker compiler decides bridge/DNS policy and hashes."""
    bad = ValueError('private Tor source failed shared policy compilation')
    try:
        source = decode(raw)
        payload = json.dumps(dict(entry_node_id=node, source=source), allow_nan=False).encode('utf-8')
        if len(payload) > 128 << 10:
            raise bad
        result = subprocess.run(['/usr/local/bin/router-vpn-agent', 'compile-server-tor-source'],
                                input=payload, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                check=True, timeout=20)
        if not result.stdout or len(result.stdout) > 256 << 10:
            raise bad
        compiled = decode(result.stdout)
        if not isinstance(compiled, dict) or set(compiled) != {'source_json', 'reference'}:
            raise bad
        reference, canonical = compiled['reference'], compiled['source_json']
        if not isinstance(reference, dict) or set(reference) != {'id', 'mode', 'source_sha256', 'dns_policy_sha256'} or not isinstance(canonical, str):
            raise bad
        body = canonical.encode('utf-8')
        if not body or len(body) > MAX_TOR_SOURCE_BYTES or reference.get('id') != alias or reference.get('mode') not in ('tor', 'tor-bridge'):
            raise bad
        if any(not isinstance(reference.get(key), str) or not re.fullmatch('[0-9a-f]{64}', reference[key]) for key in ('source_sha256', 'dns_policy_sha256')):
            raise bad
        captured = decode(body)
        if (not isinstance(captured, dict) or captured.get('id') != alias or captured.get('entry_node_id') != node or
                captured.get('mode') != reference['mode'] or hashlib.sha256(body).hexdigest() != reference['source_sha256']):
            raise bad
        return reference, body
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError, TypeError, KeyError, UnicodeError):
        raise bad from None

def node_chain_source_digest(canonical, schema):
    """Match the shared source domain and Go's JSON string encoding exactly."""
    domain = 'routervpn-server-node-chain-source-v' + str(schema)
    encoded = json.dumps([domain, canonical], ensure_ascii=False, allow_nan=False, separators=(',', ':'))
    for character, escaped in (('&', '\\u0026'), ('<', '\\u003c'), ('>', '\\u003e'),
                               ('\u2028', '\\u2028'), ('\u2029', '\\u2029')):
        encoded = encoded.replace(character, escaped)
    return hashlib.sha256(encoded.encode('utf-8')).hexdigest()


def compile_node_chain_source(raw, node):
    """Keep the shared compiler's complete descriptor and original private input."""
    bad = ValueError('private ordered source failed shared policy compilation')
    try:
        if not raw or len(raw) > MAX_NODE_CHAIN_SOURCE_BYTES:
            raise bad
        source = decode(raw)
        fields = {'schema', 'entry_id', 'entry_node_id', 'entry_mode', 'nodes', 'identity_sources'}
        if not isinstance(source, dict) or set(source) != fields:
            raise bad
        payload = json.dumps(dict(entry_node_id=node, source=source), ensure_ascii=False,
                             allow_nan=False, separators=(',', ':')).encode('utf-8')
        if len(payload) > MAX_NODE_CHAIN_SOURCE_BYTES + 4096:
            raise bad
        result = subprocess.run(['/usr/local/bin/router-vpn-agent', 'compile-server-node-chain-source'],
                                input=payload, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                check=True, timeout=20)
        return compiled_node_chain_source(result.stdout, node, source)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError, TypeError, KeyError, UnicodeError):
        raise bad from None


def compiled_node_chain_source(raw, node, original=None):
    """Validate the shared compiler output for either private input form."""
    bad = ValueError('private ordered source failed shared policy compilation')
    try:
        if not raw or len(raw) > 2 * MAX_NODE_CHAIN_SOURCE_BYTES + 4096:
            raise bad
        compiled = decode(raw)
        if not isinstance(compiled, dict) or set(compiled) != {'source_json', 'reference'}:
            raise bad
        reference, canonical = compiled['reference'], compiled['source_json']
        descriptor_fields = {'schema', 'entry_id', 'entry_node_id', 'entry_mode', 'source_sha256', 'dns_policy_sha256', 'members'}
        if not isinstance(reference, dict) or set(reference) != descriptor_fields or not isinstance(canonical, str):
            raise bad
        body = canonical.encode('utf-8')
        if not body or len(body) > MAX_NODE_CHAIN_SOURCE_BYTES:
            raise bad
        captured = decode(body)
        source_fields = {'schema', 'entry_id', 'entry_node_id', 'entry_mode', 'nodes', 'identity_sources'}
        if (not isinstance(captured, dict) or set(captured) != source_fields or
                original is not None and captured != original or
                type(captured.get('schema')) is not int or captured['schema'] not in (1, 2)):
            raise bad
        if any(reference.get(key) != captured.get(key) for key in ('schema', 'entry_id', 'entry_node_id', 'entry_mode')) or captured['entry_node_id'] != node:
            raise bad
        if any(not isinstance(reference.get(key), str) or not re.fullmatch('[0-9a-f]{64}', reference[key]) for key in ('source_sha256', 'dns_policy_sha256')):
            raise bad
        if node_chain_source_digest(canonical, captured['schema']) != reference['source_sha256']:
            raise bad
        members = reference['members']
        if not isinstance(members, list) or not isinstance(captured['nodes'], list) or not 1 <= len(members) <= 7 or len(members) != len(captured['nodes']):
            raise bad
        member_fields = {'position', 'profile_id', 'node_id', 'mode', 'start_layer'}
        optional_fields = {'client_public_key', 'server_public_key', 'node_kind', 'proof_kind', 'source_sha256', 'expected_public_ip'}
        for position, member in enumerate(members, 1):
            if (not isinstance(member, dict) or not member_fields <= set(member) or set(member) - member_fields - optional_fields or
                    type(member['position']) is not int or member['position'] != position or
                    any(not isinstance(value, str) for key, value in member.items() if key != 'position')):
                raise bad
        # Positional keys, exact node identities, selected DNS and every other
        # descriptor field remain owned by the native compiler and checker.
        return reference, body
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise bad from None


def private_snapshot(path, limit, *, optional=False):
    """Capture the exact owned file; replacements with equal bytes are stale."""
    path = Path(os.path.abspath(path))
    read, _, _ = helpers()
    try:
        before = path.lstat()
    except FileNotFoundError:
        if optional:
            return None
        raise
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o600:
        raise ValueError('private pairing input must be an owned mode-0600 regular file')
    body = read(path, limit, private=True)
    after = path.lstat()
    identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_mode, info.st_uid, info.st_nlink)
    if identity(before) != identity(after):
        raise ValueError('private pairing input changed while being captured')
    return path, body, after, limit

def require_snapshot(snapshot):
    current = private_snapshot(snapshot[0], snapshot[3])
    if current[1] != snapshot[1] or not os.path.samestat(current[2], snapshot[2]) or current[2].st_mtime_ns != snapshot[2].st_mtime_ns or current[2].st_ctime_ns != snapshot[2].st_ctime_ns:
        raise ValueError('private pairing input changed during native validation')


def compile_node_chain_plan(path, node):
    """Resolve explicit private bundle files into the shared typed plan compiler.

    The plan contains paths and selections only. Imported capture strings stay
    byte-for-byte as exported, and every source inode remains captured until
    the staged registry is checked and publication is ready to commit.
    """
    bad = ValueError('private ordered bundle plan failed shared policy compilation')
    try:
        plan_snapshot = private_snapshot(path, 64 << 10)
        plan = decode(plan_snapshot[1])
        if (not isinstance(plan, dict) or set(plan) != {'schema', 'entry', 'members'} or
                type(plan['schema']) is not int or plan['schema'] != 1 or
                not isinstance(plan['members'], list) or not 1 <= len(plan['members']) <= 7):
            raise bad
        snapshots = {plan_snapshot[0]: plan_snapshot}
        captured_bytes = len(plan_snapshot[1])

        def capture(name, limit):
            nonlocal captured_bytes
            if (not isinstance(name, str) or not name or len(name) > 4096 or
                    '\x00' in name or '://' in name):
                raise bad
            selected = Path(os.path.abspath(plan_snapshot[0].parent / name))
            if selected not in snapshots:
                snapshot = private_snapshot(selected, limit)
                captured_bytes += len(snapshot[1])
                if captured_bytes > MAX_NODE_CHAIN_SOURCE_BYTES:
                    raise bad
                snapshots[selected] = snapshot
            snapshot = snapshots[selected]
            if not snapshot[1] or len(snapshot[1]) > limit:
                raise bad
            return snapshot[1]

        def selection(value, *, peer=False):
            required = {'bundle_file', 'profile_id'} if peer else {'bundle_file', 'profile_id', 'mode'}
            optional = set() if peer else {'dns_bootstrap_file'}
            if not isinstance(value, dict) or not required <= set(value) or set(value) - required - optional:
                raise bad
            result = {'bundle': decode(capture(value['bundle_file'], 32 << 20)), 'profile_id': value['profile_id']}
            if not peer:
                result['mode'] = value['mode']
                if 'dns_bootstrap_file' in value:
                    result['dns_bootstrap'] = capture(value['dns_bootstrap_file'], 16384).decode('utf-8')
            return result

        resolved = dict(schema=1, entry_node_id=node, entry=selection(plan['entry']), members=[])
        for member in plan['members']:
            if not isinstance(member, dict):
                raise bad
            if set(member) == {'imported'}:
                imported = member['imported']
                if not isinstance(imported, dict) or set(imported) != {'capture_file'}:
                    raise bad
                original = decode(capture(imported['capture_file'], MAX_NODE_CHAIN_SOURCE_BYTES))
                if (not isinstance(original, dict) or set(original) != {'config', 'capture'} or
                        any(not isinstance(value, str) or not value for value in original.values())):
                    raise bad
                resolved['members'].append({'imported': original})
            elif set(member) == {'paired', 'server_peer'}:
                resolved['members'].append(dict(paired=selection(member['paired']),
                                                server_peer=selection(member['server_peer'], peer=True)))
            else:
                raise bad
        payload = json.dumps(resolved, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode('utf-8')
        if not payload or len(payload) > MAX_NODE_CHAIN_SOURCE_BYTES:
            raise bad
        result = subprocess.run(['/usr/local/bin/router-vpn-agent', 'compile-server-node-chain-plan'],
                                input=payload, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                check=True, timeout=20)
        addition = compiled_node_chain_source(result.stdout, node)
        return addition, list(snapshots.values())
    except (OSError, RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired,
            ValueError, TypeError, KeyError, UnicodeError):
        raise bad from None

def source_directory(path, *, create=False, label='Tor'):
    path = Path(os.path.abspath(path))
    _, _, parent = helpers()
    if create:
        parent(path / 'source.json')
    else:
        for current in (path, *path.parents):
            try:
                info = current.lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError(label + ' source path must not traverse linked or non-directory ancestors')
        # A missing directory is valid only until its first source is published.
        if not path.exists() and not path.is_symlink():
            return path
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError(label + ' source directory must be an owned mode-0700 directory')
    return path

def source_directory_snapshot(path, *, label='Tor'):
    source_directory(path, label=label)
    try:
        return path.lstat()
    except FileNotFoundError:
        return None

def require_source_directory(path, before, *, label='Tor'):
    current = source_directory_snapshot(path, label=label)
    if before is None and current is not None or before is not None and (current is None or not os.path.samestat(before, current)):
        raise ValueError(label + ' source directory changed during native validation')

def stage_tor_sources(registry, sources, stage, addition):
    return stage_private_sources(registry.get('tor_exits', []), sources, stage, addition, MAX_TOR_SOURCE_BYTES, 'Tor')


def stage_node_chain_sources(registry, sources, stage, addition):
    return stage_private_sources(registry.get('node_chains', []), sources, stage, addition, MAX_NODE_CHAIN_SOURCE_BYTES, 'ordered')


def stage_private_sources(references, sources, stage, addition, limit, label):
    if not references:
        return {}, []
    sources = source_directory(sources, label=label)
    _, write, _ = helpers()
    stage.mkdir(mode=0o700)
    bodies, snapshots = {}, []
    for reference in references:
        digest = reference.get('source_sha256') if isinstance(reference, dict) else None
        if not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest):
            raise ValueError(label + ' registry source reference is not canonical')
        if digest in bodies:
            continue
        selected = addition is not None and digest == addition[0]['source_sha256']
        snapshot = private_snapshot(sources / (digest + '.json'), limit, optional=selected)
        if selected:
            body = addition[1]
            if snapshot is not None and snapshot[1] != body:
                raise ValueError('existing immutable ' + label + ' source differs from its canonical selection')
        else:
            body = snapshot[1]
        if snapshot is not None:
            snapshots.append(snapshot)
        bodies[digest] = body
        write(stage / (digest + '.json'), body)
    return bodies, snapshots

def publish_tor_source(path, body):
    return publish_private_source(path, body, 'Tor', '.tor-source-')


def publish_node_chain_source(path, body):
    return publish_private_source(path, body, 'ordered', '.node-chain-source-')


def publish_private_source(path, body, label, prefix):
    """Publish one immutable hash-addressed source without replacing any file."""
    path = Path(os.path.abspath(path))
    source_directory(path.parent, create=True, label=label)
    descriptor, name = tempfile.mkstemp(prefix=prefix, dir=path.parent)
    temporary = Path(name)
    owned, linked = os.fstat(descriptor), False
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        owned = temporary.lstat()
        # The complete source becomes visible before the registry references it.
        # link() has no replacement mode, unlike a general atomic file writer.
        os.link(temporary, path, follow_symlinks=False)
        linked = True
        if not os.path.samestat(owned, path.lstat()):
            raise ValueError(label + ' source ownership changed during publication')
        temporary.unlink()
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            try:
                os.fsync(directory)
            except OSError:
                # As with the registry writer, some filesystems do not expose
                # directory fsync. The exact complete inode is already linked.
                pass
        finally:
            os.close(directory)
        return path.lstat()
    except BaseException:
        if linked:
            remove_owned_tor_source(path, owned)
        raise
    finally:
        try:
            if os.path.samestat(temporary.lstat(), owned):
                temporary.unlink()
        except FileNotFoundError:
            pass

def remove_owned_tor_source(path, identity):
    try:
        current = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISREG(current.st_mode) and os.path.samestat(current, identity) and current.st_size == identity.st_size and current.st_mtime_ns == identity.st_mtime_ns:
        path.unlink()

def registry_unchanged(path, snapshot):
    try:
        if snapshot is not None:
            require_snapshot(snapshot)
        elif path.exists() or path.is_symlink():
            return False
        return True
    except (OSError, ValueError, RuntimeError):
        return False

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--bundle', type=Path)
    source.add_argument('--tor-source', type=Path, help='private data-only Tor source; shared native compiler preserves its ID and selected DNS')
    source.add_argument('--node-chain-source', type=Path, help='private complete ordered server source; preserve its original descriptor and selected DNS')
    source.add_argument('--node-chain-plan', type=Path, help='private ordered plan naming complete client and independent server bundle files')
    parser.add_argument('--exit-id', help='required ID for ordinary and Tor exits; ordered sources retain their own descriptor identity')
    parser.add_argument('--bundle-profile')
    parser.add_argument('--server-peer-profile', type=Path, help='separate private WG/AWG/OpenVPN server peer JSON; never a client bundle')
    parser.add_argument('--agent-config', type=Path, default=Path('/etc/router-vpn/router-agent.json'))
    parser.add_argument('--registry', type=Path, default=Path('/etc/router-vpn/multihop-relays.json'))
    parser.add_argument('--tor-sources', type=Path, help='private immutable source directory; defaults to tor-sources beside the registry')
    parser.add_argument('--node-chain-sources', type=Path, help='private immutable ordered source directory; defaults to node-chain-sources beside the registry')
    parser.add_argument('--dry-run', type=Path, help='write a private validated review plan to this explicit file; leave the registry and sources unchanged')
    parser.add_argument('--listen-ip', required=True, help='entry tunnel IP used by clients for the Router API')
    args = parser.parse_args()
    ordered = args.node_chain_source is not None or args.node_chain_plan is not None
    if not ordered and args.exit_id is None:
        parser.error('--exit-id is required for ordinary and Tor pairing')
    if ordered and args.exit_id is not None:
        parser.error('ordered source pairing preserves its descriptor and does not accept --exit-id')
    read, write, parent = helpers()
    args.registry = Path(os.path.abspath(args.registry))
    args.agent_config = Path(os.path.abspath(args.agent_config))
    sources = Path(os.path.abspath(args.tor_sources or args.registry.parent / 'tor-sources'))
    chain_sources = Path(os.path.abspath(args.node_chain_sources or args.registry.parent / 'node-chain-sources'))
    if args.tor_source is not None and (args.bundle_profile is not None or args.server_peer_profile is not None):
        raise ValueError('Tor source pairing does not accept a bundle profile or provider peer')
    if ordered and (args.bundle_profile is not None or args.server_peer_profile is not None):
        raise ValueError('ordered source pairing does not accept a bundle profile or provider peer')
    if args.dry_run is not None:
        args.dry_run = Path(os.path.abspath(args.dry_run))
        protected = [args.registry, args.agent_config, args.bundle, args.tor_source, args.node_chain_source, args.node_chain_plan, args.server_peer_profile]
        if args.dry_run in [Path(os.path.abspath(path)) for path in protected if path is not None] or any(args.dry_run == directory or directory in args.dry_run.parents for directory in (sources, chain_sources)):
            raise ValueError('dry-run output must be separate from live and input files')
        parent(args.dry_run)
    agent_snapshot = private_snapshot(args.agent_config, 1 << 20)
    agent = decode(agent_snapshot[1])
    input_snapshot = private_snapshot(args.tor_source, MAX_TOR_SOURCE_BYTES) if args.tor_source is not None else None
    addition = compile_tor_source(input_snapshot[1], args.exit_id, agent.get('node_id')) if input_snapshot is not None else None
    chain_input = private_snapshot(args.node_chain_source, MAX_NODE_CHAIN_SOURCE_BYTES) if args.node_chain_source is not None else None
    chain_addition = compile_node_chain_source(chain_input[1], agent.get('node_id')) if chain_input is not None else None
    input_snapshots = [snapshot for snapshot in (input_snapshot, chain_input) if snapshot is not None]
    if args.node_chain_plan is not None:
        chain_addition, plan_snapshots = compile_node_chain_plan(args.node_chain_plan, agent.get('node_id'))
        input_snapshots.extend(plan_snapshots)
        if args.dry_run is not None and args.dry_run in [snapshot[0] for snapshot in plan_snapshots]:
            raise ValueError('dry-run output must be separate from every private plan input')
    server_peer = decode(read(args.server_peer_profile, 512 << 10)) if args.server_peer_profile is not None else None
    entries = [] if addition is not None or chain_addition is not None else pair(decode(read(args.bundle, 32 << 20)), args.exit_id, args.bundle_profile, server_peer)
    listen = ipaddress.ip_address(literal(args.listen_ip))
    if not listen.is_private or not any(listen in ipaddress.ip_network(n) for n in agent.get('tunnel_cidrs', [])):
        raise ValueError('listen IP must belong to the entry tunnel ranges')
    if any(e.get('node_id') and e['node_id'] == agent.get('node_id') for e in entries):
        raise ValueError('entry and exit must have distinct identities')
    # Dry-run may inspect a read-only production mount. It takes immutable
    # snapshots and rechecks them, without creating a lock or source there.
    lock = contextlib.nullcontext() if args.dry_run is not None else registry_lock(args.registry)
    with lock:
        registry_snapshot = private_snapshot(args.registry, MAX_REGISTRY_BYTES, optional=True)
        if registry_snapshot is None:
            registry = dict(listen_ip=str(listen), first_port=26240, last_port=26271, ttl_seconds=90, exits=[])
        else:
            registry = decode(registry_snapshot[1])
        if registry.get('listen_ip') != str(listen):
            raise ValueError('existing registry has a different entry listener')
        ordinary, tor, chains = registry.get('exits'), registry.get('tor_exits'), registry.get('node_chains')
        ordinary = [] if ordinary is None else ordinary
        tor = [] if tor is None else tor
        chains = [] if chains is None else chains
        if not all(isinstance(value, list) for value in (ordinary, tor, chains)):
            raise ValueError('registry exits must be bounded lists')
        if chain_addition is not None:
            # The manager keys ordered paths by source digest, not an exit alias
            # or a tuple of node names. Keep distinct DNS/layer/source variants.
            same = [item for item in chains if isinstance(item, dict) and item.get('source_sha256') == chain_addition[0]['source_sha256']]
            if len(same) > 1 or same and same[0] != chain_addition[0]:
                raise ValueError('existing ordered descriptor differs from its immutable source identity')
            registry['node_chains'] = chains if same else [*chains, chain_addition[0]]
        elif addition is not None:
            registry['tor_exits'] = [e for e in tor if e['id'] != args.exit_id] + [addition[0]]
        else:
            registry['exits'] = [e for e in ordinary if e['id'] != args.exit_id] + entries
        if sum(len(registry.get(name) or []) for name in ('exits', 'tor_exits', 'node_chains')) > 64:
            raise ValueError('paired exit count exceeds bound')
        body = registry_bytes(registry)
        staging_parent = args.dry_run.parent if args.dry_run is not None else args.registry.parent
        with tempfile.TemporaryDirectory(prefix='.relay-pair-', dir=staging_parent) as tmp:
            stage = Path(tmp)/'registry.json'
            write(stage, body)
            directory_identity = source_directory_snapshot(sources) if registry.get('tor_exits') else None
            chain_directory_identity = source_directory_snapshot(chain_sources, label='ordered') if registry.get('node_chains') else None
            source_bodies, source_snapshots = stage_tor_sources(registry, sources, Path(tmp)/'tor-sources', addition)
            chain_bodies, chain_snapshots = stage_node_chain_sources(registry, chain_sources, Path(tmp)/'node-chain-sources', chain_addition)
            source_snapshots.extend(chain_snapshots)
            command = ['/usr/local/bin/router-vpn-agent', 'check-multihop-registry', str(stage), str(args.agent_config)]
            if source_bodies or chain_bodies:
                # The optional ordered directory is argv[5]; argv[4] remains
                # the Tor directory, including an empty private placeholder.
                (Path(tmp)/'tor-sources').mkdir(mode=0o700, exist_ok=True)
                command.append(str(Path(tmp)/'tor-sources'))
            if chain_bodies:
                command.append(str(Path(tmp)/'node-chain-sources'))
            subprocess.run(command, check=True, timeout=60, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for snapshot in [agent_snapshot, *source_snapshots, *input_snapshots]:
                require_snapshot(snapshot)
            if source_bodies:
                require_source_directory(sources, directory_identity)
            if chain_bodies:
                require_source_directory(chain_sources, chain_directory_identity, label='ordered')
            if not registry_unchanged(args.registry, registry_snapshot):
                raise ValueError('registry changed during native validation; no replacement was written')
            if args.dry_run is not None:
                plan = dict(schema=1, kind='routervpn-relay-pairing-plan', entry_node_id=agent['node_id'], registry=registry,
                            tor_sources={digest: raw.decode('utf-8') for digest, raw in source_bodies.items()})
                if chain_bodies:
                    plan['node_chain_sources'] = {digest: raw.decode('utf-8') for digest, raw in chain_bodies.items()}
                write(args.dry_run, registry_bytes(plan))
            else:
                created = None
                selected = chain_addition if chain_addition is not None else addition
                selected_sources = chain_sources if chain_addition is not None else sources
                selected_limit = MAX_NODE_CHAIN_SOURCE_BYTES if chain_addition is not None else MAX_TOR_SOURCE_BYTES
                publish = publish_node_chain_source if chain_addition is not None else publish_tor_source
                target = selected_sources / (selected[0]['source_sha256'] + '.json') if selected is not None else None
                try:
                    if source_bodies:
                        require_source_directory(sources, directory_identity)
                    if chain_bodies:
                        require_source_directory(chain_sources, chain_directory_identity, label='ordered')
                    if target is not None and all(snapshot[0] != target for snapshot in source_snapshots):
                        created = publish(target, selected[1])
                        snapshot = private_snapshot(target, selected_limit)
                        if not os.path.samestat(created, snapshot[2]) or snapshot[1] != selected[1]:
                            raise ValueError('new private source changed before registry publication')
                        source_snapshots.append(snapshot)
                    for snapshot in [agent_snapshot, *source_snapshots, *input_snapshots]:
                        require_snapshot(snapshot)
                    if not registry_unchanged(args.registry, registry_snapshot):
                        raise ValueError('registry changed before publication; no replacement was written')
                    write(args.registry, body)
                except BaseException:
                    # An uncertain/changed registry may already reference the
                    # source. Never undo another owner's adoption or replacement.
                    if created is not None and registry_unchanged(args.registry, registry_snapshot):
                        remove_owned_tor_source(target, created)
                    raise
    if args.dry_run is not None:
        print('Validated private pairing plan written. Registry and source files were not changed.')
    else:
        print('Paired',1 if addition is not None or chain_addition is not None else len(entries),'validated transport configurations. No tunnel or service was started.')

if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # No imported payload, credentials or compiler stderr in a public error.
        raise SystemExit('Relay pairing failed: ' + str(error))
