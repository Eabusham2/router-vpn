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
    if not exits:
        raise ValueError('bundle has no supported native server exit graph')
    layer = paired_start_layer(bundle, profile, endpoint)
    if layer is not None:
        # Pair exactly the saved choice. A later client requesting another
        # encryption mode must re-pair; it cannot fall back to a bare exit.
        for item in exits: item['start_layer'] = copy.deepcopy(layer)
    return exits

def registry_bytes(registry):
    body = (json.dumps(registry, indent=2, allow_nan=False)+'\n').encode('utf-8')
    if len(body) > MAX_REGISTRY_BYTES:
        raise ValueError('paired registry exceeds its private source bound')
    return body

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
            existing_raw = read(args.registry, MAX_REGISTRY_BYTES)
            registry = decode(existing_raw)
        except FileNotFoundError:
            existing_raw = None
            registry = dict(listen_ip=str(listen), first_port=26240, last_port=26271, ttl_seconds=90, exits=[])
        if registry.get('listen_ip') != str(listen):
            raise ValueError('existing registry has a different entry listener')
        registry['exits'] = [e for e in registry['exits'] if e['id'] != args.exit_id] + entries
        if len(registry['exits']) > 64:
            raise ValueError('paired exit count exceeds bound')
        body = registry_bytes(registry)
        with tempfile.TemporaryDirectory(prefix='.relay-pair-', dir=args.registry.parent) as tmp:
            stage = Path(tmp)/'registry.json'
            write(stage, body)
            subprocess.run(['/usr/local/bin/router-vpn-agent', 'check-multihop-registry', str(stage), str(args.agent_config)],
                           check=True, timeout=60, stdout=subprocess.DEVNULL)
            try:
                now = read(args.registry, MAX_REGISTRY_BYTES)
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
