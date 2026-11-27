"""Independent protocol peers for installed Linux SMART qualification inside a disposable peer namespace."""

from contextlib import contextmanager, ExitStack
import base64
import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path
import secrets
import signal
import select
import stat
import subprocess
import time


ROOT = Path(__file__).resolve().parents[1]
INSTALL = Path('/opt/router-vpn-client')
ENGINE = INSTALL/'runtime/native/sing-box-routervpn'
OUTER = '172.30.241.2'
PRIVATE = '10.77.0.1'
PORTS = {'wg': 51820, 'wg-pq': 51821, 'rosenpass': 51822,
         'naive-h3': 18443, 'naive-h2': 18444, 'hysteria2': 18445,
         'aes-256-gcm': 8388, 'aes-256-gcm+xor-whitening': 8389}


def output(args, *, data=None):
    return subprocess.run(args, input=data, stdout=subprocess.PIPE, check=True).stdout


def prepare_reference_tools(directory):
    """Run on the host before entering the qualification namespaces."""
    target = Path(directory).resolve() / 'reference-tools'
    target.mkdir(mode=0o700)
    # This is the same upstream binary copied into the shipping Rosenpass peer.
    source = (ROOT/'server/rosenpass/Dockerfile').read_text().splitlines()[0].split()
    if source[:1] != ['FROM'] or source[2:] != ['AS', 'rosenpass']:
        raise ValueError('Unrecognized Rosenpass reference build')
    container = output(['docker', 'create', '--entrypoint', '/usr/local/bin/rosenpass', source[1], '--version']).decode().strip()
    try:
        subprocess.run(['docker', 'cp', container+':/usr/local/bin/rosenpass', str(target/'rosenpass')], check=True)
    finally:
        subprocess.run(['docker', 'rm', container], stdout=subprocess.DEVNULL, check=True)
    subprocess.run([target/'rosenpass', '--version'], check=True)
    subprocess.run(['go', 'build', '-buildvcs=false', '-mod=readonly', '-o', target/'router-agent', './cmd/router-agent'], cwd=ROOT, check=True)
    return {'ROUTERVPN_QUALIFICATION_ROSENPASS': str(target/'rosenpass'),
            'ROUTERVPN_QUALIFICATION_ROUTER_AGENT': str(target/'router-agent')}


def http_header_summary(data):
    """Bounded header-only readback from the existing private -tt -S capture."""
    first, last = [], []
    offset = complete = count = invalid = 0
    for raw in data.splitlines(keepends=True):
        offset += len(raw)
        if not raw.endswith(b'\n'):
            continue
        complete = offset
        match = re.fullmatch(
            rb'([0-9]{9,12})\.([0-9]{1,6})\s+'
            rb'(?:[A-Za-z0-9_.@:-]{1,32}\s+(?:In|Out)\s+)?'
            rb'IP ([0-9.]{7,15})\.([0-9]{1,5}) > ([0-9.]{7,15})\.([0-9]{1,5}): '
            rb'Flags \[([FSRPAUEW.]{0,9})\](.{0,512}?)length ([0-9]{1,5})(?::[^\r\n]*)?\r?\n',
            raw)
        if match is None:
            continue
        seconds, fraction, source, source_port, target, target_port, flags, details, length = match.groups()
        if source == PRIVATE.encode() and source_port == b'8787':
            direction = 'from_private'
        elif target == PRIVATE.encode() and target_port == b'8787':
            direction = 'to_private'
        else:
            continue
        try:
            source_ip, target_ip = str(ipaddress.IPv4Address(source.decode())), str(ipaddress.IPv4Address(target.decode()))
        except ValueError:
            invalid += 1
            continue
        source_port, target_port, length = int(source_port), int(target_port), int(length)
        if not (0 < source_port <= 65535 and 0 < target_port <= 65535 and length <= 65535):
            invalid += 1
            continue
        sequence = re.search(rb'(?:^|,\s*)seq ([0-9]{1,10})(?::([0-9]{1,10}))?(?=,|$)', details)
        ack = re.search(rb'(?:^|,\s*)ack ([0-9]{1,10})(?=,|$)', details)
        stamp = re.search(rb'\bTS val ([0-9]{1,10}) ecr ([0-9]{1,10})(?=,|\]|$)', details)
        numbers = {'sequence': int(sequence[1]) if sequence else None,
                   'sequence_end': int(sequence[2]) if sequence and sequence[2] else None,
                   'acknowledgment': int(ack[1]) if ack else None,
                   'tsval': int(stamp[1]) if stamp else None,
                   'tsecr': int(stamp[2]) if stamp else None}
        if any(value is not None and value > 0xffffffff for value in numbers.values()):
            invalid += 1
            continue
        count += 1
        record = {'index': count, 'byte_end': offset,
                  'unix_us': int(seconds)*1_000_000 + int(fraction.ljust(6, b'0')),
                  'direction': direction, 'source': source_ip, 'source_port': source_port,
                  'target': target_ip, 'target_port': target_port,
                  'flags': flags.decode('ascii'), 'payload_bytes': length, **numbers}
        if len(first) < 8:
            first.append(record)
        last.append(record)
        del last[:-16]
    tail = [record for record in last if record['index'] > len(first)]
    return {'clock': 'unix_microseconds', 'sequence_numbers': 'absolute',
            'cursor': {'sample_bytes': len(data), 'complete_line_bytes': complete, 'parsed_headers': count},
            'invalid_numeric_headers': invalid, 'omitted_headers': count-len(first)-len(tail),
            'first': first, 'last': tail}


def stop_process(process):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(4)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(4)


class Peers:
    def __init__(self, namespace, workdir, source, candidate, stack, layer='off'):
        self.ns = ['ip', 'netns', 'exec', namespace]
        self.work = Path(workdir).resolve() / 'peers'
        self.work.mkdir(mode=0o700)
        self.source, self.candidate, self.stack, self.layer = source, candidate, stack, layer
        self.ports, self.assets, self.processes = dict(PORTS), {}, {}
        self.enabled = False
        self.last_pq_key_digest, self.pq_generation = None, 0
        self.agent_table = 'smart_agent_'+secrets.token_hex(4)
        self.server_key = self.wg_key('server')
        self.client_keys = {}
        node = hashlib.sha256(('router-vpn-node-proof-v1\n'+self.server_key).encode()).hexdigest()
        self.profile = {'id': 'qualification', 'name': 'Qualification', 'node_kind': 'router-vpn',
                        'endpoint': OUTER, 'node_proof_id': node, 'api_token': secrets.token_hex(32),
                        'router_api': f'http://{PRIVATE}:8787', 'path_probe_url': f'http://{PRIVATE}:8787/health',
                        'adguard_ipv4': PRIVATE, 'dns_mode': 'home', 'dns_protocol': 'udp',
                        'start_layer': layer, 'ipv6_mode': 'off', 'kill_switch': True}
        self.password = secrets.token_urlsafe(32)

    def put(self, name, value):
        path = self.work/name
        with path.open('xb') as file:
            os.fchmod(file.fileno(), 0o600)
            file.write(value if isinstance(value, bytes) else value.encode())
        return path

    def wg_key(self, name):
        private = output(['wg', 'genkey'])
        self.put(name+'.key', private)
        return output(['wg', 'pubkey'], data=private).decode().strip()

    def spawn(self, name, args, env=None):
        log = self.stack.enter_context((self.work/(name+'.log')).open('wb'))
        process = subprocess.Popen(self.ns+list(args), stdout=log, stderr=log,
                                   env=env, start_new_session=True, cwd=self.work)
        self.stack.callback(stop_process, process)
        self.processes[name] = process
        return process

    def wait_listening(self, name, port, tcp):
        until = time.monotonic()+8
        while time.monotonic() < until and self.processes[name].poll() is None:
            sockets = output(self.ns+['ss', '-H', '-lntp' if tcp else '-lnup', 'sport', '=', ':'+str(port)])
            if f'pid={self.processes[name].pid},'.encode() in sockets:
                return
            time.sleep(.05)
        raise RuntimeError(f'{name} did not start its private peer listener')

    def start(self):
        addresses = json.loads(output(self.ns+['ip', '-j', 'address', 'show', 'dev', 'smartpeer']))
        if os.readlink('/proc/self/ns/net') == output(self.ns+['readlink', '/proc/self/ns/net']).decode().strip() or not any(
                a.get('local') == OUTER for link in addresses for a in link['addr_info']):
            raise ValueError('Expected the independently provisioned smartpeer namespace')
        output(self.ns+['ip', 'link', 'set', 'lo', 'up'])
        output(self.ns+['ip', 'addr', 'add', PRIVATE+'/32', 'dev', 'lo'])
        self.stack.callback(output, self.ns+['ip', 'addr', 'del', PRIVATE+'/32', 'dev', 'lo'])
        output(self.ns+['nft', 'create', 'table', 'inet', 'smart_peer'])
        self.stack.callback(output, self.ns+['nft', 'delete', 'table', 'inet', 'smart_peer'])
        # Even when the client has a physical default route, private proof and
        # DNS can enter only on the tunnel or from a locally decrypted stream.
        rules = [f'iifname "smartpeer" ip daddr {PRIVATE} counter drop']
        if self.layer != 'off':
            # Kernel WireGuard listens on all addresses. Reject exposed inner
            # ports independently of the client, including the Rosenpass socket.
            inner = ', '.join(str(PORTS[m]) for m in (self.source, self.candidate, 'rosenpass'))
            rules.extend(f'iifname "smartpeer" ip daddr {OUTER} {net} dport {{ {inner} }} counter drop' for net in ('tcp', 'udp'))
        ruleset = 'table inet smart_peer {\n chain input { type filter hook input priority -20; policy accept;\n'
        output(self.ns+['nft', '-f', '-'], data=(ruleset+'\n'.join(rules)+'\n }\n}\n').encode())
        self.start_services()
        self.build_assets()
        if self.layer != 'off':
            self.start_layer()
        self.start_mode(self.source)

    def start_services(self):
        path = self.put('agent.json', json.dumps({'listen': PRIVATE+':8787', 'node_id': self.profile['node_proof_id'],
            'token': self.profile['api_token'], 'wan_interface': 'smartpeer', 'nft_table': self.agent_table,
            'tunnel_cidrs': ['10.77.0.0/24'], 'daita_listen': PRIVATE+':45999'}))
        # The Router agent owns this private NAT table during its process lifetime.
        self.stack.callback(subprocess.run, self.ns+['nft', 'delete', 'table', 'inet', self.agent_table],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.spawn('router', [os.environ['ROUTERVPN_QUALIFICATION_ROUTER_AGENT']],
                   dict(os.environ, ROUTER_VPN_CONFIG=str(path), ROUTER_VPN_MULTIHOP_CONFIG=str(self.work/'no-relays')))
        self.wait_listening('router', 8787, True)
        self.spawn('dns', ['dnsmasq', '--no-daemon', '--conf-file=/dev/null', '--no-resolv', '--no-hosts',
             '--cache-size=0', '--bind-interfaces', '--listen-address='+PRIVATE, '--log-queries',
             '--local=/#/', '--host-record=example.com,93.184.216.34', '--address=/#/'+OUTER])
        self.wait_listening('dns', 53, False)
        self.capture('http', ['-tt', '-S', '-A', '-s', '2048', '-i', 'any', f'host {PRIVATE} and tcp port 8787'])

    def capture(self, name, options):
        self.spawn(name, ['tcpdump', '-nn', '-l', *options])
        until = time.monotonic()+5
        while b'listening on ' not in (self.work/(name+'.log')).read_bytes():
            if self.processes[name].poll() is not None or time.monotonic() >= until:
                raise RuntimeError(f'{name} packet capture did not start')
            time.sleep(.05)

    def build_assets(self):
        for mode, inner in [('wg', '10.77.0.3'), ('wg-pq', '10.77.0.2')]:
            if mode == 'wg-pq' and mode != self.source:
                continue
            public = self.wg_key(mode)
            self.client_keys[mode] = public
            private = (self.work/(mode+'.key')).read_text().strip()
            conf = (f'[Interface]\nPrivateKey = {private}\nAddress = {inner}/32\nDNS = {PRIVATE}\nMTU = 1280\n'
                    f'[Peer]\nPublicKey = {self.server_key}\nEndpoint = {OUTER}:{PORTS[mode]}\n'
                    'AllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 15\n')
            self.assets[mode] = {'wg.conf': conf.encode()}
        if self.source == 'wg-pq':
            self.build_pq()
        for mode in (self.source, self.candidate):
            if mode in ('naive-h2', 'naive-h3', 'hysteria2'):
                self.build_proxy(mode)

    def build_pq(self):
        rp = os.environ['ROUTERVPN_QUALIFICATION_ROSENPASS']
        for role in ('client', 'server'):
            output([rp, 'gen-keys', '--public-key='+str(self.work/(role+'.rp-public')),
                    '--secret-key='+str(self.work/(role+'.rp-secret'))])
        files = self.assets['wg-pq']
        files['rosenpass-client-public'] = (self.work/'client.rp-public').read_bytes()
        files['rosenpass-client-secret'] = (self.work/'client.rp-secret').read_bytes()
        files['rosenpass-server-public'] = (self.work/'server.rp-public').read_bytes()
        port = PORTS['rosenpass']
        files['rosenpass.env'] = (f'ROSENPASS_TOOL=wg\nROSENPASS_INTERFACE=wg\nROSENPASS_WG_PEER={self.server_key}\n'
                                  f'ROSENPASS_KEY_OUT=rosenpass.psk\nROSENPASS_PORT={port}\n').encode()
        files['rosenpass.toml'] = (f'public_key = "rosenpass-client-public"\nsecret_key = "rosenpass-client-secret"\n'
                                   f'listen = []\nverbosity = "Quiet"\n[[peers]]\npublic_key = "rosenpass-server-public"\n'
                                   f'endpoint = "{OUTER}:{port}"\nkey_out = "rosenpass.psk"\n').encode()
        host = OUTER if self.layer == 'off' else PRIVATE
        self.put('server.toml', f'public_key = "server.rp-public"\nsecret_key = "server.rp-secret"\nlisten = ["{host}:{port}"]\n'
                                'verbosity = "Quiet"\n[[peers]]\npublic_key = "client.rp-public"\nkey_out = "negotiated.psk"\n')

    def build_proxy(self, mode):
        cert, key = self.work/'cert.pem', self.work/'tls.key'
        if not cert.exists():
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                '-nodes', '-sha256', '-days', '1', '-subj', '/CN=router-qualification.test',
                '-addext', 'subjectAltName=DNS:router-qualification.test', '-addext', 'basicConstraints=critical,CA:TRUE',
                '-addext', 'extendedKeyUsage=serverAuth', '-keyout', key, '-out', cert], check=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        host = 'router-qualification.test'
        hy = mode == 'hysteria2'
        kind = 'hysteria2' if hy else 'naive'
        listener = OUTER if self.layer == 'off' else '127.0.0.1'
        inbound = {'type': kind, 'tag': mode, 'listen': listener, 'listen_port': PORTS[mode],
                   'users': [{'name': 'qualification', 'password': self.password}] if hy else
                            [{'username': 'qualification', 'password': self.password}],
                   'tls': {'enabled': True, 'certificate_path': str(cert), 'key_path': str(key)}}
        outbound = {'type': kind, 'tag': 'proxy', 'server': OUTER, 'server_port': PORTS[mode],
                    'password': self.password, 'tls': {'enabled': True, 'server_name': host, 'certificate_path': 'cert.pem'}}
        if hy:
            outbound['obfs'] = inbound['obfs'] = {'type': 'salamander', 'password': self.password}
        else:
            inbound['network'] = 'udp' if mode == 'naive-h3' else 'tcp'
            outbound.update(username='qualification', quic=mode == 'naive-h3', udp_over_tcp={'enabled': True, 'version': 2})
        self.put(mode+'.json', json.dumps({'log': {'level': 'info'}, 'inbounds': [inbound],
                                           'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'route': {'final': 'direct'}}))
        graph = {'dns': {'servers': [{'type': 'udp', 'tag': 'home-dns', 'server': PRIVATE, 'server_port': 53, 'detour': 'proxy'}],
                         'final': 'home-dns'},
                 'inbounds': [{'type': 'tun', 'tag': 'tun-in', 'interface_name': 'router-vpn', 'address': ['172.19.0.1/30','fdfe:dcba:9876::1/126'],
                               'auto_route': True, 'strict_route': True, 'mtu': 1280}],
                 'outbounds': [outbound, {'type': 'direct', 'tag': 'direct'}],
                 'route': {'auto_detect_interface': True, 'final': 'proxy', 'rules': [{'protocol': 'dns', 'action': 'hijack-dns'}]}}
        self.assets[mode] = {'sing-box.json': json.dumps(graph).encode(), 'cert.pem': cert.read_bytes()}

    def start_layer(self):
        method = '2022-blake3-aes-256-gcm'
        password = base64.b64encode(secrets.token_bytes(32)).decode()
        xor = self.layer == 'aes-256-gcm+xor-whitening'
        # In XOR mode only the whitening listener is physically reachable.
        ss_host = '127.0.0.1' if xor else OUTER
        server = {'type': 'shadowsocks', 'tag': 'aes', 'listen': ss_host, 'listen_port': PORTS['aes-256-gcm'],
                  'method': method, 'password': password}
        # The full SMART catalog can try standalone Shadowsocks before H3.
        # This peer authenticates only the encrypted inner protocol services.
        services = [self.source, self.candidate]
        if self.source == 'wg-pq':
            services.append('rosenpass')
        rules = []
        for mode in services:
            host = PRIVATE if mode in ('wg', 'wg-pq', 'rosenpass') else '127.0.0.1'
            network = 'tcp' if mode == 'naive-h2' else 'udp'
            rules.append({'inbound': 'aes', 'ip_cidr': host+'/32', 'network': network, 'port': PORTS[mode],
                          'action': 'route', 'outbound': 'direct'})
        rules.append({'inbound': 'aes', 'action': 'reject'})
        config = self.put('aes-server.json', json.dumps({'inbounds': [server], 'outbounds': [{'type': 'direct', 'tag': 'direct'}],
                                                         'route': {'rules': rules}}))
        client = {'type': 'shadowsocks', 'tag': 'proxy', 'server': OUTER, 'server_port': PORTS['aes-256-gcm'],
                  'method': method, 'password': password}
        graph = {'inbounds': [{'type': 'tun', 'tag': 'tun-in', 'auto_route': True, 'strict_route': True}],
                 'outbounds': [client], 'route': {'final': 'proxy', 'rules': []}}
        self.assets['shadowsocks'] = {'sing-box.json': json.dumps(graph).encode()}
        self.spawn('aes', [ENGINE, 'run', '-c', config])
        self.wait_listening('aes', PORTS['aes-256-gcm'], False)
        if xor:
            self.spawn('xor', [INSTALL/'router-vpn-start-layer-relay', '--mode', 'server', '--listen',
                               f'{OUTER}:{PORTS[self.layer]}', '--target', f'{ss_host}:{PORTS["aes-256-gcm"]}', '--key-config', config])
            self.wait_listening('xor', PORTS[self.layer], False)
        self.capture('decrypted', ['-i', 'lo', 'udp or tcp'])

    def start_mode(self, mode):
        if mode not in ('wg', 'wg-pq'):
            self.spawn(mode, [ENGINE, 'run', '-c', self.work/(mode+'.json')])
            self.wait_listening(mode, PORTS[mode], mode == 'naive-h2')
            return
        interface = 'wgplain' if mode == 'wg' else 'wgpq'
        inner = '10.77.0.3/32' if mode == 'wg' else '10.77.0.2/32'
        output(self.ns+['ip', 'link', 'add', interface, 'type', 'wireguard'])
        self.stack.callback(output, self.ns+['ip', 'link', 'del', interface])
        setup = self.ns+['wg', 'set', interface, 'listen-port', str(PORTS[mode]), 'private-key', self.work/'server.key',
                         'peer', self.client_keys[mode], 'allowed-ips', inner]
        if mode == 'wg-pq':
            setup += ['preshared-key', self.put('initial.psk', output(['wg', 'genpsk']))]
        output(setup)
        output(self.ns+['ip', 'link', 'set', interface, 'up'])
        output(self.ns+['ip', 'route', 'add', inner, 'dev', interface])
        if mode == 'wg-pq':
            self.spawn('rosenpass', [os.environ['ROUTERVPN_QUALIFICATION_ROSENPASS'], 'exchange-config', self.work/'server.toml'])
            self.wait_listening('rosenpass', PORTS['rosenpass'], False)
            self.spawn('key-watch', ['bash', ROOT/'modes/rosenpass-key-watch.sh', 'wg', interface, self.client_keys[mode],
                                     self.work/'negotiated.psk'])

    def enable_candidate(self):
        if not self.enabled:
            self.start_mode(self.candidate)
            self.enabled = True

    def observation(self, *, diagnostic=False):
        # The failure-only readback shares these exact existing peer counters.
        # It cannot extend a probe, restart a peer or replace the original error.
        deadline = time.monotonic()+3 if diagnostic else None
        log_samples = {}
        def observed_output(args):
            if deadline is None:
                return output(args)
            remaining = deadline-time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Diagnostic peer readback deadline')
            value = subprocess.run(args, check=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, timeout=remaining).stdout
            if len(value) > 4096:
                raise ValueError('Diagnostic peer readback exceeded its bound')
            return value
        for name, process in self.processes.items():
            if process.poll() is not None:
                raise RuntimeError(f'{name} peer stopped before the qualification ended')
        def records(name):
            path = self.work/(name+'.log')
            if not diagnostic:
                return path.read_bytes() if path.exists() else b''
            try:
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            except FileNotFoundError:
                log_samples[name] = {'present': False}
                return b''
            with os.fdopen(descriptor, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError('Diagnostic peer log changed its file type')
                value = stream.read(256 << 10)
            log_samples[name] = {'file_bytes': info.st_size, 'sample_bytes': len(value),
                                 'truncated': info.st_size > len(value)}
            return value
        body = json.dumps({'node_id': self.profile['node_proof_id'], 'ok': True, 'proof': 'router-vpn-private-agent-v1'},
                          separators=(',', ':')).encode()
        http_records = records('http')
        # These are captured packet observations, not handler receipts or
        # distinct TCP exchanges. Retransmissions are deliberately counted.
        packet_fields = ('packets', 'syn', 'syn_ack', 'ack', 'rst', 'fin', 'data_packets', 'payload_bytes')
        http_packets = {direction: dict.fromkeys(packet_fields, 0) for direction in ('to_private', 'from_private')}
        for line in http_records.splitlines():
            match = re.search(rb'\bIP ([0-9.]+)\.([0-9]+) > ([0-9.]+)\.([0-9]+): Flags \[([^\]]*)\].*length ([0-9]+)(?:$|:)', line)
            if match is None:
                continue
            source, source_port, target, target_port, flags, length = match.groups()
            if source == PRIVATE.encode() and source_port == b'8787':
                direction = 'from_private'
            elif target == PRIVATE.encode() and target_port == b'8787':
                direction = 'to_private'
            else:
                continue
            counts = http_packets[direction]
            counts['packets'] += 1
            counts['syn'] += int(b'S' in flags and b'.' not in flags)
            counts['syn_ack'] += int(b'S' in flags and b'.' in flags)
            counts['ack'] += int(b'.' in flags)
            counts['rst'] += int(b'R' in flags)
            counts['fin'] += int(b'F' in flags)
            counts['data_packets'] += int(int(length) > 0)
            counts['payload_bytes'] += int(length)
        result = {'http': http_records.count(body),
                  'http_get_health_headers': http_records.count(b'GET /health HTTP/1.1'),
                  'http_packets': http_packets,
                  'http_headers': http_header_summary(http_records),
                  'dns': records('dns').count(b' query['), 'pq_key_applied': False,
                  'source_uot': records(self.source).count(b'inbound UoT'),
                  'candidate_uot': records(self.candidate).count(b'inbound UoT'),
                  'candidate_hy2': records('hysteria2').count(f'[qualification] inbound connection to {PRIVATE}:8787'.encode()),
                  'candidate_hy2_dns': records('hysteria2').count(f'[qualification] inbound packet connection to {PRIVATE}:53'.encode()),
                  'wg_handshake': 0, 'candidate_handshake': 0, 'source_wg_received': 0, 'candidate_wg_received': 0,
                  'source_wg_sent': 0, 'candidate_wg_sent': 0}
        for mode, field, device in [('wg-pq', 'wg_handshake', 'wgpq'), ('wg', 'candidate_handshake', 'wgplain')]:
            if mode == self.source or mode == self.candidate and self.enabled:
                result[field] = int(observed_output(self.ns+['wg', 'show', device, 'latest-handshakes']).split()[1])
                role = 'source' if mode == self.source else 'candidate'
                transfer = observed_output(self.ns+['wg', 'show', device, 'transfer']).split()
                result[role+'_wg_received'], result[role+'_wg_sent'] = int(transfer[1]), int(transfer[2])
        for prefix, mode in [('source', self.source), ('candidate', self.candidate), ('pq', 'rosenpass')]:
            result[prefix+'_layer_packets'] = records('decrypted').count(f'.{PORTS[mode]}:'.encode())
        key = self.work/'negotiated.psk'
        if self.source == 'wg-pq' and key.exists():
            installed = observed_output(self.ns+['wg', 'show', 'wgpq', 'preshared-keys']).split()[1]
            result['pq_key_applied'] = installed == key.read_bytes().strip() and installed != (self.work/'initial.psk').read_bytes().strip()
            if result['pq_key_applied']:
                digest = hashlib.sha256(installed).digest()
                if self.last_pq_key_digest != digest:
                    self.last_pq_key_digest = digest
                    self.pq_generation += 1
        result['pq_generation'] = self.pq_generation
        if diagnostic:
            result['log_samples'] = log_samples
        return result


@contextmanager
def open_peers(namespace, workdir, source, candidate, layer='off'):
    if source not in ('wg-pq', 'naive-h3') or candidate not in ('wg', 'hysteria2', 'naive-h2'):
        raise ValueError('Unsupported SMART qualification pair')
    if layer not in ('off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening'):
        raise ValueError('Unsupported SMART qualification Start Layer')
    with ExitStack() as stack:
        peers = Peers(namespace, workdir, source, candidate, stack, layer)
        peers.start()
        yield peers


# The installed complete-path gate is separate from the SMART candidate matrix.
# These owners never grant native readiness; they provide real private peers.
class OrderedChild:
    def __init__(self, stack, args, *, log, cwd, env=None):
        self.process = self.pidfd = None
        self.closed = False
        self.waited = False
        self.receipt = {}
        self.failure = None
        stack.callback(self.close)
        # Retain Popen before pidfd, /proc or other fallible admission work.
        self.process = subprocess.Popen(list(args), stdout=log, stderr=log,
                                        cwd=cwd, env=env, start_new_session=True)
        self.pidfd = os.pidfd_open(self.process.pid)
        self.original = os.stat('/proc/%d' % self.process.pid)

    @staticmethod
    def group_members(group):
        members = []
        for entry in Path('/proc').iterdir():
            if not entry.name.isdigit():
                continue
            try:
                fields = (entry/'stat').read_text().rsplit(')', 1)[1].split()
                if int(fields[2]) == group:
                    members.append(int(entry.name))
            except FileNotFoundError:
                continue
        return sorted(members)

    def wait(self, timeout):
        result = self.process.wait(timeout=timeout)
        self.waited = True
        return result

    def close(self):
        if self.closed:
            if self.failure is not None:
                raise self.failure
            return
        self.closed = True
        if self.process is None:
            return
        errors, forced, joined = [], False, False
        process = self.process
        was_running = process.poll() is None
        if not was_running and not self.waited:
            errors.append('unexpected-peer-exit')
        if was_running:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except BaseException as error:
                errors.append('TERM:' + type(error).__name__)
        def wait_original(seconds):
            until = time.monotonic()+seconds
            while True:
                try:
                    process.wait(timeout=max(0,until-time.monotonic()))
                    return True
                except subprocess.TimeoutExpired:
                    return False
                except BaseException as error:
                    errors.append('wait:' + type(error).__name__)
                    if time.monotonic() >= until:
                        return False
        joined = wait_original(4)
        if not joined:
            forced = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except BaseException as error:
                errors.append('KILL:' + type(error).__name__)
            joined = wait_original(4)
        terminal, members = False, None
        try:
            terminal = self.pidfd is not None and bool(select.select([self.pidfd], [], [], 0)[0])
        except BaseException as error:
            errors.append('pidfd:' + type(error).__name__)
        try:
            members = self.group_members(process.pid)
        except BaseException as error:
            errors.append('group:' + type(error).__name__)
        self.receipt = {'pid': process.pid, 'returncode': process.returncode,
                        'joined': joined, 'pidfd_terminal': terminal,
                        'process_group_members': members, 'forced': forced,
                        'cleanup_errors': errors}
        if self.pidfd is not None:
            try:
                os.close(self.pidfd)
            except BaseException as error:
                errors.append('pidfd-close:' + type(error).__name__)
            self.pidfd = None
        if not joined or not terminal or members != [] or forced or errors:
            self.failure = RuntimeError('Original ordered peer/process retirement was not proved')
            raise self.failure


class OrderedPeer(Peers):
    def __init__(self, namespace, work, mode, identity, physical, private, port, link, stack):
        work.mkdir(mode=0o700)
        super().__init__(namespace, work, mode, mode, stack)
        self.mode, self.physical, self.private, self.port = mode, physical, private, port
        self.link, self.children = link, {}
        self.profile.update(id=identity, name='Ordered ' + identity, endpoint=physical,
                            router_api='http://' + private + ':8787',
                            path_probe_url='http://' + private + ':8787/health',
                            adguard_ipv4=private, start_layer='off', home_lan_access=False,
                            kill_switch_policy='on-connect', mtu_policy='manual', manual_mtu=1280)
        self.inner = '10.77.1.3'
        client = self.wg_key('ordered-client')
        self.client_keys['wg'] = client
        companion_port = port if mode == 'wg' else (51821 if mode == 'hysteria2' else 51822)
        config = ('[Interface]\nPrivateKey = ' + (self.work/'ordered-client.key').read_text().strip() +
                  '\nAddress = ' + self.inner + '/32\nDNS = ' + private + '\nMTU = 2000\n' +
                  '[Peer]\nPublicKey = ' + self.server_key + '\nEndpoint = ' + physical + ':' +
                  str(companion_port) + '\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 15\n')
        self.assets = {'wg': {'wg.conf': config.encode()}}

    def spawn(self, name, args, env=None):
        log = self.stack.enter_context((self.work/(name+'.log')).open('xb'))
        child = OrderedChild(self.stack, self.ns+list(args), log=log, cwd=self.work, env=env)
        self.children[name] = child
        self.processes[name] = child.process
        return child.process

    def services(self):
        output(self.ns+['ip', 'addr', 'add', self.private+'/32', 'dev', 'lo'])
        self.stack.callback(output, self.ns+['ip', 'addr', 'del', self.private+'/32', 'dev', 'lo'])
        table = 'ordered_agent_'+secrets.token_hex(6)
        config = self.put('agent.json', json.dumps({'listen': self.private+':8787',
            'node_id': self.profile['node_proof_id'], 'token': self.profile['api_token'],
            'wan_interface': self.link, 'nft_table': table,
            'tunnel_cidrs': [self.private+'/32', self.inner+'/32'],
            'daita_listen': self.private+':45999'}))
        self.stack.callback(subprocess.run, self.ns+['nft','delete','table','inet',table],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.spawn('router', [os.environ['ROUTERVPN_QUALIFICATION_ROUTER_AGENT']],
            dict(os.environ, ROUTER_VPN_CONFIG=str(config),
                 ROUTER_VPN_MULTIHOP_CONFIG=str(self.work/'no-relays')))
        self.wait_listening('router', 8787, True)
        self.spawn('dns', ['dnsmasq','--no-daemon','--conf-file=/dev/null','--no-resolv','--no-hosts',
            '--cache-size=0','--bind-interfaces','--listen-address='+self.private,
            '--local=/#/','--address=/#/93.184.216.34'])
        self.wait_listening('dns', 53, False)

    def proxy(self, targets):
        if self.mode == 'hysteria2':
            cert, key = self.work/'cert.pem', self.work/'tls.key'
            subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256',
                '-nodes','-sha256','-days','1','-subj','/CN=router-qualification.test',
                '-addext','subjectAltName=DNS:router-qualification.test',
                '-addext','basicConstraints=critical,CA:TRUE','-addext','extendedKeyUsage=serverAuth',
                '-keyout',key,'-out',cert], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            password, obfs = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            inbound = {'type':'hysteria2','tag':'ordered-peer','listen':self.physical,'listen_port':self.port,
                'users':[{'name':'ordered','password':password}],
                'obfs':{'type':'salamander','password':obfs},
                'tls':{'enabled':True,'certificate_path':str(cert),'key_path':str(key)}}
            outbound = {'type':'hysteria2','tag':'proxy','server':self.physical,'server_port':self.port,
                'password':password,'obfs':{'type':'salamander','password':obfs},
                'tls':{'enabled':True,'server_name':'router-qualification.test','certificate_path':'cert.pem'}}
            assets = {'cert.pem':cert.read_bytes()}
        elif self.mode == 'shadowsocks':
            password = base64.b64encode(secrets.token_bytes(32)).decode()
            inbound = {'type':'shadowsocks','tag':'ordered-peer','listen':self.physical,'listen_port':self.port,
                       'method':'2022-blake3-aes-256-gcm','password':password}
            outbound = {'type':'shadowsocks','tag':'proxy','server':self.physical,'server_port':self.port,
                        'method':'2022-blake3-aes-256-gcm','password':password}
            assets = {}
        else:
            raise ValueError('Expected original ordered stream peer')
        rules = [{'inbound':'ordered-peer','ip_cidr':host+'/32','network':network,'port':port,
                  'action':'route','outbound':'direct'} for host,port,network in targets]
        rules.append({'inbound':'ordered-peer','action':'reject'})
        config = self.put('server.json',json.dumps({'log':{'level':'warn'},'inbounds':[inbound],
            'outbounds':[{'type':'direct','tag':'direct'}],'route':{'rules':rules}}))
        graph = {'dns':{'servers':[{'type':'udp','tag':'home-dns','server':self.private,
                                  'server_port':53,'detour':'proxy'}],'final':'home-dns'},
            'inbounds':[{'type':'tun','tag':'tun-in','interface_name':'router-vpn',
                         'address':['172.19.0.1/30','fdfe:dcba:9876::1/126'],
                         'auto_route':True,'strict_route':True,'mtu':2000}],
            'outbounds':[outbound,{'type':'direct','tag':'direct'}],
            'route':{'auto_detect_interface':True,'final':'proxy','rules':[{'protocol':'dns','action':'hijack-dns'}]}}
        assets['sing-box.json'] = json.dumps(graph).encode()
        self.assets[self.mode] = assets
        self.spawn(self.mode,[ENGINE,'run','-c',config])
        self.wait_listening(self.mode,self.port,self.mode=='shadowsocks')
        self.wait_listening(self.mode,self.port,False)

    def wireguard(self):
        output(self.ns+['ip','link','add','wgordered','type','wireguard'])
        self.stack.callback(output,self.ns+['ip','link','del','wgordered'])
        output(self.ns+['wg','set','wgordered','listen-port',str(self.port),'private-key',self.work/'server.key',
                        'peer',self.client_keys['wg'],'allowed-ips',self.inner+'/32'])
        output(self.ns+['ip','link','set','wgordered','mtu','9000','up'])
        output(self.ns+['ip','route','add',self.inner+'/32','dev','wgordered'])


class OrderedPeers:
    def __init__(self, topology, work, stack):
        self.topology, self.stack = topology, stack
        self.entry = OrderedPeer(topology['peer'],work/'entry','wg','ordered-entry',
                                 OUTER,'10.77.1.1',51820,'smartpeer',stack)
        self.middle = OrderedPeer(topology['peer'],work/'middle','hysteria2','ordered-middle',
                                  OUTER,'10.77.2.1',18445,'ordered-final',stack)
        self.final = OrderedPeer(topology['final'],work/'final','shadowsocks','ordered-final',
                                 topology['final_private'],'10.77.3.1',8388,'ordered-peer',stack)
        self.members = [self.entry,self.middle,self.final]
        self.tables, self.original_rules = [], {}

    def start(self):
        if os.path.samefile('/proc/self/ns/net','/run/netns/'+self.topology['peer']) or \
                os.path.samefile('/run/netns/'+self.topology['peer'],'/run/netns/'+self.topology['final']):
            raise ValueError('The complete peers require their original independent namespaces')
        for member in self.members:
            member.services()
        self.final.proxy([(self.final.private,8787,'tcp'),(self.final.private,53,'udp'),
                          (self.final.private,53,'tcp'),('1.1.1.1',443,'tcp')])
        self.middle.proxy([(self.middle.private,8787,'tcp'),(self.middle.private,53,'udp'),
                           (self.middle.private,53,'tcp'),
                           (self.final.physical,self.final.port,'tcp'),(self.final.physical,self.final.port,'udp')])
        self.entry.wireguard()
        peer_rules = [
            'chain input { type filter hook input priority -25; policy accept;',
            'iifname "smartpeer" ip daddr { 10.77.1.1, 10.77.2.1 } counter drop',
            'iifname "smartpeer" ip daddr '+OUTER+' udp dport 18445 counter drop',
            'iifname "wgordered" ip saddr != 10.77.1.3 counter drop',
            'iifname "wgordered" ip daddr 10.77.1.1 tcp dport { 53, 8787 } accept',
            'iifname "wgordered" ip daddr 10.77.1.1 udp dport 53 accept',
            'iifname "wgordered" ip daddr '+OUTER+' udp dport 18445 counter accept comment "hy2-in"',
            'iifname "wgordered" counter drop',
            '}',
            'chain output { type filter hook output priority -25; policy accept;',
            'oifname "wgordered" ip saddr '+OUTER+' ip daddr 10.77.1.3 udp sport 18445 counter comment "hy2-out"',
            '}',
            'chain forward { type filter hook forward priority -25; policy drop; }']
        final_rules = [
            'chain input { type filter hook input priority -25; policy accept;',
            'iifname "ordered-peer" ip saddr '+self.topology['peer_private']+' ip daddr '+self.final.physical+
            ' tcp dport 8388 counter accept comment "ss-tcp-in"',
            'iifname "ordered-peer" ip saddr '+self.topology['peer_private']+' ip daddr '+self.final.physical+
            ' udp dport 8388 counter accept comment "ss-udp-in"',
            'iifname "ordered-peer" counter drop',
            '}',
            'chain output { type filter hook output priority -25; policy accept;',
            'oifname "ordered-peer" ip saddr '+self.final.physical+' ip daddr '+self.topology['peer_private']+
            ' tcp sport 8388 counter comment "ss-tcp-out"',
            'oifname "ordered-peer" ip saddr '+self.final.physical+' ip daddr '+self.topology['peer_private']+
            ' udp sport 8388 counter comment "ss-udp-out"',
            '}',
            'chain forward { type filter hook forward priority -25; policy drop; }']
        for ns, rules in ((self.topology['peer'],peer_rules),(self.topology['final'],final_rules)):
            table = 'ordered_peer_'+secrets.token_hex(6)
            prefix = ['ip','netns','exec',ns]
            output(prefix+['nft','create','table','inet',table])
            self.stack.callback(output,prefix+['nft','delete','table','inet',table])
            output(prefix+['nft','-f','-'],data=('table inet '+table+' {\n'+'\n'.join(rules)+'\n}\n').encode())
            self.tables.append((ns,table))
        self.observation()

    def observation(self):
        for member in self.members:
            for child in member.children.values():
                if child.process.poll() is not None:
                    raise RuntimeError('An original ordered peer stopped early')
        result = {}
        for ns,table in self.tables:
            rows = json.loads(output(['ip','netns','exec',ns,'nft','-j','-a','list','table','inet',table]))['nftables']
            for row in rows:
                rule = row.get('rule',{})
                name = rule.get('comment')
                if not name:
                    continue
                if name in result or rule.get('family')!='inet' or rule.get('table')!=table or not rule.get('handle'):
                    raise RuntimeError('An original ordered packet counter was replaced')
                counters = [expr['counter'] for expr in rule['expr'] if 'counter' in expr]
                if len(counters)!=1:
                    raise RuntimeError('Expected one original inline packet counter')
                sealed = dict(rule,expr=[{'counter':{}} if 'counter' in expr else expr for expr in rule['expr']])
                old = self.original_rules.setdefault(name,sealed)
                if old != sealed:
                    raise RuntimeError('Original packet predicates or handles changed')
                result[name] = counters[0]
        if set(result) != {'hy2-in','hy2-out','ss-tcp-in','ss-tcp-out','ss-udp-in','ss-udp-out'}:
            raise RuntimeError('The original encrypted tuple counter set is incomplete')
        fields = output(self.entry.ns+['wg','show','wgordered','transfer']).decode().split()
        if len(fields)!=3 or fields[0]!=self.entry.client_keys['wg']:
            raise RuntimeError('The original WireGuard peer identity changed')
        result['wg'] = {'received':int(fields[1]),'sent':int(fields[2])}
        return result

    def close(self):
        failure = None
        for member in reversed(self.members):
            for child in reversed(list(member.children.values())):
                try:
                    child.close()
                except BaseException as error:
                    if failure is None:
                        failure = error
                    else:
                        failure.add_note('Another original ordered peer did not retire')
        if failure is not None:
            raise failure
        return {member.profile['id']:{name:child.receipt for name,child in member.children.items()}
                for member in self.members}


@contextmanager
def open_ordered_peers(topology, work):
    with ExitStack() as stack:
        peers = OrderedPeers(topology,work,stack)
        peers.start()
        yield peers
