"""Independent protocol peers for installed Linux SMART qualification inside a disposable peer namespace."""

from contextlib import contextmanager, ExitStack
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import time


ROOT = Path(__file__).resolve().parents[1]
INSTALL = Path('/opt/router-vpn-client')
ENGINE = INSTALL/'runtime/native/sing-box-routervpn'
OUTER = '198.18.0.2'
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
             '--local=/#/', '--address=/#/'+OUTER])
        self.wait_listening('dns', 53, False)
        self.capture('http', ['-A', '-s', '2048', '-i', 'any', f'src host {PRIVATE} and tcp src port 8787'])

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

    def observation(self):
        for name, process in self.processes.items():
            if process.poll() is not None:
                raise RuntimeError(f'{name} peer stopped before the qualification ended')
        def records(name):
            path = self.work/(name+'.log')
            return path.read_bytes() if path.exists() else b''
        body = json.dumps({'node_id': self.profile['node_proof_id'], 'ok': True, 'proof': 'router-vpn-private-agent-v1'},
                          separators=(',', ':')).encode()
        result = {'http': records('http').count(body),
                  'dns': records('dns').count(b' query['), 'pq_key_applied': False,
                  'source_uot': records(self.source).count(b'inbound UoT'),
                  'candidate_uot': records(self.candidate).count(b'inbound UoT'),
                  'candidate_hy2': records('hysteria2').count(f'[qualification] inbound connection to {PRIVATE}:8787'.encode()),
                  'candidate_hy2_dns': records('hysteria2').count(f'[qualification] inbound packet connection to {PRIVATE}:53'.encode()),
                  'wg_handshake': 0, 'candidate_handshake': 0, 'source_wg_received': 0, 'candidate_wg_received': 0}
        for mode, field, device in [('wg-pq', 'wg_handshake', 'wgpq'), ('wg', 'candidate_handshake', 'wgplain')]:
            if mode == self.source or mode == self.candidate and self.enabled:
                result[field] = int(output(self.ns+['wg', 'show', device, 'latest-handshakes']).split()[1])
                role = 'source' if mode == self.source else 'candidate'
                result[role+'_wg_received'] = int(output(self.ns+['wg', 'show', device, 'transfer']).split()[1])
        for prefix, mode in [('source', self.source), ('candidate', self.candidate), ('pq', 'rosenpass')]:
            result[prefix+'_layer_packets'] = records('decrypted').count(f'.{PORTS[mode]}:'.encode())
        key = self.work/'negotiated.psk'
        if self.source == 'wg-pq' and key.exists():
            installed = output(self.ns+['wg', 'show', 'wgpq', 'preshared-keys']).split()[1]
            result['pq_key_applied'] = installed == key.read_bytes().strip() and installed != (self.work/'initial.psk').read_bytes().strip()
            if result['pq_key_applied']:
                digest = hashlib.sha256(installed).digest()
                if self.last_pq_key_digest != digest:
                    self.last_pq_key_digest = digest
                    self.pq_generation += 1
        result['pq_generation'] = self.pq_generation
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
