#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib
import re
import secrets
import sys


def load_json(path: pathlib.Path) -> dict:
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def main() -> int:
    if len(sys.argv) != 5:
        print("usage: generate-aux-proxies.py BASE ENDPOINT OVERTLS_PORT SSR_PORT", file=sys.stderr)
        return 2

    base = pathlib.Path(sys.argv[1])
    endpoint = sys.argv[2].strip().strip("[]")
    overtls_port = int(sys.argv[3])
    ssr_port = int(sys.argv[4])
    internal_port = int(__import__('os').environ.get('OVERTLS_INTERNAL_PORT', '14444'))
    tls_settings = base / 'config' / 'tls' / 'settings.env'
    if not tls_settings.is_file():
        print('TLS settings are required before OverTLS generation.', file=sys.stderr)
        return 1
    text = tls_settings.read_text()
    m = re.search(r"(?m)^TLS_NAME='([^']+)'$", text)
    if not m:
        print('TLS_NAME missing from TLS settings.', file=sys.stderr)
        return 1
    tls_name = m.group(1)

    aux = base / 'config' / 'aux'
    gen = base / 'client-bundle' / 'generated'
    aux.mkdir(parents=True, exist_ok=True)
    (gen / 'overtls').mkdir(parents=True, exist_ok=True)
    (gen / 'shadowsocksr').mkdir(parents=True, exist_ok=True)

    secrets_path = aux / 'secrets.json'
    saved = load_json(secrets_path)
    tunnel_path = str(saved.get('overtls_path') or ('/rvpn-' + secrets.token_hex(18) + '/'))
    if not tunnel_path.startswith('/'):
        tunnel_path = '/' + tunnel_path
    if not tunnel_path.endswith('/'):
        tunnel_path += '/'
    ssr_password = str(saved.get('ssr_password') or secrets.token_urlsafe(28))
    saved = {'overtls_path': tunnel_path, 'ssr_password': ssr_password}
    secrets_path.write_text(json.dumps(saved, indent=2) + '\n')
    secrets_path.chmod(0o600)

    overtls_server = {
        'tunnel_path': tunnel_path,
        'disable_tls': True,
        'server_settings': {
            'forward_addr': 'http://127.0.0.1:80',
            'listen_host': '127.0.0.1',
            'listen_port': internal_port,
        },
    }
    overtls_client = {
        'tunnel_path': tunnel_path,
        'server_settings': {},
        'client_settings': {
            'server_host': endpoint,
            'server_port': overtls_port,
            'server_domain': tls_name,
            'listen_host': '127.0.0.1',
            'listen_port': 1080,
        },
    }
    (aux / 'overtls-server.json').write_text(json.dumps(overtls_server, indent=2) + '\n')
    (gen / 'overtls' / 'overtls-client.json').write_text(json.dumps(overtls_client, indent=2) + '\n')

    ssr_common = {
        'password': ssr_password,
        'method': 'aes-256-gcm',
        'protocol': 'auth_aes128_md5',
        'protocol_param': '',
        'obfs': 'tls1.2_ticket_auth',
        'obfs_param': '',
        'udp': True,
        'idle_timeout': 300,
        'connect_timeout': 6,
        'udp_timeout': 6,
    }
    ssr_server = dict(ssr_common)
    ssr_server['server_settings'] = {'listen_address': '0.0.0.0', 'listen_port': ssr_port}
    ssr_server['client_settings'] = {
        'server': endpoint,
        'server_port': ssr_port,
        'listen_address': '127.0.0.1',
        'listen_port': 1080,
    }
    ssr_client = json.loads(json.dumps(ssr_server))
    (aux / 'ssr-server.json').write_text(json.dumps(ssr_server, indent=2) + '\n')
    (gen / 'shadowsocksr' / 'ssr-client.json').write_text(json.dumps(ssr_client, indent=2) + '\n')

    meta = {
        'overtls_port': overtls_port,
        'overtls_internal_port': internal_port,
        'overtls_path': tunnel_path,
        'overtls_tls_name': tls_name,
        'ssr_port': ssr_port,
        'ssr_method': ssr_common['method'],
        'ssr_protocol': ssr_common['protocol'],
        'ssr_obfs': ssr_common['obfs'],
    }
    (aux / 'generated.json').write_text(json.dumps(meta, indent=2) + '\n')

    with tls_settings.open('a') as fh:
        fh.write(f"OVERTLS_PORT={shell_quote(str(overtls_port))}\n")
        fh.write(f"OVERTLS_INTERNAL_PORT={shell_quote(str(internal_port))}\n")
        fh.write(f"OVERTLS_PATH={shell_quote(tunnel_path)}\n")

    for p in [aux / 'overtls-server.json', aux / 'ssr-server.json', aux / 'generated.json', gen / 'overtls' / 'overtls-client.json', gen / 'shadowsocksr' / 'ssr-client.json']:
        p.chmod(0o600)
    print(f'Generated OverTLS TCP {overtls_port} -> loopback {internal_port} and legacy SSR TCP/UDP {ssr_port}.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
