#!/usr/bin/env python3
"""Compose complete UDP ciphertext buffers with the verified packet owner.

The shared sing copy contains both UDP capacity and reply-endpoint concurrency
fixes. Never install a second replacement that can discard either policy.
"""
from pathlib import Path
import argparse
import importlib.util
import subprocess

_socket_spec = importlib.util.spec_from_file_location('mobile_udp_sockets', Path(__file__).with_name('mobile_udp_socket_policy.py'))
SOCKETS = importlib.util.module_from_spec(_socket_spec)
_socket_spec.loader.exec_module(SOCKETS)
_packet_spec = importlib.util.spec_from_file_location('mobile_udp_packet_owner', Path(__file__).with_name('prepare-sing-packet-concurrency.py'))
PACKET = importlib.util.module_from_spec(_packet_spec)
_packet_spec.loader.exec_module(PACKET)


def prepare(vendor):
    vendor = vendor.resolve()
    if not (vendor/'go.mod').read_text().startswith('module github.com/sagernet/sing-box\n'):
        raise ValueError('native UDP policy requires the pinned disposable Libbox checkout')
    PACKET.prepare(vendor)
    SOCKETS.prepare(vendor)
    subprocess.run(['go', 'mod', 'tidy'], cwd=vendor, check=True)
    PACKET.verify(vendor)
    print('Verified native UDP buffer policy: complete 65535-byte ciphertext; TCP capacities unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor', type=Path)
    prepare(parser.parse_args().vendor)
