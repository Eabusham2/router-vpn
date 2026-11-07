#!/usr/bin/env python3
"""Execute target setup and verified compiler installation at their OS boundaries."""
from pathlib import Path
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shlex
import shutil
import stat
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('desktop_native_setup_test', ROOT/'deploy/setup-desktop-native-toolchain.py')
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)
W = G.WINDOWS
spec = importlib.util.spec_from_file_location('desktop_native_build_test', ROOT/'deploy/build-native-runtime.py')
N = importlib.util.module_from_spec(spec)
spec.loader.exec_module(N)
PHYSICAL = N.load('desktop_native_windows_physical_test', 'test_windows_node_physical.py')
PT = N.load('desktop_native_pt_inventory_test', 'test_desktop_pt_inventory.py')


def file(path, data=b'tool', executable=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if executable:
        path.chmod(0o755)
    return path


class NativeSocketUIDGate(unittest.TestCase):
    def test_matching_hosts_require_actual_unix_uid_or_windows_identity_gate(self):
        self.check_matching_hosts()

    def test_failed_or_timed_out_desktop_pt_inventory_cannot_reach_later_gates_or_compilation(self):
        for failure in (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            with self.subTest(failure=failure.__name__):
                self.check_matching_hosts(desktop_pt_failure=failure)

    def test_failed_or_timed_out_node_gate_cannot_reach_later_gates_or_compilation(self):
        for failure in (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            with self.subTest(failure=failure.__name__):
                self.check_matching_hosts(node_failure=failure)

    def test_failed_or_timed_out_socks_reality_reference_cannot_reach_later_gates_or_compilation(self):
        for failure in (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            with self.subTest(failure=failure.__name__):
                self.check_matching_hosts(socks_reference_failure=failure)

    def test_failed_or_timed_out_proxy_reality_reference_cannot_reach_later_gates_or_compilation(self):
        for failure in (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            with self.subTest(failure=failure.__name__):
                self.check_matching_hosts(proxy_reference_failure=failure)

    def test_failed_or_timed_out_connect_reality_reference_cannot_reach_later_gates_or_compilation(self):
        for failure in (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            with self.subTest(failure=failure.__name__):
                self.check_matching_hosts(connect_reference_failure=failure)

    def test_failed_or_timed_out_selected_dns_reference_cannot_reach_later_gates_or_compilation(self):
        for failure in (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            with self.subTest(failure=failure.__name__):
                self.check_matching_hosts(dns_reference_failure=failure)

    def test_failed_or_timed_out_forwarder_gate_cannot_reach_transport_tests_or_compilation(self):
        for failure in (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            with self.subTest(failure=failure.__name__):
                self.check_matching_hosts(forwarder_failure=failure)

    def test_failed_or_timed_out_openvpn_gate_cannot_reach_later_gates_or_compilation(self):
        for failure in (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            with self.subTest(failure=failure.__name__):
                self.check_matching_hosts(openvpn_failure=failure)

    def test_failed_or_timed_out_darwin_route_gate_cannot_reach_guardian_or_compilation(self):
        for failure in (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            with self.subTest(failure=failure.__name__):
                self.check_matching_hosts(darwin_route_failure=failure)

    def test_failed_or_timed_out_command_retirement_cannot_reach_later_gates_or_compilation(self):
        for failure in (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            with self.subTest(failure=failure.__name__):
                self.check_matching_hosts(command_retirement_failure=failure)

    def test_failed_timed_out_or_missing_native_phase_receipt_cannot_reach_package(self):
        for failure in (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError):
            with self.subTest(failure=failure.__name__):
                self.check_matching_hosts(physical_failure=failure)

    def check_matching_hosts(self, node_failure=None, forwarder_failure=None, openvpn_failure=None, darwin_route_failure=None, physical_failure=None, command_retirement_failure=None, socks_reference_failure=None, proxy_reference_failure=None, connect_reference_failure=None, dns_reference_failure=None, desktop_pt_failure=None):
        class CompilerBoundary(Exception):
            pass

        targets = ('linux/amd64', 'linux/arm64', 'darwin/amd64', 'darwin/arm64', 'windows/amd64', 'windows/arm64')
        if physical_failure is not None:
            targets = tuple(target for target in targets if target.startswith('windows/'))
        if darwin_route_failure is not None:
            targets = tuple(target for target in targets if target.startswith('darwin/'))
        if command_retirement_failure is not None:
            targets = tuple(target for target in targets if target.startswith('linux/'))
        if any(failure is not None for failure in (socks_reference_failure, proxy_reference_failure, connect_reference_failure, dns_reference_failure)):
            targets = tuple(target for target in targets if target.startswith('linux/'))
        for target in targets:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                source = root/'core'
                (source/'cmd/sing-box').mkdir(parents=True)
                system, arch = target.split('/')
                env = {'GOOS': system, 'GOARCH': arch, 'CGO_ENABLED': '1', 'CGO_LDFLAGS': '', 'GOTOOLCHAIN': N.TOOLCHAIN}
                calls = []
                node_errors = []
                forwarder_errors = []
                openvpn_errors = []
                darwin_route_errors = []
                physical_errors = []
                command_retirement_errors = []
                socks_reference_errors = []
                proxy_reference_errors = []
                connect_reference_errors = []
                dns_reference_errors = []
                desktop_pt_errors = []
                references = {
                    str(ROOT/'deploy/test_mobile_imported_socks_xray.py'):
                        (['--reference-only'], socks_reference_failure, socks_reference_errors, 'SOCKS REALITY'),
                    str(ROOT/'deploy/test_mobile_imported_proxy_xray.py'):
                        (['--reference-only'], proxy_reference_failure, proxy_reference_errors, 'SS2022/Hysteria2 REALITY'),
                    str(ROOT/'deploy/test_mobile_imported_connect_xray.py'):
                        (['--reference-only'], connect_reference_failure, connect_reference_errors, 'CONNECT REALITY'),
                    str(ROOT/'deploy/test_native_xray_udp443.py'):
                        ([], dns_reference_failure, dns_reference_errors, 'selected DNS'),
                }
                dnssec_destination = None

                def run(command, **kwargs):
                    args = [str(value) for value in command]
                    calls.append(args)
                    if args == ['go', 'env', 'GOVERSION']:
                        return N.TOOLCHAIN
                    if args[:2] == ['go', 'build']:
                        raise CompilerBoundary()
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_pt_inventory.py'):
                        self.assertEqual(args[2:], [str(source.resolve()), '--tags='+','.join(N.tags(target)),
                                                   *(['--without-race'] if target == 'windows/arm64' else [])])
                        self.assertEqual(kwargs['cwd'], source.resolve())
                        self.assertIs(kwargs['env'], env)
                        self.assertEqual(kwargs['timeout'], 600)
                        if desktop_pt_failure is not None:
                            error = (desktop_pt_failure(43, args, output=b'original PT inventory failure')
                                     if desktop_pt_failure is subprocess.CalledProcessError else
                                     desktop_pt_failure(args, kwargs['timeout'], output=b'original PT inventory timeout'))
                            desktop_pt_errors.append(error)
                            raise error
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_socket_uid.py'):
                        self.assertIn(system, ('linux', 'darwin'))
                        self.assertEqual(args[2:], [str(source.resolve())])
                        self.assertEqual(kwargs['env']['GOOS'], system)
                        self.assertLessEqual(kwargs['timeout'], 300)
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_windows_identity_runner.py'):
                        self.assertEqual(system, 'windows')
                        self.assertEqual(len(args), 2)
                        self.assertEqual(kwargs['cwd'], ROOT)
                        self.assertEqual(kwargs['env']['GOOS'], system)
                        self.assertEqual(kwargs['env']['GOTOOLCHAIN'], N.TOOLCHAIN)
                        return ''
                    if len(args) > 1 and args[1] in (str(ROOT/'deploy/test_desktop_windows_identity.py'), str(ROOT/'deploy/test_desktop_windows_wfp.py'), str(ROOT/'deploy/test_desktop_windows_traffic.py'), str(ROOT/'deploy/test_windows_protection_transfer.py'), str(ROOT/'deploy/test_windows_protection_observation.py')):
                        self.assertEqual(system, 'windows')
                        self.assertEqual(args[2:], [str(source.resolve())])
                        self.assertEqual(kwargs['env']['GOOS'], system)
                        self.assertEqual(kwargs['env']['GOTOOLCHAIN'], N.TOOLCHAIN)
                        self.assertLessEqual(kwargs['timeout'], 600)
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_command_retirement.py'):
                        self.assertEqual(system, 'linux')
                        self.assertEqual(args[2:], ['--native-core', str(source.resolve()), '--tags='+','.join(N.tags(target))])
                        self.assertEqual(kwargs['cwd'], ROOT)
                        self.assertEqual(kwargs['env']['GOOS'], system)
                        self.assertEqual(kwargs['env']['GOARCH'], arch)
                        self.assertEqual(kwargs['env']['CGO_ENABLED'], '1')
                        self.assertEqual(kwargs['timeout'], 180)
                        if command_retirement_failure is not None:
                            error = (command_retirement_failure(39, args) if command_retirement_failure is subprocess.CalledProcessError
                                     else command_retirement_failure(args, kwargs['timeout']))
                            command_retirement_errors.append(error)
                            raise error
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_linux_guardian.py'):
                        self.assertEqual(system, 'linux')
                        self.assertEqual(args[2:], [str(source.resolve())])
                        self.assertEqual(kwargs['env']['GOOS'], system)
                        self.assertEqual(kwargs['env']['GOTOOLCHAIN'], N.TOOLCHAIN)
                        self.assertLessEqual(kwargs['timeout'], 300)
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_linux_node_child_control_runner.py'):
                        self.assertEqual(system, 'linux')
                        self.assertEqual(args[2:], [])
                        self.assertEqual(kwargs['cwd'], ROOT)
                        self.assertEqual(kwargs['env']['GOOS'], system)
                        self.assertEqual(kwargs['env']['GOARCH'], arch)
                        self.assertEqual(kwargs['env']['CGO_ENABLED'], '1')
                        self.assertEqual(kwargs['env']['GOTOOLCHAIN'], N.TOOLCHAIN)
                        self.assertLessEqual(kwargs['timeout'], 60)
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_linux_node_child_control.py'):
                        self.assertEqual(system, 'linux')
                        self.assertEqual(args[2:], [str(source.resolve())])
                        self.assertEqual(kwargs['env']['GOOS'], system)
                        self.assertEqual(kwargs['env']['GOARCH'], arch)
                        self.assertEqual(kwargs['env']['CGO_ENABLED'], '1')
                        self.assertEqual(kwargs['env']['GOTOOLCHAIN'], N.TOOLCHAIN)
                        self.assertLessEqual(kwargs['timeout'], 900)
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_linux_external_lifecycle_runner.py'):
                        self.assertEqual(system, 'linux')
                        self.assertEqual(args[2:], [])
                        self.assertEqual(kwargs['cwd'], ROOT)
                        self.assertEqual(kwargs['env']['GOOS'], system)
                        self.assertEqual(kwargs['env']['GOARCH'], arch)
                        self.assertEqual(kwargs['env']['CGO_ENABLED'], '1')
                        self.assertEqual(kwargs['env']['GOTOOLCHAIN'], N.TOOLCHAIN)
                        self.assertLessEqual(kwargs['timeout'], 60)
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_linux_external_lifecycle.py'):
                        self.assertEqual(system, 'linux')
                        self.assertEqual(args[2:], [str(source.resolve())])
                        self.assertEqual(kwargs['env']['GOOS'], system)
                        self.assertEqual(kwargs['env']['GOARCH'], arch)
                        self.assertEqual(kwargs['env']['CGO_ENABLED'], '1')
                        self.assertEqual(kwargs['env']['GOTOOLCHAIN'], N.TOOLCHAIN)
                        self.assertLessEqual(kwargs['timeout'], 900)
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_linux_node_child_tun_runner.py'):
                        self.assertEqual(system, 'linux')
                        self.assertEqual(args[2:], [])
                        self.assertEqual(kwargs['cwd'], ROOT)
                        self.assertEqual(kwargs['env']['GOOS'], system)
                        self.assertEqual(kwargs['env']['GOARCH'], arch)
                        self.assertEqual(kwargs['env']['CGO_ENABLED'], '1')
                        self.assertEqual(kwargs['env']['GOTOOLCHAIN'], N.TOOLCHAIN)
                        self.assertLessEqual(kwargs['timeout'], 60)
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_linux_node_child_tun.py'):
                        self.assertEqual(system, 'linux')
                        self.assertEqual(args[2:], [str(source.resolve())])
                        self.assertEqual(kwargs['env']['GOOS'], system)
                        self.assertEqual(kwargs['env']['GOARCH'], arch)
                        self.assertEqual(kwargs['env']['CGO_ENABLED'], '1')
                        self.assertEqual(kwargs['env']['GOTOOLCHAIN'], N.TOOLCHAIN)
                        self.assertLessEqual(kwargs['timeout'], 1500)
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_linux_external_openvpn_runner.py'):
                        self.assertEqual(system, 'linux')
                        self.assertEqual(args[2:], [])
                        self.assertEqual(kwargs['cwd'], ROOT)
                        self.assertEqual(kwargs['env']['GOOS'], system)
                        self.assertEqual(kwargs['env']['GOARCH'], arch)
                        self.assertEqual(kwargs['env']['CGO_ENABLED'], '1')
                        self.assertEqual(kwargs['env']['GOTOOLCHAIN'], N.TOOLCHAIN)
                        self.assertLessEqual(kwargs['timeout'], 60)
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_linux_external_openvpn.py'):
                        self.assertEqual(system, 'linux')
                        self.assertEqual(args[2:], [str(source.resolve()), '--pq', str(root/'pq')])
                        self.assertEqual(kwargs['env']['GOOS'], system)
                        self.assertEqual(kwargs['env']['GOARCH'], arch)
                        self.assertEqual(kwargs['env']['CGO_ENABLED'], '1')
                        self.assertEqual(kwargs['env']['GOTOOLCHAIN'], N.TOOLCHAIN)
                        self.assertIn('-L'+str(root/'pq'), kwargs['env']['CGO_LDFLAGS'])
                        self.assertLessEqual(kwargs['timeout'], 900)
                        if openvpn_failure:
                            error = (openvpn_failure(37, args) if openvpn_failure is subprocess.CalledProcessError
                                     else openvpn_failure(args, kwargs['timeout']))
                            openvpn_errors.append(error)
                            raise error
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_linux_node_lifecycle_runner.py'):
                        self.assertEqual(system, 'linux')
                        self.assertEqual(args[2:], [])
                        self.assertEqual(kwargs['cwd'], ROOT)
                        self.assertEqual(kwargs['env']['GOOS'], system)
                        self.assertEqual(kwargs['env']['GOTOOLCHAIN'], N.TOOLCHAIN)
                        self.assertLessEqual(kwargs['timeout'], 60)
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_linux_node_lifecycle.py'):
                        self.assertEqual(system, 'linux')
                        self.assertEqual(args[2:], [str(source.resolve())])
                        self.assertEqual(kwargs['env']['GOOS'], system)
                        self.assertEqual(kwargs['env']['GOTOOLCHAIN'], N.TOOLCHAIN)
                        self.assertLessEqual(kwargs['timeout'], 600)
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_node_physical.py'):
                        self.assertIn(system, ('linux', 'windows'))
                        self.assertEqual(args[2:], [str(source.resolve())])
                        self.assertEqual(kwargs['env']['GOOS'], system)
                        self.assertEqual(kwargs['env']['GOTOOLCHAIN'], N.TOOLCHAIN)
                        self.assertEqual(kwargs['timeout'], 1800)
                        if node_failure is not None:
                            error = (node_failure(23, args, output=b'captured source gate failure')
                                     if node_failure is subprocess.CalledProcessError else
                                     node_failure(args, kwargs['timeout'], output=b'captured source gate timeout'))
                            node_errors.append(error)
                            raise error
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_node_pq.py'):
                        self.assertIn(system, ('linux', 'windows'))
                        self.assertEqual(args[2:], [str(source.resolve()), str(root/'pq'), '--cache', str(ROOT/'dist/.native-pq-cache')])
                        self.assertEqual(kwargs['env']['GOOS'], system)
                        self.assertEqual(kwargs['env']['GOTOOLCHAIN'], N.TOOLCHAIN)
                        self.assertIn('-L'+str(root/'pq'), shlex.split(kwargs['env']['CGO_LDFLAGS']))
                        self.assertLessEqual(kwargs['timeout'], 1800)
                        return ''
                    if len(args) > 1 and args[1] in references:
                        options, failure, failures, label = references[args[1]]
                        self.assertEqual(system, 'linux')
                        self.assertEqual(args[2:], [str(source.resolve()), *options])
                        self.assertEqual(kwargs['env']['GOOS'], system)
                        self.assertEqual(kwargs['env']['GOARCH'], arch)
                        self.assertEqual(kwargs['env']['CGO_ENABLED'], '1')
                        self.assertEqual(kwargs['env']['GOTOOLCHAIN'], N.TOOLCHAIN)
                        self.assertEqual(kwargs['timeout'], 3000)
                        if failure is not None:
                            output = ('captured '+label+' reference failure').encode()
                            error = (failure(43, args, output=output)
                                     if failure is subprocess.CalledProcessError else
                                     failure(args, kwargs['timeout'], output=output))
                            failures.append(error)
                            raise error
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_node_max_runner.py'):
                        self.assertIn(system, ('linux', 'windows'))
                        self.assertEqual(args[2:], [])
                        self.assertEqual(kwargs['cwd'], ROOT)
                        self.assertEqual(kwargs['env']['GOTOOLCHAIN'], N.TOOLCHAIN)
                        self.assertLessEqual(kwargs['timeout'], 60)
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_node_max.py'):
                        self.assertIn(system, ('linux', 'windows'))
                        self.assertEqual(args[2:], [str(source.resolve()), str(root/'pq'), '--cache', str(ROOT/'dist/.native-pq-cache')])
                        self.assertEqual(kwargs['env']['GOOS'], system)
                        self.assertEqual(kwargs['env']['GOTOOLCHAIN'], N.TOOLCHAIN)
                        self.assertIn('-L'+str(root/'pq'), shlex.split(kwargs['env']['CGO_LDFLAGS']))
                        self.assertLessEqual(kwargs['timeout'], 5400)
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_windows_physical_bootstrap.py'):
                        self.assertEqual(system, 'windows')
                        self.assertEqual(args[2:], [str(source.resolve()), '--prospective'])
                        self.assertEqual(kwargs['env']['GOOS'], system)
                        self.assertEqual(kwargs['env']['GOTOOLCHAIN'], N.TOOLCHAIN)
                        self.assertLessEqual(kwargs['timeout'], 900)
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_windows_physical_tunnel.py'):
                        self.assertEqual(system, 'windows')
                        self.assertEqual(args[2:], [str(source.resolve())])
                        self.assertEqual(kwargs['env']['GOOS'], system)
                        self.assertEqual(kwargs['env']['GOTOOLCHAIN'], N.TOOLCHAIN)
                        self.assertLessEqual(kwargs['timeout'], 1200)
                        return ''
                    if len(args) > 1 and args[1] in (str(ROOT/'deploy/test_windows_node_physical_runner.py'), str(ROOT/'deploy/test_windows_external_provider_join.py')):
                        self.assertEqual(system, 'windows')
                        self.assertEqual(args[2:], [])
                        self.assertEqual(kwargs['cwd'], ROOT)
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_windows_node_physical.py'):
                        self.assertEqual(system, 'windows')
                        phase = args[4]
                        self.assertEqual(args[2:4], [str(source.resolve()), '--phase'])
                        self.assertEqual(args[5], '--receipt')
                        self.assertEqual(len(args), 7)
                        self.assertEqual(kwargs['env']['GOOS'], system)
                        self.assertEqual(kwargs['env']['GOTOOLCHAIN'], N.TOOLCHAIN)
                        self.assertEqual(kwargs['timeout'], PHYSICAL.PHASE_TIMEOUTS[phase])
                        if physical_failure and phase == 'external-packet':
                            if physical_failure is ValueError:
                                return ''  # zero exit without the mandatory owned receipt
                            error = (physical_failure(41, args) if physical_failure is subprocess.CalledProcessError
                                     else physical_failure(args, kwargs['timeout']))
                            physical_errors.append(error)
                            raise error
                        receipt = {'format': 'routervpn-windows-physical-phase-v1', 'phase': phase,
                                   'architecture': arch, 'source_sha256': PHYSICAL.source_digest({'modeled-source': 'a'*64}),
                                   'executables': {name: 'b'*64 for name in PHYSICAL._PHASE_IMAGES[phase]}}
                        Path(args[6]).write_text(json.dumps(receipt))
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_windows_node_pq_runner.py'):
                        self.assertEqual(system, 'windows')
                        self.assertEqual(args[2:], [])
                        self.assertEqual(kwargs['cwd'], ROOT)
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_windows_node_pq.py'):
                        self.assertEqual(system, 'windows')
                        self.assertEqual(args[2:], [str(source.resolve()), str(root/'pq'), '--cache', str(ROOT/'dist/.native-pq-cache')])
                        self.assertEqual(kwargs['env']['GOOS'], system)
                        self.assertEqual(kwargs['env']['CGO_ENABLED'], '1')
                        self.assertEqual(kwargs['env']['GOTOOLCHAIN'], N.TOOLCHAIN)
                        self.assertIn('-L'+str(root/'pq'), shlex.split(kwargs['env']['CGO_LDFLAGS']))
                        self.assertLessEqual(kwargs['timeout'], 2400)
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_darwin_route_runner.py'):
                        self.assertEqual(system, 'darwin')
                        self.assertEqual(args[2:], [])
                        self.assertEqual(kwargs['cwd'], ROOT)
                        self.assertEqual(kwargs['env']['GOOS'], system)
                        self.assertLessEqual(kwargs['timeout'], 60)
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_darwin_route.py'):
                        self.assertEqual(system, 'darwin')
                        self.assertEqual(args[2:], [str(source.resolve()), '--mutations'])
                        self.assertEqual(kwargs['env']['GOOS'], system)
                        self.assertEqual(kwargs['env']['GOTOOLCHAIN'], N.TOOLCHAIN)
                        self.assertLessEqual(kwargs['timeout'], 900)
                        if darwin_route_failure is not None:
                            error = (darwin_route_failure(31, args, output=b'captured native route conflict failure')
                                     if darwin_route_failure is subprocess.CalledProcessError else
                                     darwin_route_failure(args, kwargs['timeout'], output=b'captured native route timeout'))
                            darwin_route_errors.append(error)
                            raise error
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_darwin_guardian.py'):
                        self.assertEqual(system, 'darwin')
                        self.assertEqual(args[2:], [str(source.resolve()), '--mutations'])
                        self.assertEqual(kwargs['env']['GOOS'], system)
                        self.assertEqual(kwargs['env']['GOTOOLCHAIN'], N.TOOLCHAIN)
                        self.assertLessEqual(kwargs['timeout'], 1800)
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_dnssec_namespace.py'):
                        self.assertEqual(system, 'linux')
                        self.assertIsNotNone(dnssec_destination)
                        self.assertEqual(args[2:], [str(source.resolve()), str(dnssec_destination), target])
                        self.assertEqual(kwargs['cwd'], ROOT)
                        self.assertIs(kwargs['env'], env)
                        self.assertEqual(kwargs['timeout'], 900)
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_dnssec_command.py'):
                        self.assertEqual(system, 'linux')
                        self.assertIsNotNone(dnssec_destination)
                        self.assertEqual(args[2:], ['--source', str(source.resolve()), '--bundle', str(dnssec_destination), '--target', target])
                        self.assertEqual(kwargs['cwd'], ROOT)
                        self.assertIs(kwargs['env'], env)
                        self.assertEqual(kwargs['timeout'], 900)
                        return ''
                    if args[:2] in (['go', 'test'], ['go', 'mod']):
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_hysteria2_deadlines_pinned.py'):
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_amnezia_timers_pinned.py'):
                        self.assertEqual(args[2:], [str(source.resolve())])
                        self.assertEqual(kwargs['env']['GOOS'], system)
                        self.assertEqual(kwargs['env']['GOARCH'], arch)
                        self.assertEqual(kwargs['env']['CGO_ENABLED'], '1')
                        self.assertEqual(kwargs['env']['GOTOOLCHAIN'], N.TOOLCHAIN)
                        self.assertLessEqual(kwargs['timeout'], 600)
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_gvisor_forwarder_pinned.py'):
                        self.assertEqual(args[2:], [str(source.resolve())])
                        self.assertEqual(kwargs['env']['GOOS'], system)
                        self.assertEqual(kwargs['env']['GOARCH'], arch)
                        self.assertEqual(kwargs['env']['CGO_ENABLED'], '1')
                        self.assertEqual(kwargs['env']['GOTOOLCHAIN'], N.TOOLCHAIN)
                        self.assertEqual(kwargs['timeout'], 200)
                        if forwarder_failure is not None:
                            error = (forwarder_failure(29, args, output=b'captured forwarder failure')
                                     if forwarder_failure is subprocess.CalledProcessError else
                                     forwarder_failure(args, kwargs['timeout'], output=b'captured forwarder timeout'))
                            forwarder_errors.append(error)
                            raise error
                        return ''
                    self.fail('Unexpected native command before build: '+repr(args))

                def stage_cronet(_source, stage, actual, _env):
                    library = N.library_name(actual)
                    if library:
                        file(stage/library, b'captured fixture library')

                def build_dnssec(actual, destination, **options):
                    nonlocal dnssec_destination
                    self.assertEqual(system, 'linux')
                    self.assertEqual(actual, target)
                    self.assertEqual(options, {'compiled': None, 'env': env})
                    self.assertIs(options['env'], env)
                    previous = calls[-1]
                    self.assertEqual(previous[:2], ['go', 'test'])
                    self.assertEqual(previous[previous.index('-run')+1], '^TestRouterVPNDesktop(Tor|External)')
                    dnssec_destination = Path(destination)
                    self.assertFalse(dnssec_destination.exists())
                    # These bytes model the producer boundary; they are never
                    # loaded as a native validator by this orchestration test.
                    for name in N.DNSSEC.names(actual):
                        file(dnssec_destination/name, ('modeled DNSSEC payload: '+name).encode())
                    return dnssec_destination

                original_load = N.load
                with patch.object(N, 'load', side_effect=lambda name, path: PHYSICAL if path == 'test_windows_node_physical.py' else original_load(name, path)), \
                     patch.object(PHYSICAL, 'checked_sources', side_effect=lambda value: (value, {'modeled-source': 'a'*64})), \
                     patch.object(N, 'environment', return_value=env), patch.object(N, 'run', side_effect=run), \
                     patch.object(N.platform, 'system', return_value={'darwin': 'Darwin', 'linux': 'Linux', 'windows': 'Windows'}[system]), \
                     patch.object(N.platform, 'machine', return_value='x86_64' if arch == 'amd64' else 'arm64'), \
                     patch.object(N, 'pristine'), patch.object(N.PQ, 'verify', return_value={'native_static_libs': []}), \
                     patch.object(N.POLICY, 'prepare_native'), patch.object(N.PERFORMANCE, 'prepare'), \
                     patch.object(N.OPENVPN, 'prepare'), patch.object(N.BUFFERS, 'prepare'), \
                     patch.object(N.EXTERNAL, 'prepare'), patch.object(N.POLICY.AMNEZIA, 'verify'), \
                     patch.object(N.DNSSEC, 'build', side_effect=build_dnssec) as dnssec, \
                     patch.object(N, 'stage_cronet', side_effect=stage_cronet):
                    expected_error = desktop_pt_failure or physical_failure or command_retirement_failure or darwin_route_failure or forwarder_failure or socks_reference_failure or proxy_reference_failure or connect_reference_failure or dns_reference_failure or (node_failure if node_failure is not None and system in ('linux', 'windows') else
                                                          openvpn_failure if openvpn_failure is not None and system == 'linux' else CompilerBoundary)
                    with self.assertRaises(expected_error) as caught:
                        N.build(target, root/'output', source=source, xray=root/'xray', pq=root/'pq')
                if system == 'linux' and expected_error is CompilerBoundary:
                    dnssec.assert_called_once_with(target, dnssec_destination, compiled=None, env=env)
                else:
                    dnssec.assert_not_called()
                if desktop_pt_errors:
                    self.assertEqual(len(desktop_pt_errors), 1)
                    self.assertIs(caught.exception, desktop_pt_errors[0])
                    self.assertEqual(calls[-1][1], str(ROOT/'deploy/test_desktop_pt_inventory.py'))
                    self.assertFalse(any(args[:2] == ['go', 'build'] for args in calls))
                    continue
                if physical_failure:
                    phases = [args[4] for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_windows_node_physical.py')]
                    self.assertEqual(phases, list(PHYSICAL.PHASES[:5]))
                    self.assertFalse(any(args[:2] == ['go', 'build'] for args in calls))
                    self.assertFalse(any(len(args) > 1 and args[1] == str(ROOT/'deploy/test_windows_node_pq.py') for args in calls))
                    if physical_errors:
                        self.assertIs(caught.exception, physical_errors[0])
                    continue
                if command_retirement_errors:
                    self.assertEqual(len(command_retirement_errors), 1)
                    self.assertIs(caught.exception, command_retirement_errors[0])
                    self.assertEqual(calls[-1][1], str(ROOT/'deploy/test_desktop_command_retirement.py'))
                    self.assertFalse(any(args[:2] == ['go', 'build'] for args in calls))
                    continue
                timers = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_amnezia_timers_pinned.py')]
                self.assertEqual(len(timers), 1, 'Native build omitted the actual pinned AWG timer gate')
                self.assertIn(ROOT/'deploy/test_amnezia_timers_pinned.py', N.inputs())
                forwarder = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_gvisor_forwarder_pinned.py')]
                self.assertEqual(len(forwarder), 1, 'Native build omitted the actual pinned TCP forwarder gate')
                self.assertEqual(calls.index(forwarder[0]), calls.index(timers[0]) + 1)
                for dependency in ('deploy/prepare-gvisor-forwarder.py', 'deploy/test_gvisor_forwarder_pinned.py',
                                   'deploy/test_gvisor_forwarder_runner.py', 'mobile/gvisorforwarder/forwarder_test.go.tmpl'):
                    self.assertIn(ROOT/dependency, N.inputs())
                if forwarder_errors:
                    self.assertEqual(len(forwarder_errors), 1)
                    self.assertIs(caught.exception, forwarder_errors[0])
                    self.assertEqual(calls[-1], forwarder[0], 'A failed native forwarder gate reached a later operation')
                    continue
                if node_errors:
                    node = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_node_physical.py')]
                    self.assertEqual(len(node), 1)
                    self.assertEqual(len(node_errors), 1)
                    self.assertIs(caught.exception, node_errors[0], 'The original source-gate failure was replaced')
                    self.assertEqual(calls[-1], node[0], 'A failed source gate reached a later gate or shipping compilation')
                    continue
                socks_reference = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_mobile_imported_socks_xray.py')]
                self.assertEqual(len(socks_reference), 1 if system == 'linux' else 0)
                if socks_reference:
                    node = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_node_physical.py')]
                    self.assertEqual(len(node), 1)
                    self.assertEqual(calls.index(socks_reference[0]), calls.index(node[0]) + 1)
                for dependency in ('deploy/test_mobile_imported_socks_xray.py',
                                   'deploy/test_mobile_imported_socks_xray_runner.py',
                                   'mobile/desktop/node_imported_socks_xray_test.go.tmpl'):
                    self.assertIn(ROOT/dependency, N.inputs())
                if socks_reference_errors:
                    self.assertEqual(len(socks_reference_errors), 1)
                    self.assertIs(caught.exception, socks_reference_errors[0], 'The original SOCKS REALITY reference failure was replaced')
                    self.assertEqual(calls[-1], socks_reference[0], 'Failed SOCKS REALITY reference reached a later gate or compiler')
                    self.assertFalse(any(args[:2] == ['go', 'build'] for args in calls))
                    continue
                proxy_reference = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_mobile_imported_proxy_xray.py')]
                self.assertEqual(len(proxy_reference), 1 if system == 'linux' else 0)
                if proxy_reference:
                    self.assertEqual(calls.index(proxy_reference[0]), calls.index(socks_reference[0])+1)
                for dependency in ('deploy/test_mobile_imported_proxy_xray.py',
                                   'deploy/test_mobile_imported_proxy_xray_runner.py',
                                   'mobile/desktop/node_imported_proxy_xray_test.go.tmpl'):
                    self.assertIn(ROOT/dependency, N.inputs())
                if proxy_reference_errors:
                    self.assertEqual(len(proxy_reference_errors), 1)
                    self.assertIs(caught.exception, proxy_reference_errors[0], 'The original proxy REALITY reference failure was replaced')
                    self.assertEqual(calls[-1], proxy_reference[0], 'Failed proxy REALITY reference reached a later gate or compiler')
                    self.assertFalse(any(args[:2] == ['go', 'build'] for args in calls))
                    continue
                connect_reference = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_mobile_imported_connect_xray.py')]
                self.assertEqual(len(connect_reference), 1 if system == 'linux' else 0)
                if connect_reference:
                    self.assertEqual(calls.index(connect_reference[0]), calls.index(proxy_reference[0])+1)
                for dependency in ('deploy/test_mobile_imported_connect_xray.py',
                                   'deploy/test_mobile_imported_connect_xray_runner.py',
                                   'mobile/desktop/node_imported_connect_xray_test.go.tmpl',
                                   'mobile/desktop/node_imported_connect_xray_dns_test.go.tmpl'):
                    self.assertIn(ROOT/dependency, N.inputs())
                if connect_reference_errors:
                    self.assertEqual(len(connect_reference_errors), 1)
                    self.assertIs(caught.exception, connect_reference_errors[0], 'The original CONNECT REALITY reference failure was replaced')
                    self.assertEqual(calls[-1], connect_reference[0], 'Failed CONNECT REALITY reference reached a later gate or compiler')
                    self.assertFalse(any(args[:2] == ['go', 'build'] for args in calls))
                    continue
                dns_reference = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_native_xray_udp443.py')]
                self.assertEqual(len(dns_reference), 1 if system == 'linux' else 0)
                if dns_reference:
                    self.assertEqual(calls.index(dns_reference[0]), calls.index(connect_reference[0])+1)
                for dependency in ('deploy/test_native_xray_udp443.py',
                                   'deploy/test_native_xray_udp443_runner.py',
                                   'mobile/applexray/udp443_traffic_test.go.tmpl'):
                    self.assertIn(ROOT/dependency, N.inputs())
                if dns_reference_errors:
                    self.assertEqual(len(dns_reference_errors), 1)
                    self.assertIs(caught.exception, dns_reference_errors[0], 'The original selected-DNS reference failure was replaced')
                    self.assertEqual(calls[-1], dns_reference[0], 'Failed selected-DNS reference reached a later gate or compiler')
                    self.assertFalse(any(args[:2] == ['go', 'build'] for args in calls))
                    continue
                if openvpn_failure and system == 'linux':
                    gate = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_linux_external_openvpn.py')]
                    self.assertEqual(len(gate), 1)
                    self.assertEqual(len(openvpn_errors), 1)
                    self.assertIs(caught.exception, openvpn_errors[0], 'The original OpenVPN gate failure was replaced')
                    self.assertEqual(calls[-1], gate[0], 'Failed native OpenVPN proof reached a later gate or compiler')
                    checks = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_linux_external_openvpn_runner.py')]
                    self.assertEqual(len(checks), 1)
                    self.assertEqual(calls.index(gate[0]), calls.index(checks[0]) + 1)
                    continue
                if darwin_route_failure is not None:
                    gate = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_darwin_route.py')]
                    self.assertEqual(len(gate), 1)
                    self.assertEqual(len(darwin_route_errors), 1)
                    self.assertIs(caught.exception, darwin_route_errors[0], 'The original route gate failure was replaced')
                    self.assertEqual(calls[-1], gate[0], 'Failed route ownership reached a later gate or compiler')
                    self.assertFalse(any(len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_darwin_guardian.py') for args in calls))
                    continue
                box = [args for args in calls if args[:2] == ['go', 'test'] and '.' in args and
                       '-run' in args and args[args.index('-run')+1] == '^TestRouterVPNDesktop(Tor|External)']
                self.assertEqual(len(box), 1, 'Native build omitted the complete Box family suite')
                self.assertEqual([arg for arg in box[0] if arg.startswith('-timeout=')],
                                 ['-timeout=180s' if system == 'linux' else '-timeout=120s'])
                dnssec_gates = [args for args in calls if len(args) > 1 and args[1] in (
                    str(ROOT/'deploy/test_desktop_dnssec_namespace.py'),
                    str(ROOT/'deploy/test_desktop_dnssec_command.py'))]
                self.assertEqual([args[1] for args in dnssec_gates], [
                    str(ROOT/'deploy/test_desktop_dnssec_namespace.py'),
                    str(ROOT/'deploy/test_desktop_dnssec_command.py')] if system == 'linux' else [])
                if dnssec_gates:
                    self.assertEqual(calls.index(dnssec_gates[0]), calls.index(box[0])+1)
                    self.assertEqual(calls.index(dnssec_gates[1]), calls.index(dnssec_gates[0])+1)
                    self.assertEqual(calls[-3:-1], dnssec_gates)
                    self.assertEqual(calls[-1][:2], ['go', 'build'])
                for args in calls:
                    if args[:2] == ['go', 'test'] and args != box[0]:
                        self.assertNotIn('-timeout=180s', args, 'Box aggregate budget changed another native gate')
                uid = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_socket_uid.py')]
                self.assertEqual(len(uid), 0 if system == 'windows' else 1)
                self.assertIn(ROOT/'deploy/test_desktop_socket_uid.py', N.inputs())
                node = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_node_physical.py')]
                self.assertEqual(len(node), 1 if system in ('linux', 'windows') else 0)
                self.assertIn(ROOT/'deploy/test_desktop_node_physical.py', N.inputs())
                node_pq = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_node_pq.py')]
                self.assertEqual(len(node_pq), len(node))
                if node_pq:
                    predecessor = dns_reference[0] if dns_reference else node[0]
                    self.assertEqual(calls.index(node_pq[0]), calls.index(predecessor)+1)
                max_runner = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_node_max_runner.py')]
                max_graph = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_node_max.py')]
                self.assertEqual(len(max_runner), len(node))
                self.assertEqual(len(max_graph), len(node))
                if max_graph:
                    self.assertEqual(calls.index(max_runner[0]), calls.index(node_pq[0])+1)
                    self.assertEqual(calls.index(max_graph[0]), calls.index(max_runner[0])+1)
                for dependency in ('deploy/test_desktop_node_max.py', 'deploy/test_desktop_node_max_runner.py',
                                   'mobile/desktop/node_max_peer_test.go.tmpl', 'mobile/desktop/node_max_stream_test.go.tmpl',
                                   'mobile/desktop/node_max_tls_reference_test.go.tmpl', 'mobile/desktop/node_max_credentials_test.go.tmpl'):
                    self.assertIn(ROOT/dependency, N.inputs())
                for dependency in ('deploy/test_desktop_node_pq.py', 'deploy/build_pq_reference_fixture.py',
                                   'deploy/test_server_pq_traffic.py', 'mobile/rosenpass/examples/native_keys.rs',
                                   'mobile/pq/native_factory_real_test.go.tmpl', 'mobile/pq/native_traffic_test.go.tmpl',
                                   'mobile/desktop/node_pq_peer_test.go.tmpl', 'mobile/amnezia/pq_reference_fixture.go.tmpl'):
                    self.assertIn(ROOT/dependency, N.inputs())
                native_factory = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_pt_inventory.py')]
                self.assertEqual(len(native_factory), 1)
                for name in ('CapturesPolicyAndRetainsLateOwner', 'RejectsUncapturedSourceBeforeConstructor', 'CloseJoinsLateFactoryAndRetriesSource'):
                    self.assertRegex('TestRouterVPNNodePhysicalUnix' + name, PT.SELECTION)
                    if system != 'windows':
                        self.assertIn('TestRouterVPNNodePhysicalUnix' + name, PT.expected_roots(system))
                for name in ('test_desktop_pt_inventory.py', 'test_desktop_pt_inventory_runner.py'):
                    self.assertIn(ROOT/'deploy'/name, N.inputs())
                self.assertIn(ROOT/'go.mod', N.inputs())
                self.assertIn(ROOT/'cmd/start-layer-relay/main.go', N.inputs())
                if (ROOT/'go.sum').exists() or (ROOT/'go.sum').is_symlink():
                    self.assertIn(ROOT/'go.sum', N.inputs())
                runner = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_windows_identity_runner.py')]
                self.assertEqual(len(runner), 1 if system == 'windows' else 0)
                windows = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_windows_identity.py')]
                self.assertEqual(len(windows), 1 if system == 'windows' else 0)
                if windows:
                    self.assertEqual(calls.index(windows[0]), calls.index(runner[0])+1)
                self.assertIn(ROOT/'deploy/test_desktop_windows_identity.py', N.inputs())
                wfp = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_windows_wfp.py')]
                self.assertEqual(len(wfp), 1 if system == 'windows' else 0)
                self.assertIn(ROOT/'deploy/test_desktop_windows_wfp.py', N.inputs())
                transfer = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_windows_protection_transfer.py')]
                self.assertEqual(len(transfer), 1 if system == 'windows' else 0)
                self.assertIn(ROOT/'deploy/test_windows_protection_transfer.py', N.inputs())
                if transfer:
                    self.assertEqual(calls.index(transfer[0]), calls.index(wfp[0])+1)
                observation = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_windows_protection_observation.py')]
                self.assertEqual(len(observation), 1 if system == 'windows' else 0)
                self.assertIn(ROOT/'deploy/test_windows_protection_observation.py', N.inputs())
                if observation:
                    self.assertEqual(calls.index(observation[0]), calls.index(transfer[0])+1)
                provider_join = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_windows_external_provider_join.py')]
                self.assertEqual(len(provider_join), 1 if system == 'windows' else 0)
                kernel_runner = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_windows_node_physical_runner.py')]
                kernel_node = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_windows_node_physical.py')]
                self.assertEqual(len(kernel_runner), 1 if system == 'windows' else 0)
                self.assertEqual(len(kernel_node), len(kernel_runner) * len(PHYSICAL.PHASES))
                if kernel_node:
                    self.assertEqual([args[4] for args in kernel_node], list(PHYSICAL.PHASES))
                if kernel_node:
                    self.assertEqual(calls.index(provider_join[0]), calls.index(observation[0])+1)
                    self.assertEqual(calls.index(kernel_runner[0]), calls.index(provider_join[0])+1)
                    self.assertEqual(calls.index(kernel_node[0]), calls.index(kernel_runner[0])+1)
                for name in ('test_windows_node_physical.py', 'test_windows_node_physical_runner.py', 'test_windows_external_provider_join.py'):
                    self.assertIn(ROOT/'deploy'/name, N.inputs())
                self.assertIn(ROOT/'deploy/fixtures/windows-node-physical/kernel_observer.go', N.inputs())
                pq_kernel_runner = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_windows_node_pq_runner.py')]
                pq_kernel = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_windows_node_pq.py')]
                self.assertEqual(len(pq_kernel_runner), len(kernel_runner))
                self.assertEqual(len(pq_kernel), len(kernel_runner))
                if pq_kernel:
                    self.assertEqual(calls.index(pq_kernel_runner[0]), calls.index(kernel_node[-1])+1)
                    self.assertEqual(calls.index(pq_kernel[0]), calls.index(pq_kernel_runner[0])+1)
                for name in ('test_windows_node_pq.py', 'test_windows_node_pq_runner.py'):
                    self.assertIn(ROOT/'deploy'/name, N.inputs())
                self.assertIn(ROOT/'mobile/desktop/node_pq_peer_windows_test.go.tmpl', N.inputs())
                traffic = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_windows_traffic.py')]
                self.assertEqual(len(traffic), 1 if system == 'windows' else 0)
                self.assertIn(ROOT/'deploy/test_desktop_windows_traffic.py', N.inputs())
                bootstrap = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_windows_physical_bootstrap.py')]
                self.assertEqual(len(bootstrap), 1 if system == 'windows' else 0)
                if bootstrap:
                    self.assertGreater(calls.index(bootstrap[0]), calls.index(traffic[0]))
                self.assertIn(ROOT/'deploy/test_windows_physical_bootstrap.py', N.inputs())
                for name in ('kernel_observer.go', 'resolver_access.go', 'bootstrap_test.go', 'tunnel_test.go'):
                    self.assertIn(ROOT/'deploy/fixtures/windows-physical-bootstrap'/name, N.inputs())
                tunnel = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_windows_physical_tunnel.py')]
                self.assertEqual(len(tunnel), 1 if system == 'windows' else 0)
                if tunnel:
                    self.assertGreater(calls.index(tunnel[0]), calls.index(bootstrap[0]))
                self.assertIn(ROOT/'deploy/test_windows_physical_tunnel.py', N.inputs())
                self.assertIn(ROOT/'deploy/test_windows_physical_tunnel_runner.py', N.inputs())
                guardian = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_linux_guardian.py')]
                self.assertEqual(len(guardian), 1 if system == 'linux' else 0)
                command_retirement = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_command_retirement.py')]
                self.assertEqual(len(command_retirement), len(guardian))
                if guardian:
                    self.assertEqual(calls.index(guardian[0]), calls.index(command_retirement[0])+1)
                self.assertIn(ROOT/'deploy/test_desktop_command_retirement.py', N.inputs())
                self.assertIn(ROOT/'deploy/test_desktop_linux_guardian.py', N.inputs())
                child_checks = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_linux_node_child_control_runner.py')]
                child = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_linux_node_child_control.py')]
                self.assertEqual(len(child_checks), 1 if system == 'linux' else 0)
                self.assertEqual(len(child), len(child_checks))
                if child:
                    self.assertEqual(calls.index(child_checks[0]), calls.index(guardian[0])+1)
                    self.assertEqual(calls.index(child[0]), calls.index(child_checks[0])+1)
                for name in ('test_linux_node_child_control.py', 'test_linux_node_child_control_runner.py'):
                    self.assertIn(ROOT/'deploy'/name, N.inputs())
                for name in ('node_command_control.go.tmpl', 'node_command_control_linux.go.tmpl',
                             'node_command_control_other.go.tmpl', 'node_command_run_linux.go.tmpl',
                             'node_command_control_linux_native_test.go.tmpl', 'node_box_linux_lifecycle.go.tmpl'):
                    self.assertIn(ROOT/'mobile/desktop'/name, N.inputs())
                for name in ('node_control_record.go', 'node_control_linux.go'):
                    self.assertIn(ROOT/'internal/linuxprotection'/name, N.inputs())
                external_checks = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_linux_external_lifecycle_runner.py')]
                external = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_linux_external_lifecycle.py')]
                self.assertEqual(len(external_checks), 1 if system == 'linux' else 0)
                self.assertEqual(len(external), len(external_checks))
                if external:
                    self.assertEqual(calls.index(external_checks[0]), calls.index(child[0])+1)
                    self.assertEqual(calls.index(external[0]), calls.index(external_checks[0])+1)
                for name in ('test_linux_external_lifecycle.py', 'test_linux_external_lifecycle_runner.py'):
                    self.assertIn(ROOT/'deploy'/name, N.inputs())
                openvpn_checks = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_linux_external_openvpn_runner.py')]
                openvpn = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_linux_external_openvpn.py')]
                self.assertEqual(len(openvpn_checks), 1 if system == 'linux' else 0)
                self.assertEqual(len(openvpn), len(openvpn_checks))
                if openvpn:
                    self.assertEqual(calls.index(openvpn_checks[0]), calls.index(external[0]) + 1)
                    self.assertEqual(calls.index(openvpn[0]), calls.index(openvpn_checks[0]) + 1)
                for name in ('test_linux_external_openvpn.py', 'test_linux_external_openvpn_runner.py'):
                    self.assertIn(ROOT/'deploy'/name, N.inputs())
                self.assertIn(ROOT/'mobile/desktop/external_box_openvpn_test.go.tmpl', N.inputs())
                lifecycle_checks = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_linux_node_lifecycle_runner.py')]
                lifecycle = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_linux_node_lifecycle.py')]
                self.assertEqual(len(lifecycle_checks), 1 if system == 'linux' else 0)
                self.assertEqual(len(lifecycle), len(lifecycle_checks))
                if lifecycle:
                    self.assertEqual(calls.index(lifecycle_checks[0]), calls.index(openvpn[0])+1)
                    self.assertEqual(calls.index(lifecycle[0]), calls.index(lifecycle_checks[0])+1)
                for name in ('test_linux_node_lifecycle.py', 'test_linux_node_lifecycle_runner.py'):
                    self.assertIn(ROOT/'deploy'/name, N.inputs())
                tun_checks = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_linux_node_child_tun_runner.py')]
                tun = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_linux_node_child_tun.py')]
                self.assertEqual(len(tun_checks), 1 if system == 'linux' else 0)
                self.assertEqual(len(tun), len(tun_checks))
                if tun:
                    self.assertEqual(calls.index(tun_checks[0]), calls.index(lifecycle[0])+1)
                    self.assertEqual(calls.index(tun[0]), calls.index(tun_checks[0])+1)
                for dependency in ('deploy/test_linux_node_child_tun.py', 'deploy/test_linux_node_child_tun_runner.py',
                                   'mobile/desktop/node_command_control_linux_tun_native_test.go.tmpl',
                                   'mobile/desktop/node_layer_peer_test.go.tmpl',
                                   'mobile/amnezia/desktop_reference_test.go.tmpl'):
                    self.assertIn(ROOT/dependency, N.inputs())
                darwin = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_darwin_guardian.py')]
                self.assertEqual(len(darwin), 1 if system == 'darwin' else 0)
                self.assertIn(ROOT/'deploy/test_desktop_darwin_guardian.py', N.inputs())
                for name in ('test_desktop_darwin_guardian_runner.py', 'test_desktop_darwin_observation.py'):
                    self.assertIn(ROOT/'deploy'/name, N.inputs())
                route_checks = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_darwin_route_runner.py')]
                routes = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_darwin_route.py')]
                self.assertEqual(len(route_checks), len(darwin))
                self.assertEqual(len(routes), len(darwin))
                if darwin:
                    self.assertEqual(calls.index(routes[0]), calls.index(route_checks[0]) + 1)
                    self.assertEqual(calls.index(darwin[0]), calls.index(routes[0]) + 1)
                for dependency in ('deploy/test_desktop_darwin_route.py', 'deploy/test_desktop_darwin_route_runner.py',
                                   'mobile/desktop/sing_tun_route_darwin_test.go.tmpl'):
                    self.assertIn(ROOT/dependency, N.inputs())
                physical = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_pt_inventory.py')]
                self.assertEqual(len(physical), 1)
                self.assertIn('PhysicalFactory|PhysicalTunnel|LinuxPhysicalFactory', PT.SELECTION)
                self.assertIn('DarwinPhysicalFactory|WindowsPhysicalFactory', PT.SELECTION)


class NativeSetup(unittest.TestCase):
    def exercise(self, target, actual_host=None, fault=''):
        system, arch = actual_host or tuple(target.split('/'))
        with tempfile.TemporaryDirectory(prefix='desktop-setup-contract-') as tmp:
            root = Path(tmp)
            bin_dir = root/'host-bin'
            for name in ('rustup', 'cmake', 'ninja', 'clang', 'clang++', 'llvm-ar', 'xcrun'):
                if name != fault:
                    file(bin_dir/name, executable=True)
            library = file(bin_dir/({'linux': 'libclang.so', 'darwin': 'libclang.dylib', 'windows': 'libclang.dll'}[system]))
            env = {'PATH': str(bin_dir), 'GITHUB_ENV': str(root/'env'), 'GITHUB_PATH': str(root/'path'),
                   'LIBCLANG_PATH': str(library), 'RUSTUP_TOOLCHAIN': 'unrelated-default'}
            file(root/'env', b'PRIOR=retained\n')
            file(root/'path', b'prior-path\n')
            calls, installs, loaded = [], [], []
            triple = G.PQ.TARGETS[target]

            def install(path):
                installs.append(path)
                suffix = '.exe' if system == 'windows' else ''
                for name in ('x86_64-w64-mingw32-clang', 'x86_64-w64-mingw32-clang++',
                             'aarch64-w64-mingw32-clang', 'aarch64-w64-mingw32-clang++', 'llvm-ar'):
                    file(path/'bin'/(name+suffix), executable=True)
                return path/'bin'

            def run(command, command_env, timeout=60):
                command = [str(arg) for arg in command]
                calls.append(command)
                self.assertGreater(timeout, 0)
                name = Path(command[0]).name
                if name in ('cmake', 'ninja'):
                    self.assertEqual(command[1:], ['--version'])
                    return '3.31.0' if name == 'cmake' else '1.12.1'
                if name == 'xcrun':
                    self.assertEqual(command[1:4], ['--sdk', 'macosx', '--find'])
                    return str(bin_dir/command[-1])
                if 'clang' in name:
                    return 'clang version 23.1.3 (fixture)'
                self.assertEqual(name, 'rustup')
                self.assertEqual(command_env['RUSTUP_TOOLCHAIN'], '1.99.0')
                self.assertTrue(command_env['PATH'].startswith(str(bin_dir)+os.pathsep))
                if command[1:3] == ['toolchain', 'install']:
                    self.assertEqual(command[3:], ['1.99.0', '--profile', 'minimal', '--no-self-update'])
                    if fault == 'rustup-failed':
                        raise RuntimeError('actual tool process failed')
                    return ''
                if command[1:3] == ['target', 'add']:
                    self.assertEqual(command[3:], ['--toolchain', '1.99.0', triple])
                    return ''
                if command[1] == 'run':
                    self.assertEqual(command[2], '1.99.0')
                    return command[3]+(' 1.98.0 ' if fault == command[3]+'-version' else ' 1.99.0 ')+'(fixture)'
                self.assertEqual(command[1:], ['target', 'list', '--installed', '--toolchain', '1.99.0'])
                return 'wrong-target' if fault == 'missing-target' else triple

            def validate(path):
                loaded.append(path)
                if fault == 'libclang':
                    raise OSError('wrong host architecture')
                self.assertEqual(path, library)
                return 'clang version 23.1.3'

            output = root/'native-toolchain'
            if fault == 'linked-output':
                other = root/'other'
                other.mkdir()
                output.symlink_to(other, target_is_directory=True)
            with patch.object(G, 'host', return_value=(system, arch)), \
                 patch.object(W, 'install', side_effect=install), \
                 patch.object(G, 'run', side_effect=run), \
                 patch.object(G, 'validate_libclang', side_effect=validate), contextlib.redirect_stdout(io.StringIO()):
                if fault:
                    with self.assertRaises((ValueError, RuntimeError)):
                        G.setup(target, output, env)
                    self.assertEqual((root/'env').read_text(), 'PRIOR=retained\n')
                    self.assertEqual((root/'path').read_text(), 'prior-path\n')
                else:
                    result = G.setup(target, output, env)
                    self.assertEqual((result['target'], result['rust_target']), (target, triple))
                    exports = result['environment']
                    self.assertEqual(exports['RUSTUP_TOOLCHAIN'], '1.99.0')
                    self.assertEqual(exports['LIBCLANG_PATH'], str(library))
                    self.assertEqual(exports['CC'], exports['CC_'+triple.replace('-', '_')])
                    self.assertEqual(exports['CC'], exports['CARGO_TARGET_'+triple.replace('-', '_').upper()+'_LINKER'])
                    self.assertEqual(loaded, [library])
                    for key, value in exports.items():
                        self.assertIn(key+'='+value+'\n', (root/'env').read_text())
                    self.assertEqual((root/'path').read_text().splitlines()[1:], list(reversed(result['prepend_path'])))
                    self.assertEqual(installs, [output/'llvm-mingw'] if target.startswith('windows/') else [])
                    if target.startswith('windows/'):
                        prefix = 'x86_64' if target.endswith('/amd64') else 'aarch64'
                        self.assertIn(prefix+'-w64-mingw32-clang', exports['CC'])
            return calls, installs

    def test_all_six_exact_native_targets_and_both_linux_cross_targets(self):
        self.assertEqual(G.PQ.RUST, '1.99.0')
        self.assertEqual(len(G.PQ.TARGETS), 6)
        for target in G.PQ.TARGETS:
            with self.subTest(target=target):
                self.exercise(target)
        for arch in ('amd64', 'arm64'):
            with self.subTest(linux_cross=arch):
                self.exercise('windows/'+arch, ('linux', arch))

    def test_setup_never_exports_missing_or_wrong_toolchains(self):
        for fault in ('rustup', 'cmake', 'ninja', 'clang', 'clang++', 'libclang',
                      'rustup-failed', 'rustc-version', 'cargo-version', 'missing-target', 'linked-output'):
            with self.subTest(fault=fault):
                self.exercise('linux/amd64', fault=fault)

    def test_unsupported_target_or_native_cross_host_fails_before_install(self):
        for target, host in [('linux/386', ('linux', 'amd64')), ('linux/arm64', ('linux', 'amd64')),
                             ('darwin/arm64', ('darwin', 'amd64')), ('windows/arm64', ('darwin', 'arm64')),
                             ('linux/amd64', ('windows', 'amd64'))]:
            with self.subTest(target=target, host=host), patch.object(G, 'host', return_value=host), \
                 patch.object(G, 'executable') as lookup, patch.object(W, 'install') as installer:
                with self.assertRaises(ValueError):
                    G.setup(target, Path('/unused-output'), {})
                lookup.assert_not_called()
                installer.assert_not_called()

    def test_invalid_explicit_libclang_does_not_fall_back_to_another_installation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            file(root/'bin/libclang.so')
            file(root/'lib/libclang.so')
            foreign = file(root/'foreign.so')
            self.assertEqual(G.libclang_candidates('linux', root/'bin/clang', {'LIBCLANG_PATH':str(foreign)}), [])
            self.assertEqual(G.libclang_candidates('linux', root/'bin/clang', {'LIBCLANG_PATH':str(root/'absent')}), [])
            with self.assertRaisesRegex(ValueError, 'correct LIBCLANG_PATH'):
                G.find_libclang('linux', root/'bin/clang', {'LIBCLANG_PATH':str(root/'absent')})

    def test_host_libclang_c_api_is_exercised_and_disposed(self):
        for version, index, valid in [(b'clang version 23.1.3', 17, True),
                                      (b'clang version 8.0.0', 17, False),
                                      (b'clang version 23.1.3', 0, False)]:
            api = MagicMock()
            api.clang_getCString.return_value = version
            api.clang_createIndex.return_value = index
            with self.subTest(version=version, index=index), tempfile.TemporaryDirectory() as temp, \
                 patch.object(G.ctypes, 'CDLL', return_value=api):
                library = Path(temp)/'libclang.so'
                if valid:
                    self.assertEqual(G.validate_libclang(library), version.decode())
                    api.clang_disposeIndex.assert_called_once_with(17)
                else:
                    with self.assertRaises(ValueError):
                        G.validate_libclang(library)
                api.clang_disposeString.assert_called_once_with(api.clang_getClangVersion.return_value)

    def test_environment_rejects_newline_injection_before_any_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = {'GITHUB_ENV':str(root/'env'), 'GITHUB_PATH':str(root/'path')}
            for values, paths in [({'RUSTUP_TOOLCHAIN':'1.99.0\nCC=foreign'}, ['safe']),
                                  ({'INVALID=NAME':'value'}, ['safe']), ({'CC':'safe'}, ['safe\nforeign'])]:
                with self.assertRaises(ValueError):
                    G.export_environment(values, paths, env)
                self.assertFalse((root/'env').exists())
                self.assertFalse((root/'path').exists())


class DarwinPQEnvironment(unittest.TestCase):
    def test_both_architectures_use_the_selected_sdk_and_product_minimum(self):
        for target, arch in [('darwin/amd64', 'x86_64'), ('darwin/arm64', 'arm64')]:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                sdk = root/'Xcode Selected.app/SDKs/MacOSX.sdk'
                file(sdk/'usr/include/stdio.h', b'/* selected SDK C header */\n')
                triple = G.PQ.TARGETS[target]
                compiler = str(root/'Xcode Selected.app/bin/clang')
                inherited = {'PATH': str(root/'bin'), 'LIBCLANG_PATH': str(root/'libclang.dylib'),
                             'SDKROOT': '/stale-ios-sdk', 'MACOSX_DEPLOYMENT_TARGET': '15.5',
                             'BINDGEN_EXTRA_CLANG_ARGS': '-isysroot /stale-generic',
                             'BINDGEN_EXTRA_CLANG_ARGS_'+triple: '-isysroot /stale-hyphen',
                             'BINDGEN_EXTRA_CLANG_ARGS_'+triple.replace('-', '_'): '-isysroot /stale-underscore',
                             'CC_'+triple.replace('-', '_'): compiler}
                queried_env = {}

                def query_sdk(command, *, env, merge_stderr):
                    queried_env.update(env)
                    return str(sdk)+'\n'

                with patch.dict(os.environ, inherited, clear=True), \
                     patch.object(G.PQ.shutil, 'which', return_value='/usr/bin/xcrun') as lookup, \
                     patch.object(G.PQ, 'run', side_effect=query_sdk) as command:
                    env = G.PQ.environment(target, root/'cargo-cache')
                lookup.assert_called_once_with('xcrun', path=inherited['PATH'])
                self.assertEqual(command.call_args.args[0], ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path'])
                self.assertFalse(command.call_args.kwargs['merge_stderr'])
                self.assertNotIn('SDKROOT', queried_env)
                self.assertEqual(env['SDKROOT'], str(sdk))
                self.assertEqual(env['MACOSX_DEPLOYMENT_TARGET'], '13.0')
                expected = ['-target', arch+'-apple-macosx13.0', '-isysroot', str(sdk)]
                for key in ('BINDGEN_EXTRA_CLANG_ARGS', 'BINDGEN_EXTRA_CLANG_ARGS_'+triple,
                            'BINDGEN_EXTRA_CLANG_ARGS_'+triple.replace('-', '_')):
                    self.assertEqual(shlex.split(env[key]), expected)
                for key in ('PATH', 'LIBCLANG_PATH', 'CC_'+triple.replace('-', '_')):
                    self.assertEqual(env[key], inherited[key])
                self.assertEqual(env['CARGO_TARGET_DIR'], str(root/'cargo-cache'))

    def test_missing_xcrun_never_uses_an_ambient_sdk(self):
        with patch.dict(os.environ, {'PATH': '/no-tools', 'SDKROOT': '/ambient-sdk'}, clear=True), \
             patch.object(G.PQ.shutil, 'which', return_value=None), patch.object(G.PQ, 'run') as command:
            with self.assertRaisesRegex(ValueError, 'selected Xcode macOS SDK'):
                G.PQ.environment('darwin/arm64', Path('/unused-cache'))
            command.assert_not_called()

    def test_sdk_lookup_failure_is_propagated_without_an_ambient_fallback(self):
        failure = subprocess.CalledProcessError(1, ['xcrun'])
        with patch.dict(os.environ, {'PATH': '/tools', 'SDKROOT': '/ambient-sdk'}, clear=True), \
             patch.object(G.PQ.shutil, 'which', return_value='/usr/bin/xcrun'), \
             patch.object(G.PQ, 'run', side_effect=failure):
            with self.assertRaises(subprocess.CalledProcessError) as caught:
                G.PQ.environment('darwin/amd64', Path('/unused-cache'))
            self.assertIs(caught.exception, failure)

    def test_sdk_output_must_be_one_absolute_existing_path_with_c_headers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sdk = root/'complete.sdk'
            file(sdk/'usr/include/stdio.h')
            incomplete = root/'without-headers.sdk'
            incomplete.mkdir()
            for selected in ('', '\n', 'relative.sdk', str(root/'missing.sdk'), str(incomplete),
                             str(sdk)+'\n/other.sdk', str(sdk)+'\r/other.sdk', str(sdk)+'\0'):
                with self.subTest(selected=selected), \
                     patch.object(G.PQ.shutil, 'which', return_value='/usr/bin/xcrun'), \
                     patch.object(G.PQ, 'run', return_value=selected):
                    with self.assertRaisesRegex(ValueError, 'does not contain its C headers'):
                        G.PQ.environment('darwin/arm64', root/'cargo-cache')

    def test_linux_build_does_not_discover_or_require_an_apple_sdk(self):
        with patch.dict(os.environ, {'PATH': '/tools', 'SDKROOT': '/ambient-sdk'}, clear=True), \
             patch.object(G.PQ.shutil, 'which') as lookup, patch.object(G.PQ, 'run') as command:
            env = G.PQ.environment('linux/amd64', Path('/cargo-cache'))
            self.assertNotIn('SDKROOT', env)
            lookup.assert_not_called()
            command.assert_not_called()


class DarwinNativeEnvironment(unittest.TestCase):
    @staticmethod
    def sdk(root):
        sdk = root/'Xcode Selected.app/SDKs/MacOSX.sdk'
        for header in ('stdio.h', 'stdlib.h', 'pthread.h'):
            file(sdk/'usr/include'/header, b'#define ROUTERVPN_SELECTED_SDK 1\n')
        return sdk

    def test_metadata_only_foreign_verification_never_requires_xcode(self):
        for target in ('darwin/amd64', 'darwin/arm64'):
            with self.subTest(target=target), patch.dict(os.environ, {'PATH': '/no-apple-tools'}, clear=True), \
                 patch.object(N.shutil, 'which') as lookup, patch.object(N, 'run') as command:
                env = N.environment(target)
                self.assertEqual((env['GOOS'], env['GOARCH']), tuple(target.split('/')))
                self.assertNotIn('SDKROOT', env)
                self.assertNotIn('CGO_CFLAGS', env)
                lookup.assert_not_called()
                command.assert_not_called()

    def test_both_native_compilers_receive_exact_sdk_architecture_and_minimum(self):
        for target, arch in [('darwin/amd64', 'x86_64'), ('darwin/arm64', 'arm64')]:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                sdk = self.sdk(root)
                inherited = {'PATH': str(root/'bin'), 'CC': str(root/'bin/clang'),
                             'SDKROOT': '/ambient-ios-sdk', 'MACOSX_DEPLOYMENT_TARGET': '15.5',
                             'CGO_CFLAGS': '-isysroot /stale-c-sdk',
                             'CGO_CXXFLAGS': '-isysroot /stale-cxx-sdk',
                             'CGO_LDFLAGS': '-isysroot /stale-link-sdk'}
                queried = {}

                def query(command, *, env):
                    queried.update(env)
                    return str(sdk)

                with patch.dict(os.environ, inherited, clear=True), \
                     patch.object(N.shutil, 'which', return_value='/usr/bin/xcrun') as lookup, \
                     patch.object(N, 'run', side_effect=query) as command:
                    env = N.environment(target, compiler=True)
                lookup.assert_called_once_with('xcrun', path=inherited['PATH'])
                self.assertEqual(command.call_args.args[0], ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path'])
                self.assertNotIn('SDKROOT', queried)
                self.assertEqual(env['SDKROOT'], str(sdk))
                self.assertEqual(env['MACOSX_DEPLOYMENT_TARGET'], '13.0')
                expected = ['-target', arch+'-apple-macosx13.0', '-isysroot', str(sdk)]
                self.assertEqual(shlex.split(env['CGO_LDFLAGS']), expected)
                for key in ('CGO_CFLAGS', 'CGO_CXXFLAGS'):
                    self.assertEqual(shlex.split(env[key]), ['-O2', '-g', *expected])
                self.assertEqual(env['CC'], inherited['CC'])

    def test_invalid_sdk_or_failed_lookup_cannot_use_ambient_headers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sdk = self.sdk(root)
            incomplete = root/'incomplete.sdk'
            file(incomplete/'usr/include/stdio.h')
            for selected in ('', 'relative.sdk', str(root/'missing.sdk'), str(incomplete),
                             str(sdk)+'\n/other.sdk', str(sdk)+'\r/other.sdk', str(sdk)+'\0'):
                with self.subTest(selected=selected), \
                     patch.object(N.shutil, 'which', return_value='/usr/bin/xcrun'), \
                     patch.object(N, 'run', return_value=selected):
                    with self.assertRaisesRegex(ValueError, 'does not contain its C headers'):
                        N.environment('darwin/arm64', compiler=True)
            with patch.object(N.shutil, 'which', return_value=None), patch.object(N, 'run') as command:
                with self.assertRaisesRegex(ValueError, 'selected Xcode macOS SDK'):
                    N.environment('darwin/arm64', compiler=True)
                command.assert_not_called()
            error = subprocess.CalledProcessError(1, ['xcrun'])
            with patch.object(N.shutil, 'which', return_value='/usr/bin/xcrun'), \
                 patch.object(N, 'run', side_effect=error):
                with self.assertRaises(subprocess.CalledProcessError) as caught:
                    N.environment('darwin/amd64', compiler=True)
                self.assertIs(caught.exception, error)

    def test_final_go_build_preserves_sdk_and_verified_pq_link_flags(self):
        class CompilerBoundary(Exception):
            pass

        for target, arch in [('darwin/amd64', 'x86_64'), ('darwin/arm64', 'arm64')]:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                sdk = self.sdk(root)
                pq = root/'verified pq'
                dependencies = ['-lresolv', '-framework', 'Security', '-framework', 'CoreFoundation']
                commands = []

                def run(command, *, env=None, **kwargs):
                    args = [str(value) for value in command]
                    if args[0] == '/usr/bin/xcrun':
                        self.assertNotIn('SDKROOT', env)
                        return str(sdk)
                    if args == ['go', 'env', 'GOVERSION']:
                        return N.TOOLCHAIN
                    if args[:2] == ['go', 'build']:
                        commands.append((args, env.copy()))
                        raise CompilerBoundary()
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_pt_inventory.py'):
                        self.assertEqual(args[2:], [str((root/'core').resolve()), '--tags='+','.join(N.tags(target))])
                        self.assertEqual(kwargs['timeout'], 600)
                        return ''
                    if args[:2] == ['go', 'test']:
                        package = args[args.index('-ldflags=-checklinkname=0')+1]
                        expected = {
                            './cmd/sing-box': '^TestRouterVPN(Desktop(External|MTU|DNS|Tor)|NodeMTU)',
                            './routervpn/mobiletor': '^TestDesktopSocket',
                            './route': '^TestRouterVPNDesktopTorNetwork',
                            '.': '^TestRouterVPNDesktopTor',
                        }
                        self.assertIn(package, expected)
                        self.assertIn(expected[package], args)
                        return ''
                    self.assertIn(args, [['go', 'mod', 'tidy'], ['go', 'mod', 'verify']])
                    return ''

                with patch.dict(os.environ, {'PATH': '/fixture-tools', 'SDKROOT': '/ambient-sdk'}, clear=True), \
                     patch.object(N.shutil, 'which', return_value='/usr/bin/xcrun'), \
                     patch.object(N, 'run', side_effect=run), patch.object(N, 'pristine'), \
                     patch.object(N.PQ, 'verify', return_value={'native_static_libs': dependencies}), \
                     patch.object(N.POLICY, 'prepare_native'), patch.object(N.PERFORMANCE, 'prepare'), \
                     patch.object(N.OPENVPN, 'prepare'), patch.object(N.BUFFERS, 'prepare'), \
                     patch.object(N.EXTERNAL, 'prepare') as external_prepare, \
                     patch.object(N.POLICY.AMNEZIA, 'verify'), patch.object(N, 'stage_cronet'):
                    with self.assertRaises(CompilerBoundary):
                        N.build(target, root/'output', source=root/'core', xray=root/'xray', pq=pq)
                    external_prepare.assert_called_once_with((root/'core').resolve(), env=commands[0][1])
                    self.assertEqual(external_prepare.call_args.kwargs['env']['GOTOOLCHAIN'], N.TOOLCHAIN)
                self.assertEqual(len(commands), 1)
                _, env = commands[0]
                expected = ['-target', arch+'-apple-macosx13.0', '-isysroot', str(sdk)]
                self.assertEqual(shlex.split(env['CGO_LDFLAGS']), [*expected, '-L'+str(pq), *dependencies])
                self.assertEqual(shlex.split(env['CGO_CFLAGS']), ['-O2', '-g', *expected])
                self.assertEqual(shlex.split(env['CGO_CXXFLAGS']), ['-O2', '-g', *expected])

    def test_actual_clang_uses_selected_headers_and_target_with_missing_sdk_control(self):
        clang = shutil.which('clang')
        if not clang:
            self.skipTest('Clang is not installed on this fixture host')
        for target, machine in [('darwin/amd64', '__x86_64__'), ('darwin/arm64', '__arm64__')]:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                sdk = self.sdk(root)
                source = file(root/'sdk.c', (
                    '#include <stdio.h>\n'
                    '#if !defined(__APPLE__) || !defined('+machine+')\n#error wrong target\n#endif\n'
                    '#if __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ != 130000\n#error wrong minimum\n#endif\n'
                    '#if ROUTERVPN_SELECTED_SDK != 1\n#error missing selected SDK\n#endif\n'
                    '_Static_assert(sizeof(void*) == 8, "64-bit ABI");\n').encode())
                with patch.object(N.shutil, 'which', return_value='/usr/bin/xcrun'), \
                     patch.object(N, 'run', return_value=str(sdk)):
                    env = N.environment(target, compiler=True)
                flags = shlex.split(env['CGO_CFLAGS'])
                command = [clang, *flags, '-std=c11', '-fsyntax-only', str(source)]
                result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
                without_sdk = flags[:-2]
                result = subprocess.run([clang, *without_sdk, '-std=c11', '-fsyntax-only', str(source)],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
                self.assertNotEqual(result.returncode, 0, 'Missing SDK control compiled without the selected header')


class Response(io.BytesIO):
    def __init__(self, data, url='https://release-assets.githubusercontent.com/pinned-asset'):
        super().__init__(data)
        self.url = url

    def geturl(self):
        return self.url


def zip_bytes(prefix, entries=None):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        for name, data in (entries or [('bin/x86_64-w64-mingw32-clang.exe', b'compiler-a'),
                                      ('bin/aarch64-w64-mingw32-clang.exe', b'compiler-b')]):
            archive.writestr(prefix+'/'+name, data)
    return output.getvalue()


class VerifiedWindowsInstaller(unittest.TestCase):
    def test_gateway_retry_installs_only_original_verified_archive(self):
        prefix = 'llvm-mingw-fixture'
        raw = zip_bytes(prefix)
        body = io.BytesIO(b'gateway failure, never an archive')
        failure = W.urllib.error.HTTPError('https://github.com/pinned', 504, 'Gateway Time-out', {}, body)
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)/'installed'
            with patch.object(W.platform, 'system', return_value='Windows'), \
                 patch.object(W.platform, 'machine', return_value='AMD64'), \
                 patch.dict(W.ARCHIVES, {('Windows', 'amd64'): (prefix+'.zip', len(raw), hashlib.sha256(raw).hexdigest())}), \
                 patch.object(W.urllib.request, 'urlopen', side_effect=[failure, Response(raw)]) as download, \
                 patch.object(W.time, 'sleep') as sleep, \
                 patch.object(W.subprocess, 'check_output', return_value=W.CLANG+' (fixture)'):
                self.assertEqual(W.install(output), output/'bin')
                self.assertTrue(body.closed)
                self.assertEqual(download.call_count, 2)
                first, second = download.call_args_list
                self.assertIs(first.args[0], second.args[0])
                self.assertEqual(first.args[0].full_url, 'https://github.com/mstorsjo/llvm-mingw/releases/download/'+W.RELEASE+'/'+prefix+'.zip')
                self.assertEqual(first.kwargs['timeout'], 60)
                self.assertEqual(second.kwargs['timeout'], 60)
                sleep.assert_called_once_with(1)
                self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()), ['installed'])

    def test_gateway_retry_is_finite_and_preserves_final_error(self):
        for code in (502, 503, 504, 400, 401, 403, 404, 429, 500):
            with self.subTest(code=code):
                errors = [W.urllib.error.HTTPError('https://pinned', code, 'failure', {}, io.BytesIO()) for _ in range(3)]
                with patch.object(W.urllib.request, 'urlopen', side_effect=errors) as download, \
                     patch.object(W.time, 'monotonic', return_value=10), patch.object(W.time, 'sleep') as sleep:
                    with self.assertRaises(W.urllib.error.HTTPError) as caught:
                        W.open_archive(W.urllib.request.Request('https://pinned'), 610)
                    retry = code in (502, 503, 504)
                    self.assertIs(caught.exception, errors[2 if retry else 0])
                    self.assertEqual(download.call_count, 3 if retry else 1)
                    self.assertEqual([call.args[0] for call in sleep.call_args_list], [1, 2] if retry else [])
                    self.assertTrue(all(error.fp.closed for error in errors[:download.call_count]))

    def test_retry_uses_one_deadline_and_does_not_sleep_past_it(self):
        request = W.urllib.request.Request('https://pinned')
        failure = W.urllib.error.HTTPError(request.full_url, 504, 'gateway', {}, io.BytesIO())
        clock = [0.0]
        def failed_open(*args, **kwargs):
            self.assertEqual(kwargs['timeout'], 2)
            clock[0] = 1.5
            raise failure
        with patch.object(W.time, 'monotonic', side_effect=lambda: clock[0]), \
             patch.object(W.urllib.request, 'urlopen', side_effect=failed_open) as download, \
             patch.object(W.time, 'sleep') as sleep:
            with self.assertRaises(TimeoutError) as caught:
                W.open_archive(request, 2)
            self.assertIs(caught.exception.__cause__, failure)
            self.assertEqual(download.call_count, 1)
            sleep.assert_not_called()
        with patch.object(W.time, 'monotonic', return_value=2), patch.object(W.urllib.request, 'urlopen') as download:
            with self.assertRaises(TimeoutError):
                W.open_archive(request, 2)
            download.assert_not_called()

    def test_partial_download_cancellation_and_transport_failure_never_retry(self):
        for failure in (KeyboardInterrupt(), TimeoutError('original socket'), W.urllib.error.URLError('transport')):
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as tmp:
                response = Response(b'partial')
                reads = iter([b'partial', failure])
                def read(_size):
                    value = next(reads)
                    if isinstance(value, BaseException):
                        raise value
                    return value
                with patch.object(W.platform, 'system', return_value='Windows'), \
                     patch.object(W.platform, 'machine', return_value='AMD64'), \
                     patch.object(W.urllib.request, 'urlopen', return_value=response) as download, \
                     patch.object(response, 'read', side_effect=read), \
                     patch.object(W, 'extract') as extract, patch.object(W, 'check_compilers') as check:
                    with self.assertRaises(type(failure)) as caught:
                        W.install(Path(tmp)/'out')
                    self.assertIs(caught.exception, failure)
                    self.assertEqual(download.call_count, 1)
                    self.assertTrue(response.closed)
                    self.assertEqual(list(Path(tmp).iterdir()), [])
                    extract.assert_not_called()
                    check.assert_not_called()

    def test_retry_backoff_never_renews_original_deadline(self):
        clock = [0.0]
        response = Response(b'pinned')
        failure = W.urllib.error.HTTPError('https://pinned', 504, 'gateway', {}, io.BytesIO())
        calls = []
        def opened(request, timeout):
            calls.append(timeout)
            if len(calls) == 1:
                clock[0] = 598
                raise failure
            return response
        def sleep(delay):
            clock[0] += delay
        with patch.object(W.time, 'monotonic', side_effect=lambda: clock[0]), \
             patch.object(W.time, 'sleep', side_effect=sleep), \
             patch.object(W.urllib.request, 'urlopen', side_effect=opened):
            self.assertIs(W.open_archive(W.urllib.request.Request('https://pinned'), 600), response)
        self.assertEqual(calls, [60, 1])
        response.close()

    def test_successful_open_or_final_eof_after_deadline_never_publishes(self):
        for phase in ('open', 'eof'):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as tmp:
                clock = [0.0]
                response = Response(b'')
                def opened(*args, **kwargs):
                    if phase == 'open':
                        clock[0] = 600
                    return response
                def read(_size):
                    clock[0] = 600
                    return b''
                with patch.object(W.time, 'monotonic', side_effect=lambda: clock[0]), \
                     patch.object(W.platform, 'system', return_value='Windows'), \
                     patch.object(W.platform, 'machine', return_value='AMD64'), \
                     patch.object(W.urllib.request, 'urlopen', side_effect=opened) as download, \
                     patch.object(response, 'read', side_effect=read), \
                     patch.object(W, 'extract') as extract, patch.object(W, 'check_compilers') as check:
                    with self.assertRaises(TimeoutError):
                        W.install(Path(tmp)/'out')
                    self.assertEqual(download.call_count, 1)
                    self.assertTrue(response.closed)
                    self.assertEqual(list(Path(tmp).iterdir()), [])
                    extract.assert_not_called()
                    check.assert_not_called()

    def test_official_pin_covers_all_supported_host_architectures(self):
        self.assertEqual(W.RELEASE, '20261006')
        self.assertEqual(set(W.ARCHIVES), {(s,a) for s in ('Windows','Linux') for a in ('amd64','arm64')})
        for (system, arch), (name, size, digest) in W.ARCHIVES.items():
            self.assertTrue(name.startswith('llvm-mingw-'+W.RELEASE+'-ucrt-'))
            self.assertTrue(name.endswith('.zip' if system == 'Windows' else '.tar.xz'))
            self.assertGreater(size, 70_000_000)
            self.assertRegex(digest, r'^[a-f0-9]{64}$')

    def test_actual_verified_install_reuse_and_file_drift_rejection(self):
        prefix = 'llvm-mingw-fixture'
        raw = zip_bytes(prefix)
        entry = (prefix+'.zip', len(raw), hashlib.sha256(raw).hexdigest())
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)/'installed'
            commands, urls = [], []

            def download(request, timeout):
                urls.append(request.full_url)
                self.assertEqual(timeout, 60)
                return Response(raw)

            def compiler(command, **kwargs):
                self.assertTrue(Path(command[0]).is_file())
                self.assertEqual(command[1:], ['--version'])
                commands.append(command)
                return W.CLANG+' (verified fixture)'

            with patch.object(W.platform, 'system', return_value='Windows'), \
                 patch.object(W.platform, 'machine', return_value='AMD64'), \
                 patch.dict(W.ARCHIVES, {('Windows','amd64'):entry}), \
                 patch.object(W.urllib.request, 'urlopen', side_effect=download), \
                 patch.object(W.subprocess, 'check_output', side_effect=compiler):
                self.assertEqual(W.install(output), output/'bin')
                self.assertEqual(W.install(output), output/'bin')
                self.assertEqual(len(urls), 1)
                self.assertEqual(urls[0], 'https://github.com/mstorsjo/llvm-mingw/releases/download/20261006/'+prefix+'.zip')
                self.assertEqual(len(commands), 4)
                receipt = json.loads((output/'INSTALL.json').read_text())
                self.assertEqual(receipt['files']['bin/x86_64-w64-mingw32-clang.exe']['sha256'], hashlib.sha256(b'compiler-a').hexdigest())
                file(output/'bin/x86_64-w64-mingw32-clang.exe', b'foreign')
                with self.assertRaisesRegex(ValueError, 'unowned or mismatched'):
                    W.install(output)
                self.assertEqual(len(commands), 4, 'modified compiler executed before receipt validation')

    def test_download_size_hash_and_https_fail_before_extract_or_execution(self):
        raw = zip_bytes('llvm-mingw-fixture')
        for fault in ('long', 'short', 'hash', 'http'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as tmp:
                size = len(raw)+(1 if fault == 'short' else -1 if fault == 'long' else 0)
                digest = '0'*64 if fault == 'hash' else hashlib.sha256(raw).hexdigest()
                response = Response(raw, 'http://invalid' if fault == 'http' else 'https://example.test/asset')
                with patch.object(W.platform, 'system', return_value='Windows'), \
                     patch.object(W.platform, 'machine', return_value='AMD64'), \
                     patch.dict(W.ARCHIVES, {('Windows','amd64'):('llvm-mingw-fixture.zip',size,digest)}), \
                     patch.object(W.urllib.request, 'urlopen', return_value=response), \
                     patch.object(W, 'extract') as extract, patch.object(W, 'check_compilers') as check:
                    with self.assertRaises(ValueError):
                        W.install(Path(tmp)/'out')
                    extract.assert_not_called()
                    check.assert_not_called()
                    self.assertFalse((Path(tmp)/'out').exists())

    def test_windows_extraction_rejects_unsafe_namespace_and_links(self):
        prefix = 'llvm-mingw-fixture'
        entries = [('..\u002fescape', b'bad'), ('bin\\escape', b'bad'), ('bin/../escape', b'bad'),
                   ('bin/CON.exe', b'bad'), ('bin/clang.exe:stream', b'bad'), ('INSTALL.JSON', b'bad')]
        for unsafe in entries:
            with self.subTest(name=unsafe[0]), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                archive = file(root/'input.zip', zip_bytes(prefix, [unsafe]))
                with self.assertRaises(ValueError):
                    W.extract(archive, root, prefix, 'Windows')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = file(root/'input.zip', zip_bytes(prefix, [('bin/clang.exe',b'a'),('bin/CLANG.exe',b'b')]))
            with self.assertRaises(ValueError):
                W.extract(archive, root, prefix, 'Windows')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root/'input.zip'
            with zipfile.ZipFile(archive, 'w') as zipped:
                link = zipfile.ZipInfo(prefix+'/bin/link')
                link.create_system = 3
                link.external_attr = (stat.S_IFLNK|0o777)<<16
                zipped.writestr(link, 'clang.exe')
            with self.assertRaises(ValueError):
                W.extract(archive, root, prefix, 'Windows')

    def test_tar_accepts_real_internal_tool_links_and_rejects_escapes(self):
        prefix = 'llvm-mingw-fixture'
        for target, valid in [('clang',True), ('../../escape',False), ('/outside',False), ('missing',False)]:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                archive = root/'input.tar.xz'
                with tarfile.open(archive, 'w:xz') as tar:
                    compiler = tarfile.TarInfo(prefix+'/bin/clang')
                    compiler.size = 8
                    compiler.mode = 0o755
                    tar.addfile(compiler, io.BytesIO(b'compiler'))
                    link = tarfile.TarInfo(prefix+'/bin/x86_64-w64-mingw32-clang')
                    link.type = tarfile.SYMTYPE
                    link.linkname = target
                    tar.addfile(link)
                if valid:
                    W.extract(archive, root, prefix, 'Linux')
                    self.assertEqual((root/prefix/'bin/x86_64-w64-mingw32-clang').read_bytes(), b'compiler')
                    self.assertEqual(W.inventory(root/prefix)['bin/x86_64-w64-mingw32-clang'], {'link':'clang'})
                else:
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        W.extract(archive, root, prefix, 'Linux')

    def test_archive_expansion_and_existing_ownership_are_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = file(root/'input.zip', zip_bytes('compiler', [('large',b'0123456789')]))
            with patch.object(W, 'MAX_MEMBER', 9), self.assertRaises(ValueError):
                W.extract(archive, root, 'compiler', 'Windows')
            other = root/'unowned'
            other.mkdir()
            with patch.object(W.platform, 'system', return_value='Windows'), \
                 patch.object(W.platform, 'machine', return_value='AMD64'), \
                 patch.object(W.urllib.request, 'urlopen') as download, self.assertRaises(ValueError):
                W.install(other)
            download.assert_not_called()


class SelectedNodeCompiler(unittest.TestCase):
    @staticmethod
    def runner():
        spec = importlib.util.spec_from_file_location('selected_node_compiler', ROOT/'deploy/test_desktop_node_physical.py')
        node = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(node)
        return node

    def test_reused_module_helper_executes_selected_compiler_before_ambient_go(self):
        node = self.runner()
        if node.platform.system() not in ('Linux', 'Windows'):
            self.skipTest('Node compiler selection executes on Linux and Windows')
        go = shutil.which('go')
        self.assertIsNotNone(go, 'The executable compiler regression requires Go')
        with tempfile.TemporaryDirectory(prefix='node compiler ') as tmp:
            root = Path(tmp)
            source = root/'source'
            file(source/'go.mod', b'module example.test/node-compiler\n\ngo 1.26.0\n')
            env = dict(os.environ, GOTOOLCHAIN=N.TOOLCHAIN, GOWORK='off', GOFLAGS='', CGO_ENABLED='0')
            compiler, captured, _ = node.selected_compiler(go, source, env)
            decoy = root/'ambient compiler'
            decoy.mkdir()
            marker = root/'ambient-invocations'
            fake = file(root/'ambient.go', b'package main\nimport ("os"; "fmt")\nfunc main(){os.WriteFile(os.Getenv("ROUTERVPN_COMPILER_TEST_MARKER"), []byte("ambient compiler executed"), 0600); fmt.Fprintln(os.Stderr,"ambient compiler must not execute"); os.Exit(97)}\n')
            N.run([compiler, 'build', '-mod=readonly', '-o', decoy/compiler.name, fake], cwd=source, env=captured, timeout=60)

            # A private file proxy gives the real Go helper checksum-bearing
            # module metadata without network access or mocked subprocesses.
            dependency = 'example.test/compiler-fixture'
            version = 'v1.0.0'
            proxy = root/'proxy'
            prefix = proxy/dependency/'@v'
            module = b'module example.test/compiler-fixture\n\ngo 1.26.0\n'
            file(prefix/(version+'.mod'), module)
            file(prefix/(version+'.info'), json.dumps({'Version': version, 'Time': '2026-01-01T00:00:00Z'}).encode())
            with zipfile.ZipFile(prefix/(version+'.zip'), 'w') as archive:
                archive.writestr(dependency+'@'+version+'/go.mod', module)
            (source/'go.mod').write_text('module example.test/node-compiler\n\ngo 1.26.0\n\nrequire '+dependency+' '+version+'\n')
            incoming = dict(env, PATH=str(decoy)+os.pathsep+env.get('PATH', os.defpath),
                            GOPROXY=proxy.as_uri(), GOSUMDB='off', GOPRIVATE='', GONOPROXY='',
                            GOMODCACHE=str(root/'module-cache'), ROUTERVPN_COMPILER_TEST_MARKER=str(marker))
            before = incoming.copy()
            selected, captured, _ = node.selected_compiler(compiler, source, incoming)
            self.assertEqual(incoming, before)
            self.assertEqual(selected, compiler)
            N.run([selected, 'mod', 'download', dependency], cwd=source, env=captured, timeout=30)
            info = N.module(source, dependency, captured)
            self.assertEqual(info['Version'], version)
            self.assertTrue(info['Sum'].startswith('h1:'))
            self.assertFalse(marker.exists(), 'A packaging helper executed the ambient compiler')
            self.assertEqual(captured['PATH'].split(os.pathsep)[1:], incoming['PATH'].split(os.pathsep))
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(subprocess.CalledProcessError) as caught:
                N.module(source, dependency, dict(captured, PATH=incoming['PATH']))
            self.assertEqual(caught.exception.returncode, 97)
            self.assertEqual(marker.read_text(), 'ambient compiler executed')

    def test_windows_path_case_is_preserved_and_ambiguity_is_rejected(self):
        node = self.runner()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            file(root/'bin/go.exe')
            identity = {'GOROOT': str(root), 'GOVERSION': N.TOOLCHAIN, 'GOHOSTOS': 'windows', 'GOHOSTARCH': 'amd64'}
            for key in ('PATH', 'Path', 'pAtH'):
                with self.subTest(key=key), patch.object(node.platform, 'system', return_value='Windows'), \
                     patch.object(node, 'run', return_value=(0, json.dumps(identity))):
                    _, captured, _ = node.selected_compiler('bootstrap-go', root, {key: 'preserved-native-tools'})
                    self.assertEqual([key for key in captured if key.upper() == 'PATH'], ['PATH'])
                    self.assertEqual(captured['PATH'], str(root/'bin')+os.pathsep+'preserved-native-tools')
            with patch.object(node.platform, 'system', return_value='Windows'), \
                 patch.object(node, 'run', return_value=(0, json.dumps(identity))), \
                 self.assertRaisesRegex(ValueError, 'ambiguous executable search paths'):
                node.selected_compiler('bootstrap-go', root, {'PATH': 'first', 'Path': 'second'})


class RetainedNodeFileIdentity(unittest.TestCase):
    """Exercise CPython's distinct Windows path/handle views with real bytes."""
    def setUp(self):
        self.node = SelectedNodeCompiler.runner()
        temporary = tempfile.TemporaryDirectory(prefix='node image identity ')
        self.addCleanup(temporary.cleanup)
        self.image = file(Path(temporary.name)/'baseline.test.exe', b'original compiled image bytes')
        self.named = dict(st_dev=33, st_ino=(1 << 90) + 29, st_mode=stat.S_IFREG | 0o777,
                          st_nlink=1, st_size=self.image.stat().st_size,
                          st_mtime_ns=900, st_ctime_ns=100, st_birthtime_ns=100,
                          st_file_attributes=stat.FILE_ATTRIBUTE_ARCHIVE, st_reparse_tag=0)
        # Exact CPython 3.12.10 semantics: descriptor ctime is ChangeTime;
        # pathname ctime is creation time, and only the name gains execute bits.
        self.handled = dict(self.named, st_mode=stat.S_IFREG | 0o666, st_ctime_ns=800)

    def readback(self, *, named=None, handled=None, named_after=None, handled_after=None,
                 system='Windows', suffix='.exe'):
        named = self.named if named is None else named
        handled = self.handled if handled is None else handled
        path = MagicMock()
        path.suffix = suffix
        path.lstat.side_effect = [SimpleNamespace(**named),
                                 SimpleNamespace(**(named if named_after is None else named_after))]
        path.open.side_effect = self.image.open
        with patch.object(self.node.platform, 'system', return_value=system), \
             patch.object(self.node.os, 'fstat', side_effect=[SimpleNamespace(**handled),
                         SimpleNamespace(**(handled if handled_after is None else handled_after))]):
            return self.node.retained_binary(path)

    def test_windows_executable_annotation_and_native_times_keep_a_stable_receipt(self):
        for suffix in ('.exe', '.EXE'):
            with self.subTest(suffix=suffix):
                receipt = self.readback(suffix=suffix)
                self.assertEqual(receipt, self.readback(suffix=suffix))
                self.assertIn(hashlib.sha256(self.image.read_bytes()).hexdigest(), receipt)

    def test_both_original_ctime_values_remain_bound_between_invocations(self):
        original = self.readback()
        self.assertNotEqual(original, self.readback(named=dict(self.named, st_ctime_ns=101)))
        self.assertNotEqual(original, self.readback(handled=dict(self.handled, st_ctime_ns=801)))

    def test_equal_metadata_does_not_hide_different_file_contents(self):
        original = self.readback()
        self.image.write_bytes(self.image.read_bytes()[::-1])
        self.assertNotEqual(original, self.readback())

    def test_every_shared_native_field_must_match_the_opened_object(self):
        changes = {'st_dev': 34, 'st_ino': (1 << 90) + 30,
                   'st_mode': stat.S_IFREG | 0o466, 'st_nlink': 2,
                   'st_size': self.named['st_size'] + 1, 'st_mtime_ns': 901,
                   'st_birthtime_ns': 101, 'st_file_attributes': stat.FILE_ATTRIBUTE_READONLY}
        for field, value in changes.items():
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.readback(handled=dict(self.handled, **{field: value}))

    def test_every_original_field_is_read_back_on_both_authorities(self):
        changes = {'st_dev': 34, 'st_ino': (1 << 90) + 30,
                   'st_mode': stat.S_IFREG | 0o444, 'st_nlink': 2,
                   'st_size': self.named['st_size'] + 1, 'st_mtime_ns': 901,
                   'st_ctime_ns': 999, 'st_birthtime_ns': 101,
                   'st_file_attributes': stat.FILE_ATTRIBUTE_READONLY, 'st_reparse_tag': 1}
        for view, original in (('named_after', self.named), ('handled_after', self.handled)):
            for field, value in changes.items():
                with self.subTest(view=view, field=field), self.assertRaises(ValueError):
                    self.readback(**{view: dict(original, **{field: value})})

    def test_regular_looking_reparse_files_and_missing_native_fields_are_rejected(self):
        for view, original in (('named', self.named), ('handled', self.handled), ('both', None)):
            for changes in ({'st_file_attributes': stat.FILE_ATTRIBUTE_REPARSE_POINT},
                            {'st_reparse_tag': 0xA0000003}, {'st_birthtime_ns': None},
                            {'st_file_attributes': None}, {'st_reparse_tag': None}):
                with self.subTest(view=view, changes=changes), self.assertRaises(ValueError):
                    records = ({'named': dict(self.named, **changes), 'handled': dict(self.handled, **changes)}
                               if view == 'both' else {view: dict(original, **changes)})
                    self.readback(**records)

    def test_filename_annotation_cannot_hide_other_modes_or_posix_ctime_changes(self):
        for system, suffix, handled in (
                ('Windows', '.test', self.handled),
                ('Linux', '.exe', dict(self.handled, st_ctime_ns=self.named['st_ctime_ns'])),
                ('Linux', '.exe', dict(self.named, st_ctime_ns=101))):
            with self.subTest(system=system, suffix=suffix, handled=handled), self.assertRaises(ValueError):
                self.readback(system=system, suffix=suffix, handled=handled)
        # POSIX still requires the complete unmodified raw tuple in both views.
        self.assertEqual(self.readback(system='Linux', handled=self.named),
                         self.readback(system='Linux', handled=self.named))


class RetainedNodeBaselines(unittest.TestCase):
    def setUp(self):
        self.node = SelectedNodeCompiler.runner()
        if self.node.platform.system() not in ('Linux', 'Windows'):
            self.skipTest('Node baseline binaries execute on Linux and Windows')
        self.temporary = tempfile.TemporaryDirectory(prefix='node baseline ')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source, self.workspace = self.root/'source', self.root/'owned outputs'
        self.source.mkdir()
        self.workspace.mkdir()
        file(self.source/'go.mod', b'module example.test/node-baseline\n\ngo 1.26.0\n')
        self.test_source = file(self.source/'baseline_test.go', br'''package baseline
import ("fmt"; "os"; "testing")
func record(t *testing.T) {
    f, err := os.OpenFile(os.Getenv("ROUTERVPN_BASELINE_MARKER"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
    if err != nil { t.Fatal(err) }
    if _, err = fmt.Fprintf(f, "%s:%d\n", t.Name(), os.Getpid()); err != nil { t.Fatal(err) }
    if err = f.Close(); err != nil { t.Fatal(err) }
}
func TestFirst(t *testing.T) { record(t) }
func TestSecond(t *testing.T) { record(t) }
func TestRejected(t *testing.T) { record(t); t.Fatal("actual second selector failure") }
func TestChangesSource(t *testing.T) {
    record(t)
    f, err := os.OpenFile("baseline_test.go", os.O_APPEND|os.O_WRONLY, 0)
    if err != nil { t.Fatal(err) }
    if _, err = f.WriteString("\n// source changed by actual test execution\n"); err != nil { t.Fatal(err) }
    if err = f.Close(); err != nil { t.Fatal(err) }
}
''')
        go = shutil.which('go')
        self.assertIsNotNone(go, 'The retained baseline regression requires actual Go')
        env = dict(os.environ, GOTOOLCHAIN=N.TOOLCHAIN, GOWORK='off', GOFLAGS='', CGO_ENABLED='0')
        self.compiler, self.captured, _ = self.node.selected_compiler(go, self.source, env)
        self.marker = self.root/'invocations'
        self.captured['ROUTERVPN_BASELINE_MARKER'] = str(self.marker)
        self.build = [self.compiler, 'test', '-c', '-mod=readonly']
        self.records = {str(path.relative_to(self.source)): hashlib.sha256(path.read_bytes()).hexdigest()
                        for path in (self.source/'go.mod', self.test_source)}
        self.baselines = self.node.BaselineBinaries(self.source, self.workspace, self.build, self.captured, self.records)

    def execute(self, name, package='.'):
        return self.baselines.execute(name, package, '^'+name+'$', 10)

    def test_reuses_exact_image_but_executes_each_selector_in_a_separate_process(self):
        with patch.object(self.node, 'run', wraps=self.node.run) as actual:
            status, first = self.execute('TestFirst')
            self.assertEqual(status, 0, first)
            binary = self.baselines.binary('.')
            before = self.node.retained_binary(binary)
            status, second = self.execute('TestSecond')
            self.assertEqual(status, 0, second)
        self.assertIn('--- PASS: TestFirst (', first)
        self.assertNotIn('--- PASS: TestSecond (', first)
        self.assertIn('--- PASS: TestSecond (', second)
        self.assertNotIn('--- PASS: TestFirst (', second)
        records = [line.split(':') for line in self.marker.read_text().splitlines()]
        self.assertEqual([row[0] for row in records], ['TestFirst', 'TestSecond'])
        self.assertNotEqual(records[0][1], records[1][1])
        self.assertEqual(self.node.retained_binary(binary), before)
        builds = [call for call in actual.call_args_list if 'test' in call.args[0] and '-c' in call.args[0]]
        self.assertEqual(len(builds), 1, 'An identical baseline package was compiled again')
        invocations = [call for call in actual.call_args_list if str(call.args[0][0]) == str(binary)]
        self.assertEqual(len(invocations), 2)
        self.assertTrue(all(call.kwargs['timeout'] == 25 for call in invocations))

    def test_equal_bytes_replacement_is_rejected_before_the_next_selector(self):
        status, output = self.execute('TestFirst')
        self.assertEqual(status, 0, output)
        binary = self.baselines.binary('.')
        original = self.workspace/'original retained image'
        binary.rename(original)
        shutil.copy2(original, binary)
        self.assertEqual(hashlib.sha256(binary.read_bytes()).hexdigest(), hashlib.sha256(original.read_bytes()).hexdigest())
        with self.assertRaisesRegex(ValueError, 'original compiled image'):
            self.execute('TestSecond')
        self.assertEqual(len(self.marker.read_text().splitlines()), 1)

    def test_changed_binary_bytes_are_rejected_before_the_next_selector(self):
        status, output = self.execute('TestFirst')
        self.assertEqual(status, 0, output)
        binary = self.baselines.binary('.')
        with binary.open('ab') as stream:
            stream.write(b'changed actual compiled image')
        with self.assertRaisesRegex(ValueError, 'original compiled image'):
            self.execute('TestSecond')
        self.assertEqual(len(self.marker.read_text().splitlines()), 1)

    def test_changed_recorded_source_is_rejected_before_the_next_selector(self):
        status, output = self.execute('TestFirst')
        self.assertEqual(status, 0, output)
        self.test_source.write_bytes(self.test_source.read_bytes()+b'\n// changed source input\n')
        with self.assertRaisesRegex(ValueError, 'captured source input'):
            self.execute('TestSecond')
        self.assertEqual(len(self.marker.read_text().splitlines()), 1)

    def test_actual_execution_cannot_rewrite_source_then_keep_its_passing_result(self):
        with self.assertRaisesRegex(ValueError, 'captured source input'):
            self.execute('TestChangesSource')
        self.assertTrue(self.marker.read_text().startswith('TestChangesSource:'))
        self.assertIn(b'source changed by actual test execution', self.test_source.read_bytes())

    def test_changed_environment_or_build_arguments_cannot_reuse_a_baseline(self):
        status, output = self.execute('TestFirst')
        self.assertEqual(status, 0, output)
        original_environment = dict(self.captured)
        self.captured['ROUTERVPN_BASELINE_MARKER'] = str(self.root/'different owner')
        with self.assertRaisesRegex(ValueError, 'compiler arguments or environment'):
            self.execute('TestSecond')
        self.captured.clear()
        self.captured.update(original_environment)
        self.build.append('-tags=changed_build_inputs')
        with self.assertRaisesRegex(ValueError, 'compiler arguments or environment'):
            self.execute('TestSecond')
        self.assertFalse((self.root/'different owner').exists())
        self.assertEqual(len(self.marker.read_text().splitlines()), 1)

    def test_each_distinct_package_gets_its_own_compiled_image(self):
        other = file(self.source/'other/other_test.go', b'package other\nimport "testing"\nfunc TestOther(t *testing.T) {}\n')
        self.records['other/other_test.go'] = hashlib.sha256(other.read_bytes()).hexdigest()
        self.baselines = self.node.BaselineBinaries(self.source, self.workspace, self.build, self.captured, self.records)
        status, first = self.execute('TestFirst')
        self.assertEqual(status, 0, first)
        status, second = self.execute('TestOther', './other')
        self.assertEqual(status, 0, second)
        self.assertIn('--- PASS: TestOther (', second)
        self.assertNotEqual(self.baselines.binary('.'), self.baselines.binary('./other'))
        self.assertNotEqual(self.node.retained_binary(self.baselines.binary('.')),
                            self.node.retained_binary(self.baselines.binary('./other')))

    def test_prior_success_does_not_hide_an_actual_later_selector_failure(self):
        status, output = self.execute('TestFirst')
        self.assertEqual(status, 0, output)
        status, output = self.execute('TestRejected')
        self.assertNotEqual(status, 0)
        self.assertIn('--- FAIL: TestRejected (', output)
        self.assertIn('actual second selector failure', output)
        self.assertEqual([line.split(':')[0] for line in self.marker.read_text().splitlines()],
                         ['TestFirst', 'TestRejected'])


class LinuxStockDNSNativeGate(unittest.TestCase):
    @staticmethod
    def verdict_rows():
        package, parent = 'router-vpn/cmd/client', 'TestLegacyStandardDNSPinnedCore'
        rows = [{'Package': package, 'Action': 'start'}, {'Package': package, 'Test': parent, 'Action': 'run'}]
        for case in ('udp-uncached', 'udp-cached-negative-control', 'tcp-uncached', 'tcp-cached-negative-control'):
            rows += [{'Package': package, 'Test': parent+'/'+case, 'Action': action} for action in ('run', 'pass')]
        return rows + [{'Package': package, 'Test': parent, 'Action': 'pass'}, {'Package': package, 'Action': 'pass'}]

    def exercise(self, arch, reused, failure=None, output=None, verdict_failure=False, dnssec_failure=None):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary)/'bundle'
            bundle.mkdir()
            binary = bundle/N.binary_name('linux/'+arch)
            binary.write_bytes(b'exact completed core boundary')
            env = {'GOOS': 'linux', 'GOARCH': arch, 'CGO_ENABLED': '1'}
            calls = []
            def run(command, **kwargs):
                args = [str(item) for item in command]
                calls.append((args, kwargs))
                if args[:2] == ['go', 'test']:
                    if failure is not None:
                        raise failure
                    return '\n'.join(json.dumps(row) for row in self.verdict_rows()) if output is None else output
                return ''
            stdout = io.StringIO()
            with patch.object(N.platform, 'system', return_value='Linux'), \
                 patch.object(N.platform, 'machine', return_value='x86_64' if arch == 'amd64' else 'aarch64'), \
                 patch.object(N, 'environment', return_value=env), patch.object(N, 'digest', return_value='source'), \
                 patch.object(N, 'reuse', return_value={}), patch.object(N, 'run', side_effect=run), \
                 patch.object(N, 'verify_linux_standard_configs') as configs, \
                 patch.object(N.DNSSEC, 'test_native_bundle', side_effect=dnssec_failure) as dnssec:
                invoke = (lambda: N.build('linux/'+arch, bundle)) if reused else (lambda: N.verify_installed_linux_host(Path(temporary)/'core', bundle, 'linux/'+arch, env))
                with contextlib.redirect_stdout(stdout):
                    if failure is not None or verdict_failure or dnssec_failure is not None:
                        expected_failure = failure if failure is not None else dnssec_failure
                        with self.assertRaises(type(expected_failure) if expected_failure is not None else ValueError) as caught:
                            invoke()
                        if expected_failure is not None:
                            self.assertIs(caught.exception, expected_failure)
                    else:
                        invoke()
            if failure is not None or verdict_failure:
                configs.assert_not_called()
            else:
                configs.assert_called_once_with(bundle, env)
            if reused and failure is None and not verdict_failure:
                dnssec.assert_called_once_with(bundle.absolute(), 'linux/'+arch, env)
            else:
                dnssec.assert_not_called()
            if failure is not None or verdict_failure or dnssec_failure is not None:
                self.assertNotIn('Reused verified complete native runtime', stdout.getvalue())
            elif reused:
                self.assertIn('Reused verified complete native runtime linux/'+arch, stdout.getvalue())
            self.assertTrue(calls, 'completed or reused bundle omitted actual native DNS execution')
            args, options = calls[0]
            self.assertEqual(args, ['go', 'test', '-json', '-race', '-tags=routervpn_stock_dns_native', './cmd/client',
                                    '-run', '^TestLegacyStandardDNSPinnedCore$', '-count=1', '-timeout=60s'])
            self.assertEqual(options['cwd'], ROOT)
            self.assertEqual(options['timeout'], 300)
            self.assertEqual(options['env']['ROUTERVPN_STOCK_DNS_CORE'], str(binary.resolve()))
            self.assertEqual(options['env']['ROUTERVPN_STOCK_DNS_CORE_SHA256'], hashlib.sha256(binary.read_bytes()).hexdigest())
            self.assertEqual(len(calls), 1 if reused or failure or verdict_failure else 3)

    def test_completed_and_reused_matching_bundles_require_actual_pinned_dns_gate(self):
        for arch in ('amd64', 'arm64'):
            for reused in (False, True):
                with self.subTest(arch=arch, reused=reused):
                    self.exercise(arch, reused)

    def test_failed_or_timed_out_dns_gate_cannot_reach_host_acceptance_or_reuse_publication(self):
        for reused in (False, True):
            for error in (subprocess.CalledProcessError(1, 'native-dns'), subprocess.TimeoutExpired('native-dns', 300)):
                with self.subTest(reused=reused, failure=type(error).__name__):
                    self.exercise('amd64', reused, error)

    def test_failed_or_timed_out_dnssec_gate_cannot_publish_reused_bundle(self):
        for arch in ('amd64', 'arm64'):
            for error in (ValueError('native DNSSEC refused'), subprocess.CalledProcessError(1, 'native-dnssec'), subprocess.TimeoutExpired('native-dnssec', 130)):
                with self.subTest(arch=arch, failure=type(error).__name__):
                    self.exercise(arch, True, dnssec_failure=error)

    def test_zero_case_and_incomplete_success_cannot_publish_new_or_reused_bundle(self):
        rows = self.verdict_rows()
        for reused in (False, True):
            for output in ('', json.dumps({'Package': 'router-vpn/cmd/client', 'Action': 'pass'}),
                           '\n'.join(json.dumps(row) for row in rows if not row.get('Test', '').endswith('/tcp-cached-negative-control'))):
                with self.subTest(reused=reused, output=output[:30]):
                    self.exercise('amd64', reused, output=output, verdict_failure=True)

    def test_every_exact_parent_leaf_and_package_verdict_is_required_once(self):
        rows = self.verdict_rows()
        encode = lambda values: '\n'.join(json.dumps(row) for row in values)
        N.verify_linux_stock_dns_verdicts(encode(rows))
        for index in range(len(rows)):
            for changed in (rows[:index]+rows[index+1:], rows[:index]+[rows[index]]+rows[index:]):
                with self.subTest(index=index, length=len(changed)):
                    with self.assertRaises(ValueError):
                        N.verify_linux_stock_dns_verdicts(encode(changed))
        for action in ('skip', 'fail', 'build-fail', 'unknown'):
            for index in (1, 3, len(rows)-1):
                changed = [dict(row) for row in rows]; changed[index]['Action'] = action
                with self.subTest(action=action, index=index), self.assertRaises(ValueError):
                    N.verify_linux_stock_dns_verdicts(encode(changed))
        for index in (0, 2):
            changed = [dict(row) for row in rows]; changed[index]['Package'] = 'foreign'
            with self.assertRaises(ValueError): N.verify_linux_stock_dns_verdicts(encode(changed))
        changed = [dict(row) for row in rows]; changed[2]['Test'] += '-unexpected'
        with self.assertRaises(ValueError): N.verify_linux_stock_dns_verdicts(encode(changed))
        for changed in (rows[:2]+[rows[3],rows[2]]+rows[4:], rows[:2]+[rows[-2]]+rows[2:-2]+[rows[-1]],
                        rows[:-1]+[{'Package':'router-vpn/cmd/client','Action':'output','Output':'WARNING: DATA RACE'}]+rows[-1:]):
            with self.assertRaises(ValueError): N.verify_linux_stock_dns_verdicts(encode(changed))
        for output in ('not-json', '[]', '{"Action":"start","Action":"pass"}', encode(rows)+'\n{}'):
            with self.assertRaises(ValueError): N.verify_linux_stock_dns_verdicts(output)


class LinuxStandardConfigNativeGate(unittest.TestCase):
    def verdict(self):
        parent=N.STANDARD_CONFIG_TEST
        names=[parent]
        names += [parent+'/'+protocol for protocol in N.STANDARD_CONFIG_PROTOCOLS]
        names += [parent+'/'+protocol+'/'+policy for protocol in N.STANDARD_CONFIG_PROTOCOLS for policy in N.STANDARD_CONFIG_POLICIES]
        return '\n'.join('--- PASS: '+name+' (0.01s)' for name in names)

    def test_every_stock_selection_requires_exact_verdict(self):
        output=self.verdict()
        N.verify_linux_standard_config_verdicts(output)
        for line in output.splitlines():
            for changed in (output.replace(line,''),output+'\n'+line,output.replace(line,line.replace('PASS','SKIP')),output.replace(line,line.replace('StartupStockGraphs','MissingStockGraphs'))):
                with self.assertRaises(ValueError):N.verify_linux_standard_config_verdicts(changed)

    def test_actual_built_core_checks_all_exported_graphs_before_success(self):
        for failure in ('none','preparation','core'):
            calls=[]
            def run(command,**options):
                command=list(map(str,command));calls.append(command)
                if command[:2]==['go','test']:
                    if failure=='preparation':return 'ok no matching tests'
                    directory=Path(options['env']['ROUTERVPN_STANDARD_CONFIG_FIXTURES'])
                    for protocol in N.STANDARD_CONFIG_PROTOCOLS:
                        for policy in N.STANDARD_CONFIG_POLICIES:(directory/(protocol+'-'+policy+'.json')).write_text('{}')
                    return self.verdict()
                self.assertEqual(command[:3],['/actual-native-build/sing-box-routervpn','check','-c'])
                if failure=='core':raise subprocess.CalledProcessError(1,command)
                return ''
            with self.subTest(failure=failure),patch.object(N,'run',side_effect=run):
                if failure=='none':N.verify_linux_standard_configs(Path('/actual-native-build'),{'GOARCH':'amd64'})
                else:
                    with self.assertRaises(ValueError if failure=='preparation' else subprocess.CalledProcessError):N.verify_linux_standard_configs(Path('/actual-native-build'),{'GOARCH':'amd64'})
            self.assertEqual(len(calls),19 if failure=='none' else 1 if failure=='preparation' else 2)


if __name__ == '__main__':
    unittest.main()
