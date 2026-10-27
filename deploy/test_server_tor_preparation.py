#!/usr/bin/env python3
"""Check the exact server Tor source closure and no embedded/mobile lifecycle."""
from pathlib import Path
import importlib.util
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('server_tor_preparation',ROOT/'deploy/prepare-server-tor.py')
PREP=importlib.util.module_from_spec(spec)
spec.loader.exec_module(PREP)


class ServerTorPreparation(unittest.TestCase):
    def test_all_copied_pure_and_pt_sources_enter_digest(self):
        inputs=set(PREP.inputs())
        for package in ('common','mobiletor','awgpolicy','nativeopenvpn'):
            for path in (ROOT/'internal'/package).glob('*.go'):
                if not path.name.endswith('_test.go'):
                    self.assertIn(path,inputs)
        for path in (ROOT/'mobile/torpt').rglob('*'):
            if path.is_file():self.assertIn(path,inputs)
        for path in (ROOT/'mobile/server_tor').glob('*.tmpl'):self.assertIn(path,inputs)

    def test_preparation_installs_actual_command_and_no_embedded_tor(self):
        content=PREP.copies()
        self.assertIn('cmd/sing-box/routervpn_server_tor_command.go',content)
        self.assertIn('cmd/sing-box/routervpn_server_tor_native.go',content)
        self.assertIn('routervpn/servertor/network_owner.go',content)
        self.assertIn('routervpn_server_tor_box.go',content)
        self.assertIn('routervpn-server-tor-pt-notices.json',content)
        self.assertFalse(any(name.startswith(('protocol/routervpntor/','routervpn/torpack/','routervpn/desktoppt/')) for name in content))
        for name,raw in content.items():
            if name.endswith('.go'):
                self.assertNotIn(b'"router-vpn/internal/',raw,name)
                self.assertNotIn(b'"router-vpn/mobile/',raw,name)
        self.assertIn('SERVER_TOR.prepare(vendor)',(ROOT/'deploy/prepare-relay-core.py').read_text())

    def test_no_tun_worker_retains_exact_control_front_and_proof(self):
        native=(ROOT/'mobile/server_tor/native.go.tmpl').read_text()
        for gate in ('len(options.Inbounds) != 0','policy.NativeConfig(','.Configure(initialize,',
                     'RouterVPNServerTorDNSProof(ctx)','mobiletor.Prove(ctx,',
                     'mobiletor.StartServerTorFront(','.Bootstrap(ctx)',
                     'n.proofGeneration++','n.expire(generation)',
                     'n.child.Close(ctx)','n.network.Close(ctx)','n.proofNetwork.Close(ctx)'):
            self.assertIn(gate,native)


if __name__=='__main__':unittest.main()
