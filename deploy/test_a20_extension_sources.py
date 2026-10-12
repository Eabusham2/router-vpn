#!/usr/bin/env python3
"""Execute the shipping A20 extension-source validator against drift cases."""
import ast
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
module = ast.parse((ROOT/'deploy/latest-a20-product-contract-audit.py').read_text())
functions = [node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == 'packet_tunnel_sources']
if len(functions) != 1:
    raise RuntimeError('Expected exactly one shipping extension-source validator')
namespace = {'re': re}
exec(compile(ast.Module(body=functions, type_ignores=[]), '<shipping A20 source validator>', 'exec'), namespace)
validate = namespace['packet_tunnel_sources']

FIXTURE = '''targets:
  RouterVPN:
    sources: [App]
  RouterVPNPacketTunnel:
    type: app-extension
    sources: [PacketTunnel, App/IOSMultihopStartLayer.swift, App/IOSNativePQProfile.swift]
    settings:
      base:
        SWIFT_OBJC_BRIDGING_HEADER: PacketTunnel/RVPNTunnelTCPConnection.h
  AnotherTarget:
    sources: [Other]
'''

class ExtensionSources(unittest.TestCase):
    def test_actual_shipping_project(self):
        self.assertTrue(validate((ROOT/'ios/RouterVPN/project.yml').read_text()))

    def test_complete_target_and_additive_source_changes(self):
        self.assertTrue(validate(FIXTURE))
        reordered = FIXTURE.replace('PacketTunnel, App/IOSMultihopStartLayer.swift, App/IOSNativePQProfile.swift',
                                    ' App/IOSNativePQProfile.swift , PacketTunnel, App/NewOwnedFeature.swift, App/IOSMultihopStartLayer.swift ')
        self.assertTrue(validate(reordered))

    def test_each_required_source_is_independently_required(self):
        for name in ('PacketTunnel', 'App/IOSMultihopStartLayer.swift', 'App/IOSNativePQProfile.swift'):
            with self.subTest(source=name):
                changed = FIXTURE.replace(name, 'NotTheRequiredSource')
                self.assertFalse(validate(changed))

    def test_names_in_another_target_do_not_count(self):
        self.assertFalse(validate(FIXTURE.replace('  RouterVPNPacketTunnel:', '  DifferentTarget:')))
        moved = FIXTURE.replace('    sources: [PacketTunnel, App/IOSMultihopStartLayer.swift, App/IOSNativePQProfile.swift]', '    sources: [PacketTunnel]')
        moved += '    sources: [App/IOSMultihopStartLayer.swift, App/IOSNativePQProfile.swift]\n'
        self.assertFalse(validate(moved))

    def test_commented_and_missing_bridge_are_rejected(self):
        bridge = '        SWIFT_OBJC_BRIDGING_HEADER: PacketTunnel/RVPNTunnelTCPConnection.h'
        for substitute in ('        # SWIFT_OBJC_BRIDGING_HEADER: PacketTunnel/RVPNTunnelTCPConnection.h', '', bridge.replace('RVPNTunnelTCPConnection.h', 'Other.h')):
            with self.subTest(substitute=substitute):
                self.assertFalse(validate(FIXTURE.replace(bridge, substitute)))

    def test_duplicate_targets_and_lists_are_rejected(self):
        self.assertFalse(validate(FIXTURE+FIXTURE))
        line = '    sources: [PacketTunnel, App/IOSMultihopStartLayer.swift, App/IOSNativePQProfile.swift]'
        self.assertFalse(validate(FIXTURE.replace(line, line+'\n'+line)))
        self.assertFalse(validate(FIXTURE.replace('sources: [PacketTunnel,', 'sources: [PacketTunnel, PacketTunnel,')))

    def test_comments_and_malformed_inline_lists_do_not_fake_sources(self):
        self.assertFalse(validate(FIXTURE.replace('    sources:', '    # sources:')))
        self.assertFalse(validate(FIXTURE.replace('App/IOSNativePQProfile.swift]', 'App/IOSNativePQProfile.swift,]')))
        self.assertFalse(validate(FIXTURE.replace('App/IOSNativePQProfile.swift]', 'App/IOSNativePQProfile.swift #]')))

if __name__ == '__main__':
    unittest.main()
