#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SOURCE = (ROOT / "App" / "IOSConnectionProfilesView.swift").read_text(encoding="utf-8")
assert SOURCE.strip(), "iOS connection profile source is empty"

for marker in (
    'iosConnectionProfilesSchemaVersion = 4',
    'Unsupported connection profile store schema',
    'known schema v1, validate it fully, then atomically rewrite v4',
    'decodeIfPresent(Bool.self, forKey: .homeLANAccess) ?? true',
    'decodeIfPresent(String.self, forKey: .killSwitchPolicy) ?? (killSwitch ? "always" : "off")',
    'decodeIfPresent(String.self, forKey: .ipv6Mode) ?? "on"',
    'decodeIfPresent(String.self, forKey: .baseTunnel) ?? "auto"',
    'decodeIfPresent(String.self, forKey: .mtuPolicy) ?? "auto"',
    'decodeIfPresent(String.self, forKey: .startupMode) ?? "smart-auto"',
    'decodeIfPresent(String.self, forKey: .dnsMode) ?? "home"',
    'record.mode = try normalizeMode(value.mode)',
    'record.customLayers = try normalizeLayers(value.customLayers)',
    'record.preferences = try validatePreferences(preferences)',
    'Router connection profile cannot use external mode',
    'External connection profile contains Router-only saved policy',
    'Connection profile contains an invalid kill-switch policy',
    'Connection profile contains an invalid IPv6 policy',
    'Connection profile contains an invalid WG/AWG base',
    'Connection profile contains an invalid MTU policy',
    'Connection profile manual MTU must be 576–9000',
    'Connection profile contains an invalid startup policy',
    'Connection profile contains an invalid DNS mode',
    'Custom DNS in a connection profile must use UDP or TCP',
    'Encrypted DNS to a literal IP requires a TLS server name',
    'IPv4Address(p.dnsHost) != nil || IPv6Address(p.dnsHost) != nil',
    'guard allowed else { throw issue("Connection profile contains an invalid saved mode.") }',
    'guard !clean.contains(":") else { throw issue("Connection profile contains an invalid saved mode reference.") }',
    'let mode = try normalizeMode(UserDefaults.standard.string(forKey: iosConnectionModeKey) ?? "smart-auto")',
    'let effectiveMode = try normalizeMode(saved.mode)',
    'Current iOS cannot execute full desktop multihop',
    'guard !model.profileMutationBlocked else',
):
    assert marker in SOURCE, f"iOS connection profile migration contract missing {marker!r}"

assert 'return allowed ? clean : "smart-auto"' not in SOURCE, "corrupt saved mode is still silently coerced to SMART AUTO"

load_all = SOURCE.split('private static func loadAll()', 1)[1].split('static func snapshot', 1)[0]
assert load_all.find('validateStoredProfiles') >= 0
assert load_all.find('validateStoredProfiles') < load_all.find('persist(values)'), "legacy store is persisted before semantic validation"

validate = SOURCE.split('private static func validateStoredProfiles', 1)[1].split('private static func validatePreferences', 1)[0]
assert validate.find('try normalizeMode') < validate.find('validated.append(record)')
assert validate.find('try validatePreferences') < validate.find('validated.append(record)')

print("iOS connection profile migration contract: PASS")
