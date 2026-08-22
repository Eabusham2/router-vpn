#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
req = (ROOT / "client/linux/routervpn-auto-requirements-v11.inc").read_text(encoding="utf-8")
wrapper = (ROOT / "client/linux/build-native-app-current.sh").read_text(encoding="utf-8")
package = (ROOT / "deploy/package-linux-native.sh").read_text(encoding="utf-8")
backend = (ROOT / "cmd/client/profile_settings.go").read_text(encoding="utf-8")

for marker in (
    '/api/profile/settings', 'auto_require_encrypted', 'auto_require_obfuscation',
    'Require encrypted AUTO candidates', 'Require obfuscation for AUTO candidates',
    'Save requirements', 'Disconnect before saving', 'refresh_home_summary_v6(app)',
):
    assert marker in req, f"Linux AUTO requirement UI missing {marker!r}"
for marker in (
    'routervpn-auto-requirements-v11.inc', 'AUTO / SMART requirements',
    'G_CALLBACK(on_linux_auto_requirements_v11)', 'router-vpn-auto-requirements-v11',
    'has_node && !connected',
):
    assert marker in wrapper, f"Linux current shipping wrapper missing {marker!r}"
assert 'build-native-app-current.sh' in package, "Linux package path bypasses current shipping wrapper"
for marker in ('AutoRequireEncrypted', 'AutoRequireObfuscation', 'profileSettingsBusy', 'NormalizeRouterProfile'):
    assert marker in backend, f"Linux AUTO requirement UI lacks backend policy marker {marker!r}"
for forbidden in ('api_token', 'private_key', 'preshared_key', 'socks_password'):
    assert forbidden not in req, f"Linux AUTO requirement UI must not copy node secret field {forbidden!r}"
print("Linux shipping AUTO / SMART requirements contract: PASS")
