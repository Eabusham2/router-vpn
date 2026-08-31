
#!/usr/bin/env python3
from unified_control_center_contract import (
    ConnectionProfile, HopMetric, UnifiedControlCenterError, load_contract,
    map_role, total_live_rtt, validate_profile, validate_secure_path,
)

contract = load_contract()
assert contract["default_surface"] == "map"
assert contract["bottom_sheet_order"] == ["connection", "multihop", "settings", "mode", "dns"]
assert contract["defaults"]["mode"] == "smart-auto"
assert contract["defaults"]["selected_node_count"] == 1
assert contract["defaults"]["ipv6"] is True
assert contract["defaults"]["mtu_policy"] == "auto"
assert contract["defaults"]["auto_require_encrypted"] is False
assert contract["defaults"]["auto_require_obfuscation"] is False
assert contract["secure_transport"]["mandatory"] is True
assert contract["secure_transport"]["xor_allowed"] is False
assert contract["secure_transport"]["custom_crypto_allowed"] is False
assert contract["connection_controls"]["node_selection_never_auto_connects"] is True

validate_secure_path(["wireguard"])
validate_secure_path(["tor-bridge", "openvpn"])
validate_secure_path(["socks5", "amneziawg"])
for invalid in (["socks5"], ["http-connect"], ["tor-bridge"]):
    try:
        validate_secure_path(invalid)
    except UnifiedControlCenterError:
        pass
    else:
        raise AssertionError(f"plaintext/bridge-only final path was accepted: {invalid}")

profile = ConnectionProfile(profile_id="home", name="Home SMART", node_ids=["router-vpn"])
validate_profile(profile)
assert total_live_rtt([HopMetric("a", 4.2), HopMetric("b", 7.3)]) == 11.5
assert [map_role(i, 3) for i in range(3)] == ["entry", "middle", "exit"]
assert map_role(0, 1, custom=True) == "custom"
assert map_role(0, 2, bridge=True) == "bridge"
print("Unified control-center contract: PASS")
