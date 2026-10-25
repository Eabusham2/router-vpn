#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
from unittest import mock

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location("router_vpn_dns_policy", HERE / "dns-policy.py")
assert SPEC and SPEC.loader
DNS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DNS)


def base_config() -> dict:
    return {
        "log": {"level": "warn"},
        "outbounds": [
            {"type": "shadowsocks", "tag": "proxy", "server": "example.invalid", "server_port": 8388},
            {"type": "direct", "tag": "direct"},
        ],
        "route": {"rules": []},
    }


def policy() -> dict:
    return {
        "mode": "custom",
        "protocol": "https",
        "host": "1.1.1.1",
        "port": 443,
        "server_name": "cloudflare-dns.com",
        "path": "/dns-query",
        "fastest_name": "test",
        "fastest_latency_ms": 1.0,
    }


def write_config(path: Path, value) -> bytes:
    body = (json.dumps(value, indent=2) + "\n").encode()
    path.write_bytes(body)
    os.chmod(path, 0o600)
    return body


def test_atomic_patch() -> None:
    with tempfile.TemporaryDirectory(prefix="router-vpn-dns-runtime-") as td:
        root = Path(td)
        path = root / "sing-box.json"
        write_config(path, base_config())
        DNS.patch_sing(path, policy())
        value = json.loads(path.read_text())
        server = value["dns"]["servers"][0]
        assert server["tag"] == "selected-dns"
        assert server["detour"] == "proxy"
        assert server["type"] == "https"
        assert server["tls"]["server_name"] == "cloudflare-dns.com"
        assert value["route"]["rules"][0] == {"protocol": "dns", "action": "hijack-dns"}
        if os.name != "nt":
            assert path.stat().st_mode & 0o777 == 0o600
        assert not list(root.glob(".sing-box.json.dns-*"))


def test_replace_failure_preserves_original() -> None:
    with tempfile.TemporaryDirectory(prefix="router-vpn-dns-runtime-fail-") as td:
        root = Path(td)
        path = root / "sing-box.json"
        original = write_config(path, base_config())
        with mock.patch.object(DNS.os, "replace", side_effect=OSError("injected adoption failure")):
            try:
                DNS.patch_sing(path, policy())
            except OSError:
                pass
            else:
                raise AssertionError("injected DNS adoption failure did not fail")
        assert path.read_bytes() == original, "failed DNS adoption changed the authoritative runtime config"
        assert not list(root.glob(".sing-box.json.dns-*")), "failed DNS adoption leaked a temp file"


def test_foreign_regular_replacement_rejected() -> None:
    with tempfile.TemporaryDirectory(prefix="router-vpn-dns-runtime-swap-") as td:
        root = Path(td)
        path = root / "sing-box.json"
        write_config(path, base_config())
        foreign = root / "foreign.json"
        foreign_body = write_config(foreign, {"foreign": True})
        real_mkstemp = DNS.tempfile.mkstemp

        def mkstemp_then_swap(*args, **kwargs):
            fd, name = real_mkstemp(*args, **kwargs)
            os.replace(foreign, path)
            return fd, name

        with mock.patch.object(DNS.tempfile, "mkstemp", side_effect=mkstemp_then_swap):
            try:
                DNS.patch_sing(path, policy())
            except RuntimeError as exc:
                assert "target identity changed before adoption" in str(exc)
            else:
                raise AssertionError("DNS runtime patch overwrote a foreign regular replacement")
        assert path.read_bytes() == foreign_body
        assert not list(root.glob(".sing-box.json.dns-*"))


def test_symlink_target_rejected() -> None:
    if os.name == "nt":
        return
    with tempfile.TemporaryDirectory(prefix="router-vpn-dns-runtime-link-") as td:
        root = Path(td)
        real = root / "real.json"
        link = root / "sing-box.json"
        original = write_config(real, base_config())
        link.symlink_to(real)
        try:
            DNS.patch_sing(link, policy())
        except RuntimeError as exc:
            assert "symlink" in str(exc)
        else:
            raise AssertionError("DNS runtime patch followed a symlink target")
        assert real.read_bytes() == original


def test_invalid_and_oversized_rejected() -> None:
    with tempfile.TemporaryDirectory(prefix="router-vpn-dns-runtime-invalid-") as td:
        root = Path(td)
        non_object = root / "array.json"
        write_config(non_object, [])
        try:
            DNS.patch_sing(non_object, policy())
        except RuntimeError as exc:
            assert "JSON object" in str(exc)
        else:
            raise AssertionError("DNS runtime accepted a non-object config")

        oversized = root / "large.json"
        oversized.write_bytes(b"{" + b" " * 128 + b"}")
        os.chmod(oversized, 0o600)
        old = DNS.MAX_RUNTIME_CONFIG_BYTES
        DNS.MAX_RUNTIME_CONFIG_BYTES = 64
        try:
            try:
                DNS.patch_sing(oversized, policy())
            except RuntimeError as exc:
                assert "safety limit" in str(exc)
            else:
                raise AssertionError("DNS runtime accepted an oversized config")
        finally:
            DNS.MAX_RUNTIME_CONFIG_BYTES = old


def home_profile(**overrides) -> dict:
    return {
        "id": "captured", "adguard_ipv4": "10.91.0.53", "adguard_ipv6": "fd91::53",
        "dns_mode": "home", "dns_protocol": "https", "dns_host": "10.91.0.53",
        "dns_port": 8443, "dns_server_name": "DNS.Home.Example", "dns_path": "/owned-query",
        "ipv6_mode": "on", "fastest_dns_host": "1.1.1.1", **overrides,
    }


def captured_environment(root: Path, profile: dict) -> dict:
    write_config(root / "routers.json", {
        "selected_id": "other",
        "profiles": [profile, home_profile(id="other", adguard_ipv4="10.92.0.53", adguard_ipv6="fd92::53",
                                           dns_host="10.92.0.53")],
    })
    return {
        **os.environ, "HOMEVPN_ROOT": str(root), "HOMEVPN_PROFILE_ID": "captured",
        "HOMEVPN_DNS_MODE": "rescue", "HOMEVPN_DNS_PROTOCOL": "udp", "HOMEVPN_DNS_HOST": "8.8.8.8",
        "HOMEVPN_DNS_PORT": "53", "HOMEVPN_DNS_SERVER_NAME": "foreign.invalid", "HOMEVPN_DNS_PATH": "/foreign",
        "HOMEVPN_ADGUARD4": "10.92.0.53", "HOMEVPN_ADGUARD6": "fd92::53",
    }


def run_policy(env: dict, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(HERE / "dns-policy.py"), *args], env=env,
                          text=True, capture_output=True, timeout=10)


def expected_server(protocol: str, host: str, port: int) -> dict:
    result = {"type": protocol, "tag": "selected-dns", "server": host, "server_port": port, "detour": "proxy"}
    if protocol in ("tls", "https", "h3"):
        result["tls"] = {"enabled": True, "server_name": "DNS.Home.Example"}
    if protocol in ("https", "h3"):
        result["path"] = "/owned-query"
    return result


def test_captured_home_cli_and_runtime_output() -> None:
    # Exercise the actual private-store reader and launcher-facing CLI. Inherited
    # public settings and a newly selected other node cannot change this capture.
    with tempfile.TemporaryDirectory(prefix="router-vpn-home-dns-") as td:
        root = Path(td)
        path = root / "sing-box.json"
        for host in ("10.91.0.53", "fd91::53"):
            for raw_protocol, protocol in (("udp", "udp"), ("tcp", "tcp"), ("tls", "tls"),
                                           ("https", "https"), ("h3", "h3"), ("dot", "tls"),
                                           ("doh", "https"), ("doh3", "h3")):
                port = 5353 if protocol in ("udp", "tcp") else 8853 if protocol == "tls" else 8443
                env = captured_environment(root, home_profile(dns_protocol=raw_protocol, dns_host=host, dns_port=port))
                read = run_policy(env, "json")
                assert read.returncode == 0, read.stderr
                actual = json.loads(read.stdout)
                expected = {"mode": "home", "protocol": protocol, "host": host, "port": port,
                            "server_name": "DNS.Home.Example" if protocol in ("tls", "https", "h3") else "",
                            "path": "/owned-query" if protocol in ("https", "h3") else ""}
                assert {key: actual[key] for key in expected} == expected, actual
                exported = run_policy(env, "env")
                assert exported.returncode == 0, exported.stderr
                fields = dict(item.split("=", 1) for item in shlex.split(exported.stdout))
                assert fields == {"HOMEVPN_DNS_" + key.upper(): str(value) for key, value in expected.items()}
                write_config(path, base_config())
                adopted = run_policy(env, "patch-sing", str(path))
                assert adopted.returncode == 0, adopted.stderr
                value = json.loads(path.read_text())
                assert value["dns"] == {"servers": [expected_server(protocol, host, port)], "final": "selected-dns"}
                assert value["route"]["rules"][0] == {"protocol": "dns", "action": "hijack-dns"}
                assert value["outbounds"] == base_config()["outbounds"]
                assert path.stat().st_mode & 0o777 == 0o600

        for protocol, default_port in (("", 53), ("udp", 53), ("tcp", 53), ("tls", 853), ("https", 443), ("h3", 443)):
            profile = home_profile(dns_mode="", dns_protocol=protocol, dns_host="", dns_port=0, dns_path="")
            env = captured_environment(root, profile)
            result = run_policy(env, "json")
            assert result.returncode == 0, result.stderr
            value = json.loads(result.stdout)
            assert value["mode"] == "home" and value["host"] == "10.91.0.53" and value["port"] == default_port
            assert value["protocol"] == (protocol or "udp")
            if protocol in ("https", "h3"):
                assert value["path"] == "/dns-query"
        profile = home_profile()
        del profile["dns_mode"]
        assert json.loads(run_policy(captured_environment(root, profile), "json").stdout)["mode"] == "home"
        env = captured_environment(root, home_profile(adguard_ipv4="", dns_host=""))
        assert json.loads(run_policy(env, "json").stdout)["host"] == "fd91::53"


def test_home_rejects_foreign_missing_or_unsafe_policy() -> None:
    invalid = [
        {"adguard_ipv4": "", "adguard_ipv6": ""},
        {"dns_host": "10.92.0.53"}, {"dns_host": "fd92::53"}, {"dns_host": "8.8.8.8"},
        {"dns_host": "fd91::53", "ipv6_mode": "off"},
        {"dns_protocol": "rescue"}, {"dns_protocol": "quic"}, {"dns_protocol": 1},
        {"dns_mode": ["home"]},
        {"node_kind": "external"}, {"node_kind": "unknown"}, {"external": {"protocol": "socks5"}},
    ]
    for address in ("8.8.8.8", "127.0.0.1", "169.254.2.53", "192.0.2.53", "224.0.0.53", "fd91::53",
                    "10.091.0.53", " 10.91.0.53", "10.91.0.53\n"):
        invalid.append({"adguard_ipv4": address})
    for address in ("::1", "fe80::53", "2001:db8::53", "ff02::53", "::ffff:10.91.0.53", "fd91::53%eth0",
                    "FD91::53", "fd91:0:0:0:0:0:0:53", "10.91.0.53"):
        invalid.append({"adguard_ipv6": address})
    for port in (-1, 65536, True, "8443", 53.0):
        invalid.append({"dns_port": port})
    for name in ("", "10.91.0.53", "fd91::53", "localhost", "https://home.example", "home example.invalid",
                 "*.home.example", "home.example\n", "-home.example", "home..example"):
        invalid.append({"dns_server_name": name})
    for path in ("//foreign.invalid/query", "https://foreign.invalid/query", "/query?other=1", "/query#fragment",
                 "/query\\escape", "/query\n", "/query internal", "/query\x7f", "/bad%Q0", "/bad%", "/" + "x" * 2048):
        invalid.append({"dns_path": path})
    with tempfile.TemporaryDirectory(prefix="router-vpn-home-dns-invalid-") as td:
        root = Path(td)
        path = root / "sing-box.json"
        for fields in invalid:
            original = write_config(path, base_config())
            env = captured_environment(root, home_profile(**fields))
            result = run_policy(env, "patch-sing", str(path))
            assert result.returncode != 0, f"unsafe Home selection accepted: {fields}"
            assert path.read_bytes() == original, f"invalid Home policy changed runtime: {fields}"
            assert not list(root.glob(".sing-box.json.dns-*"))
        # No captured node means no adoption of the unrelated current selection.
        env = captured_environment(root, home_profile(id="removed"))
        assert run_policy(env, "json").returncode != 0


def test_home_requires_unique_tunnel_detour() -> None:
    with tempfile.TemporaryDirectory(prefix="router-vpn-home-dns-detour-") as td:
        root = Path(td)
        path = root / "sing-box.json"
        env = captured_environment(root, home_profile())
        proxy = base_config()["outbounds"][0]
        invalid = [[], [{"tag": "direct", "type": "direct"}], [proxy, dict(proxy)],
                   [{"tag": "proxy"}], [{"tag": "proxy", "type": ""}], [{"tag": "proxy", "type": " "}], [{"tag": "proxy", "type": 1}]]
        invalid += [[{"tag": "proxy", "type": kind}] for kind in ("direct", "block", "dns")]
        for outbounds in invalid:
            cfg = {**base_config(), "outbounds": outbounds}
            original = write_config(path, cfg)
            result = run_policy(env, "patch-sing", str(path))
            assert result.returncode != 0, f"Home DNS accepted unowned detour: {outbounds}"
            assert path.read_bytes() == original, "rejected Home detour changed the runtime configuration"
            assert not list(root.glob(".sing-box.json.dns-*"))
        for tag in ("proxy", "tcp-stack", "ss-hop", "outer"):
            write_config(path, {**base_config(), "outbounds": [{**proxy, "tag": tag}]})
            result = run_policy(env, "patch-sing", str(path))
            assert result.returncode == 0, result.stderr
            assert json.loads(path.read_text())["dns"]["servers"][0]["detour"] == tag
        # Keep the existing explicit non-Home path semantics outside this repair.
        write_config(path, {**base_config(), "outbounds": [{"tag": "direct", "type": "direct"}]})
        result = run_policy(captured_environment(root, home_profile(dns_mode="custom")), "patch-sing", str(path))
        assert result.returncode == 0, result.stderr
        assert json.loads(path.read_text())["dns"]["servers"][0]["detour"] == "direct"


def test_launcher_dns_capture_fails_closed() -> None:
    with tempfile.TemporaryDirectory(prefix="router-vpn-home-dns-launcher-") as td:
        root = Path(td)
        (root / "run").mkdir()
        for filename in ("run-mode.sh", "run-max.sh", "run-pq.sh"):
            source = (HERE / filename).read_text()
            assert "set -euo pipefail" in source
            if filename != "run-pq.sh":
                # The same id used to stage the runtime must reach the DNS reader,
                # including the legacy explicit 'router' default when env is unset.
                capture = source[source.index('. "$SCRIPT_DIR/profile-id.sh"'):source.index('\n', source.index('export HOMEVPN_PROFILE_ID='))]
                env = captured_environment(root, home_profile(id="router"))
                env.pop("HOMEVPN_PROFILE_ID")
                command = "set -euo pipefail\nSCRIPT_DIR=" + shlex.quote(str(HERE)) + "\n" + capture + \
                          '\npython3 "$SCRIPT_DIR/dns-policy.py" json\n'
                result = subprocess.run(["bash", "-c", command], env=env, text=True, capture_output=True, timeout=10)
                assert result.returncode == 0 and json.loads(result.stdout)["host"] == "10.91.0.53", result.stderr
            begin = source.index('DNS_POLICY_ENV=$(python3 "$SCRIPT_DIR/dns-policy.py" env)')
            end = source.index("\n", source.index("export HOMEVPN_DNS_MODE", begin))
            block = source[begin:end]
            hint_match = re.search(r'python3 "\$SCRIPT_DIR/runtime-config\.py" dns-hint [^\n]+', source)
            assert hint_match, f"{filename} does not record its selected DNS policy"
            hint_command = hint_match.group(0).split(";")[0]
            prefix = "set -euo pipefail\nSCRIPT_DIR=" + shlex.quote(str(HERE)) + \
                     "\nROOT=" + shlex.quote(str(root)) + '\nRUN="$ROOT/run"\n'
            suffix = "\nprintf 'LAUNCH_REACHED\\n'\n" + shlex.quote(sys.executable) + \
                     " -c 'import json,os;print(json.dumps({k:v for k,v in os.environ.items() if k.startswith(\"HOMEVPN_DNS_\")}))'\n"
            good = captured_environment(root, home_profile())
            result = subprocess.run(["bash", "-c", prefix + block + "\n" + hint_command + suffix], env=good,
                                    text=True, capture_output=True, timeout=10)
            assert result.returncode == 0 and result.stdout.startswith("LAUNCH_REACHED\n"), result.stderr
            actual = json.loads(result.stdout.splitlines()[1])
            assert actual == {"HOMEVPN_DNS_MODE": "home", "HOMEVPN_DNS_PROTOCOL": "https", "HOMEVPN_DNS_HOST": "10.91.0.53",
                              "HOMEVPN_DNS_PORT": "8443", "HOMEVPN_DNS_SERVER_NAME": "DNS.Home.Example", "HOMEVPN_DNS_PATH": "/owned-query"}
            expected_hint = "mode=home\nprotocol=https\nserver=10.91.0.53:8443\nserver_name=DNS.Home.Example\npath=/owned-query\n"
            assert (root / "run/dns.txt").read_text() == expected_hint, f"{filename} omitted encrypted DNS proof fields"
            incomplete_hint = hint_command.replace(' "$HOMEVPN_DNS_SERVER_NAME" "$HOMEVPN_DNS_PATH"', "")
            assert incomplete_hint != hint_command
            result = subprocess.run(["bash", "-c", prefix + block + "\n" + incomplete_hint], env=good,
                                    text=True, capture_output=True, timeout=10)
            assert result.returncode == 0 and (root / "run/dns.txt").read_text() != expected_hint, \
                f"{filename} omitted-proof defect control did not change the receipt"
            bad = captured_environment(root, home_profile(adguard_ipv4="", adguard_ipv6=""))
            result = subprocess.run(["bash", "-c", prefix + block + suffix], env=bad, text=True, capture_output=True, timeout=10)
            assert result.returncode != 0 and "LAUNCH_REACHED" not in result.stdout, f"{filename} retained inherited DNS after capture failed"
            # Prove this fixture detects the former eval-masks-Python-failure bug.
            unsafe = block.replace('DNS_POLICY_ENV=$(python3 "$SCRIPT_DIR/dns-policy.py" env)\neval "$DNS_POLICY_ENV"\nunset DNS_POLICY_ENV',
                                   'eval "$(python3 "$SCRIPT_DIR/dns-policy.py" env)"')
            assert unsafe != block
            result = subprocess.run(["bash", "-c", prefix + unsafe + suffix], env=bad, text=True, capture_output=True, timeout=10)
            assert result.returncode == 0 and "LAUNCH_REACHED" in result.stdout, f"{filename} defect control did not expose unsafe continuation"


def main() -> int:
    test_atomic_patch()
    test_replace_failure_preserves_original()
    test_foreign_regular_replacement_rejected()
    test_symlink_target_rejected()
    test_invalid_and_oversized_rejected()
    test_captured_home_cli_and_runtime_output()
    test_home_rejects_foreign_missing_or_unsafe_policy()
    test_home_requires_unique_tunnel_detour()
    test_launcher_dns_capture_fails_closed()
    print("DNS runtime atomic adoption, captured Home transports and six launcher defect controls: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
