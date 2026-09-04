#!/usr/bin/env python3
"""Keep all desktop standard-exit credentials inside validated private sessions."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def source(rel: str) -> str:
    path = ROOT / rel
    if not path.is_file():
        errors.append(f"missing standard-exit runtime source: {rel}")
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def require(rel: str, *markers: str) -> None:
    body = source(rel)
    for marker in markers:
        if marker not in body:
            errors.append(f"{rel}: missing private-runtime marker {marker!r}")


def forbid(rel: str, *markers: str) -> None:
    body = source(rel)
    for marker in markers:
        if marker in body:
            errors.append(f"{rel}: forbidden ad-hoc private-runtime marker {marker!r}")


require(
    "cmd/client/standard_exits.go",
    'Protocol: "http-connect", Implemented: true, Supported: true',
    'Protocol: "https-connect", Implemented: true, Supported: true',
    'case "http-connect", "https-connect":',
    'out["type"] = "http"',
    'out["tls"] = map[string]any{"enabled": true, "server_name": e.TLSServerName}',
    "plain HTTP CONNECT cannot specify a TLS server name",
    "HTTPS CONNECT requires a valid TLS server name for SNI and certificate verification",
)
require(
    "cmd/client/standard_exit_runtime.go",
    'newPrivateRuntimeDir(root, "native-standard-exit")',
    'writePrivateRuntimeFile(filepath.Join(runtimeDir, "sing-box.json")',
    'case "http-connect", "https-connect":',
    'out["type"] = "http"',
    'out["tls"] = map[string]any{"enabled": true, "server_name": e.TLSServerName}',
)
forbid(
    "cmd/client/standard_exit_runtime.go",
    'os.MkdirAll(base, 0o700)',
    'os.WriteFile(filepath.Join(runtimeDir, "sing-box.json")',
    'rand.Read(random)',
)
require(
    "cmd/client/external_profile_standard_exit.go",
    'case "http-connect":',
    'case "https-connect":',
    "h.Host, h.Port, h.Username, h.Password",
    "h.TLSServerName",
)
require(
    "cmd/client/external_profile_connect.go",
    '[]string{"wireguard", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2"}',
)
require(
    "cmd/client/standard_exit_platform_routes.go",
    '[]string{"wireguard", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2"}',
)
require(
    "cmd/client/standard_exits_test.go",
    "TestHTTPConnectStandardExitValidation",
    '"http-connect", "https-connect"',
    "HTTPS CONNECT lost TLS",
)
require(
    "cmd/client/standard_exit_runtime_test.go",
    '"http-connect","https-connect"',
    "HTTPS CONNECT direct path lost TLS",
    "HTTPS CONNECT TLS/SNI wrong",
)
require(
    "cmd/client/external_profile_standard_exit_test.go",
    "ext-http",
    "ext-https",
    "HTTP CONNECT adapter wrong",
    "HTTPS CONNECT adapter wrong",
)
require(
    "cmd/client/external_entry_chain_test.go",
    '"http-connect", "https-connect"',
    "HTTPS entry lost TLS/SNI",
)

require(
    "cmd/client/openvpn_entry_bridge.go",
    'newPrivateRuntimeDir(root, "openvpn-standard-exit")',
    "writePrivateRuntimeFile",
)
require(
    "cmd/client/openvpn_standard_exit_runtime.go",
    "func writePrivateFile(path, text string) error",
    "return writePrivateRuntimeFile(path, []byte(text))",
    "newOpenVPNRuntimeDir(root)",
)
forbid(
    "cmd/client/openvpn_standard_exit_runtime.go",
    "os.WriteFile(path, []byte(text), 0o600)",
    "return os.Chmod(path, 0o600)",
)
require(
    "cmd/client/windows_openvpn_external.go",
    "newOpenVPNRuntimeDir(root)",
    "writePrivateFile(auth",
    "writePrivateFile(configPath",
)
require(
    "cmd/client/external_entry_chain.go",
    "return writeStandardExitRuntime(root, cfg)",
)
require(
    "cmd/client/standard_exit_private_runtime_test.go",
    "TestStandardExitRuntimeUsesPrivateSessionDirectory",
    "TestStandardExitRuntimeRejectsPoisonedPrivateCategory",
    "TestOpenVPNPrivateFileUsesPrivateRuntimeWriter",
)

require(
    "modes/native-standard-exit-linux.sh",
    'cleanup-private-runtime.py" verify-dir',
    'verified-mode "$ROOT" "$PID_MODE"',
    'record "$ROOT" "$PID_MODE" "$child"',
    'cleanup-private-runtime.py" "$RUNTIME_DIR"',
)
forbid(
    "modes/native-standard-exit-linux.sh",
    "os.path.realpath",
    "native-standard-exit.pid",
    "PID_FILE",
)

require(
    "modes/native-openvpn-standard-exit.sh",
    'cleanup-private-runtime.py" verify-dir',
    'verified-mode "$ROOT" "$mode"',
    'record "$ROOT" "$PID_MODE_BRIDGE" "$BRIDGE_PID"',
    'record "$ROOT" "$PID_MODE_OPENVPN" "$child"',
    'cleanup-private-runtime.py" "$RUNTIME_DIR"',
)
forbid(
    "modes/native-openvpn-standard-exit.sh",
    "os.path.realpath",
    "openvpn.pid",
    "entry-bridge.pid",
    "PID_FILE",
    "BRIDGE_PID_FILE",
    'rm -rf "$RUNTIME_DIR"',
)

if errors:
    for error in errors:
        print("ERROR:", error)
    raise SystemExit(1)
print("Router VPN standard-exit private runtime audit: PASS")
