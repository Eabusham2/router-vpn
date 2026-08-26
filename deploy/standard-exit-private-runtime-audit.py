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
    "cmd/client/standard_exit_runtime.go",
    'newPrivateRuntimeDir(root, "native-standard-exit")',
    'writePrivateRuntimeFile(filepath.Join(runtimeDir, "sing-box.json")',
)
forbid(
    "cmd/client/standard_exit_runtime.go",
    'os.MkdirAll(base, 0o700)',
    'os.WriteFile(filepath.Join(runtimeDir, "sing-box.json")',
    'rand.Read(random)',
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

if errors:
    for error in errors:
        print("ERROR:", error)
    raise SystemExit(1)
print("Router VPN standard-exit private runtime audit: PASS")
