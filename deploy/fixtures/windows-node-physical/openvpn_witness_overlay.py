"""Build a test-only compiler overlay for the exact prepared OpenVPN module.

The complete generation-patched tree is checked against its official h1 before
and after staging. Only new files in the caller's owned temporary directory are
written; module, cache, prepared core and production sources remain unchanged.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import stat

ROOT = Path(__file__).resolve().parents[3]
RESOURCES = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "windows_openvpn_witness_module_policy", ROOT / "deploy/mobile_openvpn_module_policy.py")
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)
if (POLICY.MODULE != "github.com/sagernet/sing-openvpn" or
        POLICY.VERSION != "v0.0.0-20260729104525-103eb5fe5eb6" or
        POLICY.SUM != "h1:ZAvhkor0prJ8KEX9EmTEH+gJ1WlA3ffjS8GZT6KKq9c="):
    raise ValueError("OpenVPN MAC witness requires its exact pinned module")

TAG = b"//go:build windows && routervpn_windows_node_composition\n"
ENDPOINT_TAG = b"//go:build windows && routervpn_windows_node_composition && with_openvpn\n"
RESOURCE_TAGS = {
    "openvpn_control_witness.go.tmpl": TAG,
    "openvpn_control_codec.go.tmpl": TAG,
    "openvpn_endpoint_witness.go.tmpl": ENDPOINT_TAG,
}
CODEC_SCENARIOS = (
    "valid", "fallback-valid", "wrong-mac", "truncated", "replay", "malformed-authenticated",
    "rate-limited", "wrong-mac-server", "retained-codec", "collector-bound",
    "collector-owner", "collector-cancelled",
)

# These are compiler copies of authenticated pinned input. Every replacement
# is unique and fully reversible; original crypto signatures/results and the
# early short/replay returns remain intact.
PATCHES = {
    "control_wrap.go": [
        [
            "type controlAuthCodec struct {\n",
            "type controlAuthCodec struct {\n\trouterVPNTestMACRejected func()\n\n"
        ],
        [
            "type controlCryptCodec struct {\n",
            "type controlCryptCodec struct {\n\trouterVPNTestMACRejected func()\n\n"
        ],
        [
            "\t\treturn decodedPacket, true\n\t}\n\treturn nil, false\n}\n\ntype controlCryptCodec struct {",
            "\t\treturn decodedPacket, true\n\t}\n\tif c.routerVPNTestMACRejected != nil {\n\t\tc.routerVPNTestMACRejected()\n\t}\n\treturn nil, false\n}\n\ntype controlCryptCodec struct {"
        ],
        [
            "\t\treturn decodedPacket, true\n\t}\n\treturn nil, false\n}\n\n// Upstream mudp.c reads",
            "\t\treturn decodedPacket, true\n\t}\n\tif c.routerVPNTestMACRejected != nil {\n\t\tc.routerVPNTestMACRejected()\n\t}\n\treturn nil, false\n}\n\n// Upstream mudp.c reads"
        ]
    ],
    "udp_predecrypt.go": [
        [
            "packet, protection, earlyNegotiation, err := s.decodeUDPPreDecryptPacket(rawPacket)",
            "packet, protection, earlyNegotiation, err := s.routerVPNTestDecodeUDPPreDecryptPacket(rawPacket, peerAddress)"
        ],
        [
            "func (s *tlsServer) decodeUDPPreDecryptPacket(rawPacket []byte) (*proto.Packet, tlsControlProtection, bool, error) {\n",
            "func (s *tlsServer) decodeUDPPreDecryptPacket(rawPacket []byte) (*proto.Packet, tlsControlProtection, bool, error) {\n\treturn s.routerVPNTestDecodeUDPPreDecryptPacket(rawPacket, nil)\n}\n\nfunc (s *tlsServer) routerVPNTestDecodeUDPPreDecryptPacket(rawPacket []byte, peerAddress net.Addr) (*proto.Packet, tlsControlProtection, bool, error) {\n"
        ],
        [
            "\tprotection := s.staticProtection.newSessionProtection()\n\tpacketBytes, err := protection.decodeIncomingControlPacket(rawPacket)\n",
            "\tprotection := s.staticProtection.newSessionProtection()\n\t// Observe only this actual decode. Accepted protection is retained by a\n\t// session, so it must never retain this packet or its peer callback.\n\tif protection.auth != nil {\n\t\tprotection.auth.routerVPNTestMACRejected = func() { s.routerVPNTestControlMACRejected(\"tls-auth\", rawPacket, peerAddress) }\n\t}\n\tif protection.crypt != nil {\n\t\tprotection.crypt.routerVPNTestMACRejected = func() { s.routerVPNTestControlMACRejected(\"tls-crypt\", rawPacket, peerAddress) }\n\t}\n\tpacketBytes, err := protection.decodeIncomingControlPacket(rawPacket)\n\tif protection.auth != nil {\n\t\tprotection.auth.routerVPNTestMACRejected = nil\n\t}\n\tif protection.crypt != nil {\n\t\tprotection.crypt.routerVPNTestMACRejected = nil\n\t}\n"
        ]
    ],
    "server_listener.go": [
        [
            "packet, protection, _, decodeErr := s.decodeUDPPreDecryptPacket(rawPacket)",
            "packet, protection, _, decodeErr := s.routerVPNTestDecodeUDPPreDecryptPacket(rawPacket, remoteAddress)"
        ]
    ],
    "client_session_tls.go": [
        [
            "type tlsClient struct {\n",
            "type tlsClient struct {\n\trouterVPNTestControlSession RouterVPNTestControlSessionView\n\trouterVPNTestPacketConnection proto.PacketConnection\n\n"
        ],
        [
            "\tclient := &tlsClient{\n",
            "\tclient := &tlsClient{\n\t\trouterVPNTestControlSession: RouterVPNTestControlSessionView{SessionID: [8]byte(sessionManager.LocalSessionID())},\n"
        ],
        [
            "\tsessionErr := sessionContext.Err()\n",
            "\tc.routerVPNTestCaptureInitializedConnection(underlyingConnection, packetConnection)\n\tsessionErr := sessionContext.Err()\n"
        ]
    ]
}


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise ValueError("Pinned OpenVPN test instrumentation boundary changed")
    return text.replace(before, after, 1)


def read_regular(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("OpenVPN witness source is not an owned regular file")
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("OpenVPN witness source exceeds its bound")
    return path.read_bytes()


def inputs():
    return [Path(__file__).resolve(),
            *(RESOURCES / name for name in RESOURCE_TAGS), *POLICY.inputs()]


def checked_sources(source):
    source = Path(source)
    if source.is_symlink() or not source.is_dir():
        raise ValueError("OpenVPN witness requires its prepared core directory")
    source = source.resolve()
    module = source / POLICY.COPY
    POLICY.verify_tree(module)
    records = {}
    for path in inputs():
        data = read_regular(path)
        if path.name in RESOURCE_TAGS and not data.startswith(RESOURCE_TAGS[path.name]):
            raise ValueError("OpenVPN witness escaped its explicit Windows native test tag")
        records["fixture/openvpn-witness/" + path.relative_to(ROOT).as_posix()] = hashlib.sha256(data).hexdigest()
    for name in PATCHES:
        records["fixture/openvpn-module/" + name] = hashlib.sha256(read_regular(module / name)).hexdigest()
    records["fixture/openvpn-module/official-h1"] = hashlib.sha256(POLICY.SUM.encode()).hexdigest()
    return records


def overlay(source, directory):
    source = Path(source)
    before = checked_sources(source)
    source = source.resolve()
    module = source / POLICY.COPY
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("OpenVPN overlay requires an existing owned temporary directory")
    directory = directory.resolve()
    if directory.is_relative_to(source) or directory.is_relative_to(ROOT):
        raise ValueError("OpenVPN compiler copies must remain outside source trees")
    staged = directory / "openvpn-witness"
    staged.mkdir(exist_ok=False)
    mapping = {}

    def stage(target, data):
        target = Path(target)
        if str(target) in mapping:
            raise ValueError("Duplicate OpenVPN witness compiler target")
        copied = staged / (str(len(mapping)) + ".go")
        with copied.open("xb") as output:
            output.write(data)
        mapping[str(target)] = str(copied)

    for name, changes in PATCHES.items():
        original = read_regular(module / name).decode("utf-8")
        changed = original
        for old, new in changes:
            changed = replace_once(changed, old, new)
        restored = changed
        for old, new in reversed(changes):
            restored = replace_once(restored, new, old)
        if restored != original:
            raise ValueError("OpenVPN instrumentation did not preserve its exact original source")
        stage(module / name, changed.encode("utf-8"))
    for resource, target in (
            ("openvpn_control_witness.go.tmpl", module / "routervpn_test_control_witness.go"),
            ("openvpn_control_codec.go.tmpl", module / "routervpn_test_control_codec.go"),
            ("openvpn_endpoint_witness.go.tmpl", source / "protocol/openvpn/routervpn_test_control_witness.go")):
        if target.exists() or target.is_symlink():
            raise ValueError("Unowned OpenVPN witness already occupies the prepared core")
        stage(target, read_regular(RESOURCES / resource))
    # This rechecks the complete original module's official h1 and canonical
    # generation/context additions, not merely the four overlaid source files.
    if checked_sources(source) != before:
        raise ValueError("OpenVPN original sources changed during compiler staging")
    result = staged / "overlay.json"
    with result.open("x", encoding="utf-8", newline="\n") as output:
        json.dump({"Replace": mapping}, output, sort_keys=True)
    return result
