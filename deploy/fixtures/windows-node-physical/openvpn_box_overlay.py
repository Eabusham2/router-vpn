"""Compose exact OpenVPN MAC witness compiler copies with native WFP scope."""
from pathlib import Path
import hashlib
import importlib.util
import json

ROOT = Path(__file__).resolve().parents[3]
RESOURCES = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "windows_openvpn_mac_module", RESOURCES / "openvpn_witness_overlay.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
BOX = RESOURCES / "openvpn_box_witness.go.tmpl"
PHYSICAL = ROOT / "mobile/desktop/external_physical.go.tmpl"
PROOF = ROOT / "mobile/externalpolicy/box.go.tmpl"
BOX_TAG = b"//go:build windows && routervpn_windows_node_composition && with_openvpn\n"
CONTROL_MUTATIONS = ("missing-mac-callback", "missing-session-correlation", "missing-proof-read")


def inputs():
    return [Path(__file__).resolve(), BOX, PROOF, PHYSICAL, *MODULE.inputs()]


def source_inputs():
    records = {}
    for path in inputs():
        data = MODULE.read_regular(path)
        if path == BOX and not data.startswith(BOX_TAG):
            raise ValueError("OpenVPN box witness escaped its native compiler scope")
        records["fixture/openvpn-witness/" + path.relative_to(ROOT).as_posix()] = hashlib.sha256(data).hexdigest()
    return records


def provider_source(raw):
    replace = MODULE.replace_once
    raw = replace(raw, '\tOVPN "github.com/sagernet/sing-box/protocol/openvpn"\n',
                  '\tOVPN "github.com/sagernet/sing-box/protocol/openvpn"\n\tSOVPN "github.com/sagernet/sing-openvpn"\n')
    raw = replace(raw, "type desktopOpenVPNCompositionPeerReply struct {\n",
                  "type desktopOpenVPNCompositionPeerReply struct {\n"
                  '\tControlMode string `json:"control_mode"`\n'
                  '\tControlRejects SOVPN.RouterVPNTestControlRejectSnapshot `json:"control_rejects"`\n')
    raw = replace(raw, "\tctx, cancel := context.WithCancel(context.Background())\n\tpeer :=",
                  "\tctx, cancel := context.WithCancel(context.Background())\n"
                  "\tctx, controlWitness, err := SOVPN.RouterVPNTestControlCollectorContext(ctx)\n"
                  '\tif err != nil { cancel(); return fail("control-witness-owner", err) }\n\tpeer :=')
    raw = replace(raw, "return desktopOpenVPNCompositionPeerReply{Schema: 1, Network: request.Network, AppID: appID,",
                  "return desktopOpenVPNCompositionPeerReply{Schema: 1, Network: request.Network, AppID: appID,\n"
                  "\t\t\tControlMode: request.Control, ControlRejects: controlWitness.Snapshot(),")
    raw = replace(raw, 'reply.Schema != 1 || reply.Network != "tcp" && reply.Network != "udp" {',
                  'reply.Schema != 1 || reply.Network != "tcp" && reply.Network != "udp" || reply.ControlMode != "tls-auth" && reply.ControlMode != "tls-crypt" {')
    raw = replace(raw, "reply.Network != p.initial.Network || reply.Remote != p.initial.Remote",
                  "reply.Network != p.initial.Network || reply.ControlMode != p.initial.ControlMode || reply.Remote != p.initial.Remote")
    raw = replace(raw, "if p.initial.Network != request.Network || p.initial.DNS != 0",
                  "if p.initial.Network != request.Network || p.initial.ControlMode != request.Control || "
                  "p.initial.ControlRejects.Invalid || p.initial.ControlRejects.Overflow || len(p.initial.ControlRejects.Events) != 0 || p.initial.DNS != 0")
    raw = replace(raw, "type desktopOpenVPNCompositionProcess struct {\n",
                  "type desktopOpenVPNCompositionProcess struct {\n lifetime context.Context\n")
    raw = replace(raw, "p := &desktopOpenVPNCompositionProcess{address: address, cancel: cancel,",
                  "p := &desktopOpenVPNCompositionProcess{address: address, cancel: cancel, lifetime: ctx,")
    return raw


def proof_source(raw, mutation=None):
    replace = MODULE.replace_once
    raw = replace(raw, "type routerVPNExternalNativeEngine struct {\n",
                  "type routerVPNExternalNativeEngine struct {\n"
                  "\trouterVPNTestOpenVPNProofRead atomic.Pointer[func(string, adapter.Outbound, nativeopenvpn.RemoteReceipt, error)]\n")
    old = "\treceipt, err := endpoint.RouterVPNConnectedRemoteContext(ctx)\n"
    new = (
        "\tobserver := e.routerVPNTestOpenVPNProofRead.Load()\n"
        "\treceipt, err := endpoint.RouterVPNConnectedRemoteContext(ctx)\n"
        "\tif observer != nil && e.routerVPNTestOpenVPNProofRead.Load() == observer &&\n"
        "\t\tctx.Err() == nil && e.routes[tag] == owner {\n"
        "\t\t(*observer)(tag, owner, receipt, err)\n"
        "\t}\n")
    if mutation == "missing-proof-read":
        new = replace(new, "if observer != nil", "if false && observer != nil")
    return replace(raw, old, new)


def connected_source(raw):
    # Only this test compiler copy exposes the connected descriptor to the
    # original fixture, synchronously before OpenVPN may close it on a bad MAC.
    raw = MODULE.replace_once(raw, "type ExternalPhysicalOutbound struct {\n",
                              "type ExternalPhysicalOutbound struct {\n\tRouterVPNTestTCPConnected func(context.Context, net.Conn)\n")
    return MODULE.replace_once(raw, "return broker.DialContext(ctx, network, destination.String())",
                               "connection, err := broker.DialContext(ctx, network, destination.String())\n"
                               "\tif err == nil && connection != nil && (network == \"tcp\" || network == \"tcp4\" || network == \"tcp6\") && o.RouterVPNTestTCPConnected != nil {\n"
                               "\t\to.RouterVPNTestTCPConnected(ctx, connection)\n\t}\n\treturn connection, err")


def rejection_source(raw):
    replace = MODULE.replace_once
    raw = replace(raw, "remotes []nativeopenvpn.Remote, fault string) {",
                  "remotes []nativeopenvpn.Remote, fault string, originalSource netip.Addr, connected <-chan desktopExternalOpenVPNTCPRead) {")
    raw = replace(raw, "desktopExternalWFPOpenVPNReject(t, f, peer, remotes, name)",
                  "desktopExternalWFPOpenVPNReject(t, f, peer, remotes, name, alias.original.Address.Addr(), tcpReads)")
    old = '\tif provider.network != peer.initial.Network || provider.remote.String() != peer.initial.Remote {\n\t\tt.Fatal("OpenVPN rejection changed its captured final provider")\n\t}\n'
    new = old + '\tif fault == "reject/control-key" && provider.network == "udp" {\n\t\tif err := desktopExternalWFPOpenVPNRejectControl(t, f, peer, provider, remotes, originalSource); err != nil { t.Fatal(err) }\n\t\treturn\n\t}\n'
    raw = replace(raw, old, new)
    raw = replace(raw, "\t\t\t\t\tf.start(t)\n",
                  "\t\t\t\t\tvar tcpReads <-chan desktopExternalOpenVPNTCPRead\n"
                  "\t\t\t\t\tif name == \"reject/control-key\" && carrierNetwork == \"tcp\" { tcpReads = desktopExternalOpenVPNObserveTCP(t, f) }\n"
                  "\t\t\t\t\tf.start(t)\n")
    # The UDP path takes its own existing MAC witness above. The TCP path
    # consumes a complete original snapshot at each actual successful dial.
    return replace(raw, "ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)\n\t\t\t\tactual, err := mobiletor.DesktopWindowsNodeCompositionSnapshot(ctx)\n\t\t\t\tcancel()",
                   "var actual mobiletor.DesktopWindowsNodeCompositionReadback\n"
                   "\t\t\t\tvar read desktopExternalOpenVPNTCPRead\n"
                   "\t\t\t\tselect {\n\t\t\t\tcase read = <-connected:\n"
                   "\t\t\t\tcase <-done: t.Fatal(\"OpenVPN proof stopped before the actual TCP retry\")\n"
                   "\t\t\t\tcase <-deadline.C: t.Fatal(\"no connected TCP retry reached native readback\")\n\t\t\t\t}\n"
                   "\t\t\t\tstatus = endpoint.OpenVPNStatus()\n"
                   "\t\t\t\tif latest, pending := endpoint.RouterVPNConnectedRemote(); !errors.Is(pending, nativeopenvpn.ErrRemotePending) || latest != (nativeopenvpn.RemoteReceipt{}) { t.Fatal(\"invalid OpenVPN TCP retry acquired a connected receipt\") }\n"
                   "\t\t\t\tactual, err = read.snapshot, read.err")


def compose(source, directory, existing, mutation=None):
    if mutation not in (None, *CONTROL_MUTATIONS):
        raise ValueError("Unknown OpenVPN MAC witness mutation")
    source, directory, existing = Path(source).resolve(), Path(directory).resolve(), Path(existing)
    before = source_inputs()
    mapping = json.loads(MODULE.read_regular(existing).decode("utf-8"))["Replace"]
    if not isinstance(mapping, dict):
        raise ValueError("OpenVPN witness lost its original native overlay")
    native = dict(mapping)
    module_overlay = MODULE.overlay(source, directory)
    additions = json.loads(MODULE.read_regular(module_overlay).decode("utf-8"))["Replace"]
    if set(mapping) & set(additions):
        raise ValueError("OpenVPN witness collides with an original compiler target")
    mapping.update(additions)
    staged = directory / "openvpn-box-witness"
    staged.mkdir(exist_ok=False)
    # Bound acquisition of the same existing native snapshot mutex. The
    # complete strict native readback body remains unchanged after acquisition.
    kernel_target = str(source / "routervpn/mobiletor/desktop_socket_windows_node_composition_overlay.go")
    if kernel_target not in mapping:
        raise ValueError("OpenVPN witness lost its original strict native observer")
    kernel_path = Path(mapping[kernel_target])
    kernel_original = MODULE.read_regular(kernel_path).decode("utf-8")
    if kernel_original != MODULE.read_regular(RESOURCES / "kernel_observer.go").decode("utf-8"):
        raise ValueError("OpenVPN native observer changed before bounded acquisition")
    for signature in ("func DesktopWindowsNodeCompositionSnapshot(ctx", "func desktopWindowsNodeConfirmConstructor(ctx"):
        function = kernel_original.split(signature, 1)
        if len(function) != 2 or function[1].split("\n}", 1)[0].count("if err := desktopWindowsNodeCompositionLockContext(ctx); err != nil {") != 1:
            raise ValueError("OpenVPN native observer lost bounded original-owner acquisition")

    def stage(target, content):
        target = Path(target)
        if str(target) in mapping:
            raise ValueError("OpenVPN box witness would replace another compiler owner")
        copied = staged / (str(len(mapping)) + ".go")
        with copied.open("xb") as output:
            output.write(content)
        mapping[str(target)] = str(copied)

    for name, target, patch in (
            ("external_box_openvpn_reference_test.go.tmpl", "routervpn_desktop_external_box_openvpn_reference_test.go", provider_source),
            ("external_box_windows_openvpn_test.go.tmpl", "routervpn_desktop_external_box_windows_openvpn_test.go", rejection_source)):
        original = MODULE.read_regular(ROOT / "mobile/desktop" / name)
        if MODULE.read_regular(source / target) != original:
            raise ValueError("OpenVPN witness lost its exact original prepared fixture")
        stage(source / target, patch(original.decode("utf-8")).encode("utf-8"))
    physical = MODULE.read_regular(PHYSICAL)
    lower_target = source / "routervpn/desktoppt/external_physical.go"
    if MODULE.read_regular(lower_target) != physical:
        raise ValueError("OpenVPN TCP observation lost its original physical dialer")
    stage(lower_target, connected_source(physical.decode("utf-8")).encode("utf-8"))
    original_proof = MODULE.read_regular(PROOF)
    proof_target = source / "routervpn_external_policy.go"
    if MODULE.read_regular(proof_target) != original_proof:
        raise ValueError("OpenVPN witness lost its exact original proof source")
    stage(proof_target, proof_source(original_proof.decode("utf-8"), mutation).encode("utf-8"))
    target = source / "routervpn_desktop_external_windows_openvpn_control_witness_test.go"
    if target.exists() or target.is_symlink():
        raise ValueError("Unowned OpenVPN box witness occupies the prepared source")
    box = MODULE.read_regular(BOX).decode("utf-8")
    if mutation == "missing-session-correlation":
        box = MODULE.replace_once(box, "if event.SessionID == view.SessionID && event.Network == view.Network",
                                  "if true && event.Network == view.Network")
    stage(target, box.encode("utf-8"))
    if mutation == "missing-mac-callback":
        copied = Path(mapping[str(source / MODULE.POLICY.COPY / "control_wrap.go")])
        text = MODULE.read_regular(copied).decode("utf-8")
        before_hook = "if c.routerVPNTestMACRejected != nil {"
        if text.count(before_hook) != 2:
            raise ValueError("OpenVPN native causal control lost both exact codec callbacks")
        text = text.replace(before_hook, "if false && c.routerVPNTestMACRejected != nil {")
        copied.write_text(text, encoding="utf-8", newline="\n")
    if any(mapping[key] != value for key, value in native.items()) or source_inputs() != before:
        raise ValueError("OpenVPN witness changed original compiler scope or source inputs")
    MODULE.checked_sources(source)
    result = staged / "overlay.json"
    with result.open("x", encoding="utf-8", newline="\n") as output:
        json.dump({"Replace": mapping}, output, sort_keys=True)
    return result
