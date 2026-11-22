"""Expose original candidate protocol and a real TCP destination to tagged desktop component tests."""
from pathlib import Path
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('original_selected_latency_fixture', ROOT/'deploy/prepare-desktop-selected-latency-test.py')
LATENCY = importlib.util.module_from_spec(spec)
spec.loader.exec_module(LATENCY)
REMOTE = ROOT/'internal/mobilemultihop/node_chain_execution_remote_candidates_test.go'
WRAPPER = ROOT/'mobile/desktop_test/selected_candidate_fixture.go.tmpl'
TARGET = 'experimental/libbox/routervpn/mobilemultihop/routervpn_desktop_candidate_fixture.go'


def inputs():
    return [Path(__file__).resolve(), REMOTE, WRAPPER]


def copies():
    declarations = LATENCY.declarations(REMOTE.read_text())
    stop = LATENCY.one(declarations, 'func (e *nodeChainExecutionRuntimeEngine) CaptureExecutionCandidateStop(')
    stop = stop.replace('e *nodeChainExecutionRuntimeEngine', 'e *desktopLatencyOriginalNodeChainExecutionRuntimeEngine')
    methods = [LATENCY.one(declarations, 'func (r *remoteCandidateFixture) '+name+'(')
               .replace('r *remoteCandidateFixture', 'r *RouterVPNDesktopCandidateTestPeer') for name in ('serveCandidate', 'front')]
    # A successful SOCKS CONNECT must be backed by an independently counted
    # destination handshake. Keep the original auth, exact quota and EOF checks.
    ack = 'if _, e := conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); e != nil {'
    if methods[1].count(ack) != 1:
        raise ValueError('original candidate admission no longer brackets the SOCKS acknowledgement')
    methods[1] = methods[1].replace(ack, 'upstream, err := net.Dial("tcp",r.destination.Addr().String()); if err!=nil{return}; upstream.Close()\n\t'+ack)
    return {TARGET: (WRAPPER.read_text()+'\n'+stop+'\n'+'\n'.join(methods)+'\n').encode()}
