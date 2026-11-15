package mobilemultihop

import "testing"

func socksServerPlanFixture(t *testing.T, mode, authentication string) map[string]any {
	t.Helper()
	local := nodeChainSOCKSFixture(t, mode, "", authentication)
	original, err := NewNodeChainSOCKSSource(startJSON(t, local))
	if err != nil {
		t.Fatal(err)
	}
	var middle nodeChainImportedInput
	if exactJSON([]byte(local.Nodes[1]), &middle, NodeChainInputLimit) != nil {
		t.Fatal("original imported member")
	}
	entry, final := original.pair.nodes[0], original.pair.nodes[1]
	eb := nodeChainServerPlanBundle(t, entry, local.IdentitySources[0])
	fb := nodeChainServerPlanBundle(t, final, local.IdentitySources[2])
	peer := nodeChainServerPlanPeerBundle(t, fb, 2)
	return map[string]any{"schema": 3, "entry_node_id": entry.profile["node_proof_id"], "entry": map[string]any{"bundle": eb, "profile_id": entry.profile["id"], "mode": mode}, "members": []any{
		map[string]any{"imported": map[string]any{"config": middle.Config, "capture": middle.Capture}},
		map[string]any{"paired": map[string]any{"bundle": fb, "profile_id": final.profile["id"], "mode": "shadowsocks"}, "server_peer": map[string]any{"bundle": peer, "profile_id": "server-" + final.profile["id"].(string)}},
	}}
}
func TestNodeChainSOCKSServerPlanKeepsIndependentPairedIdentity(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, authentication := range []string{"password", "none"} {
			t.Run(mode+"/"+authentication, func(t *testing.T) {
				plan := socksServerPlanFixture(t, mode, authentication)
				raw := startJSON(t, plan)
				if _, err := NewNodeChainServerPlan(raw); err == nil {
					t.Fatal("generic plan admitted negotiated SOCKS")
				}
				if _, err := NewNodeChainCONNECTServerPlan(raw); err == nil {
					t.Fatal("CONNECT plan admitted SOCKS")
				}
				p, err := NewNodeChainSOCKSServerPlan(raw)
				if err != nil {
					t.Fatal(err)
				}
				if p.Descriptor().Schema != 3 || p.Descriptor().Members[0].NodeID != "" || p.Descriptor().Members[0].ClientPublicKey != "" || p.NativeCarrierRequired() {
					t.Fatal("imported association gained packet identity")
				}
				if _, err := NewNodeChainSOCKSServerPolicy(p.Source()); err != nil {
					t.Fatal("staged source cannot restore", err)
				}
				final := plan["members"].([]any)[1].(map[string]any)
				paired := final["paired"].(map[string]any)
				final["server_peer"] = map[string]any{"bundle": paired["bundle"], "profile_id": paired["profile_id"]}
				if _, err := NewNodeChainSOCKSServerPlan(startJSON(t, plan)); err == nil {
					t.Fatal("client paired key reused by server")
				}
			})
		}
	}
}
