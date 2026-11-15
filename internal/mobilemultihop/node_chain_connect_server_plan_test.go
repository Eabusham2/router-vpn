package mobilemultihop

import (
	"testing"
)

func connectServerPlanFixture(t *testing.T, mode, protocol string) map[string]any {
	t.Helper()
	original, _ := connectExecutionPreparationFixture(t, mode, protocol, "server")
	var source NodeChainSource
	var middle nodeChainImportedInput
	if exactJSON([]byte(original.sourceJSON), &source, NodeChainInputLimit) != nil || exactJSON([]byte(source.Nodes[1]), &middle, NodeChainInputLimit) != nil {
		t.Fatal("original plan sources")
	}
	entry, final := original.pair.nodes[0], original.pair.nodes[1]
	eb := nodeChainServerPlanBundle(t, entry, source.IdentitySources[0])
	fb := nodeChainServerPlanBundle(t, final, source.IdentitySources[2])
	peer := nodeChainServerPlanPeerBundle(t, fb, 2)
	return map[string]any{"schema": 4, "entry_node_id": entry.profile["node_proof_id"], "entry": map[string]any{"bundle": eb, "profile_id": entry.profile["id"], "mode": mode}, "members": []any{
		map[string]any{"imported": map[string]any{"config": middle.Config, "capture": middle.Capture}},
		map[string]any{"paired": map[string]any{"bundle": fb, "profile_id": final.profile["id"], "mode": "shadowsocks"}, "server_peer": map[string]any{"bundle": peer, "profile_id": "server-" + final.profile["id"].(string)}},
	}}
}
func TestNodeChainCONNECTServerPlanRetainsIndependentOriginalBundles(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, protocol := range []string{"http-connect", "https-connect"} {
			t.Run(mode+"/"+protocol, func(t *testing.T) {
				plan := connectServerPlanFixture(t, mode, protocol)
				raw := startJSON(t, plan)
				if _, err := NewNodeChainServerPlan(raw); err == nil {
					t.Fatal("generic plan admitted CONNECT")
				}
				policy, err := NewNodeChainCONNECTServerPlan(raw)
				if err != nil {
					t.Fatal("original typed operator plan", err)
				}
				if policy.Descriptor().Schema != 4 || policy.Descriptor().Members[0].NodeID != "" || policy.Descriptor().Members[0].ClientPublicKey != "" || policy.NativeCarrierRequired() {
					t.Fatal("plan fabricated suffix packet authority")
				}
				rows := plan["members"].([]any)
				paired := rows[1].(map[string]any)
				selected := paired["paired"].(map[string]any)
				paired["server_peer"] = map[string]any{"bundle": selected["bundle"], "profile_id": selected["profile_id"]}
				if _, err := NewNodeChainCONNECTServerPlan(startJSON(t, plan)); err == nil {
					t.Fatal("original client identity reused as server peer")
				}
			})
		}
	}
}
