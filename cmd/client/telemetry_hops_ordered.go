package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/mobilemultihop"
)

// This capture binds the UI's GET to the same complete native graph on POST.
// Heartbeat time is intentionally excluded; native reader/proof replacement is
// included, so even an authorized MTU transaction requires a fresh preflight.
func orderedPerformanceCapture(identity speedLabPathIdentity, ready mobilemultihop.DesktopNodeChainReadyRecord, members []string) (string, error) {
	if len(members) < 2 || len(members) > 8 || identity.Graph.ChainNodes != len(members) || ready.Generation == 0 || ready.Reader == 0 || ready.Identity.EngineID == "" || ready.Identity.SessionID == "" || ready.Identity.NetworkID == "" || ready.Identity.SourceSHA256 == "" || ready.Identity.ConfigSHA256 == "" {
		return "", errors.New("ordered Performance capture has no complete native proof")
	}
	ready.ObservedAt = 0
	raw, err := json.Marshal(struct {
		Ready                   mobilemultihop.DesktopNodeChainReadyRecord
		Members                 []string
		Session, Network, State string
		Graph                   activeMultihopGraph
	}{ready, members, identity.SessionID, identity.Network, identity.StateToken, identity.Graph})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// Status captures references only; it does not replay source or grant permission
// to measure. POST performs full current source/proof validation under its
// original measurement deadline before accepting this exact opaque capture.
func captureOrderedPerformanceContext(ctx context.Context, a *app) (speedLabPathIdentity, string, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	var identity speedLabPathIdentity
	tracker, session, err := measurementSessionContext(ctx, a, nil)
	if err != nil {
		return identity, "", 0, err
	}
	if err := mobilemtu.LockContext(ctx, &a.mu); err != nil {
		return identity, "", 0, err
	}
	st, command := a.state, a.cmd
	a.mu.Unlock()
	graph, graphOK := getActiveMultihopGraph(a)
	raw, found := nativeMultihopOwners.Load(a)
	owner, typed := raw.(*nativeMultihopRuntime)
	if !st.Connected || st.Phase != "connected" || st.Mode != "multihop" || !session.Connected || session.Phase != "connected" || session.PathProof != "passed" || session.ID == "" || session.RouterID != st.RouterID || !graphOK || graph.ChainNodes < 2 || !found || !typed || owner == nil || owner.launch == nil || owner.launch.chain == nil || owner.launch.command != command || owner.graph != graph || owner.network == "" {
		return identity, "", 0, errors.New("ordered Performance requires the retained connected native chain")
	}
	retained, found := desktopNodeOwners.Load(a)
	if !found || retained != owner.launch {
		return identity, "", 0, errors.New("ordered Performance lost its original native owner")
	}
	identity = speedLabPathIdentity{Tracker: tracker, SessionID: session.ID, StateToken: mtuStateSnapshotToken(st), Graph: graph, GraphOK: true, Ordered: owner, Network: owner.network}
	chain := owner.launch.chain
	if err := mobilemtu.LockContext(ctx, &chain.mu); err != nil {
		return identity, "", 0, err
	}
	if chain.ready == nil {
		chain.mu.Unlock()
		return identity, "", 0, errors.New("ordered native chain has no ready proof")
	}
	ready := *chain.ready
	members := make([]string, len(chain.selection.Nodes))
	for i, n := range chain.selection.Nodes {
		members[i] = n.Profile.ID
	}
	chain.mu.Unlock()
	token, err := orderedPerformanceCapture(identity, ready, members)
	return identity, token, len(members), errors.Join(err, ctx.Err())
}

func (a *app) orderedMultihopSpeedTest(w http.ResponseWriter, r *http.Request, q routedSpeedRequest, graph activeMultihopGraph) {
	if graph.ChainNodes < 2 || graph.ChainNodes > 8 || q.Bytes != 8<<20 || len(q.OrderedCapture) != 64 {
		http.Error(w, "ordered hop measurement requires its exact preflight capture and 8 MiB per direction", http.StatusConflict)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	identity, _, err := captureSpeedLabIdentityContext(ctx, a)
	if err != nil {
		http.Error(w, "ordered native route is no longer proved for measurement", http.StatusConflict)
		return
	}
	current, capture, count, err := captureOrderedPerformanceContext(ctx, a)
	if err != nil || identity.Ordered == nil || current.Ordered != identity.Ordered || current.SessionID != identity.SessionID || current.StateToken != identity.StateToken || identity.Graph != graph || current.Graph != graph || capture != q.OrderedCapture {
		http.Error(w, "ordered native route changed after preflight; capture the active route again", http.StatusConflict)
		return
	}
	rows, err := measureSpeedLabOrderedHops(ctx, a, identity)
	if asyncMeasurementRequestError(w, r.Context(), ctx, "ordered multihop speed test") {
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"connected": true, "mode": "multihop", "entry_id": graph.EntryID, "exit_id": graph.ExitID, "ordered_capture": capture, "ordered_nodes": count, "bytes": q.Bytes, "hops": rows, "measured_at": time.Now().UTC(), "note": "Each row is an independently measured cumulative path through that node's authenticated private API. Intermediate rows are retained; no subtraction invents link speed."})
}
