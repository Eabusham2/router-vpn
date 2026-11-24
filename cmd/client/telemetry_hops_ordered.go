package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"runtime"
	"time"

	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/mobilemultihop"
)

type desktopOrderedPerformanceSource struct {
	SourceSHA256    string   `json:"source_sha256"`
	ConfigSHA256    string   `json:"config_sha256"`
	NodeIDs         []string `json:"node_ids"`
	PairedWireGuard bool     `json:"paired_wireguard,omitempty"`
}

func (identity speedLabPathIdentity) addOrderedPerformanceSource(payload map[string]any) {
	if identity.orderedLocalSource != nil {
		payload["ordered_local_source"] = identity.orderedLocalSource
	}
	if identity.orderedOriginalSource != nil {
		payload["ordered_original_source"] = identity.orderedOriginalSource
	}
}

type desktopSelectedPerformanceSource struct {
	SourceSHA256     string   `json:"source_sha256"`
	ConfigSHA256     string   `json:"config_sha256"`
	GenerationSHA256 string   `json:"generation_sha256"`
	Execution        string   `json:"selected_execution"`
	NodeIDs          []string `json:"node_ids"`
}

// This capture binds the UI's GET to the same complete native graph on POST.
// Heartbeat time is intentionally excluded; native reader/proof replacement is
// included, so even an authorized MTU transaction requires a fresh preflight.
func orderedPerformanceCapture(identity speedLabPathIdentity, ready mobilemultihop.DesktopNodeChainReadyRecord, members []string) (string, error) {
	if len(members) < 2 || len(members) > mobilemultihop.NodeChainExtendedLocalMaximumNodes || identity.Graph.ChainNodes != len(members) || ready.Generation == 0 || ready.Reader == 0 || ready.Identity.EngineID == "" || ready.Identity.SessionID == "" || ready.Identity.NetworkID == "" || ready.Identity.SourceSHA256 == "" || ready.Identity.ConfigSHA256 == "" {
		return "", errors.New("ordered Performance capture has no complete native proof")
	}
	if len(members) > mobilemultihop.NodeChainMaximumNodes {
		bad := errors.New("long ordered Performance capture changed its original Local source")
		owner := identity.Ordered
		if owner == nil || owner.execution != nil || owner.launch == nil || owner.launch.chain == nil || identity.Graph.Execution != "local" {
			return "", bad
		}
		chain := owner.launch.chain
		if chain.policy == nil || chain.preparation != nil || chain.execution != nil {
			return "", bad
		}
		_, meta, input, err := chain.readLaunchPolicy()
		if err != nil || input != chain.input || ready.Identity.SourceSHA256 != meta.OriginalSourceSHA256 ||
			ready.Identity.ConfigSHA256 != meta.ConfigSHA256 || ready.Identity.SessionID != meta.SessionID {
			return "", bad
		}
		nodes, err := desktopOrderedLatencyInventory(chain.selection, meta)
		if err != nil || len(nodes) != len(members) || nodes[0].extended == nil {
			return "", bad
		}
		for i, node := range nodes {
			if node.NodeID != members[i] {
				return "", bad
			}
		}
	}
	ready.ObservedAt = 0
	raw, err := json.Marshal(struct {
		Ready                   mobilemultihop.DesktopNodeChainReadyRecord
		Members                 []string
		Session, Network, State string
		Profile, Entry          string
		Options                 [3]bool
		Graph                   activeMultihopGraph
	}{ready, members, identity.SessionID, identity.Network, identity.StateToken, identity.ProfileToken, identity.EntryToken, identity.Options, identity.Graph})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// Status never grants permission to measure. Protected platform hosts require
// their original bounded Current observation outside app.mu; their process
// ownership is retained by the typed platform, not desktopNodeOwners. POST
// still performs full current source/proof validation before measurement.
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
	graph, graphOK := getActiveMultihopGraph(a)
	profile, profileOK := a.profileByIDLocked(st.RouterID)
	entry, entryOK := a.profileByIDLocked(graph.EntryID)
	profileToken, entryToken := liveMeasurementProfileToken(profile), liveMeasurementProfileToken(entry)
	a.mu.Unlock()
	raw, found := nativeMultihopOwners.Load(a)
	owner, typed := raw.(*nativeMultihopRuntime)
	if !profileOK || !entryOK || !st.Connected || st.Phase != "connected" || st.Mode != "multihop" || !session.Connected || session.Phase != "connected" || session.PathProof != "passed" || session.ID == "" || session.RouterID != st.RouterID || !graphOK || graph.ChainNodes < 2 || graph.Execution != "local" || !found || !typed || owner == nil || owner.launch == nil || owner.launch.chain == nil || owner.execution != nil || owner.launch.chain.execution != nil || owner.launch.command != command || owner.graph != graph || owner.network == "" {
		return identity, "", 0, errors.New("ordered Performance requires the retained connected native chain")
	}
	identity = speedLabPathIdentity{Tracker: tracker, SessionID: session.ID, StateToken: mtuStateSnapshotToken(st), RouterID: st.RouterID,
		Graph: graph, GraphOK: true, Ordered: owner, Command: command, Network: owner.network, ProfileToken: profileToken,
		EntryToken: entryToken, Options: [3]bool{st.DAITA, st.Jumbo, st.Socks}}
	chain := owner.launch.chain
	var captured *mtuNodeChainSnapshot
	if chain.platform != nil {
		// This existing snapshot captures immutable complete source/command
		// associations only; it starts no MTU transaction or measurement.
		captured, err = captureMTUNodeChainSnapshotContext(ctx, owner)
		if err != nil || captured == nil || captured.Platform == nil ||
			(runtime.GOOS != "linux" && runtime.GOOS != "darwin") || orderedPerformanceSnapshotTarget(captured) != runtime.GOOS {
			return identity, "", 0, errors.New("ordered Performance lost its original protected platform capture")
		}
		if err := nativeMultihopLaunchCurrent(ctx, a, captured.Launch); err != nil {
			return identity, "", 0, err
		}
	}
	if err := mobilemtu.LockContext(ctx, &a.mu); err != nil {
		return identity, "", 0, err
	}
	err = validateOrderedPerformanceOwnerLocked(a, identity, captured)
	profile, profileOK = a.profileByIDLocked(identity.RouterID)
	entry, entryOK = a.profileByIDLocked(identity.Graph.EntryID)
	if !profileOK || !entryOK || liveMeasurementProfileToken(profile) != profileToken || liveMeasurementProfileToken(entry) != entryToken ||
		[3]bool{a.state.DAITA, a.state.Jumbo, a.state.Socks} != identity.Options {
		err = errors.New("ordered Performance changed its captured active profile, entry or options")
	}
	a.mu.Unlock()
	if err != nil {
		return identity, "", 0, err
	}
	_, currentSession, err := measurementSessionContext(ctx, a, tracker)
	if err != nil || currentSession.ID != session.ID || !currentSession.Connected || currentSession.Phase != "connected" ||
		currentSession.PathProof != "passed" || currentSession.RouterID != st.RouterID {
		return identity, "", 0, errors.New("ordered Performance session changed during original observation")
	}
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
	if err == nil && len(members) > mobilemultihop.NodeChainMaximumNodes {
		identity.orderedLocalSource = &desktopOrderedPerformanceSource{
			SourceSHA256: ready.Identity.SourceSHA256, ConfigSHA256: ready.Identity.ConfigSHA256, NodeIDs: members,
			PairedWireGuard: chain.selection.Native.chain.chain.ExtendedPairedLocalNodeCount() == len(members),
		}
	}
	return identity, token, len(members), errors.Join(err, ctx.Err())
}

// Caller holds app.mu. Recheck the same original command, complete graph and
// source objects after the platform observation; no native callback runs here.
func validateOrderedPerformanceOwnerLocked(a *app, identity speedLabPathIdentity, captured *mtuNodeChainSnapshot) error {
	owner := identity.Ordered
	graph, graphOK := getActiveMultihopGraph(a)
	raw, found := nativeMultihopOwners.Load(a)
	if owner == nil || owner.launch == nil || owner.launch.chain == nil || owner.execution != nil || owner.launch.chain.execution != nil || !found || raw != owner ||
		!graphOK || graph != identity.Graph || graph != owner.graph || graph.ChainNodes < 2 || graph.ChainNodes > mobilemultihop.NodeChainExtendedLocalMaximumNodes || graph.Execution != "local" ||
		a.cmd != identity.Command || owner.launch.command != identity.Command || owner.network != identity.Network ||
		!a.state.Connected || a.state.Phase != "connected" || a.state.RouterID != identity.RouterID ||
		mtuStateSnapshotToken(a.state) != identity.StateToken {
		return errors.New("ordered Performance replaced its original connected runtime")
	}
	if captured != nil {
		if captured.Platform == nil || orderedPerformanceSnapshotTarget(captured) != runtime.GOOS ||
			(runtime.GOOS != "linux" && runtime.GOOS != "darwin") {
			return errors.New("ordered Performance substituted a foreign protected platform")
		}
		return validateMTUNodeChainLocked(a, &mtuMultihopSnapshot{Graph: graph, Native: owner, Chain: captured, Command: identity.Command})
	}
	retained, found := desktopNodeOwners.Load(a)
	if owner.launch.chain.platform != nil || !found || retained != owner.launch {
		return errors.New("ordered Performance lost its original native owner")
	}
	return nil
}

func (a *app) orderedMultihopSpeedTest(w http.ResponseWriter, r *http.Request, q routedSpeedRequest, graph activeMultihopGraph) {
	if graph.ChainNodes < 2 || graph.ChainNodes > mobilemultihop.NodeChainExtendedLocalMaximumNodes || q.Bytes != 8<<20 || len(q.OrderedCapture) != 64 {
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
	current, capture, count, err := captureOrderedThroughputContext(ctx, a)
	if err != nil || identity.Ordered == nil || graph.ChainNodes > mobilemultihop.NodeChainMaximumNodes && identity.Ordered.execution != nil && current.orderedOriginalSource == nil || current.Ordered != identity.Ordered || current.SessionID != identity.SessionID || current.StateToken != identity.StateToken || identity.Graph != graph || current.Graph != graph || capture != q.OrderedCapture {
		http.Error(w, "ordered native route changed after preflight; capture the active route again", http.StatusConflict)
		return
	}
	var rows []speedLabHopMeasurement
	if identity.Ordered.execution != nil {
		rows, err = measureDesktopSelectedThroughput(ctx, a, identity, capture)
	} else {
		rows, err = measureSpeedLabOrderedHops(ctx, a, identity)
	}
	if asyncMeasurementRequestError(w, r.Context(), ctx, "ordered multihop speed test") {
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	payload := map[string]any{"connected": true, "mode": "multihop", "entry_id": graph.EntryID, "exit_id": graph.ExitID, "ordered_capture": capture, "ordered_nodes": count, "bytes": q.Bytes, "hops": rows, "measured_at": time.Now().UTC(), "note": "Each row measures an upload and a download through the original route to that position. Paired nodes use their authenticated Router API. Custom nodes use the public benchmark shown in their row."}
	current.addOrderedPerformanceSource(payload)
	payload["execution"] = graph.Execution
	_ = json.NewEncoder(w).Encode(payload)
}
