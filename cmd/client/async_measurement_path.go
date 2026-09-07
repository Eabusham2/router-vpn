package main

import (
	"context"
	"errors"
	"net/http"
	"time"

	"router-vpn/internal/common"
)

// An asynchronous proof owns one immutable session and, for multihop, one
// particular graph generation. End-of-request validation alone would still let
// an old request keep using the network after disconnect or graph replacement.
func asyncMeasurementPathContext(parent context.Context, a *app, p common.RouterProfile, st state, session connectionSession, token string) (context.Context, func(), func() error, error) {
	graph, graphOK := getActiveMultihopGraph(a)
	if st.Mode == "multihop" {
		if err := validateActiveMultihopSpeedGraph(st, graph, graphOK, graph.EntryID, graph.ExitID); err != nil {
			return nil, nil, nil, err
		}
		if p.ID != graph.ExitID || session.RouterID != graph.ExitID {
			return nil, nil, nil, errors.New("live measurement must belong to the active multihop exit")
		}
	}
	profiles, err := captureMeasurementProfiles(a, st, graph, p)
	if err != nil {
		return nil, nil, nil, err
	}
	if profiles[p.ID] != token {
		return nil, nil, nil, errors.New("captured profile changed before live measurement")
	}
	binding := &asyncMeasurementAdoption{
		owner: a, session: session, stateToken: mtuStateSnapshotToken(st), profiles: profiles,
		multihop: st.Mode == "multihop", graph: graph, generation: homeExitProofs.generation(a),
	}
	// The observer and terminal persistence use the exact same immutable
	// binding. Stop cancels HTTP only; it never stops or replaces the VPN.
	ctx, stop, err := speedLabPathContext(parent, binding.validate)
	if err != nil {
		return nil, nil, nil, err
	}
	ctx = context.WithValue(ctx, asyncMeasurementBindingKey{}, binding)
	return ctx, stop, binding.validate, nil
}

// Private API addresses can overlap across hops. Multihop DNS/public-exit
// requests therefore use the runtime's reserved exit lane, never a guessed OS
// route or an environment proxy. Failure has no direct-route fallback.
func newAsyncMeasurementHTTPClient(st state, timeout time.Duration) (*http.Client, error) {
	if st.Mode == "multihop" {
		client, _, err := newMultihopLaneHTTPClient(multihopProofProxy, timeout)
		return client, err
	}
	return newRouteBoundHTTPClient(timeout), nil
}

func asyncMeasurementRequestError(w http.ResponseWriter, parent, measured context.Context, action string) bool {
	if parent.Err() != nil {
		http.Error(w, action+" was cancelled", http.StatusRequestTimeout)
		return true
	}
	if context.Cause(measured) != nil {
		http.Error(w, action+" was discarded because the active VPN session/path changed", http.StatusConflict)
		return true
	}
	return false
}
