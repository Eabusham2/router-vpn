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
	// Reuse the joined path observer: it cancels HTTP only, never the VPN.
	validate := func() error {
		if err := validateAsyncMeasurementProfile(a, p, st, session, token); err != nil {
			return err
		}
		if st.Mode == "multihop" {
			if err := validateCurrentMultihopSpeedGraph(a, st, graph, session.ID); err != nil {
				return err
			}
		}
		return validateMeasurementProfiles(a, profiles)
	}
	ctx, stop, err := speedLabPathContext(parent, validate)
	return ctx, stop, validate, err
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
