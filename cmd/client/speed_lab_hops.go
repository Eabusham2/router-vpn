package main

import (
	"errors"
	"strings"
)

// speedLabHopMeasurement is an independently measured view of one node inside
// an actually launched multihop graph. Latency and throughput are never derived
// from another hop or from the end-to-end Speed Lab result.
type speedLabHopMeasurement struct {
	Role         string                   `json:"role"`
	RouterID     string                   `json:"router_id"`
	Name         string                   `json:"name"`
	Latency      *connectionLatencyResult `json:"latency,omitempty"`
	Speed        *routedSpeedResult       `json:"speed,omitempty"`
	LatencyError string                   `json:"latency_error,omitempty"`
	SpeedError   string                   `json:"speed_error,omitempty"`
}

func measureSpeedLabMultihopHops(a *app, identity speedLabPathIdentity) ([]speedLabHopMeasurement, error) {
	if !identity.GraphOK || strings.TrimSpace(identity.Graph.EntryID) == "" || strings.TrimSpace(identity.Graph.ExitID) == "" || identity.Graph.EntryID == identity.Graph.ExitID {
		return nil, errors.New("Speed Lab per-hop measurement requires an exact active multihop graph")
	}
	if err := validateSpeedLabIdentity(a, identity); err != nil {
		return nil, err
	}

	a.mu.Lock()
	st := a.state
	entry, entryOK := a.profileByIDLocked(identity.Graph.EntryID)
	exit, exitOK := a.profileByIDLocked(identity.Graph.ExitID)
	a.mu.Unlock()
	if !entryOK || !exitOK {
		return nil, errors.New("Speed Lab active multihop entry or exit disappeared")
	}
	if err := validateActiveMultihopSpeedGraph(st, identity.Graph, true, entry.ID, exit.ID); err != nil {
		return nil, err
	}

	measure := func(role string, profileID string, pName string) (speedLabHopMeasurement, error) {
		proxy := multihopProofProxy
		if role == "entry" {
			proxy = multihopEntryProofProxy
		} else if role != "exit" {
			return speedLabHopMeasurement{}, errors.New("unknown Speed Lab multihop role")
		}
		a.mu.Lock()
		p, ok := a.profileByIDLocked(profileID)
		a.mu.Unlock()
		if !ok {
			return speedLabHopMeasurement{}, errors.New("Speed Lab hop disappeared during measurement")
		}
		hop := speedLabHopMeasurement{Role: role, RouterID: p.ID, Name: pName}

		latency, latencyErr := measureRoutedProfileLatencyViaProxy(p, 4, proxy)
		if err := validateSpeedLabIdentity(a, identity); err != nil {
			return speedLabHopMeasurement{}, err
		}
		if latencyErr != nil {
			hop.LatencyError = latencyErr.Error()
		} else {
			hop.Latency = &latency
		}

		speed, speedErr := measureRoutedProfileSpeedViaProxy(p, 8<<20, proxy)
		if err := validateSpeedLabIdentity(a, identity); err != nil {
			return speedLabHopMeasurement{}, err
		}
		if speedErr != nil {
			hop.SpeedError = speedErr.Error()
		} else {
			hop.Speed = &speed
		}
		if hop.Latency == nil && hop.Speed == nil {
			return hop, errors.New("Speed Lab could not prove and measure latency or throughput for the " + role + " hop")
		}
		return hop, nil
	}

	entryHop, err := measure("entry", entry.ID, entry.Name)
	if err != nil {
		return nil, err
	}
	exitHop, err := measure("exit", exit.ID, exit.Name)
	if err != nil {
		return nil, err
	}
	if err := validateSpeedLabIdentity(a, identity); err != nil {
		return nil, err
	}
	return []speedLabHopMeasurement{entryHop, exitHop}, nil
}
