package main

import (
	"context"
	"errors"
	"strings"

	"router-vpn/internal/desktopnetwork"
)

// speedLabHopMeasurement is an independently measured view of one node inside
// an actually launched multihop graph. Latency and throughput are never derived
// from another hop or from the end-to-end Speed Lab result.
type speedLabHopMeasurement struct {
	Role         string                   `json:"role"`
	RouterID     string                   `json:"router_id"`
	Name         string                   `json:"name"`
	LatencyLabel string                   `json:"latency_label,omitempty"`
	SpeedLabel   string                   `json:"speed_label,omitempty"`
	Latency      *connectionLatencyResult `json:"latency,omitempty"`
	Speed        *routedSpeedResult       `json:"speed,omitempty"`
	LatencyError string                   `json:"latency_error,omitempty"`
	SpeedError   string                   `json:"speed_error,omitempty"`
}

func measureSpeedLabMultihopHops(a *app, identity speedLabPathIdentity) ([]speedLabHopMeasurement, error) {
	return measureSpeedLabMultihopHopsContext(context.Background(), a, identity)
}

func measureSpeedLabMultihopHopsContext(ctx context.Context, a *app, identity speedLabPathIdentity) ([]speedLabHopMeasurement, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !identity.GraphOK || strings.TrimSpace(identity.Graph.EntryID) == "" || strings.TrimSpace(identity.Graph.ExitID) == "" || identity.Graph.EntryID == identity.Graph.ExitID {
		return nil, errors.New("Speed Lab per-hop measurement requires an exact active multihop graph")
	}
	if err := validateSpeedLabIdentityContext(ctx, a, identity); err != nil {
		return nil, err
	}

	if identity.Ordered != nil {
		return measureSpeedLabOrderedHops(ctx, a, identity)
	}

	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	st := a.state
	entry, entryOK := a.profileByIDLocked(identity.Graph.EntryID)
	exit, exitOK := a.profileByIDLocked(identity.Graph.ExitID)
	entry, exit = cloneRouterProfile(entry), cloneRouterProfile(exit)
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
		p := exit
		if role == "entry" {
			p = entry
		}
		if p.ID != profileID {
			return speedLabHopMeasurement{}, errors.New("Speed Lab hop differs from its captured source")
		}
		if err := validateSpeedLabIdentityContext(ctx, a, identity); err != nil {
			return speedLabHopMeasurement{}, err
		}
		if role == "entry" && (p.External != nil || p.NodeKind == "external") {
			return measureSpeedLabImportedEntryHop(ctx, entry, func(call context.Context) error {
				return validateSpeedLabIdentityContext(call, a, identity)
			})
		}
		hop := speedLabHopMeasurement{Role: role, RouterID: p.ID, Name: pName, LatencyLabel: "Node HTTP response", SpeedLabel: "Node transfer"}

		latency, latencyErr := measureRoutedProfileLatencyViaProxyContext(ctx, p, 4, proxy)
		if err := ctx.Err(); err != nil {
			return speedLabHopMeasurement{}, err
		}
		if err := validateSpeedLabIdentityContext(ctx, a, identity); err != nil {
			return speedLabHopMeasurement{}, err
		}
		if latencyErr != nil {
			hop.LatencyError = latencyErr.Error()
		} else {
			hop.Latency = &latency
		}

		speed, speedErr := measureRoutedProfileSpeedViaProxyContext(ctx, p, 8<<20, proxy)
		if err := ctx.Err(); err != nil {
			return speedLabHopMeasurement{}, err
		}
		if err := validateSpeedLabIdentityContext(ctx, a, identity); err != nil {
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
	if err := validateSpeedLabIdentityContext(ctx, a, identity); err != nil {
		return nil, err
	}
	return []speedLabHopMeasurement{entryHop, exitHop}, nil
}
