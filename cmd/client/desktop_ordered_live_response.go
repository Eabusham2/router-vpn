package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/hopmeasure"
)

func (a *app) orderedLiveResponse(parent context.Context, graph activeMultihopGraph, entry, exit common.RouterProfile, samples int) ([2]connectionLatencyResult, error) {
	var output [2]connectionLatencyResult
	ctx, cancel := context.WithTimeout(parent, hopmeasure.PathResponseTimeout)
	defer cancel()
	identity, _, err := captureSpeedLabIdentityContext(ctx, a)
	if err != nil || identity.Ordered == nil || !sameActiveMultihopGraph(identity.Graph, graph) || graph.mapRouteID() == "" {
		return output, errors.Join(err, errors.New("ordered live response lost the original running route"))
	}
	launch := identity.Ordered.launch
	profiles := [2]common.RouterProfile{entry, exit}
	frozen := launch.chain.selection.Nodes
	if len(frozen) != graph.ChainNodes || frozen[0].Profile.ID != entry.ID || frozen[len(frozen)-1].Profile.ID != exit.ID {
		return output, errors.New("ordered live response changed its original private endpoints")
	}
	current := func(call context.Context) error { return validateSpeedLabIdentityContext(call, a, identity) }
	if err := current(ctx); err != nil {
		return output, err
	}
	release, err := a.holdIdleTelemetryMTU(ctx, func() {
		original, ok := nativeMultihopOwners.Load(a)
		if ok && original == identity.Ordered {
			a.startRouterNodeAutomaticMTU()
		}
	})
	if err != nil {
		return output, err
	}
	hold, err := bindDesktopNodeChainMeasurementHold(ctx, launch, release)
	if err != nil {
		return output, err
	}

	var status hopmeasure.Status
	var nonce string
	var at int64
	var prefix string
	if launch.chain.execution == nil {
		result, exchangeErr := exchangeDesktopNodeChainOperation(ctx, launch, current, nil, samples)
		if errors.Is(exchangeErr, errDesktopNodeChainMeasurementPending) && result.Request != "" {
			go func() { waitDesktopOrderedLatencyDrain(launch, result.desktopNodeChainMeasurementRequest); hold(true) }()
			return output, exchangeErr
		}
		defer hold(true)
		if exchangeErr != nil {
			return output, exchangeErr
		}
		nonce, status, at = result.Request, result.Status, result.CompletedAt
	} else {
		publication, ready, capture, nodes, err := readDesktopSelectedLatencyCapture(ctx, launch)
		if err != nil || capture.Execution != graph.Execution || len(nodes) != len(frozen) {
			hold(true)
			return output, errors.Join(err, errors.New("ordered live response lost its selected source"))
		}
		selectedCurrent := func(call context.Context) error {
			if err := current(call); err != nil {
				return err
			}
			live, latest, _, _, err := readDesktopSelectedLatencyCapture(call, launch)
			if err != nil || live.Selected != publication.Selected || !sameDesktopSelectedLatencyReady(ready, latest) {
				return errors.Join(err, errors.New("ordered live response changed its selected source"))
			}
			return call.Err()
		}
		last := nodes[len(nodes)-1]
		nonce, err = randomHex(16)
		if err != nil {
			hold(true)
			return output, err
		}
		request := desktopOrderedLatencyRequest{Request: nonce, NodeID: last.NodeID, Position: last.Position, Capture: desktopOrderedLatencyCapture{
			SessionID: identity.SessionID, ProfileID: identity.RouterID, ProfileToken: identity.ProfileToken, SourceSHA256: capture.SourceSHA256, ConfigSHA256: capture.ConfigSHA256,
			GenerationSHA256: capture.GenerationSHA256, SelectedCaptureJSON: publication.Selected}}
		if len(nodes) > 8 {
			request.Capture.ExtendedOriginalNodes = launch.chain.execution.preparation.ExtendedOriginalNodeCount()
		}
		result, exchangeErr := exchangeDesktopSelectedOperation(ctx, launch, selectedCurrent, request, 0, samples)
		if errors.Is(exchangeErr, errDesktopNodeChainMeasurementPending) && result.Request != "" {
			go func() {
				waitDesktopSelectedThroughputDrain(launch, result.desktopSelectedLatencyRequest, result.throughputFile)
				hold(true)
			}()
			return output, exchangeErr
		}
		defer hold(true)
		if exchangeErr != nil {
			return output, exchangeErr
		}
		if err := selectedCurrent(ctx); err != nil {
			return output, err
		}
		prefix = " " + capture.Execution
		status, at = result.Status, result.CompletedAt
	}
	endpoints := [2]hopmeasure.Hop{
		{ID: entry.ID, Kind: "private-node", Label: fmt.Sprintf("Cumulative%s path through node 1 of %d", prefix, len(frozen))},
		{ID: exit.ID, Kind: "private-node", Label: fmt.Sprintf("Cumulative%s path through node %d of %d", prefix, len(frozen), len(frozen))},
	}
	if frozen[0].Profile.NodeKind == "external" {
		endpoints[0].Kind = "public-path"
	}
	if frozen[len(frozen)-1].Profile.NodeKind == "external" {
		_, meta, _, err := launch.chain.readLaunchPolicy()
		if err != nil || launch.chain.execution != nil || !desktopNodeChainMetadataMatchesSelection(meta, launch.chain.selection) ||
			meta.ExternalFinal == nil || launch.chain.selection.Native == nil || launch.chain.selection.Native.chain == nil ||
			launch.chain.selection.Native.chain.chain == nil || !launch.chain.selection.Native.chain.chain.HasExternalFinal() {
			return output, errors.Join(err, errors.New("ordered public response lost its original external exit"))
		}
		endpoints[1].Kind, endpoints[1].Tag = "public-path", meta.FinalTag
		endpoints[1].Label = fmt.Sprintf("Cumulative path through custom node %d of %d → Cloudflare edge", len(frozen), len(frozen))
	}
	measured, err := hopmeasure.OrderedResponseLatencies(status, nonce, samples, endpoints)
	if err != nil {
		return output, err
	}
	for i, d := range measured {
		if i == 0 && endpoints[i].Kind == "public-path" {
			continue
		}
		proof := endpoints[i].Label + " · authenticated private HTTP response"
		if endpoints[i].Kind == "public-path" {
			proof = endpoints[i].Label + " · HTTPS response after TLS through the captured external exit"
		}
		output[i] = connectionLatencyResult{Connected: true, Mode: "multihop", RouterID: profiles[i].ID, Name: profiles[i].Name, Samples: samples,
			MinMs: d.Min, MedianMs: d.Median, AverageMs: d.Average, P90Ms: d.P90, MaxMs: d.Max, MeasuredAt: time.UnixMilli(at).UTC(), Proof: proof}
	}
	return output, current(ctx)
}
