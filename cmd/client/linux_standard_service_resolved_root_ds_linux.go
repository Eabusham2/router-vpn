//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/standardengine"
)

func (h *linuxResolvedHelper) rootDSScoped(admission, operation context.Context, index int32, name string) (state standardengine.ResolvedRootDSDecision, failure error) {
	if h == nil {
		return state, errors.New("server monitor omitted original helper")
	}
	if err := desktopnetwork.LockContext(admission, &h.mu); err != nil {
		return state, err
	}
	defer h.mu.Unlock()
	frame, end, err := resolvedFrameContext(admission, operation)
	if err != nil {
		return state, err
	}
	defer end()
	state, err = h.readRootDS(frame, index, name)
	if err != nil {
		h.failure = errors.Join(h.failure, err)
	} else {
		err = admission.Err()
	}
	return state, err
}
func (h *linuxResolvedHelper) readRootDS(ctx context.Context, index int32, name string) (state standardengine.ResolvedRootDSDecision, failure error) {
	if err := h.currentLocked(ctx); err != nil {
		return state, err
	}
	if h.policy == nil {
		if _, _, err := h.readObservation(ctx, h.name); err != nil {
			return state, err
		}
	}
	if h.sequence >= standardengine.MaxResolvedRequests-1 {
		return state, errors.New("original root-ds-decision frame budget exhausted")
	}
	h.sequence++
	request, err := (standardengine.ResolvedRequest{Schema: 1, CaptureSHA256: h.captureSHA, Sequence: h.sequence, Action: "root-ds-decision", Name: name, Index: index}).Canonical()
	if err != nil {
		return state, err
	}
	if err = h.peer.Send(ctx, request); err != nil {
		return state, err
	}
	var frames [][]byte
	for i := uint32(0); ; i++ {
		raw, err := h.peer.Receive(ctx)
		if err != nil {
			return state, err
		}
		var frame standardengine.ResolvedFrame
		if len(raw) > 12<<10 || json.Unmarshal(raw, &frame) != nil || frame.Parts == 0 || frame.Parts > 9 || frame.Part != i {
			return state, errors.New("root decision lost bounded ordered frames")
		}
		frames = append(frames, raw)
		if i+1 == frame.Parts {
			break
		}
		if i >= 8 {
			return state, errors.New("root decision exceeded frame bound")
		}
	}
	policy, err := standardengine.DecodeResolvedPolicy(h.policy, standardengine.SHA256(h.policy))
	if err != nil {
		return state, err
	}
	state, err = standardengine.DecodeResolvedRootDSFrames(frames, h.captureSHA, h.sequence, policy, name, index)
	if err != nil {
		return state, err
	}
	return state, h.currentLocked(ctx)
}
