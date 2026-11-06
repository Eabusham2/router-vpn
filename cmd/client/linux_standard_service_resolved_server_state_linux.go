//go:build linux

package main

import (
	"context"
	"errors"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/standardengine"
)

func (h *linuxResolvedHelper) serverStateScoped(admission, operation context.Context, index int32, name string) (state standardengine.ResolvedServerState, failure error) {
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
	state, err = h.readServerState(frame, index, name)
	if err != nil {
		h.failure = errors.Join(h.failure, err)
	} else {
		err = admission.Err()
	}
	return state, err
}
func (h *linuxResolvedHelper) readServerState(ctx context.Context, index int32, name string) (state standardengine.ResolvedServerState, failure error) {
	if err := h.currentLocked(ctx); err != nil {
		return state, err
	}
	if h.policy == nil {
		if _, _, err := h.readObservation(ctx, h.name); err != nil {
			return state, err
		}
	}
	if h.sequence >= standardengine.MaxResolvedRequests-1 {
		return state, errors.New("original server-state frame budget exhausted")
	}
	h.sequence++
	request, err := (standardengine.ResolvedRequest{Schema: 1, CaptureSHA256: h.captureSHA, Sequence: h.sequence, Action: "server-state", Name: name, Index: index}).Canonical()
	if err != nil {
		return state, err
	}
	if err = h.peer.Send(ctx, request); err != nil {
		return state, err
	}
	raw, err := h.peer.Receive(ctx)
	if err != nil {
		return state, err
	}
	policy, err := standardengine.DecodeResolvedPolicy(h.policy, standardengine.SHA256(h.policy))
	if err != nil {
		return state, err
	}
	state, err = standardengine.DecodeResolvedServerStateFrame(raw, h.captureSHA, h.sequence, policy, name, index)
	if err != nil {
		return state, err
	}
	return state, h.currentLocked(ctx)
}
