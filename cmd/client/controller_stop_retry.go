package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"router-vpn/internal/desktopnetwork"
)

type controllerStatus struct {
	state
	StopPending bool   `json:"stop_pending"`
	StopToken   string `json:"stop_token,omitempty"`
}

func validStopRetryToken(token string) bool {
	if len(token) != 32 {
		return false
	}
	_, err := hex.DecodeString(token)
	return err == nil
}

// Capture presentation and its exact registered Stop receipt together. The
// established lock order is tracker -> app; status never invents Connected or
// installs an observer merely to read a cleanup flag.
func (a *app) controllerStatusContext(ctx context.Context) (controllerStatus, error) {
	if a == nil || ctx == nil {
		return controllerStatus{}, errors.New("controller status requires its original caller")
	}
	for {
		if err := ctx.Err(); err != nil {
			return controllerStatus{}, err
		}
		raw, found := sessionTrackers.Load(a)
		if !found {
			if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
				return controllerStatus{}, err
			}
			_, registered := sessionTrackers.Load(a)
			status := controllerStatus{state: a.state}
			a.mu.Unlock()
			if registered {
				continue
			}
			return status, ctx.Err()
		}
		t, valid := raw.(*sessionTracker)
		if !valid || t == nil || t.a != a {
			return controllerStatus{}, errors.New("controller status lost its registered DNS owner")
		}
		if err := desktopnetwork.LockContext(ctx, &t.mu); err != nil {
			return controllerStatus{}, err
		}
		if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
			t.mu.Unlock()
			return controllerStatus{}, err
		}
		current, registered := sessionTrackers.Load(a)
		status := controllerStatus{state: a.state}
		var err error
		if !registered || current != t {
			err = errors.New("controller status DNS owner changed during capture")
		} else if receipt := t.dnsProofStop; receipt != nil {
			err = receipt.currentLocked()
			if err == nil && !validStopRetryToken(receipt.token) {
				err = errors.New("controller status lost its original Stop retry token")
			}
			if err == nil {
				status.StopPending, status.StopToken = true, receipt.token
			}
		}
		a.mu.Unlock()
		t.mu.Unlock()
		return status, errors.Join(ctx.Err(), err)
	}
}

// operationMu is already held. A delayed UI click can only acquire the exact
// outstanding receipt it rendered, never a new tracker with the same epoch.
func (a *app) captureStopRetryContext(ctx context.Context, token string) (*sessionDNSStopReceipt, error) {
	raw, found := sessionTrackers.Load(a)
	t, valid := raw.(*sessionTracker)
	if !found || !valid || t == nil || t.a != a || !validStopRetryToken(token) {
		return nil, errors.New("the displayed Stop retry is no longer current; refresh status")
	}
	if err := desktopnetwork.LockContext(ctx, &t.mu); err != nil {
		return nil, err
	}
	defer t.mu.Unlock()
	receipt := t.dnsProofStop
	if receipt == nil || receipt.token != token {
		return nil, errors.New("the displayed Stop retry is no longer current; refresh status")
	}
	if err := receipt.currentLocked(); err != nil {
		return nil, err
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	closing := a.controllerClosingLocked()
	a.mu.Unlock()
	if closing {
		return nil, errControllerClosing
	}
	return receipt, ctx.Err()
}

func (a *app) retryDisconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var request struct {
		StopToken string `json:"stop_token"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || !validStopRetryToken(request.StopToken) {
		http.Error(w, "Stop retry requires the displayed cleanup token", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		http.Error(w, "Stop retry requires one captured request", http.StatusBadRequest)
		return
	}
	if err := desktopnetwork.LockContext(r.Context(), &a.operationMu); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	defer a.operationMu.Unlock()
	receipt, err := a.captureStopRetryContext(r.Context(), request.StopToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	// Token admission precedes even cancellation. An expired displayed retry
	// must not cancel or tear down a replacement connection transaction.
	if err := a.cancelCapturedStopContext(r.Context(), receipt); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if err := finishViaEntryCancellationContext(r.Context(), a); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if err := a.stopModeWithDNSReceiptContext(r.Context(), false, receipt); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = io.WriteString(w, `{"ok":true}`)
}
