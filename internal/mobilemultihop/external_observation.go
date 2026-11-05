package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/multihoprelay"
	"router-vpn/internal/nativeopenvpn"
)

// Observation locks belong to the caller, never to a detached timeout worker.
func externalObservationLock(ctx context.Context, mu *sync.Mutex) error {
	if ctx == nil {
		return errors.New("external observation has no caller")
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if mu.TryLock() {
			if err := ctx.Err(); err != nil {
				mu.Unlock()
				return err
			}
			return nil
		}
		timer := time.NewTimer(time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
func externalObservedIdentity(ctx context.Context, engine any) (string, error) {
	if ctx == nil {
		return "", errors.New("external observation has no caller")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	reader, ok := engine.(interface {
		IdentityContext(context.Context) (string, error)
	})
	if !ok {
		return "", errors.New("external engine has no bounded identity observation")
	}
	return reader.IdentityContext(ctx)
}
func externalObservedSelection(ctx context.Context, engine any) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	reader, ok := engine.(interface {
		SelectedContext(context.Context) (string, error)
	})
	if !ok {
		return "", errors.New("external engine has no bounded selection observation")
	}
	return reader.SelectedContext(ctx)
}
func externalObservedRemote(ctx context.Context, engine any, tag string) (nativeopenvpn.RemoteReceipt, error) {
	if err := ctx.Err(); err != nil {
		return nativeopenvpn.RemoteReceipt{}, err
	}
	reader, ok := engine.(interface {
		OpenVPNRemoteContext(context.Context, string) (nativeopenvpn.RemoteReceipt, error)
	})
	if !ok {
		return nativeopenvpn.RemoteReceipt{}, errors.New("external engine has no bounded connected-remote observation")
	}
	return reader.OpenVPNRemoteContext(ctx, tag)
}

func (r *ExternalProofRequest) HealthyContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("external proof observation has no caller")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if r == nil || r.ctx.Err() != nil || !r.succeeded.Load() {
		return errors.New("external proof is no longer retained")
	}
	identity, err := externalObservedIdentity(ctx, r.engine)
	if err != nil {
		return err
	}
	if identity == "" || identity != r.identity {
		return errors.New("external proof graph identity changed")
	}
	if r.openvpnTransport != nil {
		expected := r.openvpnRemote.Load()
		if expected == nil {
			return errors.New("external OpenVPN proof has no original connected remote")
		}
		actual, err := externalObservedRemote(ctx, r.engine, ExternalFinalTag)
		if err != nil {
			return err
		}
		if actual != *expected {
			return errors.New("external OpenVPN connected remote changed")
		}
	}
	if r.execution != nil {
		if err := r.execution.HealthyContext(ctx); err != nil {
			return err
		}
	}
	if r.ctx.Err() != nil || !r.succeeded.Load() {
		return errors.New("external proof retired during observation")
	}
	return ctx.Err()
}

func (c *Controller) HealthyContext(ctx context.Context) error {
	if c == nil {
		return errors.New("external execution is unavailable")
	}
	if err := externalObservationLock(ctx, &c.mu); err != nil {
		return err
	}
	engine, identity, outcome := c.engine, c.engineID, c.progress.Execution
	complete := c.progress.Complete && c.progress.Stage == "selected"
	c.mu.Unlock()
	if !complete || engine == nil || identity == "" || (outcome != "local" && outcome != "server") || c.generation.Load() != 1 {
		return errors.New("external execution is not retained")
	}
	observed, err := externalObservedIdentity(ctx, engine)
	if err != nil {
		return err
	}
	if observed != identity {
		return errors.New("external execution graph changed")
	}
	tag := LocalTag
	if outcome == "server" {
		tag = ServerTag
	}
	selected, err := externalObservedSelection(ctx, engine)
	if err != nil {
		return err
	}
	if selected != tag {
		return errors.New("external execution selection changed")
	}
	if c.openvpnResponses != nil {
		active := c.openvpnActive.Load()
		if active == nil || active.tag != tag || !time.Now().Before(active.deadline) {
			return errors.New("external OpenVPN observation expired")
		}
		if tag == LocalTag {
			actual, err := externalObservedRemote(ctx, engine, tag)
			if err != nil {
				return err
			}
			if actual != active.receipt {
				return errors.New("external OpenVPN remote changed")
			}
		}
	}
	if err := externalObservationLock(ctx, &c.mu); err != nil {
		return err
	}
	defer c.mu.Unlock()
	if c.generation.Load() != 1 || !c.progress.Complete || c.progress.Stage != "selected" || c.progress.Execution != outcome || c.engine != engine || c.engineID != identity || (outcome == "server" && !c.leaseFresh()) {
		return errors.New("external execution changed during observation")
	}
	return ctx.Err()
}

func (c *Controller) readOpenVPNRemoteContext(ctx context.Context, tag string) (nativeopenvpn.RemoteReceipt, error) {
	var receipt nativeopenvpn.RemoteReceipt
	if err := c.HealthyContext(ctx); err != nil {
		return receipt, err
	}
	selected, err := externalObservedSelection(ctx, c.engine)
	if err != nil {
		return receipt, err
	}
	if c.openvpnResponses == nil || selected != tag {
		return receipt, errors.New("external OpenVPN observation has another candidate")
	}
	if tag == LocalTag {
		receipt, err = externalObservedRemote(ctx, c.engine, tag)
		if err != nil {
			return receipt, err
		}
	} else if tag == ServerTag {
		if err := externalObservationLock(ctx, &c.leaseMu); err != nil {
			return receipt, err
		}
		request, owns := c.proposal, c.ownsLease
		c.leaseMu.Unlock()
		if !owns || !c.leaseFresh() {
			return receipt, errors.New("external OpenVPN lease is retired")
		}
		raw, _ := json.Marshal(request)
		data, err := c.leaseRequest(ctx, "POST", raw)
		if err != nil {
			return receipt, err
		}
		var response multihoprelay.OpenVPNLeaseRemote
		if exactJSON(data, &response, 8192) != nil || response.NodeID != c.meta.EntryNodeID || response.ExitID != request.ExitID || response.SessionID != request.SessionID || response.ExternalFingerprint != request.ExternalFingerprint || response.ExternalEpoch != request.ExternalEpoch || response.ExternalAttempt != request.ExternalAttempt {
			return receipt, errors.New("external OpenVPN lease response has another owner")
		}
		if err := externalObservationLock(ctx, &c.leaseMu); err != nil {
			return receipt, err
		}
		same := c.proposal == request && c.ownsLease
		c.leaseMu.Unlock()
		if !same || !c.leaseFresh() {
			return receipt, errors.New("external OpenVPN lease changed during observation")
		}
		receipt = response.Remote
	} else {
		return receipt, errors.New("external OpenVPN candidate is invalid")
	}
	if !receipt.Matches(c.openvpnTransport) || c.openvpnResponses[receipt.Host].Validate(receipt.Host) != nil {
		return nativeopenvpn.RemoteReceipt{}, errors.New("external OpenVPN remote violates the captured transport")
	}
	if err := c.HealthyContext(ctx); err != nil {
		return nativeopenvpn.RemoteReceipt{}, err
	}
	return receipt, nil
}

// A failed read revokes admission synchronously, but never waits for teardown.
// The original connection owner still joins its workers/leases in Close.
func (r *ExternalProofRequest) VerifyCurrentPathContext(ctx context.Context) (failure error) {
	defer func() {
		if failure != nil && r != nil && !common.ObservationContextExpired(ctx, failure) {
			r.succeeded.Store(false)
			r.cancel()
			if r.execution != nil {
				r.execution.generation.Add(1)
			}
		}
	}()
	if err := r.HealthyContext(ctx); err != nil {
		return err
	}
	if r.execution == nil {
		return ctx.Err()
	}
	c := r.execution
	if c.openvpnResponses == nil {
		return ctx.Err()
	}
	captured := c.openvpnActive.Load()
	if captured == nil {
		return errors.New("external OpenVPN path has no retained receipt")
	}
	receipt, err := c.readOpenVPNRemoteContext(ctx, captured.tag)
	if err != nil {
		return err
	}
	if receipt != captured.receipt {
		return errors.New("external OpenVPN remote changed during the captured operation")
	}
	for {
		if err := c.HealthyContext(ctx); err != nil {
			return err
		}
		current := c.openvpnActive.Load()
		if current == nil || current.tag != captured.tag || current.receipt != captured.receipt || !time.Now().Before(current.deadline) {
			return errors.New("external OpenVPN path changed before receipt adoption")
		}
		next := &openVPNRemoteState{tag: current.tag, receipt: current.receipt, deadline: time.Now().Add(openVPNRemoteFreshness)}
		if err := ctx.Err(); err != nil {
			return err
		}
		if c.openvpnActive.CompareAndSwap(current, next) {
			return nil
		}
	}
}
