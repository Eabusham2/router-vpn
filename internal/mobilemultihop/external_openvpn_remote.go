package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"router-vpn/internal/multihoprelay"
	"router-vpn/internal/nativeopenvpn"
)

// This read-only interface is implemented by the exact native Box owner.
// It observes an established TLS/data channel; a live process or selected
// configuration alone must never produce a connected remote receipt.
type OpenVPNRemoteEngine interface {
	OpenVPNRemote(string) (nativeopenvpn.RemoteReceipt, error)
}

const openVPNRemoteFreshness = 2 * time.Second

type openVPNRemoteState struct {
	tag      string
	receipt  nativeopenvpn.RemoteReceipt
	deadline time.Time
}

func (c *Controller) readOpenVPNRemote(ctx context.Context, tag string) (nativeopenvpn.RemoteReceipt, error) {
	bad := errors.New("OpenVPN connected remote is unavailable or no longer belongs to the captured candidate")
	if c.openvpnResponses == nil || ctx.Err() != nil || c.requireValid() != nil || c.engine.Selected() != tag {
		return nativeopenvpn.RemoteReceipt{}, bad
	}
	var receipt nativeopenvpn.RemoteReceipt
	if tag == LocalTag {
		engine, ok := c.engine.(OpenVPNRemoteEngine)
		if !ok {
			return receipt, bad
		}
		var err error
		receipt, err = engine.OpenVPNRemote(tag)
		if err != nil {
			return receipt, err
		}
	} else if tag == ServerTag {
		c.leaseMu.Lock()
		request, owns := c.proposal, c.ownsLease
		c.leaseMu.Unlock()
		if !owns || !c.leaseFresh() {
			return receipt, bad
		}
		raw, _ := json.Marshal(request)
		data, err := c.leaseRequest(ctx, "POST", raw)
		if err != nil {
			return receipt, err
		}
		var response multihoprelay.OpenVPNLeaseRemote
		if exactJSON(data, &response, 8192) != nil || response.NodeID != c.meta.EntryNodeID || response.ExitID != request.ExitID || response.SessionID != request.SessionID || response.ExternalFingerprint != request.ExternalFingerprint || response.ExternalEpoch != request.ExternalEpoch || response.ExternalAttempt != request.ExternalAttempt {
			return receipt, bad
		}
		c.leaseMu.Lock()
		same := c.proposal == request && c.ownsLease
		c.leaseMu.Unlock()
		if !same || !c.leaseFresh() {
			return receipt, bad
		}
		receipt = response.Remote
	} else {
		return receipt, bad
	}
	if !receipt.Matches(c.openvpnTransport) || c.openvpnResponses[receipt.Host].Validate(receipt.Host) != nil || ctx.Err() != nil || c.requireValid() != nil || c.engine.Selected() != tag {
		return nativeopenvpn.RemoteReceipt{}, bad
	}
	return receipt, nil
}

func (c *Controller) awaitOpenVPNRemote(ctx context.Context, tag string) (nativeopenvpn.RemoteReceipt, error) {
	if tag == LocalTag {
		if _, ok := c.engine.(OpenVPNRemoteEngine); !ok {
			return nativeopenvpn.RemoteReceipt{}, errors.New("native core requires connected OpenVPN remote receipt support")
		}
	}
	for {
		receipt, err := c.readOpenVPNRemote(ctx, tag)
		if err == nil {
			return receipt, nil
		}
		var control controlError
		pending := errors.Is(err, nativeopenvpn.ErrRemotePending) || errors.As(err, &control) && control.status == 503
		if !pending || ctx.Err() != nil {
			return nativeopenvpn.RemoteReceipt{}, err
		}
		timer := time.NewTimer(40 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nativeopenvpn.RemoteReceipt{}, ctx.Err()
		case <-timer.C:
		}
	}
}

func (s *trial) checkOpenVPNRemote(ctx context.Context) error {
	if s.owner.openvpnResponses == nil {
		return nil
	}
	if s.openvpnRemote == nil {
		return errors.New("OpenVPN candidate has no connected remote receipt")
	}
	actual, err := s.owner.readOpenVPNRemote(ctx, s.tag)
	if err != nil || actual != *s.openvpnRemote {
		return errors.New("OpenVPN remote or transport generation changed during candidate proof")
	}
	return nil
}

func (c *Controller) openVPNRemoteHealthy(tag string) bool {
	if c.openvpnResponses == nil {
		return true
	}
	active := c.openvpnActive.Load()
	if active == nil || active.tag != tag || !time.Now().Before(active.deadline) {
		return false
	}
	if tag == LocalTag {
		engine, ok := c.engine.(OpenVPNRemoteEngine)
		if !ok {
			return false
		}
		receipt, err := engine.OpenVPNRemote(tag)
		return err == nil && receipt == active.receipt
	}
	return tag == ServerTag
}

// VerifyCurrentPath is a synchronous measurement/adoption boundary. A server
// candidate must answer a fresh authenticated native query; its health cache is
// never sufficient for publishing a new MTU or Speed Lab result.
func (c *Controller) VerifyCurrentPath(ctx context.Context) error {
	if !c.Healthy() || ctx.Err() != nil {
		return errors.New("captured external path is no longer proved")
	}
	if c.openvpnResponses == nil {
		return nil
	}
	active := c.openvpnActive.Load()
	if active == nil {
		return errors.New("captured OpenVPN path is unavailable")
	}
	receipt, err := c.readOpenVPNRemote(ctx, active.tag)
	if err != nil || receipt != active.receipt || !c.refreshOpenVPNRemote(active) || !c.Healthy() || ctx.Err() != nil {
		c.invalidate()
		return errors.New("OpenVPN remote changed during the captured operation")
	}
	return nil
}

func (c *Controller) refreshOpenVPNRemote(captured *openVPNRemoteState) bool {
	for {
		current := c.openvpnActive.Load()
		if captured == nil || current == nil || current.tag != captured.tag || current.receipt != captured.receipt || !c.valid() || !time.Now().Before(current.deadline) {
			return false
		}
		next := &openVPNRemoteState{tag: current.tag, receipt: current.receipt, deadline: time.Now().Add(openVPNRemoteFreshness)}
		if c.openvpnActive.CompareAndSwap(current, next) {
			return true
		}
	}
}

func (c *Controller) watchOpenVPNRemote() {
	ctx, cancel := context.WithCancel(context.Background())
	c.mu.Lock()
	c.openvpnRemoteCancel = cancel
	c.openvpnRemoteDone = make(chan struct{})
	done := c.openvpnRemoteDone
	c.mu.Unlock()
	go func() {
		defer close(done)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			active := c.openvpnActive.Load()
			if active == nil || !c.valid() {
				return
			}
			child, stop := context.WithTimeout(ctx, 1500*time.Millisecond)
			receipt, err := c.readOpenVPNRemote(child, active.tag)
			stop()
			if ctx.Err() != nil {
				return
			}
			if err != nil || receipt != active.receipt {
				c.failed("OpenVPN remote changed or its owned runtime receipt expired; this path must be proved again.")
				c.invalidate()
				return
			}
			// Another fresh measurement may already have extended this same
			// receipt while the watch was awaiting its private response. The
			// current CAS owner, not this old snapshot's deadline, is authority.
			// A replaced or actually expired current owner is still rejected.
			if !c.refreshOpenVPNRemote(active) {
				c.invalidate()
				return
			}
		}
	}()
}
