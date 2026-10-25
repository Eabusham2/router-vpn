package multihoprelay

import (
	"context"
	"errors"
	"net/netip"

	"router-vpn/internal/nativeopenvpn"
)

// OpenVPNRemoteProcess attests only the native endpoint inside this exact
// leased process. Implementations must bind the snapshot to their owned source
// and session, reject stale heartbeats, and check process liveness after reading.
type OpenVPNRemoteProcess interface {
	Process
	OpenVPNRemote(context.Context) (nativeopenvpn.RemoteReceipt, error)
}

// OpenVPNLeaseRemote is returned only to the authenticated tunnel peer that
// owns the exact signed acquisition. It exposes no provider identity or secret.
type OpenVPNLeaseRemote struct {
	NodeID              string                      `json:"node_id"`
	SessionID           string                      `json:"session_id"`
	ExitID              string                      `json:"exit_id"`
	ExternalFingerprint string                      `json:"external_fingerprint"`
	ExternalEpoch       string                      `json:"external_epoch"`
	ExternalAttempt     string                      `json:"external_attempt"`
	Remote              nativeopenvpn.RemoteReceipt `json:"remote"`
}

func (m *Manager) OpenVPNRemote(ctx context.Context, peer netip.Addr, q Request) (OpenVPNLeaseRemote, error) {
	if err := ctx.Err(); err != nil {
		return OpenVPNLeaseRemote{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return OpenVPNLeaseRemote{}, err
	}
	if m.closed {
		return OpenVPNLeaseRemote{}, ErrUnavailable
	}
	if err := m.validate(peer, q); err != nil {
		return OpenVPNLeaseRemote{}, err
	}
	active := m.leases[PeerKey(peer)]
	if active == nil || active.Request != q || active.retired {
		return OpenVPNLeaseRemote{}, ErrOwnership
	}
	if !active.OpenVPNRemote || !active.ExpiresAt.After(m.now()) || !active.p.Alive() {
		return OpenVPNLeaseRemote{}, ErrUnavailable
	}
	owner, ok := active.p.(OpenVPNRemoteProcess)
	if !ok {
		return OpenVPNLeaseRemote{}, ErrUnavailable
	}
	var selected *Exit
	for i := range m.cfg.Exits {
		exit := &m.cfg.Exits[i]
		if exit.ID == q.ExitID && exit.Mode == q.ExitMode && ExitLayerMode(*exit) == q.ExitStartLayer {
			selected = exit
			break
		}
	}
	if selected == nil || !OpenVPNRemoteRequired(*selected) || ValidateExternalRequest(*selected, q) != nil {
		return OpenVPNLeaseRemote{}, ErrOwnership
	}
	receipt, err := owner.OpenVPNRemote(ctx)
	if err != nil || ctx.Err() != nil || !active.p.Alive() || !active.ExpiresAt.After(m.now()) {
		return OpenVPNLeaseRemote{}, ErrUnavailable
	}
	if !receipt.Matches(selected.Transport) {
		return OpenVPNLeaseRemote{}, errors.New("native OpenVPN remote does not match the owned provider transport")
	}
	return OpenVPNLeaseRemote{NodeID: m.node, SessionID: q.SessionID, ExitID: q.ExitID, ExternalFingerprint: q.ExternalFingerprint, ExternalEpoch: q.ExternalEpoch, ExternalAttempt: q.ExternalAttempt, Remote: receipt}, nil
}
