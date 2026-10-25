package multihoprelay

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/netip"
	"time"
)

// External challenges are issued only on an authenticated, entry-routed GET.
// Peer is the actual caller observed by that entry, not a client-supplied IP.
// Epoch changes at every Manager restart. A short-lived, signed attempt can
// acquire once; its live lease alone may renew past the acquisition deadline.
type ExternalPacketChallenge struct {
	Epoch     string `json:"epoch"`
	Peer      string `json:"peer"`
	ExpiresAt int64  `json:"expires_at"`
}

const packetAcquireLifetime = 60 * time.Second
const maxPacketAttempts = 4096

var ErrExternalUpgradeRequired = errors.New("external relay acquisition requires an authenticated challenge; upgrade the client and entry server")

func (c ExternalPacketChallenge) Validate() error {
	peer, err := netip.ParseAddr(c.Peer)
	if !proofID.MatchString(c.Epoch) || err != nil || peer.Zone() != "" || peer.Is4In6() || peer.String() != c.Peer || !peer.IsGlobalUnicast() || c.ExpiresAt <= 0 {
		return ErrOwnership
	}
	return nil
}

func (m *Manager) PacketChallenge(peer netip.Addr) (ExternalPacketChallenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ExternalPacketChallenge{}, ErrUnavailable
	}
	challenge := ExternalPacketChallenge{Epoch: m.packetEpoch, Peer: PeerKey(peer), ExpiresAt: m.now().Add(packetAcquireLifetime).Unix()}
	if err := challenge.Validate(); err != nil {
		return ExternalPacketChallenge{}, err
	}
	return challenge, nil
}

func validatePacketRequestShape(q Request, allowPrepared bool) error {
	empty := q.ExternalEpoch == "" && q.ExternalPeer == "" && q.ExternalExpiresAt == 0 && q.ExternalAttempt == ""
	if !externalRequestRequiresChallenge(q) {
		if !empty {
			return ErrOwnership
		}
		return nil
	}
	if empty && allowPrepared {
		return nil
	}
	if empty {
		return ErrExternalUpgradeRequired
	}
	if !nonce.MatchString(q.ExternalAttempt) || q.ExternalFingerprint == "" {
		return ErrOwnership
	}
	return (ExternalPacketChallenge{Epoch: q.ExternalEpoch, Peer: q.ExternalPeer, ExpiresAt: q.ExternalExpiresAt}).Validate()
}

func externalRequestRequiresChallenge(q Request) bool {
	// Native Router exits share some protocol names with external exits. Their
	// separately authenticated node requests must retain their existing shape.
	return q.ExternalFingerprint != "" || ExternalIndependentMode(q.ExitMode)
}

// ChallengeExternalPacketRequest creates a fresh acquisition identity while
// retaining the captured session, private peer, final listener and graph.
// Compare's repeated winner proof must acquire a new attempt after trial close.
func ChallengeExternalPacketRequest(exit Exit, q Request, challenge ExternalPacketChallenge) (Request, error) {
	return ChallengeExternalRequest(exit, q, challenge)
}

// ChallengeExternalRequest preserves existing paired v1/v2 secrets and public
// fingerprints while binding every new external acquisition to one entry
// restart, observed peer, deadline and random attempt. Unsafe old unchallenged
// requests are not a compatibility fallback.
func ChallengeExternalRequest(exit Exit, q Request, challenge ExternalPacketChallenge) (Request, error) {
	if !ExternalMode(exit.Mode) || exit.External == nil || ExternalIndependentMode(exit.Mode) && externalIndependentOwner(exit) != "client" || challenge.Validate() != nil {
		return Request{}, ErrOwnership
	}
	// AuthenticateExternalRequest validates the complete immutable capture.
	// Clearing old authentication/challenge fields cannot import another graph.
	q.ExternalEpoch, q.ExternalPeer, q.ExternalExpiresAt = challenge.Epoch, challenge.Peer, challenge.ExpiresAt
	var attempt [16]byte
	if _, err := rand.Read(attempt[:]); err != nil {
		return Request{}, errors.New("packet acquisition identity could not be generated")
	}
	q.ExternalAttempt = hex.EncodeToString(attempt[:])
	return AuthenticateExternalRequest(exit, q)
}

func (m *Manager) sweepPacketAttemptsLocked() {
	now := m.now().Unix()
	for key, expiry := range m.packetAttempts {
		if expiry <= now {
			delete(m.packetAttempts, key)
		}
	}
}

func (m *Manager) validateNewPacketAttemptLocked(q Request) error {
	if !externalRequestRequiresChallenge(q) {
		return nil
	}
	now := m.now()
	if q.ExternalExpiresAt <= now.Unix() || q.ExternalExpiresAt > now.Add(packetAcquireLifetime).Unix() {
		return ErrOwnership
	}
	if _, used := m.packetAttempts[q.ExternalAuthentication]; used {
		return ErrOwnership
	}
	if len(m.packetAttempts) >= maxPacketAttempts {
		return ErrBusy
	}
	return nil
}

func (m *Manager) rememberPacketAttemptLocked(q Request) error {
	if !externalRequestRequiresChallenge(q) {
		return nil
	}
	m.sweepPacketAttemptsLocked()
	// Expired requests are already unusable for acquisition. Their DELETE is
	// still idempotent and may clean an existing long-lived owned lease.
	if q.ExternalExpiresAt <= m.now().Unix() {
		return nil
	}
	if q.ExternalExpiresAt > m.now().Add(packetAcquireLifetime).Unix() {
		return ErrOwnership
	}
	if _, exists := m.packetAttempts[q.ExternalAuthentication]; exists {
		return nil
	}
	if len(m.packetAttempts) >= maxPacketAttempts {
		return ErrBusy
	}
	m.packetAttempts[q.ExternalAuthentication] = q.ExternalExpiresAt
	return nil
}
