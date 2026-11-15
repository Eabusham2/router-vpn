package mobilemultihop

import (
	"context"
	"errors"
	"time"

	"router-vpn/internal/multihoprelay"
	"router-vpn/internal/nativeopenvpn"
)

// The entry's authenticated packet capacity belongs to the original native
// endpoint. A profile, successful final dial, or replacement session cannot
// supply it. Observation is synchronous and bounded by its original caller.
type ExternalOpenVPNEntryEngine interface {
	OpenVPNEntryStateContext(context.Context, string) (nativeopenvpn.PacketObservation, error)
}

func (r *ExternalProofRequest) prepareOpenVPNEntry() error {
	external, _ := r.policy.capture.Entry["external"].(map[string]any)
	if external["protocol"] != "openvpn" {
		return nil
	}
	if r.policy.capture.Execution != nil || r.meta.EntryTag == "" || r.meta.EntryMTU < 1280 {
		return errors.New("OpenVPN entry has no captured local packet owner")
	}
	if _, ok := r.engine.(ExternalOpenVPNEntryEngine); !ok {
		return errors.New("OpenVPN entry requires bounded native capacity observation")
	}
	var err error
	r.openvpnEntryTransport, err = multihoprelay.ExternalTransport("openvpn", external)
	return err
}

func (r *ExternalProofRequest) observeOpenVPNEntry(ctx context.Context) (nativeopenvpn.PacketObservation, error) {
	var empty nativeopenvpn.PacketObservation
	if err := r.currentContext(ctx); err != nil {
		return empty, err
	}
	reader, ok := r.engine.(ExternalOpenVPNEntryEngine)
	if !ok {
		return empty, errors.New("OpenVPN entry lost its native observation owner")
	}
	state, err := reader.OpenVPNEntryStateContext(ctx, r.meta.EntryTag)
	if err != nil {
		return empty, err
	}
	if state.Validate() != nil || !state.Remote.Matches(r.openvpnEntryTransport) || state.MTU < uint32(r.meta.EntryMTU) {
		return empty, errors.New("OpenVPN entry connected transport or packet capacity differs from capture")
	}
	if err := r.currentContext(ctx); err != nil {
		return empty, err
	}
	return state, nil
}

func (r *ExternalProofRequest) captureOpenVPNEntry(ctx context.Context) error {
	if r.openvpnEntryTransport == nil {
		return nil
	}
	for {
		state, err := r.observeOpenVPNEntry(ctx)
		if err == nil {
			r.openvpnEntryState.Store(&state)
			return nil
		}
		if !errors.Is(err, nativeopenvpn.ErrRemotePending) {
			return err
		}
		timer := time.NewTimer(40 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-r.ctx.Done():
			timer.Stop()
			return r.ctx.Err()
		case <-timer.C:
		}
	}
}

func (r *ExternalProofRequest) openVPNEntryHealthyContext(ctx context.Context) error {
	if r.openvpnEntryTransport == nil {
		return nil
	}
	expected := r.openvpnEntryState.Load()
	if expected == nil {
		return errors.New("OpenVPN entry has no retained connected generation")
	}
	actual, err := r.observeOpenVPNEntry(ctx)
	if err != nil {
		return err
	}
	if actual != *expected {
		return errors.New("OpenVPN entry connected generation or capacity changed")
	}
	return nil
}
