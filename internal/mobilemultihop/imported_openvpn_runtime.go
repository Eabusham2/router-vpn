package mobilemultihop

import (
	"context"
	"errors"
	"router-vpn/internal/common"
	"router-vpn/internal/nativeopenvpn"
	"time"
)

// ImportedOpenVPNState belongs to one ready native userspace endpoint. Its
// negotiated inner capacity is observed with the same transport generation.
// It grants no provider API or paired-node authority.
type ImportedOpenVPNState struct {
	Remote nativeopenvpn.RemoteReceipt
	MTU    uint32
}

type importedOpenVPNEngine interface {
	ImportedOpenVPNStateContext(context.Context, string) (ImportedOpenVPNState, error)
}

func (c *Controller) hasImportedOpenVPN() bool {
	return c != nil && c.imported != nil && c.imported.openvpnTransport != nil
}
func (c *Controller) requiresOpenVPNRemote() bool {
	return c.openvpnResponses != nil || c.hasImportedOpenVPN()
}
func (c *Controller) readImportedOpenVPN(ctx context.Context) (ImportedOpenVPNState, error) {
	var empty ImportedOpenVPNState
	if ctx == nil {
		return empty, errors.New("imported OpenVPN observation requires a caller")
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if !c.hasImportedOpenVPN() || c.generation.Load() != 1 {
		return empty, errors.New("imported OpenVPN native owner changed")
	}
	if err := c.importedOpenVPNOwner(ctx); err != nil {
		return empty, err
	}
	engine, ok := c.engine.(importedOpenVPNEngine)
	if !ok {
		return empty, errors.New("imported OpenVPN requires its bounded native endpoint observation")
	}
	actual, err := engine.ImportedOpenVPNStateContext(ctx, c.meta.EntryTag)
	if err != nil {
		return empty, err
	}
	if !actual.Remote.Matches(c.imported.openvpnTransport) || actual.MTU < c.imported.openvpnMTU || actual.MTU > 65535 {
		return empty, errors.New("imported OpenVPN remote or negotiated capacity differs from its captured source")
	}
	if err := ctx.Err(); err != nil {
		return actual, err
	}
	if err := c.importedOpenVPNOwner(ctx); err != nil {
		return actual, err
	}
	return actual, nil
}
func (c *Controller) awaitImportedOpenVPN(ctx context.Context) (ImportedOpenVPNState, error) {
	for {
		state, err := c.readImportedOpenVPN(ctx)
		if err == nil {
			return state, nil
		}
		if !errors.Is(err, nativeopenvpn.ErrRemotePending) {
			return ImportedOpenVPNState{}, err
		}
		timer := time.NewTimer(40 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ImportedOpenVPNState{}, ctx.Err()
		case <-timer.C:
		}
	}
}
func (c *Controller) checkImportedOpenVPN(ctx context.Context, remote nativeopenvpn.RemoteReceipt, mtu uint32) error {
	actual, err := c.readImportedOpenVPN(ctx)
	if err != nil {
		confirmedChange := actual.Remote.Generation != 0 && (actual.Remote != remote || actual.MTU != mtu)
		if confirmedChange || !common.ObservationContextExpired(ctx, err) {
			c.invalidate()
		}
		return err
	}
	if actual.Remote != remote || actual.MTU != mtu {
		c.invalidate()
		return errors.New("imported OpenVPN transport generation or negotiated MTU changed")
	}
	return nil
}

func (c *Controller) importedOpenVPNOwner(ctx context.Context) error {
	if c.generation.Load() != 1 {
		return errors.New("imported OpenVPN generation retired")
	}
	identity, err := externalObservedIdentity(ctx, c.engine)
	if err != nil {
		return err
	}
	if identity == "" || identity != c.engineID {
		return errors.New("imported OpenVPN native instance changed")
	}
	selected, err := externalObservedSelection(ctx, c.engine)
	if err != nil {
		return err
	}
	if selected != LocalTag || c.generation.Load() != 1 {
		return errors.New("imported OpenVPN selected owner changed")
	}
	return ctx.Err()
}
