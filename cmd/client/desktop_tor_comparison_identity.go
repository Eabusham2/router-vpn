package main

import (
	"context"
	"errors"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobiletor"
	"router-vpn/internal/routechoice"
)

var _ routechoice.ContextIdentitySession = (*desktopTorComparisonSession)(nil)
var _ routechoice.ContextIdentitySession = (*desktopExecutionSession)(nil)

func (d *desktopTorComparisonDriver) currentContext(ctx context.Context) error {
	if ctx == nil || d == nil || d.app == nil || d.operation == nil || d.network == "" || d.readNetwork == nil {
		return errors.New("Tor comparison has no original captured path observer")
	}
	if err := errors.Join(ctx.Err(), d.operation.Err()); err != nil {
		return err
	}
	if err := desktopnetwork.LockContext(ctx, &d.app.mu); err != nil {
		return err
	}
	err := desktopTorOperationCurrentLocked(d.app, d.operation, d.selected)
	if err == nil && d.temporary != nil && (!d.app.speedLabOwnerCurrentLocked(d.temporary) || d.app.cmd != d.temporary.runtime) {
		err = errors.New("Tor comparison lost its captured temporary runtime owner")
	}
	d.app.mu.Unlock()
	if err != nil {
		return err
	}
	network, err := d.readNetwork(ctx)
	if err != nil || network == "" || network != d.network {
		return errors.Join(err, errors.New("Tor comparison physical network changed"))
	}
	for _, selection := range d.selections {
		if err := selection.currentContext(ctx, d.app); err != nil {
			return err
		}
	}
	if err := desktopnetwork.LockContext(ctx, &d.app.mu); err != nil {
		return err
	}
	err = errors.Join(desktopTorOperationCurrentLocked(d.app, d.operation, d.selected), d.app.validateExternalProfileExpectedProfilesLocked(d.request, d.profile))
	if err == nil && d.temporary != nil && (!d.app.speedLabOwnerCurrentLocked(d.temporary) || d.app.cmd != d.temporary.runtime) {
		err = errors.New("Tor comparison temporary owner changed during observation")
	}
	d.app.mu.Unlock()
	if err != nil {
		return err
	}
	if d.startup != nil {
		if err := d.startup.currentContext(ctx, d.app); err != nil {
			return err
		}
	}
	return errors.Join(ctx.Err(), d.operation.Err())
}

func (s *desktopTorComparisonSession) identityContext(ctx context.Context) string {
	value, _ := s.IdentityContext(ctx)
	return value
}

func (s *desktopTorComparisonSession) IdentityContext(ctx context.Context) (string, error) {
	if ctx == nil || s == nil || s.driver == nil || s.prelaunch == nil || s.identity == "" {
		return "", errors.New("Tor comparison identity has no original caller or native session")
	}
	if err := s.driver.currentContext(ctx); err != nil {
		return "", err
	}
	if err := s.driver.app.desktopTorCurrentContext(ctx, s.prelaunch.workspace); err != nil {
		return "", err
	}
	if err := desktopnetwork.LockContext(ctx, &s.mu); err != nil {
		return "", err
	}
	defer s.mu.Unlock()
	if s.closed {
		return "", errors.New("Tor comparison identity belongs to a closed native session")
	}
	if !s.measurementDrained {
		value, err := desktopTorComparisonProbeIdentity(ctx, s.probe)
		if err != nil || value != s.identity {
			return "", errors.Join(err, errors.New("Tor comparison measurement identity changed"))
		}
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return s.identity, nil
}

func desktopTorComparisonProbeIdentity(ctx context.Context, probe mobiletor.Comparison) (string, error) {
	if ctx == nil || probe == nil {
		return "", errors.New("Tor comparison probe has no original identity owner")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	var value string
	var err error
	if captured, ok := probe.(routechoice.ContextIdentitySession); ok {
		value, err = captured.IdentityContext(ctx)
	} else {
		// Legacy in-memory identities stay synchronously joined. An available
		// native contextual observer never falls back after failure.
		value = probe.Identity()
	}
	if err = errors.Join(err, ctx.Err()); err != nil {
		return "", err
	}
	if value == "" {
		return "", errors.New("Tor comparison probe retired its captured identity")
	}
	return value, nil
}
