//go:build darwin

package mobiletor

import (
	"context"
	"errors"
	"time"
)

var _ desktopSocketRenewalPolicy = (*DesktopDarwinSocketPolicy)(nil)

func (p *DesktopDarwinSocketPolicy) renewSocketsAdmitted(ctx context.Context, members []desktopSocketRenewal) []desktopSocketRenewalResult {
	return desktopSocketControlRenewals(ctx, members, p.admitControl, p.renewLocked)
}

func (p *DesktopDarwinSocketPolicy) renewLocked(ctx context.Context, requests []DesktopSocketGrant) ([]DesktopSocketReceipt, error) {
	for _, grant := range requests {
		if grant.Capture != p.capture || grant.Binding.Owner != p.owner {
			return nil, desktopSocketUnsubmittedRenewals(requests, errors.New("Darwin renewal changed its captured policy owner"))
		}
	}
	reply, file, err := p.callLocked(ctx, desktopDarwinRequest{Operation: "renew", Capture: p.capture, Renewals: requests}, nil, true)
	if err != nil {
		if file != nil {
			file.Close()
		}
		return nil, err
	}
	valid := file == nil && reply.Owner == (DesktopSocketKernelOwner{}) && reply.Creation == (DesktopSocketCreation{}) &&
		reply.UID == 0 && reply.Account == "" && reply.PF == nil && reply.Receipt == (DesktopSocketReceipt{}) &&
		len(reply.Receipts) == len(requests)
	if valid {
		for index, receipt := range reply.Receipts {
			if !validDesktopSocketReceipt(receipt, requests[index], time.Now()) {
				valid = false
				break
			}
		}
	}
	if !valid {
		if file != nil {
			file.Close()
		}
		err = errors.New("Darwin renewal lost its exact complete native receipt set")
		p.lose("control-receive-renew", err)
		// A sent transaction with a malformed acknowledgment has an unknown
		// write outcome. Retain every attempted sequence and require the same
		// original guardian join/independent absence used by grant and revoke.
		p.channel.Close()
		return nil, err
	}
	return reply.Receipts, nil
}

func desktopDarwinRenewalFrame(request desktopDarwinRequest) bool {
	return request.Operation == "renew" && len(request.Renewals) > 0 && len(request.Renewals) <= desktopSocketRenewalLimit &&
		request.Creation == (DesktopSocketCreation{}) && request.Grant == (DesktopSocketGrant{}) && request.SOCKS == nil &&
		request.Tunnel == "" && request.Index == 0 && len(request.Options.Interfaces) == 0 &&
		len(request.Options.PrivateDestinations) == 0 && len(request.Options.LANPrefixes) == 0
}

type desktopDarwinPFRenewal struct {
	grant   DesktopSocketGrant
	control DesktopSocketGrant
}

// Every member is an exact existing permit, never initial grant authority.
// Capture all native socket/parent proofs before retaining attempted sequences
// or touching PF. The guardian's authenticated request loop owns these maps.
func (g *desktopDarwinGuardian) renew(ctx context.Context, requests []DesktopSocketGrant) ([]DesktopSocketReceipt, error) {
	if ctx == nil || g == nil || g.pf == nil || !g.pf.valid() || len(requests) == 0 || len(requests) > desktopSocketRenewalLimit {
		return nil, errors.New("Darwin renewal omitted its bounded original tuple set")
	}
	positions := make(map[string]int, len(requests))
	for index, grant := range requests {
		key := g.pf.key(grant)
		if _, found := positions[key]; found {
			return nil, errors.New("Darwin renewal repeated an original socket tuple")
		}
		positions[key] = index
	}
	owners := make([]*desktopDarwinOwnedSocket, len(requests))
	changes := make([]desktopDarwinPFRenewal, len(requests))
	for index, grant := range requests {
		owned, control, err := g.grantOwner(ctx, grant)
		if err != nil {
			return nil, err
		}
		previous, exists := owned.grants[grant.Remote.String()]
		expected := previous
		expected.Sequence++
		permit, retained := g.pf.permits[g.pf.key(previous)]
		if !exists || previous.Sequence == 0 || expected != grant ||
			!validDesktopSocketReceipt(owned.receipts[grant.Remote.String()], previous, time.Now()) ||
			!retained || permit.Grant != previous || !time.Now().Before(permit.Expires) {
			return nil, errors.New("Darwin renewal changed or outlived its original acknowledged grant")
		}
		if control != (DesktopSocketGrant{}) {
			if _, err := g.pf.socksControlExpiry(control); err != nil {
				return nil, err
			}
			if parent, included := positions[g.pf.key(control)]; included {
				if parent >= index || !desktopSocketSOCKSControlMatches(requests[parent], control) {
					return nil, errors.New("Darwin renewal must retain its original parent before its derived permit")
				}
				control = requests[parent]
			}
		}
		owners[index], changes[index] = owned, desktopDarwinPFRenewal{grant, control}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// An error after this point can have changed the kernel. Preserve all exact
	// attempted identities; never roll one back based on a sibling's result.
	for index, grant := range requests {
		owners[index].grants[grant.Remote.String()] = grant
		delete(owners[index].receipts, grant.Remote.String())
	}
	receipts, err := g.pf.renew(ctx, changes)
	if err != nil {
		return nil, err
	}
	for index, receipt := range receipts {
		if owners[index].receipts == nil {
			owners[index].receipts = make(map[string]DesktopSocketReceipt)
		}
		owners[index].receipts[requests[index].Remote.String()] = receipt
	}
	for _, grant := range requests {
		if association, exists := g.socks[grant.SocketID]; exists {
			if _, _, err = g.socksControlSocket(association); err != nil {
				break
			}
		}
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		for index, grant := range requests {
			delete(owners[index].receipts, grant.Remote.String())
		}
		return nil, err
	}
	return receipts, nil
}

func (p *desktopDarwinPF) renew(ctx context.Context, changes []desktopDarwinPFRenewal) (receipts []DesktopSocketReceipt, failure error) {
	progress := desktopPFStartGrant(ctx)
	started := progress.started
	defer func() { failure = progress.failure(failure) }()
	if ctx == nil || !p.valid() || p.permits == nil || len(changes) == 0 || len(changes) > desktopSocketRenewalLimit {
		return nil, errors.New("Darwin PF renewal requires its retained bounded owner")
	}
	seen := make(map[string]bool, len(changes))
	for _, change := range changes {
		grant := change.grant
		key := p.key(grant)
		previous, exists := p.permits[key]
		expected := previous.Grant
		expected.Sequence++
		if seen[key] || !exists || previous.Grant.Sequence == 0 || grant.Sequence <= 1 || expected != grant || grant.Capture != p.Capture || !started.Before(previous.Expires) {
			return nil, errors.New("Darwin PF renewal changed or expired an original exact permit")
		}
		seen[key] = true
	}
	if err := progress.run(1, func() error { return p.verify(ctx, true) }); err != nil {
		return nil, err
	}
	staged := *p
	staged.permits = make(map[string]desktopDarwinPFPermit, len(p.permits))
	for key, permit := range p.permits {
		staged.permits[key] = permit
	}
	for _, change := range changes {
		expires := started.Add(7 * time.Second)
		if change.control != (DesktopSocketGrant{}) {
			var err error
			expires, err = staged.socksGrantExpiry(started, change.control)
			if err != nil {
				return nil, err
			}
		}
		staged.permits[p.key(change.grant)] = desktopDarwinPFPermit{Grant: change.grant, Expires: expires}
	}
	p.permits = staged.permits
	if err := progress.run(2, func() error { return desktopDarwinPFLoad(ctx, p.Anchor, p.render()) }); err != nil {
		return nil, err
	}
	if err := progress.run(3, func() error { return p.verify(ctx, true) }); err != nil {
		return nil, err
	}
	progress.phase = 4
	observed := time.Now()
	for _, change := range changes {
		permit := p.permits[p.key(change.grant)]
		if change.control != (DesktopSocketGrant{}) {
			until, err := p.socksControlExpiry(change.control)
			if err != nil || permit.Expires.After(until) {
				return nil, errors.Join(err, errors.New("Darwin renewed relay outlived its retained original control"))
			}
		}
		if ctx.Err() != nil || !observed.Before(permit.Expires) || !observed.Before(started.Add(DesktopSocketReadbackAge)) {
			return nil, errors.Join(ctx.Err(), errors.New("Darwin PF renewal readback became stale"))
		}
		receipts = append(receipts, DesktopSocketReceipt{Grant: change.grant, ObservedAt: observed.UnixMilli(), ExpiresAt: permit.Expires.UnixMilli()})
	}
	return receipts, nil
}
