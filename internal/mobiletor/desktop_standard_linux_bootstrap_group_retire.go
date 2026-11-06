//go:build linux

package mobiletor

import (
	"context"
	"errors"
)

func (g *DesktopLinuxBootstrapDNSGroup) unpin(t *desktopLinuxStandardBootstrap) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if t != nil && t.group == g {
		t.groupPinned = false
	}
}

// retireJoined runs under the original baseline gate, group mutex and locked
// native thread. It never creates or replays a permit. A failed/unknown removal
// retains its member and accounting for original-receipt recovery by Close.
func (g *DesktopLinuxBootstrapDNSGroup) retireJoined(ctx context.Context) error {
	b := g.owner.baseline
	for i := 0; i < len(g.members); {
		t := g.members[i]
		if !t.groupJoined || t.groupPinned {
			i++
			continue
		}
		if t.grant != nil && (t.grant.poison != nil || t.grant.sent && !t.grant.complete()) {
			return errors.New("bootstrap recycling retains uncertain original creation")
		}
		generation, err := g.observe(ctx)
		if err != nil {
			return err
		}
		if t.handle != 0 && !t.retired {
			if t.removal == nil || t.removal.rejected {
				t.removal, err = b.netlink.newBootstrapRemoval(generation, t.grant)
				if err != nil {
					return err
				}
			}
			err = b.netlink.bootstrapExchange(ctx, t.removal)
			if !t.removal.complete() || t.removal.rejected {
				return errors.Join(err, errors.New("bootstrap recycling retains original removal receipt"))
			}
			if err = g.acknowledge(t.removal); err != nil {
				return err
			}
			t.retired = true
		}
		// The retired member remains in strict inventory until its exact owned
		// rule AND set are proven absent under the acknowledged generation.
		if _, err = g.observe(ctx); err != nil {
			return err
		}
		if err = t.closeSocket(); err != nil {
			return err
		}
		if g.inventoryBytes < desktopLinuxBootstrapGroupGrantBytes {
			return errors.New("bootstrap recycling lost original accounting")
		}
		g.inventoryBytes -= desktopLinuxBootstrapGroupGrantBytes
		delete(g.acknowledged, t.grant)
		delete(g.acknowledged, t.removal)
		g.members = append(g.members[:i], g.members[i+1:]...)
	}
	return nil
}
