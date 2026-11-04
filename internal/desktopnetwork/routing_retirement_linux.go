//go:build linux

package desktopnetwork

import (
	"context"
	"errors"
)

// RoutingAbsent observes complete native absence of the historical objects
// reported by the authenticated original child's successful retirement. The
// startup baseline remains proof evidence, never deletion authority. Unrelated
// newer routing is preserved so a physical-network change cannot strand Stop.
// The caller independently joins the original child and pins its namespace.
func (t *Tracker) RoutingAbsent(ctx context.Context, created *DesktopNetworkRetirementReceipt) error {
	if t == nil || ctx == nil || ctx.Err() != nil {
		return errors.New("native routing retirement lost its original caller")
	}
	if created == nil || created.TargetOS != "linux" || created.Validate() != nil {
		return errors.New("native routing retirement has no authenticated original creation ledger")
	}
	copy := *created
	copy.Objects = append([]DesktopNetworkObject(nil), created.Objects...)
	created = &copy
	t.mu.Lock()
	if t.initializing || !t.startedWithoutOwnedReceipt || t.baseline == "" || t.native == nil || !t.closed {
		t.mu.Unlock()
		return errors.New("native routing retirement requires its joined original pre-engine observer")
	}
	native := t.native
	known := append([]DesktopNetworkReceipt(nil), t.recorded...)
	if t.current != nil {
		known = append(known, *cloneReceipt(t.current))
	}
	if t.old != nil {
		known = append(known, *cloneReceipt(t.old))
	}
	t.mu.Unlock()
	snapshot, err := native.Snapshot(ctx)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(snapshot.Links) == 0 {
		return errors.New("native routing retirement omitted its complete link inventory")
	}
	if _, _, err := project(snapshot, nil); err != nil {
		return err
	}
	owned := make(map[string]bool, len(created.Objects))
	for _, object := range created.Objects {
		owned[object.Key()] = true
	}
	for _, prior := range known {
		if !created.Created || created.Unindexed || prior.Index != created.Index || prior.Name != created.Name || prior.Incarnation != created.Incarnation {
			return errors.New("native retirement changed its originally recorded constructor")
		}
		for _, object := range prior.Objects {
			if !owned[object.Key()] {
				return errors.New("native retirement omitted an originally recorded object")
			}
		}
	}
	for _, link := range snapshot.Links {
		if created.Index != 0 && link.Index == created.Index || created.Name != "" && link.Name == created.Name {
			return errors.New("original native routing interface is still present")
		}
	}
	for _, address := range snapshot.Addresses {
		if created.Index != 0 && address.Index == created.Index {
			return errors.New("original native routing address is still present")
		}
	}
	for _, object := range snapshot.Objects {
		if owned[object.Key()] {
			return errors.New("original native routing object or same-key replacement remains")
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.native != native || !t.closed {
		return errors.New("native routing retirement observer changed during readback")
	}
	return ctx.Err()
}
