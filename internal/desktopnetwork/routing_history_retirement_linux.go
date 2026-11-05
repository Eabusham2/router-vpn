//go:build linux

package desktopnetwork

import (
	"context"
	"errors"
)

// RoutingHistoryAbsent checks actual authenticated retirement of every native
// constructor retained by a failed MTU transition. It grants no deletion or
// lookup authority. The caller already joined the original child and observer.
// Successful transitions ordinarily use RoutingAbsent for their final reader.
func (t *Tracker) RoutingHistoryAbsent(ctx context.Context, history []DesktopNetworkRetirementReceipt) error {
	if t == nil || ctx == nil || ctx.Err() != nil || len(history) == 0 || len(history) > 97 {
		return errors.New("native routing history lost its bounded original caller")
	}
	byIncarnation := make(map[string]DesktopNetworkRetirementReceipt)
	canonical := make(map[string]string)
	for _, item := range history {
		raw, err := CanonicalDesktopNetworkRetirementReceipt(item)
		if err != nil || item.TargetOS != "linux" {
			return errors.New("native routing history contains malformed retirement")
		}
		if old, exists := canonical[item.Incarnation]; exists && old != raw {
			return errors.New("native routing history changed a retained constructor")
		}
		canonical[item.Incarnation] = raw
		item.Objects = append([]DesktopNetworkObject(nil), item.Objects...)
		item.Addresses = append([]string(nil), item.Addresses...)
		byIncarnation[item.Incarnation] = item
	}
	if err := LockContext(ctx, &t.mu); err != nil {
		return err
	}
	if t.initializing || !t.startedWithoutOwnedReceipt || t.baseline == "" || t.native == nil || !t.closed {
		t.mu.Unlock()
		return errors.New("native routing history requires its joined original pre-engine observer")
	}
	native := t.native
	known := append([]DesktopNetworkReceipt(nil), t.recorded...)
	if t.current != nil {
		known = append(known, *cloneReceipt(t.current))
	}
	if t.old != nil {
		known = append(known, *cloneReceipt(t.old))
	}
	partial := append([]DesktopNetworkRetirementReceipt(nil), t.retired...)
	t.mu.Unlock()
	for _, prior := range known {
		retired, exists := byIncarnation[prior.Incarnation]
		if !exists || !retired.Created || retired.Unindexed || prior.Index != retired.Index || prior.Name != retired.Name {
			return errors.New("native routing history omitted an originally observed reader")
		}
		objects, addresses := map[string]bool{}, map[string]bool{}
		for _, object := range retired.Objects {
			objects[object.Key()] = true
		}
		for _, address := range retired.Addresses {
			addresses[address] = true
		}
		for _, object := range prior.Objects {
			if !objects[object.Key()] {
				return errors.New("native routing history omitted acknowledged routing")
			}
		}
		for _, address := range prior.Addresses {
			if !addresses[address] {
				return errors.New("native routing history omitted an acknowledged address")
			}
		}
	}
	for _, prior := range partial {
		raw, err := CanonicalDesktopNetworkRetirementReceipt(prior)
		if err != nil || canonical[prior.Incarnation] != raw {
			return errors.New("native routing history omitted actual partial construction effects")
		}
	}
	snapshot, err := native.Snapshot(ctx)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if len(snapshot.Links) == 0 {
		return errors.New("native routing history omitted complete link inventory")
	}
	if _, _, err := project(snapshot, nil); err != nil {
		return err
	}
	owned := map[string]bool{}
	for _, retired := range byIncarnation {
		for _, object := range retired.Objects {
			owned[object.Key()] = true
		}
		for _, link := range snapshot.Links {
			if retired.Index != 0 && link.Index == retired.Index || retired.Name != "" && link.Name == retired.Name {
				return errors.New("historical native interface or same-name replacement remains")
			}
		}
		for _, address := range snapshot.Addresses {
			if retired.Index != 0 && address.Index == retired.Index {
				return errors.New("historical native address remains")
			}
		}
	}
	for _, object := range snapshot.Objects {
		if owned[object.Key()] {
			return errors.New("historical native routing object or same-key replacement remains")
		}
	}
	if err := LockContext(ctx, &t.mu); err != nil {
		return err
	}
	defer t.mu.Unlock()
	if t.native != native || !t.closed {
		return errors.New("native routing history observer changed during final readback")
	}
	return ctx.Err()
}
