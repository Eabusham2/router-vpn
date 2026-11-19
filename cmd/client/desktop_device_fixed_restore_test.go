package main

import (
	"context"
	"testing"
)

func TestDeviceMTURestoreBindsRevisionAndObservedValue(t *testing.T) {
	a := deviceMTUTestApp(t)
	config, err := captureDeviceMTUPolicy(a)
	if err != nil {
		t.Fatal(err)
	}
	if reply := deviceMTUTestPost(t, a, config.token, 1350); reply.Code != 200 {
		t.Fatal(reply.Body.String())
	}
	c, err := captureDeviceMTUPolicy(a)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), deviceMTUContextKey{}, c)
	p := desktopRestoredMTUPurpose{c.policy.Revision, c.policy.FixedMTU}
	if historical, err := p.forOperation(ctx, 1350); err != nil || historical != 0 {
		t.Fatal("fixed restoration was treated as a historical reader", historical, err)
	}
	if _, err := p.forOperation(ctx, 1320); err == nil {
		t.Fatal("mismatched native readback replayed")
	}
	if _, err := p.forOperation(context.Background(), 1350); err == nil {
		t.Fatal("uncaptured operation ran fixed restore")
	}
	if reply := deviceMTUTestPost(t, a, c.token, 0); reply.Code != 200 {
		t.Fatal(reply.Body.String())
	}
	current, _ := captureDeviceMTUPolicy(a)
	if reply := deviceMTUTestPost(t, a, current.token, 1350); reply.Code != 200 {
		t.Fatal(reply.Body.String())
	}
	if _, err := p.forOperation(ctx, 1350); err == nil {
		t.Fatal("same numeric size from another revision replayed")
	}
	if old, err := (desktopRestoredMTUPurpose{}).forOperation(context.Background(), 1400); err != nil || old != 1400 {
		t.Fatal("historical profile policy no longer retains the observed size", err)
	}
}
