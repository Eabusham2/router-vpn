//go:build linux || windows || darwin

package desktopnetwork

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestNativeNetworkObserverReadOnlyBarrier(t *testing.T) {
	if os.Getenv("ROUTERVPN_NATIVE_NETWORK_EVENTS") != "1" {
		t.Skip("requires explicit native network observer gate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	owner, err := Open(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if owner.Identity() == "" {
		t.Fatal("missing immutable physical identity")
	}
	if err := owner.Current(); err != nil {
		t.Fatal(err)
	}
	if err := owner.Begin(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err := owner.Current(); err == nil {
		t.Fatal("open transition was accepted for measurement")
	}
	if err := owner.End(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err := owner.Current(); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if err := owner.Current(); err == nil {
		t.Fatal("closed observer became current")
	}
}
