package mobiletor

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// This uses the actual installed static Tor and the shipping SAFECOOKIE child
// owner. Networking stays disabled: encrypted cell scheduling is exercised by
// the separate tests compiled inside the exact patched Tor source.
func TestServerTorRealChildPaddingControl(t *testing.T) {
	prefix := os.Getenv("ROUTERVPN_SERVER_TOR_PACKAGE")
	if prefix == "" {
		t.Skip("requires built standalone Tor package")
	}
	binary, err := VerifyServerTorPackage(prefix)
	if err != nil {
		t.Fatal(err)
	}
	policy := serverTorPolicy(t, serverTorSource("tor"))
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	child, err := StartServerTorChild(ctx, directory, binary, policy, port)
	if child != nil {
		defer child.Close(context.Background())
	}
	if err != nil {
		t.Fatal(err)
	}
	control := child.control.control
	capability, err := control.PaddingInfo(ctx)
	if err != nil || capability.GenerationHighWater != 0 || child.Verify(ctx) != nil || child.Session().Current() {
		t.Fatal("actual disabled child lacks its exact owned capability", err)
	}
	identity := paddingTestIdentity
	identity.Generation = capability.GenerationHighWater + 1
	if _, err := control.StartPadding(ctx, identity, 192, 5*time.Second, strings.Repeat("c", 32), strings.Repeat("d", 64)); err == nil {
		t.Fatal("padding activated on an unproved disabled child")
	}
	if _, err := control.PaddingInfo(ctx); err == nil {
		t.Fatal("failed native start reused the retired control stream")
	}
	if err := child.Close(ctx); err != nil || child.Alive() {
		t.Fatal("real child did not join after its controller retired", err)
	}
}
