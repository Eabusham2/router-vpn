package mobiletor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This runs the real shipping SAFECOOKIE/owning-process control path with all
// networking disabled. The standalone verified package is preferred. Before a
// new native source lock is published, an isolated test binary may be supplied
// with its independently recorded exact SHA; this does not mint a production
// package receipt or relax VerifyServerTorPackage.
func lastRelayNativeBinary(t *testing.T) *ServerTorBinary {
	t.Helper()
	if prefix := os.Getenv("ROUTERVPN_SERVER_TOR_PACKAGE"); prefix != "" {
		binary, err := VerifyServerTorPackage(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return binary
	}
	path, expected := os.Getenv("ROUTERVPN_LASTRELAY_TEST_BINARY"), os.Getenv("ROUTERVPN_LASTRELAY_TEST_SHA256")
	if path == "" && expected == "" {
		t.Skip("requires verified standalone Tor package or exact isolated native test binary")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !paddingHex(expected, 64) {
		t.Fatal("native last-relay test requires an exact absolute binary and SHA256")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 {
		t.Fatal("native last-relay test binary is unavailable or mutable", err)
	}
	raw, err := os.ReadFile(path)
	sum := sha256.Sum256(raw)
	if err != nil || hex.EncodeToString(sum[:]) != expected {
		t.Fatal("native last-relay test binary differs from its recorded build", err)
	}
	return &ServerTorBinary{path: path, info: info, digest: expected}
}

func TestLastRelayRealNativeOwningControl(t *testing.T) {
	binary := lastRelayNativeBinary(t)
	for _, operation := range []string{"anchor", "capture"} {
		t.Run(operation, func(t *testing.T) {
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
			capability, err := control.LastRelayInfo(ctx)
			if err != nil || capability.GenerationHighWater != 0 || child.Verify(ctx) != nil || child.Session().Current() {
				t.Fatal("real disabled child lacks exact source-bound capability", capability, err)
			}
			if operation == "anchor" {
				_, err = control.LookupLastRelayAnchor(ctx, LastRelayAnchorLocator{SessionSHA256: lastRelayTestIdentity.SessionSHA256, SourceSHA256: lastRelayTestIdentity.SourceSHA256,
					SOCKSUsername: strings.Repeat("a", 64), SOCKSPassword: strings.Repeat("b", 64), Client: netip.MustParseAddrPort("127.0.0.1:23456"), Target: netip.MustParseAddrPort("1.1.1.1:443")})
			} else {
				_, err = control.CaptureLastRelay(ctx, lastRelayTestIdentity, time.Second, 111, strings.Repeat("a", 64), strings.Repeat("b", 64))
			}
			if err == nil {
				t.Fatal("disabled native process invented an open anchor or circuit capture")
			}
			if _, err := control.LastRelayInfo(ctx); err == nil {
				t.Fatal("rejected native capture reused a retired controller")
			}
			if err := child.Close(ctx); err != nil || child.Alive() {
				t.Fatal("real native child did not join its exact rejected owner", err)
			}
		})
	}
}
