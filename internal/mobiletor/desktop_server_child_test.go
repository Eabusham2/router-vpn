package mobiletor

import (
	"context"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func TestServerTorRealChildStartsDisabledAndConcurrentVerifyClose(t *testing.T) {
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
	if os.Chmod(directory, 0700) != nil {
		t.Fatal("private directory")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	child, err := StartServerTorChild(ctx, directory, binary, policy, port)
	if child != nil {
		defer child.Close(context.Background())
	}
	if err != nil {
		t.Fatal(err)
	}
	if !child.Alive() || child.Session().Current() || child.Verify(ctx) != nil {
		t.Fatal("actual standalone Tor lost its disabled authenticated owner")
	}
	var workers sync.WaitGroup
	for range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 10 {
				_ = child.Verify(ctx)
			}
		}()
	}
	if err := child.Close(ctx); err != nil {
		t.Fatal(err)
	}
	workers.Wait()
	if child.Alive() || child.Verify(ctx) == nil {
		t.Fatal("closed standalone child was reused")
	}
}
