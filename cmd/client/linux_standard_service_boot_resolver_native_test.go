//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func bootResolverFilesFixture(t *testing.T) (string, string, string) {
	t.Helper()
	dir, e := os.MkdirTemp("/root", "boot-resolver-fixture-")
	if e != nil {
		t.Fatal(e)
	}
	dir, e = filepath.Abs(dir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path, stub, up := filepath.Join(dir, "resolv.conf"), filepath.Join(dir, "stub-resolv.conf"), filepath.Join(dir, "upstream.conf")
	for p, body := range map[string]string{stub: "nameserver 127.0.0.53\n", up: "nameserver 192.0.2.53\nnameserver 2001:db8::53\n"} {
		if e = os.WriteFile(p, []byte(body), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e = os.Symlink(stub, path); e != nil {
		t.Fatal(e)
	}
	return path, stub, up
}
func TestLinuxStandardServiceBootResolverCaptureUsesOnlyOriginalConfiguredUpstreams(t *testing.T) {
	path, stub, up := bootResolverFilesFixture(t)
	r, e := captureLinuxBootResolverAt(context.Background(), path, stub, up)
	if e != nil {
		t.Fatal(e)
	}
	defer r.close()
	if len(r.servers) != 2 || r.servers[0].String() != "192.0.2.53" || len(r.sources) != 2 {
		t.Fatalf("wrong configured capture: %+v", r)
	}
	if e = r.current(context.Background()); e != nil {
		t.Fatal(e)
	}
	expired, cancel := context.WithCancel(context.Background())
	cancel()
	if e = r.current(expired); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if e = r.current(context.Background()); e != nil {
		t.Fatal("pure observer expiry lost original resolver", e)
	}
}
func TestLinuxStandardServiceBootResolverCaptureRejectsChangedSources(t *testing.T) {
	for _, name := range []string{"contents", "same-bytes-replacement", "link", "permissions", "stub-contents"} {
		t.Run(name, func(t *testing.T) {
			path, stub, up := bootResolverFilesFixture(t)
			r, e := captureLinuxBootResolverAt(context.Background(), path, stub, up)
			if e != nil {
				t.Fatal(e)
			}
			defer r.close()
			switch name {
			case "contents":
				e = os.WriteFile(up, []byte("nameserver 203.0.113.53\n"), 0600)
			case "same-bytes-replacement":
				var b []byte
				b, e = os.ReadFile(up)
				if e == nil {
					e = os.Rename(up, up+".old")
				}
				if e == nil {
					e = os.WriteFile(up, b, 0600)
				}
			case "link":
				e = os.Remove(path)
				if e == nil {
					e = os.Symlink(up, path)
				}
			case "permissions":
				e = os.Chmod(up, 0666)
			case "stub-contents":
				e = os.WriteFile(stub, []byte("nameserver 127.0.0.54\n"), 0600)
			}
			if e != nil {
				t.Fatal(e)
			}
			if e = r.current(context.Background()); e == nil {
				t.Fatal("changed resolver admitted")
			}
		})
	}
}
func TestLinuxStandardServiceBootResolverRejectsUnownedStubAndImplicitFallback(t *testing.T) {
	for _, body := range []string{"", "nameserver resolver.example\n", "nameserver 127.0.0.1\n", "nameserver 0.0.0.0\n", "nameserver 224.0.0.1\n", "nameserver fe80::1%eth0\n", "nameserver 127.0.0.53\nnameserver 192.0.2.53\n", "nameserver 192.0.2.53 extra\n"} {
		if _, _, e := linuxBootResolverServers([]byte(body)); e == nil {
			t.Fatalf("accepted %q", body)
		}
	}
	path, stub, up := bootResolverFilesFixture(t)
	if _, e := captureLinuxBootResolverAt(context.Background(), path, stub+"-foreign", up); e == nil {
		t.Fatal("unowned local daemon accepted")
	}
	if e := os.WriteFile(up, []byte("nameserver 127.0.0.53\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := captureLinuxBootResolverAt(context.Background(), path, stub, up); e == nil {
		t.Fatal("recursive stub accepted")
	}
}
