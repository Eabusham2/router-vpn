//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func bootResolverFilesFixture(t *testing.T) ([3]string, string, string) {
	t.Helper()
	dir, e := os.MkdirTemp("/root", "boot-resolver-fixture-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	paths := [3]string{filepath.Join(dir, "nsswitch.conf"), filepath.Join(dir, "hosts"), filepath.Join(dir, "resolv.conf")}
	target, stub := filepath.Join(dir, "original-resolver.conf"), filepath.Join(dir, "stub-resolv.conf")
	for p, body := range map[string]string{paths[0]: "hosts: files dns\n", paths[1]: "", target: "nameserver 192.0.2.53\nnameserver 2001:db8::53\n", stub: "nameserver 127.0.0.53\n"} {
		if e = os.WriteFile(p, []byte(body), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e = os.Symlink(target, paths[2]); e != nil {
		t.Fatal(e)
	}
	return paths, target, stub
}
func TestLinuxStandardServiceBootResolverCaptureUsesOnlyOriginalConfiguredUpstreams(t *testing.T) {
	paths, _, _ := bootResolverFilesFixture(t)
	r, e := captureLinuxBootResolverAt(context.Background(), "vpn.example", paths)
	if e != nil {
		t.Fatal(e)
	}
	defer r.close()
	servers := r.policy.Servers()
	if len(servers) != 2 || servers[0].Addr().String() != "192.0.2.53" {
		t.Fatalf("wrong configured capture: %v", servers)
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
			paths, target, stub := bootResolverFilesFixture(t)
			r, e := captureLinuxBootResolverAt(context.Background(), "vpn.example", paths)
			if e != nil {
				t.Fatal(e)
			}
			defer r.close()
			switch name {
			case "contents":
				e = os.WriteFile(target, []byte("nameserver 203.0.113.53\n"), 0600)
			case "same-bytes-replacement":
				var b []byte
				b, e = os.ReadFile(target)
				if e == nil {
					e = os.Rename(target, target+".old")
				}
				if e == nil {
					e = os.WriteFile(target, b, 0600)
				}
			case "link":
				e = os.Remove(paths[2])
				if e == nil {
					e = os.Symlink(stub, paths[2])
				}
			case "permissions":
				e = os.Chmod(target, 0666)
			case "stub-contents":
				e = os.WriteFile(paths[1], []byte("192.0.2.6 vpn.example\n"), 0600)
			}
			if e != nil {
				t.Fatal(e)
			}
			if e = r.current(context.Background()); e == nil {
				t.Fatal("changed original resolver/NSS source admitted")
			}
		})
	}
}
func TestLinuxStandardServiceBootResolverRejectsUnownedStubAndImplicitFallback(t *testing.T) {
	for _, body := range []string{"", "nameserver resolver.example\n", "nameserver 127.0.0.1\n", "nameserver 0.0.0.0\n", "nameserver 224.0.0.1\n", "nameserver fe80::1%eth0\n", "nameserver 127.0.0.53\nnameserver 192.0.2.53\n", "nameserver 192.0.2.53 extra\n"} {
		paths, target, _ := bootResolverFilesFixture(t)
		if e := os.WriteFile(target, []byte(body), 0600); e != nil {
			t.Fatal(e)
		}
		if r, e := captureLinuxBootResolverAt(context.Background(), "vpn.example", paths); e == nil {
			_ = r.close()
			t.Fatalf("accepted %q", body)
		}
	}
	// A captured systemd upstream file is not its authenticated split-DNS policy.
	paths, _, stub := bootResolverFilesFixture(t)
	if e := os.Remove(paths[2]); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(stub, paths[2]); e != nil {
		t.Fatal(e)
	}
	if r, e := captureLinuxBootResolverAt(context.Background(), "vpn.example", paths); e == nil {
		_ = r.close()
		t.Fatal("flattened local daemon policy accepted")
	}
}

func TestLinuxStandardServiceBootResolverHostsBeforeStub(t *testing.T) {
	for _, name := range []string{"hosts-stub", "hosts-missing", "dns-first-stub"} {
		t.Run(name, func(t *testing.T) {
			paths, target, _ := bootResolverFilesFixture(t)
			if e := os.WriteFile(paths[1], []byte("192.0.2.8 vpn.example\n"), 0600); e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(target, []byte("nameserver 127.0.0.53\n"), 0600); e != nil {
				t.Fatal(e)
			}
			if name == "hosts-missing" {
				if e := os.Remove(target); e != nil {
					t.Fatal(e)
				}
			}
			if name == "dns-first-stub" {
				if e := os.WriteFile(paths[0], []byte("hosts: dns files\n"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			r, e := captureLinuxBootResolverAt(ctx, "vpn.example", paths)
			if name == "dns-first-stub" {
				if e == nil {
					_ = r.close()
					t.Fatal("DNS-first silently preferred hosts over original stub policy")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			defer r.close()
			result, e := r.policy.Resolve(ctx, nil)
			if e != nil || !result.Hosts || len(result.Addresses) != 1 || result.Addresses[0].String() != "192.0.2.8" {
				t.Fatal("files-first exact answer consulted unavailable DNS", result, e)
			}
		})
	}
}
