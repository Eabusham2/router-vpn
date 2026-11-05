//go:build linux

package systembootstrap

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testCapture(t *testing.T, ctx context.Context, hostname string, paths [3]string) (*Capture, error) {
	c, e := capture(ctx, hostname, paths, uint32(os.Geteuid()))
	if c != nil {
		t.Cleanup(func() { _ = c.Close() })
	}
	return c, e
}
func sources(t *testing.T, nss, hosts, resolver string) [3]string {
	t.Helper()
	dir := t.TempDir()
	var paths [3]string
	for i, v := range []string{nss, hosts, resolver} {
		paths[i] = filepath.Join(dir, []string{"nsswitch.conf", "hosts", "resolv.conf"}[i])
		if v != "<missing>" {
			if err := os.WriteFile(paths[i], []byte(v), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return paths
}
func original(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	return ctx
}
func TestSystemBootstrapHostsPrecedence(t *testing.T) {
	for _, resolver := range []string{"<missing>", "nameserver 127.0.0.53\n", "unrecognized transport\n"} {
		t.Run(strings.Fields(resolver)[0], func(t *testing.T) {
			ctx := original(t)
			paths := sources(t, "hosts: files dns\n", "192.0.2.4 endpoint.example alias.example\n", resolver)
			c, err := testCapture(t, ctx, "endpoint.example", paths)
			if err != nil {
				t.Fatal(err)
			}
			result, err := c.Resolve(ctx, nil)
			if err != nil || !result.Hosts || len(result.Addresses) != 1 || result.Addresses[0].String() != "192.0.2.4" {
				t.Fatalf("hosts-first result=%+v err=%v", result, err)
			}
			if len(c.sources) != 2 {
				t.Fatal("hosts success consulted unrelated resolver")
			}
		})
	}
	t.Run("dns-first-retains-stub-authority", func(t *testing.T) {
		_, err := testCapture(t, original(t), "endpoint.example", sources(t, "hosts: dns files\n", "192.0.2.4 endpoint.example\n", "nameserver 127.0.0.53\n"))
		if err == nil {
			t.Fatal("DNS-first was silently bypassed")
		}
	})
	t.Run("replacement", func(t *testing.T) {
		ctx := original(t)
		p := sources(t, "hosts: files dns", "192.0.2.4 endpoint.example", "<missing>")
		c, err := testCapture(t, ctx, "endpoint.example", p)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(p[1]+".new", []byte("192.0.2.4 endpoint.example"), 0600); err != nil {
			t.Fatal(err)
		}
		if err = os.Rename(p[1]+".new", p[1]); err != nil {
			t.Fatal(err)
		}
		if _, err = c.Resolve(ctx, nil); err == nil {
			t.Fatal("replaced hosts inode admitted")
		}
	})
}
func TestSystemBootstrapCapturedDNSOptions(t *testing.T) {
	c, err := testCapture(t, original(t), "vpn", sources(t, "hosts: dns files", "", "nameserver 192.0.2.53\nsearch corp.example second.example\noptions ndots:2 attempts:3 timeout:1 use-vc rotate no-aaaa trust-ad edns0 single-request\n"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(c.names(), ",") != "vpn.corp.example,vpn.second.example,vpn" || !c.tcp || !c.rotate || !c.noAAAA || !c.trustAD || c.attempts != 3 || c.timeout != time.Second {
		t.Fatalf("capture lost policy: %+v", c)
	}
	for _, nss := range []string{"hosts: resolve files dns", "hosts: files mdns4_minimal [NOTFOUND=return] dns", "hosts: dns dns"} {
		if _, err = testCapture(t, original(t), "vpn.example", sources(t, nss, "", "nameserver 192.0.2.53")); err == nil {
			t.Fatalf("unsupported NSS admitted %q", nss)
		}
	}
}

type testAuthority struct {
	lost      error
	calls     int
	responder func([]byte) []byte
}

func (o *testAuthority) Current(ctx context.Context) error { return errors.Join(ctx.Err(), o.lost) }
func (o *testAuthority) Exchange(ctx context.Context, network string, server netip.AddrPort, q []byte) ([]byte, error) {
	o.calls++
	if o.calls == 2 {
		o.lost = errors.New("original network owner replaced")
		return nil, o.lost
	}
	return o.responder(q), ctx.Err()
}
func TestSystemBootstrapEarlierAnswerCannotHideOwnerLoss(t *testing.T) {
	ctx := original(t)
	c, err := testCapture(t, ctx, "vpn.example", sources(t, "hosts: dns files", "192.0.2.6 vpn.example", "nameserver 192.0.2.53"))
	if err != nil {
		t.Fatal(err)
	}
	owner := &testAuthority{responder: func(q []byte) []byte {
		end := 12
		for q[end] != 0 {
			end += int(q[end]) + 1
		}
		end += 5
		response := append([]byte(nil), q[:end]...)
		response[2] = 0x81
		response[3] = 0x80
		response[7] = 1
		response[11] = 0
		return append(response, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 192, 0, 2, 5)
	}}
	result, err := c.Resolve(ctx, owner)
	if err == nil || len(result.Addresses) != 0 || owner.calls != 2 {
		t.Fatalf("owner loss hidden by earlier DNS/hosts answer: %+v %v calls=%d", result, err, owner.calls)
	}
}

func TestSystemBootstrapDNSOwnerLabelAndNegativeAnswer(t *testing.T) {
	query, err := queryFor("vpn.example", 1, false, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"original", "embedded-dot", "nxdomain-address"} {
		t.Run(name, func(t *testing.T) {
			response := append([]byte(nil), query...)
			response[2] = 0x81
			response[3] = 0x80
			response[7] = 1
			if name == "embedded-dot" {
				response = append(response, 11)
				response = append(response, []byte("vpn.example")...)
				response = append(response, 0)
			} else {
				response = append(response, 0xc0, 12)
			}
			response = append(response, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 192, 0, 2, 4)
			if name == "nxdomain-address" {
				response[3] = 0x83
			}
			addresses, err := addressesFor(query, response)
			if name == "original" {
				if err != nil || len(addresses) != 1 {
					t.Fatal(addresses, err)
				}
			} else if len(addresses) != 0 {
				t.Fatal("unrelated/negative answer adopted", addresses)
			}
			if name == "embedded-dot" && err == nil {
				t.Fatal("wire label boundaries were flattened")
			}
		})
	}
}

type policyExchange func(context.Context, string, netip.AddrPort, []byte) ([]byte, error)

func (f policyExchange) Current(ctx context.Context) error { return ctx.Err() }
func (f policyExchange) Exchange(ctx context.Context, network string, server netip.AddrPort, q []byte) ([]byte, error) {
	return f(ctx, network, server, q)
}
func TestSystemBootstrapWirePolicy(t *testing.T) {
	for _, name := range []string{"default", "edns", "tcp", "truncated", "search", "retry-server", "source-change"} {
		t.Run(name, func(t *testing.T) {
			hostname := "vpn.example"
			config := "nameserver 192.0.2.53\noptions attempts:1 timeout:1\n"
			switch name {
			case "edns":
				config += "options edns0\n"
			case "tcp":
				config += "options use-vc\n"
			case "search":
				hostname = "vpn"
				config += "search corp.example\noptions ndots:2\n"
			case "retry-server":
				config += "nameserver 192.0.2.54\n"
			}
			paths := sources(t, "hosts: dns files", "", config)
			ctx := original(t)
			c, e := testCapture(t, ctx, hostname, paths)
			if e != nil {
				t.Fatal(e)
			}
			calls := 0
			owner := policyExchange(func(call context.Context, network string, server netip.AddrPort, q []byte) ([]byte, error) {
				calls++
				if e := call.Err(); e != nil {
					return nil, e
				}
				deadline, _ := call.Deadline()
				outer, _ := ctx.Deadline()
				if deadline.After(outer) {
					t.Fatal("query renewed original deadline")
				}
				if (q[11] == 1) != (name == "edns") {
					t.Fatalf("%s changed captured EDNS setting: %x", name, q)
				}
				if name == "edns" && !strings.HasSuffix(string(q), string([]byte{0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0})) {
					t.Fatal("changed empty EDNS0 wire record")
				}
				if name == "tcp" && network != "tcp" {
					t.Fatal("ignored original use-vc")
				}
				if name != "tcp" && name != "truncated" && network != "udp" {
					t.Fatal("unexpected TCP")
				}
				got, end, e := dnsName(q, 12)
				if e != nil {
					t.Fatal(e)
				}
				want := hostname
				if name == "search" {
					want = "vpn.corp.example"
				}
				if got != want {
					t.Fatalf("wrong captured search query %q", got)
				}
				if binary.BigEndian.Uint16(q[end:end+2]) != 1 {
					t.Fatal("disabled IPv6 still queried")
				}
				if name == "retry-server" && server.Addr().String() == "192.0.2.53" {
					return nil, errors.New("first configured resolver unavailable")
				}
				response := append([]byte(nil), q[:end+4]...)
				response[2] = 0x81
				response[3] = 0x80
				response[11] = 0
				if name == "truncated" && network == "udp" {
					response[2] |= 2
					return response, nil
				}
				if name == "truncated" && network != "tcp" {
					t.Fatal("truncated reply did not switch original server to TCP")
				}
				response[7] = 1
				response = append(response, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 192, 0, 2, 9)
				if name == "source-change" {
					if e = os.WriteFile(paths[2], []byte("nameserver 203.0.113.53\n"), 0600); e != nil {
						t.Fatal(e)
					}
				}
				return response, nil
			})
			result, e := c.ResolveIPv6(ctx, owner, false)
			if name == "source-change" {
				if e == nil || len(result.Addresses) != 0 {
					t.Fatal("adopted answer after original source change", e)
				}
				return
			}
			expectedCalls := 1
			if name == "truncated" || name == "retry-server" {
				expectedCalls = 2
			}
			if e != nil || len(result.Addresses) != 1 || calls != expectedCalls {
				t.Fatalf("%s result=%+v error=%v calls=%d", name, result, e, calls)
			}
		})
	}
}
func TestSystemBootstrapClosedCaptureCannotReturnHosts(t *testing.T) {
	ctx := original(t)
	c, e := testCapture(t, ctx, "vpn.example", sources(t, "hosts: files dns", "192.0.2.7 vpn.example", "<missing>"))
	if e != nil {
		t.Fatal(e)
	}
	if e = c.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Resolve(ctx, nil); e == nil {
		t.Fatal("closed original capture supplied hosts")
	}
}
