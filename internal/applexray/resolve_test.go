package applexray

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestOuterHostnameIsFrozenBeforeNativeRuntime(t *testing.T) {
	for _, mode := range []string{"reality-vision", "reality-pq-vision", "reality-xhttp", "split", "max"} {
		t.Run(mode, func(t *testing.T) {
			original := bytes.ReplaceAll(sampleConfig(mode), []byte("192.0.2.1"), []byte("vpn.example.com"))
			wrapper := bytes.ReplaceAll(wrapperFor(mode), []byte("192.0.2.1"), []byte("vpn.example.com"))
			calls := 0
			result, err := ResolveAndCompile(context.Background(), mode, wrapper, original, func(ctx context.Context, host string) ([]netip.Addr, error) {
				calls++
				if host != "vpn.example.com" {
					t.Fatal("unowned hostname resolved")
				}
				return []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.2.45")}, nil
			})
			if err != nil || calls != 1 {
				t.Fatal(err, calls)
			}
			plan, err := Prepare(mode, result["xray.json"])
			if err != nil || plan.Server.String() != "192.0.2.45:10443" {
				t.Fatal("outer endpoint not frozen", err)
			}
			before, _ := Object(original)
			after, _ := Object(result["xray.json"])
			remote(before)["address"] = "192.0.2.45"
			same, _ := json.Marshal(before)
			same2, _ := json.Marshal(after)
			if string(same) != string(same2) {
				t.Fatal("resolution changed cryptographic/transport settings")
			}
			graph, _ := Object(result["sing-box.json"])
			for _, v := range graph["outbounds"].([]any) {
				o := v.(map[string]any)
				if o["type"] == "hysteria2" && o["server"] != "192.0.2.45" {
					t.Fatal("second physical transport would recurse through tunnel DNS")
				}
			}
		})
	}
}
func TestNoResolverOnLiteralOrInvalidInput(t *testing.T) {
	calls := 0
	lookup := func(context.Context, string) ([]netip.Addr, error) {
		calls++
		return nil, errors.New("must not resolve")
	}
	if _, err := ResolveAndCompile(context.Background(), "reality-vision", sampleWrapper(), sampleConfig("reality-vision"), lookup); err != nil || calls != 0 {
		t.Fatal("literal requested DNS", err)
	}
	for _, host := range []string{"localhost", "vpn.example.com/evil", "bad host", "vpn..example", "fe80::1%en0", ""} {
		raw := bytes.ReplaceAll(sampleConfig("reality-vision"), []byte("192.0.2.1"), []byte(host))
		if _, err := ResolveAndCompile(context.Background(), "reality-vision", sampleWrapper(), raw, lookup); err == nil {
			t.Fatal("invalid outer hostname accepted")
		}
	}
	if calls != 0 {
		t.Fatal("invalid profiles caused network requests")
	}
}
func TestDNSResolutionCannotAdoptCancelledOrUnsafeAnswers(t *testing.T) {
	raw := bytes.ReplaceAll(sampleConfig("reality-vision"), []byte("192.0.2.1"), []byte("vpn.example.com"))
	for _, address := range []string{"127.0.0.1", "::1", "::", "224.0.0.1", "fe80::1%en0"} {
		_, err := ResolveAndCompile(context.Background(), "reality-vision", sampleWrapper(), raw, func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr(address)}, nil
		})
		if err == nil {
			t.Fatal("unsafe DNS answer accepted", address)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	_, err := ResolveAndCompile(ctx, "reality-vision", sampleWrapper(), raw, func(context.Context, string) ([]netip.Addr, error) {
		cancel()
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
	})
	if err == nil || strings.Contains(err.Error(), "fixture") {
		t.Fatal("cancelled resolution accepted or secret returned")
	}
}
