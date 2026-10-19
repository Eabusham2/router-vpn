package mobilemultihop

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"router-vpn/internal/applexray"
	"router-vpn/internal/multihoprelay"
)

func maxHostnameFixture(t *testing.T, mode, layer, hostname string) (map[string]string, string) {
	t.Helper()
	files, metadata := maxFixture(t, mode)
	if strings.HasPrefix(mode, "max-tls-") {
		maxChange(t, files, "outer-xray.json", func(root map[string]any) {
			root["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["address"] = hostname
		})
	} else {
		maxChange(t, files, "middle-sing-box.json", func(root map[string]any) {
			root["outbounds"].([]any)[0].(map[string]any)["server"] = hostname
		})
	}
	var policy maxPolicy
	if json.Unmarshal([]byte(metadata), &policy) != nil {
		t.Fatal("fixture metadata")
	}
	policy.Endpoint, policy.StartLayer = hostname, layer
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	return files, string(raw)
}

func TestMAXHostnameCapturePreservesCompleteChainAndSavedSources(t *testing.T) {
	for _, mode := range []string{"max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
		for _, layer := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, address := range []string{"192.0.2.71", "2001:db8:abcd::71"} {
				t.Run(mode+"/"+layer+"/"+address, func(t *testing.T) {
					files, metadata := maxHostnameFixture(t, mode, layer, "Captured-MAX.example.")
					source := pqEncoded(files)
					if _, err := CompileMAXProfile(mode, source, metadata); err == nil {
						t.Fatal("unresolved hostname reached runtime compiler")
					}
					capture, err := CaptureMAXProfile(mode, source, metadata)
					if err != nil || !capture.RequiresResolution() || capture.Endpoint() != "Captured-MAX.example." || len(capture.SourceSHA256()) != 64 {
						t.Fatal("complete selection rejected", err)
					}
					calls := 0
					result, err := capture.Resolve(context.Background(), func(ctx context.Context, host string) ([]netip.Addr, error) {
						calls++
						if host != "Captured-MAX.example." || ctx.Err() != nil {
							t.Fatal("lookup escaped the exact selected node")
						}
						return []netip.Addr{netip.MustParseAddr(address)}, nil
					})
					if err != nil || calls != 1 {
						t.Fatal("one owned lookup did not produce a complete runtime", err, calls)
					}
					if source != pqEncoded(files) || metadata != capture.metadata || capture.Endpoint() != "Captured-MAX.example." || result.SourceSHA256() != capture.SourceSHA256() || result.Endpoint() != address {
						t.Fatal("saved source or selection identity changed")
					}
					var launch map[string]string
					if json.Unmarshal([]byte(result.Files()), &launch) != nil || len(launch) != len(files) {
						t.Fatal("launch lost captured assets")
					}
					outerFile := "middle-sing-box.json"
					if strings.HasPrefix(mode, "max-tls-") {
						outerFile = "outer-xray.json"
					}
					for name, saved := range files {
						if name != outerFile && launch[name] != saved {
							t.Fatal("non-endpoint asset changed", name)
						}
					}
					// Undo only the physical address in a fresh comparison map. Exact
					// structural equality proves authentication, SNI, PQ, camouflage,
					// ports, and the generated remote-loopback services are unchanged.
					changed := maxObject(t, launch[outerFile])
					if strings.HasPrefix(mode, "max-tls-") {
						remote := changed["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
						if remote["address"] != address {
							t.Fatal("TLS outer did not use the owned answer")
						}
						remote["address"] = capture.Endpoint()
					} else {
						out := changed["outbounds"].([]any)[0].(map[string]any)
						if out["server"] != address {
							t.Fatal("QUIC outer did not use the owned answer")
						}
						out["server"] = capture.Endpoint()
					}
					if !reflect.DeepEqual(changed, maxObject(t, files[outerFile])) {
						t.Fatal("a captured outer identity or transport field changed")
					}
					var savedPolicy, launchPolicy map[string]any
					json.Unmarshal([]byte(metadata), &savedPolicy)
					json.Unmarshal([]byte(result.Metadata()), &launchPolicy)
					if launchPolicy["endpoint"] != address {
						t.Fatal("launch metadata lost literal address")
					}
					launchPolicy["endpoint"] = capture.Endpoint()
					if !reflect.DeepEqual(savedPolicy, launchPolicy) {
						t.Fatal("node proof, private API, or Start Layer selection changed")
					}
					expected, err := CompileMAXProfile(mode, result.Files(), result.Metadata())
					if err != nil || expected != result.Config() {
						t.Fatal("result bypassed the literal-only compiler", err)
					}
					var graph map[string]any
					json.Unmarshal([]byte(result.Config()), &graph)
					if err := multihoprelay.ValidateMAXChain(graph["endpoints"].([]any)[0].(map[string]any), graph["outbounds"].([]any), mode, savedPolicy["node_id"].(string), layer, canonicalMAXTags(), ""); err != nil {
						t.Fatal("runtime lost the complete nested chain", err)
					}
					outs := graph["outbounds"].([]any)
					outer := outs[len(outs)-1].(map[string]any)
					if layer != "off" {
						if len(outs) != 3 || outer["server"] != address || outer["tag"] != MAXStartLayerTag || outs[1].(map[string]any)["detour"] != MAXStartLayerTag {
							t.Fatal("outermost Start Layer lost the same resolved physical node")
						}
					} else if len(outs) != 2 {
						t.Fatal("unexpected extra transport")
					}
				})
			}
		}
	}
}

func TestMAXHostnameRejectsBeforeOwnedLookup(t *testing.T) {
	for _, mode := range []string{"max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
		for _, mutate := range []string{"node-proof", "node-kind", "public-api", "hostname-owner", "missing-PQ", "wrong-PQ", "SS-secret", "SS-bypass", "base-bypass", "omitted-layer", "unknown-helper", "Start-Layer", "outer-credentials", "outer-dial", "outer-path", "extra-listener"} {
			t.Run(mode+"/"+mutate, func(t *testing.T) {
				files, metadata := maxHostnameFixture(t, mode, "aes-256-gcm", "captured-max.example")
				var policy map[string]any
				json.Unmarshal([]byte(metadata), &policy)
				switch mutate {
				case "node-proof":
					policy["node_id"] = "malformed-selected-node"
				case "node-kind":
					policy["node_kind"] = "external"
				case "public-api":
					policy["router_api"] = "https://198.51.100.71:8787"
				case "hostname-owner":
					policy["endpoint"] = "foreign-max.example"
				case "missing-PQ":
					delete(files, "rosenpass-client-secret")
				case "wrong-PQ":
					files["rosenpass-server-public"] = files["rosenpass-client-public"]
				case "SS-secret", "SS-bypass":
					maxChange(t, files, "middle-sing-box.json", func(root map[string]any) {
						ss := root["outbounds"].([]any)[1].(map[string]any)
						if mutate == "SS-secret" {
							ss["password"] = "private-secret-not-an-AES-key"
						} else {
							delete(ss, "detour")
						}
					})
				case "base-bypass":
					for _, name := range []string{"wg.conf", "awg.conf"} {
						if files[name] != "" {
							pqReplace(files, name, "127.0.0.1:51830", "198.51.100.71:51830")
						}
					}
				case "omitted-layer":
					pqReplace(files, "chain.env", "shadowsocks2022>", "")
				case "unknown-helper":
					files["helper.sh"] = base64.StdEncoding.EncodeToString([]byte("private-do-not-execute"))
				case "Start-Layer":
					policy["start_layer"] = "xor"
				default:
					name := "middle-sing-box.json"
					if strings.HasPrefix(mode, "max-tls-") {
						name = "outer-xray.json"
					}
					maxChange(t, files, name, func(root map[string]any) {
						out := root["outbounds"].([]any)[0].(map[string]any)
						switch mutate {
						case "extra-listener":
							root["inbounds"] = append(root["inbounds"].([]any), map[string]any{"type": "direct", "listen": "0.0.0.0"})
						case "outer-dial":
							out["domain_resolver"] = "unowned-bootstrap"
						case "outer-path":
							out["certificate_path"] = "/private/unowned-secret.pem"
						case "outer-credentials":
							if strings.HasPrefix(mode, "max-tls-") {
								out["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)["encryption"] = "none"
							} else {
								out["password"] = ""
							}
						}
					})
				}
				raw, _ := json.Marshal(policy)
				before := pqEncoded(files)
				capture, err := CaptureMAXProfile(mode, before, string(raw))
				if err == nil || capture != nil || pqEncoded(files) != before || strings.Contains(err.Error(), "private-") {
					t.Fatal("invalid chain acquired a lookup-capable capture or exposed a secret", err)
				}
			})
		}
	}
	for _, host := range []string{"", "localhost", "localhost.", "127.0.0.1", "::1", "0.0.0.0", "::", "0.1.2.3", "224.0.0.1", "255.255.255.255", "::ffff:192.0.2.3", "fe80::1%eth0", "-bad.example", "bad_host.example", "bad.example:443", "user@bad.example", "bad.example/path", " bad.example", strings.Repeat("a", 64) + ".example"} {
		files, metadata := maxHostnameFixture(t, "max-quic-wg", "off", host)
		if _, err := CaptureMAXProfile("max-quic-wg", pqEncoded(files), metadata); err == nil {
			t.Errorf("unsafe endpoint acquired a capture: %q", host)
		}
	}
}

func TestMAXResolverRejectsOwnerLossAndUnsafeAnswers(t *testing.T) {
	files, metadata := maxHostnameFixture(t, "max-tls-awg", "aes-256-gcm+xor-whitening", "captured-max.example")
	capture, err := CaptureMAXProfile("max-tls-awg", pqEncoded(files), metadata)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = capture.Resolve(context.Background(), nil); err == nil {
		t.Fatal("missing explicit resolver accepted")
	}
	for _, answers := range [][]netip.Addr{nil, {{}}, {netip.MustParseAddr("127.0.0.1")}, {netip.MustParseAddr("::ffff:192.0.2.9")}, {netip.MustParseAddr("169.254.1.2")}, {netip.MustParseAddr("255.255.255.255")}, make([]netip.Addr, 33)} {
		if result, err := capture.Resolve(context.Background(), func(context.Context, string) ([]netip.Addr, error) { return answers, nil }); result != nil || err == nil {
			t.Fatal("unsafe or unbounded DNS result produced a runtime")
		}
	}
	if result, err := capture.Resolve(context.Background(), func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.9")}, errors.New("private-resolver-secret")
	}); result != nil || err == nil || strings.Contains(err.Error(), "private-") {
		t.Fatal("errored resolver result was adopted or exposed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result, err := capture.Resolve(ctx, func(context.Context, string) ([]netip.Addr, error) {
		t.Fatal("canceled owner performed DNS")
		return nil, nil
	}); result != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("pre-canceled owner was accepted")
	}
	ctx, cancel = context.WithCancel(context.Background())
	entered, finish, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var returned atomic.Bool
	go func() {
		defer close(done)
		result, err := capture.Resolve(ctx, func(ctx context.Context, _ string) ([]netip.Addr, error) {
			close(entered)
			<-ctx.Done()
			<-finish
			return []netip.Addr{netip.MustParseAddr("192.0.2.9")}, nil
		})
		if result != nil || !errors.Is(err, context.Canceled) {
			t.Error("late DNS result adopted after owner cancellation")
		}
		returned.Store(true)
	}()
	<-entered
	cancel()
	if returned.Load() {
		t.Fatal("resolution abandoned its still-running owned lookup")
	}
	close(finish)
	<-done
	if !returned.Load() {
		t.Fatal("canceled owner was not drained")
	}
	result, err := capture.Resolve(context.Background(), func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("::1"), netip.MustParseAddr("2001:db8::9"), netip.MustParseAddr("192.0.2.9")}, nil
	})
	if err != nil || result.Endpoint() != "192.0.2.9" {
		t.Fatal("bounded safe answer preference changed", err)
	}
}

func TestMAXLiteralCaptureAndExactSourceBinding(t *testing.T) {
	files, metadata := maxFixture(t, "max-tls-wg")
	source := pqEncoded(files)
	capture, err := CaptureMAXProfile("max-tls-wg", source, metadata)
	if err != nil || capture.RequiresResolution() {
		t.Fatal("literal capture failed", err)
	}
	result, err := capture.Resolve(context.Background(), func(context.Context, string) ([]netip.Addr, error) {
		t.Fatal("literal MAX performed DNS")
		return nil, nil
	})
	if err != nil || result.Files() != source || result.Metadata() != metadata {
		t.Fatal("literal launch inputs changed", err)
	}
	again, err := CaptureMAXProfile("max-tls-wg", source, metadata)
	if err != nil || again.SourceSHA256() != capture.SourceSHA256() {
		t.Fatal("source binding was nondeterministic")
	}
	for _, input := range [][2]string{{source + "\n", metadata}, {source, metadata + "\n"}} {
		changed, err := CaptureMAXProfile("max-tls-wg", input[0], input[1])
		if err != nil || changed.SourceSHA256() == capture.SourceSHA256() {
			t.Fatal("changed raw source reused a prior capture digest", err)
		}
	}
	// Existing downstream runtime validators stay strict even though selection
	// now understands complete MAX hostnames.
	hostFiles, hostMetadata := maxHostnameFixture(t, "max-tls-wg", "off", "captured-max.example")
	raw, _ := base64.StdEncoding.DecodeString(hostFiles["outer-xray.json"])
	if _, err := applexray.Prepare("reality-xhttp", raw); err == nil {
		t.Fatal("strict Xray runtime accepted hostname")
	}
	if _, err := CompileMAXProfile("max-tls-wg", pqEncoded(hostFiles), hostMetadata); err == nil {
		t.Fatal("strict MAX runtime accepted hostname")
	}
}

func TestMAXHostnameRetainsEffectiveQUICCertificateIdentity(t *testing.T) {
	for _, saved := range []any{nil, "", "separate-certificate.example", true} {
		files, metadata := maxHostnameFixture(t, "max-quic-wg", "aes-256-gcm", "captured-max.example")
		maxChange(t, files, "middle-sing-box.json", func(root map[string]any) {
			trust := root["outbounds"].([]any)[0].(map[string]any)["tls"].(map[string]any)
			if saved == nil {
				delete(trust, "server_name")
			} else {
				trust["server_name"] = saved
			}
		})
		before := pqEncoded(files)
		capture, err := CaptureMAXProfile("max-quic-wg", before, metadata)
		if saved == true {
			if capture != nil || err == nil {
				t.Fatal("invalid TLS identity reached the resolver")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		result, err := capture.Resolve(context.Background(), func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("192.0.2.81")}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		want := "captured-max.example"
		if text, ok := saved.(string); ok && text != "" {
			want = text
		}
		var graph map[string]any
		json.Unmarshal([]byte(result.Config()), &graph)
		if graph["outbounds"].([]any)[1].(map[string]any)["tls"].(map[string]any)["server_name"] != want || pqEncoded(files) != before {
			t.Fatal("resolution changed the effective certificate identity or saved source")
		}
	}
}
