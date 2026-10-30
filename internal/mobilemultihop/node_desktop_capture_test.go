package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func desktopNodeFixture(t *testing.T, mode, layer string) *NodeProfile {
	t.Helper()
	files, profile, start := nodeProfileFixture(t, mode, layer)
	profile["kill_switch_policy"], profile["kill_switch"] = "always", true
	profile["ipv6_mode"], profile["home_lan_access"] = "on", false
	compiled, err := NewNodeProfile(mode, files, startJSON(t, profile), start, "")
	if err != nil {
		t.Fatal("complete private Router node fixture did not compile", err)
	}
	return compiled
}

func desktopNodeDNSFixture(t *testing.T) *NodeProfile {
	t.Helper()
	files, profile, start := nodeProfileFixture(t, "wg", "")
	profile["kill_switch_policy"], profile["kill_switch"] = "on-connect", true
	profile["mtu_policy"], profile["manual_mtu"] = "fixed", float64(1392)
	profile["ipv6_mode"], profile["home_lan_access"] = "off", false
	profile["dns_mode"], profile["dns_protocol"], profile["dns_host"] = "custom", "https", "selected.resolver.example"
	profile["dns_port"], profile["dns_server_name"], profile["dns_path"] = float64(4443), "selected.resolver.example", "/captured/query"
	profile["daita_enabled"], profile["daita_rate_kbps"], profile["daita_host"] = true, float64(64), "10.77.0.1"
	bootstrap := map[string]any{
		"server": map[string]any{"type": "udp", "tag": "external-dns-bootstrap", "server": "9.9.9.9", "server_port": 5353, "detour": "proxy"},
		"query":  map[string]any{"server": "external-dns-bootstrap", "strategy": "ipv4_only", "disable_cache": true, "rewrite_ttl": 17},
	}
	compiled, err := NewNodeProfile("wg", files, startJSON(t, profile), start, startJSON(t, bootstrap))
	if err != nil {
		t.Fatal("selected DNS/bootstrap node fixture did not compile", err)
	}
	return compiled
}

func TestNodeDesktopCaptureEveryRawFamilyAndStartLayer(t *testing.T) {
	count := 0
	for _, mode := range predecessorFamilies {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				profile := desktopNodeFixture(t, mode, layer)
				before, metadata := profile.Config(), profile.Metadata()
				capture, err := profile.DesktopCapture()
				if err != nil || capture.SourceSHA256 != profile.SourceSHA256() || capture.ConfigSHA256 != externalDigest([]byte(before)) ||
					capture.MetadataSHA256 != externalDigest([]byte(metadata)) || !proofID.MatchString(capture.CaptureSHA256) ||
					capture.ProfileID != "captured-router" || capture.NodeID != profile.profile["node_proof_id"] || capture.Mode != mode ||
					capture.StartLayer != layer || capture.FinalTag != "proxy" || capture.KillSwitchPolicy != "always" ||
					capture.IPv6Mode != "on" || capture.HomeLANAccess || !capture.UDPAvailable || len(capture.BlockedLANCIDRs) != 4 ||
					capture.MTUPolicy != "auto" || capture.ConfiguredMTU != 1280 || len(capture.PhysicalRoots) == 0 {
					t.Fatal("private Router capture lost exact source, mode or device policy", err)
				}
				if capture.SelectedDNS.Tag != ExternalDNSTag || capture.SelectedDNS.Mode != "home" || capture.SelectedDNS.Type != "udp" ||
					capture.SelectedDNS.Host != "192.168.50.133" || capture.SelectedDNS.Port != 53 || capture.SelectedDNS.Detour != "proxy" || capture.SelectedDNS.Physical {
					t.Fatal("Home AdGuard was substituted or became a physical exception")
				}
				graph := startObject(t, before)
				for _, root := range capture.PhysicalRoots {
					var match map[string]any
					for _, raw := range graph[root.Family].([]any) {
						value := raw.(map[string]any)
						if value["tag"] == root.Tag {
							match = value
						}
					}
					if match == nil || match["type"] != root.Type || predecessorText(match, "detour") != "" ||
						desktopExternalObjectDigest(match) != root.ConfigSHA256 || len(root.Networks) == 0 || len(root.Destinations) == 0 || root.DynamicSOCKSUDP {
						t.Fatal("captured root was not an exact original outer transport")
					}
				}
				for _, destination := range capture.PrivateDestinations {
					physical := false
					for _, root := range capture.PhysicalRoots {
						for _, tuple := range root.Destinations {
							physical = physical || tuple == destination
						}
					}
					for _, resolver := range capture.BootstrapDNS {
						physical = physical || resolver.Physical && resolver.Host == destination.Host && resolver.Port == destination.Port
					}
					if !physical {
						t.Fatal("private application DNS or node proof target escaped into physical exceptions")
					}
				}
				again, err := profile.DesktopCapture()
				if err != nil || !reflect.DeepEqual(again, capture) || profile.Config() != before || profile.Metadata() != metadata {
					t.Fatal("node projection changed immutable constructor output", err)
				}
				count++
			})
		}
	}
	if count != 57 {
		t.Fatal("missing complete Router mode/Start Layer captures", count)
	}
}

func TestNodeDesktopCapturePreservesDNSAndIndependentCopies(t *testing.T) {
	profile := desktopNodeDNSFixture(t)
	before, err := profile.DesktopCapture()
	if err != nil || before.SelectedDNS.Type != "https" || before.SelectedDNS.Host != "selected.resolver.example" || before.SelectedDNS.Port != 4443 ||
		before.SelectedDNS.ServerName != "selected.resolver.example" || before.SelectedDNS.Path != "/captured/query" ||
		before.SelectedDNS.Resolver.DisableCache == nil || !*before.SelectedDNS.Resolver.DisableCache ||
		before.SelectedDNS.Resolver.RewriteTTL == nil || *before.SelectedDNS.Resolver.RewriteTTL != 17 ||
		len(before.BootstrapDNS) != 1 || before.BootstrapDNS[0].Physical || before.BootstrapDNS[0].Detour != "proxy" ||
		before.BootstrapDNS[0].Port != 5353 || before.MTUPolicy != "fixed" || before.ConfiguredMTU != 1392 || before.IPv6Mode != "off" {
		t.Fatal("node capture changed selected DNS/bootstrap query or fixed device policy", err)
	}
	copy, err := profile.DesktopCapture()
	if err != nil {
		t.Fatal(err)
	}
	copy.PhysicalRoots[0].Networks[0] = "ip"
	copy.PhysicalRoots[0].Destinations[0].Host = "10.8.0.1"
	copy.BlockedLANCIDRs[0] = "0.0.0.0/0"
	copy.BootstrapDNS[0].Host = "10.8.0.53"
	*copy.SelectedDNS.Resolver.DisableCache = false
	*copy.SelectedDNS.Resolver.RewriteTTL = 99
	again, err := profile.DesktopCapture()
	if err != nil || !reflect.DeepEqual(again, before) {
		t.Fatal("caller mutation changed private node capture authority", err)
	}
}

func TestNodeDesktopCapturePrivateExceptionIsActualOuterTuple(t *testing.T) {
	files, profile, start := nodeProfileFixture(t, "wg", "")
	var assets map[string]string
	if json.Unmarshal([]byte(files), &assets) != nil {
		t.Fatal("invalid fixture assets")
	}
	for name, encoded := range assets {
		body, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		assets[name] = base64.StdEncoding.EncodeToString([]byte(strings.ReplaceAll(string(body), "192.0.2.1", "10.8.0.9")))
	}
	profile["endpoint"], profile["kill_switch_policy"] = "10.8.0.9", "always"
	node, err := NewNodeProfile("wg", startJSON(t, assets), startJSON(t, profile), start, "")
	if err != nil {
		t.Fatal(err)
	}
	capture, err := node.DesktopCapture()
	if err != nil || len(capture.PrivateDestinations) != 1 || capture.PrivateDestinations[0].Host != "10.8.0.9" ||
		capture.PrivateDestinations[0].Network != "udp" || capture.PrivateDestinations[0].Port == 0 {
		t.Fatal("private exception was not the exact captured physical endpoint", err)
	}
}

func TestNodeDesktopCaptureRejectsUnconstructedAndSubstitutedAuthority(t *testing.T) {
	for name, mutate := range map[string]func(*NodeProfile){
		"config": func(p *NodeProfile) { p.config += " " }, "metadata": func(p *NodeProfile) { p.metadata += " " },
		"source": func(p *NodeProfile) { p.source = strings.Repeat("f", 64) }, "mode": func(p *NodeProfile) { p.mode = "shadowsocks" },
		"profile": func(p *NodeProfile) { p.profile["api_token"] = "another-private-node" },
		"inputs":  func(p *NodeProfile) { p.inputs.ProfileJSON += " " }, "files": func(p *NodeProfile) { p.inputs.Files += " " },
		"start": func(p *NodeProfile) { p.inputs.Start = p.inputs.Files }, "bootstrap": func(p *NodeProfile) { p.inputs.DNSBootstrap = `{}` },
		"seal": func(p *NodeProfile) { p.desktopSeal = "" },
	} {
		t.Run(name, func(t *testing.T) {
			profile := desktopNodeFixture(t, "wg", "")
			mutate(profile)
			if _, err := profile.DesktopCapture(); err == nil {
				t.Fatal("substituted source gained a desktop node capture")
			}
			if _, err := profile.LaunchInput(); err == nil {
				t.Fatal("substituted source gained a private launch envelope")
			}
		})
	}
	valid := desktopNodeFixture(t, "wg", "")
	for _, profile := range []*NodeProfile{nil, {}, {config: valid.config, source: valid.source, metadata: valid.metadata, mode: valid.mode, profile: valid.profile}} {
		if _, err := profile.DesktopCapture(); err == nil {
			t.Fatal("copied public output replaced constructor authority")
		}
	}
}

func TestNodeLaunchInputRecompilesEveryOriginalModeAndLayer(t *testing.T) {
	for _, mode := range predecessorFamilies {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			profile := desktopNodeFixture(t, mode, layer)
			raw, err := profile.LaunchInput()
			if err != nil {
				t.Fatal(err)
			}
			rebuilt, err := ParseNodeLaunchInput(raw)
			if err != nil || rebuilt == profile || rebuilt.Config() != profile.Config() || rebuilt.Metadata() != profile.Metadata() ||
				rebuilt.SourceSHA256() != profile.SourceSHA256() || rebuilt.inputs != profile.inputs {
				t.Fatal("native launch reconstruction changed exact original private inputs or bytes", mode, layer, err)
			}
			again, err := rebuilt.LaunchInput()
			if err != nil || again != raw {
				t.Fatal("recompiled native launch envelope was not canonical", err)
			}
		}
	}
}

func TestNodeLaunchInputRejectsAmbiguousStaleAndPartialRecords(t *testing.T) {
	profile := desktopNodeDNSFixture(t)
	raw, err := profile.LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &record) != nil {
		t.Fatal("invalid canonical launch fixture")
	}
	reject := func(candidate string) {
		t.Helper()
		if rebuilt, err := ParseNodeLaunchInput(candidate); err == nil || rebuilt != nil || strings.Contains(err.Error(), "captured-secret-token") {
			t.Fatal("native child adopted a malformed launch record or exposed private input")
		}
	}
	for name := range record {
		changed := make(map[string]json.RawMessage, len(record))
		for key, value := range record {
			changed[key] = value
		}
		delete(changed, name)
		body, _ := json.Marshal(changed)
		reject(string(body))
		changed[name] = json.RawMessage(`null`)
		body, _ = json.Marshal(changed)
		reject(string(body))
	}
	for _, candidate := range []string{
		"", "null", raw + "\n", " " + raw, raw + raw, strings.Repeat(" ", NodeLaunchInputLimit+1),
		strings.Replace(raw, `"schema":1`, `"schema":1,"schema":1`, 1),
		strings.Replace(raw, `"schema":1`, `"schema":2`, 1),
		strings.Replace(raw, `"schema":1`, `"schema":"1"`, 1),
		strings.Replace(raw, `"schema":1`, `"Schema":1`, 1),
		strings.Replace(raw, `"schema":1`, `"schema":1,"unknown":true`, 1),
	} {
		reject(candidate)
	}
	var typed nodeLaunchInputRecord
	if json.Unmarshal([]byte(raw), &typed) != nil {
		t.Fatal("invalid typed launch fixture")
	}
	for _, mutate := range []func(*nodeLaunchInputRecord){
		func(r *nodeLaunchInputRecord) { r.Mode = "shadowsocks" }, func(r *nodeLaunchInputRecord) { r.Files = "{}" },
		func(r *nodeLaunchInputRecord) {
			r.ProfileJSON = strings.Replace(r.ProfileJSON, "captured-secret-token", "another-private-token", 1)
		},
		func(r *nodeLaunchInputRecord) { r.Start = r.Files }, func(r *nodeLaunchInputRecord) { r.DNSBootstrap = "" },
		func(r *nodeLaunchInputRecord) { r.SourceSHA256 = strings.Repeat("a", 64) },
		func(r *nodeLaunchInputRecord) { r.ConfigSHA256 = strings.Repeat("b", 64) },
		func(r *nodeLaunchInputRecord) { r.MetadataSHA256 = strings.Repeat("c", 64) },
	} {
		copy := typed
		mutate(&copy)
		body, _ := json.Marshal(copy)
		reject(string(body))
	}
}
