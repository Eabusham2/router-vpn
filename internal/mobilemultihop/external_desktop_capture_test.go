package mobilemultihop

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func externalDesktopCompile(t *testing.T, graph, selection map[string]any) *ExternalPolicy {
	t.Helper()
	policy, err := NewExternalPolicy(externalTestJSON(t, graph), externalTestJSON(t, selection))
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func externalDesktopCheckRoots(t *testing.T, policy *ExternalPolicy, capture ExternalDesktopCapture) []PhysicalEgress {
	t.Helper()
	graph := externalTestRead(t, policy.Config())
	var actual []PhysicalEgress
	for _, root := range capture.PhysicalRoots {
		if root.Family != "endpoints" && root.Family != "outbounds" {
			t.Fatal("unowned root family", root)
		}
		var matched map[string]any
		for _, item := range graph[root.Family].([]any) {
			value := item.(map[string]any)
			if value["tag"] == root.Tag {
				matched = value
			}
		}
		if matched == nil || root.Type != matched["type"] || root.ConfigSHA256 != externalDigest([]byte(externalTestJSON(t, matched))) || matched["detour"] != nil {
			t.Fatal("desktop selector did not identify its exact complete compiled physical root", root)
		}
		if len(root.Networks) == 0 || len(root.Networks) > 2 || len(root.Destinations) == 0 {
			t.Fatal("desktop root omitted its actual outer transport", root)
		}
		for _, network := range root.Networks {
			if network != "tcp" && network != "udp" {
				t.Fatal("unbounded root network")
			}
		}
		actual = append(actual, root.Destinations...)
	}
	sortPhysicalEgress(actual)
	return actual
}

func TestExternalDesktopCaptureEveryOrdinaryProtocolAndDynamicBoundary(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn"} {
		t.Run(protocol, func(t *testing.T) {
			policy, expected := directEgressFixture(t, protocol)
			capture, err := policy.DesktopCapture()
			if err != nil {
				t.Fatal("validated ordinary graph lost its desktop capture", err)
			}
			if capture.SourceSHA256 != policy.SourceSHA256() || capture.ConfigSHA256 != externalDigest([]byte(policy.Config())) ||
				capture.MetadataSHA256 != externalDigest([]byte(policy.Metadata())) || len(capture.CaptureSHA256) != 64 || capture.Protocol != protocol ||
				capture.FinalTag != ExternalFinalTag || capture.TUNTag == "" || capture.EntryID != "" || capture.KillSwitchPolicy != "off" || capture.SelectedDNS.Physical {
				t.Fatal("desktop capture changed source, policy, path or proof authority", capture)
			}
			actual := externalDesktopCheckRoots(t, policy, capture)
			if protocol == "shadowsocks" {
				expected = append(expected, PhysicalEgress{"203.0.113.20", 443, "udp"})
			}
			sortPhysicalEgress(expected)
			if !reflect.DeepEqual(actual, expected) {
				t.Fatal("desktop physical root changed its exact protocol sockets", actual, expected)
			}
			legacy, legacyErr := policy.PhysicalEgress()
			if protocol == "socks5" {
				root := capture.PhysicalRoots[0]
				if len(capture.PhysicalRoots) != 1 || !root.DynamicSOCKSUDP || root.SOCKSVersion != "5" || root.SOCKSControl == nil || *root.SOCKSControl != (PhysicalEgress{"203.0.113.20", 443, "tcp"}) || !reflect.DeepEqual(root.Networks, []string{"tcp", "udp"}) {
					t.Fatal("dynamic SOCKS lost its exact TCP association or invented a UDP target", root)
				}
				if !errors.Is(legacyErr, ErrDynamicPhysicalEgress) || legacy != nil {
					t.Fatal("desktop accessor weakened legacy fixed relay rejection")
				}
				if fixed, err := policy.DirectPhysicalEgress([]string{"tcp", "udp"}); !errors.Is(err, ErrDynamicPhysicalEgress) || fixed != nil {
					t.Fatal("direct fixed projection acquired a negotiated relay")
				}
			} else {
				if legacyErr != nil || !reflect.DeepEqual(legacy, expected) {
					t.Fatal("ordinary fixed projection changed", legacy, legacyErr)
				}
				for _, root := range capture.PhysicalRoots {
					if root.DynamicSOCKSUDP || root.SOCKSControl != nil || root.SOCKSVersion != "" {
						t.Fatal("unrelated protocol acquired SOCKS association authority")
					}
				}
			}
		})
	}
}

func TestExternalDesktopCaptureEveryPredecessorAndStartLayer(t *testing.T) {
	for _, mode := range predecessorFamilies {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				source, entry := externalPredecessorFixture(t, mode, layer, false)
				graph, selection := externalTestFixture(t, "socks5", "")
				selection["entry"], selection["entry_tag"], selection["predecessor_config"] = entry, externalEntryTag, source
				selection["profile"].(map[string]any)["multihop_entry_mode"] = mode
				policy := externalDesktopCompile(t, graph, selection)
				capture, err := policy.DesktopCapture()
				if err != nil {
					t.Fatal("captured complete predecessor lost its desktop roots", err)
				}
				if capture.EntryID != entry["id"] || capture.EntryTag != externalEntryTag || capture.PredecessorSHA256 != externalDigest([]byte(source)) {
					t.Fatal("desktop capture substituted its complete predecessor")
				}
				externalDesktopCheckRoots(t, policy, capture)
				for _, root := range capture.PhysicalRoots {
					if root.DynamicSOCKSUDP || root.SOCKSControl != nil || root.Tag == ExternalFinalTag {
						t.Fatal("detoured SOCKS relay escaped into a physical exception", root)
					}
				}
				if strings.HasPrefix(mode, "naive-") && len(capture.BootstrapDNS) == 0 {
					t.Fatal("Naive lost its exact native resolver dependency")
				}
			})
		}
	}
	for _, protocol := range externalExecutionProtocols {
		for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run("direct/"+protocol+"/"+layer, func(t *testing.T) {
				source, raw := externalDirectLayerFixture(t, protocol, layer)
				policy, err := NewExternalPolicy(source, raw)
				if err != nil {
					t.Fatal(err)
				}
				capture, err := policy.DesktopCapture()
				if err != nil || capture.StartLayer != layer {
					t.Fatal("direct capture discarded its Start Layer", err)
				}
				externalDesktopCheckRoots(t, policy, capture)
				for _, root := range capture.PhysicalRoots {
					if root.Tag == ExternalFinalTag || root.DynamicSOCKSUDP {
						t.Fatal("Start Layer was bypassed by an inner protocol", root)
					}
				}
			})
		}
	}
}

func externalDesktopDNSFixture(t *testing.T) *ExternalPolicy {
	t.Helper()
	graph, capture := externalTestFixture(t, "shadowsocks", "")
	profile := capture["profile"].(map[string]any)
	profile["kill_switch_policy"], profile["kill_switch"], profile["home_lan_access"] = "always", true, false
	profile["dns_mode"], profile["dns_protocol"], profile["dns_host"], profile["dns_port"] = "custom", "https", "selected.example", float64(5443)
	profile["dns_server_name"], profile["dns_path"] = "selected.example", "/private-dns-query"
	capture["dns_bootstrap"] = map[string]any{
		"server": map[string]any{"tag": "external-dns-bootstrap", "type": "tls", "server": "9.9.9.9", "server_port": float64(8853), "detour": ExternalFinalTag,
			"tls": map[string]any{"enabled": true, "server_name": "bootstrap.example"}},
		"query": map[string]any{"server": "external-dns-bootstrap", "strategy": "prefer_ipv6", "timeout": "9s", "disable_cache": true,
			"disable_optimistic_cache": false, "rewrite_ttl": float64(0), "client_subnet": "198.51.100.0/24"},
	}
	return externalDesktopCompile(t, graph, capture)
}

func TestExternalDesktopCapturePreservesSelectedDNSAndCompleteBootstrap(t *testing.T) {
	policy := externalDesktopDNSFixture(t)
	capture, err := policy.DesktopCapture()
	if err != nil {
		t.Fatal(err)
	}
	dns := capture.SelectedDNS
	query := dns.Resolver
	if dns.Tag != ExternalDNSTag || dns.Type != "https" || dns.Mode != "custom" || dns.Host != "selected.example" || dns.Port != 5443 || dns.ServerName != "selected.example" || dns.Path != "/private-dns-query" || dns.Detour != ExternalFinalTag || dns.Physical ||
		!query.Present || query.Server != "external-dns-bootstrap" || !query.StrategySet || query.Strategy != "prefer_ipv6" || !query.TimeoutSet || query.Timeout != "9s" ||
		query.DisableCache == nil || !*query.DisableCache || query.DisableOptimisticCache == nil || *query.DisableOptimisticCache || query.RewriteTTL == nil || *query.RewriteTTL != 0 ||
		!query.ClientSubnetSet || query.ClientSubnet != "198.51.100.0/24" || len(query.ConfigSHA256) != 64 {
		t.Fatal("selected resolver/query fields changed across desktop capture", dns)
	}
	if len(capture.BootstrapDNS) != 1 {
		t.Fatal("selected hostname lost its complete captured bootstrap", capture.BootstrapDNS)
	}
	bootstrap := capture.BootstrapDNS[0]
	if bootstrap.Tag != query.Server || bootstrap.Type != "tls" || bootstrap.Host != "9.9.9.9" || bootstrap.Port != 8853 || bootstrap.ServerName != "bootstrap.example" || bootstrap.Detour != ExternalFinalTag || bootstrap.Physical || len(bootstrap.ConfigSHA256) != 64 {
		t.Fatal("bootstrap resolver changed transport, port, TLS identity or path", bootstrap)
	}
	if len(capture.PrivateDestinations) != 0 || capture.KillSwitchPolicy != "always" || capture.HomeLANAccess || len(capture.BlockedLANCIDRs) == 0 {
		t.Fatal("desktop DNS capture broadened physical LAN or weakened selected protection")
	}
}

func TestExternalDesktopCaptureCopiesEveryMutableResult(t *testing.T) {
	for _, protocol := range []string{"shadowsocks", "socks5"} {
		var policy *ExternalPolicy
		if protocol == "shadowsocks" {
			policy = externalDesktopDNSFixture(t)
		} else {
			policy, _ = directEgressFixture(t, protocol)
		}
		before, err := policy.DesktopCapture()
		if err != nil {
			t.Fatal(err)
		}
		pristine := externalTestJSON(t, before)
		before.PhysicalRoots[0].Networks[0] = "ip"
		before.PhysicalRoots[0].Destinations[0].Host = "10.99.0.1"
		if before.PhysicalRoots[0].SOCKSControl != nil {
			before.PhysicalRoots[0].SOCKSControl.Port = 1
		}
		if len(before.BlockedLANCIDRs) != 0 {
			before.BlockedLANCIDRs[0] = "0.0.0.0/0"
		}
		if len(before.BootstrapDNS) != 0 {
			before.BootstrapDNS[0].Host = "10.99.0.53"
		}
		if before.SelectedDNS.Resolver.DisableCache != nil {
			*before.SelectedDNS.Resolver.DisableCache = false
		}
		if before.SelectedDNS.Resolver.DisableOptimisticCache != nil {
			*before.SelectedDNS.Resolver.DisableOptimisticCache = true
		}
		if before.SelectedDNS.Resolver.RewriteTTL != nil {
			*before.SelectedDNS.Resolver.RewriteTTL = 999
		}
		after, err := policy.DesktopCapture()
		if err != nil || externalTestJSON(t, after) != pristine {
			t.Fatal("caller modified another immutable desktop capture", err)
		}
	}
}

func TestExternalDesktopCaptureRejectsStaleAndUnconstructedPolicy(t *testing.T) {
	for name, mutate := range map[string]func(*ExternalPolicy){
		"source":   func(p *ExternalPolicy) { p.source = strings.Repeat("0", 64) },
		"config":   func(p *ExternalPolicy) { p.config += " " },
		"metadata": func(p *ExternalPolicy) { p.metadata += " " },
		"profile":  func(p *ExternalPolicy) { p.capture.Profile["home_lan_access"] = true },
		"dns":      func(p *ExternalPolicy) { p.capture.DNSBootstrap.Server["server"] = "10.99.0.53" },
		"query":    func(p *ExternalPolicy) { p.capture.DNSBootstrap.Query["disable_cache"] = false },
		"no-seal":  func(p *ExternalPolicy) { p.desktopSeal = "" },
		"coherent-looking-config-metadata": func(p *ExternalPolicy) {
			p.config += " "
			var meta externalPolicyMetadata
			_ = json.Unmarshal([]byte(p.metadata), &meta)
			meta.ConfigSHA256 = externalDigest([]byte(p.config))
			p.metadata = externalTestJSON(t, meta)
		},
	} {
		t.Run(name, func(t *testing.T) {
			policy := externalDesktopDNSFixture(t)
			mutate(policy)
			if capture, err := policy.DesktopCapture(); err == nil || !reflect.DeepEqual(capture, ExternalDesktopCapture{}) {
				t.Fatal("stale captured source acquired desktop authority", name)
			}
		})
	}
	for _, policy := range []*ExternalPolicy{nil, {}, {source: strings.Repeat("a", 64), config: "{}", metadata: "{}", capture: externalPolicyCapture{Profile: map[string]any{}}}} {
		if capture, err := policy.DesktopCapture(); err == nil || !reflect.DeepEqual(capture, ExternalDesktopCapture{}) {
			t.Fatal("unconstructed policy acquired desktop capture")
		}
	}
}

func TestExternalDesktopCaptureKeepsPrivateExceptionsOnPhysicalPath(t *testing.T) {
	graph, selection := externalTestFixture(t, "shadowsocks", "")
	externalTestFind(t, graph, ExternalFinalTag)["server"] = "10.44.0.20"
	selection["profile"].(map[string]any)["external"].(map[string]any)["shadowsocks"].(map[string]any)["server"] = "10.44.0.20"
	policy := externalDesktopCompile(t, graph, selection)
	capture, err := policy.DesktopCapture()
	if err != nil || !reflect.DeepEqual(capture.PrivateDestinations, []PhysicalEgress{{"10.44.0.20", 443, "tcp"}, {"10.44.0.20", 443, "udp"}}) {
		t.Fatal("explicit physical private peer was changed or broadened", capture.PrivateDestinations, err)
	}
	capture.PrivateDestinations[0].Port = 1
	again, _ := policy.DesktopCapture()
	if again.PrivateDestinations[0].Port != 443 {
		t.Fatal("private destination projection was not copied")
	}
	graph, selection = externalTestFixture(t, "socks5", "")
	externalTestFind(t, graph, ExternalFinalTag)["server"] = "10.44.0.21"
	selection["profile"].(map[string]any)["external"].(map[string]any)["socks5"].(map[string]any)["host"] = "10.44.0.21"
	policy = externalDesktopCompile(t, graph, selection)
	capture, err = policy.DesktopCapture()
	if err != nil || !reflect.DeepEqual(capture.PrivateDestinations, []PhysicalEgress{{"10.44.0.21", 443, "tcp"}}) || !capture.PhysicalRoots[0].DynamicSOCKSUDP {
		t.Fatal("private SOCKS control invented an unnegotiated private UDP exception", capture.PrivateDestinations, err)
	}
	graph, selection = externalTestFixture(t, "shadowsocks", "router-wg")
	selection["profile"].(map[string]any)["dns_mode"] = "home"
	policy = externalDesktopCompile(t, graph, selection)
	capture, err = policy.DesktopCapture()
	if err != nil || len(capture.PrivateDestinations) != 0 || capture.SelectedDNS.Host != "10.77.0.1" || capture.SelectedDNS.Detour != "entry-wg" || capture.SelectedDNS.Physical {
		t.Fatal("Home AdGuard or Router proof became a physical private exception", capture, err)
	}
}

func TestExternalDesktopCaptureExactKillPolicyAndExecution(t *testing.T) {
	for _, item := range []struct {
		policy any
		legacy any
		want   string
	}{
		{"", false, "off"}, {"", true, "on-connect"}, {"off", true, "off"}, {"on-connect", false, "on-connect"}, {"always", true, "always"},
		{" ALWAYS ", true, ""}, {"invalid", false, ""}, {true, false, ""}, {"off", "false", ""},
	} {
		graph, selection := externalTestFixture(t, "shadowsocks", "")
		profile := selection["profile"].(map[string]any)
		profile["kill_switch_policy"], profile["kill_switch"] = item.policy, item.legacy
		policy := externalDesktopCompile(t, graph, selection)
		capture, err := policy.DesktopCapture()
		if item.want == "" {
			if err == nil {
				t.Fatal("malformed kill policy acquired desktop authority", item)
			}
			continue
		}
		if err != nil || capture.KillSwitchPolicy != item.want {
			t.Fatal("exact selected kill policy changed", item, err)
		}
	}
	source, selection := externalExecutionFixture(t, "auto")
	prepared, err := PrepareExternalExecutionCapture(source, selection, "")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewExternalPolicy(source, prepared)
	if err != nil {
		t.Fatal(err)
	}
	capture, err := policy.DesktopCapture()
	if err != nil || capture.Execution != "auto" || capture.EntryID == "" || capture.SelectedDNS.Detour != ExternalFinalTag {
		t.Fatal("comparison capture replaced execution or DNS", capture, err)
	}
	externalDesktopCheckRoots(t, policy, capture)
}
