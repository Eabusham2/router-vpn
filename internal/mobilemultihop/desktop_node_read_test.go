package mobilemultihop

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDesktopNodeValidatedReadRetainsOriginalAndFreshCopies(t *testing.T) {
	policy := desktopNodePlan(t, desktopNodeDNSFixture(t), desktopNodeTestSession, "windows")
	config, meta, capture, err := policy.ReadValidated()
	if err != nil || config != policy.Config() || !reflect.DeepEqual(meta, policy.Metadata()) {
		t.Fatal("combined read changed original validated desktop bytes", err)
	}
	before, err := policy.Capture()
	if err != nil || !reflect.DeepEqual(capture, before) {
		t.Fatal("combined read changed original capture", err)
	}
	meta.Roots[0].Type = "direct"
	*capture.SelectedDNS.Resolver.RewriteTTL = 999
	capture.PhysicalRoots[0].Destinations[0].Port = 1
	capture.BlockedLANCIDRs[0] = "0.0.0.0/0"
	againConfig, againMeta, again, err := policy.ReadValidated()
	if err != nil || againConfig != config || againMeta.Roots[0].Type == "direct" || !reflect.DeepEqual(again, before) {
		t.Fatal("returned operation data aliased retained policy or next capture", err)
	}
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			c, m, v, e := policy.ReadValidated()
			if e != nil || c != againConfig || !reflect.DeepEqual(m, againMeta) || !reflect.DeepEqual(v, before) {
				t.Error("concurrent immutable read changed original authority", e)
				return
			}
			m.Roots[0].Tag = "caller-copy"
			v.PhysicalRoots[0].Destinations[0].Port = 2
		}()
	}
	workers.Wait()
	// A previous successful read is never cached as permission for a later one.
	policy.original.profile["api_token"] = "replacement-secret"
	c, m, v, e := policy.ReadValidated()
	if e == nil || c != "" || !reflect.DeepEqual(m, DesktopNodeMetadata{}) || !reflect.DeepEqual(v, NodeDesktopCapture{}) {
		t.Fatal("post-read source replacement retained a cached read")
	}
	if againConfig != config || !reflect.DeepEqual(again, before) {
		t.Fatal("source replacement rewrote an already captured value")
	}
}

func TestDesktopNodeValidatedReadRechecksDerivedAuthorityAfterRead(t *testing.T) {
	for _, fault := range []string{"config", "metadata", "inputs", "nil"} {
		t.Run(fault, func(t *testing.T) {
			policy := desktopNodePlan(t, desktopNodeFixture(t, "wg", ""), desktopNodeTestSession, "windows")
			if _, _, _, err := policy.ReadValidated(); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "config":
				policy.config += " "
				policy.metadata.ConfigSHA256 = externalDigest([]byte(policy.config))
				policy.seal = policy.currentSeal()
			case "metadata":
				policy.metadata.SessionID = strings.Repeat("b", 32)
				policy.seal = policy.currentSeal()
			case "inputs":
				policy.inputs.restoredMTU = 1400
			case "nil":
				policy = nil
			}
			c, m, v, err := policy.ReadValidated()
			if err == nil || c != "" || !reflect.DeepEqual(m, DesktopNodeMetadata{}) || !reflect.DeepEqual(v, NodeDesktopCapture{}) {
				t.Fatal("resealed or replaced operation returned authority")
			}
		})
	}
}

func TestDesktopNodeValidatedReadMAXMatchesSeparateReads(t *testing.T) {
	// This compiler/validation fixture uses deterministic opaque PQ asset bytes,
	// not a successful cryptographic exchange. Match the large MAX/TLS source
	// shape that exposed repeated JSON validation on the native Windows runner.
	files, profile, start := nodeProfileFixture(t, "max-tls-wg", "")
	var assets map[string]string
	if err := json.Unmarshal([]byte(files), &assets); err != nil {
		t.Fatal(err)
	}
	for name, size := range map[string]int{"rosenpass-client-secret": 13608, "rosenpass-client-public": 524160, "rosenpass-server-public": 524160} {
		assets[name] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{name[len("rosenpass-")]}, size))
	}
	profile["kill_switch_policy"], profile["kill_switch"] = "always", true
	profile["ipv6_mode"], profile["home_lan_access"] = "on", false
	original, err := NewNodeProfile("max-tls-wg", pqEncoded(assets), startJSON(t, profile), start, "")
	if err != nil {
		t.Fatal(err)
	}
	policy := desktopNodePlan(t, original, desktopNodeTestSession, "windows")
	started := time.Now()
	if err := policy.Validate(); err != nil {
		t.Fatal(err)
	}
	config, meta := policy.Config(), policy.Metadata()
	capture, err := policy.Capture()
	separate := time.Since(started)
	if err != nil {
		t.Fatal(err)
	}
	if len(config) < 1<<20 {
		t.Fatal("large MAX source regressed to a small placeholder")
	}
	started = time.Now()
	c, m, v, err := policy.ReadValidated()
	combined := time.Since(started)
	if err != nil || c != config || !reflect.DeepEqual(m, meta) || !reflect.DeepEqual(v, capture) {
		t.Fatal("complete MAX graph diverged during combined read", err)
	}
	t.Logf("same complete MAX graph (%d bytes): separate validated field reads=%s; one validated read=%s", len(config), separate, combined)
}
