//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// The original full graph points at an unopened final SS port. A separately
// saved candidate retains the real 8388 endpoint. Prefix Test must never need
// the original final to establish application, DNS or ordinary readiness.
func linuxNodeChainPrefixCandidateSources(t *testing.T, peer *linuxNodeChainPeer) (common.RouterProfileStore, map[string]map[string]map[string][]byte) {
	t.Helper()
	store, assets := linuxNodeChainInstalledSources(t, peer, "")
	final := store.Profiles[len(store.Profiles)-1]
	candidate := cloneRouterProfile(final)
	candidate.ID, candidate.Name = "installed-prefix-candidate", "Original independent prefix candidate"
	candidate.MultihopEnabled = false
	candidate.MultihopNodes = nil
	candidate.MultihopEntryID, candidate.MultihopExitID, candidate.MultihopEntryMode = "", "", ""
	if err := common.NormalizeRouterProfile(&candidate); err != nil {
		t.Fatal(err)
	}
	assets[candidate.ID] = map[string]map[string][]byte{}
	for mode, files := range assets[final.ID] {
		assets[candidate.ID][mode] = map[string][]byte{}
		for name, data := range files {
			assets[candidate.ID][mode][name] = append([]byte(nil), data...)
		}
	}
	var original map[string]any
	if json.Unmarshal(assets[final.ID]["shadowsocks"]["sing-box.json"], &original) != nil {
		t.Fatal("missing original paired final source")
	}
	original["outbounds"].([]any)[0].(map[string]any)["server_port"] = 1
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	assets[final.ID]["shadowsocks"]["sing-box.json"] = raw
	store.Profiles = append(store.Profiles, candidate)
	return store, assets
}

func linuxHostTUNPrefixAbsent(record *mobilemultihop.DesktopNodeCandidatePreparationReadyRecord) error {
	if record == nil || record.InterfaceName == "" || record.InterfaceIndex == 0 {
		return errors.New("prefix DOWN omitted its actual original TUN identity")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, iface := range interfaces {
		if iface.Index == int(record.InterfaceIndex) || iface.Name == record.InterfaceName {
			return errors.New("prefix DOWN retained or substituted its original native TUN")
		}
	}
	return nil
}

func linuxHostTUNPrefixCandidateParent(t *testing.T, installed, scenario, action string, modes []string, peer *linuxNodeChainPeer) {
	t.Helper()
	process := linuxHostTUNStartController(t, installed, scenario)
	if _, err := process.gate.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	result := process.readNodeChain(t, scenario)
	r, proof := result.Prepared, result.PrefixProof
	if result.Stage != "review" || !result.Retired || result.Session == "" || result.Ready != nil || result.Proof != nil || proof == nil ||
		!proof.Prepared || proof.ApplicationOpen || proof.DNSOpen || proof.Generation != 1 || proof.Identity.SessionID != result.Session ||
		len(proof.Prefixes) != len(modes) || proof.InterfaceIndex == 0 || proof.InterfaceName == "" || proof.MTU < 576 ||
		r == nil || r.Action != action || !validViaEntryRequestID(r.RequestID) || len(r.ViewToken) != 64 || !r.NativeDown || !r.Observer || r.Drained || r.SavedID != "" || !r.ProfileSame ||
		len(result.Nodes) != len(modes)+1 || r.Row.PrefixPosition != len(modes)-1 || r.Row.CandidateID != "installed-prefix-candidate" || !r.Row.Complete || !r.Row.Drained ||
		len(r.Row.Results) != 1 || r.Row.Results[0].Benchmark == nil || r.Row.Results[0].Benchmark.Attempts != 50 || r.Row.Results[0].Benchmark.Distribution == nil || r.Row.Results[0].Benchmark.Distribution.Samples != 50 {
		t.Fatal("installed prefix API omitted its separate closed proof and actual fifty-sample native DOWN review", result)
	}
	deadline := time.Now().Add(time.Second)
	var counters linuxNodeChainPeerReply
	for {
		counters = peer.observe(t, "stats")
		if counters.Final.FinalRawTCP == 50 {
			break
		}
		if counters.Final.FinalRawTCP > 50 || time.Now().After(deadline) {
			t.Fatal("prefix API omitted exact independent fifty TCP destination handshakes", counters)
		}
		time.Sleep(time.Millisecond)
	}
	if counters.Final.FinalTCP != 0 || counters.Final.FinalUDP != 0 || counters.Final.RouterQueries != 0 || counters.Final.DNSQueries != 0 || counters.Final.FinalPublicQueries != 0 || counters.Final.DirectQueries != 0 {
		t.Fatal("prefix-only API attempted original final authentication, application traffic, DNS or direct proof", counters)
	}
	for i, prefix := range counters.Prefixes {
		if result.Nodes[i].Mode != modes[i] || prefix.Mode != modes[i] || prefix.RawUDP == 0 || prefix.TCP == 0 || prefix.ProofQueries == 0 || prefix.AuthRefusals != 0 || !proof.Prefixes[i].Proven {
			t.Fatal("prefix-only API bypassed its original encrypted private prefix", i, prefix)
		}
	}
	if _, err := process.gate.Write([]byte{2}); err != nil {
		t.Fatal(err)
	}
	final := process.readNodeChain(t, scenario)
	if final.Stage != "retired" || !final.Retired || final.Session != result.Session || final.Ready != nil || final.Proof != nil || !reflect.DeepEqual(final.PrefixProof, proof) ||
		final.Prepared == nil || final.Prepared.RequestID != r.RequestID || final.Prepared.ViewToken != r.ViewToken || !final.Prepared.NativeDown || final.Prepared.Observer || !final.Prepared.Drained || !final.Prepared.ProfileSame ||
		!reflect.DeepEqual(final.Prepared.Row, r.Row) || (final.Prepared.SavedID != "") != (action == "prefix-candidates-save") {
		t.Fatal("installed prefix explicit decision lost its original closed proof or joined Save provenance", final)
	}
	select {
	case <-process.done:
		if process.waitErr != nil {
			t.Fatal(process.waitErr, process.diagnostic.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("installed prefix controller did not join")
	}
	t.Log("verified installed host native lifecycle:", scenario)
	t.Log("verified installed host closed selected prefix fifty samples final unopened native DOWN and explicit decision:", scenario)
}

func TestDesktopLinuxInstalledPrefixCandidateFixtureKeepsClosedAuthority(t *testing.T) {
	for _, item := range []struct {
		name  string
		modes []string
	}{{"wg", []string{"wg", "wg"}}, {"awg-fast", []string{"awg2-fast", "wg"}}, {"awg-strong", []string{"awg2-strong", "awg2-fast"}}} {
		t.Run(item.name, func(t *testing.T) {
			peer := linuxNodeChainPeerKeys(t, 3)
			linuxNodeChainSetModes(t, peer, item.modes)
			peer.reply.Address = "192.168.210.2:51820"
			store, assets := linuxNodeChainPrefixCandidateSources(t, peer)
			root := t.TempDir()
			for id, modes := range assets {
				for mode, files := range modes {
					directory := filepath.Join(root, "generated", id, mode)
					if err := os.MkdirAll(directory, 0700); err != nil {
						t.Fatal(err)
					}
					for name, data := range files {
						if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			raw, _ := json.Marshal(store)
			if err := os.WriteFile(filepath.Join(root, "routers.json"), raw, 0600); err != nil {
				t.Fatal(err)
			}
			a := &app{profiles: store, state: state{Mode: "off", Phase: "off"}, cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "routers.json"), ModesFile: filepath.Join(root, "modes.json"), ScriptsDir: filepath.Join(root, "modes"), StateFile: filepath.Join(root, "state.json")}}
			q := orderedCandidatePreparationRequest{Scope: orderedCandidateSavedPrefixScope, RequestID: strings.Repeat("a", 32), Position: 1, CandidateIDs: []string{"installed-prefix-candidate"}, Samples: 50}
			p, err := beginOrderedCandidatePreparationWithNetwork(context.Background(), a, q, func(ctx context.Context) (string, error) { return "source-only-physical", ctx.Err() })
			if err != nil {
				t.Fatal(err)
			}
			defer p.finish()
			full := string(assets[store.SelectedID]["shadowsocks"]["sing-box.json"])
			candidate := string(assets[q.CandidateIDs[0]]["shadowsocks"]["sing-box.json"])
			if !strings.Contains(full, `"server_port":1`) || !strings.Contains(candidate, `"server_port":8388`) || full == candidate {
				t.Fatal("prefix fixture lost independently unavailable original final and real candidate")
			}
			launch, err := newDesktopNodeCandidatePrefixLaunchForPurpose(context.Background(), p.selection, strings.Repeat("b", 32), "linux", p)
			if err != nil {
				t.Fatal(err)
			}
			meta := launch.candidatePrefix.policy.Metadata()
			if meta.ApplicationOpen || meta.DNSOpen || len(meta.Prefixes) != 2 || meta.PolicyProfileID != store.SelectedID || meta.ProfileID == store.SelectedID || launch.chain != nil || launch.command != nil || p.inventory.current(context.Background()) == nil {
				t.Fatal("installed prefix source fixture manufactured ordinary or final authority")
			}
			for i, mode := range item.modes {
				if meta.Prefixes[i].ProfileID != store.Profiles[i].ID || p.selection.Nodes[i].Mode != mode {
					t.Fatal("prefix source fixture changed independent mode or profile")
				}
			}
		})
	}
}
