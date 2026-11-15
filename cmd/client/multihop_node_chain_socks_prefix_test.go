package main

import (
	"context"
	"encoding/json"
	"fmt"
	"router-vpn/internal/hopmeasure"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func TestDesktopNodeChainSOCKSCapturedPacketPrefixes(t *testing.T) {
	for _, count := range []int{1, 2, 3, 4, 5, 6} {
		for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
			t.Run(fmt.Sprintf("%s/%d", mode, count), func(t *testing.T) {
				a, nodes := desktopSOCKSPrefixCaptureFixture(t, count, mode, "password", "off")
				final := a.profiles.Profiles[count+1]
				capture, err := captureDesktopNodeChainSOCKS(t.Context(), clientRoot(a), final, a.profiles.Profiles, nodes, "local", nil)
				if err != nil {
					t.Fatal(err)
				}
				_, meta, err := capture.source.ReadValidated()
				if err != nil || len(meta.Proofs) != count+2 || len(capture.original.members) != count+2 {
					t.Fatal("captured desktop inventory lost", err)
				}
				selected, err := resolveDesktopNodeChainSelection(final, a.profiles.Profiles, nodes, "local")
				if err != nil {
					t.Fatal(err)
				}
				selected, err = captureNativeSOCKSNodeChainSelection(t.Context(), clientRoot(a), selected, []string{"shadowsocks"}, nil)
				if err != nil || selected.Native.validateSOCKSNodeChainSelection(selected) != nil {
					t.Fatal("full original public selection rejected", err)
				}
				for _, target := range []string{"linux", "windows", "darwin"} {
					policy, err := mobilemultihop.NewDesktopNodeChainSOCKSPolicy(capture.source, strings.Repeat("a", 32), target, 0)
					if err != nil {
						t.Fatal(target, err)
					}
					_, got, _, err := policy.ReadValidated()
					if err != nil || len(got.Prefixes) != count+2 || got.KillSwitchPolicy != "always" || got.ProfileID != final.ID || got.NodeID != final.NodeProofID || got.FinalTag != meta.Proofs[count+1].Tag {
						t.Fatal("target lost middle protection", target, err)
					}
				}
				changed := append([]common.RouterProfile(nil), a.profiles.Profiles...)
				changed[0] = common.CloneRouterProfile(changed[0])
				changed[0].APIToken += "-foreign"
				if capture.validate(context.Background(), final, changed) == nil {
					t.Fatal("changed earlier prefix retained launch authority")
				}
			})
		}
	}
}

func TestDesktopNodeChainSOCKSPrefixSavedAndMeasuredPositions(t *testing.T) {
	for _, count := range []int{2, 6} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			a, nodes := desktopSOCKSPrefixCaptureFixture(t, count, "wg", "password", "off")
			desktopCONNECTSelectPublicHandler(t, a) // Explicit dispatcher boundary; no installed host acceptance.
			final := a.profiles.Profiles[count+1]
			id := saveOrderedConnectionFixture(t, a, nodes)
			store, err := loadConnectionProfileStore(a)
			if err != nil {
				t.Fatal(err)
			}
			var record connectionProfileRecord
			for _, p := range store.Profiles {
				if p.ID == id {
					record = p
				}
			}
			if len(record.NodeChain) != count+2 || validateSavedNodeChain(record) != nil {
				t.Fatal("saved SOCKS prefix lost exact original members")
			}
			capture, err := captureStartupNodeChain(a, final, a.profiles.Profiles, nil)
			if err != nil {
				t.Fatal(err)
			}
			last := startupSelection{Base: capture.selection.Base, ProfileToken: startupExternalProfileToken(final), RouterID: final.ID, RuntimeMode: "shadowsocks", LogicalMode: "multihop", UpdatedAt: time.Now().UTC(), NodeChain: capture.receipt(), PathKind: startupNodeChainPathKind}
			if err = validateStartupNodeChainSelection(last); err != nil {
				t.Fatal("Last SOCKS prefix lost exact original members", err)
			}
			if last.NodeChain.Nodes[count].NodeKind != "external" || last.NodeChain.Nodes[1].NodeKind == "external" {
				t.Fatal("Last substituted original prefix for SOCKS")
			}
			status := hopmeasure.Status{Complete: true, Drained: true, Stage: "complete"}
			for i, m := range capture.selection.Nodes {
				role, kind := "intermediate", "private-node"
				if i == 0 {
					role = "entry"
				}
				if i == count+1 {
					role = "exit"
				}
				if i == count {
					kind = "public-path"
				}
				status.Results = append(status.Results, hopmeasure.Result{ID: m.Profile.ID, Role: role, Kind: kind, Ready: true, Idle: &hopmeasure.Latency{Samples: 6, Min: 1, Median: 2, Average: 2, P90: 3, Max: 3}, Download: &hopmeasure.Transfer{Bytes: 65536, Seconds: 0.5, Mbps: 1.048576}, Upload: &hopmeasure.Transfer{Bytes: 65536, Seconds: 1, Mbps: 0.524288}})
			}
			if rows, err := desktopNodeChainMeasurementRows(status, capture.selection.Nodes, 65536); err != nil || len(rows) != count+2 || !strings.Contains(rows[count].Latency.Proof, "original socks5 transport") {
				t.Fatal("captured SOCKS measurement positions or transport label refused", err)
			}
			for _, fault := range []string{"position", "missing-source", "foreign-family"} {
				raw, _ := json.Marshal(last)
				var changed startupSelection
				json.Unmarshal(raw, &changed)
				switch fault {
				case "position":
					changed.NodeChain.Nodes[1], changed.NodeChain.Nodes[count] = changed.NodeChain.Nodes[count], changed.NodeChain.Nodes[1]
				case "missing-source":
					changed.NodeChain.Nodes[count].Sources = nil
				case "foreign-family":
					changed.NodeChain.Schema = 4
				}
				if validateStartupNodeChainSelection(changed) == nil {
					t.Fatal("changed startup SOCKS authority", fault)
				}
			}
			status.Results[count].Kind = "private-node"
			if rows, err := desktopNodeChainMeasurementRows(status, capture.selection.Nodes, 65536); err == nil || rows != nil {
				t.Fatal("SOCKS measurement borrowed private proof kind")
			}
		})
	}
}

func TestDesktopNodeChainSOCKSPrefixStartLayers(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				a, nodes := desktopSOCKSPrefixCaptureFixture(t, 2, mode, "password", layer)
				final := a.profiles.Profiles[3]
				captured, err := captureDesktopNodeChainSOCKS(t.Context(), clientRoot(a), final, a.profiles.Profiles, nodes, "local", nil)
				if err != nil {
					t.Fatal("original long SOCKS Start Layer source refused", err)
				}
				_, meta, err := captured.source.ReadValidated()
				if err != nil {
					t.Fatal(err)
				}
				for _, i := range []int{0, 1, 3} {
					if meta.Proofs[i].StartLayer != layer {
						t.Fatal("original Start Layer lost", i, meta.Proofs[i])
					}
				}
				if meta.Proofs[2].StartLayer != "off" || meta.MTU.Ceiling < 1280 {
					t.Fatal("SOCKS acquired a layer or fabricated packet capacity")
				}
			})
		}
	}
}
