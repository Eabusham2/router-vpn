package main

import (
	"encoding/json"
	"fmt"
	"testing"

	"router-vpn/internal/mobilemultihop"
)

// These tests use the actual full paired source compiler and original physical
// preparation. They do not establish installed Darwin PF or remote Linux traffic.
func TestDesktopPairedSSExecutionOriginalPreparation(t *testing.T) {
	for _, count := range []int{2, 4, 8} {
		for _, choice := range []string{"server", "auto"} {
			t.Run(fmt.Sprintf("%d/%s", count, choice), func(t *testing.T) {
				_, launch := desktopNodeChainLaunchFixture(t, count, "darwin")
				if !desktopPairedSSExecutionMembers(launch.chain.selection.Nodes, choice) {
					t.Fatal("original paired SS family refused")
				}
				source, err := newDesktopNodeChainExecutionSource(launch.chain, choice)
				if err != nil {
					t.Fatal(err)
				}
				if source.physical == nil || source.connectPhysical != nil || source.socksPhysical != nil || source.openvpnPhysical != nil {
					t.Fatal("paired SS borrowed typed authority")
				}
				original, err := source.physical.OriginalDesktopPolicy()
				if err != nil || original != launch.chain.policy {
					t.Fatal("paired SS replaced original physical policy", err)
				}
				var captured mobilemultihop.NodeChainSource
				if json.Unmarshal([]byte(source.preparation.LocalSource()), &captured) != nil || captured.Schema != 1 || len(captured.Nodes) != count || len(captured.IdentitySources) != count {
					t.Fatal("paired SS source was truncated or retyped")
				}
				proofs := launch.chain.policy.OriginalChain().ProofInventory()
				if len(proofs) != count || proofs[count-1].Mode != "shadowsocks" {
					t.Fatal("paired SS proof inventory changed")
				}
				for _, proof := range proofs {
					if proof.NodeID == "" || proof.NodeKind == "external" {
						t.Fatal("paired SS lost private proof identity")
					}
				}
				_, metadata, physical, err := source.readPolicy()
				if err != nil || metadata.TargetOS != "darwin" || metadata.Mode != "shadowsocks" || metadata.KillSwitchPolicy != "on-connect" || physical.SelectedDNS.Detour != mobilemultihop.SelectorTag || physical.SelectedDNS.Physical {
					t.Fatal("paired SS lost target, DNS or protection", err)
				}
				if err = source.attach(launch); err != nil {
					t.Fatal(err)
				}
				if err = source.bound(launch); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestDesktopPairedSSExecutionAdmissionRefusals(t *testing.T) {
	_, launch := desktopNodeChainLaunchFixture(t, 4, "darwin")
	for _, fault := range []string{"local", "duplicate-id", "duplicate-proof", "foreign-kind", "wrong-prefix", "wrong-final", "unknown-layer", "too-short", "too-long"} {
		t.Run(fault, func(t *testing.T) {
			members := cloneDesktopNodeChainMembers(launch.chain.selection.Nodes)
			requested := "server"
			switch fault {
			case "local":
				requested = "local"
			case "duplicate-id":
				members[3].Profile.ID = members[0].Profile.ID
			case "duplicate-proof":
				members[3].Profile.NodeProofID = members[0].Profile.NodeProofID
			case "foreign-kind":
				members[1].Profile.NodeKind = "external"
			case "wrong-prefix":
				members[1].Mode = "hysteria2"
			case "wrong-final":
				members[3].Mode = "hysteria2"
			case "unknown-layer":
				members[3].Profile.StartLayer = "unrecognized"
			case "too-short":
				members = members[3:]
			case "too-long":
				members = append(members, members...)
				members = append(members, members[0])
			}
			if desktopPairedSSExecutionMembers(members, requested) {
				t.Fatal("paired SS admitted foreign family/source shape", fault)
			}
		})
	}
	for _, layer := range []string{"", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		members := cloneDesktopNodeChainMembers(launch.chain.selection.Nodes)
		for i := range members {
			members[i].Profile.StartLayer = layer
		}
		if !desktopPairedSSExecutionMembers(members, "auto") {
			t.Fatal("paired SS lost independently supported layer", layer)
		}
	}
}

func TestDesktopPairedSSExecutionRetainsOriginalPreparationOwner(t *testing.T) {
	for _, fault := range []string{"replayed-preparation", "replayed-physical", "changed-private-source"} {
		t.Run(fault, func(t *testing.T) {
			_, launch := desktopNodeChainLaunchFixture(t, 4, "darwin")
			source, err := newDesktopNodeChainExecutionSource(launch.chain, "auto")
			if err != nil {
				t.Fatal(err)
			}
			original, physical := source.preparation, source.physical
			if _, _, _, err = source.readPolicy(); err != nil {
				t.Fatal("original paired SS observation refused", err)
			}
			switch fault {
			case "replayed-preparation", "replayed-physical":
				replayed, failure := mobilemultihop.ParseDesktopNodeChainExecutionPreparation(original.Source())
				if failure != nil || replayed == original {
					t.Fatal("actual original source replay unavailable", failure)
				}
				if fault == "replayed-preparation" {
					source.preparation = replayed
				} else {
					source.physical, err = replayed.DesktopPhysicalPolicy()
					if err != nil || source.physical == physical {
						t.Fatal("actual foreign physical replay unavailable", err)
					}
				}
			case "changed-private-source":
				launch.chain.selection.Nodes[1].Profile.APIToken = "replacement-private-token"
			}
			if _, _, _, err = source.readPolicy(); err == nil {
				t.Fatal("paired SS borrowed equal-valued or changed source authority", fault)
			}
		})
	}
}
