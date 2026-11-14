//go:build linux

package main

import (
	"context"
	"strings"
	"testing"

	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobilemultihop"
)

func linuxSOCKSPolicyModel(t *testing.T) (*desktopLinuxNodeHost, *desktopLinuxNodeTransaction) {
	t.Helper()
	_, selected, launch := desktopSOCKSPlatformFixture(t, "awg2-strong", "linux")
	_, meta, _, err := launch.chain.readPolicy()
	if err != nil {
		t.Fatal(err)
	}
	source := &desktopNodeChainSources{selection: selected}
	selection := linuxprotection.NodeSelection{SessionID: meta.SessionID, SourceSHA256: meta.SourceSHA256, ConfigSHA256: meta.ConfigSHA256, Policy: meta.KillSwitchPolicy, HomeLAN: meta.HomeLANAccess}
	h := &desktopLinuxNodeHost{socksChain: launch.chain.socksPolicy, launch: launch, source: []byte(launch.chain.input), selection: selection}
	transaction := &desktopLinuxNodeTransaction{socksChain: h.socksChain, chainSources: source, selection: selection, profileID: selected.Control.ID, mode: meta.Mode}
	return h, transaction
}

// These are policy/owner comparisons, not a claim of native kernel readiness.
func TestDesktopLinuxSOCKSParentKeepsExactPolicyAndPrivateInputs(t *testing.T) {
	h, transaction := linuxSOCKSPolicyModel(t)
	if err := transaction.validatePolicy(); err != nil {
		t.Fatal(err)
	}
	policy, err := h.readyPolicy()
	if err != nil || policy != h.socksChain {
		t.Fatal("Linux physical readiness changed concrete owner", err)
	}
	inputs := h.privateInputs()
	if len(inputs) != 2 || inputs[1].name != "node-chain-socks-source.json" || string(inputs[1].body) != h.launch.chain.input {
		t.Fatal("Linux staging replaced typed original input")
	}
	if _, err := mobilemultihop.ParseDesktopNodeChainLaunchInput(string(inputs[1].body)); err == nil {
		t.Fatal("Linux typed source became ordinary chain")
	}
	profile, err := h.capturedProofProfile()
	if err != nil || profile.ID != h.launch.chain.selection.Exit.ID || profile.NodeProofID != h.launch.chain.selection.Exit.NodeProofID || profile.APIToken != h.launch.chain.selection.Exit.APIToken {
		t.Fatal("Linux proof changed original final authority", err)
	}
}
func TestDesktopLinuxSOCKSParentRejectsMixedOrForeignPolicy(t *testing.T) {
	for _, fault := range []string{"foreign-policy", "foreign-source", "ordinary-policy", "foreign-ready", "foreign-input", "foreign-selection"} {
		t.Run(fault, func(t *testing.T) {
			h, transaction := linuxSOCKSPolicyModel(t)
			_, _, other := desktopSOCKSPlatformFixture(t, "awg2-strong", "linux")
			switch fault {
			case "foreign-policy":
				transaction.socksChain = other.chain.socksPolicy
			case "foreign-source":
				transaction.chainSources.selection.Native.chain.socks.source = other.chain.selection.Native.chain.socks.source
			case "ordinary-policy":
				_, ordinary := desktopNodeChainLaunchFixture(t, 3, "linux")
				transaction.chain = ordinary.chain.policy
			case "foreign-ready":
				h.socksChain = other.chain.socksPolicy
				if _, err := h.readyPolicy(); err == nil {
					t.Fatal("Linux readiness adopted foreign typed policy")
				}
				return
			case "foreign-input":
				foreign, err := mobilemultihop.NewDesktopNodeChainSOCKSPolicy(other.chain.selection.Native.chain.socks.source, strings.Repeat("c", 32), "linux", 0)
				if err != nil {
					t.Fatal(err)
				}
				input, err := foreign.LaunchInput()
				if err != nil || input == string(h.source) {
					t.Fatal("foreign-input fixture did not change its canonical original session", err)
				}
				h.source = []byte(input)
				if _, err := h.capturedProofProfile(); err == nil {
					t.Fatal("Linux proof adopted foreign input")
				}
				return
			case "foreign-selection":
				transaction.selection.SourceSHA256 = strings.Repeat("f", 64)
			}
			if err := transaction.validatePolicy(); err == nil {
				t.Fatal("Linux transaction adopted mixed/foreign source")
			}
		})
	}
}
func TestDesktopLinuxSOCKSActivationPinsOriginalConcreteOwner(t *testing.T) {
	for _, fault := range []string{"original", "host-policy", "transaction-policy", "active-policy", "mixed-policy", "joined", "ended"} {
		t.Run(fault, func(t *testing.T) {
			h, finish := linuxNodeActivationCaptureModel(t)
			defer finish()
			typed, _ := linuxSOCKSPolicyModel(t)
			h.policy = nil
			h.socksChain = typed.socksChain
			h.launch.chain = typed.launch.chain
			h.transaction.policy = nil
			h.transaction.socksChain = typed.socksChain
			h.activation.policy = nil
			h.activation.socksChain = typed.socksChain
			switch fault {
			case "host-policy":
				h.socksChain = nil
			case "transaction-policy":
				h.transaction.socksChain = nil
			case "active-policy":
				h.activation.socksChain = nil
			case "mixed-policy":
				_, ordinary := desktopNodeChainLaunchFixture(t, 3, "linux")
				h.activation.chain = ordinary.chain.policy
			case "joined":
				close(h.process.joined)
			case "ended":
				h.activation.cancel()
			}
			err := h.activation.matches(h)
			if (fault == "original") != (err == nil) {
				t.Fatal("typed activation lost exact owner/lifetime comparison", fault, err)
			}
		})
	}
}
func TestDesktopLinuxSOCKSPhysicalRetainsClosedFamily(t *testing.T) {
	h, _ := linuxSOCKSPolicyModel(t)
	_, ordinary := desktopNodeChainLaunchFixture(t, 3, "linux")
	h.chain = ordinary.chain.policy
	if _, err := h.readyPolicy(); err == nil {
		t.Fatal("Linux physical owner accepted simultaneous policy families")
	}
	if err := h.currentNodeChain(context.Background()); err == nil {
		t.Fatal("unprepared mixed host acquired native authority")
	}
}
