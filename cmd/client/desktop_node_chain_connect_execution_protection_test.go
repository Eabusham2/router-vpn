package main

import (
	"context"
	"errors"
	"testing"

	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
)

// This tests actual protection selection with explicitly modeled runtime
// ownership. It does not assert that Windows BFE filters or a TUN were installed.
func TestDesktopCONNECTExecutionProtectionPinsOriginalPreparation(t *testing.T) {
	for _, fault := range []string{"http-server", "https-compare", "omitted", "different-preparation", "foreign-launch", "local-config", "equal-policy", "missing-policy", "mixed-policy", "mixed-source", "mixed-socks"} {
		t.Run(fault, func(t *testing.T) {
			protocol, choice := "https-connect", "auto"
			if fault == "http-server" {
				protocol, choice = "http-connect", "server"
			}
			launch, execution := desktopCONNECTExecutionLaunchFixture(t, "awg2-strong", protocol, "windows", choice)
			if err := execution.attach(launch); err != nil {
				t.Fatal(err)
			}
			owned := &desktopOwnedNodeRuntime{chain: launch.chain}
			attempt := &desktopNodeProtectionAttempt{launch: launch, connectChain: launch.chain.connectPolicy, execution: execution}
			switch fault {
			case "omitted":
				attempt.execution = nil
			case "different-preparation":
				_, other := desktopCONNECTExecutionLaunchFixture(t, "awg2-strong", protocol, "windows", choice)
				attempt.execution = other
			case "foreign-launch":
				attempt.launch = &desktopNodeLaunch{chain: launch.chain}
			case "local-config":
				_, meta, _, err := launch.chain.connectPolicy.ReadValidated()
				if err != nil {
					t.Fatal(err)
				}
				launch.configSHA256 = meta.ConfigSHA256
			case "equal-policy":
				input, err := launch.chain.connectPolicy.LaunchInput()
				if err != nil {
					t.Fatal(err)
				}
				attempt.connectChain, err = mobilemultihop.ParseDesktopNodeChainCONNECTLaunchInput(input)
				if err != nil {
					t.Fatal(err)
				}
			case "missing-policy":
				attempt.connectChain = nil
			case "mixed-policy":
				attempt.chain = &mobilemultihop.DesktopNodeChainPolicy{}
			case "mixed-source":
				attempt.policy = &mobilemultihop.DesktopNodePolicy{}
			case "mixed-socks":
				attempt.socksChain = &mobilemultihop.DesktopNodeChainSOCKSPolicy{}
			}
			selected, err := attempt.selection()
			if fault == "http-server" || fault == "https-compare" {
				if err != nil || selected.config != execution.preparation.ConfigSHA256() || !attempt.matchesOwned(owned) {
					t.Fatal("original CONNECT execution protection lost exact preparation", err)
				}
			} else if err == nil {
				t.Fatal("foreign CONNECT execution protection source accepted")
			}
		})
	}
}

func TestDesktopCONNECTExecutionProtectionBeginRetainsOriginalAuthority(t *testing.T) {
	for _, fault := range []string{"http-server", "https-compare", "paired-original", "equal-policy", "missing-policy", "mixed-policy", "missing-preparation", "cancelled"} {
		t.Run(fault, func(t *testing.T) {
			var launch *desktopNodeLaunch
			var execution *desktopNodeChainExecutionLaunch
			if fault == "paired-original" {
				launch, execution = desktopExecutionAttachedFixture(t, "windows")
			} else {
				protocol, choice := "https-connect", "auto"
				if fault == "http-server" {
					protocol, choice = "http-connect", "server"
				}
				launch, execution = desktopCONNECTExecutionLaunchFixture(t, "wg", protocol, "windows", choice)
				if err := execution.attach(launch); err != nil {
					t.Fatal(err)
				}
			}
			launch.ownedNode = &desktopOwnedNodeRuntime{chain: launch.chain, profileToken: desktopOwnedNodeProfileToken(launch.chain.selection.Control)}
			chain, connect := launch.chain.policy, launch.chain.connectPolicy
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch fault {
			case "equal-policy":
				input, err := connect.LaunchInput()
				if err != nil {
					t.Fatal(err)
				}
				connect, err = mobilemultihop.ParseDesktopNodeChainCONNECTLaunchInput(input)
				if err != nil {
					t.Fatal(err)
				}
			case "missing-policy":
				connect = nil
			case "mixed-policy":
				chain = &mobilemultihop.DesktopNodeChainPolicy{}
			case "missing-preparation":
				execution.preparation = nil
			case "cancelled":
				cancel()
			}
			reads := 0
			slot := &desktopNodeProtectionSlot{backend: desktopNodeProtectionBackend{
				read: func(_ context.Context, previous *mobiletor.DesktopWindowsProtectionTarget) error {
					reads++
					if previous != nil {
						return errors.New("new modeled slot borrowed a previous kernel target")
					}
					return nil
				},
				prepared: func(context.Context, mobiletor.DesktopWindowsProtectionTarget) error {
					return errors.New("source admission cannot claim native preparation")
				},
				release: func(context.Context, mobiletor.DesktopWindowsProtectionTarget) (desktopNodeProtectionRelease, error) {
					return nil, errors.New("source admission cannot claim native retirement")
				},
			}}
			attempt, err := slot.beginConcretePurposesCapturedWithCONNECT(ctx, launch, nil, nil, nil, chain, nil, connect, nil, launch.ownedNode.profileToken)
			valid := fault == "http-server" || fault == "https-compare" || fault == "paired-original"
			if !valid {
				if err == nil || attempt != nil || reads != 0 || slot.active != nil {
					t.Fatal("changed execution source reached original protection transfer")
				}
				return
			}
			if err != nil || attempt == nil || reads != 1 || slot.active != attempt || attempt.execution != execution ||
				attempt.chain != chain || attempt.connectChain != connect || attempt.transfer.ConfigSHA256 != execution.preparation.ConfigSHA256() || !attempt.matchesOwned(launch.ownedNode) {
				t.Fatal("original execution could not begin its typed protection transfer", err)
			}
			selected, err := attempt.selection()
			if err != nil || selected.config != attempt.transfer.ConfigSHA256 {
				t.Fatal("protection attempt lost its original execution config", err)
			}
		})
	}
}
