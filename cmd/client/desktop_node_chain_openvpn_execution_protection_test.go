package main

import (
	"context"
	"errors"
	"testing"

	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
)

func TestDesktopOpenVPNExecutionProtectionRetainsOriginalSource(t *testing.T) {
	for _, fault := range []string{"server", "auto", "missing-execution", "foreign-execution", "foreign-launch", "local-config", "equal-policy", "missing-policy", "SOCKS-policy", "CONNECT-policy"} {
		t.Run(fault, func(t *testing.T) {
			choice := "auto"
			if fault == "server" {
				choice = "server"
			}
			_, _, launch, execution, _ := desktopOpenVPNExecutionLaunchFixture(t, 4, "windows", choice)
			if err := execution.attach(launch); err != nil {
				t.Fatal(err)
			}
			owned := &desktopOwnedNodeRuntime{chain: launch.chain}
			attempt := &desktopNodeProtectionAttempt{launch: launch, chain: launch.chain.policy, execution: execution}
			switch fault {
			case "missing-execution":
				attempt.execution = nil
			case "foreign-execution":
				_, _, _, attempt.execution, _ = desktopOpenVPNExecutionLaunchFixture(t, 4, "windows", choice)
			case "foreign-launch":
				attempt.launch = &desktopNodeLaunch{chain: launch.chain}
			case "local-config":
				_, meta, _, err := launch.chain.policy.ReadValidated()
				if err != nil {
					t.Fatal(err)
				}
				launch.configSHA256 = meta.ConfigSHA256
			case "equal-policy":
				input, err := launch.chain.policy.NodeChain().LaunchInput()
				if err != nil {
					t.Fatal(err)
				}
				attempt.chain, err = mobilemultihop.ParseDesktopNodeChainLaunchInput(input)
				if err != nil {
					t.Fatal(err)
				}
			case "missing-policy":
				attempt.chain = nil
			case "SOCKS-policy":
				attempt.socksChain = &mobilemultihop.DesktopNodeChainSOCKSPolicy{}
			case "CONNECT-policy":
				attempt.connectChain = &mobilemultihop.DesktopNodeChainCONNECTPolicy{}
			}
			selection, err := attempt.selection()
			if fault == "server" || fault == "auto" {
				if err != nil || selection.config != execution.preparation.ConfigSHA256() || !attempt.matchesOwned(owned) {
					t.Fatal("OpenVPN protection lost its exact source and preparation", err)
				}
			} else if err == nil {
				t.Fatal("foreign OpenVPN execution acquired original protection authority")
			}
		})
	}
}

// Only the kernel backend is modeled. Shipping source admission must refuse
// changed owners before the first protection read or transfer allocation.
func TestDesktopOpenVPNExecutionProtectionBeginChecksOriginalBeforeBackend(t *testing.T) {
	for _, fault := range []string{"server", "auto", "equal-policy", "missing-policy", "mixed-CONNECT", "missing-preparation", "cancelled"} {
		t.Run(fault, func(t *testing.T) {
			choice := "auto"
			if fault == "server" {
				choice = "server"
			}
			_, _, launch, execution, _ := desktopOpenVPNExecutionLaunchFixture(t, 4, "windows", choice)
			if err := execution.attach(launch); err != nil {
				t.Fatal(err)
			}
			launch.ownedNode = &desktopOwnedNodeRuntime{chain: launch.chain, profileToken: desktopOwnedNodeProfileToken(launch.chain.selection.Control)}
			policy := launch.chain.policy
			var connect *mobilemultihop.DesktopNodeChainCONNECTPolicy
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch fault {
			case "equal-policy":
				input, err := policy.NodeChain().LaunchInput()
				if err != nil {
					t.Fatal(err)
				}
				policy, err = mobilemultihop.ParseDesktopNodeChainLaunchInput(input)
				if err != nil {
					t.Fatal(err)
				}
			case "missing-policy":
				policy = nil
			case "mixed-CONNECT":
				connect = &mobilemultihop.DesktopNodeChainCONNECTPolicy{}
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
						return errors.New("modeled empty slot borrowed another target")
					}
					return nil
				},
				prepared: func(context.Context, mobiletor.DesktopWindowsProtectionTarget) error {
					return errors.New("source model has no kernel preparation")
				},
				release: func(context.Context, mobiletor.DesktopWindowsProtectionTarget) (desktopNodeProtectionRelease, error) {
					return nil, errors.New("source model has no kernel retirement")
				},
			}}
			attempt, err := slot.beginConcretePurposesCapturedWithCONNECT(ctx, launch, nil, nil, nil, policy, nil, connect, nil, launch.ownedNode.profileToken)
			if fault != "server" && fault != "auto" {
				if err == nil || attempt != nil || reads != 0 || slot.active != nil {
					t.Fatal("changed OpenVPN source reached the original protection backend")
				}
				return
			}
			if err != nil || attempt == nil || reads != 1 || slot.active != attempt || attempt.execution != execution || attempt.chain != policy ||
				attempt.transfer.ConfigSHA256 != execution.preparation.ConfigSHA256() || !attempt.matchesOwned(launch.ownedNode) {
				t.Fatal("OpenVPN execution lost its original protection transfer", err)
			}
		})
	}
}
