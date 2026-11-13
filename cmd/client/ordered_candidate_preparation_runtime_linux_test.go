package main

import (
	"context"
	"testing"

	"router-vpn/internal/mobilemultihop"
)

func TestOrderedCandidateLinuxActivationRetainsExactPurpose(t *testing.T) {
	// This existing model tests retained in-memory capability comparisons. It
	// neither invokes Activate nor substitutes for its mandatory native proof.
	for _, fault := range []string{"unchanged", "missing-launch-purpose", "different-launch-purpose", "different-operation", "different-launch", "missing-chain"} {
		t.Run(fault, func(t *testing.T) {
			h, finish := linuxNodeActivationCaptureModel(t)
			defer finish()
			chain := &mobilemultihop.DesktopNodeChainPolicy{}
			h.policy, h.activation.policy, h.transaction.policy = nil, nil, nil
			h.chain, h.activation.chain, h.transaction.chain = chain, chain, chain
			h.launch.chain = &desktopNodeChainLaunch{policy: chain}
			p := &orderedCandidatePreparation{operation: h.operation, launch: h.launch}
			h.launch.chain.preparation, h.activation.preparation = p, p
			switch fault {
			case "missing-launch-purpose":
				h.launch.chain.preparation = nil
			case "different-launch-purpose":
				h.launch.chain.preparation = &orderedCandidatePreparation{}
			case "different-operation":
				p.operation = context.Background()
			case "different-launch":
				p.launch = &desktopNodeLaunch{}
			case "missing-chain":
				h.launch.chain = nil
			}
			err := h.activation.matches(h)
			if (err == nil) != (fault == "unchanged") {
				t.Fatal("activation lost its exact retained temporary purpose", fault, err)
			}
		})
	}
	h, finish := linuxNodeActivationCaptureModel(t)
	defer finish()
	h.activation.preparation = &orderedCandidatePreparation{}
	if h.activation.matches(h) == nil {
		t.Fatal("ordinary activation adopted candidate purpose")
	}
}
