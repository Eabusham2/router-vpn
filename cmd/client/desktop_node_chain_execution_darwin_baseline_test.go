package main

import (
	"encoding/json"
	"testing"

	"router-vpn/internal/macosprocess"
)

func TestDesktopMacOSExecutionBaselineRetainsExactFamily(t *testing.T) {
	for _, policy := range []string{"on-connect", "always"} {
		for _, phase := range []string{"active", "held", "retired"} {
			t.Run(policy+"/"+phase, func(t *testing.T) {
				value := macOSNodeChainBaselineFixture(policy, phase)
				value.Capture.Family = macosprocess.NodeChainExecutionFamily
				raw, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				got, err := decodeDesktopMacOSNodeChainReceipt(raw, value.Capture, phase)
				if err != nil || got != value {
					t.Fatal("execution family lost its complete captured baseline", err)
				}
				for _, family := range []macosprocess.Family{macosprocess.ExternalFamily, macosprocess.NodeChainFamily,
					macosprocess.NodeChainSOCKSFamily, macosprocess.NodeChainCONNECTFamily, macosprocess.CandidatePrefixFamily,
					"ordered-node-chain-execution", "ordered-node-chain-execution-v2", "Ordered-node-chain-execution-v1"} {
					t.Run(string(family), func(t *testing.T) {
						foreign := value.Capture
						foreign.Family = family
						if _, err := decodeDesktopMacOSNodeChainReceipt(raw, foreign, phase); err == nil {
							t.Fatal("execution PF receipt became another concrete owner")
						}
						if _, err := encodeDesktopMacOSNodeChainBaselineRequest(foreign, "release", &value); err == nil {
							t.Fatal("foreign family acquired execution retirement authority")
						}
					})
				}
				for _, action := range []string{"retire", "release"} {
					if _, err := encodeDesktopMacOSNodeChainBaselineRequest(value.Capture, action, &value); err != nil {
						t.Fatal("execution cleanup lost its original receipt", err)
					}
				}
			})
		}
	}
}
