package main

import (
	"encoding/json"
	"router-vpn/internal/macosprocess"
	"testing"
)

func TestDesktopMacOSSOCKSBaselineRetainsExactFamily(t *testing.T) {
	for _, policy := range []string{"on-connect", "always"} {
		for _, phase := range []string{"active", "held", "retired"} {
			t.Run(policy+"/"+phase, func(t *testing.T) {
				original := macOSNodeChainBaselineFixture(policy, phase)
				original.Capture.Family = macosprocess.NodeChainSOCKSFamily
				raw, _ := json.Marshal(original)
				actual, err := decodeDesktopMacOSNodeChainReceipt(raw, original.Capture, phase)
				if err != nil || actual != original {
					t.Fatal("typed PF receipt changed original scope", err)
				}
				generic := original.Capture
				generic.Family = macosprocess.NodeChainFamily
				if _, err := decodeDesktopMacOSNodeChainReceipt(raw, generic, phase); err == nil {
					t.Fatal("typed PF receipt became generic ordered authority")
				}
				foreign := original
				foreign.Capture.Family = macosprocess.NodeChainFamily
				body, _ := json.Marshal(foreign)
				if _, err := decodeDesktopMacOSNodeChainReceipt(body, original.Capture, phase); err == nil {
					t.Fatal("ordinary PF receipt became typed authority")
				}
			})
		}
	}
}
