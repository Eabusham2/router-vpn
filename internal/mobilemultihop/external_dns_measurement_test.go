package mobilemultihop

import "testing"

func TestExternalDNSMeasurementRequiresTheExactSuccessfulProof(t *testing.T) {
	for _, mutation := range []string{"unproved", "valid", "session", "source", "policy", "entry", "cancelled", "native"} {
		t.Run(mutation, func(t *testing.T) {
			r, engine, _ := externalRequestFixture(t, "router-wg")
			graph, capture := externalTestFixture(t, "shadowsocks", "router-wg")
			source, session := externalTestJSON(t, graph), "session-old"
			if mutation != "unproved" {
				if _, err := r.Run(); err != nil {
					t.Fatal(err)
				}
			}
			switch mutation {
			case "session":
				session = "different-session"
			case "source":
				source += " "
			case "policy":
				capture["profile"].(map[string]any)["dns_mode"] = "home"
			case "entry":
				capture["entry"].(map[string]any)["api_token"] = "different-entry-secret"
			case "cancelled":
				r.Cancel()
			case "native":
				engine.current.Store(false)
			}
			config, metadata, err := r.DNSMeasurementAuthority(source, externalTestJSON(t, capture), session)
			if mutation == "valid" {
				if err != nil || config != r.policy.Config() || metadata != r.policy.Metadata() {
					t.Fatal("proved DNS authority changed", err)
				}
			} else if err == nil || config != "" || metadata != "" {
				t.Fatal("unproved or changed policy gained DNS authority")
			}
		})
	}
}
