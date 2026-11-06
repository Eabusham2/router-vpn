package standardengine

import (
	"bytes"
	"testing"
)

func TestResolvedDNSSECRootDecisionPlan(t *testing.T) {
	for _, scenario := range []string{"synthetic-empty", "strict-missing", "root-positive", "closer-ds", "closer-dnskey", "root-dnskey", "shadowed-positive", "omitted-observation", "changed-decision", "ordinary-recheck"} {
		t.Run(scenario, func(t *testing.T) {
			p, root := resolvedRootDSFixture()
			present := map[ResolvedDNSSECQuestion]bool{}
			switch scenario {
			case "strict-missing":
				p.Manager.DNSSEC = "yes"
				root.DNSSEC = "yes"
				root.Outcome = "no-trust-anchor"
			case "root-positive":
				present[ResolvedDNSSECQuestion{".", 43}] = true
				root.Outcome = "positive"
			case "closer-ds", "shadowed-positive":
				present[ResolvedDNSSECQuestion{"example", 43}] = true
			case "closer-dnskey":
				present[ResolvedDNSSECQuestion{"example", 48}] = true
			case "root-dnskey":
				present[ResolvedDNSSECQuestion{".", 48}] = true
			}
			if scenario == "shadowed-positive" {
				p.Manager.NegativeTrustAnchors = []string{"example"}
			}
			policyRaw, _ := p.Canonical()
			root.PolicySHA256 = ResolvedPolicySHA256(policyRaw)
			all := resolvedDNSSECObservations(t, p, "vpn.example", 0, present)
			var rows []ResolvedAnchorResult
			for _, row := range all {
				if row.Name == "." && row.Type == 43 {
					if row.Present {
						copy := row
						root.Root = &copy
					}
					continue
				}
				rows = append(rows, row)
			}
			if scenario == "omitted-observation" {
				rows = rows[:len(rows)-1]
			}
			plan, err := BuildResolvedDNSSECPlanWithRootDS(p, "vpn.example", 0, root, rows)
			if scenario == "shadowed-positive" || scenario == "omitted-observation" {
				if err == nil {
					t.Fatal("incomplete or discarded positive plan admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !plan.HasRootDSDecision() || !bytes.Contains(plan.Canonical(), []byte(`"root_ds":`)) {
				t.Fatal("typed source provenance omitted")
			}
			inputs, err := plan.ValidatorInputs()
			if scenario == "strict-missing" {
				if err == nil {
					t.Fatal("strict absent root enabled empty validator")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			if len(present) > 0 {
				want = 1
			}
			if len(inputs.TrustAnchors) != want || len(inputs.InsecureDomains) != 0 {
				t.Fatal("positive island lost or synthetic NTA invented", inputs)
			}
			if err = plan.RecheckWithRootDS(root, rows); err != nil {
				t.Fatal(err)
			}
			if scenario == "changed-decision" {
				changed := root
				changed.DNSSEC = "yes"
				changed.Outcome = "no-trust-anchor"
				if plan.RecheckWithRootDS(changed, rows) == nil {
					t.Fatal("changed root decision adopted")
				}
			}
			if plan.Recheck(all) == nil {
				t.Fatal("typed root substituted by ordinary NoSource observation")
			}
		})
	}
}
