package standardengine

import (
	"bytes"
	"strings"
	"testing"
)

func resolvedRootDSFixture() (ResolvedPolicy, ResolvedRootDSDecision) {
	p, _ := resolvedServerStateFixture()
	raw, _ := p.Canonical()
	return p, ResolvedRootDSDecision{PolicySHA256: ResolvedPolicySHA256(raw), Name: "vpn.example", DNSSEC: "allow-downgrade", Selected: *p.Manager.CurrentDNS, Outcome: "synthetic-unsigned"}
}
func TestResolvedRootDSOriginalDecision(t *testing.T) {
	for _, name := range []string{"synthetic-unsigned", "positive", "strict-missing"} {
		t.Run(name, func(t *testing.T) {
			p, d := resolvedRootDSFixture()
			if name == "positive" {
				a := resolvedAnchorFixture(43)
				a.PolicySHA256 = d.PolicySHA256
				d.Outcome = "positive"
				d.Root = &a
			}
			if name == "strict-missing" {
				p.Manager.DNSSEC = "yes"
				raw, _ := p.Canonical()
				d.PolicySHA256 = ResolvedPolicySHA256(raw)
				d.DNSSEC = "yes"
				d.Outcome = "no-trust-anchor"
			}
			raw, err := d.Canonical()
			if err != nil {
				t.Fatal(err)
			}
			if _, err = DecodeResolvedRootDS(raw, p, d.Name, 0); err != nil {
				t.Fatal(err)
			}
			capture := strings.Repeat("b", 64)
			request := ResolvedRequest{Schema: 1, CaptureSHA256: capture, Sequence: 13, Action: "root-ds-decision", Name: d.Name, Index: d.Index}
			if _, err := request.Canonical(); err != nil {
				t.Fatal("fixed root action rejected original qualified name", err)
			}
			request.Type = 48
			if _, err := request.Canonical(); err == nil {
				t.Fatal("root decision admitted caller-selected record type")
			}
			frames, err := BuildResolvedRootDSFrames(capture, 13, raw)
			if err != nil {
				t.Fatal(err)
			}
			got, err := DecodeResolvedRootDSFrames(frames, capture, 13, p, d.Name, 0)
			if err != nil {
				t.Fatal(err)
			}
			again, _ := got.Canonical()
			if !bytes.Equal(raw, again) {
				t.Fatal("original root records/outcome changed")
			}
			if _, err = DecodeResolvedRootDSFrames(frames, capture, 14, p, d.Name, 0); err == nil {
				t.Fatal("foreign sequence admitted")
			}
		})
	}
}
func TestResolvedRootDSRejectsChangedAuthority(t *testing.T) {
	for _, name := range []string{"mode", "name", "scope", "selected", "policy", "no-source", "foreign-error", "synthetic-with-anchor", "positive-without-anchor", "strict-empty-in-downgrade", "positive-wrong-origin"} {
		t.Run(name, func(t *testing.T) {
			p, d := resolvedRootDSFixture()
			switch name {
			case "mode":
				d.DNSSEC = "yes"
			case "name":
				d.Name = "other.example"
			case "scope":
				d.Index = 7
			case "selected":
				d.Selected.Port++
			case "policy":
				d.PolicySHA256 = strings.Repeat("c", 64)
			case "no-source":
				d.Outcome = "no-source"
			case "foreign-error":
				d.Outcome = "NoSuchResourceRecord"
			case "synthetic-with-anchor":
				a := resolvedAnchorFixture(43)
				d.Root = &a
			case "positive-without-anchor":
				d.Outcome = "positive"
			case "strict-empty-in-downgrade":
				d.Outcome = "no-trust-anchor"
			case "positive-wrong-origin":
				a := resolvedAnchorFixture(43)
				a.PolicySHA256 = d.PolicySHA256
				a.Flags = 1 << 9
				d.Root = &a
				d.Outcome = "positive"
			}
			raw, err := d.Canonical()
			if err == nil {
				_, err = DecodeResolvedRootDS(raw, p, "vpn.example", 0)
			}
			if err == nil {
				t.Fatal("changed original root decision admitted")
			}
		})
	}
}
