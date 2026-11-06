package standardengine

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestResolvedFixedCommandCaptureAndRequests(t *testing.T) {
	c := ResolvedCapture{1, strings.Repeat("a", 32), 12345, "original.example"}
	raw, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	digest := ResolvedPolicySHA256(raw)
	if _, err = DecodeResolvedCapture(raw, digest); err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeResolvedCapture(append([]byte(" "), raw...), digest); err == nil {
		t.Fatal("noncanonical inherited capture accepted")
	}
	for _, action := range []string{"observe", "close"} {
		r := ResolvedRequest{Schema: 1, CaptureSHA256: digest, Sequence: 1, Action: action}
		body, err := r.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = DecodeResolvedRequest(body, digest, 1); err != nil {
			t.Fatal(err)
		}
		if _, err = DecodeResolvedRequest(body, digest, 2); err == nil {
			t.Fatal("replayed request accepted")
		}
	}
	for _, name := range []string{"vpn.private.example", "original.example"} {
		body, err := (ResolvedRequest{Schema: 1, CaptureSHA256: digest, Sequence: 2, Action: "observe", Name: name}).Canonical()
		if err != nil {
			t.Fatal(err)
		}
		request, err := DecodeResolvedRequest(body, digest, 2)
		if err != nil || request.Name != name {
			t.Fatal("exact local preflight question lost", err)
		}
	}
	if _, err := (ResolvedRequest{Schema: 1, CaptureSHA256: digest, Sequence: 2, Action: "close", Name: "unrelated.example"}).Canonical(); err == nil {
		t.Fatal("close accepted question mutation")
	}
	for _, action := range []string{"resolve-public", "set-dns", "refresh-parent", ""} {
		if _, err = (ResolvedRequest{Schema: 1, CaptureSHA256: digest, Sequence: 1, Action: action}).Canonical(); err == nil {
			t.Fatal("mutable operation escaped fixed helper", action)
		}
	}
}

func TestResolvedFixedCommandWholePolicyFrames(t *testing.T) {
	p := resolvedPolicyFixture()
	// Force several frames using complete ordered global domains, never filler
	// outside the policy or a truncated list.
	for i := 0; i < 100; i++ {
		p.Manager.Domains = append(p.Manager.Domains, ResolvedDomain{Name: strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + ".example", RoutingOnly: true})
	}
	policy, err := p.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	local, err := (ResolvedLocalResult{PolicySHA256: ResolvedPolicySHA256(policy), Name: "original.example"}).Canonical()
	if err != nil {
		t.Fatal(err)
	}
	capture := strings.Repeat("c", 64)
	frames, err := BuildResolvedFrames(capture, 0, "original.example", string(policy), string(local))
	if err != nil || len(frames) < 2 {
		t.Fatal("whole observation did not span frames", len(frames), err)
	}
	decoded, err := DecodeResolvedFrames(frames, capture, 0, "original.example")
	if err != nil || !bytes.Equal(decoded.Policy, policy) {
		t.Fatal("whole original policy not preserved", err)
	}
	for _, fault := range []string{"missing", "reorder", "digest", "capture", "sequence", "unknown", "foreign-name"} {
		t.Run(fault, func(t *testing.T) {
			altered := make([][]byte, len(frames))
			for i := range frames {
				altered[i] = append([]byte(nil), frames[i]...)
			}
			name := "original.example"
			switch fault {
			case "missing":
				altered = altered[:len(altered)-1]
			case "reorder":
				altered[0], altered[1] = altered[1], altered[0]
			case "foreign-name":
				name = "another.example"
			case "unknown":
				altered[0] = bytes.Replace(altered[0], []byte(`"schema":1`), []byte(`"schema":1,"extra":true`), 1)
			default:
				var f ResolvedFrame
				if err := json.Unmarshal(altered[0], &f); err != nil {
					t.Fatal(err)
				}
				switch fault {
				case "digest":
					f.SHA256 = strings.Repeat("d", 64)
				case "capture":
					f.CaptureSHA256 = strings.Repeat("e", 64)
				case "sequence":
					f.Sequence++
				}
				altered[0], _ = json.Marshal(f)
			}
			if _, err := DecodeResolvedFrames(altered, capture, 0, name); err == nil {
				t.Fatal("observation frames accepted causal substitution")
			}
		})
	}
}

func TestResolvedFixedCommandBoundedCohortSequence(t *testing.T) {
	capture := strings.Repeat("a", 64)
	for _, sequence := range []uint32{64, 65, 72110, MaxResolvedRequests} {
		r := ResolvedRequest{Schema: 1, CaptureSHA256: capture, Sequence: sequence, Action: "observe"}
		raw, err := r.Canonical()
		if err != nil {
			t.Fatal(sequence, err)
		}
		if _, err = DecodeResolvedRequest(raw, capture, sequence); err != nil {
			t.Fatal(sequence, err)
		}
	}
	for _, sequence := range []uint32{0, MaxResolvedRequests + 1, ^uint32(0)} {
		r := ResolvedRequest{Schema: 1, CaptureSHA256: capture, Sequence: sequence, Action: "observe"}
		if _, err := r.Canonical(); err == nil {
			t.Fatal("original sequence bound lost", sequence)
		}
	}
}

func TestResolvedFixedCommandDNSSECSequenceBudget(t *testing.T) {
	if resolvedCompleteRequestBudget != 1044288011 || uint64(MaxResolvedRequests) < resolvedCompleteRequestBudget || uint64(MaxResolvedRequests)/2 >= resolvedCompleteRequestBudget {
		t.Fatal("complete guarded DNSSEC cohort budget was truncated or arbitrarily widened")
	}
	capture := strings.Repeat("a", 64)
	for _, sequence := range []uint32{uint32(resolvedCompleteRequestBudget), MaxResolvedRequests} {
		raw, err := (ResolvedRequest{Schema: 1, CaptureSHA256: capture, Sequence: sequence, Action: "observe"}).Canonical()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = DecodeResolvedRequest(raw, capture, sequence); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := (ResolvedRequest{Schema: 1, CaptureSHA256: capture, Sequence: MaxResolvedRequests + 1, Action: "observe"}).Canonical(); err == nil {
		t.Fatal("finite DNSSEC frame bound renewed")
	}
}
