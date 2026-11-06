package awgpolicy

import "testing"

func TestPacketEnvelopeCapacity(t *testing.T) {
	for _, row := range []struct {
		ipv6                          bool
		layer, overhead, control, cap int
	}{
		{false, 0, 60, 176, 1360}, {true, 0, 80, 196, 1328},
		{false, 70, 130, 246, 1280}, {true, 70, 150, 266, 0},
	} {
		e, err := Envelope(nil, row.ipv6, row.layer)
		if err != nil || e.DataOverhead != row.overhead || e.ControlMax != row.control {
			t.Fatalf("wrong carrier envelope: %+v %v", e, err)
		}
		got, err := e.Capacity(1420, 1420, false)
		if row.cap == 0 {
			if err == nil {
				t.Fatal("undersized dual-stack capacity admitted")
			}
			continue
		}
		if err != nil || got != row.cap {
			t.Fatalf("cap = %d, %v; want %d", got, err, row.cap)
		}
		if _, err = e.Capacity(1420, 1420, true); err == nil {
			t.Fatal("Fixed overflow silently reduced")
		}
		if got, err = e.Capacity(1420, 1280, true); err != nil || got != 1280 {
			t.Fatal("fitting Fixed changed", got, err)
		}
	}
}

func TestPacketEnvelopeAWGControlBudget(t *testing.T) {
	p := map[string]string{"jc": "3", "jmin": "40", "jmax": "900", "s1": "56", "s2": "48", "s3": "24", "s4": "32", "h1": "10-19", "h2": "20-29", "h3": "30-39", "h4": "40-49"}
	for _, key := range []string{"s1", "s2", "s3", "jmax"} {
		q := map[string]string{}
		for k, v := range p {
			q[k] = v
		}
		q[key] = "1280"
		q["s4"] = "0"
		e, err := Envelope(q, false, 0)
		if err != nil {
			t.Fatal(err)
		}
		if key == "jmax" {
			if _, err = e.Capacity(1360, 1280, false); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if _, err = e.Capacity(1360, 1280, false); err == nil {
			t.Fatal("oversized control admitted", key, e)
		}
	}
	p["jc"] = "0"
	p["jmax"] = "1280"
	e, err := Envelope(p, false, 0)
	if err != nil || e.ControlMax != 232 || e.DataOverhead != 92 {
		t.Fatal("disabled junk or padding counted incorrectly", e, err)
	}
	p["s1"] = "-1"
	if _, err = Envelope(p, false, 0); err == nil {
		t.Fatal("malformed parameters admitted")
	}
	if _, err = Envelope(nil, false, -1); err == nil {
		t.Fatal("negative layer overhead admitted")
	}
}
