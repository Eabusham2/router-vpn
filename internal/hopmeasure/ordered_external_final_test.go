package hopmeasure

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
	"testing"
)

func TestOrderedExternalFinalMeasuresOriginalHTTPS(t *testing.T) {
	legacy, private := fixture(t)
	hops := importedNodesHops(3, 1, 2)
	hops[0].API, hops[0].Token, hops[0].Proof = legacy.hops[0].API, legacy.hops[0].Token, legacy.hops[0].Proof
	hops[0].Label = "Original paired entry"
	engine := &importedNodesMeasurementFixture{private: private, public: [2]*publicFixture{newPublicFixture(t), newPublicFixture(t)}, hops: hops}
	s, err := NewOrderedExternalFinalContext(t.Context(), engine, hops)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	trust := x509.NewCertPool()
	for _, p := range engine.public {
		trust.AddCert(p.server.Certificate())
	}
	s.publicTLS = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: trust}
	const samples = 3
	request := strings.Repeat("4", 32)
	if err = s.StartOrderedResponseContext(t.Context(), request, samples); err != nil {
		t.Fatal(err)
	}
	if err = s.Drain(request); err != nil {
		t.Fatal(err)
	}
	status, err := s.CompletedOrderedResponseContext(t.Context(), request, samples)
	if err != nil {
		t.Fatal(err)
	}
	pair := [2]Hop{hops[0], hops[2]}
	if _, err := OrderedResponseLatencies(status, request, samples, pair); err != nil {
		t.Fatal(err)
	}
	if status.Results[1].Response.Endpoint != "https://speed.cloudflare.com/__down?bytes=1" || status.Results[0].Response.Endpoint != "" {
		t.Fatal("wrong measurement endpoints")
	}
	for _, fault := range []string{"private-label", "endpoint", "not-original", "missing-tag"} {
		with := pair
		wrong := status
		wrong.Results = append([]Result(nil), status.Results...)
		r := *wrong.Results[1].Response
		wrong.Results[1].Response = &r
		switch fault {
		case "private-label":
			r.Measurement = "routed-private-response-including-connection"
		case "endpoint":
			r.Endpoint = "https://foreign.invalid/"
		case "not-original":
			with[1].ID = with[0].ID
		case "missing-tag":
			with[1].Tag = ""
		}
		if _, err := OrderedResponseLatencies(wrong, request, samples, with); err == nil {
			t.Fatal("accepted foreign public response", fault)
		}
	}
	history, err := NewOrderedLatencyContext(t.Context(), s, strings.Repeat("a", 64), strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	defer history.Close()
	request = strings.Repeat("8", 32)
	if err = history.StartContext(t.Context(), request, hops[2].ID); err != nil {
		t.Fatal(err)
	}
	if err = history.DrainContext(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if history.SavedJSON(hops[2].ID) == "" || history.SavedJSON(hops[1].ID) != "" || engine.public[0].downloaded.Load() != 0 || engine.public[1].downloaded.Load() != samples+LatencyBenchmarkSamples {
		t.Fatal("public exit did not own exactly 3 live and 50 durable HTTPS replies")
	}
	if _, err := NewOrderedImportedNodesContext(t.Context(), engine, hops); err == nil {
		t.Fatal("ordinary imported-interior service claimed public final")
	}
}
