package mobilemtu

import (
	"context"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
)

func TestTorMTURetainsDynamicProofAndHonestTransferEvidence(t *testing.T) {
	c, owner, preferences := publicFixtureController(t, true)
	if err := c.Run(strings.Repeat("a", 32), true); err != nil {
		t.Fatal(err, c.StatusJSON())
	}
	status := readStatus(t, c)
	state, _ := owner.Capture()
	if !status.Measured || status.Source != "measured-tor-system-tun-transfer" || status.EffectiveMTU != 1500 || state.MTU != 1500 || preferences.data == "" {
		t.Fatal(status, state)
	}
	if len(owner.dials) != len(status.Candidates)+1 || len(owner.proofs) != 1+2*len(owner.dials) {
		t.Fatal("Tor winner did not repeat its proof and full transfer")
	}
	for i, candidate := range status.Candidates {
		if candidate.MTU != owner.dials[i].MTU || candidate.LatencyKind != "https-response" || candidate.PacketsSent != 0 || candidate.PacketsReceived != 0 || candidate.DatagramBytes != 0 || candidate.Download.Bytes != 262144 || candidate.Upload.Bytes != 262144 {
			t.Fatal("Tor HTTPS evidence was replaced with a packet-size claim", candidate)
		}
	}
	engine := &probeEngine{controller: c, state: state}
	if _, err := engine.Dial(context.Background(), "custom-exit", hopmeasure.PublicAddress); err == nil {
		t.Fatal("ordinary external route replaced the Tor owner")
	}
	if _, err := engine.dial(context.Background(), "udp", hopmeasure.PublicAddress); err == nil {
		t.Fatal("Tor accepted an unauthenticated packet probe")
	}
}

func TestTorMTURejectsStaticIdentityAndPolicyReclassification(t *testing.T) {
	_, owner, _ := publicFixtureController(t, true)
	graph := strings.ReplaceAll(externalFixtureGraph(), "custom-exit", "routervpn-tor-exit")
	for _, mutate := range []func(map[string]any){
		func(p map[string]any) { delete(p, "source_kind") },
		func(p map[string]any) { p["source_kind"] = "external" },
		func(p map[string]any) { p["expected_public_ip"] = "198.51.100.9" },
		func(p map[string]any) { p["mtu_policy"] = true },
		func(p map[string]any) { p["source_sha256"] = "saved-result" },
	} {
		p := externalFixtureAuthority()
		delete(p, "expected_public_ip")
		p["source_kind"] = "tor"
		mutate(p)
		if _, err := NewTor(owner, graph, encoded(p), nil); err == nil {
			t.Fatal("unbound or fixed Tor identity accepted")
		}
	}
	p := externalFixtureAuthority()
	delete(p, "expected_public_ip")
	p["source_kind"] = "tor"
	if _, err := NewExternal(owner, externalFixtureGraph(), encoded(p), nil); err == nil {
		t.Fatal("dynamic Tor proof became fixed external authority")
	}
	if _, err := NewTor(owner, externalFixtureGraph(), encoded(p), nil); err == nil {
		t.Fatal("Tor policy accepted a different final transport")
	}
	for _, policy := range []string{"fixed", "manual", "default"} {
		p["mtu_policy"] = policy
		c, err := NewTor(owner, graph, encoded(p), nil)
		if err != nil {
			t.Fatal(err)
		}
		if c.Requested() || c.Run(strings.Repeat("a", 32), true) == nil {
			t.Fatal("Tor policy became automatic")
		}
		c.Close()
	}
}

func TestTorMTUCancelDrainsAndRollsBackExactInterface(t *testing.T) {
	c, owner, preferences := publicFixtureController(t, true)
	entered := make(chan struct{})
	c.external.measure = func(ctx context.Context, _ hopmeasure.Engine, _ hopmeasure.Hop, _ int) (hopmeasure.Result, error) {
		close(entered)
		<-ctx.Done()
		return hopmeasure.Result{}, ctx.Err()
	}
	id, done := strings.Repeat("c", 32), make(chan error, 1)
	go func() { done <- c.Run(id, true) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("Tor transfer did not begin")
	}
	c.Cancel(id)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled Tor measurement won")
		}
	case <-time.After(time.Second):
		t.Fatal("Tor transfer did not drain")
	}
	status, state := readStatus(t, c), State{}
	state, _ = owner.Capture()
	if status.Measured || !status.Restored || state.MTU != 1380 || preferences.data != "" {
		t.Fatal(status, state)
	}
}
