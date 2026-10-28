package mobiletor

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestExternalPredecessorProofUsesOnlyCapturedLowerAndDistinctAuthority(t *testing.T) {
	profile, graph := externalTorPredecessorFixture(t, "socks5")
	owner, err := NewExternalPredecessorProof(torHostEncode(t, profile), torHostEncode(t, graph))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		calls++
		if network != "tcp" || address != "1.1.1.1:443" || ctx.Err() != nil {
			t.Fatal("external proof escaped captured lower")
		}
		return nil, errors.New("isolated lower deliberately unavailable")
	}
	if owner.Prove(context.Background(), dial) == nil || calls != 1 {
		t.Fatal("external proof fabricated a successful address")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if owner.Prove(ctx, dial) == nil || calls != 1 {
		t.Fatal("retired external proof opened replacement work")
	}
	var missing *ExternalPredecessorProof
	var router *PredecessorProof
	var desktop *DesktopPredecessor
	if missing.Kind() != "" || missing.Fingerprint() != "" || router.Kind() != "" || desktop.IsRouter() || missing.Prove(context.Background(), dial) == nil {
		t.Fatal("absent proof acquired authority")
	}
	captured, _ := desktopEntryFixture(t, "wg", "", nil)
	if !captured.IsRouter() || captured.Proof().Kind() != RouterPredecessorProofKind || owner.Kind() == captured.Proof().Kind() {
		t.Fatal("entry proof kinds collapsed")
	}
	copy := *captured
	copy.kind = ExternalPredecessorProofKind
	if copy.IsRouter() {
		t.Fatal("external kind borrowed Router protection authority")
	}
	copy = *captured
	copy.proof = nil
	if copy.IsRouter() || (&DesktopPredecessor{proof: captured.Proof()}).IsRouter() {
		t.Fatal("unvalidated proof pointer acquired Router authority")
	}
}
