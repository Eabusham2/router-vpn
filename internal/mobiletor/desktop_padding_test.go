package mobiletor

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDesktopPaddingRetainsOffRateWithoutOpeningAdmission(t *testing.T) {
	for _, rate := range []int{0, 32, 64, 192} {
		profile := desktopProfile()
		profile["daita_enabled"], profile["daita_rate_kbps"] = false, rate
		policy := desktopPolicy(t, profile, "linux")
		if policy.Metadata().Padding != (TorPaddingPolicy{RateKbps: rate}) {
			t.Fatal("Off discarded the saved cover rate")
		}
		profile["daita_enabled"] = true
		if _, err := NewDesktopBridgePolicy(torHostEncode(t, profile), desktopSession, desktopIsolation, "linux"); err == nil {
			t.Fatal("disabled desktop foundation admitted cover before its shipping host")
		}
	}
}

func TestDesktopPaddingSessionBindsActualControlIsolationAndSingleClaim(t *testing.T) {
	var source, session string
	var starts atomic.Int32
	f := newDesktopSessionFixture(t, func(command, reply string, _ int) string {
		if command == "ROUTERVPN_PADDING INFO" {
			return paddingTestReply(paddingTestCapability)
		}
		if !strings.HasPrefix(command, "ROUTERVPN_PADDING ") {
			return reply
		}
		state := "running"
		if strings.HasPrefix(command, "ROUTERVPN_PADDING START ") {
			starts.Add(1)
			fields := strings.Fields(command)
			if len(fields) != 9 || fields[2] != session || fields[3] != source || fields[7] != desktopSession || fields[8] != desktopIsolation {
				t.Error("Local cover borrowed another source or SOCKS circuit isolation")
			}
		}
		if strings.HasPrefix(command, "ROUTERVPN_PADDING STOP ") {
			state = "stopped"
		}
		status := paddingTestReplace(paddingTestStatus(state), "source", source)
		return paddingTestReply(paddingTestReplace(status, "session", session))
	})
	// Exercise this disabled foundation's internal control boundary directly;
	// the public saved-profile compiler still rejects enabled Local cover.
	f.session.metadata.Padding = TorPaddingPolicy{Enabled: true, RateKbps: 192}
	source, session = f.session.metadata.SourceSHA256, desktopDigest([]byte(desktopSession))
	until := time.Now().Add(PaddingProofMaxAge)
	var retired atomic.Bool
	options := PaddingLeaseOptions{SessionSHA256: session, SourceSHA256: source, RateKbps: 192,
		Current: func() bool { return true }, ProofValidUntil: func() time.Time { return until }, Retire: func(error) { retired.Store(true) }}
	before := len(f.wire.snapshot())
	if _, err := f.session.PaddingLease(t.Context(), options); err == nil || len(f.wire.snapshot()) != before {
		t.Fatal("disabled child admitted cover or issued native I/O")
	}
	f.start(t)
	before = len(f.wire.snapshot())
	for name, change := range map[string]func(*PaddingLeaseOptions){
		"session":  func(o *PaddingLeaseOptions) { o.SessionSHA256 = strings.Repeat("f", 64) },
		"source":   func(o *PaddingLeaseOptions) { o.SourceSHA256 = strings.Repeat("f", 64) },
		"rate":     func(o *PaddingLeaseOptions) { o.RateKbps = 32 },
		"username": func(o *PaddingLeaseOptions) { o.Username = strings.Repeat("f", 32) },
		"password": func(o *PaddingLeaseOptions) { o.Password = strings.Repeat("f", 64) },
		"no-owner": func(o *PaddingLeaseOptions) { o.Current = nil },
	} {
		wrong := options
		change(&wrong)
		if _, err := f.session.PaddingLease(t.Context(), wrong); err == nil || len(f.wire.snapshot()) != before {
			t.Fatal("unowned padding request reached the authenticated child", name)
		}
	}
	lease, err := f.session.PaddingLease(t.Context(), options)
	if err != nil || len(f.wire.snapshot()) != before {
		t.Fatal("capturing the exact cover owner performed I/O", err)
	}
	if _, err := f.session.PaddingLease(t.Context(), options); err == nil {
		t.Fatal("second cover claim borrowed the same child")
	}
	f.mutation.Store(1)
	if err := lease.Start(t.Context()); err != nil || !lease.Healthy() || starts.Load() != 1 {
		t.Fatal("captured Local cover did not verify its actual control receipt", err)
	}
	lease.Cancel()
	if err := lease.Join(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := f.session.Quiesce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(t.Context()); err != nil || lease.Healthy() || retired.Load() {
		t.Fatal("explicit Local cover cancellation failed its owned native drain", err)
	}
}

func TestDesktopPaddingCannotStartWithoutFreshPathAndDNSWitness(t *testing.T) {
	for _, fault := range []string{"off", "owner", "proof"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopSessionFixture(t, nil)
			f.session.metadata.Padding = TorPaddingPolicy{Enabled: fault != "off", RateKbps: 64}
			f.start(t)
			before := len(f.wire.snapshot())
			options := PaddingLeaseOptions{SessionSHA256: desktopDigest([]byte(desktopSession)), SourceSHA256: f.session.metadata.SourceSHA256,
				RateKbps: 64, Current: func() bool { return fault != "owner" }, ProofValidUntil: func() time.Time { return time.Time{} }, Retire: func(error) {}}
			lease, err := f.session.PaddingLease(t.Context(), options)
			if fault == "off" {
				if err == nil || lease != nil {
					t.Fatal("Off borrowed a native cover owner")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if err := lease.Start(t.Context()); err == nil || lease.Healthy() {
					t.Fatal("missing current path/DNS witness started native cover")
				}
				if err := lease.Close(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if len(f.wire.snapshot()) != before {
				t.Fatal("unproved cover sent a native command")
			}
		})
	}
}

func TestDesktopPaddingReceiptRequiresFreshPairedProofAndSameNativeGeneration(t *testing.T) {
	now := time.Now().UTC()
	started := now.Add(-time.Minute)
	metadata := DesktopBridgeMetadata{SessionID: desktopSession, SourceSHA256: strings.Repeat("b", 64), Padding: TorPaddingPolicy{Enabled: true, RateKbps: 64}}
	proof := DesktopBridgePaddingProof{Proof: Proof{SessionID: desktopSession, IP: "198.51.100.18", IsTor: true, DNSProven: true, CheckedAt: now.Add(-time.Second)}, DNSCheckedAt: now.Add(-2 * time.Second)}
	receipt := PaddingReceipt{Direction: "outgoing", Accounting: "tor-link-cell", SessionSHA256: desktopDigest([]byte(desktopSession)), SourceSHA256: metadata.SourceSHA256,
		Generation: 1, RateKbps: 64, ChannelCells: 4, ChannelBytes: 4 * 514, ObservedAt: now.Add(-time.Millisecond).UnixMilli(), ExpiresAt: now.Add(4 * time.Second).UnixMilli()}
	if err := metadata.ValidatePaddingProof(&receipt, &proof, started, now); err != nil {
		t.Fatal(err)
	}
	until, err := metadata.PaddingProofUntil(&proof, started, now)
	if err != nil || !until.Equal(proof.DNSCheckedAt.Add(PaddingProofMaxAge)) {
		t.Fatal("cover deadline was refreshed without the earlier actual DNS proof", err)
	}
	for name, change := range map[string]func(*DesktopBridgePaddingProof){
		"session":          func(p *DesktopBridgePaddingProof) { p.Proof.SessionID = strings.Repeat("f", 32) },
		"no-DNS":           func(p *DesktopBridgePaddingProof) { p.Proof.DNSProven = false },
		"no-Tor":           func(p *DesktopBridgePaddingProof) { p.Proof.IsTor = false },
		"private-exit":     func(p *DesktopBridgePaddingProof) { p.Proof.IP = "192.168.50.1" },
		"mapped-exit":      func(p *DesktopBridgePaddingProof) { p.Proof.IP = "::ffff:198.51.100.18" },
		"stale-DNS":        func(p *DesktopBridgePaddingProof) { p.DNSCheckedAt = now.Add(-PaddingProofMaxAge) },
		"future-DNS":       func(p *DesktopBridgePaddingProof) { p.DNSCheckedAt = now.Add(time.Second) },
		"missing-DNS-time": func(p *DesktopBridgePaddingProof) { p.DNSCheckedAt = time.Time{} },
		"exit-before-DNS":  func(p *DesktopBridgePaddingProof) { p.Proof.CheckedAt = p.DNSCheckedAt.Add(-time.Second) },
		"future-exit":      func(p *DesktopBridgePaddingProof) { p.Proof.CheckedAt = now.Add(time.Second) },
	} {
		wrong := proof
		change(&wrong)
		if metadata.ValidatePaddingProof(&receipt, &wrong, started, now) == nil {
			t.Fatal("invalid Local cover proof was accepted", name)
		}
	}
	for name, change := range map[string]func(*PaddingReceipt){
		"generation":      func(r *PaddingReceipt) { r.Generation++ },
		"cell-regression": func(r *PaddingReceipt) { r.ChannelCells-- },
		"byte-regression": func(r *PaddingReceipt) { r.ChannelBytes -= 514 },
		"old-observation": func(r *PaddingReceipt) { r.ObservedAt-- },
		"other-owner":     func(r *PaddingReceipt) { r.SourceSHA256 = strings.Repeat("f", 64) },
	} {
		wrong := receipt
		change(&wrong)
		if ValidateDesktopPaddingProgress(&receipt, &wrong, &proof, &proof) == nil {
			t.Fatal("changed native cover owner or counters were adopted", name)
		}
	}
	for _, execution := range []string{"off", "server"} {
		other := metadata
		if execution == "off" {
			other.Padding.Enabled = false
		} else {
			other.Execution = execution
		}
		if other.ValidatePaddingProof(nil, nil, started, now) != nil || other.ValidatePaddingProof(&receipt, &proof, started, now) == nil {
			t.Fatal("Off/Server borrowed Local padding authority", execution)
		}
	}
}
