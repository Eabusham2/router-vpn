package mobiletor

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestDesktopLastRelayRequiresActualNativeJoinWitness(t *testing.T) {
	wire := newDesktopControlFixture(t, nil)
	owner, err := NewDesktopControl(t.Context(), wire.connection, wire.cookie, wire.pid)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	policy := desktopPolicy(t, desktopProfile(), "linux")
	joined := make(chan struct{})
	closed := make(chan struct{})
	close(closed)
	for _, invalid := range []<-chan struct{}{nil, closed} {
		if session, err := NewDesktopBridgeSessionWithNativeJoin(owner, policy, invalid); err == nil || session != nil {
			t.Fatal("invalid join witness claimed authenticated child")
		}
	}
	session, err := NewDesktopBridgeSessionWithNativeJoin(owner, policy, joined)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := session.LastRelaySOCKS(); err == nil {
		t.Fatal("unconfigured child admitted comparison")
	}
	owner.Close()
	if session.NativeJoined() {
		t.Fatal("closed control impersonated actual child join")
	}
	close(joined)
	if !session.NativeJoined() {
		t.Fatal("exact child join was lost")
	}
}

func TestDesktopLastRelayBindsRawSOCKSTupleAndSource(t *testing.T) {
	for _, fault := range []string{"none", "client", "target", "source", "session", "remote", "joined"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopSessionFixture(t, func(command, reply string, _ int) string {
				parts := strings.Fields(command)
				if len(parts) != 10 || parts[0] != "ROUTERVPN_LASTRELAY" || parts[1] != "ANCHOR" {
					return reply
				}
				if parts[4] != desktopSession || parts[5] != desktopIsolation {
					t.Error("anchor lost captured SOCKS identity")
				}
				fields := map[string]string{"session": parts[2], "source": parts[3], "client_ip": parts[6], "client_port": parts[7], "target_ip": parts[8], "target_port": parts[9]}
				switch fault {
				case "client":
					fields["client_port"] = "1"
				case "target":
					fields["target_ip"] = "1.0.0.1"
				case "source":
					fields["source"] = strings.Repeat("f", 64)
				case "session":
					fields["session"] = strings.Repeat("f", 64)
				}
				return fmt.Sprintf("250 version=1 session=%s source=%s anchor=111 circuit=222 exit=%s path_sha256=%s client_ip=%s client_port=%s target_ip=%s target_port=%s\r\n", fields["session"], fields["source"], strings.Repeat("4", 40), strings.Repeat("5", 64), fields["client_ip"], fields["client_port"], fields["target_ip"], fields["target_port"])
			})
			f.start(t)
			joined := make(chan struct{})
			f.session.nativeJoined = joined
			f.mutation.Store(1)
			address := "127.0.0.1:19950"
			if fault == "remote" {
				address = "127.0.0.1:0"
			}
			listener, err := net.Listen("tcp4", address)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			raw, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			peer, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			if fault == "joined" {
				close(joined)
			}
			anchor, err := f.session.LookupLastRelayAnchor(t.Context(), raw, netip.MustParseAddrPort("1.1.1.1:443"))
			if fault == "none" {
				if err != nil || anchor.AnchorStream != 111 || anchor.Client.String() != raw.LocalAddr().String() || anchor.SourceSHA256 != f.session.Metadata().SourceSHA256 {
					t.Fatal("actual socket anchor rejected", anchor, err)
				}
			} else if err == nil {
				t.Fatal("foreign native anchor admitted", fault, anchor)
			}
		})
	}
}

func TestDesktopLastRelayAdapterCannotBorrowSourceIsolationOrJoin(t *testing.T) {
	f := newDesktopSessionFixture(t, nil)
	f.start(t)
	if _, _, _, err := f.session.LastRelaySOCKS(); err == nil {
		t.Fatal("legacy constructor without process join authorized comparison")
	}
	joined := make(chan struct{})
	f.session.nativeJoined = joined
	address, user, password, err := f.session.LastRelaySOCKS()
	if err != nil || address != "127.0.0.1:19950" {
		t.Fatal(err, address)
	}
	anchor := newLastRelayProbeFixture(t)
	anchor.path.SessionSHA256 = desktopDigest([]byte(f.session.metadata.SessionID))
	anchor.path.SourceSHA256 = f.session.metadata.SourceSHA256
	anchor.path.SOCKSUsername, anchor.path.SOCKSPassword = user, password
	for _, fault := range []string{"session", "source", "username", "password"} {
		before := anchor.path
		switch fault {
		case "session":
			anchor.path.SessionSHA256 = strings.Repeat("f", 64)
		case "source":
			anchor.path.SourceSHA256 = strings.Repeat("f", 64)
		case "username":
			anchor.path.SOCKSUsername = strings.Repeat("f", 32)
		case "password":
			anchor.path.SOCKSPassword = strings.Repeat("f", 64)
		}
		if probe, err := f.session.LastRelayProbe(t.Context(), anchor); err == nil || probe != nil {
			t.Fatal("comparison borrowed another capture", fault, err)
		}
		anchor.path = before
	}
	anchor.joined = true // A caller's asserted join cannot replace the exact child.
	probe, err := f.session.LastRelayProbe(t.Context(), anchor)
	if err != nil || probe == nil || probe.anchor.NativeJoined() {
		t.Fatal("adapter accepted self-declared child join", err)
	}
	f.owner.Close()
	if probe.anchor.NativeJoined() {
		t.Fatal("control retirement substituted for child join")
	}
	close(joined)
	if !probe.anchor.NativeJoined() {
		t.Fatal("retained adapter lost exact child join")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := probe.Close(ctx); err != nil || anchor.holds != 0 {
		t.Fatal("unused shared probe lost retained reference", err)
	}
}

func TestDesktopComparisonWireRejectsUnknownIdentityAndDeadline(t *testing.T) {
	now := time.Now()
	valid := DesktopTorCompareRequest{Schema: 1, SessionID: strings.Repeat("a", 32), SourceSHA256: strings.Repeat("b", 64), ConfigSHA256: strings.Repeat("c", 64), Generation: 1, RequestID: strings.Repeat("d", 32), Sequence: 1, Action: DesktopTorComparePrepare, Target: "https://1.1.1.1/cdn-cgi/trace", ExpiresAt: now.Add(time.Minute).UnixMilli()}
	if err := valid.Validate(now); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*DesktopTorCompareRequest){
		"schema": func(r *DesktopTorCompareRequest) { r.Schema = 2 }, "session": func(r *DesktopTorCompareRequest) { r.SessionID = strings.ToUpper(r.SessionID) },
		"source": func(r *DesktopTorCompareRequest) { r.SourceSHA256 = "" }, "config": func(r *DesktopTorCompareRequest) { r.ConfigSHA256 = "" },
		"generation": func(r *DesktopTorCompareRequest) { r.Generation = 0 }, "request": func(r *DesktopTorCompareRequest) { r.RequestID = "../other" },
		"sequence": func(r *DesktopTorCompareRequest) { r.Sequence = 0 }, "action": func(r *DesktopTorCompareRequest) { r.Action = "connect" },
		"target": func(r *DesktopTorCompareRequest) { r.Target = "https://example.com/" }, "expired": func(r *DesktopTorCompareRequest) { r.ExpiresAt = now.UnixMilli() },
		"extended":    func(r *DesktopTorCompareRequest) { r.ExpiresAt = now.Add(time.Minute + time.Millisecond).UnixMilli() },
		"last-budget": func(r *DesktopTorCompareRequest) { r.Action = DesktopTorCompareLast },
	} {
		t.Run(name, func(t *testing.T) {
			r := valid
			change(&r)
			if r.Validate(now) == nil {
				t.Fatal("malformed request accepted")
			}
		})
	}
}
