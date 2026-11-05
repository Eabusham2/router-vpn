//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobiletor"
	"strings"
	"testing"
	"time"
)

// Canonical closed-policy bytes are from the actual native request builder.
// Native observations/mutations are explicitly modeled below; peer/pidfd,
// creator process, sealed files, mutation lease and service handlers are real.
const reverseNodeSnapshotModel = `{"standard":false,"namespace_device":1,"namespace_inode":2,"capture":{"SessionID":"11111111111111111111111111111111","SourceSHA256":"2222222222222222222222222222222222222222222222222222222222222222","NetworkID":"33333333333333333333333333333333"},"home_lan":false,"inventory":{"Capture":{"SessionID":"11111111111111111111111111111111","SourceSHA256":"2222222222222222222222222222222222222222222222222222222222222222","NetworkID":"33333333333333333333333333333333"},"TableName":"router_vpn_node_11111111111111111111111111111111","UID":0,"Prefix":"","TableHandle":11,"ChainHandle":12,"Rules":null,"Sets":null,"Baseline":{"100":[{"match":{"left":{"meta":{"key":"oifname"}},"op":"==","right":"lo"}},{"accept":null}],"101":[{"match":{"left":{"meta":{"key":"oifname"}},"op":"==","right":{"set":["wg","awg","router-vpn"]}}},{"accept":null}],"102":[{"match":{"left":{"payload":{"field":"protocol","protocol":"ip"}},"op":"==","right":17}},{"match":{"left":{"payload":{"field":"sport","protocol":"udp"}},"op":"==","right":68}},{"match":{"left":{"payload":{"field":"dport","protocol":"udp"}},"op":"==","right":67}},{"accept":null}],"103":[{"match":{"left":{"payload":{"field":"nexthdr","protocol":"ip6"}},"op":"==","right":58}},{"match":{"left":{"payload":{"field":"type","protocol":"icmpv6"}},"op":"==","right":{"set":[133,134,135,136]}}},{"accept":null}]}}}`
const reverseStandardSnapshotModel = `{"standard":true,"namespace_device":1,"namespace_inode":2,"capture":{"SessionID":"11111111111111111111111111111111","SourceSHA256":"2222222222222222222222222222222222222222222222222222222222222222","NetworkID":"33333333333333333333333333333333"},"home_lan":false,"endpoints":["203.0.113.7"],"inventory":{"Capture":{"SessionID":"11111111111111111111111111111111","SourceSHA256":"2222222222222222222222222222222222222222222222222222222222222222","NetworkID":"33333333333333333333333333333333"},"TableName":"router_vpn_standard_11111111111111111111111111111111","UID":0,"Prefix":"","TableHandle":11,"ChainHandle":12,"Rules":null,"Sets":null,"Baseline":{"100":[{"match":{"left":{"meta":{"key":"oifname"}},"op":"==","right":"lo"}},{"accept":null}],"101":[{"match":{"left":{"meta":{"key":"oifname"}},"op":"==","right":{"set":["wg","awg","router-vpn"]}}},{"accept":null}],"102":[{"match":{"left":{"payload":{"field":"protocol","protocol":"ip"}},"op":"==","right":17}},{"match":{"left":{"payload":{"field":"sport","protocol":"udp"}},"op":"==","right":68}},{"match":{"left":{"payload":{"field":"dport","protocol":"udp"}},"op":"==","right":67}},{"accept":null}],"103":[{"match":{"left":{"payload":{"field":"nexthdr","protocol":"ip6"}},"op":"==","right":58}},{"match":{"left":{"payload":{"field":"type","protocol":"icmpv6"}},"op":"==","right":{"set":[133,134,135,136]}}},{"accept":null}],"104":[{"match":{"left":{"payload":{"field":"daddr","protocol":"ip"}},"op":"==","right":"203.0.113.7"}},{"accept":null}]}}}`

type reverseServicePinModel struct {
	snapshot mobiletor.DesktopLinuxClosedTransferSnapshot
	alive    *bool
	resolved bool
	fail     bool
}

func (p *reverseServicePinModel) Snapshot(ctx context.Context) (mobiletor.DesktopLinuxClosedTransferSnapshot, error) {
	return p.snapshot, ctx.Err()
}
func (p *reverseServicePinModel) Resolve(ctx context.Context, source mobiletor.DesktopLinuxClosedTransferSnapshot, committed bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.fail {
		return errors.New("retained native resolution unavailable")
	}
	if *p.alive == committed {
		return errors.New("actual original source did not match resolution")
	}
	p.resolved = true
	return nil
}
func reverseServiceFixture(t *testing.T) (*linuxStandardService, *legacyExitFixture, *linuxStandardServicePeer, linuxStandardServiceRequest, *os.File, *bool) {
	t.Helper()
	s, f, _ := linuxStandardServiceRuntimeFixture(t, "on-connect")
	peer, _, _ := linuxStandardPeerFixture(t)
	start, directory := linuxStandardServiceRequestFixture(t, f)
	if err := s.loadProfiles(); err != nil {
		t.Fatal(err)
	}
	loaded, _ := s.app.profileByIDLocked(start.ProfileID)
	var source mobiletor.DesktopLinuxClosedTransferSnapshot
	if err := json.Unmarshal([]byte(reverseNodeSnapshotModel), &source); err != nil {
		t.Fatal(err)
	}
	source.NamespaceDevice = peer.record.NetworkNamespace.Device
	source.NamespaceInode = peer.record.NetworkNamespace.Inode
	obj := func(n uint64, mode uint32) linuxprotection.NativeObject {
		return linuxprotection.NativeObject{Device: 999, Inode: n, Mode: mode}
	}
	rootInfo, err := os.Stat(s.root)
	if err != nil {
		t.Fatal(err)
	}
	root, err := desktopLinuxNodeObjectOf(rootInfo)
	if err != nil {
		t.Fatal(err)
	}
	parent := linuxprotection.ParentRecord{Generation: strings.Repeat("a", 32), BootID: peer.record.BootID, ProcessID: peer.record.ProcessID, ProcProcessID: peer.record.ProcProcessID, StartTicks: peer.record.StartTicks, CallerUID: 1000, InstallationAnchor: obj(1, 0040755), Root: root, Image: linuxprotection.NativeObject(peer.record.Image), Input: obj(2, 0010600), InstallLock: obj(3, 0100600), ProcessLock: obj(4, 0100600), NetworkNamespace: linuxprotection.NativeObject(peer.record.NetworkNamespace), PIDNamespace: linuxprotection.NativeObject(peer.record.PIDNamespace)}
	parent.Input.UID = 1000
	if err = parent.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(source)
	sum := sha256.Sum256(raw)
	q := linuxStandardServiceReverseRequest{Parent: parent, Source: source, Intent: linuxprotection.NodeStandardTransfer{ID: strings.Repeat("b", 32), DeadlineNS: time.Now().Add(20 * time.Second).UnixNano(), Source: linuxprotection.NodeSelection{SessionID: source.Capture.SessionID, SourceSHA256: source.Capture.SourceSHA256, ConfigSHA256: strings.Repeat("4", 64), Policy: "on-connect"}, SourceProfileID: start.ProfileID, SourceProfileRevision: desktopOwnedNodeProfileToken(loaded), SourceReceiptSHA256: hex.EncodeToString(sum[:]), DestinationSession: start.Session, DestinationConfigSHA256: start.ConfigSHA256, DestinationProfileID: start.ProfileID, DestinationProfileSHA256: start.ProfileSHA256, Endpoint: start.Endpoint, Policy: "on-connect"}}
	start.Action = "reverse-prepare"
	start.Reverse = &q
	alive := true
	s.reverseSourceOnly = func(ctx context.Context, actual mobiletor.DesktopLinuxClosedTransferSnapshot) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !alive {
			return errors.New("source no longer current")
		}
		return nil
	}
	s.reverseSourcePresent = s.reverseSourceOnly
	s.reversePin = func(ctx context.Context, owner *linuxLegacyStandardExitOwner, id string) (linuxStandardReversePin, error) {
		raw := strings.ReplaceAll(reverseStandardSnapshotModel, strings.Repeat("1", 32), owner.session)
		raw = strings.ReplaceAll(raw, strings.Repeat("2", 64), owner.digest)
		raw = strings.ReplaceAll(raw, "203.0.113.7", owner.protectionEndpoint)
		var snapshot mobiletor.DesktopLinuxClosedTransferSnapshot
		if err := json.Unmarshal([]byte(raw), &snapshot); err != nil {
			return nil, err
		}
		snapshot.NamespaceDevice = peer.record.NetworkNamespace.Device
		snapshot.NamespaceInode = peer.record.NetworkNamespace.Inode
		if err := snapshot.Validate(); err != nil {
			return nil, err
		}
		return &reverseServicePinModel{snapshot: snapshot, alive: &alive}, nil
	}
	return s, f, peer, start, directory, &alive
}
func reverseServiceAction(q linuxStandardServiceRequest, action string) linuxStandardServiceRequest {
	return linuxStandardServiceRequest{Schema: 1, Action: action, Session: q.Session, BudgetMS: 30000, DeadlineNS: time.Now().Add(30 * time.Second).UnixNano(), Reverse: q.Reverse}
}
func TestLinuxStandardServiceReverseRetainsPreparedOriginal(t *testing.T) {
	for _, mode := range []string{"commit-start", "abort", "lost-prepare", "wrong-peer", "changed-intent", "held-gate", "held-app", "held-owner", "pending-release", "foreign-scope", "late-start", "source-still-live", "pending-native"} {
		t.Run(mode, func(t *testing.T) {
			s, f, peer, q, directory, alive := reverseServiceFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			if mode == "held-gate" {
				<-s.gate
				short, stop := context.WithTimeout(ctx, 20*time.Millisecond)
				defer stop()
				_, err := s.reverseRequest(short, peer, q, []*os.File{directory})
				s.gate <- struct{}{}
				if !errors.Is(err, context.DeadlineExceeded) || s.reverse != nil {
					t.Fatal("held admission escaped original budget", err)
				}
				return
			}
			if mode == "held-app" {
				s.app.mu.Lock()
				short, stop := context.WithTimeout(ctx, 20*time.Millisecond)
				_, err := s.reverseRequest(short, peer, q, []*os.File{directory})
				stop()
				s.app.mu.Unlock()
				if !errors.Is(err, context.DeadlineExceeded) || s.reverse == nil || s.session != nil {
					t.Fatal("held application metadata did not retain bounded reservation", err)
				}
				return
			}
			if mode == "foreign-scope" {
				if _, err := s.protectionRequest(ctx, peer, q); err == nil {
					t.Fatal("protection admitted reverse authority")
				}
				if _, err := s.transferRequest(ctx, peer, q); err == nil {
					t.Fatal("forward admitted reverse authority")
				}
				if _, err := s.mtuRequest(ctx, peer, q); err == nil {
					t.Fatal("MTU admitted reverse authority")
				}
				if err := s.handle(ctx, peer, q, []*os.File{directory}); err == nil {
					t.Fatal("ordinary runtime admitted reverse authority")
				}
				return
			}
			out, err := s.reverseRequest(ctx, peer, q, []*os.File{directory})
			if err != nil || out == nil || out.Phase != "prepared" || s.session == nil || s.session.owner.started || s.session.owner.command.Process != nil {
				t.Fatal("guard-only preparation did not retain exact unstarted owner", out, err)
			}
			owner := s.session.owner
			if mode == "pending-release" {
				stop := reverseServiceAction(q, "stop")
				stop.Reverse = nil
				stop.Release = true
				if err := s.handle(ctx, peer, stop, nil); err == nil || s.session.owner != owner || !s.reversePending() {
					t.Fatal("ordinary Stop discarded unresolved original reverse owner", err)
				}
				mode = "abort"
			}
			if mode == "wrong-peer" {
				other, _, _ := linuxStandardPeerFixture(t)
				if _, err = s.reverseRequest(ctx, other, reverseServiceAction(q, "reverse-commit"), nil); err == nil {
					t.Fatal("replacement peer gained original creator")
				}
				return
			}
			if mode == "changed-intent" {
				changed := *q.Reverse
				changed.Intent.Endpoint = netip.MustParseAddr("203.0.113.99").String()
				request := reverseServiceAction(q, "reverse-commit")
				request.Reverse = &changed
				if _, err = s.reverseRequest(ctx, peer, request, nil); err == nil {
					t.Fatal("changed intent gained original creator")
				}
				return
			}
			if mode == "lost-prepare" {
				out, err = s.reverseRequest(ctx, peer, q, []*os.File{directory})
				if err != nil || out.Phase != "prepared" || s.session.owner != owner {
					t.Fatal("lost prepare created replacement", out, err)
				}
				mode = "abort"
			}
			if mode == "source-still-live" {
				if _, err = s.reverseRequest(ctx, peer, reverseServiceAction(q, "reverse-commit"), nil); err == nil || s.reverse.committed {
					t.Fatal("live source fabricated absence")
				}
				return
			}
			if mode == "pending-native" {
				pin := s.reverse.pin.(*reverseServicePinModel)
				pin.fail = true
				*alive = false
				if _, err = s.reverseRequest(ctx, peer, reverseServiceAction(q, "reverse-commit"), nil); err == nil || !s.reversePending() {
					t.Fatal("unproved resolution discarded original pins")
				}
				pin.fail = false
				*alive = true
				mode = "abort"
			}
			if mode == "abort" {
				out, err = s.reverseRequest(ctx, peer, reverseServiceAction(q, "reverse-abort"), nil)
				if err != nil || out.Phase != "aborted" || owner.started {
					t.Fatal("abort did not retire exact unstarted candidate", out, err)
				}
				if _, err = s.reverseRequest(ctx, peer, q, []*os.File{directory}); err == nil {
					t.Fatal("late prepare revived aborted creator")
				}
				return
			}
			*alive = false
			out, err = s.reverseRequest(ctx, peer, reverseServiceAction(q, "reverse-commit"), nil)
			if err != nil || !out.Committed {
				t.Fatal("actual modeled source absence not acknowledged", out, err)
			}
			start := reverseServiceLaunch(q)
			if mode == "held-owner" {
				owner.mu.Lock()
				short, stop := context.WithTimeout(ctx, 20*time.Millisecond)
				err = s.handle(short, peer, start, []*os.File{directory})
				stop()
				owner.mu.Unlock()
				if !errors.Is(err, context.DeadlineExceeded) || owner.started || s.session.owner != owner {
					t.Fatal("held original owner escaped Start budget", err)
				}
				return
			}
			if mode == "late-start" {
				s.reverse.request.Intent.DeadlineNS = time.Now().Add(-time.Second).UnixNano()
				if err = s.handle(ctx, peer, start, []*os.File{directory}); err == nil || owner.started {
					t.Fatal("late original intent started replacement engine", err)
				}
				return
			}
			if err = s.handle(ctx, peer, start, []*os.File{directory}); err != nil {
				t.Fatal("normal Start did not resume exact committed owner", err)
			}
			waitLegacyOffEngine(t, f)
			if s.session.owner != owner || owner.command.Process == nil || !owner.started {
				t.Fatal("reverse Start replaced actual creator")
			}
		})
	}
}
func TestLinuxStandardServiceReverseAbortFencesUnsentPrepare(t *testing.T) {
	s, _, peer, q, directory, _ := reverseServiceFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := s.reverseRequest(ctx, peer, reverseServiceAction(q, "reverse-abort"), nil)
	if err != nil || out.Phase != "aborted" || s.session != nil {
		t.Fatal("unsent original request not fenced", out, err)
	}
	if _, err = s.reverseRequest(ctx, peer, q, []*os.File{directory}); err == nil || s.session != nil {
		t.Fatal("late preparation crossed abort tombstone")
	}
}
