package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
)

// These tests execute the host compiler and actual captured private-file
// protocol. Only the kernel and retained process boundaries are modeled. They
// do not stand in for the separate actual Windows process or BFE gates.
type desktopOwnedNodeTestProcess struct {
	started, closed bool
	aliveErr        error
	closeErr        error
	closes          int
	join            func()
}

func (p *desktopOwnedNodeTestProcess) Started() bool { return p.started }
func (p *desktopOwnedNodeTestProcess) Alive() error {
	if !p.started || p.closed {
		return errors.New("fixture captured child is no longer live")
	}
	return p.aliveErr
}
func (p *desktopOwnedNodeTestProcess) Wait(ctx context.Context) (uint32, error) {
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	if !p.closed {
		return 0, errors.New("fixture child and Job have not joined")
	}
	return 0, nil
}
func (p *desktopOwnedNodeTestProcess) Close(ctx context.Context) error {
	p.closes++
	if ctx.Err() != nil || p.closeErr != nil {
		return errors.Join(ctx.Err(), p.closeErr)
	}
	if !p.closed {
		if p.join != nil {
			p.join()
		}
		p.closed = true
	}
	return nil
}

type desktopOwnedNodeTestFixture struct {
	a        *app
	launch   *desktopNodeLaunch
	profile  common.RouterProfile
	original *mobilemultihop.NodeProfile
	kernel   *desktopNodeProtectionFixture
	process  *desktopOwnedNodeTestProcess
}

func desktopOwnedNodeTestNetwork(t *testing.T) string {
	t.Helper()
	network := physicalNetworkIdentity()
	if network == "" {
		t.Fatal("owned Node host tests require actual local interface enumeration")
	}
	return network
}

func desktopOwnedNodeTestSource(t *testing.T, id, endpoint, mode string) (common.RouterProfile, *mobilemultihop.NodeProfile) {
	t.Helper()
	profile, files := desktopNodeFixture(t, endpoint)
	if mode != "wg" {
		profile, files = viaEntryBaseFixture(t, mode)
	}
	profile.ID, profile.KillSwitch, profile.KillSwitchPolicy = id, true, "always"
	original, _, err := compileDesktopNode(context.Background(), profile, mode, files, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return profile, original
}

func desktopOwnedNodeTestCapture(t *testing.T, a *app, kernel *desktopNodeProtectionFixture,
	profile common.RouterProfile, original *mobilemultihop.NodeProfile, mode, session string, restored int) *desktopOwnedNodeTestFixture {
	t.Helper()
	root := t.TempDir()
	launch, err := newDesktopOwnedNodeLaunch(profile, original, mode, root, profile.Endpoint, desktopOwnedNodeTestNetwork(t), strings.Repeat(session, 32), restored)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "native-private")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := captureDesktopRuntimeDirectory(launch, directory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = launch.directoryRoot.Close() })
	if a == nil {
		a = &app{nodeProtection: &desktopNodeProtectionSlot{backend: kernel.backend()}}
	}
	if err := writeDesktopRuntimeFile(launch, "sing-box.json", launch.config, false); err != nil {
		t.Fatal(err)
	}
	if err := writeDesktopRuntimeFile(launch, "capture.json", launch.metadata, false); err != nil {
		t.Fatal(err)
	}
	if err := stageDesktopOwnedNodeInputs(a, launch); err != nil {
		t.Fatal(err)
	}
	command, err := desktopOwnedNodeDescriptor(launch, filepath.Join(root, "package"), []string{"CAPTURED_NODE_FIXTURE=1"})
	if err != nil {
		t.Fatal(err)
	}
	launch.command = command
	a.mu.Lock()
	a.cmd = command
	a.profiles = common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}}
	a.state = state{Mode: mode, RuntimeMode: mode, RouterID: profile.ID, Phase: "starting",
		DAITA: profile.DAITAEnabled, Jumbo: profile.JumboTUN, Socks: profile.SocksEnabled}
	a.mu.Unlock()
	desktopNodeOwners.Store(a, launch)
	t.Cleanup(func() { desktopNodeOwners.CompareAndDelete(a, launch) })
	process := &desktopOwnedNodeTestProcess{started: true, join: func() { kernel.locked = false }}
	return &desktopOwnedNodeTestFixture{a: a, launch: launch, profile: profile, original: original, kernel: kernel, process: process}
}

func newDesktopOwnedNodeTestFixture(t *testing.T) *desktopOwnedNodeTestFixture {
	t.Helper()
	profile, original := desktopOwnedNodeTestSource(t, "node-A", "198.51.100.8", "wg")
	return desktopOwnedNodeTestCapture(t, nil, &desktopNodeProtectionFixture{}, profile, original, "wg", "1", 0)
}

func desktopOwnedNodeTestWrite(t *testing.T, launch *desktopNodeLaunch, name string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := launch.directoryRoot.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err := writeDesktopRuntimeFile(launch, name, raw, false); err != nil {
		t.Fatal(err)
	}
}

func desktopOwnedNodeTestHandoff(launch *desktopNodeLaunch) desktopNodeHandoffRecord {
	meta := launch.ownedNode.policy.Metadata()
	return desktopNodeHandoffRecord{Schema: 1, Kind: "routervpn-node-physical-handoff-v2", SessionID: meta.SessionID,
		SourceSHA256: meta.SourceSHA256, ConfigSHA256: meta.ConfigSHA256, TransferSHA256: launch.ownedNode.attempt.digest,
		NetworkID: strings.Repeat("d", 32), Policy: meta.KillSwitchPolicy, BaselineSHA256: strings.Repeat("e", 64), Nonce: strings.Repeat("a", 64)}
}

func (f *desktopOwnedNodeTestFixture) ready(t *testing.T, when time.Time) (mobilemultihop.DesktopNodeReadyRecord, desktopNodeMTURecord) {
	t.Helper()
	owned := f.launch.ownedNode
	meta := owned.policy.Metadata()
	capture, err := owned.policy.Capture()
	if err != nil {
		t.Fatal(err)
	}
	mtu := capture.ConfiguredMTU
	if meta.RestoredMTU != 0 {
		mtu = meta.RestoredMTU
	}
	record := mobilemultihop.DesktopNodeReadyRecord{Schema: 1, Kind: "routervpn-node-ready-v1", SessionID: meta.SessionID,
		SourceSHA256: meta.SourceSHA256, ConfigSHA256: meta.ConfigSHA256, TransferSHA256: owned.attempt.digest,
		DNSConfigSHA256: capture.SelectedDNS.ConfigSHA256, InterfaceName: "router-vpn", InterfaceIndex: 71,
		MTU: mtu, ProvedAt: when.UnixMilli(), DNSMilliseconds: 1.25}
	live := desktopNodeMTURecord{Schema: 1, Session: meta.SessionID, Config: meta.ConfigSHA256, Path: strings.Repeat("f", 64),
		Reader: 1, Interface: record.InterfaceName, Index: int(record.InterfaceIndex), MTU: mtu, Heartbeat: time.Now().UnixMilli()}
	desktopOwnedNodeTestWrite(t, f.launch, "node-ready.json", record)
	desktopOwnedNodeTestWrite(t, f.launch, "node-mtu-status.json", live)
	return record, live
}

func (f *desktopOwnedNodeTestFixture) start(t *testing.T, ctx context.Context, afterPrepared func()) error {
	t.Helper()
	base := f.launch.ownedNode.slot.backend.prepared
	if afterPrepared != nil {
		f.launch.ownedNode.slot.backend.prepared = func(ctx context.Context, target mobiletor.DesktopWindowsProtectionTarget) error {
			err := base(ctx, target)
			afterPrepared()
			return err
		}
	}
	return startDesktopOwnedNodeLaunchWith(ctx, f.a, f.launch,
		func(actual context.Context, arguments, environment []string, directory string) (desktopNodeProcess, error) {
			if actual != ctx || directory != f.launch.directory || !reflect.DeepEqual(environment, f.launch.command.Env) {
				t.Fatal("native start lost its captured process inputs")
			}
			want, err := desktopOwnedNodeArguments(f.launch)
			if err != nil || !reflect.DeepEqual(arguments, want) {
				t.Fatal("native start substituted its sealed source/session command", err)
			}
			handoff := desktopOwnedNodeTestHandoff(f.launch)
			raw, _ := json.Marshal(handoff)
			_, target, err := desktopNodeHandoff(raw, f.launch)
			if err != nil {
				t.Fatal(err)
			}
			f.kernel.target, f.kernel.locked = copyDesktopNodeProtectionTarget(&target), true
			desktopOwnedNodeTestWrite(t, f.launch, "node-physical-handoff-ready.json", handoff)
			f.ready(t, time.Now())
			return f.process, nil
		})
}

func (f *desktopOwnedNodeTestFixture) retirement(t *testing.T) {
	t.Helper()
	owned := f.launch.ownedNode
	record := desktopNodeProtectionRetired(owned.attempt, f.kernel.target)
	desktopOwnedNodeTestWrite(t, f.launch, "node-protection-retired.json", record)
	desktopOwnedNodeTestWrite(t, f.launch, "stopped.json", desktopExternalStop{Schema: 1, SessionID: f.launch.mtuSession, SourceSHA256: f.launch.configSHA256, Closed: true})
}

func TestDesktopOwnedNodeSealedSourceAndRestoredMTU(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		t.Run(mode, func(t *testing.T) {
			profile, original := desktopOwnedNodeTestSource(t, "sealed-node", "198.51.100.8", mode)
			before, err := original.LaunchInput()
			if err != nil {
				t.Fatal(err)
			}
			f := desktopOwnedNodeTestCapture(t, nil, &desktopNodeProtectionFixture{}, profile, original, mode, "2", 1392)
			raw, err := readDesktopRuntimeFile(f.launch, "node-source.json", mobilemultihop.NodeLaunchInputLimit)
			if err != nil || string(raw) != before || !bytes.Equal(raw, f.launch.ownedNode.source) {
				t.Fatal("host staging replaced the original sealed private inputs", err)
			}
			reconstructed, err := mobilemultihop.ParseNodeLaunchInput(string(raw))
			if err != nil {
				t.Fatal(err)
			}
			policy, err := mobilemultihop.NewDesktopNodePolicyWithMTU(reconstructed, f.launch.mtuSession, "windows", 1392)
			if err != nil || policy.Config() != string(f.launch.config) || !reflect.DeepEqual(policy.Metadata(), f.launch.ownedNode.policy.Metadata()) {
				t.Fatal("child reconstruction changed the captured session or MTU", err)
			}
			args, err := desktopOwnedNodeArguments(f.launch)
			if err != nil || args[len(args)-2] != "--physical-mtu" || args[len(args)-1] != "1392" {
				t.Fatal("restored actual MTU did not reach the direct Node command", err)
			}
			transferBytes, err := readDesktopRuntimeFile(f.launch, "node-protection-transfer.json", mobiletor.DesktopProtectionTransferRecordLimit)
			transfer, parseErr := mobiletor.ParseDesktopProtectionTransferRecord(transferBytes)
			if err != nil || parseErr != nil || transfer.Predecessor != nil || transfer.SessionID != f.launch.mtuSession {
				t.Fatal("fresh host staging invented a protection predecessor", err, parseErr)
			}
			if after, err := original.LaunchInput(); err != nil || before != after {
				t.Fatal("MTU restoration changed its retained original graph", err)
			}
			if f.launch.command.Process != nil {
				t.Fatal("native command descriptor fabricated a wrapper process")
			}
		})
	}
}

func TestDesktopOwnedNodeConstructorRejectsMixedPrivateProfile(t *testing.T) {
	profile, original := desktopOwnedNodeTestSource(t, "sealed-node", "198.51.100.8", "wg")
	root, network := t.TempDir(), desktopOwnedNodeTestNetwork(t)
	for name, alter := range map[string]func(*common.RouterProfile){
		"dns":              func(p *common.RouterProfile) { p.AdGuardIPv4 = "192.168.50.134" },
		"api-token":        func(p *common.RouterProfile) { p.APIToken = "replacement-private-token" },
		"api-endpoint":     func(p *common.RouterProfile) { p.RouterAPI = "http://10.77.0.2:8787" },
		"literal-endpoint": func(p *common.RouterProfile) { p.Endpoint = "198.51.100.9" },
		"node-proof":       func(p *common.RouterProfile) { p.NodeProofID = strings.Repeat("f", 64) },
		"ipv6":             func(p *common.RouterProfile) { p.IPv6Mode = "off" },
		"lan":              func(p *common.RouterProfile) { p.HomeLANAccess = !p.HomeLANAccess },
	} {
		t.Run(name, func(t *testing.T) {
			changed := profile
			alter(&changed)
			if launch, err := newDesktopOwnedNodeLaunch(changed, original, "wg", root, profile.Endpoint, network, strings.Repeat("3", 32), 0); err == nil || launch != nil {
				t.Fatal("owned Node constructor paired another private profile with sealed source")
			}
		})
	}
	measured := profile
	measured.EffectiveMTU = 1392
	if launch, err := newDesktopOwnedNodeLaunch(measured, original, "wg", root, profile.Endpoint, network, strings.Repeat("4", 32), 1392); err != nil || launch == nil {
		t.Fatal("separately captured live MTU was mistaken for replacement private input", err)
	}
	hostname, files := desktopNodeFixture(t, "node.example.test")
	hostname.KillSwitch, hostname.KillSwitchPolicy = true, "always"
	resolved, endpoint, err := compileDesktopNode(context.Background(), hostname, "wg", files, nil,
		func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("198.51.100.8")}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if launch, err := newDesktopOwnedNodeLaunch(hostname, resolved, "wg", root, endpoint, network, strings.Repeat("5", 32), 0); err != nil || launch == nil {
		t.Fatal("original hostname lost its already captured literal endpoint", err)
	}
	if launch, err := newDesktopOwnedNodeLaunch(hostname, resolved, "wg", root, "198.51.100.9", network, strings.Repeat("6", 32), 0); err == nil || launch != nil {
		t.Fatal("owned Node constructor accepted another resolved endpoint")
	}
}

func TestDesktopOwnedNodeHandoffRejectsSubstitutedAuthority(t *testing.T) {
	f := newDesktopOwnedNodeTestFixture(t)
	base := desktopOwnedNodeTestHandoff(f.launch)
	raw, _ := json.Marshal(base)
	if _, _, err := desktopNodeHandoff(raw, f.launch); err != nil {
		t.Fatal(err)
	}
	for name, alter := range map[string]func(*desktopNodeHandoffRecord){
		"schema": func(r *desktopNodeHandoffRecord) { r.Schema++ }, "kind": func(r *desktopNodeHandoffRecord) { r.Kind = "routervpn-external-handoff" },
		"session":  func(r *desktopNodeHandoffRecord) { r.SessionID = strings.Repeat("9", 32) },
		"source":   func(r *desktopNodeHandoffRecord) { r.SourceSHA256 = strings.Repeat("9", 64) },
		"config":   func(r *desktopNodeHandoffRecord) { r.ConfigSHA256 = strings.Repeat("9", 64) },
		"transfer": func(r *desktopNodeHandoffRecord) { r.TransferSHA256 = strings.Repeat("9", 64) },
		"network":  func(r *desktopNodeHandoffRecord) { r.NetworkID = "another-network" },
		"policy":   func(r *desktopNodeHandoffRecord) { r.Policy = "on-connect" },
		"baseline": func(r *desktopNodeHandoffRecord) { r.BaselineSHA256 = strings.Repeat("E", 64) },
		"nonce":    func(r *desktopNodeHandoffRecord) { r.Nonce = strings.Repeat("A", 64) },
		"accepted": func(r *desktopNodeHandoffRecord) { r.Accepted = true },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			alter(&changed)
			body, _ := json.Marshal(changed)
			if _, _, err := desktopNodeHandoff(body, f.launch); err == nil {
				t.Fatal("native handoff accepted substituted authority")
			}
		})
	}
	variants := map[string][]byte{
		"duplicate": []byte(strings.TrimSuffix(string(raw), "}") + `,"nonce":"` + base.Nonce + `"}`),
		"unknown":   []byte(strings.TrimSuffix(string(raw), "}") + `,"success":true}`),
		"oversize":  bytes.Repeat([]byte(" "), 2049),
		"trailing":  append(append([]byte(nil), raw...), []byte(`{}`)...),
	}
	for name, body := range variants {
		t.Run(name, func(t *testing.T) {
			if _, _, err := desktopNodeHandoff(body, f.launch); err == nil {
				t.Fatal("native handoff accepted ambiguous or unbounded encoding")
			}
		})
	}
}

func TestDesktopOwnedNodeAdmissionBindsCurrentProcessAndNonce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newDesktopOwnedNodeTestFixture(t)
		if err := f.start(t, context.Background(), nil); err != nil {
			t.Fatal(err)
		}
		raw, err := readDesktopRuntimeFile(f.launch, "node-physical-handoff-ack.json", 2048)
		var ack desktopNodeHandoffRecord
		if err != nil || json.Unmarshal(raw, &ack) != nil {
			t.Fatal(err)
		}
		want := desktopOwnedNodeTestHandoff(f.launch)
		want.Accepted = true
		if ack != want || f.kernel.prepared != 1 || f.launch.ownedNode.ready == nil || f.a.state.Connected {
			t.Fatal("handoff acknowledgement substituted its nonce or skipped native readiness")
		}
		if f.launch.command.Process != nil || desktopOwnedNodeProcess(f.launch) != f.process || !desktopOwnedNodeCreated(f.launch) {
			t.Fatal("admitted native owner was replaced by a wrapper descriptor")
		}
		if _, err := f.a.readDesktopOwnedNodeReady(f.launch, false); err != nil {
			t.Fatal("captured native readiness did not retain its exact record", err)
		}
	})
}

func TestDesktopOwnedNodeAdmissionRejectsLateCancellationAndReplacement(t *testing.T) {
	for _, fault := range []string{"cancel", "command", "profile", "network", "process"} {
		t.Run(fault, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newDesktopOwnedNodeTestFixture(t)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				err := f.start(t, ctx, func() {
					switch fault {
					case "cancel":
						cancel()
					case "command":
						f.a.mu.Lock()
						f.a.cmd = &exec.Cmd{}
						f.a.mu.Unlock()
					case "profile":
						f.a.mu.Lock()
						f.a.profiles.Profiles[0].AdGuardIPv4 = "192.168.50.134"
						f.a.mu.Unlock()
					case "network":
						f.launch.ownedNode.network = strings.Repeat("f", 64)
					case "process":
						f.process.aliveErr = errors.New("captured child token retired")
					}
				})
				if err == nil || f.launch.ownedNode.process != f.process || f.launch.ownedNode.ready != nil || f.launch.ownedNode.slot.active != f.launch.ownedNode.attempt {
					t.Fatal("late cancelled or replaced handoff discarded its captured partial owner", err)
				}
				if _, err := f.launch.directoryRoot.Stat("node-physical-handoff-ack.json"); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("late cancelled or replaced native handoff published an acknowledgement")
				}
			})
		})
	}
}

func TestDesktopOwnedNodeStartFailureRetainsPartialOwnerAndPredecessor(t *testing.T) {
	for _, fault := range []string{"before-start", "during-start", "native-error", "nil-child", "dead-child", "replacement"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopOwnedNodeTestFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if fault == "before-start" {
				cancel()
			}
			calls := 0
			var replacement *exec.Cmd
			err := startDesktopOwnedNodeLaunchWith(ctx, f.a, f.launch,
				func(context.Context, []string, []string, string) (desktopNodeProcess, error) {
					calls++
					switch fault {
					case "during-start":
						cancel()
					case "native-error":
						return f.process, errors.New("fixture native creation returned a partial owner")
					case "nil-child":
						return nil, nil
					case "dead-child":
						f.process.closed = true
					case "replacement":
						replacement = &exec.Cmd{}
						f.a.mu.Lock()
						f.a.cmd = replacement
						f.a.mu.Unlock()
					}
					return f.process, nil
				})
			owned := f.launch.ownedNode
			if err == nil || owned.slot.active != owned.attempt || owned.retired {
				t.Fatal("failed native start discarded its captured protection expectation", err)
			}
			if fault == "before-start" && (calls != 0 || owned.process != nil || !owned.started.IsZero()) {
				t.Fatal("cancelled native operation reached process creation")
			}
			if fault != "before-start" && fault != "nil-child" && owned.process != f.process {
				t.Fatal("failed native start lost its actual partial process owner")
			}
			if _, err := f.launch.directoryRoot.Stat("node-physical-handoff-ack.json"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed native start acknowledged a nonexistent handoff")
			}
			reads := f.kernel.reads
			if err := f.a.retireDesktopOwnedNode(context.Background(), f.launch); err != nil || !owned.retired || owned.slot.active != nil || f.kernel.reads <= reads {
				t.Fatal("failed launch was not joined and independently proved unchanged", err)
			}
			if owned.process != nil && (!f.process.closed || f.process.closes == 0) {
				t.Fatal("failed native launch guessed exit without joining its exact child")
			}
			if replacement != nil && f.a.cmd != replacement {
				t.Fatal("late child cleanup replaced the user's newer connection")
			}
		})
	}
}

func TestDesktopOwnedNodeWorkspaceReplacementPreservesNewOwner(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newDesktopOwnedNodeTestFixture(t)
		directory := f.launch.directory
		moved := directory + ".original"
		sentinel := []byte("replacement workspace remains owned by its new session")
		err := f.start(t, context.Background(), func() {
			if err := os.Rename(directory, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(directory, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, "replacement-owner"), sentinel, 0600); err != nil {
				t.Fatal(err)
			}
		})
		if err == nil || f.launch.ownedNode.ready != nil {
			t.Fatal("native handoff acknowledged a replacement private workspace")
		}
		if _, err := os.Stat(filepath.Join(directory, "node-physical-handoff-ack.json")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("native handoff wrote into another workspace owner")
		}
		if err := f.a.retireDesktopOwnedNode(context.Background(), f.launch); err == nil || !f.process.closed || f.launch.ownedNode.retired {
			t.Fatal("replaced workspace retirement guessed proof or stranded its exact child", err)
		}
		if body, err := os.ReadFile(filepath.Join(directory, "replacement-owner")); err != nil || !bytes.Equal(body, sentinel) {
			t.Fatal("native cleanup changed a replacement workspace", err)
		}
		if _, err := f.launch.directoryRoot.Stat("node-source.json"); err != nil {
			t.Fatal("failed retirement lost its original retained directory handle", err)
		}
	})
}

func TestDesktopOwnedNodeCurrentKeepsMeasuredStateSeparateFromSelection(t *testing.T) {
	f := newDesktopOwnedNodeTestFixture(t)
	f.launch.ownedNode.process = f.process
	f.launch.ownedNode.started = time.Now()
	if !f.a.desktopOwnedNodeCurrent(f.launch, true) {
		t.Fatal("fixture did not capture its original process and profile")
	}
	f.a.profiles.Profiles[0].EffectiveMTU = 1392
	if !f.a.desktopOwnedNodeCurrent(f.launch, true) {
		t.Fatal("fresh measured MTU incorrectly replaced saved private profile authority")
	}
	f.a.state.Jumbo = !f.a.state.Jumbo
	if f.a.desktopOwnedNodeCurrent(f.launch, true) {
		t.Fatal("new runtime options silently adopted an older native graph")
	}
	f.a.state.Jumbo = !f.a.state.Jumbo
	f.a.profiles.Profiles[0].APIToken = "new-private-credential"
	if f.a.desktopOwnedNodeCurrent(f.launch, true) {
		t.Fatal("new private node credentials silently adopted an older native graph")
	}
}

func TestDesktopOwnedNodeReadinessRequiresCurrentStartAndTUN(t *testing.T) {
	for _, fault := range []string{"before-start", "expired", "future", "interface", "index", "mtu", "active", "failure", "changed-captured-record"} {
		t.Run(fault, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newDesktopOwnedNodeTestFixture(t)
				if err := f.start(t, context.Background(), nil); err != nil {
					t.Fatal(err)
				}
				record, live := f.ready(t, time.Now())
				fresh := true
				switch fault {
				case "before-start":
					record.ProvedAt = f.launch.ownedNode.started.Add(-time.Millisecond).UnixMilli()
				case "expired":
					f.launch.ownedNode.started = time.Now().Add(-time.Minute)
					record.ProvedAt = time.Now().Add(-31 * time.Second).UnixMilli()
				case "future":
					record.ProvedAt = time.Now().Add(time.Millisecond).UnixMilli()
				case "interface":
					live.Interface = "replacement-tun"
				case "index":
					live.Index++
				case "mtu":
					live.MTU++
				case "active":
					live.Active = true
				case "failure":
					live.Failure = "fixture reader failed"
				case "changed-captured-record":
					fresh = false
					record.DNSMilliseconds++
				}
				desktopOwnedNodeTestWrite(t, f.launch, "node-ready.json", record)
				desktopOwnedNodeTestWrite(t, f.launch, "node-mtu-status.json", live)
				if _, err := f.a.readDesktopOwnedNodeReady(f.launch, fresh); err == nil {
					t.Fatal("native readiness accepted a stale start or different TUN owner")
				}
			})
		})
	}
}

func TestDesktopOwnedNodeRetirementRequiresJoinedChildAndIndependentTarget(t *testing.T) {
	for _, fault := range []string{"join", "read", "replaced-target", "wrong-transfer", "missing-stop", "missing-retirement"} {
		t.Run(fault, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newDesktopOwnedNodeTestFixture(t)
				if err := f.start(t, context.Background(), nil); err != nil {
					t.Fatal(err)
				}
				f.retirement(t)
				owned := f.launch.ownedNode
				switch fault {
				case "join":
					f.process.closeErr = errors.New("fixture native descendants remain live")
				case "read":
					f.kernel.readFail = true
				case "replaced-target":
					f.kernel.target.BaselineSHA256 = strings.Repeat("b", 64)
				case "wrong-transfer":
					record := desktopNodeProtectionRetired(owned.attempt, owned.attempt.prepared)
					record.TransferSHA256 = strings.Repeat("b", 64)
					desktopOwnedNodeTestWrite(t, f.launch, "node-protection-retired.json", record)
				case "missing-stop":
					if err := f.launch.directoryRoot.Remove("stopped.json"); err != nil {
						t.Fatal(err)
					}
				case "missing-retirement":
					if err := f.launch.directoryRoot.Remove("node-protection-retired.json"); err != nil {
						t.Fatal(err)
					}
				}
				reads := f.kernel.reads
				if err := f.a.retireDesktopOwnedNode(context.Background(), f.launch); err == nil || owned.retired || owned.slot.active != owned.attempt {
					t.Fatal("unproved native retirement forgot its exact pending owner", err)
				}
				if fault == "join" && f.kernel.reads != reads {
					t.Fatal("native retirement read protection before the actual child Job joined")
				}
				if f.process.closes == 0 {
					t.Fatal("failed native retirement left its exact child and Job unjoined")
				}
				if _, err := readDesktopRuntimeFile(f.launch, "node-source.json", mobilemultihop.NodeLaunchInputLimit); err != nil {
					t.Fatal("failed retirement removed the captured private source", err)
				}
			})
		})
	}
}

func TestDesktopOwnedNodeFailedTrialRestoresOriginalWithLatestJoinedPredecessor(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		kernel := &desktopNodeProtectionFixture{}
		profileA, originalA := desktopOwnedNodeTestSource(t, "node-A", "198.51.100.8", "wg")
		before, _ := originalA.LaunchInput()
		a := desktopOwnedNodeTestCapture(t, nil, kernel, profileA, originalA, "wg", "1", 0)
		if err := a.start(t, context.Background(), nil); err != nil {
			t.Fatal(err)
		}
		a.retirement(t)
		if err := a.a.retireDesktopOwnedNode(context.Background(), a.launch); err != nil {
			t.Fatal(err)
		}
		firstTarget := copyDesktopNodeProtectionTarget(kernel.target)
		profileB, originalB := desktopOwnedNodeTestSource(t, "node-B", "198.51.100.9", "wg")
		b := desktopOwnedNodeTestCapture(t, a.a, kernel, profileB, originalB, "wg", "2", 1392)
		if !reflect.DeepEqual(b.launch.ownedNode.attempt.transfer.Predecessor, firstTarget) {
			t.Fatal("trial B did not acquire joined A's exact predecessor")
		}
		if err := b.start(t, context.Background(), nil); err != nil {
			t.Fatal(err)
		}
		b.retirement(t)
		b.process.closeErr = errors.New("failed trial still has an owned child")
		if err := b.a.retireDesktopOwnedNode(context.Background(), b.launch); err == nil {
			t.Fatal("failed trial was treated as already joined")
		}
		if _, err := b.launch.ownedNode.slot.begin(context.Background(), &desktopNodeLaunch{}, a.launch.ownedNode.policy); err == nil {
			t.Fatal("restoration replaced an unjoined trial owner")
		}
		b.process.closeErr = nil
		if err := b.a.retireDesktopOwnedNode(context.Background(), b.launch); err != nil {
			t.Fatal(err)
		}
		latest := copyDesktopNodeProtectionTarget(kernel.target)
		if reflect.DeepEqual(firstTarget, latest) {
			t.Fatal("fixture did not create a distinct trial successor")
		}
		restored := desktopOwnedNodeTestCapture(t, a.a, kernel, profileA, originalA, "wg", "3", 1280)
		if !reflect.DeepEqual(restored.launch.ownedNode.attempt.transfer.Predecessor, latest) {
			t.Fatal("restored A reused obsolete A protection instead of joined trial B")
		}
		if string(restored.launch.ownedNode.source) != before || restored.launch.ownedNode.policy.Metadata().RestoredMTU != 1280 ||
			restored.launch.mtuSession == a.launch.mtuSession || restored.launch.configSHA256 == b.launch.configSHA256 {
			t.Fatal("restoration changed original private source or reused a trial execution identity")
		}
		if err := restored.start(t, context.Background(), nil); err != nil {
			t.Fatal(err)
		}
		restored.retirement(t)
		if err := restored.a.retireDesktopOwnedNode(context.Background(), restored.launch); err != nil {
			t.Fatal(err)
		}
		if !a.process.closed || !b.process.closed || !restored.process.closed || !restored.launch.ownedNode.retired {
			t.Fatal("A to B to restored A did not join every exact process owner")
		}
	})
}

func TestDesktopOwnedNodeReleasedSlotDoesNotClaimLaterLegacyCleanup(t *testing.T) {
	policy := desktopNodeProtectionPolicy(t, "1", "on-connect", 0)
	target := desktopNodeProtectionInstalled(policy)
	kernel := &desktopNodeProtectionFixture{target: copyDesktopNodeProtectionTarget(&target)}
	slot := &desktopNodeProtectionSlot{backend: kernel.backend(), known: true, target: copyDesktopNodeProtectionTarget(&target)}
	a := &app{nodeProtection: slot}
	if handled, err := a.releaseDesktopOwnedNodeProtection(); err != nil || !handled || a.nodeProtection != nil || kernel.target != nil {
		t.Fatal("proved on-connect release retained a stale application dispatch slot", handled, err)
	}
	if a.retainedDesktopNodeProtection() || a.guardDesktopOwnedNodeTransition(nil) != nil {
		t.Fatal("proved empty native protection blocked a later legacy connection")
	}
	legacy := &exec.Cmd{}
	a.cmd = legacy
	reads, releases := kernel.reads, kernel.releases
	if handled, err := a.releaseDesktopOwnedNodeProtection(); handled || err != nil || a.cmd != legacy || kernel.reads != reads || kernel.releases != releases {
		t.Fatal("stale empty native slot swallowed a later legacy owner's cleanup", handled, err)
	}
}

func TestDesktopOwnedNodeUnprovedOrAlwaysSlotCannotFallThrough(t *testing.T) {
	for _, kind := range []string{"unknown", "failed-read", "always"} {
		t.Run(kind, func(t *testing.T) {
			kill := "on-connect"
			if kind == "always" {
				kill = "always"
			}
			policy := desktopNodeProtectionPolicy(t, "1", kill, 0)
			target := desktopNodeProtectionInstalled(policy)
			kernel := &desktopNodeProtectionFixture{target: copyDesktopNodeProtectionTarget(&target)}
			slot := &desktopNodeProtectionSlot{backend: kernel.backend(), known: true, target: copyDesktopNodeProtectionTarget(&target)}
			if kind == "unknown" {
				slot.known, slot.target = false, nil
				kernel.target = nil
			}
			if kind == "failed-read" {
				kernel.readFail = true
			}
			a := &app{nodeProtection: slot}
			if !a.retainedDesktopNodeProtection() || a.guardDesktopOwnedNodeTransition(nil) == nil {
				t.Fatal("unknown or retained native protection allowed an unsupported transition")
			}
			handled, err := a.releaseDesktopOwnedNodeProtection()
			if !handled || a.nodeProtection != slot || !a.retainedDesktopNodeProtection() || kind != "always" && err == nil || kind == "always" && err != nil {
				t.Fatal("unproved or Always protection was detached as an empty legacy slot", handled, err)
			}
		})
	}
}

func TestDesktopOwnedNodeOldReleasePreservesReplacementSlot(t *testing.T) {
	policy := desktopNodeProtectionPolicy(t, "1", "on-connect", 0)
	target := desktopNodeProtectionInstalled(policy)
	kernel := &desktopNodeProtectionFixture{target: copyDesktopNodeProtectionTarget(&target)}
	backend := kernel.backend()
	slot := &desktopNodeProtectionSlot{backend: backend, known: true, target: copyDesktopNodeProtectionTarget(&target)}
	a := &app{nodeProtection: slot}
	replacement := &desktopNodeProtectionSlot{backend: backend}
	slot.backend.read = func(ctx context.Context, target *mobiletor.DesktopWindowsProtectionTarget) error {
		if err := backend.read(ctx, target); err != nil {
			return err
		}
		a.mu.Lock()
		a.nodeProtection = replacement
		a.mu.Unlock()
		return nil
	}
	if handled, err := a.releaseDesktopOwnedNodeProtection(); err != nil || !handled || a.nodeProtection != replacement || !a.retainedDesktopNodeProtection() {
		t.Fatal("late old native release discarded a replacement application's slot", handled, err)
	}
}
