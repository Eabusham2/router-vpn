package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"router-vpn/internal/mobilemultihop"
)

func nodePhysicalLaunchFixture(t *testing.T) *desktopNodeLaunch {
	t.Helper()
	profile, files := desktopNodeFixture(t, "198.51.100.8")
	compiled, endpoint, err := compileDesktopNode(context.Background(), profile, "wg", files, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	physical, err := compiled.PhysicalEgress()
	if err != nil {
		t.Fatal(err)
	}
	launch := &desktopNodeLaunch{profileID: profile.ID, mode: "wg", endpoint: endpoint, config: []byte(compiled.Config()), mtuSession: strings.Repeat("a", 32), nodePhysicalEgress: physical}
	nodePhysicalReceipt(t, launch)
	return launch
}

func nodePhysicalReceipt(t *testing.T, launch *desktopNodeLaunch) {
	t.Helper()
	digest := sha256.Sum256(launch.config)
	launch.configSHA256 = hex.EncodeToString(digest[:])
	var err error
	launch.metadata, err = json.Marshal(map[string]any{
		"schema": 1, "profile_id": launch.profileID, "mode": launch.mode,
		"config_sha256": launch.configSHA256, "physical_egress": launch.nodePhysicalEgress,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDesktopNodePhysicalCapturePreservesExactCompiledTuples(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-strong", "wg-pq", "shadowsocks", "hysteria2", "naive-h2", "split", "max"} {
		for _, layer := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				root, selection := nativeEntryMultihopFixture(t, mode, layer)
				selection, err := captureNativeMultihopSelection(context.Background(), root, selection, []string{selection.ExitMode}, nil)
				if err != nil {
					t.Fatal(err)
				}
				for _, server := range []bool{false, true} {
					var descriptor *desktopExecutionDescriptor
					if server {
						_, value := executionFixture()
						value.Lease.ExitMode = selection.ExitMode
						if selection.Exit.StartLayer != "off" {
							value.Lease.ExitStartLayer = selection.Exit.StartLayer
						}
						descriptor = &value
					}
					launch, err := compileRetainedNativeMultihopLaunch(selection, descriptor)
					if err != nil {
						t.Fatal(err)
					}
					digest := sha256.Sum256(launch.config)
					launch.configSHA256, launch.mtuSession = hex.EncodeToString(digest[:]), strings.Repeat("a", 32)
					capture, err := captureDesktopNodePhysical(launch)
					if err != nil {
						t.Fatal(err)
					}
					var tuples []mobilemultihop.PhysicalEgress
					if err := json.Unmarshal([]byte(capture.egressJSON), &tuples); err != nil || !slices.Equal(tuples, selection.Native.entryPhysical) {
						t.Fatal("local/server handoff substituted the exit or broadened a physical port", err, tuples)
					}
				}
			})
		}
	}
}

func TestDesktopNodePhysicalEnvironmentRetainsFrozenOwnerAfterGraphClears(t *testing.T) {
	launch := nodePhysicalLaunchFixture(t)
	// The compiler can retain multiple physical dependencies. Its selected
	// logical node is not automatically an additional physical exception.
	launch.nodePhysicalEgress = []mobilemultihop.PhysicalEgress{
		{Host: "192.0.2.1", Port: 443, Network: "tcp"},
		{Host: "2001:db8::8", Port: 51822, Network: "udp"},
		{Host: "2001:db8::8", Port: 51820, Network: "udp"},
	}
	launch.endpoint = "2001:db8::8"
	nodePhysicalReceipt(t, launch)
	var err error
	launch.nodePhysicalCapture, err = captureDesktopNodePhysical(launch)
	if err != nil {
		t.Fatal(err)
	}
	captured := *launch.nodePhysicalCapture
	if captured.primary != "2001:db8::8" || captured.endpointsJSON != `["2001:db8::8","192.0.2.1"]` {
		t.Fatal("actual captured primary was not first", captured)
	}
	clear(launch.config)
	clear(launch.metadata)
	launch.config, launch.metadata = nil, nil
	launch.endpoint, launch.nodePhysicalEgress[0].Port = "203.0.113.99", 1
	base := []string{"KEEP=original", "HOMEVPN_PROFILE_ID=entry", "HOMEVPN_POLICY_PROFILE_ID=control",
		"homevpn_endpoint=foreign", "HOMEVPN_STANDARD_ENGINE=stock",
		"HomeVpn_Node_Session=foreign", "HOMEVPN_NODE_CONFIG_SHA256=foreign",
		"HOMEVPN_EXTERNAL_SESSION=foreign", "HOMEVPN_NATIVE_ENDPOINTS_JSON=foreign", "HOMEVPN_NATIVE_EGRESS_JSON=foreign"}
	original := slices.Clone(base)
	env, err := desktopNodePhysicalEnvironment(base, launch)
	if err != nil || !slices.Equal(base, original) || strings.Contains(strings.Join(env, "\n"), "foreign") {
		t.Fatal("ambient state survived or handoff changed its caller's environment", err, env)
	}
	for _, value := range []string{"HOMEVPN_PROFILE_ID=entry", "HOMEVPN_POLICY_PROFILE_ID=control",
		"HOMEVPN_ENDPOINT=" + captured.primary, "HOMEVPN_NODE_SESSION=" + captured.session,
		"HOMEVPN_NODE_CONFIG_SHA256=" + captured.configSHA256,
		"HOMEVPN_NATIVE_ENDPOINTS_JSON=" + captured.endpointsJSON, "HOMEVPN_NATIVE_EGRESS_JSON=" + captured.egressJSON} {
		if !slices.Contains(env, value) {
			t.Fatal("frozen source was lost during entry/control environment replacement", value)
		}
	}
	for _, fault := range []string{"session", "config", "external", "tor", "missing"} {
		copy := &desktopNodeLaunch{mtuSession: launch.mtuSession, configSHA256: launch.configSHA256, nodePhysicalCapture: launch.nodePhysicalCapture}
		switch fault {
		case "session":
			copy.mtuSession = strings.Repeat("b", 32)
		case "config":
			copy.configSHA256 = strings.Repeat("b", 64)
		case "external":
			copy.external = &desktopExternalRuntime{}
		case "tor":
			copy.tor = &desktopTorRuntime{}
		case "missing":
			copy.nodePhysicalCapture = nil
		}
		if env, err := desktopNodePhysicalEnvironment(base, copy); err == nil || env != nil {
			t.Fatal("replacement runtime borrowed the captured physical environment", fault)
		}
	}
}

func TestDesktopNodePhysicalCaptureRejectsStaleGraphAndInvalidTuples(t *testing.T) {
	for _, fault := range []string{"missing", "different", "graph", "metadata", "session", "external", "tor", "duplicate",
		"hostname", "loopback", "multicast", "mapped", "zone", "expanded", "zero-port", "large-port", "transport", "unbounded"} {
		t.Run(fault, func(t *testing.T) {
			launch := nodePhysicalLaunchFixture(t)
			switch fault {
			case "missing":
				launch.nodePhysicalEgress = nil
			case "different":
				launch.nodePhysicalEgress[0].Port++
			case "graph":
				launch.config = append(launch.config, ' ')
			case "metadata":
				launch.metadata = []byte("{}")
			case "session":
				launch.mtuSession = strings.Repeat("A", 32)
			case "external":
				launch.external = &desktopExternalRuntime{}
			case "tor":
				launch.tor = &desktopTorRuntime{}
			default:
				switch fault {
				case "duplicate":
					launch.nodePhysicalEgress = append(launch.nodePhysicalEgress, launch.nodePhysicalEgress[0])
				case "hostname":
					launch.nodePhysicalEgress[0].Host = "node.example.test"
				case "loopback":
					launch.nodePhysicalEgress[0].Host = "127.0.0.1"
				case "multicast":
					launch.nodePhysicalEgress[0].Host = "ff02::1"
				case "mapped":
					launch.nodePhysicalEgress[0].Host = "::ffff:192.0.2.1"
				case "zone":
					launch.nodePhysicalEgress[0].Host = "2001:db8::8%3"
				case "expanded":
					launch.nodePhysicalEgress[0].Host = "2001:0db8::8"
				case "zero-port":
					launch.nodePhysicalEgress[0].Port = 0
				case "large-port":
					launch.nodePhysicalEgress[0].Port = 65536
				case "transport":
					launch.nodePhysicalEgress[0].Network = "UDP"
				case "unbounded":
					for port := 1; port <= 16; port++ {
						launch.nodePhysicalEgress = append(launch.nodePhysicalEgress, mobilemultihop.PhysicalEgress{Host: launch.endpoint, Port: port, Network: "udp"})
					}
				}
				nodePhysicalReceipt(t, launch)
			}
			if capture, err := captureDesktopNodePhysical(launch); err == nil || capture != nil {
				t.Fatal("invalid capture could widen the Windows firewall", fault)
			}
		})
	}
	launch := nodePhysicalLaunchFixture(t)
	launch.endpoint = "203.0.113.99"
	capture, err := captureDesktopNodePhysical(launch)
	if err != nil || capture.primary != "198.51.100.8" || strings.Contains(capture.endpointsJSON, launch.endpoint) {
		t.Fatal("logical node address became a physical exemption", err)
	}
}

func TestSpeedLabNativeRestoreRetainsIndependentPhysicalTupleCapture(t *testing.T) {
	a, snapshot, _ := speedLabRestorationFixture(t, true)
	fixture := newDesktopNodeMTUFixture(t)
	launch := nodePhysicalLaunchFixture(t)
	launch.profileID, launch.root, launch.command = snapshot.State.RouterID, clientRoot(a), snapshot.Runtime
	nodePhysicalReceipt(t, launch)
	launch.directory, launch.directoryRoot, launch.directoryInfo = fixture.launch.directory, fixture.launch.directoryRoot, fixture.launch.directoryInfo
	fixture.launch = launch
	fixture.base.Session, fixture.base.Config, fixture.base.MTU = launch.mtuSession, launch.configSHA256, 1380
	if err := fixture.publish(fixture.base, false); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{"sing-box.json": launch.config, "capture.json": launch.metadata} {
		if err := writeDesktopRuntimeFile(launch, name, raw, false); err != nil {
			t.Fatal(err)
		}
	}
	desktopNodeOwners.Store(a, launch)
	plan, err := a.speedLabCaptureRestorePlan(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer clearSpeedLabRestorePlan(plan)
	if plan.native == nil || !slices.Equal(plan.native.nodePhysicalEgress, launch.nodePhysicalEgress) {
		t.Fatal("Speed Lab restored only graph bytes and lost the physical capture")
	}
	original := slices.Clone(plan.native.nodePhysicalEgress)
	launch.nodePhysicalEgress[0].Port = 1
	if !reflect.DeepEqual(original, plan.native.nodePhysicalEgress) {
		t.Fatal("restoration borrowed a mutable predecessor slice")
	}
	digest := sha256.Sum256(plan.native.config)
	plan.native.configSHA256, plan.native.mtuSession = hex.EncodeToString(digest[:]), strings.Repeat("b", 32)
	if _, err := captureDesktopNodePhysical(plan.native); err != nil {
		t.Fatal("restored measured MTU lost the original physical handoff", err)
	}
}
