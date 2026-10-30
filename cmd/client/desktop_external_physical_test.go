package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func desktopExternalPhysicalLaunchFixture(t *testing.T, protocol, kill, ipv6 string, lan bool) *desktopNodeLaunch {
	t.Helper()
	profile, exit := desktopExternalNativeFixture(t, protocol)
	profile.KillSwitchPolicy, profile.KillSwitch, profile.IPv6Mode, profile.HomeLANAccess = kill, kill != "off", ipv6, lan
	profile.MTUPolicy, profile.ManualMTU = "manual", 1360
	launch, err := compileDesktopExternalCaptured(context.Background(), profile, common.RouterProfile{}, exit, true, "", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return launch
}

func TestDesktopExternalPhysicalCapturePreservesProofAndMailboxOwners(t *testing.T) {
	count := 0
	for _, protocol := range []string{"http-connect", "https-connect", "shadowsocks"} {
		for _, kill := range []string{"on-connect", "always"} {
			for _, ipv6 := range []string{"on", "off"} {
				for _, lan := range []bool{false, true} {
					t.Run(strings.Join([]string{protocol, kill, ipv6, map[bool]string{true: "lan", false: "no-lan"}[lan]}, "/"), func(t *testing.T) {
						launch := desktopExternalPhysicalLaunchFixture(t, protocol, kill, ipv6, lan)
						owner := launch.external
						source, capture := bytes.Clone(owner.source), bytes.Clone(owner.capture)
						original, expected := bytes.Clone(launch.config), owner.expected
						if err := prepareDesktopExternalPhysical(launch, "windows"); err != nil || owner.physical == nil {
							t.Fatal("eligible original graph did not acquire its captured Windows lower path", err)
						}
						meta, err := capturedDesktopExternalPhysical(owner)
						if err != nil || meta == nil || meta.KillSwitchPolicy != kill || meta.IPv6Mode != ipv6 || meta.HomeLANAccess != lan || meta.Protocol != protocol ||
							!bytes.Equal(source, owner.source) || !bytes.Equal(capture, owner.capture) || expected != owner.expected || bytes.Equal(original, launch.config) ||
							meta.OriginalSourceSHA256 != expected.SourceSHA256 || meta.OriginalConfigSHA256 != expected.ConfigSHA256 ||
							string(original) != owner.physical.OriginalPolicy().Config() || string(launch.config) != owner.physical.Config() {
							t.Fatal("physical capture relabeled the original proof or changed captured settings", err, meta)
						}
						measurement, err := capturedDesktopMeasurementRuntime(launch)
						if err != nil || measurement.source != meta.SourceSHA256 || measurement.config != meta.ConfigSHA256 || measurement.node != expected.ExitID || measurement.session != expected.SessionID {
							t.Fatal("MTU/path mailbox did not bind the actual derived graph", measurement, err)
						}
						resolver, err := capturedDesktopDNSRuntime(launch)
						if err != nil || resolver.source != meta.SourceSHA256 || resolver.config != meta.ConfigSHA256 || resolver.node != expected.ExitID {
							t.Fatal("DNS mailbox did not bind the actual derived graph", resolver, err)
						}
						selected, _, _, err := desktopDNSExpectedEndpoints(launch)
						if err != nil || selected.Address != owner.profile.DNSHost || selected.Port != owner.profile.DNSPort || selected.Transport != owner.profile.DNSProtocol {
							t.Fatal("selected DNS was replaced during physical capture", selected, err)
						}
						if err := prepareDesktopExternalPhysical(launch, "windows"); err == nil {
							t.Fatal("captured physical owner was silently replaced")
						}
						count++
					})
				}
			}
		}
	}
	if count != 24 {
		t.Fatal("physical policy matrix did not execute", count)
	}
}

func TestDesktopExternalPhysicalAdmissionPreservesOtherGraphs(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg", "hysteria2", "socks5", "http-connect", "https-connect", "shadowsocks"} {
		for _, target := range []string{"windows", "linux", "darwin"} {
			for _, kill := range []string{"off", "always"} {
				launch := desktopExternalPhysicalLaunchFixture(t, protocol, kill, "off", false)
				before, metadata := bytes.Clone(launch.config), bytes.Clone(launch.metadata)
				if err := prepareDesktopExternalPhysical(launch, target); err != nil {
					t.Fatal(protocol, target, kill, err)
				}
				eligible := target == "windows" && kill != "off" && (protocol == "http-connect" || protocol == "https-connect" || protocol == "shadowsocks")
				if (launch.external.physical != nil) != eligible {
					t.Fatal("unsupported graph was admitted or an eligible graph silently fell back", protocol, target, kill)
				}
				if !eligible && (!bytes.Equal(before, launch.config) || !bytes.Equal(metadata, launch.metadata)) {
					t.Fatal("physical preparation changed an existing non-admitted graph")
				}
			}
		}
	}
	for _, fault := range []string{"graph", "metadata", "source", "session", "proof-source", "proof-config"} {
		t.Run(fault, func(t *testing.T) {
			launch := desktopExternalPhysicalLaunchFixture(t, "http-connect", "always", "off", false)
			switch fault {
			case "graph":
				launch.config = []byte(`{}`)
			case "metadata":
				launch.metadata = []byte(`{}`)
			case "source":
				launch.external.source = []byte(`{}`)
			case "session":
				launch.external.session = strings.Repeat("f", 32)
			case "proof-source":
				launch.external.expected.SourceSHA256 = strings.Repeat("f", 64)
			case "proof-config":
				launch.external.expected.ConfigSHA256 = strings.Repeat("f", 64)
			}
			if err := prepareDesktopExternalPhysical(launch, "windows"); err == nil || launch.external.physical != nil {
				t.Fatal("malformed eligible graph fell back or acquired physical authority", fault)
			}
		})
	}
}

func TestDesktopExternalPhysicalProofRejectsMissingForeignAndRelabeledCapture(t *testing.T) {
	launch := desktopExternalPhysicalLaunchFixture(t, "https-connect", "always", "off", false)
	if err := prepareDesktopExternalPhysical(launch, "windows"); err != nil {
		t.Fatal(err)
	}
	owner := launch.external
	metadata, err := capturedDesktopExternalPhysical(owner)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	owner.started = now
	proof := desktopExternalProof{ExternalProofResult: owner.expected, Physical: metadata, Healthy: true, HeartbeatAt: now.UnixMilli()}
	proof.CheckedAt = now.UnixMilli()
	raw, _ := json.Marshal(proof)
	if _, err := validateDesktopExternalProof(raw, owner, now); err != nil {
		t.Fatal("exact original and derived proof were not both accepted", err)
	}
	for _, fault := range []string{"missing", "session", "source", "config", "original", "dns-lan", "os", "relabeled-proof"} {
		changed := proof
		copy := *metadata
		changed.Physical = &copy
		switch fault {
		case "missing":
			changed.Physical = nil
		case "session":
			copy.SessionID = strings.Repeat("f", 32)
		case "source":
			copy.SourceSHA256 = strings.Repeat("f", 64)
		case "config":
			copy.ConfigSHA256 = strings.Repeat("f", 64)
		case "original":
			copy.OriginalSourceSHA256 = strings.Repeat("f", 64)
		case "dns-lan":
			copy.HomeLANAccess = !copy.HomeLANAccess
		case "os":
			copy.TargetOS = "linux"
		case "relabeled-proof":
			changed.SourceSHA256, changed.ConfigSHA256 = copy.SourceSHA256, copy.ConfigSHA256
		}
		raw, _ := json.Marshal(changed)
		if _, err := validateDesktopExternalProof(raw, owner, now); err == nil {
			t.Fatal("unproved native physical capture reached Connected", fault)
		}
	}
	legacy := desktopExternalPhysicalLaunchFixture(t, "socks5", "always", "off", false).external
	if desktopExternalPhysicalReceipt(legacy, metadata) {
		t.Fatal("legacy graph adopted an unsolicited physical receipt")
	}
	owner.capture = []byte(`{}`)
	if _, err := capturedDesktopMeasurementRuntime(launch); err == nil {
		t.Fatal("MTU/path mailbox survived substitution of its original capture")
	}
	if _, err := capturedDesktopDNSRuntime(launch); err == nil {
		t.Fatal("DNS mailbox survived substitution of its original capture")
	}
}

func TestDesktopExternalPhysicalEnvironmentAndPreflight(t *testing.T) {
	launch := desktopExternalPhysicalLaunchFixture(t, "http-connect", "on-connect", "off", false)
	if err := prepareDesktopExternalPhysical(launch, "windows"); err != nil {
		t.Fatal(err)
	}
	meta := launch.external.physical.Metadata()
	foreign := []string{"SAFE=value", "HOMEVPN_EXTERNAL_PHYSICAL_SOURCE_SHA256=foreign", "homevpn_external_physical_config_sha256=foreign", "HOMEVPN_NODE_SESSION=foreign", "HOMEVPN_TOR_SESSION=foreign", "HOMEVPN_NATIVE_EGRESS_JSON=foreign", "HOMEVPN_NATIVE_ENDPOINTS_JSON=foreign", "HOMEVPN_ENDPOINT=foreign"}
	environment, err := desktopExternalPhysicalEnvironment(foreign, launch.external)
	if err != nil || strings.Contains(strings.Join(environment, "\n"), "foreign") {
		t.Fatal("physical environment inherited another owner's authority", environment, err)
	}
	values := make(map[string]string)
	for _, entry := range environment {
		name, value, _ := strings.Cut(entry, "=")
		if _, duplicate := values[name]; duplicate {
			t.Fatal("duplicate environment authority", name)
		}
		values[name] = value
	}
	if values["HOMEVPN_EXTERNAL_PHYSICAL_SOURCE_SHA256"] != meta.SourceSHA256 || values["HOMEVPN_EXTERNAL_PHYSICAL_CONFIG_SHA256"] != meta.ConfigSHA256 || values["HOMEVPN_ENDPOINT"] != "" || values["SAFE"] != "value" {
		t.Fatal("physical environment did not preserve its exact captured graph")
	}
	for _, engine := range []string{"stock", "amnezia", "native"} {
		for _, value := range desktopSelectedStandardEngineEnvironment(foreign, engine) {
			if strings.HasPrefix(strings.ToUpper(value), "HOMEVPN_EXTERNAL_PHYSICAL_") {
				t.Fatal("ordinary engine inherited another physical owner", engine)
			}
		}
	}
	launch.root = t.TempDir()
	binary := filepath.Join(launch.root, "native-engine")
	calls := 0
	err = preflightDesktopExternalLaunch(context.Background(), binary, launch, func(ctx context.Context, actual string, arguments, env []string, directory string) error {
		calls++
		if ctx.Err() != nil || actual != binary || strings.Contains(strings.Join(env, "\n"), "HOMEVPN_EXTERNAL_PHYSICAL_SOURCE_SHA256=") {
			t.Fatal("read-only preflight inherited activation authority")
		}
		if calls == 1 && strings.Join(arguments, " ") != "routervpn-external --help --physical-source-sha256 "+meta.SourceSHA256 {
			t.Fatal("preflight omitted the actual command's captured lower-path flag", arguments)
		}
		staged, err := os.ReadFile(filepath.Join(directory, "sing-box.json"))
		if err != nil || !bytes.Equal(staged, launch.config) {
			t.Fatal("preflight did not inspect the exact derived graph", err)
		}
		return nil
	})
	if err != nil || calls != 2 {
		t.Fatal("read-only derived native preflight failed", err, calls)
	}
	if runtime.GOOS != "windows" {
		return // Actual Windows stage is exercised by the matching-host gate.
	}
	launch.external.network = "captured-fixture-network"
	launch.external.networkIdentity = func() string { return launch.external.network }
	a := &app{cfg: common.ClientConfig{ScriptsDir: filepath.Join(launch.root, "modes")}}
	if err := stageDesktopNodeLaunch(a, launch); err != nil {
		t.Fatal("actual Windows stage rejected its owned derived graph", err)
	}
	t.Cleanup(func() { _ = cleanupDesktopNodeLaunch(launch) })
	if !strings.Contains(strings.Join(launch.command.Env, "\n"), "HOMEVPN_EXTERNAL_PHYSICAL_SOURCE_SHA256="+meta.SourceSHA256) || strings.Contains(strings.Join(launch.command.Env, "\n"), "HOMEVPN_NATIVE_EGRESS_JSON=") {
		t.Fatal("actual Windows stage reopened a legacy endpoint rule")
	}
	var staged map[string]any
	data, err := readDesktopRuntimeFile(launch, "sing-box.json", 4<<20)
	if err != nil || json.Unmarshal(data, &staged) != nil || len(staged["services"].([]any)) != 1 || launch.config != nil {
		t.Fatal("actual Windows stage lost its retained native service", err)
	}
	if !desktopExternalPhysicalReceipt(launch.external, &meta) {
		t.Fatal("clearing staged private byte slices erased the retained captured authority")
	}
}

func TestDesktopExternalPhysicalRetirementRevokesMailboxCapture(t *testing.T) {
	launch := desktopExternalPhysicalLaunchFixture(t, "shadowsocks", "always", "off", false)
	if err := prepareDesktopExternalPhysical(launch, "windows"); err != nil {
		t.Fatal(err)
	}
	owner := launch.external
	meta := owner.physical.Metadata()
	launch.directory = filepath.Join(t.TempDir(), "already-retired-workspace")
	a := &app{}
	desktopNodeOwners.Store(a, launch)
	t.Cleanup(func() { desktopNodeOwners.Delete(a) })
	started, stop, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		_ = desktopExternalPhysicalReceipt(owner, &meta)
		close(started)
		for {
			select {
			case <-stop:
				return
			default:
				_, _, _ = desktopExternalMeasurementIdentity(owner)
			}
		}
	}()
	<-started
	err := finishDesktopNodeRuntime(a)
	close(stop)
	<-done
	if err != nil || desktopExternalPhysicalReceipt(owner, &meta) {
		t.Fatal("retired original source still authorized the former physical proof", err)
	}
	if _, err := capturedDesktopMeasurementRuntime(launch); err == nil {
		t.Fatal("retired derived MTU/path mailbox retained admission")
	}
	if _, err := capturedDesktopDNSRuntime(launch); err == nil {
		t.Fatal("retired derived DNS mailbox retained admission")
	}
}
