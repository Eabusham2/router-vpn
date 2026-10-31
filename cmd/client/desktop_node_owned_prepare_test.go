package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"router-vpn/internal/applexray"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

type desktopOwnedNodePreparationFixture struct {
	a           *app
	profile     common.RouterProfile
	files       map[string][]byte
	capture     desktopOwnedNodePreparation
	operation   context.Context
	cancel      context.CancelFunc
	cancelOwner context.CancelFunc
	network     string
	controller  error
	verifyCalls int
	lookupCalls int
}

func newDesktopOwnedNodePreparationFixture(t *testing.T, mode string) *desktopOwnedNodePreparationFixture {
	t.Helper()
	profile, files := viaEntryBaseFixture(t, mode)
	profile.KillSwitch, profile.KillSwitchPolicy = true, "on-connect"
	profile.MTUPolicy, profile.ManualMTU = "manual", 1392
	root := t.TempDir()
	data, packageRoot := filepath.Join(root, "Data"), filepath.Join(root, "App", "RouterVPN")
	directory := filepath.Join(data, "generated", profile.ID, mode)
	for _, path := range []string{directory, packageRoot} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(directory, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	op, cancel := context.WithCancel(context.Background())
	lifetime, cancelOwner := context.WithCancel(context.Background())
	f := &desktopOwnedNodePreparationFixture{profile: profile, files: files, operation: op, cancel: cancel, cancelOwner: cancelOwner,
		network: strings.Repeat("b", 64)}
	f.a = &app{connectionContext: op, cmd: &exec.Cmd{},
		profiles: common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}},
		state:    state{Connected: true, Phase: "connected", RuntimeMode: "previous", RouterID: "previous"}}
	f.capture = desktopOwnedNodePreparation{packageRoot: packageRoot, dataRoot: data, lifetime: lifetime, current: func() error { return f.controller }}
	t.Cleanup(cancel)
	t.Cleanup(cancelOwner)
	return f
}

func (f *desktopOwnedNodePreparationFixture) verify(ctx context.Context, root string) (string, error) {
	f.verifyCalls++
	if ctx == nil || ctx.Err() != nil || root != f.capture.packageRoot {
		return "", errors.New("preparation changed its verifier owner or package")
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || time.Until(deadline) > 30*time.Second {
		return "", errors.New("preparation verifier has no bounded owner")
	}
	return filepath.Join(root, "runtime", "native", nativeBinaryName()), nil
}

func (f *desktopOwnedNodePreparationFixture) lookup(context.Context, string) ([]netip.Addr, error) {
	f.lookupCalls++
	return []netip.Addr{netip.MustParseAddr("198.51.100.8")}, nil
}

func (f *desktopOwnedNodePreparationFixture) prepare(mode string, verify func(context.Context, string) (string, error), lookup applexray.Lookup) (*desktopNodeLaunch, error) {
	return prepareDesktopOwnedNodeLaunchWith(f.a, f.profile, mode, f.operation, f.capture, verify, lookup, func() string { return f.network })
}

func TestDesktopOwnedNodePreparationPreservesSourceAndExistingRuntime(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		t.Run(mode, func(t *testing.T) {
			f := newDesktopOwnedNodePreparationFixture(t, mode)
			command, state := f.a.cmd, f.a.state
			t.Setenv("HOMEVPN_ROOT", t.TempDir())
			launch, err := f.prepare(mode, f.verify, f.lookup)
			if err != nil {
				t.Fatal("captured private roots were replaced during preparation", err)
			}
			defer clearSpeedLabRestorePlan(speedLabRestorePlan{native: launch})
			original, endpoint, err := compileDesktopNode(context.Background(), f.profile, mode, f.files, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			metadata := launch.ownedNode.policy.Metadata()
			if launch.root != f.capture.dataRoot || launch.endpoint != endpoint || launch.ownedNode.network != f.network ||
				launch.command != nil || launch.directory != "" || launch.ownedNode.attempt != nil || launch.ownedNode.slot != nil ||
				launch.ownedNode.policy.OriginalProfile().Config() != original.Config() || launch.ownedNode.policy.OriginalProfile().Metadata() != original.Metadata() ||
				string(launch.config) != launch.ownedNode.policy.Config() || metadata.SessionID != launch.mtuSession || len(metadata.SessionID) != 32 || metadata.RestoredMTU != 0 ||
				f.verifyCalls != 1 || f.lookupCalls != 0 || f.a.cmd != command || f.a.state != state || f.a.nodeProtection != nil {
				t.Fatal("preparation substituted the private source, captured root or existing runtime")
			}
			for name, body := range f.files {
				actual, err := os.ReadFile(filepath.Join(f.capture.dataRoot, "generated", f.profile.ID, mode, name))
				if err != nil || !bytes.Equal(actual, body) {
					t.Fatal("preparation changed the saved node bundle", err)
				}
			}
			if _, err := os.Stat(filepath.Join(f.capture.dataRoot, "run")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("preparation staged runtime ownership before the previous connection joined", err)
			}
		})
	}
}

func TestDesktopOwnedNodePreparationCapturesResolvedEndpointOnce(t *testing.T) {
	f := newDesktopOwnedNodePreparationFixture(t, "wg")
	f.profile.Endpoint = "node.example.test"
	f.a.profiles.Profiles[0] = f.profile
	for name, body := range f.files {
		body = []byte(strings.ReplaceAll(string(body), "198.51.100.8", f.profile.Endpoint))
		f.files[name] = body
		if err := os.WriteFile(filepath.Join(f.capture.dataRoot, "generated", f.profile.ID, "wg", name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	launch, err := f.prepare("wg", f.verify, f.lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer clearSpeedLabRestorePlan(speedLabRestorePlan{native: launch})
	if f.lookupCalls != 1 || launch.endpoint != "198.51.100.8" || !strings.Contains(launch.ownedNode.policy.OriginalProfile().Config(), launch.endpoint) ||
		!strings.Contains(launch.ownedNode.policy.OriginalProfile().Config(), f.profile.AdGuardIPv4) || f.profile.Endpoint != "node.example.test" {
		t.Fatal("preparation changed the captured endpoint, saved hostname or selected DNS")
	}
}

func desktopOwnedNodePreparationAES(t *testing.T, endpoint string) map[string][]byte {
	t.Helper()
	graph := map[string]any{
		"inbounds": []any{map[string]any{"type": "tun", "tag": "tun-in", "auto_route": true, "strict_route": true}},
		"outbounds": []any{map[string]any{"type": "shadowsocks", "tag": "proxy", "server": endpoint, "server_port": 8388,
			"method": mobilemultihop.NativeStartLayerMethod, "password": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{43}, 32))}},
		"route": map[string]any{"final": "proxy", "rules": []any{}},
	}
	raw, err := json.Marshal(graph)
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{"sing-box.json": raw}
}

func TestDesktopOwnedNodePreparationKeepsCapturedAESAndWhitening(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong", "shadowsocks", "hysteria2", "reality-vision", "reality-pq-vision", "reality-xhttp"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				base := mode
				if mode == "shadowsocks" || mode == "hysteria2" || mobilemultihop.XrayEntryMode(mode) {
					base = "wg"
				}
				f := newDesktopOwnedNodePreparationFixture(t, base)
				f.profile.StartLayer = layer
				f.a.profiles.Profiles[0] = f.profile
				aes := desktopOwnedNodePreparationAES(t, f.profile.Endpoint)
				directory := filepath.Join(f.capture.dataRoot, "generated", f.profile.ID, "shadowsocks")
				if err := os.MkdirAll(directory, 0700); err != nil {
					t.Fatal(err)
				}
				for name, raw := range aes {
					if err := os.WriteFile(filepath.Join(directory, name), raw, 0600); err != nil {
						t.Fatal(err)
					}
				}
				var start map[string][]byte
				if mode == "shadowsocks" {
					f.files = aes
				} else if layer != "" {
					start = aes
				}
				if mode == "hysteria2" {
					graph := map[string]any{
						"inbounds": []any{map[string]any{"type": "tun", "tag": "tun-in", "auto_route": true, "strict_route": true}},
						"outbounds": []any{map[string]any{"type": "hysteria2", "tag": "proxy", "server": f.profile.Endpoint, "server_port": 8443,
							"password": "captured-hysteria-credential", "obfs": map[string]any{"type": "salamander", "password": "captured-hysteria-obfuscation"},
							"tls": map[string]any{"enabled": true, "server_name": "captured-node.test"}}},
						"route": map[string]any{"final": "proxy", "rules": []any{}},
					}
					raw, err := json.Marshal(graph)
					if err != nil {
						t.Fatal(err)
					}
					f.files = map[string][]byte{"sing-box.json": raw}
					directory := filepath.Join(f.capture.dataRoot, "generated", f.profile.ID, mode)
					if err := os.MkdirAll(directory, 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(directory, "sing-box.json"), raw, 0600); err != nil {
						t.Fatal(err)
					}
				}
				if mobilemultihop.XrayEntryMode(mode) {
					f.files = nativeMultihopProxyExitAssets(t, f.profile, mode)
					directory := filepath.Join(f.capture.dataRoot, "generated", f.profile.ID, mode)
					if err := os.MkdirAll(directory, 0700); err != nil {
						t.Fatal(err)
					}
					for name, raw := range f.files {
						if err := os.WriteFile(filepath.Join(directory, name), raw, 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
				command, previous := f.a.cmd, f.a.state
				t.Setenv("HOMEVPN_ROOT", t.TempDir())
				launch, err := f.prepare(mode, f.verify, f.lookup)
				if err != nil {
					t.Fatal("captured native graph lost its selected Start Layer", err)
				}
				defer clearSpeedLabRestorePlan(speedLabRestorePlan{native: launch})
				original, _, err := compileDesktopNode(context.Background(), f.profile, mode, f.files, start, nil)
				if err != nil || launch.ownedNode.policy.OriginalProfile().Config() != original.Config() ||
					launch.ownedNode.policy.Metadata().StartLayer != layer || f.a.cmd != command || f.a.state != previous ||
					f.a.nodeProtection != nil || f.lookupCalls != 0 {
					t.Fatal("native preparation substituted a protocol, layer, private node or previous runtime", err)
				}
			})
		}
	}
}

func TestDesktopOwnedNodePreparationDoesNotBorrowAnotherNodesStartLayer(t *testing.T) {
	f := newDesktopOwnedNodePreparationFixture(t, "wg")
	f.profile.StartLayer = "aes-256-gcm"
	f.a.profiles.Profiles[0] = f.profile
	directory := filepath.Join(f.capture.dataRoot, "generated", "another-node", "shadowsocks")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	for name, raw := range desktopOwnedNodePreparationAES(t, f.profile.Endpoint) {
		if err := os.WriteFile(filepath.Join(directory, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	command, previous := f.a.cmd, f.a.state
	if launch, err := f.prepare("wg", f.verify, f.lookup); err == nil || launch != nil || f.lookupCalls != 0 ||
		f.a.cmd != command || f.a.state != previous || f.a.nodeProtection != nil {
		t.Fatal("native preparation borrowed another node's Start Layer or changed the proved runtime", err)
	}
}

func TestDesktopOwnedNodePreparationRejectsRetiredCapture(t *testing.T) {
	for _, fault := range []string{"operation", "controller", "lifetime", "profile", "network", "replaced-operation", "wrong-executable", "verification"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopOwnedNodePreparationFixture(t, "wg")
			command, state := f.a.cmd, f.a.state
			verify := func(ctx context.Context, root string) (string, error) {
				path, err := f.verify(ctx, root)
				switch fault {
				case "operation":
					f.cancel()
				case "controller":
					f.controller = errors.New("original controller retired")
				case "lifetime":
					f.cancelOwner()
				case "profile":
					f.a.profiles.Profiles[0].APIToken = "replacement-token"
				case "network":
					f.network = strings.Repeat("c", 64)
				case "replaced-operation":
					f.a.connectionContext = context.Background()
				case "wrong-executable":
					path += ".other"
				case "verification":
					err = errors.New("runtime provenance rejected")
				}
				return path, err
			}
			if launch, err := f.prepare("wg", verify, f.lookup); err == nil || launch != nil {
				t.Fatal("preparation adopted a late retired or substituted capture", err)
			}
			if f.lookupCalls != 0 || f.a.cmd != command || f.a.state != state || f.a.nodeProtection != nil {
				t.Fatal("failed preparation changed the previous connection or reached endpoint lookup")
			}
		})
	}
}

func TestDesktopOwnedNodePreparationRejectsLateLookupReplacement(t *testing.T) {
	for _, fault := range []string{"network", "operation", "profile"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopOwnedNodePreparationFixture(t, "wg")
			f.profile.Endpoint = "node.example.test"
			f.a.profiles.Profiles[0] = f.profile
			for name, body := range f.files {
				body = []byte(strings.ReplaceAll(string(body), "198.51.100.8", f.profile.Endpoint))
				if err := os.WriteFile(filepath.Join(f.capture.dataRoot, "generated", f.profile.ID, "wg", name), body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			lookup := func(ctx context.Context, host string) ([]netip.Addr, error) {
				answer, err := f.lookup(ctx, host)
				switch fault {
				case "network":
					f.network = strings.Repeat("d", 64)
				case "operation":
					f.a.connectionContext = context.Background()
				case "profile":
					f.a.profiles.Profiles[0].AdGuardIPv4 = "192.168.50.134"
				}
				return answer, err
			}
			if launch, err := f.prepare("wg", f.verify, lookup); err == nil || launch != nil || f.lookupCalls != 1 {
				t.Fatal("late lookup adopted a replaced source operation or physical network", err)
			}
		})
	}
}

func TestDesktopOwnedNodePreparationCancelsItsVerificationChild(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newDesktopOwnedNodePreparationFixture(t, "wg")
		_, err := f.prepare("wg", func(ctx context.Context, root string) (string, error) {
			f.cancelOwner()
			<-ctx.Done()
			return "", ctx.Err()
		}, f.lookup)
		if !errors.Is(err, context.Canceled) || f.operation.Err() != nil || f.lookupCalls != 0 {
			t.Fatal("retired controller did not cancel its exact in-flight verification child", err)
		}
	})
}

func TestDesktopOwnedNodePreparationRejectsSourceBeforeLookup(t *testing.T) {
	f := newDesktopOwnedNodePreparationFixture(t, "wg")
	f.profile.Endpoint = "node.example.test"
	f.a.profiles.Profiles[0] = f.profile
	if err := os.WriteFile(filepath.Join(f.capture.dataRoot, "generated", f.profile.ID, "wg", "wg.conf"), []byte("[Interface]\nPrivateKey = invalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if launch, err := f.prepare("wg", f.verify, f.lookup); err == nil || launch != nil || f.lookupCalls != 0 {
		t.Fatal("invalid private node source reached a resolver or acquired launch ownership", err)
	}
}

func TestDesktopOwnedNodePreparationRejectsUnsupportedAdmission(t *testing.T) {
	for _, fault := range []string{"off", "layer", "mode", "no-operation", "wrong-operation", "no-network", "no-controller"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopOwnedNodePreparationFixture(t, "wg")
			mode := "wg"
			switch fault {
			case "off":
				f.profile.KillSwitchPolicy = "off"
			case "layer":
				f.profile.StartLayer = "xor-only"
			case "mode":
				mode = "naive-h2"
			case "no-operation":
				f.operation = nil
			case "wrong-operation":
				f.a.connectionContext = context.Background()
			case "no-network":
				f.network = ""
			case "no-controller":
				f.capture.current = nil
			}
			if launch, err := f.prepare(mode, f.verify, f.lookup); err == nil || launch != nil || f.verifyCalls != 0 || f.lookupCalls != 0 {
				t.Fatal("unadmitted preparation reached a native executable or resolver", err)
			}
		})
	}
}
