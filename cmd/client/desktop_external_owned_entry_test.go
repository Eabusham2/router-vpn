package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"router-vpn/internal/common"
	"router-vpn/internal/mobiletor"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// Execute the real compiler and retained source guards. Native Windows
// process/Job, BFE and encrypted peer acceptance are separately required.
func TestDesktopWindowsExternalSSEntrySources(t *testing.T) {
	for _, protocol := range []string{"shadowsocks", "http-connect", "https-connect", "hysteria2"} {
		for _, method := range desktopSSEntryMethods {
			for _, kill := range []string{"on-connect", "always"} {
				t.Run(protocol+"/"+method+"/"+kill, func(t *testing.T) {
					var profile, entry common.RouterProfile
					var launch *desktopNodeLaunch
					if protocol == "shadowsocks" {
						profile, entry, launch = desktopSSEntryFixture(t, kill, method, desktopSSEntryMethods[1], "tcp")
					} else {
						profile, entry, launch = desktopWindowsSSFinalFixture(t, kill, method, protocol)
					}
					if !desktopWindowsExternalGraphEligible(profile, entry, false, "") {
						t.Fatal("captured SS entry refused")
					}
					if err := prepareDesktopExternalPhysicalCaptured(launch, "windows"); err != nil {
						t.Fatal(err)
					}
					selection, err := desktopProtectionSelectionFor(nil, launch.external.physical)
					if err != nil || selection.profileID != profile.ID || selection.profileID == entry.ID || selection.source != launch.external.physical.Metadata().SourceSHA256 {
						t.Fatal("composed journal selection lost final owner or original physical graph", err)
					}
					a := &app{}
					a.profiles.Profiles = []common.RouterProfile{profile, entry}
					owner := &desktopWindowsExternalRuntime{app: a, launch: launch, entryToken: desktopOwnedNodeProfileToken(entry)}
					if err := owner.sourcesCurrentLocked(profile); err != nil {
						t.Fatal(err)
					}
					originalPhysicalID := launch.profileID
					launch.profileID = profile.ID
					if desktopWindowsExternalEligible(launch) || owner.sourcesCurrentLocked(profile) == nil {
						t.Fatal("final identity replaced the captured physical entry")
					}
					launch.profileID = originalPhysicalID
					if err := validateDesktopWindowsExternalSourceContext(context.Background(), profile, launch); err != nil {
						t.Fatal(err)
					}
					if launch.profileID != entry.ID || launch.policyProfileID != profile.ID || launch.external.expected.EntryID != entry.ID || !launch.external.expected.EntryProven || launch.external.expected.EntryNodeID != "" {
						t.Fatal("entry invented Router identity or lost final policy")
					}
					capture, err := launch.external.physical.Capture()
					if err != nil || capture.SelectedDNS.Detour != "custom-exit" || capture.SelectedDNS.Physical || len(capture.PhysicalRoots) != 1 || capture.PhysicalRoots[0].Tag != "external-entry" {
						t.Fatal("final DNS or physical root changed", err)
					}
					for _, fault := range []string{"password", "method", "server", "port", "public", "id", "option"} {
						changed := cloneRouterProfile(entry)
						mutateDesktopSSSource(&changed, fault)
						a.profiles.Profiles[1] = changed
						if err := owner.sourcesCurrentLocked(profile); err == nil {
							t.Fatal("replaced independently saved entry accepted", fault)
						}
						if owner.entryCurrentLocked() {
							t.Fatal("activation accepted changed original entry", fault)
						}
						a.profiles.Profiles[1] = entry
						if err := owner.sourcesCurrentLocked(profile); err != nil {
							t.Fatal("entry refusal damaged original retry", err)
						}
					}
					for _, fault := range []string{"password", "public", "option"} {
						changed := cloneRouterProfile(profile)
						if protocol == "shadowsocks" {
							mutateDesktopSSSource(&changed, fault)
						} else {
							mutateWindowsSSFinal(&changed, fault)
						}
						if err := owner.sourcesCurrentLocked(changed); err == nil {
							t.Fatal("changed final accepted", fault)
						}
					}
					for _, fault := range []string{"entry-layer", "final-layer", "server", "packet-entry"} {
						p, e := cloneRouterProfile(profile), cloneRouterProfile(entry)
						switch fault {
						case "entry-layer":
							e.StartLayer = "aes-256-gcm"
						case "final-layer":
							p.StartLayer = "aes-256-gcm"
						case "server":
							p.MultihopExecution = "server"
						case "packet-entry":
							e.External.Protocol = "wireguard"
						}
						if desktopWindowsExternalGraphEligible(p, e, false, "") {
							t.Fatal("unsupported Windows graph admitted", fault)
						}
					}
				})
			}
		}
	}
}

func windowsSSEntryHostFixture(t *testing.T, protocol, kill string) (*desktopWindowsExternalFixture, common.RouterProfile, common.RouterProfile) {
	t.Helper()
	f := newDesktopWindowsExternalFixture(t, kill)
	var p, e common.RouterProfile
	if protocol == "shadowsocks" {
		p, e, _ = desktopSSEntryFixture(t, kill, desktopSSEntryMethods[1], desktopSSEntryMethods[2], "tcp")
	} else {
		p, e, _ = desktopWindowsSSFinalFixture(t, kill, desktopSSEntryMethods[1], protocol)
	}
	p.ID = "windows-ss-final-" + protocol
	for _, v := range []common.RouterProfile{p, e} {
		f.base.a.profiles.Profiles = append(f.base.a.profiles.Profiles, v)
	}
	// Protection settings act on the selected saved profile, independently of
	// the physical entry used by this connection. Select the final as the UI does.
	f.base.a.profiles.SelectedID = p.ID
	if err := f.base.a.persistProfilesLocked(); err != nil {
		t.Fatal(err)
	}
	return f, p, e
}
func windowsSSEntryConnect(f *desktopWindowsExternalFixture, p, e common.RouterProfile) *httptest.ResponseRecorder {
	direct := false
	body, _ := json.Marshal(externalProfileConnectRequest{ProfileID: p.ID, EntryID: e.ID, Direct: &direct, Execution: "local"})
	response := httptest.NewRecorder()
	f.base.a.externalProfileConnect(response, httptest.NewRequest(http.MethodPost, "/api/external/connect", bytes.NewReader(body)))
	return response
}
func TestDesktopWindowsExternalSSEntryPublicLifecycle(t *testing.T) {
	for _, protocol := range []string{"shadowsocks", "http-connect", "https-connect", "hysteria2"} {
		for _, kill := range []string{"on-connect", "always"} {
			t.Run(protocol+"/"+kill, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					f, p, e := windowsSSEntryHostFixture(t, protocol, kill)
					response := windowsSSEntryConnect(f, p, e)
					if response.Code != http.StatusOK {
						t.Fatal("SS-entry public connect failed", response.Code, response.Body.String())
					}
					raw, found := desktopExternalRetainedLaunches.Load(f.base.a)
					if !found {
						t.Fatal("entry lost retained registry")
					}
					l := raw.(*desktopNodeLaunch)
					if l.profileID != e.ID || l.policyProfileID != p.ID || f.base.a.state.RouterID != p.ID || l.external.windows.current(true) != nil || l.external.windows.entryToken != desktopOwnedNodeProfileToken(e) {
						t.Fatal("retained host lost independent physical/final owner")
					}
					expected := "HOMEVPN_POLICY_PROFILE_ID=" + p.ID
					if !slices.Contains(l.command.Env, "HOMEVPN_PROFILE_ID="+e.ID) || !slices.Contains(l.command.Env, expected) {
						t.Fatal("child environment lost final policy identity", expected)
					}
					proof, err := f.base.a.readDesktopExternalProof(l)
					if err != nil || !proof.EntryProven || proof.EntryID != e.ID || proof.EntryNodeID != "" || !proof.DNSProven {
						t.Fatal("entry proof changed identity", err)
					}
					observed := sessionTrackerFor(f.base.a).capture()
					if dns := proveSelectedDNSWithLookup(context.Background(), f.base.a, observed, l.mode, func(context.Context, string) ([]string, error) {
						t.Fatal("external proof queried ambient DNS")
						return nil, nil
					}); dns.Status != "passed" {
						t.Fatal("selected DNS lost final session", dns)
					}
					synctest.Wait()
					child := f.children[0]
					child.mu.Lock()
					child.closeErr = errors.New("controlled original-child close refusal")
					child.mu.Unlock()
					if err := l.external.windows.Close(context.Background()); err == nil {
						t.Fatal("failed exact child retirement claimed success")
					}
					child.mu.Lock()
					child.closeErr = nil
					child.mu.Unlock()
					if err := l.external.windows.Close(context.Background()); err != nil {
						t.Fatal("original child retirement retry", err)
					}
					if err := child.Alive(); err == nil {
						t.Fatal("original child survived joined retry")
					}
				})
			})
		}
	}
}
func TestDesktopWindowsExternalSSEntryActivationCapturesBothSources(t *testing.T) {
	for _, field := range []string{"entry", "final"} {
		t.Run(field, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f, p, e := windowsSSEntryHostFixture(t, "shadowsocks", "always")
				f.onAdmit = func(_ *desktopWindowsExternalChild) error {
					a := f.base.a
					a.mu.Lock()
					defer a.mu.Unlock()
					id := e.ID
					if field == "final" {
						id = p.ID
					}
					for i := range a.profiles.Profiles {
						if a.profiles.Profiles[i].ID == id {
							a.profiles.Profiles[i].External.Shadowsocks.Password = desktopSSEntryKey(desktopSSEntryMethods[1], 'z')
						}
					}
					return nil
				}
				response := windowsSSEntryConnect(f, p, e)
				if response.Code == http.StatusOK || f.base.a.state.Connected {
					t.Fatal("changed source activated", field, response.Body.String())
				}
				if len(f.children) != 1 || f.children[0].Alive() == nil {
					t.Fatal("failed dual-source activation did not join original child")
				}
			})
		})
	}
}

func TestDesktopWindowsExternalSSEntrySpeedLabRestoresBothSources(t *testing.T) {
	for _, protocol := range []string{"shadowsocks", "http-connect", "https-connect", "hysteria2"} {
		t.Run(protocol, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f, p, e := windowsSSEntryHostFixture(t, protocol, "always")
				response := windowsSSEntryConnect(f, p, e)
				if response.Code != http.StatusOK {
					t.Fatal("original composed connect", response.Code, response.Body.String())
				}
				a := f.base.a
				original := f.children[0].launch
				for deadline := time.Now().Add(time.Second); ; {
					if _, _, err := captureSpeedLabIdentity(a); err == nil {
						break
					} else if !time.Now().Before(deadline) {
						t.Fatal("original session observation", err)
					}
					time.Sleep(100 * time.Millisecond)
				}
				source := bytes.Clone(original.external.source)
				privateBefore, err := os.ReadFile(a.cfg.ProfilesFile)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				f.base.onHTTP = func(*desktopNodeConnectionChild) { cancel() }
				request := speedLabRequest{Scope: "temporary", DurationMode: "custom", MinSeconds: 1, MaxSeconds: 1, Topology: "router", NodeID: f.base.profile.ID, Mode: "wg"}
				body, _ := json.Marshal(request)
				response = httptest.NewRecorder()
				synctest.Wait()
				a.speedLabRun(response, httptest.NewRequest(http.MethodPost, "/api/speed-lab/run", bytes.NewReader(body)).WithContext(ctx))
				if response.Code != http.StatusConflict || strings.TrimSpace(response.Body.String()) != errConnectionOperationCancelled.Error() || ctx.Err() == nil || !a.state.Connected || len(f.children) != 3 {
					t.Fatal("temporary cancellation lost composed restore", response.Code, response.Body.String(), a.state, len(f.children))
				}
				trial, restored := f.children[1], f.children[2]
				if f.children[0].Alive() == nil || trial.Alive() == nil {
					t.Fatal("restoration retained an unjoined original or trial child")
				}
				l := restored.launch
				if restored.attempt.transfer.Predecessor == nil || *restored.attempt.transfer.Predecessor != trial.target || l.command == original.command || restored.Alive() != nil {
					t.Fatal("restoration reused a predecessor or process")
				}
				if l.external == nil || l.ownedNode != nil || l.external.windowsHost != original.external.windowsHost || !bytes.Equal(source, l.external.source) || l.profileID != e.ID || l.policyProfileID != p.ID || l.external.entry.ID != e.ID || l.external.windows.entryToken != original.external.windows.entryToken || l.external.windows.current(true) != nil {
					t.Fatal("restore changed original host, entry, final, or source")
				}
				if !slices.Contains(l.command.Env, "HOMEVPN_PROFILE_ID="+e.ID) || !slices.Contains(l.command.Env, "HOMEVPN_POLICY_PROFILE_ID="+p.ID) {
					t.Fatal("restoration changed separate entry/final environment identities")
				}
				if mtu, err := captureDesktopMTURestore(l); err != nil || mtu != 1360 {
					t.Fatal("restored MTU changed", mtu, err)
				}
				privateAfter, err := os.ReadFile(a.cfg.ProfilesFile)
				if err != nil || !bytes.Equal(privateBefore, privateAfter) || a.connectionContext != nil {
					t.Fatal("temporary transaction changed saved private sources", err)
				}
			})
		})
	}
}

func TestDesktopWindowsExternalSSEntryAlwaysOffRetriesOriginalOwner(t *testing.T) {
	for _, protocol := range []string{"shadowsocks", "http-connect", "https-connect", "hysteria2"} {
		t.Run(protocol, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f, p, e := windowsSSEntryHostFixture(t, protocol, "always")
				a, k := f.base.a, f.base.kernel
				off := &desktopProtectionOffFixture{a: a, slot: a.nodeProtection, kernel: k, profile: p}
				a.nodeProtection.backend.recoverWithBarrier = func(ctx context.Context, target mobiletor.DesktopWindowsProtectionTarget, barrier mobiletor.DesktopWindowsProtectionCommitBarrier) (desktopNodeProtectionRelease, error) {
					off.calls++
					if ctx.Err() != nil || barrier == nil || k.locked || k.target == nil || *k.target != target {
						return nil, errors.New("paired Off replaced its original joined target")
					}
					owner := &desktopProtectionOffFixtureOwner{fixture: off, target: target, armed: true}
					off.beforeClose = func(ctx context.Context) error {
						if err := barrier(ctx, mobiletor.DesktopWindowsProtectionCommit{Action: "off", Previous: copyDesktopNodeProtectionTarget(&target)}); err != nil {
							return err
						}
						if f.store.head.Phase != "intent" || f.store.head.Intent == nil || f.store.head.Intent.Action != "off" || f.store.head.Committed.Target == nil || *f.store.head.Committed.Target != target {
							return errors.New("paired Off removal preceded its exact durable intent")
						}
						return nil
					}
					off.owners = append(off.owners, owner)
					k.locked = true
					return owner, nil
				}
				a.nodeProtection.backend.recover = func(context.Context, mobiletor.DesktopWindowsProtectionTarget) (desktopNodeProtectionRelease, error) {
					return nil, errors.New("paired durable Off used callback-free native removal")
				}
				connected := windowsSSEntryConnect(f, p, e)
				if connected.Code != http.StatusOK {
					t.Fatal("paired original connect", connected.Code, connected.Body.String())
				}
				synctest.Wait()
				joined := httptest.NewRecorder()
				a.disconnect(joined, httptest.NewRequest(http.MethodPost, "/api/disconnect", nil))
				if joined.Code != http.StatusOK || k.target == nil || k.locked || a.nodeProtection.active != nil || f.children[0].Alive() == nil {
					t.Fatal("paired Disconnect lost retained Always or original join", joined.Code, joined.Body.String())
				}
				// Selecting the physical entry must not authorize changing the
				// final profile's retained protection.
				a.profiles.SelectedID = e.ID
				wrong := ownedProtectionGet(t, a)
				if wrong.ProfileID != e.ID || wrong.ProtectionProfileID != p.ID || wrong.Message != "Protection still belongs to another node. Select that node to turn its kill switch off." {
					t.Fatal("different selected profile hid original protection mismatch", wrong)
				}
				a.profiles.SelectedID = p.ID
				before := cloneRouterProfileStore(a.profiles)
				captured := ownedProtectionGet(t, a)
				if captured.ProfileID != p.ID || captured.ProtectionProfileID != p.ID || captured.EffectivePolicy != "always" || captured.Message != "" {
					t.Fatal("paired retained protection belongs to physical entry instead of final", captured)
				}
				off.closeFail = true
				pending := postProtectionForTest(a, bytes.NewReader(ownedProtectionBody(t, captured, "off")))
				if pending.Code != http.StatusServiceUnavailable || off.calls != 1 || a.nodeProtection.pendingOff() == nil || k.target == nil || !k.locked {
					t.Fatal("paired Off discarded pending original owner", pending.Code, pending.Body.String())
				}
				originalOwner := a.nodeProtection.pendingOff().owner
				blocked := windowsSSEntryConnect(f, p, e)
				if blocked.Code != http.StatusConflict || len(f.children) != 1 || a.state.Connected {
					t.Fatal("paired Connect escaped pending Off", blocked.Code, blocked.Body.String())
				}
				var retry profileProtectionSettings
				if json.Unmarshal(pending.Body.Bytes(), &retry) != nil || retry.ProfileToken != captured.ProfileToken {
					t.Fatal("pending paired Off lost exact saved token")
				}
				off.closeFail = false
				finished := postProtectionForTest(a, bytes.NewReader(ownedProtectionBody(t, retry, "off")))
				if finished.Code != http.StatusOK || off.calls != 1 || len(off.owners) != 1 || off.owners[0] != originalOwner || !off.owners[0].closed || a.nodeProtection != nil || k.target != nil || k.locked {
					t.Fatal("paired Off retry replaced original removal or failed exact absence", finished.Code, finished.Body.String())
				}
				for i := range before.Profiles {
					if before.Profiles[i].ID == p.ID {
						before.Profiles[i].KillSwitchPolicy = "off"
						before.Profiles[i].KillSwitch = false
					}
				}
				if !reflect.DeepEqual(before, a.profiles) {
					t.Fatal("paired Off rewrote entry or unrelated final policy")
				}
				raw, err := os.ReadFile(a.cfg.ProfilesFile)
				var saved common.RouterProfileStore
				if err != nil || json.Unmarshal(raw, &saved) != nil {
					t.Fatal("paired Off saved result", err)
				}
				if err := common.NormalizeRouterProfileStore(&before); err != nil || !reflect.DeepEqual(before, saved) {
					t.Fatal("paired Off changed its persisted original sources", err)
				}
			})
		})
	}
}

func desktopWindowsSSFinalFixture(t *testing.T, kill, method, protocol string) (common.RouterProfile, common.RouterProfile, *desktopNodeLaunch) {
	t.Helper()
	if protocol != "hysteria2" {
		return desktopSSCONNECTFixture(t, kill, method, protocol)
	}
	profile, _ := desktopExternalNativeFixture(t, protocol)
	_, entry, _ := desktopSSEntryFixture(t, kill, method, desktopSSEntryMethods[1], "tcp")
	profile.KillSwitchPolicy, profile.KillSwitch, profile.MultihopExecution = kill, true, "local"
	profile.MTUPolicy, profile.ManualMTU, profile.DNSProtocol = "manual", 1360, "udp"
	exit, err := standardExitFromExternalProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	launch, err := compileDesktopExternalCaptured(context.Background(), profile, entry, exit, false, "", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return profile, entry, launch
}
func mutateWindowsSSFinal(p *common.RouterProfile, field string) {
	if p.External.Protocol != "hysteria2" {
		mutateSSCONNECTFinal(p, field)
		return
	}
	switch field {
	case "password":
		p.External.Hysteria2.Password += "changed"
	case "tls":
		p.External.Hysteria2.TLSServerName = "changed.example"
	case "host":
		p.External.Hysteria2.Server = "198.51.100.99"
	case "port":
		p.External.Hysteria2.Port++
	case "public":
		p.External.ExpectedPublicIP = "203.0.113.99"
	case "option":
		p.DAITAEnabled = !p.DAITAEnabled
	}
}
func TestDesktopWindowsExternalSSEntryHysteriaPlatformBoundary(t *testing.T) {
	p, e, launch := desktopWindowsSSFinalFixture(t, "always", desktopSSEntryMethods[1], "hysteria2")
	if !desktopWindowsExternalGraphEligible(p, e, false, "") || desktopExternalSSEntryOwner(launch.external) || desktopExternalRetainedEntryForOS(launch.external, "linux") || desktopExternalRetainedEntryForOS(launch.external, "darwin") {
		t.Fatal("SS HY2 changed platform scope")
	}
	if err := prepareDesktopExternalPhysicalCaptured(launch, "windows"); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"password", "tls", "host", "port", "public", "option"} {
		changed := cloneRouterProfile(p)
		mutateWindowsSSFinal(&changed, field)
		if validateDesktopRetainedExternalSourcesLocked(changed, e, launch) == nil {
			t.Fatal("changed final source admitted", field)
		}
	}
	for _, target := range []string{"linux", "darwin"} {
		_, _, fresh := desktopWindowsSSFinalFixture(t, "always", desktopSSEntryMethods[1], "hysteria2")
		if err := prepareDesktopExternalPhysicalCaptured(fresh, target); err != nil || fresh.external.physical != nil {
			t.Fatal("unproved platform admitted", target)
		}
	}
}
