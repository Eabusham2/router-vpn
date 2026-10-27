package main

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"router-vpn/internal/common"
)

func TestDesktopTorEntryDNSSettingsPreserveExactPrivateNodeAndTransport(t *testing.T) {
	for _, execution := range []string{"local", "server"} {
		for _, transport := range []string{"udp", "tcp", "tls", "https", "h3"} {
			t.Run(execution+"/"+transport, func(t *testing.T) {
				a, _, _ := desktopTorEntryFixture(t, "198.51.100.8")
				a.profiles.Profiles[0].MultihopExecution = execution
				before := cloneRouterProfileStore(a.profiles)
				snapshot := dnsPolicySnapshotForTest(t, a)
				request := dnsPolicyRequest{Mode: "home", Protocol: transport, Port: 5353, ServerName: "adguard.home.example", Path: "/private-query?node=one"}
				w := postDNSPolicyForTest(a, bytes.NewReader(dnsPolicyBodyForTest(t, snapshot, request)))
				if w.Code != http.StatusOK {
					t.Fatal("captured Router Home DNS was rejected", w.Code, w.Body.String())
				}
				profile, entry := a.profiles.Profiles[0], a.profiles.Profiles[1]
				if !reflect.DeepEqual(entry, before.Profiles[1]) || !reflect.DeepEqual(profile.External, before.Profiles[0].External) || profile.AdGuardIPv4 != before.Profiles[0].AdGuardIPv4 || profile.APIToken != "" || profile.DNSHost != entry.AdGuardIPv4 || profile.DNSProtocol != transport || profile.DNSPort != 5353 {
					t.Fatal("Home editor changed private owners or the selected transport")
				}
				policy, err := externalDNSPolicyForPath(profile, entry, false)
				if err != nil {
					t.Fatal(err)
				}
				captured, err := captureDesktopTorPredecessor(a, profile, nil)
				if err != nil {
					t.Fatal(err)
				}
				binary := ""
				if execution == "local" {
					binary = installFakeExecutable(t, t.TempDir(), "tor")
				}
				prepared, err := stageDesktopTorInputsWithPredecessor(clientRoot(a), policy, profile, binary, installFakeExecutable(t, t.TempDir(), "native"), captured)
				if err != nil {
					t.Fatal("saved DNS does not compile in the shipping graph", err)
				}
				t.Cleanup(func() { _ = prepared.Launch.directoryRoot.Close() })
				metadata := prepared.Launch.tor.expected
				if desktopTorExecution(metadata.Execution) != execution || profile.MultihopExecution != execution {
					t.Fatal("DNS edit lost captured execution")
				}
				selected, _, _, err := desktopDNSExpectedEndpoints(prepared.Launch)
				if err != nil || metadata.DNS.Transport != transport || metadata.DNS.Address != entry.AdGuardIPv4 || metadata.DNS.Port != 5353 || metadata.DNSDetour != metadata.EntryTag || selected.Route != metadata.EntryTag || selected.RouteLabel != "Selected DNS via captured Router entry" {
					t.Fatal("saved/compiled/measured Home DNS diverged", metadata.DNS, selected, err)
				}
			})
		}
	}
}

func TestDesktopTorEntryDNSSettingsRejectStalePrivateSelection(t *testing.T) {
	for _, fault := range []string{"missing-entry", "wrong-entry", "wrong-exit", "credentials", "different-home", "public-home", "stale-editor", "server-ordinary", "compare"} {
		t.Run(fault, func(t *testing.T) {
			a, _, _ := desktopTorEntryFixture(t, "198.51.100.8")
			request := dnsPolicyRequest{Mode: "home", Protocol: "udp"}
			snapshot := dnsPolicySnapshotForTest(t, a)
			switch fault {
			case "missing-entry":
				a.profiles.Profiles = a.profiles.Profiles[:1]
			case "wrong-entry":
				a.profiles.Profiles[0].MultihopEntryID = "missing"
			case "wrong-exit":
				a.profiles.Profiles[0].MultihopExitID = "other"
			case "credentials":
				a.profiles.Profiles[1].APIToken = ""
			case "different-home":
				request.Host = "192.168.66.53"
			case "public-home":
				request.Host = "1.1.1.1"
			case "stale-editor":
				a.profiles.Profiles[1].AdGuardIPv4 = "192.168.55.53"
			case "server-ordinary":
				a.profiles.Profiles[0].MultihopExecution = "server"
				a.profiles.Profiles[1].NodeKind = "external"
			case "compare":
				a.profiles.Profiles[0].MultihopExecution = "auto"
			}
			if fault != "stale-editor" {
				snapshot = dnsPolicySnapshotForTest(t, a)
			}
			before := cloneRouterProfileStore(a.profiles)
			w := postDNSPolicyForTest(a, bytes.NewReader(dnsPolicyBodyForTest(t, snapshot, request)))
			if w.Code != http.StatusBadRequest && w.Code != http.StatusConflict || !reflect.DeepEqual(before, a.profiles) {
				t.Fatal("unowned resolver modified the saved path", w.Code, w.Body.String())
			}
		})
	}
}

func TestDesktopTorEntryDNSRetestKeepsPrivateRouteAndRejectsChangedSource(t *testing.T) {
	for _, home := range []bool{false, true} {
		a, launch := desktopTorRunningEntryFixture(t, "tor-dns-complete", func(profile, entry *common.RouterProfile) {
			if home {
				profile.DNSMode, profile.DNSProtocol, profile.DNSHost = "home", "udp", entry.AdGuardIPv4
			}
		})
		a.state.Connected, a.state.Phase = true, "connected"
		captureDesktopMTUBaselineLocked(a, launch)
		baseline := desktopMeasurementMTUSession(launch)
		if baseline == nil || baseline.entryID != a.profiles.Profiles[1].ID || baseline.entryToken != mtuProfileSnapshotToken(a.profiles.Profiles[1]) {
			t.Fatal("measurement dropped its original Router entry")
		}
		before := cloneRouterProfileStore(a.profiles)
		operation, _ := desktopDNSStartForTest(t, a, "tls")
		view := desktopDNSWaitForTest(t, a, operation, func(v desktopDNSView) bool { return v.Status.Complete && v.Status.Drained })
		<-operation.done
		if view.Status.Stage != "complete" || len(view.Status.Results) != 13 || !reflect.DeepEqual(before, a.profiles) {
			t.Fatal("captured Tor entry DNS did not complete without changing settings", view.Status)
		}
		selected := view.Status.Results[0]
		wantRoute, wantLabel := launch.tor.expected.FinalTag, "Selected DNS via captured Tor exit"
		if home {
			wantRoute, wantLabel = launch.tor.expected.EntryTag, "Selected DNS via captured Router entry"
		}
		if selected.Route != wantRoute || selected.RouteLabel != wantLabel || selected.Address != launch.tor.expected.DNS.Address {
			t.Fatal("selected measurement was attributed to another path", selected)
		}
		for _, row := range view.Status.Results[1:] {
			if row.Kind != "public" || row.Route != "exit" || row.RouteLabel != "Current Tor connection" {
				t.Fatal("public comparison used the private Router resolver", row)
			}
		}
		snapshot, err := captureDesktopDNSSnapshot(a)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(clientRoot(a), "generated", "captured", "wg", "wg.conf")
		raw, err := os.ReadFile(path)
		if err != nil || os.WriteFile(path, append(raw, []byte("\n# replacement source\n")...), 0600) != nil {
			t.Fatal("could not replace the isolated entry source", err)
		}
		if snapshot.current(a) == nil {
			t.Fatal("old DNS sample retained a changed Router entry source")
		}
		invalidateDesktopDNSResults(a)
		mtuSuspensions.Delete(a)
	}
}
