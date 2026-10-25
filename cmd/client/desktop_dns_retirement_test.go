package main

import (
	"net/http"
	"testing"
	"time"
)

func TestDesktopDNSNativeFailureRetiresCompletedDraftOnUnchangedNetwork(t *testing.T) {
	for _, kind := range []string{"ordinary", "tor"} {
		t.Run(kind, func(t *testing.T) {
			var a *app
			var launch *desktopNodeLaunch
			if kind == "tor" {
				a, launch = desktopTorDNSControllerFixture(t, "tor-dns-complete")
			} else {
				a, launch = desktopDNSControllerFixture(t, "dns-winner")
			}
			operation, request := desktopDNSStartForTest(t, a, "https")
			view := desktopDNSWaitForTest(t, a, operation, func(view desktopDNSView) bool { return view.Status.Complete && view.Status.Drained })
			<-operation.done
			if view.Status.Stage != "complete" || len(view.Status.Results) != 13 {
				t.Fatal("fixture did not complete a valid measured draft", view.Status)
			}
			request.Transport, request.ResultID = "", "fastest"
			if w := desktopDNSHTTP(t, a, http.MethodPost, "/api/dns/measurement/select", request); w.Code != http.StatusOK {
				t.Fatal("valid connected draft was not available", w.Code, w.Body.String())
			}
			if !desktopDNSNetworkCurrent(launch) {
				t.Fatal("fixture did not retain the same physical network")
			}
			// Crash only the captured isolated native child. The shipping
			// monitor must retire the old DNS result before its failed drain.
			if err := launch.command.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			<-desktopConnectionProcessDone(a, launch.command)
			if kind == "tor" {
				a.monitorDesktopTorRuntime(launch)
			} else {
				a.monitorDesktopExternalRuntime(launch)
			}
			deadline := time.Now().Add(8 * time.Second)
			for {
				a.mu.Lock()
				failed := a.state.Phase == "failed"
				a.mu.Unlock()
				if failed {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("shipping native monitor did not report the captured process failure")
				}
				time.Sleep(5 * time.Millisecond)
			}
			if !desktopDNSNetworkCurrent(launch) {
				t.Fatal("test accidentally depended on a changed physical fingerprint")
			}
			operation.mu.Lock()
			invalid := operation.invalid
			operation.mu.Unlock()
			if !invalid {
				t.Fatal("automatic native failure preserved a completed DNS draft")
			}
			if w := desktopDNSHTTP(t, a, http.MethodPost, "/api/dns/measurement/select", request); w.Code != http.StatusConflict {
				t.Fatal("failed-path DNS result remained selectable", w.Code, w.Body.String())
			}
			if view := operation.view(a); len(view.Status.Results) != 0 || view.ExpiresInMS != 0 {
				t.Fatal("failed-path DNS samples remained visible as current", view)
			}
		})
	}
}
