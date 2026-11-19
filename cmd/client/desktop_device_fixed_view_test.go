package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestDeviceMTUCompleteTwoHopNativeProjection(t *testing.T) {
	privateOperationRoot(t)
	a := deviceMTUTestApp(t)
	before, err := captureDeviceMTUPolicy(a)
	if err != nil {
		t.Fatal(err)
	}
	if reply := deviceMTUTestPost(t, a, before.token, 1300); reply.Code != 200 {
		t.Fatal(reply.Code, reply.Body.String())
	}
	ctx, finish, err := a.beginConnectionOperation()
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	_, sel := nativeMultihopCapturedFixture(t, "wg", "off")
	frozen := sel.Native.configs[sel.ExitMode]
	launch, err := compileRetainedNativeMultihopLaunchContext(ctx, sel, nil)
	if err != nil {
		t.Fatal(err)
	}
	graph := retainedGraph(t, launch.config)
	var found bool
	for _, item := range graph["inbounds"].([]any) {
		if tun := item.(map[string]any); tun["type"] == "tun" {
			found = tun["mtu"] == float64(1300)
		}
	}
	var meta map[string]any
	if !found || launch.multihopDeviceMTU != deviceMTUForContext(ctx) || sel.Native.configs[sel.ExitMode] != frozen || json.Unmarshal(launch.metadata, &meta) != nil || meta["device_mtu_revision"] != a.deviceMTU.policy.Revision || meta["device_fixed_mtu"] != float64(1300) {
		t.Fatal("native two-hop source or client TUN lost the independent device revision")
	}
	sel.restoreMTU = 1300
	if _, err := compileRetainedNativeMultihopLaunchContext(ctx, sel, nil); err == nil {
		t.Fatal("different MTU purposes overlapped")
	}
	sel.restoreMTU = 0
	sel.deviceFixed, sel.deviceRevision = 1300, a.deviceMTU.policy.Revision
	if _, err := compileRetainedNativeMultihopLaunchContext(context.Background(), sel, nil); err == nil {
		t.Fatal("fixed source reopened without its original device preference")
	}
}

func TestDeviceMTUViewRequiresOriginalReaderAndPreference(t *testing.T) {
	a := deviceMTUTestApp(t)
	before, err := captureDeviceMTUPolicy(a)
	if err != nil {
		t.Fatal(err)
	}
	if reply := deviceMTUTestPost(t, a, before.token, 1320); reply.Code != 200 {
		t.Fatal(reply.Body.String())
	}
	c, err := captureDeviceMTUPolicy(a)
	if err != nil {
		t.Fatal(err)
	}
	view := desktopDeviceMTUView{mtuViewIdentity{Session: "original", Profile: "first", Native: true}, c.policy.Revision, 1320, 1320}
	if err := view.verify(c); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*desktopDeviceMTUView){
		func(v *desktopDeviceMTUView) { v.revision += "a" }, func(v *desktopDeviceMTUView) { v.actual = 1300 }, func(v *desktopDeviceMTUView) { v.fixed = 0 }, func(v *desktopDeviceMTUView) { v.identity.Session = "" },
	} {
		other := view
		edit(&other)
		if other.verify(c) == nil {
			t.Fatal("view accepted different reader, source or session")
		}
	}
	a.deviceMTU = c
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/mtu/status", nil)
	if !a.writeDeviceFixedMTUStatus(w, r, "", "") || w.Code != 409 {
		t.Fatal("disconnected saved size appeared as a live configured MTU", w.Code)
	}
}
