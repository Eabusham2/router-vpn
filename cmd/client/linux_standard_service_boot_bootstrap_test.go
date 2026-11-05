//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func bootBootstrapRequestFixture() linuxStandardServiceRequest {
	return linuxStandardServiceRequest{Schema: 1, Action: "boot-bootstrap", Session: strings.Repeat("2", 32), BudgetMS: 1500, DeadlineNS: time.Now().Add(1500 * time.Millisecond).UnixNano(), Bootstrap: &linuxStandardBootBootstrapRequest{ID: strings.Repeat("3", 32), DeadlineNS: time.Now().Add(time.Second).UnixNano(), ProfileID: "node", ProfileRevision: strings.Repeat("4", 64), Mode: "wg", Hostname: "node.example", NetworkID: strings.Repeat("5", 64)}}
}
func TestBootBootstrapFramesRejectCrossScope(t *testing.T) {
	q := bootBootstrapRequestFixture()
	raw, e := json.Marshal(q)
	if e != nil {
		t.Fatal(e)
	}
	var decoded linuxStandardServiceRequest
	if e = linuxStandardServiceDecode(raw, &decoded); e != nil {
		t.Fatal(e)
	}
	for _, action := range []string{"start", "image-prepare", "mtu-start", "reverse-prepare", "transfer-reserve", "protection-status"} {
		t.Run(action, func(t *testing.T) {
			q := q
			q.Action = action
			raw, _ := json.Marshal(q)
			if e := linuxStandardServiceDecode(raw, &decoded); e == nil {
				t.Fatal("bootstrap scope entered another operation")
			}
			r := linuxStandardServiceResponse{Schema: 1, Action: action, Bootstrap: &linuxStandardBootBootstrapResponse{ID: q.Bootstrap.ID, Clean: true}}
			raw, _ = json.Marshal(r)
			var response linuxStandardServiceResponse
			if e := linuxStandardServiceDecode(raw, &response); e == nil {
				t.Fatal("bootstrap response entered another operation")
			}
		})
	}
}
func TestBootBootstrapOriginalParentAdmissionIsBounded(t *testing.T) {
	for _, name := range []string{"capture", "shipping-prepare", "retirement"} {
		t.Run(name, func(t *testing.T) {
			a := &app{}
			a.mu.Lock()
			defer a.mu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
			defer cancel()
			entered, done := make(chan struct{}), make(chan error, 1)
			go func() {
				close(entered)
				switch name {
				case "capture":
					_, e := captureDesktopLinuxNodeParentContext(ctx, a)
					done <- e
				case "shipping-prepare":
					p := common.RouterProfile{ID: "node", Endpoint: "node.example", KillSwitchPolicy: "always"}
					_, e := prepareDesktopLinuxNodeHostWith(ctx, a, p, "wg", 0, func(context.Context, string) (string, error) {
						t.Error("expired admission reached native verification")
						return "", nil
					}, nil)
					done <- e
				case "retirement":
					c := &desktopLinuxNodeParentCapture{app: a}
					done <- c.retirementCurrent(ctx)
				}
			}()
			<-entered
			select {
			case e := <-done:
				if !errors.Is(e, context.DeadlineExceeded) {
					t.Fatal("original cancellation was lost", e)
				}
			case <-time.After(time.Second):
				t.Fatal("caller stayed behind held app mutex")
			}
		})
	}
}
func TestBootBootstrapParentGenerationStillRejectsReplacement(t *testing.T) {
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(linuxOwnedControllerRoot, "routers.json"), ModesFile: filepath.Join(linuxOwnedControllerRoot, "modes.json"), ScriptsDir: filepath.Join(linuxOwnedControllerRoot, "modes"), StateFile: filepath.Join(linuxOwnedControllerRoot, "state.json")}}
	owner := &ownedDesktopController{}
	parent := &desktopLinuxNodeParent{controller: owner}
	owner.nodeParent = parent
	a.localController = owner
	c := &desktopLinuxNodeParentCapture{app: a, controller: owner, parent: parent, lifetime: lifetime, record: parent.record}
	if e := c.currentAppModeContext(context.Background(), true); e != nil {
		t.Fatal(e)
	}
	expired, stop := context.WithCancel(context.Background())
	stop()
	if e := c.currentAppModeContext(expired, true); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if e := c.currentAppModeContext(context.Background(), true); e != nil {
		t.Fatal("pure expiry poisoned original parent", e)
	}
	owner.nodeParent = &desktopLinuxNodeParent{controller: owner}
	if e := c.currentAppModeContext(context.Background(), true); e == nil {
		t.Fatal("same controller adopted replaced native parent")
	}
}
