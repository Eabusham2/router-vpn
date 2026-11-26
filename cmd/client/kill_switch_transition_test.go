package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func envValueForTest(env []string, key string) (string, int) {
	prefix := key + "="
	value := ""
	count := 0
	for _, item := range env {
		if strings.HasPrefix(item, prefix) {
			value = strings.TrimPrefix(item, prefix)
			count++
		}
	}
	return value, count
}

func TestProtectedStopAndCapturedRestore(t *testing.T) {
	t.Setenv(killSwitchHoldEnv, "stale")
	a := &app{}
	if value, count := envValueForTest(a.stopCommandEnv(false), killSwitchHoldEnv); value != "0" || count != 1 {
		t.Fatal("manual stop retained a stale protection hold")
	}
	if value, count := envValueForTest(a.stopCommandEnv(true), killSwitchHoldEnv); value != "1" || count != 1 {
		t.Fatal("transition stop did not retain protection")
	}

	for _, mode := range []string{"wg-pq", "naive-h3"} {
		t.Run(mode, func(t *testing.T) {
			launch := &desktopNodeLaunch{profileID: "home", mode: mode, mtuSession: strings.Repeat("1", 32)}
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := captureDesktopRuntimeDirectory(launch, dir); err != nil {
				t.Fatal(err)
			}
			defer launch.directoryRoot.Close()
			write := func(name string, value any) {
				t.Helper()
				data, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			graph := json.RawMessage(`{"inbounds":[{"type":"tun","mtu":1400}],"route":{"final":"original"}}`)
			launch.configSHA256 = fmt.Sprintf("%x", sha256.Sum256(graph))
			write("sing-box.json", graph)
			write("capture.json", map[string]any{"schema": 1, "profile_id": "home", "mode": mode, "config_sha256": launch.configSHA256})
			live := desktopNodeMTURecord{Schema: 1, Session: launch.mtuSession, Config: launch.configSHA256, Path: strings.Repeat("2", 64),
				Index: 7, Reader: 1, Interface: "router-vpn", MTU: 1340, Heartbeat: time.Now().UnixMilli()}
			write("node-mtu-status.json", live)
			var plan speedLabRestorePlan
			if err := plan.captureWrapper(context.Background(), launch); err != nil {
				t.Fatal(err)
			}
			defer clearSpeedLabRestorePlan(plan)
			wantBudget := 25 * time.Second
			if mode == "wg-pq" {
				wantBudget += 30 * time.Second
			}
			budget, err := desktopNodeReadyBudget(plan.native)
			if err != nil || budget != wantBudget {
				t.Fatalf("captured %s readiness budget is %s, want %s: %v", mode, budget, wantBudget, err)
			}
			var saved struct {
				Inbounds []struct {
					Type string
					MTU  int
				}
				Route struct{ Final string }
			}
			if err := json.Unmarshal(plan.native.config, &saved); err != nil {
				t.Fatal(err)
			}
			if plan.wrapperMTU != 1340 || plan.native.mode != mode || saved.Route.Final != "original" ||
				len(saved.Inbounds) != 1 || saved.Inbounds[0].Type != "tun" || saved.Inbounds[0].MTU != 1340 {
				t.Fatal("restore changed the captured route or TUN", plan.native.mode, plan.wrapperMTU)
			}
			live.Config = strings.Repeat("f", 64)
			write("node-mtu-status.json", live)
			var stale speedLabRestorePlan
			if err := stale.captureWrapper(context.Background(), launch); err == nil || stale.native != nil {
				t.Fatal("a different runtime supplied the restore MTU")
			}
		})
	}
}
