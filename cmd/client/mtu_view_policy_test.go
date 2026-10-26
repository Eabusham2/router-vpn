package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemtu"
)

func TestMTUViewPolicyDistinguishesConfiguredCapacityFromLegacyIdleAuto(t *testing.T) {
	for _, policy := range []string{"legacy-auto", "external-auto", "tor-auto", "tor-default", "tor-fixed", "tor-jumbo"} {
		t.Run(policy, func(t *testing.T) {
			var a *app
			wantAllowed, wantRequested, wantMTU := false, false, 1280
			switch policy {
			case "legacy-auto":
				a, _ = newMTUTransactionFixture(t)
				wantAllowed, wantMTU = true, 1420
			case "external-auto":
				a, _ = desktopMTUControllerFixture(t, "mtu-winner")
				wantAllowed, wantRequested = true, true
			default:
				var launch *desktopNodeLaunch
				a, launch, _ = desktopTorRunningFixture(t, "healthy", func(p *common.RouterProfile) {
					p.MTUPolicy = strings.TrimPrefix(policy, "tor-")
					if policy == "tor-fixed" {
						p.MTUPolicy, p.ManualMTU = "manual", 1400
					} else if policy == "tor-jumbo" {
						p.MTUPolicy, p.JumboTUN = "auto", true
					}
				})
				a.mu.Lock()
				a.state.Connected, a.state.Phase = true, "connected"
				a.mu.Unlock()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if _, err := a.waitDesktopTorProof(ctx, launch); err != nil {
					t.Fatal(err)
				}
				wantAllowed, wantRequested = policy == "tor-auto", policy == "tor-auto"
				wantMTU = launch.tor.expected.ConfiguredMTU
			}
			response := httptest.NewRecorder()
			a.desktopMTUStatus(response, httptest.NewRequest(http.MethodGet, "/api/mtu/status", nil))
			var value struct {
				Allowed   *bool            `json:"optimization_allowed"`
				Requested bool             `json:"requested"`
				Status    mobilemtu.Status `json:"status"`
			}
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &value) != nil || value.Allowed == nil ||
				*value.Allowed != wantAllowed || value.Requested != wantRequested || value.Status.EffectiveMTU != wantMTU || value.Status.Measured || value.Status.Running {
				t.Fatal("MTU view confused requested work with configured optimization authority", response.Code, response.Body.String())
			}
		})
	}
}
