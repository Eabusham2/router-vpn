package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/mobiletor"
)

func TestDesktopTorConfiguredCapacityCannotAcquireMutableMTUAuthority(t *testing.T) {
	for _, policy := range []string{"jumbo-auto", "jumbo-default", "fixed", "default"} {
		t.Run(policy, func(t *testing.T) {
			_, inputs := desktopTorPolicyFixture(t, func(p *common.RouterProfile) {
				p.JumboTUN = strings.HasPrefix(policy, "jumbo-")
				p.MTUPolicy, p.ManualMTU = "default", 0
				if policy == "jumbo-auto" {
					p.MTUPolicy = "auto"
				} else if policy == "fixed" {
					p.MTUPolicy, p.ManualMTU = "manual", 1400
				}
			})
			now := time.Now()
			meta := inputs.Policy().Metadata()
			initial := desktopTorFixtureProof(meta, now)
			owner := &desktopTorRuntime{expected: meta, started: now, adopted: &initial, mtu: &desktopMTUSession{}}
			launch := &desktopNodeLaunch{tor: owner}
			request := desktopMTURequest{Schema: 1, Session: meta.SessionID, SourceSHA256: meta.SourceSHA256,
				ConfigSHA256: meta.ConfigSHA256, Generation: 1, Request: strings.Repeat("c", 32), Force: true}
			if err := authorizeDesktopTorMTURequest(launch, request); err == nil {
				t.Error("configured interface policy granted a mutable MTU operation")
			}
			raw, _ := json.Marshal(initial)
			if _, err := validateDesktopTorProof(raw, owner, now); err != nil {
				t.Fatal("unchanged configured interface lost its original proof", err)
			}
			idle := desktopMTURecord{Status: mobilemtu.Status{Phase: "idle", EffectiveMTU: meta.ConfiguredMTU, Source: "configured-unmeasured"}}
			if err := validateDesktopTorMTURecord(launch, idle); err != nil {
				t.Fatal("configured interface lost its unmeasured status", err)
			}
			idle.Requested = true
			if err := validateDesktopTorMTURecord(launch, idle); err == nil {
				t.Error("native status invented an Auto request against configured policy")
			}
			// Even a matching operation identifier must not override the frozen
			// Jumbo/Fixed/Default choice in a native proof or status receipt.
			owner.mtuAuthority = desktopTorMTUAuthority{generation: 1, request: request.Request}
			changed := initial
			changed.InterfaceIndex++
			changed.EffectiveMTU -= 20
			if changed.EffectiveMTU < 1280 {
				changed.EffectiveMTU = 1300
			}
			changed.MTUReadback = &mobiletor.DesktopBridgeMTUReadback{Generation: 1, RequestID: request.Request, Revision: 1,
				InterfaceName: changed.InterfaceName, InterfaceIndex: changed.InterfaceIndex, EffectiveMTU: changed.EffectiveMTU}
			raw, _ = json.Marshal(changed)
			if _, err := validateDesktopTorProof(raw, owner, now); err == nil {
				t.Error("mutable reader receipt overrode configured interface policy")
			}
			if owner.mtuReadback != nil {
				t.Error("rejected policy mutation changed the retained reader")
			}
			mutated := desktopMTURecord{Generation: 1, Requested: true, MTUReadback: changed.MTUReadback,
				Status: mobilemtu.Status{Request: request.Request, Complete: true, EffectiveMTU: changed.EffectiveMTU}}
			if err := validateDesktopTorMTURecord(launch, mutated); err == nil {
				t.Error("status receipt overrode configured interface policy")
			}
		})
	}
}

func TestDesktopTorJumboRestoreReprovesConfiguredReaderWithoutMutation(t *testing.T) {
	a, launch, _ := desktopTorRunningFixture(t, "healthy", func(p *common.RouterProfile) {
		p.JumboTUN, p.MTUPolicy = true, "auto"
		p.EffectiveMTU, p.EffectiveMTUSource = 1350, "historical-fixture"
	})
	a.cfg.ProfilesFile = filepath.Join(t.TempDir(), "profiles.json")
	a.state.Connected, a.state.Phase = true, "connected"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := a.waitDesktopTorProof(ctx, launch); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	captureDesktopMTUBaselineLocked(a, launch)
	a.mu.Unlock()
	owner := desktopMeasurementMTUSession(launch)
	owner.restoreMTU = 9000
	if err := a.restoreDesktopCapturedMTU(ctx, launch); err != nil {
		t.Fatal("captured Jumbo restore failed its fresh native path proof", err)
	}
	if owner.restoreMTU != 0 || owner.generation != 0 || launch.tor.mtuAuthority.generation != 0 {
		t.Fatal("configured Jumbo restore created a mutation generation")
	}
	path, err := readDesktopPathRecord(launch)
	if err != nil || path.Generation != 1 || !path.Verified {
		t.Fatal("configured Jumbo restore omitted fresh native path proof", err)
	}
	proof, err := a.readDesktopTorProof(launch)
	if err != nil || proof.EffectiveMTU != 9000 || proof.MTUReadback != nil || desktopTorSavedMTU(t, a).EffectiveMTU != 1350 {
		t.Fatal("configured Jumbo restore changed the reader or saved history", err)
	}
	for _, name := range []string{"mtu-request.json", "mtu-commit.json", "mtu-cancel.json"} {
		if _, err := readDesktopRuntimeFile(launch, name, 8192); !os.IsNotExist(err) {
			t.Fatal("configured Jumbo restore published a mutation command", name, err)
		}
	}
}
