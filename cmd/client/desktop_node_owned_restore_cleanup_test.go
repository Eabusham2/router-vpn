package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Execute the real restore capture, private staging, host admission and checked
// retirement. Only the process/Job and kernel are modeled by the existing host
// fixture; this test does not establish native Windows acceptance.
func TestDesktopOwnedNodeRestorePlanCleanupTransfersSourceOwnership(t *testing.T) {
	for _, phase := range []string{"unused", "staged", "active"} {
		t.Run(phase, func(t *testing.T) {
			prior := newDesktopOwnedNodeTestFixture(t)
			if err := prior.start(t, context.Background(), nil); err != nil {
				t.Fatal(err)
			}
			defer prior.process.Close(context.Background())
			restored, err := prior.a.captureDesktopOwnedNodeRestore(prior.launch, prior.profile)
			if err != nil {
				t.Fatal("could not capture a real proved restore source", err)
			}
			plan := speedLabRestorePlan{native: restored}
			config := append([]byte(nil), restored.config...)
			metadata := append([]byte(nil), restored.metadata...)
			source := append([]byte(nil), restored.ownedNode.source...)
			backing := restored.ownedNode.source
			configBacking, metadataBacking := restored.config, restored.metadata
			if len(source) == 0 || len(config) == 0 || len(metadata) == 0 {
				t.Fatal("restore capture has no private source or derived bytes")
			}
			if phase == "unused" {
				priorSource := append([]byte(nil), prior.launch.ownedNode.source...)
				clearSpeedLabRestorePlan(plan)
				for name, body := range map[string][]byte{"source": backing, "config": configBacking, "metadata": metadataBacking} {
					if !bytes.Equal(body, make([]byte, len(body))) {
						t.Fatal("unused restore plan retained private bytes", name)
					}
				}
				if !bytes.Equal(prior.launch.ownedNode.source, priorSource) {
					t.Fatal("unused plan cleanup erased the original live runtime source")
				}
				prior.retirement(t)
				if _, err := stopDesktopNodeRuntime(prior.a, prior.launch.command); err != nil {
					t.Fatal(err)
				}
				if err := finishDesktopNodeRuntime(prior.a); err != nil {
					t.Fatal(err)
				}
				return
			}

			prior.retirement(t)
			if _, err := stopDesktopNodeRuntime(prior.a, prior.launch.command); err != nil {
				t.Fatal(err)
			}
			if err := finishDesktopNodeRuntime(prior.a); err != nil {
				t.Fatal(err)
			}
			directory := filepath.Join(restored.root, "restored-private")
			if err := os.Mkdir(directory, 0700); err != nil {
				t.Fatal(err)
			}
			if err := captureDesktopRuntimeDirectory(restored, directory); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = restored.directoryRoot.Close() })
			for name, body := range map[string][]byte{"sing-box.json": restored.config, "capture.json": restored.metadata} {
				if err := writeDesktopRuntimeFile(restored, name, body, false); err != nil {
					t.Fatal(err)
				}
			}
			if err := stageDesktopOwnedNodeInputs(prior.a, restored); err != nil {
				t.Fatal("restore did not consume the actual joined predecessor", err)
			}
			restored.command, err = desktopOwnedNodeDescriptor(restored, filepath.Join(restored.root, "package"), []string{"CAPTURED_RESTORE_FIXTURE=1"})
			if err != nil {
				t.Fatal(err)
			}
			prior.a.mu.Lock()
			prior.a.cmd = restored.command
			prior.a.state.Connected, prior.a.state.Phase = false, "starting"
			prior.a.mu.Unlock()
			desktopNodeOwners.Store(prior.a, restored)
			defer desktopNodeOwners.CompareAndDelete(prior.a, restored)
			current := &desktopOwnedNodeTestFixture{a: prior.a, launch: restored, profile: prior.profile,
				original: restored.ownedNode.policy.OriginalProfile(), kernel: prior.kernel,
				process: &desktopOwnedNodeTestProcess{started: true, join: func() { prior.kernel.locked = false }}}
			defer current.process.Close(context.Background())
			if phase == "active" {
				if err := current.start(t, context.Background(), nil); err != nil {
					t.Fatal("captured restore admission failed", err)
				}
			}

			clearSpeedLabRestorePlan(plan)
			if !bytes.Equal(restored.ownedNode.source, source) || !bytes.Equal(restored.config, config) || !bytes.Equal(restored.metadata, metadata) {
				t.Fatal("restore plan cleanup erased private bytes after ownership transferred to the runtime", phase)
			}
			actual, err := readDesktopRuntimeFile(restored, "node-source.json", int64(len(source))+1)
			if err != nil || !bytes.Equal(actual, source) {
				t.Fatal("restored runtime lost the exact staged constructor input", err)
			}
			if phase == "active" {
				next, err := prior.a.captureDesktopOwnedNodeRestore(restored, prior.profile)
				if err != nil || next == nil {
					t.Fatal("the restored live runtime could not capture its next restore after plan cleanup", err)
				}
				clearSpeedLabRestorePlan(speedLabRestorePlan{native: next})
				current.retirement(t)
			}
			if owned, err := stopDesktopNodeRuntime(prior.a, restored.command); err != nil || !owned {
				t.Fatal("restored source could not complete checked retirement", err)
			}
			if err := finishDesktopNodeRuntime(prior.a); err != nil {
				t.Fatal(err)
			}
			if restored.ownedNode.source != nil || !bytes.Equal(backing, make([]byte, len(backing))) {
				t.Fatal("checked runtime retirement did not clear the retained source backing bytes")
			}
			for name, body := range map[string][]byte{"config": configBacking, "metadata": metadataBacking} {
				if !bytes.Equal(body, make([]byte, len(body))) {
					t.Fatal("checked runtime retirement did not clear its derived private backing bytes", name)
				}
			}
		})
	}
}
