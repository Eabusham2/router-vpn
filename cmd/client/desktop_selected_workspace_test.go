package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The process/protection state is a fixture boundary. Workspace capture,
// refusal, private-file deletion, directory retirement and MTU release use
// the shipping controller, including its exact original stop guard.
func TestDesktopSelectedMeasurementWorkspaceRetirement(t *testing.T) {
	for _, family := range []string{"selected-latency", "selected-candidate", "typed-candidate"} {
		t.Run(family, func(t *testing.T) {
			launch := desktopWorkspaceCaptureFixture(t)
			var names []string
			switch family {
			case "selected-latency":
				for _, suffix := range []string{"latency-capture", "measure-request", "measure-cancel", "measure-result"} {
					name := "node-chain-execution-" + suffix + ".json"
					names = append(names, name, "."+name+".pending")
				}
			case "selected-candidate":
				for _, suffix := range []string{"source", "request", "start", "live", "cancel"} {
					name := "node-chain-execution-candidate-" + suffix + ".json"
					names = append(names, name, "."+name+".pending")
				}
				for _, suffix := range []string{"metadata", "result"} {
					name := "node-chain-execution-candidate-" + suffix + ".json"
					names = append(names, name, "."+name+"."+strings.Repeat("a", 32)+".pending")
				}
			case "typed-candidate":
				for _, suffix := range []string{"source", "request", "live", "cancel", "result"} {
					name := "node-chain-typed-candidate-" + suffix + ".json"
					names = append(names, name, "."+name+".pending")
				}
			}
			body := []byte(`{"original":"selected measurement"}`)
			for _, name := range names {
				if err := launch.directoryRoot.WriteFile(name, body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			process := &desktopOwnedNodeTestProcess{started: true}
			launch.ownedNode = &desktopOwnedNodeRuntime{process: process}
			launch.chain = &desktopNodeChainLaunch{}
			pending := &desktopNodeChainCandidateRetirement{launch: launch, request: strings.Repeat("a", 32)}
			launch.chain.candidatePending = pending
			releases := 0
			launch.chain.measurementRelease = func() { releases++ }
			if cleanupDesktopNodeLaunch(launch) == nil || releases != 0 || pending.joined.Load() {
				t.Fatal("selected workspace retired before its original native process and protection")
			}
			for _, name := range names {
				actual, err := launch.directoryRoot.ReadFile(name)
				if err != nil || !bytes.Equal(actual, body) {
					t.Fatal("unjoined cleanup changed an original selected mailbox", name, err)
				}
			}
			process.closed, launch.ownedNode.retired = true, true
			if err := cleanupDesktopNodeLaunch(launch); err != nil {
				t.Fatal("joined selected workspace rejected its original measurement files", family, err)
			}
			if releases != 1 || !pending.joined.Load() || launch.chain.candidatePending != nil || launch.chain.measurementRelease != nil {
				t.Fatal("selected workspace lost its original pending measurement retirement")
			}
			if _, err := os.Lstat(launch.directory); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("joined selected workspace still exists", err)
			}
			if _, err := launch.directoryRoot.Stat("."); err == nil {
				t.Fatal("selected workspace retained an open directory handle")
			}
		})
	}
	t.Run("foreign-lookalikes", func(t *testing.T) {
		for _, name := range []string{
			"node-chain-execution-measure-result.json.foreign",
			"node-chain-execution-candidate-result.json.foreign",
			"node-chain-typed-candidate-result.json.foreign",
			".node-chain-execution-candidate-metadata.json.pending",
			".node-chain-execution-candidate-result.json.pending",
			".node-chain-execution-candidate-result.json." + strings.Repeat("a", 31) + ".pending",
			".node-chain-execution-candidate-result.json." + strings.Repeat("a", 33) + ".pending",
			".node-chain-execution-candidate-result.json." + strings.Repeat("A", 32) + ".pending",
			".node-chain-execution-candidate-result.json." + strings.Repeat("g", 32) + ".pending",
			".node-chain-execution-candidate-result.json." + strings.Repeat("a", 32) + ".pending.foreign",
			".node-chain-execution-candidate-source.json." + strings.Repeat("a", 32) + ".pending",
		} {
			launch := desktopWorkspaceCaptureFixture(t)
			body := []byte("retain original owned and unrelated files")
			for _, file := range []string{"node-chain-execution-measure-result.json", name} {
				if err := launch.directoryRoot.WriteFile(file, body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if cleanupDesktopNodeLaunch(launch) == nil || desktopExternalDirectoryCurrent(launch) != nil {
				t.Fatal("selected cleanup accepted an unrelated filename or lost the retained directory", name)
			}
			for _, file := range []string{"node-chain-execution-measure-result.json", name} {
				actual, err := os.ReadFile(filepath.Join(launch.directory, file))
				if err != nil || !bytes.Equal(actual, body) {
					t.Fatal("rejected selected cleanup partially erased the workspace", name, file, err)
				}
			}
			if err := launch.directoryRoot.Remove(name); err != nil {
				t.Fatal(err)
			}
			if err := cleanupDesktopNodeLaunch(launch); err != nil {
				t.Fatal("original selected workspace could not finish its authorized retry", name, err)
			}
		}
	})
}
