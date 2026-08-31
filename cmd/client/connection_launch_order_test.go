package main

import (
	"os"
	"strings"
	"testing"
)

func sourceFunctionForTest(t *testing.T, file, signature string) string {
	t.Helper()
	body, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	text := string(body)
	start := strings.Index(text, signature)
	if start < 0 {
		t.Fatalf("%s is missing %q", file, signature)
	}
	endOffset := strings.Index(text[start+len(signature):], "\nfunc ")
	if endOffset < 0 {
		return text[start:]
	}
	return text[start : start+len(signature)+endOffset]
}

func assertGuardedProcessStart(t *testing.T, file, signature, startMarker, ownershipMarker string) {
	t.Helper()
	fn := sourceFunctionForTest(t, file, signature)
	start := strings.Index(fn, startMarker)
	if start < 0 {
		t.Fatalf("%s %s is missing process start %q", file, signature, startMarker)
	}
	if guard := strings.LastIndex(fn[:start], "checkConnectionOperation()"); guard < 0 {
		t.Fatalf("%s %s starts a process without a cancellation check immediately upstream", file, signature)
	}
	ownershipRelative := strings.Index(fn[start+len(startMarker):], ownershipMarker)
	if ownershipRelative < 0 {
		t.Fatalf("%s %s never publishes ownership marker %q after process start", file, signature, ownershipMarker)
	}
	ownership := start + len(startMarker) + ownershipRelative
	guardAfter := strings.Index(fn[ownership+len(ownershipMarker):], "checkConnectionOperation()")
	if guardAfter < 0 {
		t.Fatalf("%s %s publishes process ownership without a post-launch cancellation check", file, signature)
	}
}

func TestEveryShippingConnectionStartIsGuardedBeforeAndAfterLaunch(t *testing.T) {
	assertGuardedProcessStart(t, "main.go", "func (a *app) startModeAttempt", "if err = cmd.Start(); err != nil", "a.cmd = cmd")
	assertGuardedProcessStart(t, "standard_exit_platform_routes.go", "func (a *app) platformStandardExitConnect", "if err = cmd.Start(); err != nil", "a.cmd = cmd")
	assertGuardedProcessStart(t, "multihop_native_routes.go", "func (a *app) nativeMultihopConnect", "if err = cmd.Start(); err != nil", "a.cmd = cmd")
	assertGuardedProcessStart(t, "multihop.go", "func (a *app) multihopConnect", "if err := cmd.Start(); err != nil", "a.cmd = cmd")
	assertGuardedProcessStart(t, "external_profile_connect.go", "func (a *app) externalProfileConnect", "if err = cmd.Start(); err != nil", "a.cmd = cmd")
	assertGuardedProcessStart(t, "external_profile_connect.go", "func (a *app) externalProfileConnect", "if err = realCmd.Start(); err != nil", "a.cmd = realCmd")
}

func TestFallbackLoopsRecognizeStableCancellationSentinel(t *testing.T) {
	for _, item := range []struct {
		file    string
		markers []string
	}{
		{
			file: "strategy_modes.go",
			markers: []string{
				"errors.Is(err, errConnectionOperationCancelled)",
				"errors.Is(tryErr, errConnectionOperationCancelled)",
				"errors.Is(restoreErr, errConnectionOperationCancelled)",
				"finalizeCancelledFallback",
				"cancelPendingStartupPolicy",
			},
		},
		{
			file: "logical_modes.go",
			markers: []string{
				"errors.Is(err, errConnectionOperationCancelled)",
				"finalizeCancelledFallback",
				"connectionOperationContextOrBackground",
				"http.StatusConflict",
			},
		},
	} {
		body, err := os.ReadFile(item.file)
		if err != nil {
			t.Fatalf("read %s: %v", item.file, err)
		}
		text := string(body)
		for _, marker := range item.markers {
			if !strings.Contains(text, marker) {
				t.Errorf("%s is missing cancellation contract marker %q", item.file, marker)
			}
		}
	}
}

func TestLegacyStandardExitDispatcherDelegatesWithoutNestedTransaction(t *testing.T) {
	fn := sourceFunctionForTest(t, "openvpn_standard_exit_runtime.go", "func (a *app) standardExitConnectDispatch")
	if !strings.Contains(fn, "a.platformStandardExitConnect(w, r)") {
		t.Fatal("legacy standard-exit dispatcher does not delegate to the authoritative platform transaction")
	}
	if strings.Contains(fn, "beginConnectionOperation()") {
		t.Fatal("legacy standard-exit dispatcher still acquires a nested connection transaction")
	}
}
