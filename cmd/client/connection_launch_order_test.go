package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
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
	assertCapturedGuardedProcessStart(t, file, signature, startMarker, ownershipMarker, "checkConnectionOperation()")
}

func assertCapturedGuardedProcessStart(t *testing.T, file, signature, startMarker, ownershipMarker, guardMarker string) {
	t.Helper()
	fn := sourceFunctionForTest(t, file, signature)
	start := strings.Index(fn, startMarker)
	if start < 0 {
		t.Fatalf("%s %s is missing process start %q", file, signature, startMarker)
	}
	if guard := strings.LastIndex(fn[:start], guardMarker); guard < 0 {
		t.Fatalf("%s %s starts a process without a cancellation check immediately upstream", file, signature)
	}
	ownershipRelative := strings.Index(fn[start+len(startMarker):], ownershipMarker)
	if ownershipRelative < 0 {
		t.Fatalf("%s %s never publishes ownership marker %q after process start", file, signature, ownershipMarker)
	}
	ownership := start + len(startMarker) + ownershipRelative
	guardAfter := strings.Index(fn[ownership+len(ownershipMarker):], guardMarker)
	if guardAfter < 0 {
		t.Fatalf("%s %s publishes process ownership without a post-launch cancellation check", file, signature)
	}
}

func TestEveryShippingConnectionStartIsGuardedBeforeAndAfterLaunch(t *testing.T) {
	// Router Node and ordinary starts share the captured request check and
	// locked publication helper. Re-reading whichever request is current after
	// a native callback would let an old start adopt a replacement operation.
	assertCapturedGuardedProcessStart(t, "main.go", "func (a *app) startModeAttempt", "err = cmd.Start()", "a.publishStartedDesktopNode(startupCtx, native, cmd", "checkCapturedConnectionOperation(startupCtx)")
	assertGuardedProcessStart(t, "standard_exit_platform_routes.go", "func (a *app) platformStandardExitConnectOwned", "err = cmd.Start()", "a.cmd = cmd")
	wrapper := sourceFunctionForTest(t, "multihop_native_routes.go", "func (a *app) nativeMultihopConnect(")
	for _, required := range []string{"a.nativeMultihopConnectOwned(w, r, nativeMultihopConnectRuntime{", "capture: captureNativeMultihopForApp", "preflight: preflightOwnedNativeMultihopCommand", "stage: stageOwnedNativeMultihopCommand", "proof: (*app).proveNativeMultihop"} {
		if !strings.Contains(wrapper, required) {
			t.Fatal("public native multihop lost its shipping adapter", required)
		}
	}
	assertGuardedProcessStart(t, "multihop_native_routes.go", "func (a *app) nativeMultihopConnectOwned", "if err = cmd.Start(); err != nil", "a.cmd = cmd")
	assertGuardedProcessStart(t, "multihop.go", "func (a *app) multihopConnect", "if err := cmd.Start(); err != nil", "a.cmd = cmd")
	assertGuardedProcessStart(t, "external_profile_connect.go", "func (a *app) externalProfileConnectOwned", "if err = cmd.Start(); err != nil", "a.cmd = cmd")
	assertGuardedProcessStart(t, "external_profile_connect.go", "func (a *app) externalProfileConnectOwned", "err = nativeRetained.Start(a.connectionOperationContextOrBackground())", "a.cmd = realCmd")
	assertGuardedProcessStart(t, "external_profile_connect.go", "func (a *app) externalProfileConnectOwned", "err = realCmd.Start()", "a.cmd = realCmd")
	fn := sourceFunctionForTest(t, "external_profile_connect.go", "func (a *app) externalProfileConnectOwned")
	if err := sharedNativeExternalLaunchGuards(fn); err != nil {
		t.Fatal(err)
	}
}

// Both native branches must share guards and publication in their own enclosing
// block. Checks in the separate OpenVPN branch, or inside only one native start
// branch, cannot stand in for the common cancellation boundary.
func sharedNativeExternalLaunchGuards(fn string) error {
	source := "package fixture\n" + fn
	positions := token.NewFileSet()
	file, err := parser.ParseFile(positions, "external_profile_connect.go", source, 0)
	if err != nil {
		return err
	}
	text := func(node ast.Node) string {
		return source[positions.Position(node.Pos()).Offset:positions.Position(node.End()).Offset]
	}
	var blocks []*ast.BlockStmt
	ast.Inspect(file, func(node ast.Node) bool {
		block, ok := node.(*ast.BlockStmt)
		if !ok {
			return true
		}
		for _, statement := range block.List {
			if _, declaration := statement.(*ast.DeclStmt); declaration && text(statement) == "var realCmd *exec.Cmd" {
				blocks = append(blocks, block)
			}
		}
		return true
	})
	if len(blocks) != 1 {
		return fmt.Errorf("native external launch must have one command ownership block, found %d", len(blocks))
	}
	before, launch, publication, after := -1, -1, -1, -1
	for index, statement := range blocks[0].List {
		switch value := statement.(type) {
		case *ast.AssignStmt:
			switch text(value) {
			case "err = a.checkConnectionOperation()":
				before = index
			case "a.cmd = realCmd":
				publication = index
			}
		case *ast.IfStmt:
			if value.Init != nil && text(value.Init) == "err = a.checkConnectionOperation()" {
				after = index
			}
			// Startup capture can refuse before either native branch starts. Both
			// actual starts must remain in the same exact success-gated pair;
			// an unrelated nested start or branch-local guard is insufficient.
			if text(value.Cond) == "err == nil" && value.Init == nil && value.Else == nil && len(value.Body.List) == 1 {
				pair, ok := value.Body.List[0].(*ast.IfStmt)
				if ok && pair.Init == nil && text(pair.Cond) == "nativeRetained != nil" && pair.Else != nil &&
					strings.Contains(text(pair.Body), "err = nativeRetained.Start(a.connectionOperationContextOrBackground())") &&
					strings.Contains(text(pair.Else), "err = realCmd.Start()") {
					launch = index
				}
			}
		}
	}
	if before < 0 || launch <= before || publication <= launch || after <= publication {
		return fmt.Errorf("native external starts lost their shared guard/publication order: before=%d launch=%d publication=%d after=%d", before, launch, publication, after)
	}
	return nil
}

func TestNativeExternalSharedLaunchGuardsRejectMutations(t *testing.T) {
	fn := sourceFunctionForTest(t, "external_profile_connect.go", "func (a *app) externalProfileConnectOwned")
	if err := sharedNativeExternalLaunchGuards(fn); err != nil {
		t.Fatal("shipping launch prerequisite:", err)
	}
	// Select the last occurrence so the original OpenVPN guards remain in
	// place and cannot accidentally make a broken native branch look guarded.
	replaceLast := func(source, old, replacement string) string {
		index := strings.LastIndex(source, old)
		if index < 0 {
			t.Fatalf("missing mutation prerequisite %q", old)
		}
		return source[:index] + replacement + source[index+len(old):]
	}
	for _, mutation := range []struct{ name, old, replacement string }{
		{"retained start omitted", "err = nativeRetained.Start(a.connectionOperationContextOrBackground())", "err = nil"},
		{"direct start omitted", "err = realCmd.Start()", "err = nil"},
		{"failed startup admitted", "if err == nil {\n\t\t\tif nativeRetained != nil {", "if err != nil {\n\t\t\tif nativeRetained != nil {"},
		{"shared prelaunch guard omitted", "err = a.checkConnectionOperation()\n", "err = nil\n"},
		{"shared post-publication guard omitted", "if err = a.checkConnectionOperation(); err != nil {", "if err = error(nil); err != nil {"},
		{"wrong command published", "a.cmd = realCmd", "a.cmd = nil"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			if err := sharedNativeExternalLaunchGuards(replaceLast(fn, mutation.old, mutation.replacement)); err == nil {
				t.Fatal("broken native launch satisfied shared cancellation ownership")
			}
		})
	}
	t.Run("retained-only guard cannot protect direct start", func(t *testing.T) {
		broken := replaceLast(fn, "err = a.checkConnectionOperation()\n", "err = nil\n")
		broken = replaceLast(broken, "err = nativeRetained.Start(a.connectionOperationContextOrBackground())", "err = a.checkConnectionOperation()\n\t\t\terr = nativeRetained.Start(a.connectionOperationContextOrBackground())")
		if err := sharedNativeExternalLaunchGuards(broken); err == nil {
			t.Fatal("branch-local guard authorized the other native start")
		}
	})
	t.Run("publication before launch", func(t *testing.T) {
		broken := replaceLast(fn, "a.cmd = realCmd", "a.cmd = nil")
		broken = replaceLast(broken, "if err == nil {\n\t\t\tif nativeRetained != nil {", "a.cmd = realCmd\n\t\tif err == nil {\n\t\t\tif nativeRetained != nil {")
		if err := sharedNativeExternalLaunchGuards(broken); err == nil {
			t.Fatal("unstarted native command was accepted as published ownership")
		}
	})
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
