package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
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
	standardWrapper := sourceFunctionForTest(t, "standard_exit_platform_routes.go", "func (a *app) platformStandardExitConnectOwned(")
	for _, required := range []string{"operation, finish, guardErr := a.beginConnectionOperation()", "defer finish()", "a.platformStandardExitConnectCaptured(w, r, adapter, operation)"} {
		if !strings.Contains(standardWrapper, required) {
			t.Fatal("public standard exit lost its original operation", required)
		}
	}
	assertCapturedGuardedProcessStart(t, "standard_exit_platform_routes.go", "func (a *app) platformStandardExitConnectCaptured(", "err = cmd.Start()", "a.cmd = cmd", "checkCapturedConnectionOperation(operation)")
	wrapper := sourceFunctionForTest(t, "multihop_native_routes.go", "func (a *app) nativeMultihopConnect(")
	for _, required := range []string{"a.nativeMultihopConnectOwned(w, r, nativeMultihopConnectRuntime{", "capture: captureNativeMultihopForApp", "preflight: preflightOwnedNativeMultihopCommand", "stage: stageOwnedNativeMultihopCommand", "proof: (*app).proveNativeMultihop"} {
		if !strings.Contains(wrapper, required) {
			t.Fatal("public native multihop lost its shipping adapter", required)
		}
	}
	assertGuardedProcessStart(t, "multihop_native_routes.go", "func (a *app) nativeMultihopConnectLocalOwned", "err = cmd.Start()", "a.cmd = cmd")
	if err := nativeMultihopLaunchGuards(nativeMultihopLaunchSources(t)); err != nil {
		t.Fatal(err)
	}
	assertGuardedProcessStart(t, "multihop.go", "func (a *app) multihopConnect", "if err := cmd.Start(); err != nil", "a.cmd = cmd")
	assertGuardedProcessStart(t, "external_profile_connect.go", "func (a *app) externalProfileConnectOwned", "if err = cmd.Start(); err != nil", "a.cmd = cmd")
	assertGuardedProcessStart(t, "external_profile_connect.go", "func (a *app) externalProfileConnectOwned", "err = nativeRetained.Start(a.connectionOperationContextOrBackground())", "a.cmd = realCmd")
	assertGuardedProcessStart(t, "external_profile_connect.go", "func (a *app) externalProfileConnectOwned", "err = realCmd.Start()", "a.cmd = realCmd")
	fn := sourceFunctionForTest(t, "external_profile_connect.go", "func (a *app) externalProfileConnectOwned")
	if err := sharedNativeExternalLaunchGuards(fn); err != nil {
		t.Fatal(err)
	}
}

func nativeMultihopLaunchSources(t *testing.T) []string {
	t.Helper()
	return []string{
		sourceFunctionForTest(t, "multihop_native_routes.go", "func (a *app) nativeMultihopConnectLocalOwned("),
		sourceFunctionForTest(t, "desktop_imported_owned.go", "func (a *app) publishDesktopImportedMultihopStartLocked("),
		sourceFunctionForTest(t, "desktop_imported_owned.go", "func startDesktopOwnedImportedLaunch("),
		sourceFunctionForTest(t, "desktop_node_owned.go", "func startDesktopOwnedNodeLaunchFor("),
		sourceFunctionForTest(t, "desktop_imported_platform.go", "func startDesktopImportedPlatform("),
		sourceFunctionForTest(t, "desktop_imported_linux_lifecycle.go", "func (owner *desktopLinuxImportedConnection) Start("),
		sourceFunctionForTest(t, "desktop_node_session_linux.go", "func (s *desktopLinuxNodeSession) startWithVerifier("),
		sourceFunctionForTest(t, "desktop_node_host_linux_start.go", "func (h *desktopLinuxNodeHost) startWithVerifier("),
		sourceFunctionForTest(t, "desktop_node_host_linux_start.go", "func (h *desktopLinuxNodeHost) publishStarting("),
		sourceFunctionForTest(t, "multihop_native_routes.go", "func (a *app) nativeMultihopConnectOwned("),
		sourceFunctionForTest(t, "desktop_node_chain_dispatch.go", "func desktopMultihopPlatformLaunch("),
		sourceFunctionForTest(t, "desktop_node_chain_dispatch.go", "func startDesktopMultihopPlatform("),
		sourceFunctionForTest(t, "desktop_node_chain_dispatch.go", "func (a *app) publishDesktopCapturedMultihopStartLocked("),
		sourceFunctionForTest(t, "desktop_node_chain_dispatch.go", "func startDesktopCapturedMultihopOwned("),
		sourceFunctionForTest(t, "desktop_node_chain_owned.go", "func startDesktopOwnedNodeChainLaunch("),
		sourceFunctionForTest(t, "desktop_node_chain_owned.go", "func (a *app) publishDesktopNodeChainStartLocked("),
		sourceFunctionForTest(t, "desktop_node_chain_linux.go", "func (owner *desktopNodeChainPlatformRuntime) start("),
		sourceFunctionForTest(t, "multihop_node_chain_request.go", "func (a *app) resolveNativeMultihopRequestLocked("),
	}
}

// The protected imported path publishes its partial owner before native child
// creation so a failed start can still be joined. Follow that actual helper as
// well as the ordinary cmd.Start branch; an unrelated guard, comment or string
// cannot stand in for either branch's original operation.
func nativeMultihopLaunchGuards(sources []string) error {
	if len(sources) != 18 {
		return fmt.Errorf("native multihop launch lost its original Windows and Linux shipping functions")
	}
	positions := token.NewFileSet()
	methods := make([]*ast.FuncDecl, 0, len(sources))
	for _, source := range sources {
		file, err := parser.ParseFile(positions, "", "package fixture\n"+source, 0)
		if err != nil || len(file.Decls) != 1 {
			return fmt.Errorf("native multihop launch source is invalid: %v", err)
		}
		method, ok := file.Decls[0].(*ast.FuncDecl)
		if !ok || method.Body == nil {
			return fmt.Errorf("native multihop launch lost its function body")
		}
		methods = append(methods, method)
	}
	text := func(node ast.Node) string {
		var out bytes.Buffer
		_ = format.Node(&out, positions, node)
		return out.String()
	}
	contains := func(block *ast.BlockStmt, exact string) bool {
		if block != nil {
			for _, statement := range block.List {
				if text(statement) == exact {
					return true
				}
			}
		}
		return false
	}
	returns := func(block *ast.BlockStmt) bool {
		if block != nil && len(block.List) != 0 {
			_, ok := block.List[len(block.List)-1].(*ast.ReturnStmt)
			return ok
		}
		return false
	}
	guard := func(statement ast.Stmt, exact string) bool {
		branch, ok := statement.(*ast.IfStmt)
		return ok && branch.Init != nil && text(branch.Init) == exact && text(branch.Cond) == "err != nil" && returns(branch.Body)
	}
	before, launch, failed, publication, after, protectedStart := -1, -1, -1, -1, -1, -1
	for index, statement := range methods[0].Body.List {
		if guard(statement, "err = a.checkConnectionOperation()") {
			if launch < 0 {
				before = index
			} else if protectedStart < 0 {
				after = index
			}
		}
		branch, ok := statement.(*ast.IfStmt)
		if !ok || branch.Init != nil {
			continue
		}
		switch text(branch.Cond) {
		case "desktopMultihopPlatformLaunch(native)":
			retained, protected := branch.Else.(*ast.IfStmt)
			if !protected || retained.Init != nil || text(retained.Cond) != "protected" {
				continue
			}
			other, ordinary := retained.Else.(*ast.BlockStmt)
			if ordinary && len(branch.Body.List) == 2 &&
				text(branch.Body.List[0]) == "err = startDesktopMultihopPlatform(operation, a, sel, native)" &&
				text(branch.Body.List[1]) == "cmd = native.command" &&
				len(retained.Body.List) == 3 && text(retained.Body.List[0]) == "a.mu.Lock()" &&
				text(retained.Body.List[1]) == "err = a.publishDesktopCapturedMultihopStartLocked(operation, native, sel)" &&
				text(retained.Body.List[2]) == "a.mu.Unlock()" && len(other.List) == 1 && text(other.List[0]) == "err = cmd.Start()" {
				launch = index
			}
		case "protected && !desktopMultihopPlatformLaunch(native)":
			if branch.Else == nil && len(branch.Body.List) == 1 &&
				guard(branch.Body.List[0], "err := startDesktopCapturedMultihopOwned(operation, operation, a, native)") {
				protectedStart = index
			}
		case "err != nil":
			if launch >= 0 && publication < 0 && returns(branch.Body) {
				failed = index
			}
		case "!protected":
			if branch.Else == nil && contains(branch.Body, "a.mu.Lock()") && contains(branch.Body, "a.cmd = cmd") && contains(branch.Body, "a.mu.Unlock()") {
				publication = index
			}
		}
	}
	if before < 0 || launch <= before || failed <= launch || publication <= failed || after <= publication || protectedStart <= after {
		return fmt.Errorf("native multihop branches lost guarded start/retained publication order: %d %d %d %d %d %d", before, launch, failed, publication, after, protectedStart)
	}
	// Protected publication validates the captured request under its caller's
	// app lock, before retaining the exact unstarted command.
	publicationGuard, retained := -1, -1
	for index, statement := range methods[1].Body.List {
		if guard(statement, "err := a.checkCapturedConnectionOperationLocked(operation)") {
			publicationGuard = index
		}
		if text(statement) == "a.cmd = launch.command" {
			retained = index
		}
	}
	if publicationGuard < 0 || retained <= publicationGuard {
		return fmt.Errorf("protected multihop publication lost its captured operation")
	}
	delegates, callbacks, callbackGuard := 0, 0, 0
	ast.Inspect(methods[2].Body, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok && text(call.Fun) == "startDesktopOwnedNodeLaunchFor" && len(call.Args) == 5 &&
			text(call.Args[0]) == "ctx" && text(call.Args[1]) == "operation" && text(call.Args[2]) == "a" && text(call.Args[3]) == "launch" {
			delegates++
		}
		if result, ok := node.(*ast.ReturnStmt); ok && len(result.Results) == 1 && text(result.Results[0]) == "owner.host.start(call, a, launch, arguments, environment, directory)" {
			callbacks++
		}
		if statement, ok := node.(ast.Stmt); ok && guard(statement, "err := owner.currentContext(call)") {
			callbackGuard++
		}
		return true
	})
	if delegates != 1 || callbacks != 1 || callbackGuard != 1 {
		return fmt.Errorf("protected multihop lost its original-context native start delegate")
	}
	pre, child, capture, post, refusal, admit := -1, -1, -1, -1, -1, -1
	for index, statement := range methods[3].Body.List {
		if guard(statement, "err := a.checkCapturedConnectionOperation(operation)") {
			pre = index
		}
		switch text(statement) {
		case "process, err := start(ctx, args, launch.command.Env, launch.directory)":
			child = index
		case "owned.process = process":
			capture = index
		case "operationErr := a.checkCapturedConnectionOperation(operation)":
			post = index
		case "return errors.Join(a.admitDesktopOwnedNodeFor(ctx, operation, launch), a.checkCapturedConnectionOperation(operation))":
			admit = index
		}
		if branch, ok := statement.(*ast.IfStmt); ok && branch.Init == nil &&
			text(branch.Cond) == "err != nil || operationErr != nil || process == nil || !process.Started() || a.desktopOwnedNodeCurrentFor(ctx, launch, true) != nil" && returns(branch.Body) {
			refusal = index
		}
	}
	if pre < 0 || child <= pre || capture <= child || post <= capture || refusal <= post || admit <= refusal {
		return fmt.Errorf("protected native child lost captured pre/post-start admission and retained failure cleanup")
	}
	// Linux deliberately uses its existing session/process owner. Trace the
	// concrete call chain rather than requiring a second Windows-style owner
	// registry or accepting an unrelated cancellation marker elsewhere.
	ordered := func(method int, checks ...func(ast.Stmt) bool) bool {
		next := 0
		for _, statement := range methods[method].Body.List {
			if checks[next](statement) {
				next++
				if next == len(checks) {
					return true
				}
			}
		}
		return false
	}
	exact := func(want string) func(ast.Stmt) bool {
		return func(statement ast.Stmt) bool { return text(statement) == want }
	}
	checked := func(want string) func(ast.Stmt) bool {
		return func(statement ast.Stmt) bool { return guard(statement, want) }
	}
	if !ordered(4,
		checked("err := launch.importedPlatform.Start(ctx)"),
		checked("err := launch.importedPlatform.Current(ctx)"),
		exact("return registerActiveDNSRuntimeConfigKind(a, sel.Exit.ID, sel.ExitMode, filepath.Join(launch.directory, \"sing-box.json\"), true)")) {
		return fmt.Errorf("Linux imported launch lost original Start-before-Current-before-DNS ownership")
	}
	if !ordered(5,
		exact("ctx, cancel := context.WithTimeout(ctx, 45*time.Second)"), exact("defer cancel()"),
		exact("return owner.session.startWithVerifier(ctx, owner.host, os.Environ(), owner.capture.verify)")) {
		return fmt.Errorf("Linux imported launch replaced its original caller, session or source verifier")
	}
	if !ordered(6,
		checked("err := s.currentLocked(ctx)"),
		exact("s.active = host"),
		checked("_, err := s.selectedPredecessorLocked(ctx, s.predecessor)"),
		exact("return host.startWithVerifier(ctx, s.journal, s.predecessor, environment, verify)")) {
		return fmt.Errorf("Linux imported session lost original observation, partial owner or captured start")
	}
	partialCommand := func(statement ast.Stmt) bool {
		branch, ok := statement.(*ast.IfStmt)
		return ok && branch.Init == nil && branch.Else == nil && text(branch.Cond) == "h.process != nil && h.process.Started()" &&
			contains(branch.Body, "h.launch.command = h.process.command")
	}
	if !ordered(7,
		checked("err := h.unoccupied(ctx)"), checked("err := h.current(ctx)"),
		exact("h.process, err = startDesktopLinuxNodeProcessWithVerifier(ctx, h.parent, arguments, environment, h.launch.directory, capture, verify)"),
		partialCommand, checked("err := h.publishStarting(ctx)"),
		checked("err := h.transaction.ServePreparation(dialogue)"), exact("return h.runningLocked(ctx)")) {
		return fmt.Errorf("Linux imported native child lost its retained original process or pre/post-start checks")
	}
	publicationCurrent := func(statement ast.Stmt) bool {
		branch, ok := statement.(*ast.IfStmt)
		return ok && branch.Init == nil && branch.Else == nil &&
			strings.HasPrefix(text(branch.Cond), "a.checkCapturedConnectionOperationLocked(h.operation) != nil ||") && returns(branch.Body)
	}
	if !ordered(8,
		checked("err := h.current(ctx)"), checked("err := desktopnetwork.LockContext(ctx, &a.mu)"),
		exact("defer a.mu.Unlock()"), publicationCurrent, exact("a.cmd = h.launch.command")) {
		return fmt.Errorf("Linux imported publication lost its locked original-operation guard")
	}
	// The Local transaction remains entered through the original request owner.
	// Its internal native fixture seam cannot supply a different operation or
	// skip the source resolver in the shipping HTTP path.
	if !ordered(9,
		exact("operation, finish, guardErr := a.beginConnectionOperationContext(r.Context())"),
		exact("defer finish()"),
		exact("q, err := decodeMultihopConnectRequest(http.MaxBytesReader(w, r.Body, 16<<10))"),
		exact("a.mu.Lock()"),
		exact("sel, err := a.resolveNativeMultihopRequestLocked(q)"),
		exact("a.mu.Unlock()"),
		exact("a.nativeMultihopConnectLocalOwned(w, r, operation, sel, driver)")) {
		return fmt.Errorf("native Local dispatcher lost its captured request or full source resolver")
	}
	refusing := func(condition string) func(ast.Stmt) bool {
		return func(statement ast.Stmt) bool {
			branch, ok := statement.(*ast.IfStmt)
			return ok && branch.Init == nil && branch.Else == nil && strings.Join(strings.Fields(text(branch.Cond)), " ") == condition && returns(branch.Body)
		}
	}
	// The request helper now owns the catalog snapshot. Trace its complete
	// ordered revision inventory before resolving either native graph family;
	// the old direct-resolver marker cannot substitute for this closure.
	references := func(statement ast.Stmt) bool {
		branch, ok := statement.(*ast.IfStmt)
		if !ok || branch.Init != nil || branch.Else != nil || text(branch.Cond) != "q.ordered()" || len(branch.Body.List) != 1 {
			return false
		}
		loop, ok := branch.Body.List[0].(*ast.RangeStmt)
		return ok && text(loop.X) == "q.Nodes" && loop.Key != nil && text(loop.Key) == "_" && loop.Value != nil && text(loop.Value) == "node" &&
			len(loop.Body.List) == 1 && text(loop.Body.List[0]) == "required = append(required, node.ID)"
	}
	legacyRevisions := func(statement ast.Stmt) bool {
		branch, ok := statement.(*ast.IfStmt)
		return ok && branch.Init == nil && branch.Else == nil && text(branch.Cond) == "err == nil && q.present() && !q.ordered()" &&
			len(branch.Body.List) == 1 && text(branch.Body.List[0]) == "err = a.validateDesktopProfileExpectationsLocked(q.desktopProfileExpectations, []string{selection.Entry.ID, selection.Exit.ID}, false)"
	}
	if !ordered(17,
		checked("err := q.validateOrdered()"), exact("var required []string"), references,
		checked("err := a.validateDesktopProfileExpectationsLocked(q.desktopProfileExpectations, required, q.ordered())"),
		exact("store := cloneRouterProfileStore(a.profiles)"),
		exact("control, ok := profileByID(store.Profiles, store.SelectedID)"), refusing("!ok"), refusing("control.NodeKind == \"external\""),
		exact("selection, err := resolveNativeMultihopSelection(control, store.Profiles, q)"), legacyRevisions, exact("return selection, err")) {
		return fmt.Errorf("native Local source resolver lost original complete revisions or immutable catalog ownership")
	}
	if len(methods[0].Body.List) == 0 || !refusing("operation == nil || a.checkCapturedConnectionOperation(operation) != nil || driver.capture == nil || driver.preflight == nil || driver.stage == nil || driver.proof == nil")(methods[0].Body.List[0]) {
		return fmt.Errorf("native Local transaction accepts an uncaptured operation or incomplete driver")
	}
	if len(methods[10].Body.List) != 1 || !exact("return launch != nil && (launch.importedPlatform != nil || launch.chain != nil && launch.chain.platform != nil)")(methods[10].Body.List[0]) {
		return fmt.Errorf("native platform dispatch accepts an unrelated runtime family")
	}
	branchReturn := func(condition, result string) func(ast.Stmt) bool {
		return func(statement ast.Stmt) bool {
			branch, ok := statement.(*ast.IfStmt)
			return ok && branch.Init == nil && branch.Else == nil && text(branch.Cond) == condition && len(branch.Body.List) == 1 && text(branch.Body.List[0]) == "return "+result
		}
	}
	if !ordered(11,
		branchReturn("launch == nil || launch.chain == nil", "startDesktopImportedPlatform(ctx, a, selection, launch)"),
		refusing("launch.chain.platform == nil || selection.Native == nil || selection.Native.chain == nil || launch.chain.selection.Native != selection.Native"),
		exact("budget, err := desktopNodeReadyBudget(launch)"),
		exact("startup, cancel := context.WithTimeout(ctx, budget)"), exact("defer cancel()"),
		checked("err := launch.chain.platform.start(startup)"),
		refusing("launch.command == nil"), checked("err := launch.chain.platform.current(ctx)"),
		exact("return registerActiveDNSRuntimeConfigKind(a, selection.Exit.ID, selection.ExitMode, filepath.Join(launch.directory, \"sing-box.json\"), true)")) {
		return fmt.Errorf("ordered platform launch lost captured source, caller, native start or current DNS owner")
	}
	if len(methods[12].Body.List) != 2 || !ordered(12,
		branchReturn("launch != nil && launch.chain != nil", "a.publishDesktopNodeChainStartLocked(operation, launch, selection)"),
		exact("return a.publishDesktopImportedMultihopStartLocked(operation, launch, selection)")) ||
		len(methods[13].Body.List) != 2 || !ordered(13,
		branchReturn("launch != nil && launch.chain != nil", "startDesktopOwnedNodeChainLaunch(ctx, operation, a, launch)"),
		exact("return startDesktopOwnedImportedLaunch(ctx, operation, a, launch)")) {
		return fmt.Errorf("native captured dispatcher substituted the operation or a concrete runtime family")
	}
	if len(methods[14].Body.List) != 2 || !refusing("launch == nil || launch.chain == nil || launch.ownedNode == nil || launch.ownedNode.chain != launch.chain || launch.chain.selection.Native == nil || launch.chain.selection.Native.chain.host == nil || launch.chain.selection.Native.chain.host.app != a")(methods[14].Body.List[0]) {
		return fmt.Errorf("ordered native child start lost its original typed owner")
	}
	delegates, callbacks, callbackGuard = 0, 0, 0
	ast.Inspect(methods[14].Body, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok && text(call.Fun) == "startDesktopOwnedNodeLaunchFor" && len(call.Args) == 5 &&
			text(call.Args[0]) == "ctx" && text(call.Args[1]) == "operation" && text(call.Args[2]) == "a" && text(call.Args[3]) == "launch" {
			delegates++
		}
		if result, ok := node.(*ast.ReturnStmt); ok && len(result.Results) == 1 && text(result.Results[0]) == "owner.host.start(call, a, launch, arguments, environment, directory)" {
			callbacks++
		}
		if statement, ok := node.(ast.Stmt); ok && guard(statement, "err := owner.currentContext(call)") {
			callbackGuard++
		}
		return true
	})
	if delegates != 1 || callbacks != 1 || callbackGuard != 1 {
		return fmt.Errorf("ordered native child replaced the original native start delegate or caller")
	}
	if !ordered(15,
		checked("err := a.checkCapturedConnectionOperationLocked(operation)"),
		refusing("launch == nil || launch.command == nil || launch.chain == nil || launch.ownedNode == nil || launch.ownedNode.chain != launch.chain || a.cmd != nil || launch.chain.selection.Native != selection.Native"),
		exact("owned := launch.ownedNode"),
		refusing("owned.operation != operation || owned.slot == nil || owned.slot != a.nodeProtection || owned.attempt == nil || !owned.attempt.matchesOwned(owned) || owned.attempt.launch != launch || !owned.chainSourceCurrentLocked(a)"),
		exact("a.cmd = launch.command"), exact("desktopNodeOwners.Store(a, launch)")) {
		return fmt.Errorf("ordered native publication lost original operation, protection, full source or process owner")
	}
	if len(methods[16].Body.List) != 2 || !ordered(16,
		refusing("owner == nil || owner.session == nil || owner.host == nil || owner.capture == nil || owner.capture.platform == nil"),
		exact("return owner.session.startWithVerifier(ctx, owner.host, os.Environ(), owner.capture.platform.verify)")) {
		return fmt.Errorf("ordered Linux start replaced its original caller, session or source verifier")
	}
	return nil
}

func TestNativeMultihopLaunchGuardsRejectMutations(t *testing.T) {
	original := nativeMultihopLaunchSources(t)
	if err := nativeMultihopLaunchGuards(original); err != nil {
		t.Fatal("shipping launch prerequisite:", err)
	}
	for _, mutation := range []struct {
		name, old, replacement string
		part                   int
	}{
		{"ordinary-start-omitted", "err = cmd.Start()", "err = nil", 0},
		{"ordinary-owner-omitted", "a.cmd = cmd", "a.cmd = nil", 0},
		{"prelaunch-guard-omitted", "if err = a.checkConnectionOperation(); err != nil {", "if err = error(nil); err != nil {", 0},
		{"protected-publication-omitted", "err = a.publishDesktopCapturedMultihopStartLocked(operation, native, sel)", "err = nil", 0},
		{"protected-caller-replaced", "startDesktopCapturedMultihopOwned(operation, operation, a, native)", "startDesktopCapturedMultihopOwned(context.Background(), operation, a, native)", 0},
		{"protected-publication-guard-omitted", "a.checkCapturedConnectionOperationLocked(operation)", "unrelatedGuard()", 1},
		{"protected-command-substituted", "a.cmd = launch.command", "a.cmd = nil", 1},
		{"delegate-operation-replaced", "startDesktopOwnedNodeLaunchFor(ctx, operation, a, launch,", "startDesktopOwnedNodeLaunchFor(ctx, ctx, a, launch,", 2},
		{"native-caller-replaced", "owner.host.start(call, a, launch, arguments, environment, directory)", "owner.host.start(context.Background(), a, launch, arguments, environment, directory)", 2},
		{"native-owner-guard-omitted", "owner.currentContext(call)", "unrelatedGuard()", 2},
		{"native-prelaunch-guard-omitted", "if err := a.checkCapturedConnectionOperation(operation); err != nil {", "if err := error(nil); err != nil {", 3},
		{"partial-child-omitted", "owned.process = process", "owned.process = nil", 3},
		{"native-postlaunch-guard-omitted", "operationErr := a.checkCapturedConnectionOperation(operation)", "operationErr := error(nil)", 3},
		{"native-postlaunch-error-ignored", "err != nil || operationErr != nil || process == nil", "err != nil || process == nil", 3},
		{"native-final-admission-omitted", "a.admitDesktopOwnedNodeFor(ctx, operation, launch)", "unrelatedAdmission()", 3},
		{"platform-caller-replaced", "startDesktopMultihopPlatform(operation, a, sel, native)", "startDesktopMultihopPlatform(context.Background(), a, sel, native)", 0},
		{"platform-command-substituted", "cmd = native.command", "cmd = nil", 0},
		{"platform-start-caller-replaced", "launch.importedPlatform.Start(ctx)", "launch.importedPlatform.Start(context.Background())", 4},
		{"platform-current-omitted", "launch.importedPlatform.Current(ctx)", "unrelatedGuard()", 4},
		{"platform-dns-owner-replaced", "registerActiveDNSRuntimeConfigKind(a, sel.Exit.ID, sel.ExitMode,", "registerActiveDNSRuntimeConfigKind(a, \"foreign\", sel.ExitMode,", 4},
		{"linux-timeout-caller-replaced", "context.WithTimeout(ctx, 45*time.Second)", "context.WithTimeout(context.Background(), 45*time.Second)", 5},
		{"linux-source-verifier-replaced", "owner.capture.verify)", "verifyBundledNativeContext)", 5},
		{"linux-session-current-omitted", "s.currentLocked(ctx)", "unrelatedGuard()", 6},
		{"linux-partial-owner-omitted", "s.active = host", "s.active = nil", 6},
		{"linux-session-caller-replaced", "host.startWithVerifier(ctx, s.journal,", "host.startWithVerifier(context.Background(), s.journal,", 6},
		{"linux-predecessor-guard-omitted", "s.selectedPredecessorLocked(ctx, s.predecessor)", "unrelatedPredecessor()", 6},
		{"linux-native-current-omitted", "h.current(ctx)", "unrelatedGuard()", 7},
		{"linux-native-caller-replaced", "startDesktopLinuxNodeProcessWithVerifier(ctx, h.parent,", "startDesktopLinuxNodeProcessWithVerifier(context.Background(), h.parent,", 7},
		{"linux-partial-command-omitted", "h.launch.command = h.process.command", "h.launch.command = nil", 7},
		{"linux-native-postcheck-omitted", "h.runningLocked(ctx)", "unrelatedGuard()", 7},
		{"linux-publication-current-omitted", "a.checkCapturedConnectionOperationLocked(h.operation)", "unrelatedGuard()", 8},
		{"linux-publication-lock-omitted", "desktopnetwork.LockContext(ctx, &a.mu)", "unrelatedGuard()", 8},
		{"local-operation-substituted", "a.nativeMultihopConnectLocalOwned(w, r, operation, sel, driver)", "a.nativeMultihopConnectLocalOwned(w, r, context.Background(), sel, driver)", 9},
		{"local-source-resolver-omitted", "a.resolveNativeMultihopRequestLocked(q)", "unrelatedSelection()", 9},
		{"local-request-context-substituted", "a.beginConnectionOperationContext(r.Context())", "a.beginConnectionOperation()", 9},
		{"local-request-decoder-omitted", "decodeMultihopConnectRequest(http.MaxBytesReader(w, r.Body, 16<<10))", "unrelatedDecoder()", 9},
		{"local-catalog-lock-omitted", "a.mu.Lock()", "unrelatedLock()", 9},
		{"source-ordered-validation-omitted", "q.validateOrdered()", "unrelatedGuard()", 17},
		{"source-middle-revisions-omitted", "required = append(required, node.ID)", "required = nil", 17},
		{"source-revision-guard-omitted", "a.validateDesktopProfileExpectationsLocked(q.desktopProfileExpectations, required, q.ordered())", "unrelatedGuard()", 17},
		{"source-revision-inventory-weakened", "q.desktopProfileExpectations, required, q.ordered()", "q.desktopProfileExpectations, required, false", 17},
		{"source-catalog-alias-substituted", "cloneRouterProfileStore(a.profiles)", "a.profiles", 17},
		{"source-selected-control-substituted", "profileByID(store.Profiles, store.SelectedID)", "profileByID(store.Profiles, q.ExitID)", 17},
		{"source-original-catalog-substituted", "resolveNativeMultihopSelection(control, store.Profiles, q)", "resolveNativeMultihopSelection(control, a.profiles.Profiles, q)", 17},
		{"source-pair-revisions-omitted", "err = a.validateDesktopProfileExpectationsLocked(q.desktopProfileExpectations, []string{selection.Entry.ID, selection.Exit.ID}, false)", "err = nil", 17},
		{"local-operation-guard-omitted", "a.checkCapturedConnectionOperation(operation) != nil ||", "", 0},
		{"foreign-platform-family", "launch.chain != nil && launch.chain.platform != nil", "launch.chain != nil", 10},
		{"chain-platform-source-substitution", "launch.chain.selection.Native != selection.Native", "false", 11},
		{"chain-platform-caller-substitution", "context.WithTimeout(ctx, budget)", "context.WithTimeout(context.Background(), budget)", 11},
		{"chain-platform-start-omitted", "launch.chain.platform.start(startup)", "unrelatedStart()", 11},
		{"chain-platform-current-omitted", "launch.chain.platform.current(ctx)", "unrelatedGuard()", 11},
		{"chain-platform-dns-substituted", "registerActiveDNSRuntimeConfigKind(a, selection.Exit.ID,", "registerActiveDNSRuntimeConfigKind(a, \"foreign\",", 11},
		{"chain-publication-caller-substituted", "a.publishDesktopNodeChainStartLocked(operation, launch, selection)", "a.publishDesktopNodeChainStartLocked(context.Background(), launch, selection)", 12},
		{"imported-publication-dispatch-omitted", "return a.publishDesktopImportedMultihopStartLocked(operation, launch, selection)", "return nil", 12},
		{"chain-start-caller-substituted", "startDesktopOwnedNodeChainLaunch(ctx, operation, a, launch)", "startDesktopOwnedNodeChainLaunch(context.Background(), operation, a, launch)", 13},
		{"imported-start-dispatch-omitted", "return startDesktopOwnedImportedLaunch(ctx, operation, a, launch)", "return nil", 13},
		{"chain-native-family-guard-omitted", "launch.ownedNode.chain != launch.chain ||", "", 14},
		{"chain-native-operation-substituted", "startDesktopOwnedNodeLaunchFor(ctx, operation, a, launch,", "startDesktopOwnedNodeLaunchFor(ctx, ctx, a, launch,", 14},
		{"chain-native-caller-substituted", "owner.host.start(call, a, launch, arguments, environment, directory)", "owner.host.start(context.Background(), a, launch, arguments, environment, directory)", 14},
		{"chain-native-current-omitted", "owner.currentContext(call)", "unrelatedGuard()", 14},
		{"chain-publish-operation-omitted", "a.checkCapturedConnectionOperationLocked(operation)", "unrelatedGuard()", 15},
		{"chain-publish-middle-source-omitted", "!owned.chainSourceCurrentLocked(a)", "false", 15},
		{"chain-publish-protection-substituted", "owned.slot != a.nodeProtection", "false", 15},
		{"chain-publish-child-omitted", "a.cmd = launch.command", "a.cmd = nil", 15},
		{"chain-linux-session-caller-substituted", "owner.session.startWithVerifier(ctx,", "owner.session.startWithVerifier(context.Background(),", 16},
		{"chain-linux-source-verifier-substituted", "owner.capture.platform.verify)", "verifyBundledNativeContext)", 16},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			changed := append([]string(nil), original...)
			if strings.Count(changed[mutation.part], mutation.old) < 1 {
				t.Fatal("mutation lost its actual shipping operation")
			}
			changed[mutation.part] = strings.Replace(changed[mutation.part], mutation.old, mutation.replacement, 1) + "\n// " + mutation.old
			if err := nativeMultihopLaunchGuards(changed); err == nil {
				t.Fatal("broken native launch passed with an obsolete comment marker")
			}
		})
	}
	// Retain the earlier guard while removing the check after ordinary owner
	// publication. It cannot protect either newly launched native branch.
	t.Run("post-publication-guard-omitted", func(t *testing.T) {
		changed := append([]string(nil), original...)
		marker := "if err = a.checkConnectionOperation(); err != nil {"
		if strings.Count(changed[0], marker) != 2 {
			t.Fatal("expected exact prelaunch and post-publication guards")
		}
		index := strings.LastIndex(changed[0], marker)
		changed[0] = changed[0][:index] + strings.Replace(changed[0][index:], marker, "if err = error(nil); err != nil {", 1)
		if err := nativeMultihopLaunchGuards(changed); err == nil {
			t.Fatal("prelaunch guard substituted for post-publication admission")
		}
	})
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
