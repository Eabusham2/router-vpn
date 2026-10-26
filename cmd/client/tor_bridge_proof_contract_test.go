package main

import (
	"bytes"
	"errors"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// Follow the shipping helpers, ignoring comments and string literals. Actual
// handler/filesystem tests separately exercise proof failure, durable rollback,
// cancelled operations and the final native owner; this is the source gate that
// used to require a retired inline save after Connected.
func torControllerProofContract(route, persistence []byte) error {
	files := token.NewFileSet()
	methods := map[string]*ast.FuncDecl{}
	for _, source := range [][]byte{route, persistence} {
		file, err := parser.ParseFile(files, "", source, 0)
		if err != nil {
			return err
		}
		for _, declaration := range file.Decls {
			if method, ok := declaration.(*ast.FuncDecl); ok {
				methods[method.Name.Name] = method
			}
		}
	}
	text := func(node ast.Node) string {
		var out bytes.Buffer
		_ = format.Node(&out, files, node)
		return out.String()
	}
	calls := func(method *ast.FuncDecl, name string) []token.Pos {
		var found []token.Pos
		if method != nil {
			ast.Inspect(method.Body, func(node ast.Node) bool {
				if call, ok := node.(*ast.CallExpr); ok && text(call.Fun) == name {
					found = append(found, call.Pos())
				}
				return true
			})
		}
		return found
	}
	connected := func(method *ast.FuncDecl) []token.Pos {
		var found []token.Pos
		if method != nil {
			ast.Inspect(method.Body, func(node ast.Node) bool {
				if assignment, ok := node.(*ast.AssignStmt); ok {
					for index, left := range assignment.Lhs {
						if text(left) == "a.state.Connected" && index < len(assignment.Rhs) && text(assignment.Rhs[index]) == "true" {
							found = append(found, assignment.Pos())
						}
					}
				}
				return true
			})
		}
		return found
	}
	ordered := func(groups ...[]token.Pos) bool {
		var previous token.Pos
		for _, group := range groups {
			if len(group) != 1 || group[0] <= previous {
				return false
			}
			previous = group[0]
		}
		return true
	}
	controller, save, adopt := methods["torBridgeConnectSelectionOwned"], methods["commitDesktopTorChoice"], methods["adopt"]
	if !ordered(calls(controller, "a.proveTorBridgeExit"), calls(controller, "a.commitDesktopTorChoice"), calls(controller, "saved.adopt"), calls(controller, "a.monitorDesktopTorRuntime")) || len(connected(controller)) != 0 {
		return errors.New("Tor controller must prove, save and adopt the same runtime before monitoring; Connected belongs to final adoption")
	}
	if !ordered(calls(save, "a.readDesktopTorProof"), calls(save, "a.persistProfilesLocked"), calls(save, "launch.tor.committedChoice.Store")) || len(connected(save)) != 0 {
		return errors.New("Tor choice must retain fresh proof and a successful durable save before binding its new source")
	}
	rollback := false
	ast.Inspect(save.Body, func(node ast.Node) bool {
		branch, ok := node.(*ast.IfStmt)
		if ok && text(branch.Cond) == "err != nil" && branch.Init != nil && strings.Contains(text(branch.Init), "a.persistProfilesLocked()") {
			for _, statement := range branch.Body.List {
				if expression, ok := statement.(*ast.ExprStmt); ok && text(expression.X) == "a.rollbackProfilesLocked(previous)" {
					rollback = true
				}
			}
		}
		return true
	})
	if !rollback {
		return errors.New("Tor save failure must restore the captured in-memory store")
	}
	proofs, owners := calls(adopt, "a.readDesktopTorProof"), calls(adopt, "saved.currentLocked")
	if len(proofs) != 2 || len(owners) != 2 || !ordered(proofs[:1], owners[:1], calls(adopt, "a.saveStartupSelection"), proofs[1:], owners[1:], connected(adopt)) {
		return errors.New("Tor final Connected requires fresh proof and current ownership after Startup Last is saved")
	}
	return nil
}

func TestTorBridgeControllerProofContractRejectsRetiredOrdering(t *testing.T) {
	route, err := os.ReadFile("tor_bridge_routes.go")
	if err != nil {
		t.Fatal(err)
	}
	persistence, err := os.ReadFile("desktop_tor_persistence.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct {
		name, old, replacement string
		route                  bool
	}{
		{"ignored-proof", "actualIP, proofErr := a.proveTorBridgeExit()", "actualIP, proofErr := unrelatedProof()", true},
		{"early-connected", "actualIP, proofErr := a.proveTorBridgeExit()", "a.state.Connected = true\nactualIP, proofErr := a.proveTorBridgeExit()", true},
		{"ignored-adoption", "retainedProof, err = saved.adopt(a)", "retainedProof, err = unrelatedAdopt(a)", true},
		{"ignored-save", "if err := a.persistProfilesLocked(); err != nil {", "if err := unrelatedSave(); err != nil {", false},
		{"ignored-save-error", "if err := a.persistProfilesLocked(); err != nil {", "if err := a.persistProfilesLocked(); false {", false},
		{"ignored-rollback", "a.rollbackProfilesLocked(previous)", "unrelatedRollback(previous)", false},
		{"stale-adoption-proof", "proof, err := a.readDesktopTorProof(saved.launch)", "proof, err := unrelatedProof(saved.launch)", false},
	} {
		t.Run(change.name, func(t *testing.T) {
			r, p := string(route), string(persistence)
			target := &p
			if change.route {
				target = &r
			}
			if strings.Count(*target, change.old) != 1 {
				t.Fatal("mutation no longer names one shipping operation")
			}
			*target = strings.Replace(*target, change.old, change.replacement+" // "+change.old, 1)
			if torControllerProofContract([]byte(r), []byte(p)) == nil {
				t.Fatal("broken proof/persistence contract was accepted")
			}
		})
	}
}
