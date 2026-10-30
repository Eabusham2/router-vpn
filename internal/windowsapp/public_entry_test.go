package windowsapp

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// This source check binds the small public wrappers to the separately executed
// native Main/Session tests. It is not a substitute for running the packaged
// binaries, interactive UAC or the physical device acceptance cases.
func checkPublicWindowsEntry(source []byte, portable bool) error {
	if !strings.HasPrefix(string(source), "//go:build windows\n") {
		return errors.New("public Windows entry lost its explicit platform boundary")
	}
	file, err := parser.ParseFile(token.NewFileSet(), "entry.go", source, 0)
	if err != nil || file.Name.Name != "main" || len(file.Decls) != 2 || len(file.Imports) != 2 {
		return errors.New("public Windows entry is not its fixed native wrapper")
	}
	wanted := map[string]bool{"os": true, "router-vpn/internal/windowsapp": true}
	for _, spec := range file.Imports {
		name, err := strconv.Unquote(spec.Path.Value)
		if err != nil || spec.Name != nil || !wanted[name] {
			return errors.New("public Windows entry changed its captured implementation import")
		}
		delete(wanted, name)
	}
	if len(wanted) != 0 {
		return errors.New("public Windows entry omitted its native owner")
	}
	main, ok := file.Decls[1].(*ast.FuncDecl)
	if !ok || main.Name.Name != "main" || main.Recv != nil || main.Type.TypeParams != nil ||
		main.Type.Results != nil || len(main.Type.Params.List) != 0 || main.Body == nil || len(main.Body.List) != 1 {
		return errors.New("public Windows entry added an alternate lifetime")
	}
	statement, ok := main.Body.List[0].(*ast.ExprStmt)
	if !ok {
		return errors.New("public Windows entry did not wait for its native result")
	}
	call := func(value ast.Expr, packageName, name string) (*ast.CallExpr, bool) {
		expression, ok := value.(*ast.CallExpr)
		if !ok || len(expression.Args) != 1 || expression.Ellipsis.IsValid() {
			return nil, false
		}
		selector, ok := expression.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != name {
			return nil, false
		}
		owner, ok := selector.X.(*ast.Ident)
		return expression, ok && owner.Name == packageName
	}
	exit, ok := call(statement.X, "os", "Exit")
	if !ok {
		return errors.New("public Windows entry did not return its checked native exit")
	}
	entry, ok := call(exit.Args[0], "windowsapp", "Main")
	if !ok {
		return errors.New("public Windows entry bypassed the owned Session")
	}
	choice, ok := entry.Args[0].(*ast.Ident)
	if !ok || choice.Name != strconv.FormatBool(portable) {
		return errors.New("public Windows entry changed its installed or Portable authority")
	}
	return nil
}

func TestWindowsPublicEntriesUseOwnedMain(t *testing.T) {
	for name, portable := range map[string]bool{
		"cmd/windows-app-launcher/main.go":      false,
		"cmd/portable-bootstrap/main.go":        true,
		"cmd/portable-launcher/main_windows.go": true,
	} {
		t.Run(name, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(name)))
			if err != nil || checkPublicWindowsEntry(body, portable) != nil {
				t.Fatal("public package entry escaped its native owned Session", err)
			}
			for label, broken := range map[string]string{
				"wrong-layout":     strings.Replace(string(body), "Main("+strconv.FormatBool(portable)+")", "Main("+strconv.FormatBool(!portable)+")", 1),
				"legacy-call":      strings.Replace(string(body), "windowsapp.Main(", "windowsapp.LegacyMain(", 1),
				"discarded-status": strings.Replace(string(body), "os.Exit(", "os.Getenv(", 1),
				"unjoined-owner":   strings.Replace(string(body), "\tos.Exit(", "\tgo windowsapp.Main(true)\n\tos.Exit(", 1),
			} {
				if checkPublicWindowsEntry([]byte(broken), portable) == nil {
					t.Fatal("public entry admitted an alternate authority or lifetime", label)
				}
			}
		})
	}
}
