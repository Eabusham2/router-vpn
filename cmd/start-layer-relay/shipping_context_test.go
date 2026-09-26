package main

import (
	"context"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Reconstruct the exact COPY inputs of the relay's Docker build stage and
// compile only that context. A full-repository build cannot catch missing
// package COPY declarations in a multi-stage production image.
func TestProductionRelayCompilesFromItsActualContainerContext(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile(filepath.Join(root, "server", "aux-proxies", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	stage := strings.SplitN(string(doc), "\nFROM ", 2)[0]
	if !strings.Contains(stage, " AS start-layer-build") {
		t.Fatal("relay build stage changed")
	}
	temp := t.TempDir()
	copyFile := func(source, target string) error {
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return err
		}
		input, err := os.Open(source)
		if err != nil {
			return err
		}
		defer input.Close()
		output, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(output, input)
		closeErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	}
	copies := 0
	for _, line := range strings.Split(stage, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "COPY" {
			continue
		}
		if len(fields) != 3 || strings.HasPrefix(fields[1], "--") {
			t.Fatal("unreviewed relay Docker COPY form")
		}
		source, target := filepath.Join(root, filepath.FromSlash(fields[1])), filepath.Join(temp, filepath.FromSlash(fields[2]))
		if !strings.HasPrefix(source, root+string(filepath.Separator)) || (target != temp && !strings.HasPrefix(target, temp+string(filepath.Separator))) {
			t.Fatal("COPY escapes owned source context")
		}
		info, err := os.Stat(source)
		if err != nil {
			t.Fatal(err)
		}
		if !info.IsDir() {
			if strings.HasSuffix(fields[2], "/") {
				target = filepath.Join(target, filepath.Base(source))
			}
			if err := copyFile(source, target); err != nil {
				t.Fatal(err)
			}
		} else {
			err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if entry.Type()&os.ModeSymlink != 0 {
					t.Fatal("build input contains a symlink")
				}
				relative, err := filepath.Rel(source, path)
				if err != nil {
					return err
				}
				if entry.IsDir() {
					return os.MkdirAll(filepath.Join(target, relative), 0700)
				}
				return copyFile(path, filepath.Join(target, relative))
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		copies++
	}
	if copies < 3 {
		t.Fatal("relay source dependency omitted from container context")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", filepath.Join(temp, "relay-test-binary"), "./cmd/start-layer-relay")
	cmd.Dir = temp
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOWORK=off")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("actual container COPY inputs cannot compile relay: %v\n%s", err, output)
	}
}
