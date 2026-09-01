package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestValidSHA(t *testing.T) {
	good := "0123456789abcdef0123456789abcdef01234567"
	if !validSHA(good) {
		t.Fatal("valid full SHA rejected")
	}
	for _, bad := range []string{"", "short", "0123456789ABCDEF0123456789ABCDEF01234567", good + "0", good[:39] + "g"} {
		if validSHA(bad) {
			t.Fatalf("invalid SHA accepted: %q", bad)
		}
	}
}

func TestEnvDurationBounds(t *testing.T) {
	t.Setenv("ROUTER_VPN_TEST_DURATION", "10m")
	if got := envDuration("ROUTER_VPN_TEST_DURATION", time.Hour, 5*time.Minute, 24*time.Hour); got != 10*time.Minute {
		t.Fatalf("got %s", got)
	}
	t.Setenv("ROUTER_VPN_TEST_DURATION", "30s")
	if got := envDuration("ROUTER_VPN_TEST_DURATION", time.Hour, 5*time.Minute, 24*time.Hour); got != time.Hour {
		t.Fatalf("out-of-range duration did not fail closed: %s", got)
	}
}

func TestReadPrivateToken(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX private mode contract")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	token := "0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readPrivateToken(path)
	if err != nil || got != token {
		t.Fatalf("private token read failed: got=%q err=%v", got, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateToken(path); err == nil {
		t.Fatal("broad token permissions were accepted")
	}
}

func TestReadPrivateTokenRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX symlink contract")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "token")
	if err := os.WriteFile(target, []byte("0123456789abcdef0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateToken(link); err == nil {
		t.Fatal("symlink token was accepted")
	}
}
