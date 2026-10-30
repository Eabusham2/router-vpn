//go:build darwin && routervpn_darwin_guardian

package mobiletor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"testing"
	"time"
)

func TestDesktopPFAnchorProbeReferenceOwnership(t *testing.T) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || desktopDarwinTestFixture.Nonce == "" || desktopDarwinPFTestScope == "" {
		t.Fatal("actual isolated native PF reference fixture is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	owned := make(map[string]bool)
	command := func(ctx context.Context, arguments ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, "/sbin/pfctl", arguments...)
		cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}
		cmd.Dir = "/"
		return cmd.CombinedOutput()
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		for token, retained := range owned {
			if retained {
				if _, err := command(cleanup, "-X", token); err != nil {
					t.Error("native reference fixture retained an exact owned enable reference", err)
				}
			}
		}
	})
	acquire := func() string {
		t.Helper()
		output, err := command(ctx, "-E")
		match := regexp.MustCompile(`(?im)^Token\s*:\s*([0-9]+)\s*$`).FindSubmatch(output)
		if err != nil || len(match) != 2 {
			t.Fatal("native reference fixture did not capture its newly owned token", err)
		}
		token := string(match[1])
		if _, err := desktopDarwinPFReferenceToken(token); err != nil || owned[token] {
			t.Fatal("native reference fixture received an invalid or duplicate owner", err)
		}
		owned[token] = true
		return token
	}
	read := func(token string) bool {
		t.Helper()
		raw, err := EncodeDesktopDarwinPFReferenceRequest(DesktopDarwinPFReferenceRequest{Schema: 1, Token: token})
		if err != nil {
			t.Fatal(err)
		}
		body, err := RunDesktopDarwinPFReference(ctx, raw)
		var result DesktopDarwinPFReferenceResult
		if err != nil || json.Unmarshal(body, &result) != nil || result.Schema != 1 || result.Token != token {
			t.Fatal("native reference inspection lost its exact requested identity", err)
		}
		return result.Present
	}
	first, other := acquire(), acquire()
	if !read(first) || !read(other) {
		t.Fatal("native reference inspection reported an owned live token absent")
	}
	if _, err := command(ctx, "-X", first); err != nil {
		t.Fatal("native reference fixture could not release its exact first owner", err)
	}
	owned[first] = false
	if read(first) || !read(other) {
		t.Fatal("native reference inspection lost exact retirement or another retained owner")
	}
	raw, _ := EncodeDesktopDarwinPFReferenceRequest(DesktopDarwinPFReferenceRequest{Schema: 1, Token: other})
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if body, err := RunDesktopDarwinPFReference(cancelled, raw); !errors.Is(err, context.Canceled) || len(body) != 0 || !read(other) {
		t.Fatal("cancelled native reference inspection changed or fabricated its retained owner", err)
	}
}
