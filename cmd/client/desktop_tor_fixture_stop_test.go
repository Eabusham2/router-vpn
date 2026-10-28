package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// The public Disconnect handler owns operationMu throughout teardown. Fixture
// callers of the internal hold-protection variant must preserve that same
// transaction, so the live runtime monitor cannot race stop and Startup Last.
func stopDesktopTorLifecycleFixture(t *testing.T, a *app) {
	t.Helper()
	a.operationMu.Lock()
	defer a.operationMu.Unlock()
	if err := a.stopModeWithIntent(true); err != nil {
		t.Fatal(err)
	}
}

// The real native reader ignores an incomplete O_EXCL input until it contains
// the exact three-field request for its captured owner. An unparseable prefix
// is not a native crash, and a complete foreign input is not an owned Stop.
func desktopTorFixtureStopRequested(raw []byte, session, source string) bool {
	var request struct {
		Schema       int    `json:"schema"`
		SessionID    string `json:"session_id"`
		SourceSHA256 string `json:"source_sha256"`
	}
	return len(raw) <= 1024 && decodeRelayControlJSON(raw, &request) == nil &&
		request.Schema == 1 && request.SessionID == session && request.SourceSHA256 == source
}

func TestDesktopTorFixtureStopDecoderRejectsPartialForeignAndAmbiguous(t *testing.T) {
	session, source := strings.Repeat("a", 32), strings.Repeat("b", 64)
	raw, err := json.Marshal(desktopExternalStop{Schema: 1, SessionID: session, SourceSHA256: source})
	if err != nil || !desktopTorFixtureStopRequested(raw, session, source) {
		t.Fatal("complete captured Stop was rejected", err)
	}
	for length := 0; length < len(raw); length++ {
		if desktopTorFixtureStopRequested(raw[:length], session, source) {
			t.Fatal("incomplete Stop prefix was accepted", length)
		}
	}
	for _, invalid := range []string{
		strings.Replace(string(raw), `"schema":1`, `"schema":2`, 1),
		strings.Replace(string(raw), session, strings.Repeat("c", 32), 1),
		strings.Replace(string(raw), source, strings.Repeat("c", 64), 1),
		strings.Replace(string(raw), `"schema":1`, `"schema":1,"schema":1`, 1),
		strings.TrimSuffix(string(raw), "}") + `,"unknown":true}`,
		strings.TrimSuffix(string(raw), "}") + `,"closed":false}`,
		strings.TrimSuffix(string(raw), "}") + `,"closed":true}`,
		string(raw) + `{}`,
		`null`, `[]`, `{}`,
		strings.Repeat(" ", 1024) + string(raw),
	} {
		if desktopTorFixtureStopRequested([]byte(invalid), session, source) {
			t.Fatal("complete foreign or ambiguous Stop was accepted", invalid)
		}
	}
}

func waitDesktopTorFixturePastStopRead(t *testing.T, ctx context.Context, a *app, launch *desktopNodeLaunch) {
	t.Helper()
	proof, err := a.readDesktopTorProof(launch)
	if err != nil {
		t.Fatal(err)
	}
	// This child's loop publishes before reading Stop. Two actual newer
	// heartbeats cross the input read even if the first publication was already
	// in flight when the parent finished its write. No scheduling sleep stands
	// in for that observed protocol progress.
	for updates := 0; updates < 2; {
		select {
		case <-desktopNodeProcessDone(launch):
			t.Fatal("incomplete or invalid Stop killed the captured child")
		case <-ctx.Done():
			t.Fatal("captured child stopped progressing on an unowned Stop", ctx.Err())
		case <-time.After(5 * time.Millisecond):
		}
		next, err := a.readDesktopTorProof(launch)
		if err != nil {
			t.Fatal("incomplete or invalid Stop lost captured proof", err)
		}
		if next.HeartbeatAt > proof.HeartbeatAt {
			proof = next
			updates++
		}
	}
	if desktopNodeProcessExited(launch) {
		t.Fatal("unowned Stop exited after its last publication")
	}
	if _, err := launch.directoryRoot.Lstat("stopped.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unowned Stop fabricated a closed receipt", err)
	}
}

func TestDesktopTorFixtureStopWaitsForCompleteOwnedInput(t *testing.T) {
	for _, kind := range []string{"partial", "session", "source", "schema", "unknown", "closed", "duplicate", "trailing"} {
		t.Run(kind, func(t *testing.T) {
			a, launch, _ := desktopTorRunningFixture(t, "proof")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := a.waitDesktopTorProof(ctx, launch); err != nil {
				t.Fatal(err)
			}
			owner := launch.tor.expected
			raw, _ := json.Marshal(desktopExternalStop{Schema: 1, SessionID: owner.SessionID, SourceSHA256: owner.SourceSHA256})
			input := string(raw)
			switch kind {
			case "partial":
				input = string(raw[:len(raw)/2])
			case "session":
				input = strings.Replace(input, owner.SessionID, strings.Repeat("e", 32), 1)
			case "source":
				input = strings.Replace(input, owner.SourceSHA256, strings.Repeat("e", 64), 1)
			case "schema":
				input = strings.Replace(input, `"schema":1`, `"schema":2`, 1)
			case "unknown":
				input = strings.TrimSuffix(input, "}") + `,"unknown":true}`
			case "closed":
				input = strings.TrimSuffix(input, "}") + `,"closed":false}`
			case "duplicate":
				input = strings.Replace(input, `"schema":1`, `"schema":1,"schema":1`, 1)
			case "trailing":
				input += `{}`
			}
			file, err := launch.directoryRoot.OpenFile("stop.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if _, err := file.WriteString(input); err != nil {
				t.Fatal(err)
			}
			if err := file.Sync(); err != nil {
				t.Fatal(err)
			}
			waitDesktopTorFixturePastStopRead(t, ctx, a, launch)
			if kind == "partial" {
				if _, err := file.Write(raw[len(raw)/2:]); err != nil {
					t.Fatal(err)
				}
				if err := file.Sync(); err != nil {
					t.Fatal(err)
				}
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			if kind != "partial" {
				if err := requestDesktopTorStop(ctx, a, launch, launch.command); err == nil {
					t.Fatal("controller reused a complete foreign Stop input")
				}
				retained, err := readDesktopRuntimeFile(launch, "stop.json", 1024)
				if err != nil || string(retained) != input || desktopNodeProcessExited(launch) {
					t.Fatal("rejected Stop changed the input or retired its live owner", err)
				}
				if err := launch.directoryRoot.Remove("stop.json"); err != nil {
					t.Fatal(err)
				}
			}
			if err := requestDesktopTorStop(ctx, a, launch, launch.command); err != nil {
				t.Fatal("complete matching Stop did not finish actual checked drain", err)
			}
			if !desktopNodeProcessExited(launch) || !launch.command.ProcessState.Success() {
				t.Fatal("complete matching Stop did not join a successful child")
			}
		})
	}
}
