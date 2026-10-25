package controllerprocess

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestControllerProcessOwnershipToken(t *testing.T) {
	first, err := NewToken()
	if err != nil || len(first) != 32 || strings.Trim(first, "0123456789abcdef") != "" {
		t.Fatal("invalid launch identity", err)
	}
	second, err := NewToken()
	if err != nil || second == first {
		t.Fatal("controller launches share ownership")
	}
	env := Environment([]string{"HOMEVPN_CONTROLLER_OWNER=old", "homevpn_controller_owner=other", "PATH=preserved"}, first)
	if len(env) != 2 || env[0] != "PATH=preserved" || env[1] != "HOMEVPN_CONTROLLER_OWNER="+first {
		t.Fatal("inherited controller ownership was retained", env)
	}
	if err := Stop(&exec.Cmd{}); err == nil {
		t.Fatal("unowned controller was accepted for shutdown")
	}
}

func TestControllerProcessCheckedHTTPReceipt(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	valid := `{"schema":1,"process_id":1234,"owner_token":"` + token + `","closed":true}`
	cases := []struct {
		name string
		body string
		code int
		ok   bool
	}{
		{"closed", valid, 200, true},
		{"pending", valid, 503, false},
		{"wrong-process", strings.Replace(valid, "1234", "5678", 1), 200, false},
		{"wrong-owner", strings.Replace(valid, token, strings.Repeat("a", 32), 1), 200, false},
		{"not-closed", strings.Replace(valid, "true", "false", 1), 200, false},
		{"null-closed", strings.Replace(valid, "true", "null", 1), 200, false},
		{"duplicate", strings.Replace(valid, `"schema":1`, `"schema":2,"schema":1`, 1), 200, false},
		{"unknown", strings.Replace(valid, `"closed":true`, `"closed":true,"other":1`, 1), 200, false},
		{"trailing", valid + `{}`, 200, false},
		{"oversize", valid + strings.Repeat(" ", 1024), 200, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" || r.URL.Path != "/api/controller/shutdown" {
					t.Error("wrong shipping shutdown request")
				}
				var request map[string]any
				if json.NewDecoder(r.Body).Decode(&request) != nil || len(request) != 3 || request["schema"] != float64(1) || request["process_id"] != float64(1234) || request["owner_token"] != token {
					t.Error("shutdown did not carry its exact captured identity")
				}
				w.WriteHeader(tc.code)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			err := requestShutdown(context.Background(), server.Client(), server.URL+"/api/controller/shutdown", 1234, token)
			if (err == nil) != tc.ok {
				t.Fatalf("receipt accepted=%v expected=%v: %v", err == nil, tc.ok, err)
			}
		})
	}
}

func TestControllerProcessChildProcess(t *testing.T) {
	if os.Getenv("ROUTERVPN_SHUTDOWN_TEST_CHILD") != "1" {
		return
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}

func testController(t *testing.T) (*Owner, func()) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestControllerProcessChildProcess$")
	cmd.Env = append(os.Environ(), "ROUTERVPN_SHUTDOWN_TEST_CHILD=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	owner := Track(cmd, strings.Repeat("a", 32))
	closeChild := func() { _ = stdin.Close() }
	t.Cleanup(func() {
		closeChild()
		select {
		case <-owner.done:
		case <-time.After(10 * time.Second):
			t.Error("fixture child did not exit after releasing stdin")
		}
		owners.Delete(cmd)
	})
	return owner, closeChild
}

func TestControllerProcessPendingCleanupRetainsOwnedProcess(t *testing.T) {
	owner, closeChild := testController(t)
	pending := make(chan struct{}, 1)
	acknowledge := make(chan struct{})
	done := make(chan error, 1)
	var calls atomic.Int32
	go func() {
		done <- waitForShutdown(owner, func(_ context.Context, pid int, token string) error {
			if pid != owner.command.Process.Pid || token != owner.token {
				return errors.New("replacement process identity was substituted")
			}
			if calls.Add(1) == 1 {
				return errors.New("native rollback pending")
			}
			<-acknowledge
			return nil
		}, func() { pending <- struct{}{} })
	}()
	select {
	case <-pending:
	case <-time.After(5 * time.Second):
		t.Fatal("pending cleanup was not surfaced")
	}
	select {
	case <-owner.done:
		t.Fatal("launcher killed the controller before native cleanup")
	case err := <-done:
		t.Fatal("launcher returned before checked cleanup", err)
	default:
	}
	close(acknowledge)
	// A successful HTTP response alone is insufficient: the same process must
	// finish its HTTP drain and exit, without a second Wait or forced kill.
	select {
	case err := <-done:
		t.Fatal("launcher returned before its acknowledged child exited", err)
	case <-time.After(1200 * time.Millisecond):
	}
	closeChild()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("checked child exit was not joined")
	}
}

func TestControllerProcessDeathIsNotCleanupEvidence(t *testing.T) {
	owner, closeChild := testController(t)
	closeChild()
	<-owner.done
	err := waitForShutdown(owner, func(context.Context, int, string) error { return errors.New("no receipt") }, nil)
	if err == nil || !strings.Contains(err.Error(), "without a checked cleanup receipt") {
		t.Fatal("abrupt/unacknowledged exit was accepted", err)
	}
}

func TestControllerProcessExitDoesNotCancelFlushedReceipt(t *testing.T) {
	owner, closeChild := testController(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Publish the response in two parts, with the process exiting between
		// them. Cancel-on-Wait loses the valid receipt's trailing bytes.
		_, _ = io.WriteString(w, `{"schema":1,`)
		w.(http.Flusher).Flush()
		closeChild()
		<-owner.done
		_, _ = fmt.Fprintf(w, `"process_id":%d,"owner_token":%q,"closed":true}`, owner.command.Process.Pid, owner.token)
	}))
	defer server.Close()
	err := waitForShutdown(owner, func(ctx context.Context, pid int, token string) error {
		return requestShutdown(ctx, server.Client(), server.URL, pid, token)
	}, nil)
	if err != nil {
		t.Fatal("valid receipt lost when process exit preceded its final bytes", err)
	}
}
