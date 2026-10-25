package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/multihoprelay"
	"router-vpn/internal/nativeopenvpn"
)

func testOpenVPNRemoteProcess(t *testing.T) (*relayProcess, multihoprelay.NativeOpenVPNReceipt) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	capture := multihoprelay.NativeOpenVPNCapture{Schema: 1, SessionID: strings.Repeat("a", 32), ConfigSHA256: strings.Repeat("b", 64), ExternalFingerprint: strings.Repeat("c", 64), ExternalAttempt: strings.Repeat("d", 32)}
	p := &relayProcess{root: root, dir: dir, capture: capture, done: make(chan struct{})}
	r := multihoprelay.NativeOpenVPNReceipt{Capture: capture, RequestID: strings.Repeat("e", 32), Remote: nativeopenvpn.RemoteReceipt{Remote: nativeopenvpn.Remote{Host: "203.0.113.21", Port: 443, Network: "tcp"}, Generation: 3, ConnectedAt: time.Now().UnixMilli()}, HeartbeatAt: time.Now().UnixMilli()}
	return p, r
}

// The child answers the fresh private query, rather than handing the parent a
// recently written file. Mutations happen after receipt of the actual nonce.
func testOpenVPNRemoteQuery(t *testing.T, p *relayProcess, base multihoprelay.NativeOpenVPNReceipt, mutate func(*multihoprelay.NativeOpenVPNReceipt), mode os.FileMode) (nativeopenvpn.RemoteReceipt, error, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	responded := make(chan string, 1)
	go func() {
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			file, err := p.root.Open("openvpn-query.json")
			if err == nil {
				var query multihoprelay.NativeOpenVPNQuery
				err = json.NewDecoder(file).Decode(&query)
				_ = file.Close()
				if err == nil && query.Validate(p.capture) == nil {
					value := base
					value.RequestID = query.RequestID
					if mutate != nil {
						mutate(&value)
					}
					raw, _ := json.Marshal(value)
					file, err := p.root.OpenFile("response.tmp", os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
					if err == nil {
						_, err = file.Write(raw)
						_ = file.Close()
						if err == nil {
							err = renameRelayRootFile(p.root, "response.tmp", "openvpn-remote.json")
						}
					}
					if err != nil {
						responded <- "write-failed"
					} else {
						responded <- query.RequestID
					}
					return
				}
			}
			select {
			case <-ctx.Done():
				responded <- "missing-query"
				return
			case <-ticker.C:
			}
		}
	}()
	receipt, err := p.OpenVPNRemote(ctx)
	return receipt, err, <-responded
}

func TestOpenVPNProcessReceiptRequiresFreshExactLivePrivateChild(t *testing.T) {
	p, r := testOpenVPNRemoteProcess(t)
	path := filepath.Join(p.dir, "openvpn-remote.json")
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		actual, err, nonce := testOpenVPNRemoteQuery(t, p, r, nil, 0600)
		if err != nil || actual != r.Remote || seen[nonce] || len(nonce) != 32 {
			t.Fatal("fresh owned connected receipt rejected or nonce reused", err)
		}
		seen[nonce] = true
	}
	for name, mutate := range map[string]func(*multihoprelay.NativeOpenVPNReceipt){
		"session":   func(r *multihoprelay.NativeOpenVPNReceipt) { r.Capture.SessionID = strings.Repeat("f", 32) },
		"source":    func(r *multihoprelay.NativeOpenVPNReceipt) { r.Capture.ConfigSHA256 = strings.Repeat("f", 64) },
		"attempt":   func(r *multihoprelay.NativeOpenVPNReceipt) { r.Capture.ExternalAttempt = strings.Repeat("f", 32) },
		"old query": func(r *multihoprelay.NativeOpenVPNReceipt) { r.RequestID = strings.Repeat("f", 32) },
		"stale": func(r *multihoprelay.NativeOpenVPNReceipt) {
			r.HeartbeatAt = time.Now().Add(-4 * time.Second).UnixMilli()
		},
		"future": func(r *multihoprelay.NativeOpenVPNReceipt) {
			r.HeartbeatAt = time.Now().Add(2 * time.Second).UnixMilli()
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err, _ := testOpenVPNRemoteQuery(t, p, r, mutate, 0600); err == nil {
				t.Fatal("stale or foreign receipt accepted")
			}
		})
	}
	if _, err, _ := testOpenVPNRemoteQuery(t, p, r, nil, 0644); err == nil {
		t.Fatal("public receipt accepted")
	}
	// A valid heartbeat from a previous request must never answer a new read.
	raw, _ := json.Marshal(r)
	if os.WriteFile(path, raw, 0600) != nil || os.Chmod(path, 0600) != nil {
		t.Fatal("cached fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := p.OpenVPNRemote(ctx); err == nil {
		t.Fatal("cached receipt answered a fresh query")
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := p.OpenVPNRemote(cancelled); err == nil {
		t.Fatal("cancelled receipt read accepted")
	}
	foreign := filepath.Join(t.TempDir(), "foreign")
	if os.WriteFile(foreign, raw, 0600) != nil || os.Remove(path) != nil || os.Symlink(foreign, path) != nil {
		t.Fatal("linked fixture")
	}
	if _, err := p.readOpenVPNReceiptLocked(); err == nil {
		t.Fatal("linked receipt accepted")
	}
	if os.Remove(path) != nil {
		t.Fatal("unlink")
	}
	close(p.done)
	if _, err := p.OpenVPNRemote(context.Background()); err == nil {
		t.Fatal("dead process receipt accepted")
	}
	if err := p.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(p.dir); !os.IsNotExist(err) {
		t.Fatal("owned private directory survived cleanup")
	}
	if os.Mkdir(p.dir, 0700) != nil || os.WriteFile(path, []byte("replacement"), 0600) != nil {
		t.Fatal("replacement fixture")
	}
	if err := p.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(path); err != nil || string(raw) != "replacement" {
		t.Fatal("repeated old cleanup removed replacement")
	}
}

func TestOpenVPNProcessDirectoryReplacementIsNotAdoptedOrDeleted(t *testing.T) {
	p, r := testOpenVPNRemoteProcess(t)
	old := p.dir + "-retained"
	if os.Rename(p.dir, old) != nil || os.Mkdir(p.dir, 0700) != nil || os.WriteFile(filepath.Join(p.dir, "foreign"), []byte("retained"), 0600) != nil {
		t.Fatal("replacement fixture")
	}
	t.Cleanup(func() { _ = os.RemoveAll(old) })
	actual, err, _ := testOpenVPNRemoteQuery(t, p, r, nil, 0600)
	if err != nil || actual != r.Remote {
		t.Fatal("runtime adopted replacement path", err)
	}
	close(p.done)
	if p.Stop(context.Background()) == nil {
		t.Fatal("ambiguous directory removal reported success")
	}
	if data, err := os.ReadFile(filepath.Join(p.dir, "foreign")); err != nil || string(data) != "retained" {
		t.Fatal("replacement workspace deleted")
	}
}
