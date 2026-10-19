package mobiletor

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func predecessorProfile() map[string]any {
	return map[string]any{"id": "captured-entry", "node_kind": "router-vpn", "node_proof_id": strings.Repeat("a", 64), "router_api": "http://10.77.0.1:8787", "api_token": "private-entry-secret"}
}

func predecessorJSON(value any) string { data, _ := json.Marshal(value); return string(data) }

func TestPredecessorProofCapturesExactPrivateOriginAndAuthentication(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://unowned.invalid:9")
	for _, address := range []string{"10.77.0.1:8787", "[fd77::1]:8787"} {
		t.Run(address, func(t *testing.T) {
			profile := predecessorProfile()
			profile["router_api"] = "http://" + address + "/"
			owned, err := NewPredecessorProof(predecessorJSON(profile))
			if err != nil {
				t.Fatal(err)
			}
			profile["api_token"] = "changed-after-capture"
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			done := make(chan error, 1)
			go func() {
				request, err := http.ReadRequest(bufio.NewReader(server))
				if err == nil && (request.Method != "GET" || request.URL.String() != "/health" || request.Host != address || request.Header.Get("Authorization") != "Bearer private-entry-secret" || request.Header.Get("Cache-Control") != "no-store" || request.Header.Get("Accept-Encoding") != "identity") {
					err = errors.New("captured private proof request changed")
				}
				if err == nil {
					body := `{"ok":true,"node_id":"` + strings.Repeat("a", 64) + `","proof":"router-vpn-private-agent-v1"}`
					_, err = fmt.Fprintf(server, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
				}
				done <- err
			}()
			err = owned.Prove(context.Background(), func(ctx context.Context, network, destination string) (net.Conn, error) {
				if network != "tcp" || destination != address || ctx.Err() != nil {
					t.Error("dial escaped captured private TCP origin")
				}
				return client, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPredecessorProofRejectsUnsafeProfileBeforeDial(t *testing.T) {
	mutations := map[string]func(map[string]any){
		"external":               func(p map[string]any) { p["node_kind"] = "external" },
		"missing-node":           func(p map[string]any) { delete(p, "node_proof_id") },
		"bad-node":               func(p map[string]any) { p["node_proof_id"] = strings.Repeat("A", 64) },
		"typed-id":               func(p map[string]any) { p["id"] = true },
		"empty-token":            func(p map[string]any) { p["api_token"] = "" },
		"token-header-injection": func(p map[string]any) { p["api_token"] = "secret\r\nX-Other: yes" },
		"token-whitespace":       func(p map[string]any) { p["api_token"] = " secret" },
		"token-oversize":         func(p map[string]any) { p["api_token"] = strings.Repeat("s", 4097) },
	}
	for _, target := range []string{"https://10.77.0.1:8787", "http://public.invalid:8787", "http://8.8.8.8:8787", "http://127.0.0.1:8787", "http://[::1]:8787", "http://[::ffff:10.77.0.1]:8787", "http://10.77.0.1", "http://10.77.0.1:0", "http://10.77.0.1:65536", "http://10.77.0.1:8787/api/other", "http://user:secret@10.77.0.1:8787", "http://10.77.0.1:8787/?token=secret", "http://10.77.0.1:8787/?", "http://10.77.0.1:8787/#secret"} {
		mutations[target] = func(p map[string]any) { p["router_api"] = target }
	}
	for name, mutation := range mutations {
		t.Run(name, func(t *testing.T) {
			profile := predecessorProfile()
			mutation(profile)
			if _, err := NewPredecessorProof(predecessorJSON(profile)); err == nil || strings.Contains(err.Error(), "private-entry-secret") {
				t.Fatal("unsafe captured profile accepted or credentials exposed", err)
			}
		})
	}
	source := predecessorJSON(predecessorProfile())
	for _, invalid := range []string{source + source, strings.Replace(source, `"id":"captured-entry"`, `"id":"captured-entry","id":"other"`, 1)} {
		if _, err := NewPredecessorProof(invalid); err == nil {
			t.Fatal("ambiguous captured profile accepted")
		}
	}
}

func TestPredecessorProofRejectsWrongUnboundedAndRedirectedReplies(t *testing.T) {
	good := `{"ok":true,"node_id":"` + strings.Repeat("a", 64) + `","proof":"router-vpn-private-agent-v1"}`
	for name, response := range map[string]string{
		"wrong-node":  strings.Replace(good, strings.Repeat("a", 64), strings.Repeat("b", 64), 1),
		"false":       strings.Replace(good, "true", "false", 1),
		"typed-ok":    strings.Replace(good, "true", `"true"`, 1),
		"wrong-proof": strings.Replace(good, "private-agent", "other-agent", 1),
		"duplicate":   strings.Replace(good, `"ok":true`, `"ok":true,"ok":true`, 1),
		"unknown":     strings.Replace(good, `"ok":true`, `"ok":true,"extra":1`, 1),
		"trailing":    good + "{}",
		"oversize":    strings.Repeat(" ", 8193),
		"redirect":    "HTTP/1.1 302 Found\r\nLocation: http://unowned.invalid/steal\r\nContent-Length: 0\r\n\r\n",
		"compressed":  "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n",
		"headers":     "HTTP/1.1 200 OK\r\nX-Oversized: " + strings.Repeat("a", 17000),
	} {
		t.Run(name, func(t *testing.T) {
			owned, _ := NewPredecessorProof(predecessorJSON(predecessorProfile()))
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer server.Close()
				_, _ = http.ReadRequest(bufio.NewReader(server))
				if !strings.HasPrefix(response, "HTTP/") {
					response = fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(response), response)
				}
				_, _ = io.WriteString(server, response)
			}()
			var calls atomic.Int32
			err := owned.Prove(context.Background(), func(context.Context, string, string) (net.Conn, error) { calls.Add(1); return client, nil })
			if err == nil || strings.Contains(err.Error(), "private-entry-secret") || calls.Load() != 1 {
				t.Fatal("invalid proof accepted, followed, or leaked", err)
			}
			<-done
		})
	}
}

type predecessorCloseConn struct {
	net.Conn
	closing chan struct{}
	release chan struct{}
	once    sync.Once
	writes  atomic.Int32
	failure bool
}

func (c *predecessorCloseConn) Write(p []byte) (int, error) { c.writes.Add(1); return c.Conn.Write(p) }
func (c *predecessorCloseConn) Close() error {
	c.once.Do(func() {
		_ = c.Conn.Close()
		if c.closing != nil {
			close(c.closing)
		}
		if c.release != nil {
			<-c.release
		}
	})
	if c.failure {
		return errors.New("private-entry-secret close failure")
	}
	return nil
}

func TestPredecessorCancellationRetainsLateDialWithoutSendingCredentials(t *testing.T) {
	owned, _ := NewPredecessorProof(predecessorJSON(predecessorProfile()))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, server := net.Pipe()
	defer server.Close()
	connection := &predecessorCloseConn{Conn: client, closing: make(chan struct{})}
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- owned.Prove(ctx, func(context.Context, string, string) (net.Conn, error) {
			close(entered)
			<-release
			return connection, nil
		})
	}()
	<-entered
	cancel()
	select {
	case <-done:
		t.Fatal("pending captured dial was forgotten")
	default:
	}
	close(release)
	if err := <-done; err == nil {
		t.Fatal("cancelled late dial proved a node")
	}
	<-connection.closing
	if connection.writes.Load() != 0 {
		t.Fatal("late socket received captured credentials")
	}
}

func TestPredecessorCancellationJoinsRealCloseAndActiveRead(t *testing.T) {
	owned, _ := NewPredecessorProof(predecessorJSON(predecessorProfile()))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, server := net.Pipe()
	defer server.Close()
	connection := &predecessorCloseConn{Conn: client, closing: make(chan struct{}), release: make(chan struct{})}
	requested := make(chan struct{})
	go func() { _, _ = http.ReadRequest(bufio.NewReader(server)); close(requested) }()
	done := make(chan error, 1)
	go func() {
		done <- owned.Prove(ctx, func(context.Context, string, string) (net.Conn, error) { return connection, nil })
	}()
	<-requested
	cancel()
	<-connection.closing
	select {
	case <-done:
		t.Fatal("proof returned before the real socket close callback joined")
	default:
	}
	close(connection.release)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled proof accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled proof did not finish after physical close")
	}
}

func TestPredecessorCloseFailureCannotReturnSuccessOrCredentials(t *testing.T) {
	owned, _ := NewPredecessorProof(predecessorJSON(predecessorProfile()))
	client, server := net.Pipe()
	defer server.Close()
	connection := &predecessorCloseConn{Conn: client, failure: true}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = http.ReadRequest(bufio.NewReader(server))
		body := `{"ok":true,"node_id":"` + strings.Repeat("a", 64) + `","proof":"router-vpn-private-agent-v1"}`
		_, _ = fmt.Fprintf(server, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	}()
	err := owned.Prove(context.Background(), func(context.Context, string, string) (net.Conn, error) { return connection, nil })
	if err == nil || strings.Contains(err.Error(), "private-entry-secret") {
		t.Fatal("unconfirmed close was adopted or leaked", err)
	}
	<-done
}
