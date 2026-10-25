package controllerprocess

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"router-vpn/internal/applexray"
)

const localURL = "http://127.0.0.1:8788/"

type Owner struct {
	command *exec.Cmd
	token   string
	done    chan struct{}
	waitErr error // Published by closing done; only read after receiving it.
}

var owners sync.Map

func NewToken() (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", errors.New("cannot create owned controller identity")
	}
	return hex.EncodeToString(nonce[:]), nil
}

func Environment(env []string, token string) []string {
	out := make([]string, 0, len(env)+1)
	for _, value := range env {
		key, _, _ := strings.Cut(value, "=")
		if !strings.EqualFold(key, "HOMEVPN_CONTROLLER_OWNER") {
			out = append(out, value)
		}
	}
	return append(out, "HOMEVPN_CONTROLLER_OWNER="+token)
}

func Track(cmd *exec.Cmd, token string) *Owner {
	owner := &Owner{command: cmd, token: token, done: make(chan struct{})}
	owners.Store(cmd, owner)
	go func() {
		owner.waitErr = cmd.Wait()
		close(owner.done)
	}()
	return owner
}

type shutdownRequest struct {
	Schema int    `json:"schema"`
	PID    int    `json:"process_id"`
	Token  string `json:"owner_token"`
}

type shutdownReceipt struct {
	Schema int    `json:"schema"`
	PID    int    `json:"process_id"`
	Token  string `json:"owner_token"`
	Closed bool   `json:"closed"`
}

func requestShutdown(ctx context.Context, client *http.Client, url string, pid int, token string) error {
	raw, _ := json.Marshal(shutdownRequest{Schema: 1, PID: pid, Token: token})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return errors.New("owned controller shutdown has not been acknowledged")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1025))
	if err != nil || len(body) > 1024 || response.StatusCode != http.StatusOK {
		return errors.New("owned controller cleanup is still pending")
	}
	fields, err := applexray.Object(body)
	if err != nil || len(fields) != 4 {
		return errors.New("controller returned an invalid shutdown receipt")
	}
	var receipt shutdownReceipt
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&receipt) != nil || receipt.Schema != 1 || receipt.PID != pid || receipt.Token != token || !receipt.Closed {
		return errors.New("controller shutdown receipt does not match this launch")
	}
	return nil
}

// A temporary HTTP failure does not transfer ownership or justify terminating
// the child. Its shutdown worker may still be rolling back a native MTU lease.
// Keep the launcher alive until that exact child has acknowledged and exited.
func waitForShutdown(owner *Owner, request func(context.Context, int, string) error, pending func()) error {
	if owner == nil || owner.command == nil || owner.command.Process == nil || request == nil {
		return errors.New("Router VPN launcher does not own this controller process")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The server flushes its receipt before exiting. Do not cancel its response
	// reader merely because Wait wins the scheduling race with the last bytes.
	for {
		err := request(ctx, owner.command.Process.Pid, owner.token)
		if err == nil {
			<-owner.done
			if owner.waitErr != nil {
				return fmt.Errorf("controller exited after cleanup with an error: %w", owner.waitErr)
			}
			return nil
		}
		select {
		case <-owner.done:
			return errors.New("owned controller exited without a checked cleanup receipt")
		default:
		}
		if pending != nil {
			pending()
		}
		delay := time.NewTimer(time.Second)
		select {
		case <-owner.done:
			if !delay.Stop() {
				<-delay.C
			}
			return errors.New("owned controller exited before cleanup was acknowledged")
		case <-delay.C:
		}
	}
}

func Stop(cmd *exec.Cmd) error {
	raw, exists := owners.Load(cmd)
	if !exists {
		return errors.New("Router VPN launcher cannot stop a controller from another launch")
	}
	owner := raw.(*Owner)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 35 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("controller shutdown redirects are not allowed")
	}}
	var notice sync.Once
	err := waitForShutdown(owner, func(ctx context.Context, pid int, token string) error {
		return requestShutdown(ctx, client, localURL+"api/controller/shutdown", pid, token)
	}, func() {
		notice.Do(func() {
			fmt.Fprintln(os.Stderr, "Router VPN is waiting for owned tunnel cleanup before exiting.")
		})
	})
	owners.CompareAndDelete(cmd, owner)
	return err
}
