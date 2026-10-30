package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/controllertransport"
)

func TestLocalControllerPinnedDrainUtilityArguments(t *testing.T) {
	pin := strings.Repeat("a", 64)
	pid, actual, handled, err := parseWindowsControllerDrainUtility([]string{windowsControllerDrainUtilityFlag, "731", pin})
	if err != nil || !handled || pid != 731 || actual != pin {
		t.Fatal("captured public drain arguments changed", pid, actual, handled, err)
	}
	for _, args := range [][]string{
		{windowsControllerDrainUtilityFlag}, {windowsControllerDrainUtilityFlag, "731"},
		{windowsControllerDrainUtilityFlag, "731", pin, "bearer"},
		{windowsControllerDrainUtilityFlag, "0", pin}, {windowsControllerDrainUtilityFlag, "0731", pin},
		{windowsControllerDrainUtilityFlag, "+731", pin}, {windowsControllerDrainUtilityFlag, " 731", pin},
		{windowsControllerDrainUtilityFlag, "4294967296", pin}, {windowsControllerDrainUtilityFlag, "-1", pin},
		{windowsControllerDrainUtilityFlag, "731", strings.ToUpper(pin)},
		{windowsControllerDrainUtilityFlag, "731", pin + "0"},
		{windowsControllerDrainUtilityFlag, "731", "https://127.0.0.1:8788"},
	} {
		if _, _, handled, err := parseWindowsControllerDrainUtility(args); !handled || err == nil {
			t.Fatal("invalid owner or extra authority entered the drain utility", args, handled, err)
		}
	}
	if _, _, handled, err := parseWindowsControllerDrainUtility([]string{"--verify-native-runtime"}); handled || err != nil {
		t.Fatal("drain utility consumed another operation", handled, err)
	}
}

// This fixture always owns the real public loopback origin. No endpoint or
// listener override enters the production utility or its pinned transport.
func controllerDrainUtilityServer(t *testing.T, identity *controllertransport.Identity, handler http.Handler) {
	t.Helper()
	listener, err := net.Listen("tcp4", controllertransport.Address)
	if err != nil {
		t.Fatal("actual drain utility origin is unavailable", err)
	}
	if identity != nil {
		config, err := identity.Config()
		if err != nil {
			_ = listener.Close()
			t.Fatal(err)
		}
		listener = tls.NewListener(listener, config)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Error("actual utility listener did not join", err)
		}
	})
}

func TestLocalControllerPinnedDrainUtilityReadOnly(t *testing.T) {
	for _, draining := range []bool{false, true} {
		t.Run(strconv.FormatBool(draining), func(t *testing.T) {
			identity, err := controllertransport.NewIdentity()
			if err != nil {
				t.Fatal(err)
			}
			var received atomic.Int32
			controllerDrainUtilityServer(t, identity, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received.Add(1)
				if r.TLS == nil || r.Host != controllertransport.Address || r.Method != http.MethodGet || r.URL.RequestURI() != controllertransport.DrainPath ||
					r.ContentLength != 0 || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("X-RouterVPN-Challenge") != "" {
					t.Error("drain utility disclosed private authority or changed its fixed read-only operation")
				}
				_, _ = io.WriteString(w, `{"schema":1,"process_id":`+strconv.Itoa(os.Getpid())+`,"draining":`+strconv.FormatBool(draining)+`}`)
			}))
			var output bytes.Buffer
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := writeCapturedControllerDrain(ctx, new(pinnedControllerTestProcess), identity.Pin(), &output); err != nil {
				t.Fatal("actual utility read-only observation failed", err)
			}
			var receipt map[string]any
			if err := json.Unmarshal(output.Bytes(), &receipt); err != nil || len(receipt) != 3 || len(output.Bytes()) > 1024 ||
				receipt["schema"] != float64(1) || receipt["process_id"] != float64(os.Getpid()) || receipt["draining"] != draining || received.Load() != 1 {
				t.Fatal("utility published another process or an unbounded drain observation", output.String(), err)
			}
		})
	}
}

func TestLocalControllerPinnedDrainUtilityRejectsUnknownAndCancelled(t *testing.T) {
	for _, mode := range []string{"wrong-pin", "wrong-process", "failed-status", "cancelled", "retired"} {
		t.Run(mode, func(t *testing.T) {
			identity, err := controllertransport.NewIdentity()
			if err != nil {
				t.Fatal(err)
			}
			owner := new(pinnedControllerTestProcess)
			entered, left := make(chan struct{}), make(chan struct{})
			var received atomic.Int32
			controllerDrainUtilityServer(t, identity, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received.Add(1)
				if mode == "cancelled" {
					close(entered)
					<-r.Context().Done()
					close(left)
					return
				}
				if mode == "retired" {
					owner.closed.Store(true)
				}
				pid := os.Getpid()
				if mode == "wrong-process" {
					pid++
				}
				if mode == "failed-status" {
					w.WriteHeader(http.StatusForbidden)
				}
				_, _ = io.WriteString(w, `{"schema":1,"process_id":`+strconv.Itoa(pid)+`,"draining":true}`)
			}))
			pin := identity.Pin()
			if mode == "wrong-pin" {
				other, err := controllertransport.NewIdentity()
				if err != nil {
					t.Fatal(err)
				}
				pin = other.Pin()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			var output bytes.Buffer
			done := make(chan error, 1)
			go func() { done <- writeCapturedControllerDrain(ctx, owner, pin, &output) }()
			if mode == "cancelled" {
				select {
				case <-entered:
					cancel()
				case <-ctx.Done():
					t.Fatal("actual utility cancellation never entered its request")
				}
			}
			err = <-done
			if err == nil || output.Len() != 0 || mode == "wrong-pin" && received.Load() != 0 {
				t.Fatal("unknown or cancelled utility observation published stop authority", mode, output.String(), err)
			}
			if mode == "cancelled" {
				if !errors.Is(err, context.Canceled) {
					t.Fatal("utility lost actual caller cancellation", err)
				}
				select {
				case <-left:
				case <-time.After(time.Second):
					t.Fatal("cancelled utility left its real TLS request running")
				}
			}
		})
	}
}
