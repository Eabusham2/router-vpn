//go:build linux

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestLinuxStandardServiceBootBootstrapUnsentDestination(t *testing.T) {
	for _, name := range []string{"legacy", "generation", "missing-receipt", "foreign-socket", "missing-image", "mixed-error", "cancelled", "wrong-network", "wrong-operation", "wrong-syscall", "attempted", "retained-peer"} {
		t.Run(name, func(t *testing.T) {
			b := &linuxStandardBootBootstrapClient{}
			socket := linuxStandardServiceSocket
			if name == "generation" {
				socket = "/original-image/run/original-generation.sock"
			}
			response := linuxStandardServiceResponse{unconnectedSocket: socket}
			call := &os.SyscallError{Syscall: "connect", Err: syscall.ENOENT}
			op := &net.OpError{Op: "dial", Net: "unixpacket", Addr: &net.UnixAddr{Name: socket, Net: "unixpacket"}, Err: call}
			var failure error = op
			switch name {
			case "missing-receipt":
				response.unconnectedSocket = ""
			case "foreign-socket":
				op.Addr = &net.UnixAddr{Name: "/foreign.sock", Net: "unixpacket"}
			case "missing-image":
				failure = &os.PathError{Op: "open", Path: "original-image", Err: syscall.ENOENT}
			case "mixed-error":
				failure = errors.Join(op, errors.New("source lost"))
			case "cancelled":
				failure = errors.Join(op, context.Canceled)
			case "wrong-network":
				op.Net = "unix"
			case "wrong-operation":
				op.Op = "read"
			case "wrong-syscall":
				call.Syscall = "open"
			case "attempted":
				b.attempted = true
			case "retained-peer":
				b.peer = &linuxStandardServicePeer{}
			}
			if got := b.unsentAbsent(response, failure); got != (name == "legacy" || name == "generation") {
				t.Fatalf("%s fallback=%v", name, got)
			}
		})
	}
}

// These are local dependency/ordering models. The pending-failure case has no
// native parent authority and must retain the request; the later acknowledgement
// models settlement, not a successful native service exchange.
func TestLinuxStandardServiceBootBootstrapParentJoin(t *testing.T) {
	for _, name := range []string{"cancelled-no-next-lookup", "held-cleanup-retry", "replacement", "consumed-transfer", "consumed-detach-retry", "pending-failure-retry"} {
		t.Run(name, func(t *testing.T) {
			lifetime, stop := context.WithCancel(context.Background())
			defer stop()
			operation, cancel := context.WithCancel(lifetime)
			cancel()
			a := &app{}
			p := &desktopLinuxNodeParent{gate: make(chan struct{}, 1), ctx: lifetime, dependents: make(map[ownedDesktopNodeParent]struct{})}
			p.gate <- struct{}{}
			b := &linuxStandardBootBootstrapClient{app: a, parent: &desktopLinuxNodeParentCapture{app: a, parent: p}, operation: operation}
			p.dependents[b] = struct{}{}
			linuxStandardBootBootstraps.Store(a, b)
			defer linuxStandardBootBootstraps.Delete(a)
			var replacement *linuxStandardBootBootstrapClient
			if name == "replacement" {
				replacement = &linuxStandardBootBootstrapClient{app: a}
				linuxStandardBootBootstraps.Store(a, replacement)
			}
			var successorPeer *linuxStandardServicePeer
			if name == "consumed-transfer" || name == "consumed-detach-retry" {
				successorPeer = &linuxStandardServicePeer{}
				b.peer = successorPeer
				if name == "consumed-detach-retry" {
					<-p.gate
					ctx, done := context.WithTimeout(context.Background(), 20*time.Millisecond)
					e := b.consumeTransferLocked(ctx)
					done()
					p.gate <- struct{}{}
					if !errors.Is(e, context.DeadlineExceeded) || !b.consumed.Load() || len(p.dependents) != 1 || b.peer != successorPeer {
						t.Fatal("consumed ownership lost during bounded detach", e)
					}
				} else if e := b.consumeTransferLocked(context.Background()); e != nil {
					t.Fatal(e)
				}
			}
			if name == "pending-failure-retry" {
				b.attempted = true
				ctx, done := context.WithTimeout(context.Background(), time.Second)
				e := p.prepareTransactionShutdown(ctx)
				done()
				if e == nil || b.closed.Load() || len(p.dependents) != 1 || lifetime.Err() != nil {
					t.Fatal("unsettled original lost before parent cancellation", e)
				}
				b.cleanupAcknowledged = true
			}
			if name == "held-cleanup-retry" {
				b.mu.Lock()
				ctx, done := context.WithTimeout(context.Background(), 20*time.Millisecond)
				e := p.prepareTransactionShutdown(ctx)
				done()
				b.mu.Unlock()
				if !errors.Is(e, context.DeadlineExceeded) || b.closed.Load() || len(p.dependents) != 1 || lifetime.Err() != nil {
					t.Fatal("held original was not retained", e)
				}
			}
			ctx, done := context.WithTimeout(context.Background(), time.Second)
			defer done()
			e := p.prepareTransactionShutdown(ctx)
			if name == "replacement" {
				actual, _ := linuxStandardBootBootstraps.Load(a)
				if e == nil || b.closed.Load() || len(p.dependents) != 1 || actual != replacement {
					t.Fatal("replacement adopted or removed", e)
				}
			} else if e != nil || len(p.dependents) != 0 || !b.closed.Load() && !b.consumed.Load() {
				t.Fatal("original dependency not joined", e)
			}
			if lifetime.Err() != nil {
				t.Fatal("parent canceled before dependency retirement")
			}
			if successorPeer != nil && b.peer != successorPeer {
				t.Fatal("cleanup closed successor-owned peer")
			}
		})
	}
}
