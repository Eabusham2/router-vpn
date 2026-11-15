//go:build windows && routervpn_windows_candidate_prefix_native && go1.25

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"router-vpn/internal/controllertransport"
	"router-vpn/internal/windowsbootstrap"
	"router-vpn/internal/windowscontroller"
	"sync"
	"testing"
	"time"
)

// The original protected pipe/token/image/TLS bootstrap is unchanged. The
// retained closer reports bounded join failure to the alias retirement owner.
func windowsCONNECTExecutionLaunch(t *testing.T, root string, retained *func(context.Context) error) (*controllertransport.Client, func(context.Context) error) {
	t.Helper()
	var pipe *windowscontroller.Pipe
	var image *windowscontroller.Image
	var process *windowscontroller.Process
	var command *exec.Cmd
	var client *controllertransport.Client
	var done chan struct{}
	var waitErr, terminal error
	var mu sync.Mutex
	closed := false
	diagnostic := new(windowsPrefixOutput)
	// Publish cleanup before the first allocation. A started child is retained
	// through its original exec.Cmd even if opening the stronger handle fails.
	closeOwner := func(ctx context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		if closed {
			return terminal
		}
		if ctx == nil {
			return errors.New("controller join requires captured context")
		}
		if pipe != nil {
			terminal = errors.Join(terminal, pipe.Close())
		}
		if done != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-done:
			}
			if waitErr != nil {
				terminal = errors.Join(terminal, waitErr, errors.New(diagnostic.String()))
			}
		}
		if client != nil {
			terminal = errors.Join(terminal, client.Close())
			client = nil
		}
		if process != nil {
			terminal = errors.Join(terminal, process.Close())
			process = nil
		}
		if image != nil {
			terminal = errors.Join(terminal, image.Close())
			image = nil
		}
		closed = true
		return terminal
	}
	*retained = closeOwner
	var err error
	pipe, err = windowscontroller.NewPipe()
	if err != nil {
		t.Fatal(err)
	}
	image, err = windowscontroller.PinImage(filepath.Join(root, "router-vpn-client.exe"))
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	arguments, err := windowsbootstrap.Arguments(pipe.Name(), uint32(os.Getpid()), executable)
	if err != nil {
		t.Fatal(err)
	}
	command = exec.Command(image.Path(), arguments...)
	command.Stdout, command.Stderr = diagnostic, diagnostic
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	done = make(chan struct{})
	go func() { waitErr = command.Wait(); close(done) }()
	process, err = windowscontroller.OpenProcess(uint32(command.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := pipe.Accept(ctx); err != nil {
		t.Fatal(err)
	}
	frame, err := pipe.ReadFrame(ctx)
	if err != nil {
		t.Fatal("prefix actual child handshake", err, diagnostic.String())
	}
	peer, err := pipe.VerifyPeer(process, image)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := peer.Process.Close(); err != nil {
			t.Error("original handshake peer handle close", err)
		}
	}()
	primary, err := process.Identity()
	if err != nil || peer.Identity.Primary || !primary.Primary || !primary.Elevated || !primary.Administrator || peer.Identity.SID != primary.SID || peer.Identity.AuthenticationID != primary.AuthenticationID {
		t.Fatal("prefix child lost original native token", err)
	}
	hello, err := windowsbootstrap.DecodeHello(frame, process.PID())
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := windowsbootstrap.NewCredentials()
	if err != nil {
		t.Fatal(err)
	}
	private, err := windowsbootstrap.EncodeCredentials(credentials)
	if err != nil {
		t.Fatal(err)
	}
	if err := pipe.WriteFrame(ctx, private); err != nil {
		t.Fatal(err)
	}
	client, err = controllertransport.NewClient(process, hello.TLSPin, credentials.AccessToken, credentials.OwnerToken)
	if err != nil {
		t.Fatal(err)
	}
	for {
		if err = client.VerifyIdentity(ctx); err == nil {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("prefix pinned TLS identity", ctx.Err(), diagnostic.String())
		}
		if err := process.Alive(); err != nil {
			t.Fatal(err, diagnostic.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	return client, closeOwner
}
