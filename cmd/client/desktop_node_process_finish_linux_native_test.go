//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"router-vpn/internal/linuxprocess"
)

// The fixture holds the real child after native channel closure. The parent
// releases it explicitly, so the join assertion does not depend on scheduling
// a short timeout before an otherwise immediate successful exit.
func linuxNodeFinishEngineFixture(ctx context.Context, bootstrap *linuxprocess.Bootstrap, directory string) error {
	if err := bootstrap.Send(ctx, []byte("native-engine-finishing")); err != nil {
		return err
	}
	if _, err := bootstrap.Receive(ctx); !errors.Is(err, linuxprocess.ErrPeerClosed) {
		return errors.Join(err, errors.New("finishing child did not observe its original native peer closure"))
	}
	if err := os.WriteFile(filepath.Join(directory, "finish-channel-closed"), []byte("original-channel-closed"), 0600); err != nil {
		return err
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "finish-release")); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func linuxNodeFinishParentFixture(ctx context.Context, process *desktopLinuxNodeProcess, bootstrap *linuxprocess.Bootstrap,
	directory string, cancelled bool) error {
	if cancelled {
		stopped, stop := context.WithCancel(ctx)
		stop()
		if _, err := process.FinishAndWait(stopped); err == nil || process.finishing || process.retiring.Load() {
			return errors.New("cancelled finish changed the original live process owner")
		}
		if err := process.Alive(); err != nil {
			return errors.Join(err, errors.New("cancelled finish closed its original channel"))
		}
	}
	if err := bootstrap.Send(ctx, []byte("finish-hold")); err != nil {
		return err
	}
	if body, err := bootstrap.Receive(ctx); err != nil || string(body) != "native-engine-finishing" {
		return errors.Join(err, errors.New("actual finishing child omitted its final acknowledgment"))
	}
	type outcome struct {
		code uint32
		err  error
	}
	result := make(chan outcome, 1)
	go func() { code, err := process.FinishAndWait(ctx); result <- outcome{code, err} }()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case completed := <-result:
			return errors.Join(completed.err, errors.New("finish returned before its actual held child joined"))
		default:
		}
		if _, err := os.Stat(filepath.Join(directory, "finish-channel-closed")); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case completed := <-result:
		return errors.Join(completed.err, errors.New("finish returned before its actual held child joined"))
	default:
	}
	if err := os.WriteFile(filepath.Join(directory, "finish-release"), []byte("release-original-child"), 0600); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case completed := <-result:
		if completed.err != nil || completed.code != 0 {
			return errors.Join(completed.err, errors.New("original child did not finish successfully after channel closure"))
		}
	}
	if !process.finishing || process.bootstrap != nil || process.closed || process.released || process.root == nil {
		return errors.New("finish discarded retained owners before ordinary process cleanup")
	}
	for _, pin := range process.pins {
		if pin.file == nil {
			return errors.New("finish released its original package pins before process cleanup")
		}
		if _, err := pin.file.Stat(); err != nil {
			return errors.Join(err, errors.New("finish closed its original package pins before process cleanup"))
		}
	}
	if _, exists := process.parent.parent.dependents[process]; !exists || process.parent.Current(ctx) != nil {
		return errors.New("finish discarded its original parent dependency")
	}
	if code, err := process.FinishAndWait(ctx); err != nil || code != 0 {
		return errors.Join(err, errors.New("repeated finish lost the original joined result"))
	}
	return nil
}
