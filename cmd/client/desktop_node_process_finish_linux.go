//go:build linux

package main

import (
	"context"
	"errors"
)

// FinishAndWait closes this original authenticated channel and joins the actual
// created command without releasing its package pins or parent dependency.
// The caller must first finish its own source-retirement acknowledgment. This
// method does not prove firewall retirement or settle a durable journal.
//
// The child must stay alive after receiving that final acknowledgment until it
// observes this channel's native peer closure. Otherwise its exit can race the
// parent's required process observation after Send. A cancelled finish retains
// all remaining owners for retry or ordinary Close.
func (p *desktopLinuxNodeProcess) FinishAndWait(ctx context.Context) (uint32, error) {
	if err := p.enter(ctx); err != nil {
		return 0, err
	}
	defer func() { p.gate <- struct{}{} }()
	if !p.started.Load() || p.command == nil || p.closed || p.released {
		return 0, errors.New("Linux Node finish lost its original started process owner")
	}
	if !p.finishing {
		if err := p.currentFiles(ctx); err != nil {
			return 0, err
		}
		if p.bootstrap == nil {
			return 0, errors.New("Linux Node finish has no original authenticated channel")
		}
		if err := p.bootstrap.Current(ctx); err != nil {
			return 0, err
		}
		p.finishing = true
		p.retiring.Store(true)
		p.cancel()
	}
	if p.bootstrap != nil {
		if err := p.bootstrap.Close(ctx); err != nil {
			return 0, err
		}
		p.bootstrap = nil
	}
	return p.Wait(ctx)
}
