package main

import (
	"context"
	"errors"
	"path/filepath"
)

type desktopImportedPreparationContextKey struct{}

// Platform hosts retain their native lifecycle authority. This seam supplies
// observation and ordered operations, never a second process or Wait owner.
type desktopImportedPlatformCapture interface {
	Seal() string
	Verify(context.Context) (string, error)
	Prepare(context.Context, *app, multihopSelection) (*desktopNodeLaunch, error)
}

type desktopImportedPlatformRuntime interface {
	Stage(context.Context) error
	Start(context.Context) error
	Current(context.Context) error
	Prove(context.Context) error
	Activate(context.Context) error
	Close(context.Context) error
	ProcessDone() <-chan struct{}
	ValidateConfig(context.Context, []byte) error
	Restore(context.Context) error
	RetainMTU(context.Context, *desktopImportedMTUOwner) error
	MTUCleanupCurrent(context.Context, *desktopImportedMTUOwner) error
}

// Linux creates Cmd only during Start. The runtime is retained by its actual
// session before creation; DNS registration must follow that actual start.
func startDesktopImportedPlatform(ctx context.Context, a *app, sel multihopSelection, launch *desktopNodeLaunch) error {
	if launch == nil || launch.importedPlatform == nil || sel.Native == nil || !sel.Native.imported {
		return errors.New("imported startup lost its original typed host")
	}
	if err := launch.importedPlatform.Start(ctx); err != nil {
		return err
	}
	if launch.command == nil {
		return errors.New("imported startup returned no original created command")
	}
	if err := launch.importedPlatform.Current(ctx); err != nil {
		return err
	}
	return registerActiveDNSRuntimeConfigKind(a, sel.Exit.ID, sel.ExitMode, filepath.Join(launch.directory, "sing-box.json"), true)
}
