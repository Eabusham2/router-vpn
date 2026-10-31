//go:build windows

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"router-vpn/internal/windowsprotection"
)

func desktopNodeRecoveryBootstrap(controller *windowsOwnedController) func(context.Context, string) (desktopNodeRecoveryBackend, error) {
	return func(ctx context.Context, profiles string) (desktopNodeRecoveryBackend, error) {
		var empty desktopNodeRecoveryBackend
		if ctx == nil || ctx.Err() != nil {
			return empty, errors.New("startup recovery has no live captured controller operation")
		}
		if err := currentDesktopNodeController(controller); err != nil {
			return empty, err
		}
		if controller.self == nil || controller.parent == nil || len(controller.directories) != 1 ||
			!windowsOwnedSamePath(controller.directories[0].Name(), controller.dataRoot) ||
			!windowsOwnedSamePath(profiles, filepath.Join(controller.dataRoot, "routers.json")) {
			return empty, errors.New("startup recovery lost its original desktop Data/profile directory")
		}
		started, err := controller.self.StartTimeUTCTicks()
		if err != nil {
			return empty, err
		}
		identity, err := controller.self.Identity()
		if err != nil || identity != controller.elevated {
			return empty, errors.Join(err, errors.New("startup recovery changed its actual controller primary token"))
		}
		captured := windowsprotection.Controller{PID: controller.self.PID(), StartTimeUTCTicks: started,
			SID: identity.SID, AuthenticationID: identity.AuthenticationID, SessionID: identity.SessionID}
		if err := captured.Validate(); err != nil {
			return empty, err
		}
		return desktopNodeRecoveryBackend{controller: captured,
			current: func() error {
				if err := currentDesktopNodeController(controller); err != nil {
					return err
				}
				if len(controller.directories) != 1 || !windowsOwnedSamePath(controller.directories[0].Name(), controller.dataRoot) {
					return errors.New("startup recovery lost its retained original Data handle")
				}
				return nil
			},
			open: func(ctx context.Context) (desktopNodeProtectionJournal, error) {
				return openDesktopNodeStartupJournal(ctx, controller)
			},
			begin: func(ctx context.Context, journal desktopNodeProtectionJournal) (desktopNodeJournalRecovery, error) {
				if err := currentDesktopNodeController(controller); err != nil {
					return nil, err
				}
				store, ok := journal.(*windowsprotection.ProtectionJournal)
				if !ok || store == nil {
					return nil, errors.New("startup recovery has another journal storage owner")
				}
				return store.BeginRecovery(ctx)
			}}, nil
	}
}

func openDesktopNodeStartupJournal(ctx context.Context, controller *windowsOwnedController) (*windowsprotection.ProtectionJournal, error) {
	if err := currentDesktopNodeController(controller); err != nil {
		return nil, err
	}
	store, err := windowsprotection.OpenProtectionJournal(ctx, controller.parent, controller.directories[0])
	if !errors.Is(err, os.ErrNotExist) {
		return store, err
	}
	if store != nil {
		if closeErr := store.Close(); closeErr != nil {
			return store, errors.Join(err, closeErr)
		}
	}
	// Creation independently proves native absence and the exact empty
	// protected namespace; a missing peer/header never authorizes repair.
	return windowsprotection.CreateProtectionJournal(ctx, controller.parent, controller.directories[0])
}

func (a *app) initializeDesktopNodeRecovery() error {
	controller := windowsOwnedCapture.Load()
	if controller == nil {
		return nil // ordinary unsigned utility/test startup has no native authority
	}
	backend, err := desktopOwnedNodeProtectionBackend()
	if err != nil {
		return err
	}
	// The launcher's controller identity deadline is 30 seconds. Bound this
	// first attempt below it so unresolved recovery can still expose truthful
	// status and retry controls through the authenticated listener.
	ctx, cancel := context.WithTimeout(controller.ctx, 10*time.Second)
	defer cancel()
	return a.initializeDesktopNodeRecoveryWith(ctx, backend)
}
