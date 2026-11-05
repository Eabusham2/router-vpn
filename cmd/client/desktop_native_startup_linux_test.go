//go:build linux

package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobiletor"
)

func TestDesktopNativeStartupAdmissionKeepsRefusalDialogue(t *testing.T) {
	for _, mode := range []string{"original", "expired-create", "expired-admit", "shorter-dialogue"} {
		t.Run(mode, func(t *testing.T) {
			identity := context.Background()
			startup, stop := context.WithTimeout(identity, time.Second)
			defer stop()
			dialogue, end := context.WithTimeout(context.Background(), 2*time.Second)
			defer end()
			tx := &desktopLinuxNodeTransaction{operation: identity, startup: startup}
			if mode == "expired-create" || mode == "expired-admit" {
				stop()
				var err error
				if mode == "expired-create" {
					_, err = tx.createBaseline(dialogue, mobiletor.DesktopSocketCapture{})
				} else {
					err = tx.admitSource(dialogue, linuxprotection.NodePreparedRecord{})
				}
				if !errors.Is(err, context.Canceled) || dialogue.Err() != nil || tx.baseline != nil || tx.created != nil || tx.prepared != nil {
					t.Fatal("expired mutation entered native admission or killed refusal dialogue", err)
				}
				return
			}
			expected, _ := startup.Deadline()
			if mode == "shorter-dialogue" {
				var cancel context.CancelFunc
				dialogue, cancel = context.WithTimeout(dialogue, 20*time.Millisecond)
				defer cancel()
				expected, _ = dialogue.Deadline()
			}
			call, cancel, err := tx.startupCall(dialogue)
			if err != nil {
				t.Fatal(err)
			}
			actual, _ := call.Deadline()
			if !actual.Equal(expected) || tx.operation != identity {
				t.Fatal("startup renewed budget or replaced identity")
			}
			cancel()
			if dialogue.Err() != nil || startup.Err() != nil {
				t.Fatal("callback completion canceled retained work or dialogue")
			}
			stop()
			if _, _, err := tx.startupCall(dialogue); !errors.Is(err, context.Canceled) {
				t.Fatal("later callback renewed expired mutation allowance", err)
			}
		})
	}
}
