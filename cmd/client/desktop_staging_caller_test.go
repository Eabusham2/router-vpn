package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestDesktopNativeStagingPreservesOriginalCallerRefusal(t *testing.T) {
	for _, cause := range []string{"cancelled", "deadline", "missing"} {
		t.Run(cause, func(t *testing.T) {
			root := t.TempDir()
			ambient, stopAmbient := context.WithCancel(context.Background())
			defer stopAmbient()
			prior := exec.Command("never-started-original-owner")
			a := &app{connectionContext: ambient, cmd: prior}
			launch := &desktopNodeLaunch{root: root, config: []byte(`{}`), metadata: []byte(`{}`)}
			originalConfig, originalMetadata := string(launch.config), string(launch.metadata)
			var ctx context.Context
			var want error
			switch cause {
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(context.Background())
				cancel()
				want = context.Canceled
			case "deadline":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(context.Background(), time.Unix(0, 0))
				defer cancel()
				want = context.DeadlineExceeded
			}
			err := stageDesktopNodeLaunchContext(ctx, a, launch)
			if err == nil || want != nil && (!errors.Is(err, want) || !errors.Is(err, errConnectionOperationCancelled)) {
				t.Fatal("native staging discarded the original caller refusal", cause, err)
			}
			if cause == "missing" && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
				t.Fatal("absent original caller manufactured a cancellation cause", err)
			}
			files, readErr := os.ReadDir(root)
			if readErr != nil || len(files) != 0 || launch.directory != "" || launch.directoryRoot != nil || launch.command != nil ||
				string(launch.config) != originalConfig || string(launch.metadata) != originalMetadata ||
				a.cmd != prior || a.connectionContext != ambient || ambient.Err() != nil || a.state != (state{}) {
				t.Fatal("rejected staging changed the original capture, ambient owner or private directory", readErr)
			}
		})
	}
}
