//go:build linux && routervpn_controller_privileged

package linuxprocess

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/common"
)

// These calls use the authenticated original helper and captured kernel
// objects. No saved process record or synthetic guard supplies liveness.
func TestLinuxProcessNamespaceBootstrapCurrentObservation(t *testing.T) {
	for _, mode := range []string{"normal-signal", "expired", "parent-task", "created-child", "child-task", "mixed-native-loss", "retired", "foreign-child"} {
		t.Run(mode, func(t *testing.T) {
			original := observationContextBootstrap(t)
			parent, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			var ctx context.Context = parent
			var release func()
			if mode == "normal-signal" {
				notified, stop := signal.NotifyContext(context.Background(), syscall.SIGUSR1)
				defer stop()
				if err := syscall.Kill(os.Getpid(), syscall.SIGUSR1); err != nil {
					t.Fatal(err)
				}
				select {
				case <-notified.Done():
				case <-parent.Done():
					t.Fatal("original signal did not cancel lifetime")
				}
				ctx = notified
			} else if mode == "expired" || mode == "retired" {
				expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				defer stop()
				ctx = expired
			}
			if mode == "retired" {
				original.revoked = true
			}
			if mode == "foreign-child" {
				original.childRecord.ProcessID++
			}
			if mode == "mixed-native-loss" {
				if err := original.child.task.image.Close(); err != nil {
					t.Fatal(err)
				}
				ctx = &observationContextCancelAtTask{Context: parent, task: original.child.task, cancel: cancel}
			}
			target := map[string]int32{"parent-task": 2, "created-child": 3, "child-task": 4}[mode]
			if target != 0 {
				gate := original.parent.gate
				if mode == "created-child" {
					gate = original.child.gate
				}
				if mode == "child-task" {
					gate = original.child.task.gate
				}
				<-gate
				released := false
				release = func() {
					if !released {
						gate <- struct{}{}
						released = true
					}
				}
				defer release()
				entered := &observationContextEntered{Context: parent, entered: make(chan struct{})}
				entered.target.Store(target)
				ctx = entered
				done := make(chan error, 1)
				go func() { done <- original.Current(ctx) }()
				select {
				case <-entered.entered:
				case <-time.After(time.Second):
					t.Fatal("current did not reach original nested witness")
				}
				cancel()
				select {
				case err := <-done:
					if !common.ObservationContextExpired(ctx, err) {
						t.Fatal("pure original observation became owner loss", err)
					}
				case <-time.After(time.Second):
					release()
					<-done
					t.Fatal("current did not honor original nested observation bound")
				}
				release()
			} else {
				// Hold the actual bootstrap gate and call its real admitted helper so an
				// already-expired context cannot merely lose the public select race.
				<-original.gate
				err := original.current(ctx)
				original.gate <- struct{}{}
				genuine := mode == "mixed-native-loss" || mode == "retired" || mode == "foreign-child"
				if genuine {
					if err == nil || common.ObservationContextOnly(err) || !original.revoked {
						t.Fatal("genuine original loss was not retained", err)
					}
					if mode == "mixed-native-loss" && parent.Err() == nil {
						t.Fatal("native loss did not coincide with actual cancellation")
					}
					return
				}
				if !common.ObservationContextExpired(ctx, err) {
					t.Fatal("pure original observation became owner loss", err)
				}
			}
			if original.revoked || original.parent.revoked || original.child.revoked || original.child.task.revoked {
				t.Fatal("pure current observation revoked original participants")
			}
			retry, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if err := original.Current(retry); err != nil {
				t.Fatal("original current could not be reproved", err)
			}
		})
	}
}
