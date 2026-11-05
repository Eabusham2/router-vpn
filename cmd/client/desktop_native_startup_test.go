package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/mobilemultihop"
)

func startupContextLaunch(kind string) *desktopNodeLaunch {
	source, config, session := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 32)
	launch := &desktopNodeLaunch{}
	if kind == "tor" {
		launch.tor = &desktopTorRuntime{}
		launch.tor.expected.SessionID = session
		launch.tor.expected.SourceSHA256 = source
		launch.tor.expected.ConfigSHA256 = config
	} else {
		launch.external = &desktopExternalRuntime{session: session}
		launch.external.expected.SourceSHA256 = source
		launch.external.expected.ConfigSHA256 = config
	}
	return launch
}
func TestDesktopNativeStartupCapturesOneOriginalBudget(t *testing.T) {
	for _, kind := range []string{"external", "tor"} {
		t.Run(kind, func(t *testing.T) {
			original, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			launch := startupContextLaunch(kind)
			work, err := captureDesktopNativeStartup(original, launch)
			if err != nil {
				t.Fatal(err)
			}
			want, _ := original.Deadline()
			got, _ := work.Deadline()
			if !got.Equal(want) {
				t.Fatal("host extended shorter original deadline")
			}
			again, err := captureDesktopNativeStartup(original, launch)
			if err != nil || again != work {
				t.Fatal("host renewed admitted startup", err)
			}
			replacement, stop := context.WithCancel(original)
			defer stop()
			if _, err := captureDesktopNativeStartup(replacement, launch); err == nil {
				t.Fatal("replacement operation borrowed startup")
			}
			env, err := desktopNativeStartupEnvironment(work, launch, []string{mobilemultihop.DesktopStartupAdmissionEnvironment + "=foreign", "KEPT=value"})
			if err != nil {
				t.Fatal(err)
			}
			var raw string
			count := 0
			for _, v := range env {
				if strings.HasPrefix(v, mobilemultihop.DesktopStartupAdmissionEnvironment+"=") {
					raw = strings.TrimPrefix(v, mobilemultihop.DesktopStartupAdmissionEnvironment+"=")
					count++
				}
			}
			a := launch.startup.Load().admission
			parsed, err := mobilemultihop.ParseDesktopStartupAdmission(raw, kind, a.Session, a.SourceSHA256, a.ConfigSHA256)
			if err != nil || count != 1 || parsed.DeadlineNS != want.UnixNano() {
				t.Fatal("host failed exact child transport", err)
			}
			observer, stopObserver, err := desktopNativeStartupObservation(original, launch)
			if err != nil {
				t.Fatal(err)
			}
			stopObserver()
			if observer.Err() == nil || work.Err() != nil {
				t.Fatal("observer canceled original startup")
			}
			cancel()
			if _, _, err := desktopNativeStartupObservation(context.Background(), launch); !errors.Is(err, context.Canceled) {
				t.Fatal("fresh observer resurrected canceled startup", err)
			}
		})
	}
}
func TestDesktopNativeStartupExpiryCannotPublishOrAdopt(t *testing.T) {
	for _, kind := range []string{"external", "tor"} {
		for _, mode := range []string{"admission-lock", "proof-lock", "source-change"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				launch := startupContextLaunch(kind)
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
				defer cancel()
				lock, unlock := launch.externalLockForStartupTest()
				if mode == "admission-lock" {
					lock()
					done := make(chan error, 1)
					go func() { _, err := captureDesktopNativeStartup(ctx, launch); done <- err }()
					select {
					case err := <-done:
						if !errors.Is(err, context.DeadlineExceeded) {
							t.Error(err)
						}
					case <-time.After(time.Second):
						unlock()
						<-done
						t.Fatal("startup blocked past original budget")
					}
					unlock()
					if launch.startup.Load() != nil {
						t.Fatal("expired capture published startup")
					}
					return
				}
				if _, err := captureDesktopNativeStartup(ctx, launch); err != nil {
					t.Fatal(err)
				}
				if mode == "source-change" {
					if launch.external != nil {
						launch.external.expected.ConfigSHA256 = strings.Repeat("d", 64)
					} else {
						launch.tor.expected.ConfigSHA256 = strings.Repeat("d", 64)
					}
					if _, err := desktopNativeStartupEnvironment(ctx, launch, nil); err == nil || errors.Is(err, context.DeadlineExceeded) {
						t.Fatal("real source loss accepted or relabeled", err)
					}
					return
				}
				lock()
				done := make(chan error, 1)
				a := &app{}
				go func() {
					if kind == "tor" {
						_, err := a.waitDesktopTorProof(context.Background(), launch)
						done <- err
					} else {
						_, err := a.waitDesktopExternalProof(context.Background(), launch)
						done <- err
					}
				}()
				select {
				case err := <-done:
					if !errors.Is(err, context.DeadlineExceeded) {
						t.Error("proof lost original deadline", err)
					}
				case <-time.After(time.Second):
					unlock()
					<-done
					t.Fatal("proof renewed budget or blocked")
				}
				unlock()
				if launch.tor != nil && launch.tor.adopted != nil || launch.external != nil && launch.external.execution != "" {
					t.Fatal("expired proof adopted result")
				}
			})
		}
	}
}
func (launch *desktopNodeLaunch) externalLockForStartupTest() (func(), func()) {
	if launch.external != nil {
		return launch.external.mu.Lock, launch.external.mu.Unlock
	}
	return launch.tor.mu.Lock, launch.tor.mu.Unlock
}
