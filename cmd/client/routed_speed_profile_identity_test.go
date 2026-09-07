package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRoutedSpeedCancelsWhenEitherHopProfileChanges(t *testing.T) {
	for _, route := range []string{"single", "entry", "exit", "pair"} {
		for _, change := range []string{"credential", "policy", "removed", "other-hop"} {
			if route == "single" && change == "other-hop" { continue }
			t.Run(route+"/"+change, func(t *testing.T) {
				started := make(chan struct{}, 2)
				a, handle, body := routedSpeedPathFixture(t, route, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					started <- struct{}{}
					<-r.Context().Done()
				}))
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				done := make(chan *httptest.ResponseRecorder, 1)
				go func() {
					w := httptest.NewRecorder()
					handle(w, httptest.NewRequest(http.MethodPost, "/speed", strings.NewReader(body)).WithContext(ctx))
					done <- w
				}()
				select {
				case <-started:
				case w := <-done: t.Fatalf("measurement did not start: %d %s", w.Code, w.Body.String())
				case <-ctx.Done(): t.Fatal("measurement did not reach endpoint")
				}
				index := 1
				if route == "entry" || route == "pair" { index = 0 }
				a.mu.Lock()
				switch change {
				case "credential": a.profiles.Profiles[index].APIToken = "rotated"
				case "policy": a.profiles.Profiles[index].IPv6Mode = "off"
				case "removed": a.profiles.Profiles = append(a.profiles.Profiles[:index], a.profiles.Profiles[index+1:]...)
				case "other-hop": a.profiles.Profiles[1-index].APIToken = "other-hop-rotated"
				}
				a.mu.Unlock()
				select {
				case w := <-done:
					if w.Code != http.StatusConflict { t.Fatalf("status=%d body=%s", w.Code, w.Body.String()) }
				case <-time.After(time.Second): cancel(); <-done; t.Fatal("stale profile kept transferring")
				}
				if !a.state.Connected { t.Fatal("measurement cleanup stopped the VPN") }
			})
		}
	}
}

func TestRoutedSpeedRejectsProfileReplacedBeforeObserverStarts(t *testing.T) {
	a, p, session := asyncPathFixture(t, "http://10.77.0.1:8787")
	graph, _ := getActiveMultihopGraph(a)
	a.profiles.Profiles[1].APIToken = "replacement"
	_, stop, _, err := routedSpeedPathContext(context.Background(), a, a.state, graph, session.ID, p)
	if stop != nil { stop() }
	if err == nil { t.Fatal("captured stale profile accepted before first transfer") }
}
