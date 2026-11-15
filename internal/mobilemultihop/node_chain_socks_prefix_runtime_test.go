package mobilemultihop

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// Actual authenticated HTTP/TLS proof peers; the native transport/manager
// boundary remains the existing explicit shared component fixture.
func TestNodeChainSOCKSPrefixRuntimeRetainsEveryProof(t *testing.T) {
	for _, count := range []int{2, 6} {
		for _, authentication := range []string{"password", "none"} {
			t.Run(fmt.Sprintf("%s/%d", authentication, count), func(t *testing.T) {
				source, err := NewNodeChainSOCKSSource(startJSON(t, nodeChainSOCKSPrefixFixture(t, count, "wg", "", authentication)))
				if err != nil {
					t.Fatal(err)
				}
				runtime, engine := newNodeChainSOCKSRuntimeSourceFixture(t, source)
				if err := runtime.Run(t.Context(), engine); err != nil {
					t.Fatal(err)
				}
				got := runtime.Progress()
				if !got.Ready || !got.Complete || !got.DNSProven || !got.PublicProven || len(got.Prefixes) != count+2 {
					t.Fatal("full ordered proof absent", got)
				}
				if count == 6 && authentication == "password" {
					engine.mu.Lock()
					engine.dead = count - 1
					engine.mu.Unlock()
					deadline := time.Now().Add(7 * time.Second)
					for time.Now().Before(deadline) && runtime.HealthyContext(t.Context()) == nil {
						time.Sleep(10 * time.Millisecond)
					}
					if runtime.HealthyContext(t.Context()) == nil || runtime.Progress().Ready {
						t.Fatal("retained observer lost original later prefix death")
					}
				}

			})
		}
	}
	for position := 0; position < 6; position++ {
		t.Run(fmt.Sprintf("refuse-prefix-%d", position), func(t *testing.T) {
			source, err := NewNodeChainSOCKSSource(startJSON(t, nodeChainSOCKSPrefixFixture(t, 6, "wg", "", "password")))
			if err != nil {
				t.Fatal(err)
			}
			runtime, engine := newNodeChainSOCKSRuntimeSourceFixture(t, source)
			engine.mu.Lock()
			engine.wrong = position
			engine.mu.Unlock()
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			if err := runtime.Run(ctx, engine); err == nil || runtime.Progress().Ready {
				t.Fatal("wrong earlier paired identity accepted", position)
			}
		})
	}
}
