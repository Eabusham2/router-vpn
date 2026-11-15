package mobilemultihop

import (
	"context"
	"fmt"
	"net"
	"testing"
)

func TestNodeChainImportedSSPrefixCompleteRuntime(t *testing.T) {
	for _, count := range []int{2, 6} {
		for _, hostname := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d-hostname-%t", count, hostname), func(t *testing.T) {
				chain, err := NewNodeChain(startJSON(t, nodeChainImportedSSPrefixFixture(t, count, "wg", NativeStartLayerMethod, hostname)))
				if err != nil {
					t.Fatal(err)
				}
				engine := newNodeChainTestEngine(t, chain)
				if err = chain.Run(t.Context(), engine); err != nil {
					t.Fatal(err)
				}
				p := chain.Progress()
				if !p.Ready || !p.DNSProven || !p.PublicProven || len(p.Prefixes) != count+2 {
					t.Fatal("complete original imported path not proved", p)
				}
				for _, prefix := range p.Prefixes {
					if !prefix.Proven {
						t.Fatal("original member omitted")
					}
				}
				engine.mu.Lock()
				engine.identity.NetworkID = "foreign-network"
				engine.mu.Unlock()
				if chain.HealthyContext(t.Context()) == nil || chain.Progress().Ready {
					t.Fatal("foreign network renewed original imported owner")
				}
			})
		}
	}
	for position := 0; position < 8; position++ {
		t.Run(fmt.Sprintf("original-network-during-prefix-%d", position), func(t *testing.T) {
			chain, err := NewNodeChain(startJSON(t, nodeChainImportedSSPrefixFixture(t, 6, "wg", NativeStartLayerMethod, false)))
			if err != nil {
				t.Fatal(err)
			}
			engine := newNodeChainTestEngine(t, chain)
			engine.beforeDial = func(_ context.Context, tag string) (net.Conn, bool) {
				if tag == chain.proofs[position].Tag {
					engine.mu.Lock()
					engine.identity.NetworkID = "foreign-network"
					engine.mu.Unlock()
				}
				return nil, false
			}
			if chain.Run(t.Context(), engine) == nil || chain.Progress().Ready {
				t.Fatal("original prefix proof admitted replacement network", position)
			}
		})
	}
}
