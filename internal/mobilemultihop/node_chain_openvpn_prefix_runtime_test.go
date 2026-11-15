package mobilemultihop

import (
	"context"
	"fmt"
	"net"
	"router-vpn/internal/nativeopenvpn"
	"testing"
)

func TestNodeChainOpenVPNPrefixRuntimeOriginalObservation(t *testing.T) {
	for _, count := range []int{2, 6} {
		for _, network := range []string{"tcp", "udp"} {
			t.Run(fmt.Sprintf("%s-%d", network, count), func(t *testing.T) {
				chain, err := NewNodeChain(startJSON(t, nodeChainOpenVPNPrefixFixture(t, count, "wg", network, "")))
				if err != nil {
					t.Fatal(err)
				}
				actual := newNodeChainTestEngine(t, chain)
				capture, err := chain.OpenVPNMiddleCapture()
				if err != nil {
					t.Fatal(err)
				}
				native := &nodeChainOpenVPNObserver{NodeChainEngine: actual, state: nativeopenvpn.PacketObservation{Remote: nativeopenvpn.RemoteReceipt{Remote: capture.Remote, Generation: 1, ConnectedAt: 1}, MTU: uint32(capture.ConfiguredMTU)}}
				if err := chain.Run(t.Context(), native); err != nil {
					t.Fatal(err)
				}
				progress := chain.Progress()
				if !progress.Ready || !progress.Complete || !progress.PublicProven || !progress.DNSProven || len(progress.Prefixes) != count+2 {
					t.Fatal("original complete proof inventory absent", progress)
				}
				for _, p := range progress.Prefixes {
					if !p.Proven {
						t.Fatal("original prefix omitted", p)
					}
				}
				native.state.Remote.Generation++
				if chain.HealthyContext(t.Context()) == nil || chain.Progress().Ready {
					t.Fatal("reconnected middle renewed original complete proof")
				}
			})
		}
	}
	for position := 0; position < 8; position++ {
		t.Run(fmt.Sprintf("generation-during-prefix-%d", position), func(t *testing.T) {
			chain, err := NewNodeChain(startJSON(t, nodeChainOpenVPNPrefixFixture(t, 6, "wg", "udp", "")))
			if err != nil {
				t.Fatal(err)
			}
			actual := newNodeChainTestEngine(t, chain)
			capture, _ := chain.OpenVPNMiddleCapture()
			native := &nodeChainOpenVPNObserver{NodeChainEngine: actual, state: nativeopenvpn.PacketObservation{Remote: nativeopenvpn.RemoteReceipt{Remote: capture.Remote, Generation: 1, ConnectedAt: 1}, MTU: uint32(capture.ConfiguredMTU)}}
			actual.beforeDial = func(_ context.Context, tag string) (net.Conn, bool) {
				if tag == chain.proofs[position].Tag {
					native.state.Remote.Generation++
				}
				return nil, false
			}
			if err := chain.Run(t.Context(), native); err == nil || chain.Progress().Ready {
				t.Fatal("prefix reproof adopted changed original connected generation", position)
			}
		})
	}
}
