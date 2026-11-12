//go:build routervpn_server_chain_acceptance

package mobilemultihop

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestNodeChainServerCarrierLinuxReadOnlyOriginalRoute(t *testing.T) {
	// No packet is sent and no network/interface/namespace is mutated. This
	// witnesses only Linux route acquisition, not an encrypted/native path.
	original := serverCarrierPolicyFixture(t, "wg", "", 0, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	carrier, err := NewNodeChainServerCarrierContext(ctx, ctx, original.sourceJSON)
	if carrier != nil {
		defer func() {
			cleanup, done := context.WithTimeout(context.Background(), time.Second)
			defer done()
			if err := carrier.CloseContext(cleanup); err != nil {
				t.Error(err)
			}
		}()
	}
	if err != nil {
		t.Fatal("read-only native route capture", err)
	}
	if carrier.snapshot.InterfaceIndex <= 0 || carrier.snapshot.InterfaceName == "" || carrier.snapshot.SourceAddress == "" || carrier.snapshot.NamespaceInode == 0 || !strings.HasPrefix(carrier.target.Host, "198.51.100.") {
		t.Fatal("native route omitted original identity")
	}
	if err := carrier.CurrentContext(ctx); err != nil {
		t.Fatal(err)
	}
}
