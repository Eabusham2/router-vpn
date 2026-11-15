package mobilemultihop

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func socksExecutionFixture(t *testing.T, mode, authentication, execution string) (*NodeChainSOCKSSource, *NodeChainExecutionPreparation, NodeChainExecutionSource) {
	t.Helper()
	original, server, capture := socksServerFixture(t, mode, authentication)
	prep, err := NewNodeChainSOCKSExecutionPreparation(original, execution)
	if err != nil {
		t.Fatal("typed SOCKS preparation", err)
	}
	request := capture.Request.Clone()
	key, err := original.pair.nodes[0].PacketClientPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	request.LocalPacketPublicKeys = []string{key}
	request.Peer = "10.80.0.2"
	request.Port = 32003
	return original, prep, NodeChainExecutionSource{Schema: 3, Execution: execution, LocalSource: original.sourceJSON, Server: server.Descriptor(), Request: request, FirstPort: 32000, LastPort: 32007}
}
func TestNodeChainSOCKSExecutionPreservesOriginalAssociationAndPrivateFront(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, auth := range []string{"password", "none"} {
			for _, execution := range []string{"server", "auto"} {
				t.Run(mode+"/"+auth+"/"+execution, func(t *testing.T) {
					original, prep, source := socksExecutionFixture(t, mode, auth, execution)
					retained, err := prep.OriginalSOCKSSource()
					if err != nil || retained != original || prep.local.socksSource != original || prep.local.nodes[0] != original.pair.nodes[0] || prep.local.nodes[1] != nil || prep.local.nodes[2] != original.pair.nodes[1] {
						t.Fatal("preparation replaced original source or member owners", err)
					}
					if _, err := NewNodeChainExecutionPreparation(prep.LocalSource(), execution); err == nil {
						t.Fatal("generic preparation admitted schema3")
					}
					if _, err := ParseNodeChainExecutionPreparation(prep.Source()); err == nil {
						t.Fatal("generic restoration admitted schema3")
					}
					if _, err := NewNodeChainExecutionPolicy(startJSON(t, source)); err == nil {
						t.Fatal("generic policy admitted schema3")
					}
					reopened, err := ParseNodeChainSOCKSExecutionPreparation(prep.Source())
					if err != nil || reopened.Config() != prep.Config() || reopened.socks.source == original {
						t.Fatal("fresh typed construction lost independent source ownership", err)
					}
					policy, err := NewNodeChainSOCKSExecutionPolicy(prep, startJSON(t, source))
					if err != nil {
						t.Fatal("typed execution policy", err)
					}
					if _, err := policy.LaunchInput(); err == nil {
						t.Fatal("typed source escaped through generic native launch")
					}
					projection, err := prep.BindExecution(policy)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := reopened.BindExecution(policy); err == nil {
						t.Fatal("same-content preparation borrowed original execution binding")
					}
					before, closed, after := externalTestRead(t, original.config), externalTestRead(t, prep.Config()), externalTestRead(t, projection.Config())
					for _, proof := range original.metadata.Proofs {
						if !reflect.DeepEqual(externalTestFind(t, before, proof.Tag), externalTestFind(t, closed, proof.Tag)) || !reflect.DeepEqual(externalTestFind(t, before, proof.Tag), externalTestFind(t, after, proof.Tag)) {
							t.Fatal("execution changed an original native member")
						}
					}
					if closed["route"].(map[string]any)["final"] != NodeChainExecutionGateTag || after["route"].(map[string]any)["final"] != NodeChainExecutionGateTag {
						t.Fatal("preparation or projection opened application without native proof")
					}
					middle, final := externalTestFind(t, after, original.metadata.Proofs[1].Tag), externalTestFind(t, after, original.metadata.Proofs[2].Tag)
					if middle["type"] != "socks" || middle["udp_over_tcp"] != nil || final["udp_over_tcp"] != nil || middle["detour"] != original.metadata.Proofs[0].Tag || final["detour"] != original.metadata.Proofs[1].Tag {
						t.Fatal("SOCKS association was converted into CONNECT/UoT")
					}
					front := externalTestFind(t, after, policy.serverProofs[2].Tag)
					if front["type"] != "socks" || front["detour"] != original.metadata.Proofs[0].Tag || front["udp_over_tcp"].(map[string]any)["version"] != float64(2) || front["username"] != source.Request.Users[1].Username || front["password"] != source.Request.Users[1].Password {
						t.Fatal("separate private front lost original lease credentials/UoT contract")
					}
					physical, err := policy.PhysicalEgress()
					if err != nil || !reflect.DeepEqual(physical, original.metadata.Physical) {
						t.Fatal("execution added physical SOCKS/relay authority", err)
					}
					for _, choice := range []string{"local", "server"} {
						dns, err := projection.DNSCapture(choice)
						if err != nil || dns.DNS.FinalTag != SelectorTag || dns.DNS.ResolverTag != original.metadata.DNS.ResolverTag {
							t.Fatal("selected DNS source changed", err)
						}
					}
				})
			}
		}
	}
}

type socksExecutionObserverFixture struct {
	source  *NodeChainSOCKSSource
	seen    int
	failure error
	hook    func()
}

func (e *socksExecutionObserverFixture) ObserveSOCKSExecutionContext(ctx context.Context, source *NodeChainSOCKSSource) error {
	e.seen++
	if e.hook != nil {
		e.hook()
	}
	if source != e.source {
		return errors.New("foreign original SOCKS source")
	}
	return e.failure
}
func TestNodeChainSOCKSExecutionRejectsChangedOriginalAuthority(t *testing.T) {
	for _, fault := range []string{"foreign-source", "foreign-runtime", "copied-binding", "missing-observer", "foreign-observer", "failed-observer", "cancelled", "replaced-during-observer", "wrong-family", "wrong-request", "borrowed-preparation"} {
		t.Run(fault, func(t *testing.T) {
			original, p, source := socksExecutionFixture(t, "wg", "password", "server")
			other, err := NewNodeChainSOCKSSource(original.sourceJSON)
			if err != nil {
				t.Fatal(err)
			}
			observer := &socksExecutionObserverFixture{source: original}
			switch fault {
			case "foreign-source":
				p.socks.source = other
			case "foreign-runtime":
				runtime, err := NewNodeChainSOCKSRuntime(other)
				if err != nil {
					t.Fatal(err)
				}
				p.local = runtime.chain
			case "copied-binding":
				copy := *p.socks
				p.socks = &copy
			case "missing-observer":
				if p.observeSOCKSExecutionContext(context.Background(), struct{}{}) == nil {
					t.Fatal("missing native association observer admitted")
				}
				return
			case "foreign-observer":
				observer.source = other
			case "failed-observer":
				observer.failure = errors.New("original association retired")
			case "cancelled":
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				if p.observeSOCKSExecutionContext(ctx, observer) == nil || observer.seen != 0 {
					t.Fatal("cancelled observation ran")
				}
				return
			case "replaced-during-observer":
				observer.hook = func() { p.socks.source = other }
			case "wrong-family":
				source.Server.Schema = 4
				if _, err := NewNodeChainSOCKSExecutionPolicy(p, startJSON(t, source)); err == nil {
					t.Fatal("CONNECT descriptor borrowed SOCKS owner")
				}
				return
			case "wrong-request":
				source.Request.Schema = 4
				if _, err := NewNodeChainSOCKSExecutionPolicy(p, startJSON(t, source)); err == nil {
					t.Fatal("CONNECT request borrowed SOCKS owner")
				}
				return
			case "borrowed-preparation":
				policy, err := NewNodeChainSOCKSExecutionPolicy(p, startJSON(t, source))
				if err != nil {
					t.Fatal(err)
				}
				replacement, err := NewNodeChainSOCKSExecutionPreparation(other, "server")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := replacement.BindExecution(policy); err == nil {
					t.Fatal("foreign preparation acquired original projection")
				}
				return
			}
			if p.observeSOCKSExecutionContext(context.Background(), observer) == nil {
				t.Fatal("changed original authority accepted")
			}
		})
	}
	original, p, _ := socksExecutionFixture(t, "wg", "password", "auto")
	e := &socksExecutionObserverFixture{source: original}
	if err := p.observeSOCKSExecutionContext(context.Background(), e); err != nil || e.seen != 1 {
		t.Fatal("original native observer omitted", err)
	}
}

func TestNodeChainSOCKSExecutionDoesNotBroadenUnimplementedFamilies(t *testing.T) {
	input := nodeChainSOCKSPrefixFixture(t, 2, "wg", "", "password")
	longer, err := NewNodeChainSOCKSSource(startJSON(t, input))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewNodeChainSOCKSExecutionPreparation(longer, "server"); err == nil {
		t.Fatal("longer local source borrowed trio-only server authority")
	}
	original, _, _ := socksExecutionFixture(t, "wg", "password", "server")
	for _, execution := range []string{"local", "unsupported", ""} {
		if _, err := NewNodeChainSOCKSExecutionPreparation(original, execution); err == nil {
			t.Fatal("unselected execution acquired typed preparation")
		}
	}
}
