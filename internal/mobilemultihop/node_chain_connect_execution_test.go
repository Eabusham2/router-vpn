package mobilemultihop

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func connectExecutionPreparationFixture(t *testing.T, mode, protocol, execution string) (*NodeChainCONNECTSource, *NodeChainExecutionPreparation) {
	t.Helper()
	input := nodeChainCONNECTFixture(t, mode, protocol, "", NativeStartLayerMethod, "password")
	source, err := NewNodeChainCONNECTSource(startJSON(t, input))
	if err != nil {
		t.Fatal(err)
	}
	prep, err := NewNodeChainCONNECTExecutionPreparation(source, execution)
	if err != nil {
		t.Fatal(err)
	}
	return source, prep
}

func TestNodeChainCONNECTExecutionPreparationRetainsClosedOriginalTrio(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, protocol := range []string{"http-connect", "https-connect"} {
			for _, execution := range []string{"server", "auto"} {
				t.Run(mode+"/"+protocol+"/"+execution, func(t *testing.T) {
					source, p := connectExecutionPreparationFixture(t, mode, protocol, execution)
					got, err := p.OriginalCONNECTSource()
					if err != nil || got != source || p.local.connectSource != source || p.local.nodes[0] != source.pair.nodes[0] || p.local.nodes[2] != source.pair.nodes[1] || p.local.nodes[1] != nil {
						t.Fatal("typed preparation replaced original source/member pointers")
					}
					if p.SourceSHA256() == source.metadata.SourceSHA256 || p.ConfigSHA256() == source.metadata.ConfigSHA256 {
						t.Fatal("closed gate borrowed Local source/config receipt")
					}
					graph := externalTestRead(t, p.Config())
					route := graph["route"].(map[string]any)
					if route["final"] != NodeChainExecutionGateTag {
						t.Fatal("typed preparation opened application route")
					}
					selector := externalTestFind(t, graph, SelectorTag)
					if !reflect.DeepEqual(selector["outbounds"], []any{source.metadata.Proofs[2].Tag}) || selector["default"] != source.metadata.Proofs[2].Tag {
						t.Fatal("preparation guessed a server front")
					}
					for _, proof := range source.metadata.Proofs {
						before := externalTestFind(t, externalTestRead(t, source.config), proof.Tag)
						after := externalTestFind(t, graph, proof.Tag)
						if !reflect.DeepEqual(before, after) {
							t.Fatal("closed preparation changed original transport options")
						}
					}
					dns, err := p.DNSCapture()
					if err != nil || dns.DNS.FinalTag != SelectorTag || dns.SelectedTag != source.metadata.Proofs[2].Tag || dns.DNS.ResolverTag != source.metadata.DNS.ResolverTag {
						t.Fatal("closed preparation changed final selected DNS", err)
					}
					if _, err = NewNodeChain(p.LocalSource()); err == nil {
						t.Fatal("typed execution entered generic Local parser")
					}
					if _, err = NewNodeChainExecutionPreparation(p.LocalSource(), execution); err == nil {
						t.Fatal("typed execution entered generic preparation")
					}
					if _, err = ParseNodeChainExecutionPreparation(p.Source()); err == nil {
						t.Fatal("typed preparation entered generic source parser")
					}
					reopened, err := ParseNodeChainCONNECTExecutionPreparation(p.Source())
					if err != nil || reopened.Config() != p.Config() || reopened.connect.source == source {
						t.Fatal("new construction did not retain its own typed source", err)
					}
				})
			}
		}
	}
}

type connectExecutionObserverFixture struct {
	source  *NodeChainCONNECTSource
	seen    int
	hook    func()
	failure error
}

func (e *connectExecutionObserverFixture) ObserveCONNECTExecutionContext(ctx context.Context, source *NodeChainCONNECTSource) error {
	e.seen++
	if e.hook != nil {
		e.hook()
	}
	if source != e.source {
		return errors.New("foreign original source")
	}
	return e.failure
}

func TestNodeChainCONNECTExecutionPreparationRejectsChangedAuthority(t *testing.T) {
	for _, fault := range []string{"long", "local", "unsupported", "foreign-source", "foreign-runtime", "copied-binding", "missing-observer", "foreign-observer", "failed-observer", "cancelled", "replaced-during-observer"} {
		t.Run(fault, func(t *testing.T) {
			source, p := connectExecutionPreparationFixture(t, "wg", "https-connect", "server")
			if fault == "long" {
				input := nodeChainCONNECTPrefixFixture(t, 2, "wg", "https-connect", "", NativeStartLayerMethod, "password")
				long, err := NewNodeChainCONNECTSource(startJSON(t, input))
				if err != nil {
					t.Fatal(err)
				}
				if _, err = NewNodeChainCONNECTExecutionPreparation(long, "server"); err == nil {
					t.Fatal("long CONNECT acquired execution")
				}
				return
			}
			if fault == "local" || fault == "unsupported" {
				if _, err := NewNodeChainCONNECTExecutionPreparation(source, fault); err == nil {
					t.Fatal("unselected execution acquired preparation")
				}
				return
			}
			other, err := NewNodeChainCONNECTSource(source.sourceJSON)
			if err != nil {
				t.Fatal(err)
			}
			observer := &connectExecutionObserverFixture{source: source}
			switch fault {
			case "foreign-source":
				p.connect.source = other
			case "foreign-runtime":
				replacement, err := NewNodeChainCONNECTRuntime(other)
				if err != nil {
					t.Fatal(err)
				}
				p.local = replacement.chain
			case "copied-binding":
				copy := *p.connect
				p.connect = &copy
			case "missing-observer":
				if p.observeCONNECTExecutionContext(context.Background(), struct{}{}) == nil {
					t.Fatal("missing native observer acquired execution")
				}
				return
			case "foreign-observer":
				observer.source = other
			case "failed-observer":
				observer.failure = errors.New("original middle retired")
			case "cancelled":
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				if p.observeCONNECTExecutionContext(ctx, observer) == nil || observer.seen != 0 {
					t.Fatal("cancelled original observation ran")
				}
				return
			case "replaced-during-observer":
				observer.hook = func() { p.connect.source = other }
			}
			if p.observeCONNECTExecutionContext(context.Background(), observer) == nil {
				t.Fatal("changed native source/capture acquired execution authority")
			}
		})
	}
	source, p := connectExecutionPreparationFixture(t, "wg", "http-connect", "auto")
	e := &connectExecutionObserverFixture{source: source}
	if err := p.observeCONNECTExecutionContext(context.Background(), e); err != nil || e.seen != 1 {
		t.Fatal("original native observer was omitted", err)
	}
}
