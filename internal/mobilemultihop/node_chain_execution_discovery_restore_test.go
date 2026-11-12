package mobilemultihop

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNodeChainExecutionDiscoveryRestoreKeepsOriginalPrivateProposal(t *testing.T) {
	o, e, original, requests := nodeChainExecutionDiscoveryTestFixture(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := o.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	expected, err := o.prep.BindExecution(original)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := o.PlanOriginalContext(ctx, original)
	if err != nil {
		t.Fatal(err)
	}
	if projection.Source() != original.Source() || projection.Config() != expected.Config() || !reflect.DeepEqual(projection.policy.Request(), original.Request()) || !reflect.DeepEqual(projection.policy.Front(), original.Front()) || requests.Load() != 2 || e.dials.Load() != e.closes.Load() {
		t.Fatal("restore changed original proposal or left discovery unjoined")
	}
	if _, err := o.PlanContext(ctx, "", 32003); err == nil {
		t.Fatal("original restore planning allowed a fresh substitute")
	}
	if err := o.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestNodeChainExecutionDiscoveryRestoreRejectsChangedOriginalSource(t *testing.T) {
	for _, fault := range []string{"missing-source", "changed-source", "pool", "peer", "dns", "late-network", "execution", "original-bytes"} {
		t.Run(fault, func(t *testing.T) {
			o, e, original, _ := nodeChainExecutionDiscoveryTestFixture(t, func(d *NodeChainExecutionDiscovery) {
				switch fault {
				case "missing-source":
					d.Sources[0].SourceSHA256 = strings.Repeat("a", 64)
				case "changed-source":
					d.Sources[0].Members[0].ProfileID = "changed"
				case "pool":
					d.LastPort++
				case "peer":
					d.Challenge.Peer = "10.80.0.3"
				case "dns":
					d.Sources[0].DNSPolicySHA256 = strings.Repeat("a", 64)
				}
			}, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if _, err := o.Discover(ctx); err != nil {
				t.Fatal(err)
			}
			if fault == "late-network" {
				e.mu.Lock()
				e.identity.NetworkID = "replacement"
				e.mu.Unlock()
			}
			if fault == "execution" || fault == "original-bytes" {
				source := original.source
				if fault == "execution" {
					source.Execution = "server"
				} else {
					source.LocalSource += " "
				}
				var err error
				original, err = NewNodeChainExecutionPolicy(startJSON(t, source))
				if err != nil {
					t.Fatal("independent changed source must remain structurally valid", err)
				}
			}
			if _, err := o.PlanOriginalContext(ctx, original); err == nil {
				t.Fatal("restoration substituted original source/discovery")
			}
		})
	}
}
