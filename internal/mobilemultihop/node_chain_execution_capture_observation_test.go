package mobilemultihop

import (
	"reflect"
	"testing"
)

func TestDesktopTypedExecutionSealRetainsOriginal(t *testing.T) {
	t.Run("optional exit copied in both observations", func(t *testing.T) {
		_, preparation, _ := desktopSOCKSExecutionFixture(t, "wg", "password", "linux", "auto")
		_, current := preparation.typedDesktopMetadata()
		current.ExternalFinal = &NodeChainExternalFinalMetadata{ProfileID: "original", ExpectedPublicIP: "192.0.2.1", SourceSHA256: "original-source"}
		preparation.rememberPreparationSeal()
		physical := preparation.socks.desktop.canonical
		derived := newTypedDesktopExecutionSeal(physical.original, physical.source, physical.native, physical.seal,
			physical.inputs, physical.kind, *current, physical.physical, physical.capture)
		derivedMatches := func() bool {
			return derived.matches(physical.original, physical.source, physical.native, physical.inputs, physical.kind, *current, physical.physical, physical.capture)
		}
		if !preparation.originalPreparationSeal.matches(preparation) || !derivedMatches() {
			t.Fatal("matching optional exit rejected")
		}
		current.ExternalFinal.SourceSHA256 = "replaced-source"
		if preparation.originalPreparationSeal.matches(preparation) || derivedMatches() {
			t.Fatal("mutating the current exit also changed a retained observation")
		}
	})
	for _, family := range []string{"socks", "connect"} {
		t.Run(family, func(t *testing.T) {
			var p *NodeChainExecutionPreparation
			if family == "socks" {
				_, p, _ = desktopSOCKSExecutionFixture(t, "wg", "password", "linux", "auto")
			} else {
				_, p = desktopCONNECTExecutionFixture(t, "wg", "https-connect", "linux", "auto")
			}
			original := p.originalPreparationSeal
			if original == nil || !original.matches(p) || p.validateCapture() != nil {
				t.Fatal("valid typed preparation was not retained")
			}
			p.originalPreparationSeal = nil
			want := p.captureSeal()
			p.originalPreparationSeal = original
			if want != p.captureSeal() || want != p.seal {
				t.Fatal("typed snapshot changed the original canonical seal")
			}
			t.Run("local packet and exact typed middle", func(t *testing.T) {
				c := p.local
				original := c.typedOriginal
				if original == nil || !original.matches(c) {
					t.Fatal("missing original typed runtime graph")
				}
				c.typedOriginal = nil
				canonical := c.captureSeal()
				c.typedOriginal = original
				if canonical != c.captureSeal() || canonical != c.seal {
					t.Fatal("typed runtime digest differs from its canonical original")
				}
				first := c.nodes[0]
				old := first.profile["id"]
				first.profile["id"] = "foreign-original-packet"
				if p.validateCapture() == nil {
					t.Fatal("changed packet retained its typed runtime")
				}
				first.profile["id"] = old
				index := len(c.nodes) - 2
				c.nodes[index] = first
				if p.validateCapture() == nil {
					t.Fatal("packet replaced the original typed middle")
				}
				c.nodes[index] = nil
				if p.validateCapture() != nil {
					t.Fatal("original graph was not restored")
				}
			})
			t.Run("original desktop derivation", func(t *testing.T) {
				var cached **nodeChainTypedDesktopExecutionSeal
				var original *DesktopPhysicalCapture
				var digest func() string
				if family == "socks" {
					d := p.socks.desktop
					cached, original, digest = &d.canonical, &d.capture, d.captureSeal
				} else {
					d := p.connect.desktop
					cached, original, digest = &d.canonical, &d.capture, d.captureSeal
				}
				saved := *cached
				if saved == nil {
					t.Fatal("missing original physical derivation")
				}
				*cached = nil
				canonical := digest()
				*cached = saved
				if digest() != canonical {
					t.Fatal("derived desktop seal differs from canonical source")
				}
				original.SelectedDNS.Detour += "changed"
				if digest() == canonical || p.validateCapture() == nil {
					t.Fatal("changed physical DNS kept original derivation")
				}
				original.SelectedDNS.Detour = saved.capture.SelectedDNS.Detour
			})
			copy := *p
			if original.matches(&copy) {
				t.Fatal("copied preparation acquired the original producer")
			}
			t.Run("foreign physical owner", func(t *testing.T) {
				var err error
				if family == "socks" {
					_, other, _ := desktopSOCKSExecutionFixture(t, "wg", "password", "linux", "auto")
					desktop := p.socks.desktop
					held := desktop.physical
					defer func() { desktop.physical = held }()
					desktop.physical = other.socks.desktop.physical
					_, err = p.SOCKSDesktopPhysicalPolicy()
				} else {
					_, other := desktopCONNECTExecutionFixture(t, "wg", "https-connect", "linux", "auto")
					desktop := p.connect.desktop
					held := desktop.physical
					defer func() { desktop.physical = held }()
					desktop.physical = other.connect.desktop.physical
					_, err = p.CONNECTDesktopPhysicalPolicy()
				}
				if err == nil {
					t.Fatal("a different preparation supplied the physical owner")
				}
			})
			_, metadata := p.typedDesktopMetadata()
			for _, fault := range []string{"prefix", "root", "external final", "physical", "dns", "capture", "request"} {
				t.Run(fault, func(t *testing.T) {
					switch fault {
					case "prefix":
						old := metadata.Prefixes[0]
						defer func() { metadata.Prefixes[0] = old }()
						metadata.Prefixes[0].Position++
					case "external final":
						old := metadata.ExternalFinal
						defer func() { metadata.ExternalFinal = old }()
						metadata.ExternalFinal = &NodeChainExternalFinalMetadata{ProfileID: "injected"}
					case "root":
						old := metadata.Roots[0]
						defer func() { metadata.Roots[0] = old }()
						metadata.Roots[0].Tag += "-other"
					case "physical":
						old := p.physical[0]
						defer func() { p.physical[0] = old }()
						p.physical[0] = PhysicalEgress{}
					case "dns":
						old := p.dns
						defer func() { p.dns = old }()
						p.dns.SelectedTag += "-other"
					case "capture":
						old := p.config
						defer func() { p.config = old }()
						p.config += " "
					case "request":
						old := p.source
						defer func() { p.source = old }()
						p.source.Execution = "server"
					}
					if original.matches(p) || p.captureSeal() == want || p.validateCapture() == nil {
						t.Fatal("changed original inputs kept their typed capture")
					}
				})
			}
		})
	}
}

func TestOrdinaryExecutionSealPreservesCanonicalInputs(t *testing.T) {
	p, policy, projection := nodeChainExecutionProjectionFixture(t)
	prepSeal, policySeal, projectionSeal := p.originalPreparationSeal, policy.originalSeal, projection.originalSeal
	if !prepSeal.matches(p) || !policySeal.matches(policy) || !projectionSeal.matches(projection) {
		t.Fatal("missing ordinary execution observation")
	}
	p.originalPreparationSeal, policy.originalSeal, projection.originalSeal = nil, nil, nil
	canonicalPrep, canonicalPolicy, canonicalProjection := p.captureSeal(), policy.captureSeal(), projection.captureSeal()
	p.originalPreparationSeal, policy.originalSeal, projection.originalSeal = prepSeal, policySeal, projectionSeal
	if canonicalPrep != p.captureSeal() || canonicalPolicy != policy.captureSeal() || canonicalProjection != projection.captureSeal() {
		t.Fatal("ordinary capture differs from its canonical encoding")
	}
	for _, graph := range []*NodeChain{p.local, policy.local} {
		old := graph.nodes[0].profile["id"]
		graph.nodes[0].profile["id"] = "other-packet-source"
		if graph == p.local && (prepSeal.localPacketCurrent(p) || p.validateCapture() == nil) ||
			graph == policy.local && (policySeal.localPacketCurrent(policy) || policy.validateCapture() == nil) {
			t.Fatal("changed original packet source kept an ordinary execution owner")
		}
		graph.nodes[0].profile["id"] = old
	}
	p.physical[0].Host += "-changed"
	if prepSeal.matches(p) || p.captureSeal() == canonicalPrep || p.validateCapture() == nil {
		t.Fatal("retained changed original physical capture")
	}
	policy.source.Server.Members[0].NodeID += "-changed"
	if policySeal.matches(policy) || policy.captureSeal() == canonicalPolicy || policy.validateCapture() == nil {
		t.Fatal("substituted server member kept the original execution")
	}
	policy.seal = policy.captureSeal()
	if policy.validateCapture() == nil {
		t.Fatal("recomputing a changed policy digest bypassed its request-to-descriptor validation")
	}
	projection.transition.AddedOutbounds[0] += " "
	if projectionSeal.matches(projection) || projection.captureSeal() == canonicalProjection || projection.validateCapture() == nil {
		t.Fatal("changed original transitions preserved their observation")
	}
}

// Each explicit metadata comparison must reject an independent change to
// every field. A new field without corresponding comparison fails this test.
func TestTypedOriginalMetadataFieldInventory(t *testing.T) {
	checkTypedOriginalMetadata(t, sameDesktopNodeChainMetadata)
	checkTypedOriginalMetadata(t, func(a, b NodeChainExternalFinalMetadata) bool {
		return sameDesktopNodeChainMetadata(DesktopNodeChainMetadata{ExternalFinal: &a}, DesktopNodeChainMetadata{ExternalFinal: &b})
	})
	checkTypedOriginalMetadata(t, sameNodeChainSOCKSSourceMetadata)
	checkTypedOriginalMetadata(t, sameNodeChainCONNECTSourceMetadata)
	checkTypedOriginalMetadata(t, sameNodeChainMTUPlan)
}

func checkTypedOriginalMetadata[T any](t *testing.T, equal func(T, T) bool) {
	t.Helper()
	var original T
	metadata := reflect.TypeOf(original)
	for i := 0; i < metadata.NumField(); i++ {
		t.Run(metadata.Name()+"/"+metadata.Field(i).Name, func(t *testing.T) {
			var changed T
			field := reflect.ValueOf(&changed).Elem().Field(i)
			for field.Kind() == reflect.Struct {
				field = field.Field(0)
			}
			switch field.Kind() {
			case reflect.String:
				field.SetString("changed")
			case reflect.Bool:
				field.SetBool(true)
			case reflect.Int:
				field.SetInt(1)
			case reflect.Pointer:
				field.Set(reflect.New(field.Type().Elem()))
			case reflect.Slice:
				field.Set(reflect.MakeSlice(field.Type(), 0, 0))
			default:
				t.Fatalf("add a mutation for %v", field.Type())
			}
			if equal(original, changed) || equal(changed, original) || !equal(changed, changed) {
				t.Fatal("metadata equality lost the original field")
			}
		})
	}
}
