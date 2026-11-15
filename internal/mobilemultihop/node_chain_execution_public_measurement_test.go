package mobilemultihop

import (
	"fmt"
	"reflect"
	"testing"
)

func importedPublicExecutionFixture(t *testing.T, mode, requested string) (*NodeChainExecutionPreparation, *NodeChainExecutionProjection) {
	t.Helper()
	source := nodeChainImportedExecutionFixtureSource(t, mode, "", requested)
	prep, err := NewNodeChainExecutionPreparation(source.LocalSource, requested)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewNodeChainExecutionPolicy(startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	projection, err := prep.BindExecution(policy)
	if err != nil {
		t.Fatal(err)
	}
	return prep, projection
}

func TestNodeChainExecutionImportedPublicRetainsOriginalCapture(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, requested := range []string{"server", "auto"} {
			t.Run(mode+"/"+requested, func(t *testing.T) {
				prep, projection := importedPublicExecutionFixture(t, mode, requested)
				original, middle := prep.local, prep.local.importedMiddle
				nodes := append([]*NodeProfile(nil), original.nodes...)
				source, config, dns := prep.Source(), prep.Config(), prep.dns
				_, wantIPv6, err := original.PublicMeasurementCapture()
				if err != nil {
					t.Fatal(err)
				}
				for _, selected := range []string{"local", "server"} {
					proofs, err := projection.ProofInventory(selected)
					if err != nil {
						t.Fatal(err)
					}
					tag, ipv6, err := projection.ImportedPublicMeasurementCapture(selected)
					if err != nil || tag != proofs[1].Tag || ipv6 != wantIPv6 {
						t.Fatal("original imported public capture lost selected tag/device policy", selected, err)
					}
				}
				if prep.local != original || original.importedMiddle != middle || !reflect.DeepEqual(nodes, original.nodes) || prep.Source() != source || prep.Config() != config || prep.dns != dns {
					t.Fatal("public capture replaced original source or selected DNS")
				}
			})
		}
	}
}

func TestNodeChainExecutionImportedPublicRejectsReplacement(t *testing.T) {
	for _, fault := range []string{"receipt", "source-replay", "preparation-copy", "entry-copy", "middle-copy", "middle-policy-copy", "config", "execution", "private-family", "typed-socks"} {
		t.Run(fault, func(t *testing.T) {
			prep, p := importedPublicExecutionFixture(t, "wg", "auto")
			selected := "local"
			switch fault {
			case "receipt":
				prep.importedPublic = nil
			case "source-replay":
				replacement, err := NewNodeChain(prep.LocalSource())
				if err != nil {
					t.Fatal(err)
				}
				if replacement == prep.local || replacement.SourceSHA256() != prep.local.SourceSHA256() {
					t.Fatal("equal-source replacement fixture invalid")
				}
				prep.local = replacement
			case "preparation-copy":
				copy := *prep
				p.preparation = &copy
			case "entry-copy":
				copy := *prep.local.nodes[0]
				prep.local.nodes[0] = &copy
			case "middle-copy":
				copy := *prep.local.importedMiddle
				prep.local.importedMiddle = &copy
			case "middle-policy-copy":
				copy := *prep.local.importedMiddle.policy
				prep.local.importedMiddle.policy = &copy
			case "config":
				prep.config += " "
			case "execution":
				selected = "auto"
			case "typed-socks":
				_, typedPrep, source := socksExecutionFixture(t, "wg", "password", "auto")
				policy, err := NewNodeChainSOCKSExecutionPolicy(typedPrep, startJSON(t, source))
				if err != nil {
					t.Fatal(err)
				}
				p, err = typedPrep.BindExecution(policy)
				if err != nil {
					t.Fatal(err)
				}
				if captureNodeChainExecutionImportedPublic(typedPrep) != nil {
					t.Fatal("typed SOCKS acquired generic SS receipt")
				}
			case "private-family":
				_, _, p = nodeChainExecutionProjectionFixture(t)
			}
			if tag, ipv6, err := p.ImportedPublicMeasurementCapture(selected); err == nil || tag != "" || ipv6 {
				t.Fatal("foreign generic public capture accepted", fault)
			}
		})
	}
}

func TestNodeChainExecutionImportedPublicPrefixCapture(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, count := range []int{2, 6} {
			t.Run(fmt.Sprintf("%s/%d", mode, count), func(t *testing.T) {
				source := nodeChainImportedPrefixExecutionSource(t, count, mode, "auto")
				prep, err := NewNodeChainExecutionPreparation(source.LocalSource, "auto")
				if err != nil {
					t.Fatal(err)
				}
				policy, err := NewNodeChainExecutionPolicy(startJSON(t, source))
				if err != nil {
					t.Fatal(err)
				}
				projection, err := prep.BindExecution(policy)
				if err != nil {
					t.Fatal(err)
				}
				for _, selected := range []string{"local", "server"} {
					proofs, err := projection.ProofInventory(selected)
					if err != nil {
						t.Fatal(err)
					}
					tag, _, err := projection.ImportedPublicMeasurementCapture(selected)
					if err != nil || tag != proofs[count].Tag || proofs[count].Kind != "public-path" || proofs[count].NodeID != "" {
						t.Fatal("original penultimate public prefix lost", err)
					}
				}
				replacement, err := NewNodeChain(prep.LocalSource())
				if err != nil {
					t.Fatal(err)
				}
				prep.local = replacement
				if _, _, err := projection.ImportedPublicMeasurementCapture("local"); err == nil {
					t.Fatal("replayed complete prefix borrowed original public owner")
				}
			})
		}
	}
}
