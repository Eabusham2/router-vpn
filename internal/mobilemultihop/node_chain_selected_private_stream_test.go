package mobilemultihop

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/multihoprelay"
)

func TestSelectedPairedStreamOriginal(t *testing.T) {
	t.Run("recursive", testSelectedPairedStreamRecursive)
	layout := nodeChainImportedLayout{"selected-private-stream", 4, []int{1}}
	for _, execution := range []string{"server", "auto"} {
		t.Run(execution, func(t *testing.T) {
			original, prep, src := multipleImportedExecutionFixture(t, layout, "wg", "", execution, "")
			policy, e := NewNodeChainMultipleImportedExecutionPolicy(prep, startJSON(t, src))
			if e != nil || policy == nil {
				t.Fatal("operator private-stream policy", e)
			}
			member := src.Server.Members[1]
			if !original.selectedPrivateStream(2) || !src.Server.PrivateStreamAt(2) || member.NodeID != original.proofs[2].NodeID || member.SourceSHA256 != original.proofs[2].SourceSHA256 || member.StreamIdentitySHA256 == "" || member.ClientPublicKey != "" || member.ServerPublicKey != "" || !slices.Equal(src.Request.LocalPacketPositions, []int{0}) {
				t.Fatal("private stream became another packet or lost its identity")
			}
			var originalSource NodeChainSource
			if exactJSON([]byte(original.sourceJSON), &originalSource, NodeChainInputLimit) != nil {
				t.Fatal("original")
			}
			localKey, _, e := chainCompanionKeys(originalSource.IdentitySources[2], original.nodes[2].profile)
			if e != nil {
				t.Fatal(e)
			}
			entryKey, entryRemote, e := chainCompanionKeys(originalSource.IdentitySources[0], original.nodes[0].profile)
			if e != nil {
				t.Fatal(e)
			}
			exitKey, _, e := chainCompanionKeys(originalSource.IdentitySources[3], original.nodes[3].profile)
			if e != nil {
				t.Fatal(e)
			}
			for _, modify := range []func(*multihoprelay.NodeChainMember){
				func(m *multihoprelay.NodeChainMember) { m.NodeID = original.proofs[0].NodeID },
				func(m *multihoprelay.NodeChainMember) { m.SourceSHA256 = original.proofs[1].SourceSHA256 },
				func(m *multihoprelay.NodeChainMember) { m.StreamIdentitySHA256 = externalDigest([]byte(localKey)) },
				func(m *multihoprelay.NodeChainMember) { m.StreamIdentitySHA256 = externalDigest([]byte(entryKey)) },
				func(m *multihoprelay.NodeChainMember) { m.StreamIdentitySHA256 = externalDigest([]byte(entryRemote)) },
				func(m *multihoprelay.NodeChainMember) { m.StreamIdentitySHA256 = externalDigest([]byte(exitKey)) },
				func(m *multihoprelay.NodeChainMember) { m.ClientPublicKey = localKey },
				func(m *multihoprelay.NodeChainMember) { m.NodeKind = "external" },
				func(m *multihoprelay.NodeChainMember) { m.StartLayer = "aes-256-gcm" },
			} {
				foreign := src
				foreign.Server = src.Server.Clone()
				foreign.Request = src.Request.Clone()
				modify(&foreign.Server.Members[1])
				foreign.Request.DescriptorSHA256, _ = foreign.Server.Digest()
				if got, e := NewNodeChainMultipleImportedExecutionPolicy(prep, startJSON(t, foreign)); e == nil || got != nil {
					t.Fatal("changed original private stream acquired selection")
				}
			}
		})
	}
}

func selectedPrivateStreamLayout(n, position int) nodeChainImportedLayout {
	var imported []int
	for i := 1; i < n-1; i++ {
		if i != position {
			imported = append(imported, i)
		}
	}
	return nodeChainImportedLayout{"selected-private-stream", n, imported}
}

func TestSelectedPairedStreamDepth(t *testing.T) {
	for n := 4; n <= NodeChainExtendedLocalMaximumNodes; n++ {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			position := n - 2
			if n%2 != 0 && n != 9 {
				position = 2
			}
			layout := selectedPrivateStreamLayout(n, position)
			original, prep, source := multipleImportedExecutionFixture(t, layout, "wg", "", "server", "")
			d := source.Server
			if original.selectedPrivateStreamPosition() != position || d.PrivateStreamPosition() != position || !slices.Equal(source.Request.LocalPacketPositions, []int{0}) {
				t.Fatal("original position or packet inventory changed")
			}
			launch, err := original.LaunchInput()
			if err != nil {
				t.Fatal(err)
			}
			reopened, err := ParseNodeChainLaunchInput(launch)
			if err != nil || reopened.SourceSHA256() != original.SourceSHA256() || reopened.selectedPrivateStreamPosition() != position {
				t.Fatal("changed Local reopen", err)
			}
			replayed, err := ParseNodeChainMultipleImportedExecutionPreparation(prep.Source())
			if err != nil || replayed.ConfigSHA256() != prep.ConfigSHA256() {
				t.Fatal("changed selected reopen", err)
			}
			host := "10.80.0.1"
			requestSize, err := nodeChainStatusRequest(source.Request, strings.Repeat("a", 64))
			if err != nil {
				t.Fatal(err)
			}
			capacity := multihoprelay.CheckNodeChainLeaseResponseCapacity(d, source.Request, host)
			policy, err := NewNodeChainMultipleImportedExecutionPolicy(prep, startJSON(t, source))
			oversized := len(requestSize) > multihoprelay.NodeChainLeaseRequestMaximumBytes || capacity != nil
			if oversized {
				if policy != nil || !errors.Is(err, errNodeChainControlCapacity) {
					t.Fatal("request or Ready receipt exceeded capacity without its original refusal", err)
				}
			} else {
				if err != nil || policy == nil {
					t.Fatal("valid original failed before its actual wire limits", err)
				}
				projection, err := prep.BindExecution(policy)
				if err != nil {
					t.Fatal("original selected graph did not bind", err)
				}
				if n == 5 || n == 9 || n == 16 {
					bound, err := projection.MTUPlan()
					if err != nil || len(bound.Prefixes) != n {
						t.Fatal("selected MTU inventory lost an original prefix", err)
					}
					if plan, err := projection.PlanForMTU(projection.Config(), bound.Original); err != nil || plan == nil {
						t.Fatal("original configured MTU bound failed", err)
					}
					if plan, err := projection.PlanForMTU(projection.Config(), bound.Ceiling+1); err == nil || plan != nil {
						t.Fatal("selected execution accepted a larger MTU")
					}
				}
			}
			now := time.Now().UTC()
			descriptor, err := d.Digest()
			if err != nil {
				t.Fatal(err)
			}
			c := multihoprelay.NodeChainCapture{Schema: 1, Request: source.Request, Source: d, RegistrySHA256: descriptor, OwnerID: strings.Repeat("a", 64), Peer: source.Request.Peer, Host: host, BootstrapDeadline: now.Add(time.Minute)}
			if err = c.Validate(); err != nil {
				t.Fatal(err)
			}
			cd, err := c.Digest()
			if err != nil {
				t.Fatal(err)
			}
			nonce := strings.Repeat("b", 64)
			receipt := multihoprelay.NodeChainReceipt{Schema: 1, SessionID: c.Request.SessionID, OwnerID: c.OwnerID, Peer: c.Peer, SourceSHA256: d.SourceSHA256, RegistrySHA256: descriptor, DNSPolicySHA256: d.DNSPolicySHA256, CaptureSHA256: cd, Nonce: nonce, Sequence: 1, HeartbeatAt: now.UnixMilli(), ProofAt: now.UnixMilli(), Phase: multihoprelay.NodeChainReady, FrontReady: true, TrafficAllowed: true, DNSProven: true, PublicProven: true}
			for _, m := range d.Members {
				receipt.Prefixes = append(receipt.Prefixes, multihoprelay.NodeChainPrefixReceipt{Position: m.Position, ProfileID: m.ProfileID, NodeID: m.NodeID, Mode: m.Mode, NodeKind: m.NodeKind, ProofKind: m.ProofKind, SourceSHA256: m.SourceSHA256, Proven: true, ResponseMS: 1})
			}
			if err = multihoprelay.ValidateNodeChainReceipt(receipt, c, nonce, now, now); err != nil {
				t.Fatal("all original receipt positions", err)
			}
			raw, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			receipt.Prefixes[position-1].SourceSHA256 = d.Members[0].SourceSHA256
			if multihoprelay.ValidateNodeChainReceipt(receipt, c, nonce, now, now) == nil {
				t.Fatal("a preceding import acquired the private member's receipt")
			}
			t.Logf("depth=%d private=%d status_request=%d receipt_body=%d capacity_refused=%t", n, position, len(requestSize), len(raw), oversized)
		})
	}
}

func TestSelectedPairedStreamRefusesChangedFamily(t *testing.T) {
	_, _, source := multipleImportedExecutionFixture(t, selectedPrivateStreamLayout(9, 4), "wg", "", "auto", "")
	for name, change := range map[string]func(*multihoprelay.NodeChainDescriptor){
		"paired-first": func(d *multihoprelay.NodeChainDescriptor) {
			d.Members[0], d.Members[3] = d.Members[3], d.Members[0]
			d.Members[0].Position, d.Members[3].Position = 1, 4
		},
		"reused-stream-companion": func(d *multihoprelay.NodeChainDescriptor) {
			member := d.Members[3]
			member.Position, member.ProfileID = 3, "second-paired"
			member.NodeID = strings.Repeat("d", 64)
			member.SourceSHA256 = strings.Repeat("e", 64)
			member.StreamIdentitySHA256 = d.Members[3].StreamIdentitySHA256
			d.Members[2] = member
		},
		"layered-final":   func(d *multihoprelay.NodeChainDescriptor) { d.Members[len(d.Members)-1].StartLayer = "aes-256-gcm" },
		"different-entry": func(d *multihoprelay.NodeChainDescriptor) { d.EntryMode = "awg2-strong" },
		"packet-interior": func(d *multihoprelay.NodeChainDescriptor) {
			d.Members[2].Mode = "wg"
			d.Members[2].ClientPublicKey = source.Request.LocalPacketPublicKeys[0]
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := source.Server.Clone()
			change(&changed)
			if changed.Validate() == nil {
				t.Fatal("changed remote graph gained a private stream role")
			}
		})
	}
	// Use 97 distinct original inputs. A repeat at this boundary would also
	// fail the ordinary duplicate-ID check, obscuring the physical depth test.
	tooLong, local := multipleImportedServerPlanFixture(t, selectedPrivateStreamLayout(NodeChainExtendedLocalMaximumNodes+1, 94), "wg", "")
	if p, err := NewNodeChainMultipleImportedServerPlan(startJSON(t, tooLong)); err == nil || p != nil {
		t.Fatal("97 original nodes acquired a remote operator plan")
	}
	if c, err := NewNodeChain(startJSON(t, local)); err == nil || c != nil {
		t.Fatal("97 original nodes acquired a Local source")
	}
}

func testSelectedPairedStreamRecursive(t *testing.T) {
	for _, layout := range []nodeChainImportedLayout{
		{"selected-private-stream", 5, []int{1}},
		{"selected-private-stream", 7, []int{1, 3}},
		{"selected-private-stream", 10, []int{1, 2, 5, 7}},
	} {
		t.Run(fmt.Sprint(layout.count), func(t *testing.T) {
			local, prep, source := multipleImportedExecutionFixture(t, layout, "wg", "", "auto", "")
			policy, err := NewNodeChainMultipleImportedExecutionPolicy(prep, startJSON(t, source))
			if err != nil || !slices.Equal(source.Request.LocalPacketPositions, []int{0}) {
				t.Fatal("private stream became a packet or failed source validation", err)
			}
			for i := 1; i < layout.count-1; i++ {
				private := !slices.Contains(layout.positions, i)
				if source.Server.PrivateStreamAt(i) != private || local.selectedPrivateStream(i) != private || !prep.SupportsCompareLocalResponseCandidate(i) {
					t.Fatal("original private/public response stop lost", i)
				}
			}
			projection, err := prep.BindExecution(policy)
			if err != nil {
				t.Fatal(err)
			}
			mtu, err := projection.MTUPlan()
			if err != nil || len(mtu.Prefixes) != layout.count {
				t.Fatal("exact recursive route lost an MTU prefix", err)
			}
			a, b := 0, 0
			for i, m := range source.Server.Members {
				if m.StreamIdentitySHA256 == "" {
					continue
				}
				if a == 0 {
					a = i
				} else {
					b = i
					break
				}
			}
			for _, field := range []string{"source", "identity", "companion", "reorder"} {
				foreign := source
				foreign.Server, foreign.Request = source.Server.Clone(), source.Request.Clone()
				x, y := &foreign.Server.Members[a], &foreign.Server.Members[b]
				switch field {
				case "source":
					y.SourceSHA256 = x.SourceSHA256
				case "identity":
					y.NodeID = x.NodeID
				case "companion":
					y.StreamIdentitySHA256 = x.StreamIdentitySHA256
				case "reorder":
					*x, *y = *y, *x
					x.Position, y.Position = a+1, b+1
				}
				foreign.Request.DescriptorSHA256, _ = foreign.Server.Digest()
				if got, err := NewNodeChainMultipleImportedExecutionPolicy(prep, startJSON(t, foreign)); got != nil || err == nil {
					t.Fatal("substituted private stream gained the original route", field)
				}
			}
		})
	}
}
