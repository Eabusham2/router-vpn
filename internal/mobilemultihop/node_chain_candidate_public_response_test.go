package mobilemultihop

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
)

func TestNodeChainExternalFinalPublicCandidateSource(t *testing.T) {
	for _, count := range []int{3, 9, 96} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			input := startJSON(t, externalFinalSourceFixture(t, count, "home"))
			c, err := NewNodeChain(input)
			if err != nil {
				t.Fatal(err)
			}
			candidate := nodeChainIndependentImportedFixture(t, 116)
			inventory := candidateInventoryFixture(t, "original-import-catalog", candidate)
			if c.CandidatePrefixMeasurement(0) != hopmeasure.CandidateTCPMeasurement || c.CandidatePrefixMeasurement(count-1) != "" {
				t.Fatal("entry/final roles changed")
			}
			for pos := 1; pos < count-1; pos++ {
				if c.CandidatePrefixMeasurement(pos) != hopmeasure.CandidatePublicResponseMeasurement {
					t.Fatal("lost original stream", pos)
				}
			}
			pos := count - 2
			p, err := c.NewCandidatePlan(pos, inventory)
			if err != nil {
				t.Fatal(err)
			}
			if p.PublicResponseCandidateDepth(pos, p.prefix.ProfileID, p.prefix.Tag) != count || p.ResponseCandidateDepth(pos, p.prefix.ProfileID, p.prefix.Tag) != 0 || p.PacketCandidateDepth(pos, p.prefix.ProfileID, p.prefix.Tag) != 0 {
				t.Fatal("lost distinct scope")
			}
			prep, err := NewNodeChainCandidatePreparation(input, pos, inventory)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(prep.proofs, c.proofs[:pos+1]) || prep.ExtendedCandidateDepth() != count || prep.ExtendedPacketDepth() != 0 {
				t.Fatal("closed prefix changed original scope")
			}
			if count == 3 {
				retained, err := c.NewPublicCandidatePreparation(pos, inventory)
				if err != nil || retained.original != c || retained.Source() != prep.Source() || retained.CaptureSHA256() != prep.CaptureSHA256() {
					t.Fatal("unprojected original public owner differs from full source replay", err)
				}
				metrics := c.PublicCandidatePrefixMeasurements()
				metrics[pos] = "foreign"
				if c.PublicCandidatePrefixMeasurements()[pos] != hopmeasure.CandidatePublicResponseMeasurement {
					t.Fatal("copy-out mutated original source")
				}
				projected, err := ProjectNodeChain(c, "linux", 0)
				if err != nil {
					t.Fatal(err)
				}
				borrowed := *c
				for _, foreign := range []*NodeChain{projected, &borrowed} {
					if _, err := foreign.NewPublicCandidatePreparation(pos, inventory); err == nil {
						t.Fatal("foreign or projected graph became original candidate owner")
					}
				}
			}
			reopened, err := ParseNodeChainMultipleImportedCandidatePreparation(prep.Source())
			if err != nil || reopened.CaptureSHA256() != prep.CaptureSHA256() {
				t.Fatal("closed original replay", err)
			}
			// The final can never attest to a candidate by reusing its endpoint under another ID.
			colliding := nodeChainIndependentImportedFixture(t, count-1)
			if _, err := c.NewCandidatePlan(pos, candidateInventoryFixture(t, "original-import-catalog", colliding)); err == nil {
				t.Fatal("retained final reused for candidate")
			}
			p.publicResponses[0].ExpectedIP = "198.51.100.77"
			if p.Metadata() != "" || p.PublicResponseCandidateDepth(pos, p.prefix.ProfileID, p.prefix.Tag) != 0 {
				t.Fatal("substituted original expected IP retained authority")
			}
		})
	}
}

func TestNodeChainExternalFinalPublicCandidateRefusesAliases(t *testing.T) {
	chain, err := NewNodeChain(startJSON(t, externalFinalSourceFixture(t, 4, "home")))
	if err != nil {
		t.Fatal(err)
	}
	base := nodeChainIndependentImportedFixture(t, 42)
	var record, original nodeChainImportedInput
	if err = json.Unmarshal([]byte(base), &record); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal([]byte(nodeChainIndependentImportedFixture(t, 2)), &original); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"endpoint", "credential", "expected-ip", "private-agent", "duplicate-candidate"} {
		t.Run(fault, func(t *testing.T) {
			input := base
			profile, config := externalTestRead(t, record.Capture), externalTestRead(t, record.Config)
			external := profile["profile"].(map[string]any)["external"].(map[string]any)
			ss := external["shadowsocks"].(map[string]any)
			out, prior := externalTestFind(t, config, ExternalFinalTag), externalTestFind(t, externalTestRead(t, original.Config), ExternalFinalTag)
			switch fault {
			case "endpoint":
				out["server"], ss["server"], out["server_port"], ss["port"] = prior["server"], prior["server"], prior["server_port"], prior["server_port"]
			case "credential":
				out["password"], ss["password"] = prior["password"], prior["password"]
			case "expected-ip":
				delete(profile, "expected_public_ip")
			case "private-agent":
				input, _ = nodeChainFixtureNodes(t, 8, "")[7].LaunchInput()
			}
			if fault != "private-agent" {
				input = startJSON(t, nodeChainImportedInput{record.Kind, record.Schema, startJSON(t, config), startJSON(t, profile)})
			}
			inputs := []string{input}
			if fault == "duplicate-candidate" {
				inputs = append(inputs, input)
			}
			if _, e := chain.NewCandidatePlan(1, candidateInventoryFixture(t, "original", inputs...)); e == nil {
				t.Fatal("accepted substituted public source")
			}
		})
	}
	t.Run("filter-independent-catalog", func(t *testing.T) {
		// A renamed source can be valid as an independent import and still
		// duplicate a retained member or another alternative in this route.
		renamed := func(input, id string) string {
			var r nodeChainImportedInput
			if err := json.Unmarshal([]byte(input), &r); err != nil {
				t.Fatal(err)
			}
			capture := externalTestRead(t, r.Capture)
			capture["exit_id"] = id
			capture["profile"].(map[string]any)["id"] = id
			r.Capture = startJSON(t, capture)
			input = startJSON(t, r)
			if !NodeChainCandidateInputSupportedForMeasurement(input, hopmeasure.CandidatePublicResponseMeasurement) {
				t.Fatal("fixture is not a valid original import")
			}
			return input
		}
		good1 := nodeChainIndependentImportedFixture(t, 50)
		good2 := nodeChainIndependentImportedFixture(t, 48)
		aliasOriginal := renamed(chain.importedNodes.members[2].input, "renamed-original")
		aliasCandidate := renamed(base, "renamed-candidate")
		all := candidateInventoryFixture(t, "same-original-generation", aliasCandidate, good1, aliasOriginal, "malformed", good2, base)
		exact := candidateInventoryFixture(t, "same-original-generation", good1, good2)
		subset, err := chain.FilterPublicCandidateInventory(1, all)
		if err != nil || subset != exact {
			t.Fatal("retained ambiguous inputs, dropped independent rows or changed ordering", err)
		}
		if replay, err := FilterNodeChainPublicCandidateInventory(chain.sourceJSON, 1, all); err != nil || replay != subset {
			t.Fatal("source replay differs from retained catalog", err)
		}
		if _, err = chain.NewCandidatePlan(1, all); err == nil {
			t.Fatal("mixed unfiltered input acquired transport authority")
		}
		if _, err = chain.NewCandidatePlan(1, subset); err != nil {
			t.Fatal("independent rows became unmeasurable", err)
		}
		empty := candidateInventoryFixture(t, "same-original-generation", aliasCandidate, base)
		left, err := chain.FilterPublicCandidateInventory(1, empty)
		var decoded NodeChainCandidateInventory
		if err != nil || json.Unmarshal([]byte(left), &decoded) != nil || decoded.Inputs == nil || len(decoded.Inputs) != 0 || decoded.Revision != "same-original-generation" {
			t.Fatal("empty subset invented authority", err)
		}
		if _, err := chain.NewCandidatePlan(1, left); err == nil {
			t.Fatal("empty filtered inventory acquired transport")
		}
		if _, err := chain.FilterPublicCandidateInventory(0, all); err == nil {
			t.Fatal("WG candidate borrowed stream eligibility")
		}
		if _, err := chain.FilterPublicCandidateInventory(len(chain.nodes)-1, all); err == nil {
			t.Fatal("public final borrowed interior eligibility")
		}
	})
}

func TestNodeChainPublicCandidatesCompareDecodedCipherKeys(t *testing.T) {
	source := externalFinalSourceFixture(t, 4, "home")
	chain, err := NewNodeChain(startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	first, second, independent := nodeChainIndependentImportedFixture(t, 42), nodeChainIndependentImportedFixture(t, 43), nodeChainIndependentImportedFixture(t, 44)
	alias := func(input, original string) string {
		t.Helper()
		var record nodeChainImportedInput
		if err := json.Unmarshal([]byte(input), &record); err != nil {
			t.Fatal(err)
		}
		prior, err := parseCandidatePublicResponseSource(original)
		if err != nil {
			t.Fatal(err)
		}
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
		key := []byte(prior.Password)
		if !strings.HasSuffix(prior.Password, "=") || len(key) < 3 {
			t.Fatal("expected padded source key")
		}
		last := len(key) - 2
		index := strings.IndexByte(alphabet, key[last])
		if index < 0 || index%4 != 0 {
			t.Fatal("expected a canonical 32-byte key")
		}
		key[last] = alphabet[index+1]
		graph, capture := externalTestRead(t, record.Config), externalTestRead(t, record.Capture)
		externalTestFind(t, graph, ExternalFinalTag)["password"] = string(key)
		capture["profile"].(map[string]any)["external"].(map[string]any)["shadowsocks"].(map[string]any)["password"] = string(key)
		raw, err := NodeChainImportedMemberInput(startJSON(t, graph), startJSON(t, capture))
		if err != nil {
			t.Fatal("standalone source must retain native-compatible original spelling", err)
		}
		actual, err := parseCandidatePublicResponseSource(raw)
		if err != nil || actual.Password != string(key) || actual.Password == prior.Password || actual.keyIdentity != prior.keyIdentity {
			t.Fatal("native bytes and decoded identity were not independently retained", err)
		}
		return raw
	}
	for _, test := range []struct {
		name string
		rows []string
		want []string
	}{
		{"retained-source", []string{alias(first, source.Nodes[2]), independent}, []string{independent}},
		{"candidate-pair", []string{alias(second, first), independent, first}, []string{independent}},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := candidateInventoryFixture(t, "original-key-generation", test.rows...)
			subset, err := chain.FilterPublicCandidateInventory(1, raw)
			if err != nil || subset != candidateInventoryFixture(t, "original-key-generation", test.want...) {
				t.Fatal("alternate cipher encoding survived original inventory filter", err)
			}
			if _, err := chain.NewCandidatePlan(1, raw); err == nil {
				t.Fatal("alias pair acquired measurement authority")
			}
			if _, err := chain.NewCandidatePlan(1, subset); err != nil {
				t.Fatal("independent imported key unavailable", err)
			}
		})
	}
	t.Run("original-members", func(t *testing.T) {
		source.Nodes[1] = alias(source.Nodes[1], source.Nodes[2])
		if _, err := NewNodeChain(startJSON(t, source)); !errors.Is(err, pairedStreamConflict) {
			t.Fatal("aliased original chain acquired transport authority", err)
		}
	})
}

// Keep the public TLS exchange, typed receipt and original preparation owner
// real. The native cipher adapter is independently exercised by encrypted peers.
func TestNodeChainExternalFinalPublicCandidateHTTPS(t *testing.T) {
	input := startJSON(t, externalFinalSourceFixture(t, 4, "home"))
	candidate := nodeChainIndependentImportedFixture(t, 42)
	inventory := candidateInventoryFixture(t, "public-import-catalog", candidate)
	for _, fault := range []string{"original", "wrong-exit", "held-close-catalog-changed"} {
		t.Run(fault, func(t *testing.T) {
			p, err := NewNodeChainCandidatePreparation(input, 1, inventory)
			if err != nil {
				t.Fatal(err)
			}
			s := p.candidates.publicResponses[0]
			r, owner := candidatePreparationRuntimeFromSource(t, p)
			r.testTLS = p.original.runtime.testTLS.Clone()
			r.testTLS.RootCAs = r.testTLS.RootCAs.Clone()
			seen := map[string]bool{}
			var mu sync.Mutex
			peer, _ := externalMTUTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				nonce := req.URL.Query().Get("routervpn_candidate")
				mu.Lock()
				if !candidateTraceNonce(nonce) || seen[nonce] || req.Method != "GET" || req.Host != "1.1.1.1" || req.URL.Path != "/cdn-cgi/trace" || req.Header.Get("Authorization") != "" || req.Header.Get("Cache-Control") != "no-store" {
					t.Error("request changed fixed public trace identity")
				}
				seen[nonce] = true
				mu.Unlock()
				ip := s.ExpectedIP
				if fault == "wrong-exit" {
					ip = "198.51.100.133"
				}
				fmt.Fprintln(w, "ip="+ip)
			}))
			r.testTLS.RootCAs.AddCert(peer.Certificate())
			owner.peer = peer.Listener.Addr().String()
			originalWrap := wrapCandidateSS2022
			wrapCandidateSS2022 = func(ctx context.Context, raw net.Conn, method, key, dest string) (net.Conn, error) {
				if method != s.Method || key != s.Password || dest != "1.1.1.1:443" {
					return nil, errors.New("wrong candidate transport")
				}
				return raw, ctx.Err()
			}
			t.Cleanup(func() { wrapCandidateSS2022 = originalWrap })
			if err = r.StartContext(t.Context()); err != nil {
				t.Fatal(err)
			}
			service, err := r.NewMeasurementContext(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer service.Close()
			if fault == "held-close-catalog-changed" {
				owner.closeEntered, owner.closeRelease = make(chan struct{}), make(chan struct{})
			}
			request := strings.Repeat("c", 32)
			if err = service.Start(request, s.Target.ID); err != nil {
				t.Fatal(err)
			}
			if fault == "held-close-catalog-changed" {
				select {
				case <-owner.closeEntered:
				case <-time.After(3 * time.Second):
					t.Fatal("original close was not reached")
				}
				if st := candidateStatus(t, service); st.Drained || st.Complete || !owner.lease.active.Load() {
					t.Fatal("held original worker published a result")
				}
				owner.mu.Lock()
				owner.capture = "replaced"
				owner.mu.Unlock()
				close(owner.closeRelease)
			}
			_ = service.Drain(request)
			st := candidateStatus(t, service)
			if st.Measurement != hopmeasure.CandidatePublicResponseMeasurement || !st.Complete || !st.Drained || owner.lease.active.Load() || owner.lease.released.Load() != 1 {
				t.Fatalf("terminal ownership %+v", st)
			}
			if fault != "original" {
				for _, row := range st.Results {
					if row.Ready || row.Benchmark != nil || row.CandidateDisposition != "" {
						t.Fatal("wrong exit or stale owner produced score")
					}
				}
				return
			}
			if st.Request != request || st.CaptureSHA256 != p.capture || st.PrefixID != p.proofs[1].ProfileID || st.PrefixPosition != 1 || st.CandidateID != s.Target.ID || st.CandidateSourceSHA256 != s.Target.SourceSHA256 || st.MeasuredAt <= 0 || st.ExpiresAt-st.MeasuredAt != 120000 || st.Failure != "" || len(st.Results) != 1 {
				t.Fatalf("lost public source receipt %+v", st)
			}
			row := st.Results[0]
			if !row.Ready || row.Kind != "public-exit-response" || row.Role != "candidate" || row.Benchmark == nil || row.Benchmark.Attempts != 50 || row.Benchmark.Measurement != st.Measurement || row.Benchmark.Endpoint != hopmeasure.CandidatePublicResponseEndpoint || row.Benchmark.TrimmedMean <= 0 || owner.count.Load() != 50 {
				t.Fatalf("wrong public response evidence %+v", row)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(seen) != 50 {
				t.Fatal("reused public proof")
			}
		})
	}
	t.Run("connected-owner-and-post-TLS-clock", func(t *testing.T) {
		chain, err := NewNodeChain(input)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := chain.NewCandidatePlan(1, inventory)
		if err != nil {
			t.Fatal(err)
		}
		source := plan.publicResponses[0]
		owner := &candidateOwnerFixture{nodeChainMeasurementFixture: nodeChainMeasurementFixture{chain: chain}, capture: plan.capture}
		engine := &candidateRouteFixture{nodeChainTestEngine: newNodeChainTestEngine(t, chain), tag: plan.prefix.Tag, address: source.Target.Address}
		peer, trust := externalMTUTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if !candidateTraceNonce(req.URL.Query().Get("routervpn_candidate")) {
				t.Error("missing fresh public nonce")
			}
			fmt.Fprintln(w, "ip="+source.ExpectedIP)
		}))
		engine.peer = peer.Listener.Addr().String()
		chain.runtime.testTLS.RootCAs.AddCert(peer.Certificate())
		originalWrap := wrapCandidateSS2022
		wrapCandidateSS2022 = func(ctx context.Context, raw net.Conn, method, key, dest string) (net.Conn, error) {
			if method != source.Method || key != source.Password || dest != "1.1.1.1:443" {
				return nil, errors.New("unexpected captured candidate route")
			}
			return raw, ctx.Err()
		}
		t.Cleanup(func() { wrapCandidateSS2022 = originalWrap })
		if _, err := plan.NewMeasurementContext(t.Context(), owner); err == nil {
			t.Fatal("unproved connected source acquired candidate measurement")
		}
		if err = chain.Run(t.Context(), engine); err != nil {
			t.Fatal(err)
		}
		defer chain.CloseContext(t.Context())
		progress := chain.Progress()
		if !progress.Ready || !progress.PublicProven || !progress.DNSProven || len(progress.Prefixes) != 4 {
			t.Fatalf("missing original public final proof %+v", progress)
		}
		service, err := plan.NewMeasurementContext(t.Context(), owner)
		if err != nil {
			t.Fatal(err)
		}
		defer service.Close()
		request := strings.Repeat("b", 32)
		if err = service.StartContext(t.Context(), request, source.Target.ID); err != nil {
			t.Fatal(err)
		}
		if err = service.Drain(request); err != nil {
			t.Fatal(err)
		}
		st := candidateStatus(t, service)
		if !st.Drained || !st.Complete || len(st.Results) != 1 || !st.Results[0].Ready || st.Results[0].Benchmark == nil || st.Results[0].Benchmark.Attempts != 50 || st.CaptureSHA256 != plan.capture || engine.count.Load() != 50 || owner.active.Load() {
			t.Fatalf("connected public measurement %+v", st)
		}
		// Exercise the same production verifier hooks separately: a certificate
		// rejection must prevent the clock from starting, and the completed
		// interval must follow certificate verification and the first callback.
		verified, began, finished := false, false, false
		trust.VerifyConnection = func(tls.ConnectionState) error { verified = true; return nil }
		checkBegin := func() error {
			if !verified {
				return errors.New("clock started before TLS verification")
			}
			began = true
			return nil
		}
		checkEnd := func() error {
			if !began {
				return errors.New("clock ended before HTTP request")
			}
			finished = true
			return nil
		}
		if err = source.exchange(t.Context(), engine.Dial, plan.prefix.Tag, trust, checkBegin, checkEnd); err != nil || !finished {
			t.Fatal("post-TLS response timer", err)
		}
		verified, began, finished = false, false, false
		trust.VerifyConnection = func(tls.ConnectionState) error { return errors.New("untrusted peer") }
		if err = source.exchange(t.Context(), engine.Dial, plan.prefix.Tag, trust, checkBegin, checkEnd); err == nil || began || finished {
			t.Fatal("untrusted TLS reached measurement clock", err)
		}
		owner.setCapture("replaced-catalog")
		if _, err = plan.NewMeasurementContext(t.Context(), owner); err == nil {
			t.Fatal("changed connected catalog reissued a plan")
		}
	})
}

func candidateTraceNonce(value string) bool {
	if len(value) != 32 {
		return false
	}
	return strings.Trim(value, "0123456789abcdef") == ""
}
