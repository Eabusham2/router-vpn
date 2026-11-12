package mobilemultihop

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
)

func candidateSourceFixture(t *testing.T, kind, method string) (string, string) {
	t.Helper()
	size := 32
	if method == "2022-blake3-aes-128-gcm" {
		size = 16
	}
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{97}, size))
	if kind == "external" {
		source := nodeChainImportedFixture(t, "wg", "")
		var record nodeChainImportedInput
		if err := json.Unmarshal([]byte(source.Nodes[1]), &record); err != nil {
			t.Fatal(err)
		}
		graph, capture := externalTestRead(t, record.Config), externalTestRead(t, record.Capture)
		out := externalTestFind(t, graph, ExternalFinalTag)
		profile := capture["profile"].(map[string]any)
		ss := profile["external"].(map[string]any)["shadowsocks"].(map[string]any)
		profile["id"] = "candidate-external"
		capture["exit_id"] = "candidate-external"
		out["method"], out["password"], ss["method"], ss["password"] = method, key, method, key
		input, err := NodeChainImportedMemberInput(startJSON(t, graph), startJSON(t, capture))
		if err != nil {
			t.Fatal(err)
		}
		return input, net.JoinHostPort(out["server"].(string), strconv.Itoa(int(out["server_port"].(float64))))
	}
	node := nodeChainFixtureNodes(t, 3, "")[2]
	var files map[string]string
	if err := json.Unmarshal([]byte(node.inputs.Files), &files); err != nil {
		t.Fatal(err)
	}
	graph := externalTestRead(t, string(mustDecodeChainAsset(t, files["sing-box.json"])))
	out := graph["outbounds"].([]any)[0].(map[string]any)
	out["method"], out["password"] = method, key
	files["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(startJSON(t, graph)))
	profile := predecessorCopy(node.profile)
	profile["id"] = "candidate-paired"
	node, err := NewNodeProfile("shadowsocks", startJSON(t, files), startJSON(t, profile), "", "")
	if err != nil {
		t.Fatal(err)
	}
	input, err := node.LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	return input, net.JoinHostPort(out["server"].(string), strconv.Itoa(int(out["server_port"].(float64))))
}

func candidateInventoryFixture(t *testing.T, revision string, inputs ...string) string {
	t.Helper()
	return startJSON(t, NodeChainCandidateInventory{Schema: 1, Revision: revision, Inputs: inputs})
}

func TestNodeChainCandidateSealsOriginalSourcesAndPrefixes(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, kind := range []string{"paired", "external"} {
			for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
				t.Run(mode+"/"+kind+"/"+method, func(t *testing.T) {
					chain, err := NewNodeChain(startJSON(t, nodeChainImportedFixture(t, mode, "")))
					if err != nil {
						t.Fatal(err)
					}
					input, expectedAddress := candidateSourceFixture(t, kind, method)
					inventory := candidateInventoryFixture(t, "catalog-epoch-1", input)
					beforeSource, beforeConfig, beforeLaunch := chain.SourceSHA256(), chain.Config(), chain.sourceJSON
					plan, err := chain.NewCandidatePlan(0, inventory)
					if err != nil {
						t.Fatal("original SS2022 candidate rejected", err)
					}
					if plan.chain != chain || plan.prefix != chain.proofs[0] || plan.inventory != inventory || len(plan.targets) != 1 || plan.targets[0].Address != expectedAddress {
						t.Fatal("candidate substituted captured source/prefix/endpoint", plan)
					}
					if chain.SourceSHA256() != beforeSource || chain.Config() != beforeConfig || chain.sourceJSON != beforeLaunch {
						t.Fatal("candidate constructed another WG source or altered original configuration")
					}
					metadata := plan.Metadata()
					for _, secret := range []string{expectedAddress, "captured-chain-token", "password", "api_token", "router_api", "private_key"} {
						if strings.Contains(metadata, secret) {
							t.Fatal("public metadata leaked a source capability", secret)
						}
					}
					changed, err := chain.NewCandidatePlan(0, candidateInventoryFixture(t, "catalog-epoch-3", input))
					if err != nil || changed.capture == plan.capture {
						t.Fatal("change-away-and-back catalog revision reused prior capture", err)
					}
					plan.targets[0].Address = "192.0.2.99:8080"
					if plan.validate() == nil || plan.Metadata() != "" {
						t.Fatal("mutated target retained seal")
					}
				})
			}
		}
	}
}

type candidateOwnerFixture struct {
	nodeChainMeasurementFixture
	mu      sync.Mutex
	capture string
	checks  atomic.Int32
}

func (o *candidateOwnerFixture) CandidateInventoryCurrentContext(ctx context.Context, capture string) error {
	o.checks.Add(1)
	o.mu.Lock()
	defer o.mu.Unlock()
	if capture != o.capture {
		return hopmeasure.ErrStale
	}
	return ctx.Err()
}
func (o *candidateOwnerFixture) setCapture(capture string) {
	o.mu.Lock()
	o.capture = capture
	o.mu.Unlock()
}

type candidateRouteFixture struct {
	*nodeChainTestEngine
	tag, address, peer string
	count              atomic.Int32
	before             func(context.Context)
	closeEntered       chan struct{}
	closeRelease       chan struct{}
	closeOnce          sync.Once
}

func (e *candidateRouteFixture) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	if address != e.address {
		return e.nodeChainTestEngine.Dial(ctx, tag, address)
	}
	if tag != e.tag {
		return nil, errors.New("candidate reached another retained prefix")
	}
	e.count.Add(1)
	if e.before != nil {
		e.before(ctx)
	}
	conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", e.peer)
	if conn != nil && e.closeEntered != nil {
		return &candidateBlockedClose{Conn: conn, owner: e}, err
	}
	return conn, err
}

type candidateBlockedClose struct {
	net.Conn
	owner *candidateRouteFixture
}

func (c *candidateBlockedClose) Close() error {
	c.owner.closeOnce.Do(func() { close(c.owner.closeEntered) })
	<-c.owner.closeRelease
	return c.Conn.Close()
}

func newCandidateRuntimeFixture(t *testing.T) (*NodeChainCandidatePlan, *candidateOwnerFixture, *candidateRouteFixture) {
	t.Helper()
	chain := nodeChainFixture(t, 3, "")
	input, address := candidateSourceFixture(t, "external", "2022-blake3-aes-256-gcm")
	plan, err := chain.NewCandidatePlan(1, candidateInventoryFixture(t, "catalog-epoch-1", input))
	if err != nil {
		t.Fatal(err)
	}
	base := newNodeChainTestEngine(t, chain)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	engine := &candidateRouteFixture{nodeChainTestEngine: base, tag: chain.proofs[1].Tag, address: address, peer: listener.Addr().String()}
	if err := chain.Run(context.Background(), engine); err != nil {
		t.Fatal(err)
	}
	owner := &candidateOwnerFixture{nodeChainMeasurementFixture: nodeChainMeasurementFixture{chain: chain}, capture: plan.capture}
	return plan, owner, engine
}
func candidateStatus(t *testing.T, service *hopmeasure.CandidateService) hopmeasure.CandidateStatus {
	t.Helper()
	var status hopmeasure.CandidateStatus
	if err := json.Unmarshal([]byte(service.StatusJSON()), &status); err != nil {
		t.Fatal(err)
	}
	return status
}
func TestNodeChainCandidateRetainsOriginalRouteAndCompleteFifty(t *testing.T) {
	plan, owner, engine := newCandidateRuntimeFixture(t)
	source, config, native := plan.chain.SourceSHA256(), plan.chain.ConfigSHA256(), plan.chain.runtime.engine
	service, err := plan.NewMeasurementContext(context.Background(), owner)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	request := strings.Repeat("a", 32)
	if err := service.Start(request, plan.targets[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := service.Drain(request); err != nil {
		t.Fatal(err)
	}
	status := candidateStatus(t, service)
	if !status.Complete || !status.Drained || status.Failure != "" || len(status.Results) != 1 || !status.Results[0].Ready || status.Results[0].Benchmark == nil || status.Results[0].Benchmark.Attempts != 50 || engine.count.Load() != 50 {
		t.Fatal("missing actual complete fifty connection result", status, engine.count.Load())
	}
	if status.Measurement != "routed-tcp-connect" || status.PrefixPosition != 1 || status.PrefixID != plan.prefix.ProfileID || status.CaptureSHA256 != plan.capture || status.CandidateID != plan.targets[0].ID || status.ExpiresAt-status.MeasuredAt != 120000 {
		t.Fatal("result lost captured routing/expiry semantics", status)
	}
	if owner.active.Load() || owner.released.Load() != 1 || owner.checks.Load() < 50 {
		t.Fatal("candidate bypassed catalog checks or MTU hold")
	}
	if plan.chain.SourceSHA256() != source || plan.chain.ConfigSHA256() != config || plan.chain.runtime.engine != native {
		t.Fatal("candidate replaced original native owner")
	}
	if err := service.Start(strings.Repeat("b", 32), "127.0.0.1:80"); err == nil {
		t.Fatal("arbitrary destination acquired candidate capability")
	}
}

func TestNodeChainCandidateInvalidatesEveryOriginalIdentity(t *testing.T) {
	for _, field := range []string{"EngineID", "SessionID", "NetworkID", "SourceSHA256", "ConfigSHA256", "catalog", "reader", "proof-generation"} {
		t.Run(field, func(t *testing.T) {
			plan, owner, engine := newCandidateRuntimeFixture(t)
			service, err := plan.NewMeasurementContext(context.Background(), owner)
			if err != nil {
				t.Fatal(err)
			}
			defer service.Close()
			engine.mu.Lock()
			original := engine.identity
			engine.mu.Unlock()
			switch field {
			case "catalog":
				changed, err := plan.chain.NewCandidatePlan(plan.prefix.Position, candidateInventoryFixture(t, "catalog-epoch-3", func() string {
					var record NodeChainCandidateInventory
					_ = json.Unmarshal([]byte(plan.inventory), &record)
					return record.Inputs[0]
				}()))
				if err != nil {
					t.Fatal(err)
				}
				owner.setCapture(changed.capture)
			case "reader":
				plan.chain.runtime.mu.Lock()
				plan.chain.runtime.engine = &candidateRouteFixture{nodeChainTestEngine: engine.nodeChainTestEngine, tag: engine.tag, address: engine.address, peer: engine.peer}
				plan.chain.runtime.mu.Unlock()
			case "proof-generation":
				plan.chain.runtime.generation.Store(2)
			default:
				engine.mu.Lock()
				reflect.ValueOf(&engine.identity).Elem().FieldByName(field).SetString("replacement")
				engine.mu.Unlock()
			}
			if err := service.Start(strings.Repeat("c", 32), plan.targets[0].ID); err == nil {
				_ = service.Drain(strings.Repeat("c", 32))
				t.Fatal("changed original owner admitted candidate", field)
			}
			// Restoring copied text cannot restore a capability once its loss was observed.
			engine.mu.Lock()
			engine.identity = original
			engine.mu.Unlock()
			if field == "reader" {
				plan.chain.runtime.mu.Lock()
				plan.chain.runtime.engine = engine
				plan.chain.runtime.mu.Unlock()
			}
			if err := service.Start(strings.Repeat("d", 32), plan.targets[0].ID); err == nil {
				_ = service.Drain(strings.Repeat("d", 32))
				t.Fatal("change-away-and-back resurrected original candidate", field)
			}
			if engine.count.Load() != 0 || len(candidateStatus(t, service).Results) != 0 {
				t.Fatal("invalidated source retained a score or native dial")
			}
		})
	}
}

func TestNodeChainCandidateCancelRetainsMTUHoldThroughSocketDrain(t *testing.T) {
	plan, owner, engine := newCandidateRuntimeFixture(t)
	engine.closeEntered, engine.closeRelease = make(chan struct{}), make(chan struct{})
	service, err := plan.NewMeasurementContext(context.Background(), owner)
	if err != nil {
		t.Fatal(err)
	}
	var release sync.Once
	defer func() { release.Do(func() { close(engine.closeRelease) }); _ = service.Close() }()
	request := strings.Repeat("e", 32)
	if err := service.Start(request, plan.targets[0].ID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-engine.closeEntered:
	case <-time.After(time.Second):
		t.Fatal("candidate did not retain actual socket close")
	}
	service.Cancel(request)
	status := candidateStatus(t, service)
	if status.Drained || !owner.active.Load() || owner.released.Load() != 0 || len(status.Results) != 0 {
		t.Fatal("cancel certified drain before original socket joined", status)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err = service.CloseContext(ctx)
	cancel()
	if err == nil || !owner.active.Load() {
		t.Fatal("bounded close released native activity before socket joined", err)
	}
	release.Do(func() { close(engine.closeRelease) })
	if err := service.Drain(request); err != nil {
		t.Fatal(err)
	}
	if owner.active.Load() || owner.released.Load() != 1 || len(candidateStatus(t, service).Results) != 0 {
		t.Fatal("cancelled candidate escaped final drain")
	}
}

func TestNodeChainCandidateRejectsUnsealedOrUnsupportedSources(t *testing.T) {
	chain := nodeChainFixture(t, 3, "")
	original, _ := candidateSourceFixture(t, "external", "2022-blake3-aes-256-gcm")
	for _, fault := range []string{"missing", "schema", "revision", "duplicate-id", "duplicate-prefix", "udp-only", "layered", "unknown-field", "wrong-port", "hostname", "method", "capture-mismatch"} {
		t.Run(fault, func(t *testing.T) {
			inventory := NodeChainCandidateInventory{Schema: 1, Revision: "catalog-epoch-1", Inputs: []string{original}}
			switch fault {
			case "missing":
				inventory.Inputs = nil
			case "schema":
				inventory.Schema = 2
			case "revision":
				inventory.Revision = ""
			case "duplicate-id":
				inventory.Inputs = append(inventory.Inputs, original)
			case "duplicate-prefix", "udp-only":
				input, err := chain.nodes[0].LaunchInput()
				if err != nil {
					t.Fatal(err)
				}
				inventory.Inputs = []string{input}
			case "layered":
				node := nodeChainFixtureNodes(t, 3, "aes-256-gcm")[2]
				input, err := node.LaunchInput()
				if err != nil {
					t.Fatal(err)
				}
				inventory.Inputs = []string{input}
			default:
				var record nodeChainImportedInput
				_ = json.Unmarshal([]byte(original), &record)
				graph, capture := externalTestRead(t, record.Config), externalTestRead(t, record.Capture)
				out := externalTestFind(t, graph, ExternalFinalTag)
				ss := capture["profile"].(map[string]any)["external"].(map[string]any)["shadowsocks"].(map[string]any)
				switch fault {
				case "unknown-field":
					inventory.Inputs[0] = strings.TrimSuffix(original, "}") + `,"address":"127.0.0.1:80"}`
				case "wrong-port":
					out["server_port"], ss["server_port"] = float64(0), float64(0)
				case "hostname":
					out["server"], ss["server"] = "other.invalid", "other.invalid"
				case "method":
					out["method"], ss["method"] = "aes-256-gcm", "aes-256-gcm"
				case "capture-mismatch":
					out["server"] = "192.0.2.99"
				}
				if fault != "unknown-field" {
					record.Config, record.Capture = startJSON(t, graph), startJSON(t, capture)
					inventory.Inputs[0] = startJSON(t, record)
				}
			}
			if _, err := chain.NewCandidatePlan(0, startJSON(t, inventory)); err == nil {
				t.Fatal("unowned candidate admitted", fault)
			}
		})
	}
	for _, position := range []int{-1, 2, 3} {
		if _, err := chain.NewCandidatePlan(position, candidateInventoryFixture(t, "catalog-1", original)); err == nil {
			t.Fatal("invalid or lazy final prefix admitted", position)
		}
	}
	custom, err := NewNodeChain(startJSON(t, nodeChainImportedFixture(t, "wg", "")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := custom.NewCandidatePlan(1, candidateInventoryFixture(t, "catalog-1", original)); err == nil {
		t.Fatal("lazy imported SS middle acquired TCP handshake timing")
	}
}

func TestNodeChainCandidateEngineRejectsForeignTagOrAddress(t *testing.T) {
	plan, owner, engine := newCandidateRuntimeFixture(t)
	e := &nodeChainCandidateEngine{plan: plan, owner: owner, active: plan.chain, identity: engine.identity, reader: engine}
	for _, target := range [][2]string{{"proxy", plan.targets[0].Address}, {plan.chain.proofs[0].Tag, plan.targets[0].Address}, {plan.prefix.Tag, "127.0.0.1:80"}, {plan.prefix.Tag, "1.1.1.1:443"}} {
		conn, err := e.Dial(context.Background(), target[0], target[1])
		if conn != nil {
			_ = conn.Close()
		}
		if conn != nil || err == nil {
			t.Fatal("unsealed candidate route admitted", target)
		}
	}
	if engine.count.Load() != 0 {
		t.Fatal("refused target reached native callback")
	}
}
