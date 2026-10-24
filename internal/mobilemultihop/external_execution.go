package mobilemultihop

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"router-vpn/internal/multihoprelay"
	"router-vpn/internal/routechoice"
)

// One frozen proposal is retained in the private capture, so compilation,
// proof, MTU authority and measurement reconstruct the exact same native graph.
// A fresh connection obtains new random listener/session credentials.
type externalExecutionCapture struct {
	Selection string                `json:"selection"`
	Request   multihoprelay.Request `json:"request"`
}

// ValidateExternalResponseProbe validates the same bounded endpoint contract
// used by the captured native execution graph. Native profile editors call it
// before saving, without inventing a Router entry or opening network sockets.
func ValidateExternalResponseProbe(host, probeJSON string) error {
	var probe multihoprelay.ResponseProbe
	if exactJSON([]byte(probeJSON), &probe, 4096) != nil {
		return errors.New("external response endpoint is invalid")
	}
	return probe.Validate(host)
}

func externalSavedExecution(p map[string]any) (string, error) {
	if raw, ok := p["multihop_execution"]; ok && raw != "" {
		value, ok := raw.(string)
		if !ok || value != "local" && value != "server" && value != "auto" {
			return "", errors.New("external execution selection is invalid")
		}
		return value, nil
	}
	return "local", nil
}

// PrepareExternalExecutionCapture is the string-only native host entry point.
// restored may only be a previously proved local/server choice validated by the
// host's exact saved-bundle receipt. It cannot change a saved explicit choice.
func PrepareExternalExecutionCapture(source, capture, restored string) (string, error) {
	var selected externalPolicyCapture
	if exactJSON([]byte(capture), &selected, 8<<20) != nil || selected.Execution != nil {
		return "", errors.New("external execution requires one fresh captured selection")
	}
	saved, err := externalSavedExecution(selected.Profile)
	if err != nil {
		return "", err
	}
	if restored != "" && (restored != "local" && restored != "server" || saved != "auto" && restored != saved) {
		return "", errors.New("restored external execution differs from its saved selection")
	}
	if saved == "local" && restored == "" {
		if _, err := NewExternalPolicy(source, capture); err != nil {
			return "", err
		}
		return capture, nil
	}
	selection := saved
	if restored != "" {
		selection = restored
	}
	exit, err := externalRelaySelection(selected)
	if err != nil {
		return "", err
	}
	entryNode, _ := selected.Entry["node_proof_id"].(string)
	session, err := randomHex(16)
	if err != nil {
		return "", err
	}
	user, err := randomHex(24)
	if err != nil {
		return "", err
	}
	password, err := randomHex(24)
	if err != nil {
		return "", err
	}
	// Bounded port pool is the same published private relay contract.
	var seed [1]byte
	if _, err = rand.Read(seed[:]); err != nil {
		return "", err
	}
	port := 26240 + int(seed[0])%32
	request, err := multihoprelay.AuthenticateExternalRequest(exit, multihoprelay.Request{SessionID: session, EntryNodeID: entryNode, ExitID: selected.ExitID, ExitMode: exit.Mode, ExitStartLayer: multihoprelay.LayerMode(exit.StartLayer), Port: port, Username: user, Password: password})
	if err != nil {
		return "", err
	}
	selected.Execution = &externalExecutionCapture{Selection: selection, Request: request}
	encoded, err := json.Marshal(selected)
	if err != nil {
		return "", err
	}
	if _, err := NewExternalPolicy(source, string(encoded)); err != nil {
		return "", err
	}
	return string(encoded), nil
}

func externalRelaySelection(s externalPolicyCapture) (multihoprelay.Exit, error) {
	bad := errors.New("external server execution requires a captured Router entry, authenticated native exit and verified node response endpoint")
	entryID, entryIDOK := s.Entry["id"].(string)
	selectedEntry, selectedEntryOK := s.Profile["multihop_entry_id"].(string)
	if !multihoprelay.ExternalMode(s.Protocol) || s.Profile["node_kind"] != "external" || s.Entry == nil || s.Entry["node_kind"] != "router-vpn" ||
		s.Profile["multihop_enabled"] != true || !entryIDOK || !selectedEntryOK || !exactID.MatchString(entryID) || selectedEntry != entryID || s.Profile["multihop_exit_id"] != s.ExitID || s.Profile["multihop_exit_mode"] != s.Protocol || entryID == s.ExitID {
		return multihoprelay.Exit{}, bad
	}
	ext, ok := s.Profile["external"].(map[string]any)
	if !ok || ext["protocol"] != s.Protocol || ext["expected_public_ip"] != s.ExpectedPublicIP {
		return multihoprelay.Exit{}, bad
	}
	layer, err := externalCapturedStartLayer(s)
	if err != nil {
		return multihoprelay.Exit{}, err
	}
	exit, err := multihoprelay.ExternalSelection(s.ExitID, s.Protocol, ext, layer)
	if err != nil {
		return multihoprelay.Exit{}, bad
	}
	return exit, nil
}

func compileExternalExecution(graph map[string]any, selected externalPolicyCapture, meta *externalPolicyMetadata) error {
	saved, err := externalSavedExecution(selected.Profile)
	if err != nil {
		return err
	}
	if selected.Execution == nil {
		if saved != "local" {
			return errors.New("external server/compare has no captured execution owner")
		}
		return nil
	}
	exit, err := externalRelaySelection(selected)
	if err != nil {
		return err
	}
	plan := selected.Execution
	if plan.Selection != saved && (saved != "auto" || plan.Selection != "local" && plan.Selection != "server") {
		return errors.New("external execution does not retain its captured selection")
	}
	if plan.Request.EntryNodeID != meta.EntryNodeID || plan.Request.Port < 26240 || plan.Request.Port > 26271 || multihoprelay.ValidateExternalRequest(exit, plan.Request) != nil {
		return errors.New("external execution proposal differs from its captured private transport")
	}
	api, err := privateAPI(selected.Entry["router_api"].(string))
	if err != nil {
		return err
	}
	count := 0
	for _, family := range []string{"outbounds", "endpoints"} {
		raw, present := graph[family]
		if !present {
			continue
		}
		values, ok := raw.([]any)
		if !ok {
			return errors.New("external execution transport family is invalid")
		}
		for _, raw := range values {
			value, ok := raw.(map[string]any)
			if !ok {
				return errors.New("external execution transport is invalid")
			}
			if value["tag"] == LocalTag || value["tag"] == ServerTag {
				return errors.New("external execution tags already belong to another owner")
			}
			if value["tag"] == ExternalFinalTag {
				value["tag"] = LocalTag
				count++
			}
		}
	}
	if count != 1 {
		return errors.New("external execution lost its exact local transport")
	}
	values, _ := graph["outbounds"].([]any)
	values = append(values, map[string]any{"type": "socks", "tag": ServerTag, "server": api.Hostname(), "server_port": plan.Request.Port, "version": "5", "username": plan.Request.Username, "password": plan.Request.Password, "detour": selected.EntryTag})
	initial := LocalTag
	if plan.Selection == "server" {
		initial = ServerTag
	}
	values = append(values, map[string]any{"type": "selector", "tag": ExternalFinalTag, "outbounds": []string{LocalTag, ServerTag}, "default": initial, "interrupt_exist_connections": true})
	graph["outbounds"] = values
	meta.Execution, meta.LastNodeMeasurement = plan.Selection, "https-response-time"
	return nil
}

func newExternalExecution(policy *ExternalPolicy) (*Controller, error) {
	if policy == nil || policy.capture.Execution == nil {
		return nil, errors.New("external execution capture is missing")
	}
	s := policy.capture
	entryAPI, _ := s.Entry["router_api"].(string)
	entryToken, _ := s.Entry["api_token"].(string)
	entryNode, _ := s.Entry["node_proof_id"].(string)
	entryID, _ := s.Entry["id"].(string)
	api, err := url.Parse(entryAPI)
	if err != nil {
		return nil, errors.New("external entry API invalid")
	}
	proposal := s.Execution.Request
	c := &Controller{meta: Metadata{EntryID: entryID, ExitID: s.ExitID, EntryNodeID: entryNode, EntryAPI: entryAPI, EntryToken: entryToken, EntryTag: s.EntryTag, ExitMode: s.Protocol, ExitStartLayer: proposal.ExitStartLayer, Execution: s.Execution.Selection}, config: policy.Config(), proposal: proposal, external: policy,
		progress: Progress{Stage: "prepared", Measurements: []routechoice.Measurement{}, LastNodeMeasurement: "https-response-time", ExternalMeasurement: "https-response-time"}}
	c.expected = multihoprelay.Lease{Request: proposal, NodeID: entryNode, Host: api.Hostname(), Port: proposal.Port, Username: proposal.Username, Password: proposal.Password}
	if multihoprelay.ExternalPacketMode(s.Protocol) {
		exit, err := externalRelaySelection(s)
		if err != nil {
			return nil, err
		}
		local, _, err := multihoprelay.ExternalPacketIdentities(exit)
		if err != nil {
			return nil, err
		}
		c.localPublicKey = local
	}
	c.generation.Store(1)
	return c, nil
}

func (c *Controller) verifyExternalTrial(ctx context.Context, tag string) error {
	if c.external == nil || c.requireValid() != nil || c.engine.Selected() != tag {
		return errors.New("external candidate is not the current selected owner")
	}
	if _, err := c.prove(ctx, c.meta.EntryTag, c.meta.EntryAPI, c.meta.EntryToken, c.meta.EntryNodeID); err != nil {
		return err
	}
	engine, ok := c.engine.(ExternalProofEngine)
	if !ok {
		return errors.New("external candidate has no selected DNS owner")
	}
	var meta externalPolicyMetadata
	if exactJSON([]byte(c.external.Metadata()), &meta, 64<<10) != nil {
		return errors.New("external candidate metadata invalid")
	}
	if err := engine.DNSProof(ctx, meta.TUNTag); err != nil {
		return errors.New("external candidate selected DNS failed proof")
	}
	data, err := externalProofHTTP(ctx, engine.Dial, tag, Targets[0], "", nil)
	if err != nil || externalTraceAddress(data, c.external.capture.ExpectedPublicIP) != nil || c.engine.Selected() != tag {
		return errors.New("external candidate public exit proof failed")
	}
	return c.requireValid()
}

func (c *Controller) externalNodeResponse(ctx context.Context, tag string) (time.Duration, error) {
	if c.external == nil || c.requireValid() != nil || c.engine.Selected() != tag {
		return 0, errors.New("external response probe is stale")
	}
	exit, err := externalRelaySelection(c.external.capture)
	if err != nil {
		return 0, err
	}
	probe := exit.External.ResponseProbe
	start := time.Now()
	_, err = externalProofHTTPName(ctx, c.engine.Dial, tag, probe.URL, "", probe.ServerName, c.externalResponseTLS)
	elapsed := time.Since(start)
	if err != nil || ctx.Err() != nil || c.requireValid() != nil || c.engine.Selected() != tag {
		return 0, errors.New("external last-node HTTPS response failed or became stale")
	}
	return elapsed, nil
}
