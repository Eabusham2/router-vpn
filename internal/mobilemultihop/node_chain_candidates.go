package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"

	"router-vpn/internal/hopmeasure"
)

// Revision belongs to the original host catalog, including its change-away-and-
// back generation. Inputs are exact validated private launch captures, not a
// host-supplied list of addresses or outbound tags.
type NodeChainCandidateInventory struct {
	Schema       int      `json:"schema"`
	Revision     string   `json:"revision"`
	Inputs       []string `json:"inputs"`
	ResponseMode string   `json:"response_mode,omitempty"`
}

func candidateInventoryResponseMode(inventory string) (string, error) {
	var header struct {
		ResponseMode json.RawMessage `json:"response_mode"`
	}
	if len(inventory) == 0 || len(inventory) > NodeChainInputLimit || json.Unmarshal([]byte(inventory), &header) != nil {
		return "", nodeChainCandidatePreparationError
	}
	if len(header.ResponseMode) == 0 {
		return "", nil
	}
	var mode string
	if json.Unmarshal(header.ResponseMode, &mode) != nil || !nodeChainNativeResponseMode(mode) {
		return "", nodeChainCandidatePreparationError
	}
	return mode, nil
}

// The host must observe both its live connection and the complete original
// candidate catalog at admission and publication. An immutable copied catalog
// alone cannot establish that a saved source has not changed or been removed.
type NodeChainCandidateOwner interface {
	NodeChainMeasurementOwner
	CandidateInventoryCurrentContext(context.Context, string) error
}

type NodeChainCandidatePlan struct {
	appendSource           *NodeChainCandidateAppendSource
	appendImportSeals      []*nodeChainMultipleImportedMemberSeal
	chain                  *NodeChain
	multiple               *nodeChainCandidateMultipleOriginal
	multipleSeal           *nodeChainMultipleCandidatePlanSeal
	metadataPages          *nodeChainCandidateMetadataCache
	inventory              string
	revision               string
	prefix                 NodeChainProof
	targets                []hopmeasure.CandidateTarget
	measurement            string
	connectedFinalResponse bool
	preparedNativeResponse bool
	responseMode           string
	responses              []candidateResponseSource
	publicResponses        []candidatePublicResponseSource
	capture                string
	seal                   string
}

func (c *NodeChain) NewCandidatePlan(position int, inventory string) (*NodeChainCandidatePlan, error) {
	// Planning captures the complete original graph but grants no connected
	// route. NewMeasurementContext separately requires that same full chain's
	// fresh native owner and complete private/public/DNS readiness. Temporary
	// closed-prefix preparations retain their distinct admission and lifetime.
	return c.NewCandidatePlanFromInputs(position, inventory, nil)
}

func (c *NodeChain) newPacketCandidatePlan(position int, inventory string) (*NodeChainCandidatePlan, error) {
	return c.newPacketCandidatePlanOwned(position, inventory, nil)
}

func (c *NodeChain) newPacketCandidatePlanOwned(position int, inventory string, multiple *nodeChainCandidateMultipleOriginal) (*NodeChainCandidatePlan, error) {
	return c.newPacketCandidatePlanInputs(position, inventory, multiple, nil)
}

// NewCandidatePlanFromInputs chooses the owner from the complete original
// graph. A supplied parse result is reused only if its exact source bytes
// occur at the same ordinal in the complete inventory.
func (c *NodeChain) NewCandidatePlanFromInputs(position int, inventory string, inputs []*NodeChainCandidateInput) (*NodeChainCandidatePlan, error) {
	// The optional discriminator is revalidated with the complete inventory
	// below. Only this connected Local factory can request the native UDP
	// carrier; dormant and selected factories retain their existing admission.
	requested, err := candidateInventoryResponseMode(inventory)
	if err != nil {
		return nil, err
	}
	if requested != "" {
		var multiple *nodeChainCandidateMultipleOriginal
		if c != nil && c.importedNodes != nil {
			multiple, err = newNodeChainCandidateMultipleOriginal(c)
			if err != nil {
				return nil, err
			}
		}
		return c.newCandidatePlanInputs(position, inventory, multiple, inputs, false, requested, false)
	}
	if c != nil && c.validateCapture() == nil && c.connectedFinalResponsePrefix(position) {
		return c.newCandidatePlanInputs(position, inventory, nil, inputs, true, "", false)
	}
	var multiple *nodeChainCandidateMultipleOriginal
	if c != nil && c.importedNodes != nil {
		var err error
		multiple, err = newNodeChainCandidateMultipleOriginal(c)
		if err != nil {
			return nil, err
		}
	}
	return c.newPacketCandidatePlanInputs(position, inventory, multiple, inputs)
}
func (c *NodeChain) newPacketCandidatePlanInputs(position int, inventory string, multiple *nodeChainCandidateMultipleOriginal, inputs []*NodeChainCandidateInput) (*NodeChainCandidatePlan, error) {
	return c.newCandidatePlanInputs(position, inventory, multiple, inputs, false, "", false)
}

func (c *NodeChain) newCandidatePlanInputs(position int, inventory string, multiple *nodeChainCandidateMultipleOriginal, inputs []*NodeChainCandidateInput, connectedFinalResponse bool, responseMode string, prepared bool) (*NodeChainCandidatePlan, error) {
	requested, err := candidateInventoryResponseMode(inventory)
	if err != nil || requested != responseMode {
		return nil, nodeChainCandidatePreparationError
	}
	measurement := c.CandidatePrefixMeasurement(position)
	if responseMode != "" {
		if connectedFinalResponse || c.candidateNativeResponseModeAt(position) != responseMode {
			return nil, nodeChainCandidatePreparationError
		}
		measurement = hopmeasure.CandidatePrivateResponseMeasurement
	}
	if connectedFinalResponse {
		if multiple != nil || measurement != "" || c.ConnectedCandidatePrefixMeasurement(position) != hopmeasure.CandidatePrivateResponseMeasurement {
			return nil, nodeChainCandidatePreparationError
		}
		measurement = hopmeasure.CandidatePrivateResponseMeasurement
	}
	if measurement == "" {
		return nil, errors.New("candidate requires a captured packet prefix or a qualified routed response path")
	}
	if multiple == nil && c.importedNodes != nil && !connectedFinalResponse || multiple != nil && !multiple.currentValidated(c) {
		return nil, nodeChainCandidatePreparationError
	}
	// A temporary prefix stops before its saved OpenVPN, SOCKS or CONNECT hop.
	// Only the connected original owner may carry an authenticated response
	// through those imported hops or the captured imported-entry SS route.
	// Neither admission turns an imported UDP transport into a TCP timing
	// target or grants a dormant preparation its native owner.
	var record NodeChainCandidateInventory
	if exactJSON([]byte(inventory), &record, NodeChainInputLimit) != nil || record.Schema != 1 ||
		!nodeChainIdentityText(record.Revision) || len(record.Inputs) == 0 || record.ResponseMode != responseMode {
		return nil, errors.New("candidate timing requires the complete original source inventory")
	}
	plan := &NodeChainCandidatePlan{metadataPages: &nodeChainCandidateMetadataCache{}, chain: c, multiple: multiple, inventory: inventory, revision: record.Revision, prefix: c.proofs[position]}
	plan.connectedFinalResponse = connectedFinalResponse
	plan.responseMode = responseMode
	plan.preparedNativeResponse = prepared
	if measurement != hopmeasure.CandidateTCPMeasurement {
		plan.measurement = measurement
	}
	ids, proofs := map[string]bool{}, map[string]bool{}
	members := c.proofs[:position+1]
	var packetKeys map[string]bool
	if prepared || NodeChainPrefixMode(responseMode) {
		members = c.proofs
	}
	if NodeChainPrefixMode(responseMode) {
		packetKeys = make(map[string]bool)
		for position, member := range c.nodes {
			if member == nil {
				if multiple == nil || c.importedSSMemberAt(position) == nil {
					return nil, nodeChainCandidatePreparationError
				}
				continue
			}
			if !NodeChainPrefixMode(member.mode) {
				continue
			}
			client, server, err := nodeChainPacketKeys(member)
			if err != nil || client == server || packetKeys[client] || packetKeys[server] {
				return nil, nodeChainCandidatePreparationError
			}
			packetKeys[client], packetKeys[server] = true, true
		}
	}
	for _, member := range members {
		ids[member.ProfileID] = true
		if member.NodeID != "" {
			proofs[member.NodeID] = true
		}
	}
	if inputs != nil && len(inputs) != len(record.Inputs) {
		return nil, errors.New("captured candidate inventory changed size")
	}
	for i, input := range record.Inputs {
		var target hopmeasure.CandidateTarget
		var proof string
		var err error
		var response candidateResponseSource
		if inputs == nil {
			if responseMode != "" {
				response, err = parseCandidateNativeResponseSource(input, responseMode)
				target, proof = response.Target, response.NodeID
			} else {
				target, proof, err = nodeChainCandidateTarget(input)
			}
		} else {
			original := inputs[i]
			if original == nil || original.self != original || original.input != input || original.input != original.originalInput || original.proof != original.originalProof || original.target != original.originalTarget ||
				original.responseMode != responseMode || original.responseMode != original.originalResponseMode || original.response != original.originalResponse {
				return nil, errors.New("candidate source changed after compilation")
			}
			target, proof = original.target, original.proof
			response = original.response
		}
		if err != nil || ids[target.ID] || proof != "" && proofs[proof] {
			return nil, errors.Join(err, errors.New("candidate source duplicates or changes the captured prefix inventory"))
		}
		ids[target.ID] = true
		if proof != "" {
			proofs[proof] = true
		}
		if plan.measurement == hopmeasure.CandidatePublicResponseMeasurement {
			source, err := parseCandidatePublicResponseSource(input)
			if err != nil || source.Target != target || proof != "" {
				return nil, errors.Join(err, errors.New("invalid external candidate public response source"))
			}
			plan.publicResponses = append(plan.publicResponses, source)
		} else if plan.measurement == hopmeasure.CandidatePrivateResponseMeasurement {
			source := response
			if responseMode == "" {
				source, err = parseCandidateResponseSource(input)
			}
			if err != nil || source.Target != target || source.NodeID != proof {
				return nil, errors.Join(err, errors.New("invalid private candidate response source"))
			}
			if packetKeys != nil {
				if packetKeys[source.ClientKey] || packetKeys[source.ServerKey] {
					return nil, errors.New("packet candidate requires independent client and server keys")
				}
				packetKeys[source.ClientKey], packetKeys[source.ServerKey] = true, true
				source.PacketOptions, err = c.candidatePacketOptions(position, input)
				if err != nil {
					return nil, err
				}
			}
			plan.responses = append(plan.responses, source)
		}
		plan.targets = append(plan.targets, target)
	}
	if plan.measurement == hopmeasure.CandidatePublicResponseMeasurement {
		if err := c.validatePublicCandidateInventory(plan.publicResponses); err != nil {
			return nil, err
		}
	}
	domain := nodeChainMultipleCandidateDomain(multiple)
	if connectedFinalResponse {
		domain += "/connected-original-final-response"
	}
	if responseMode != "" {
		if prepared && position < len(c.proofs)-2 {
			domain += "/closed-prefix-" + responseMode + "-packet-successor-response"
		} else if prepared {
			domain += "/closed-prefix-" + responseMode + "-final-response"
		} else if position < len(c.proofs)-2 {
			domain += "/connected-original-" + responseMode + "-packet-successor-response"
		} else {
			domain += "/connected-original-" + responseMode + "-final-response"
		}
	}
	if plan.measurement != "" {
		domain += "/" + plan.measurement
	}
	raw, _ := json.Marshal([]any{domain, c.SourceSHA256(), c.ConfigSHA256(), plan.prefix, inventory})
	plan.capture = externalDigest(raw)
	clear(raw)
	plan.seal = plan.digest()
	plan.rememberMultipleCandidateSeal()
	return plan, plan.validate()
}

// NodeChainCandidateInput is an opaque socket-free result of the original
// compiler. Its private endpoint cannot be supplied or read by its caller.
type NodeChainCandidateInput struct {
	self                               *NodeChainCandidateInput
	input, proof                       string
	target                             hopmeasure.CandidateTarget
	originalInput, originalProof       string
	originalTarget                     hopmeasure.CandidateTarget
	responseMode, originalResponseMode string
	response, originalResponse         candidateResponseSource
}

func ParseNodeChainCandidateInput(input string) (*NodeChainCandidateInput, error) {
	if len(input) == 0 || len(input) > NodeChainInputLimit {
		return nil, nodeChainError
	}
	target, proof, err := nodeChainCandidateTarget(input)
	if err != nil {
		return nil, err
	}
	captured := &NodeChainCandidateInput{input: input, proof: proof, target: target, originalInput: input, originalProof: proof, originalTarget: target}
	captured.self = captured
	return captured, nil
}

// ParseNodeChainHysteria2CandidateInput retains only the validated original
// HY2 source. It grants neither TCP eligibility nor a native prefix owner.
func ParseNodeChainHysteria2CandidateInput(input string) (*NodeChainCandidateInput, error) {
	return ParseNodeChainResponseCandidateInput(input, "hysteria2")
}

func ParseNodeChainResponseCandidateInput(input, mode string) (*NodeChainCandidateInput, error) {
	if len(input) == 0 || len(input) > NodeChainInputLimit || !nodeChainNativeResponseMode(mode) {
		return nil, nodeChainError
	}
	response, err := parseCandidateNativeResponseSource(input, mode)
	if err != nil {
		return nil, err
	}
	captured := &NodeChainCandidateInput{input: input, proof: response.NodeID, target: response.Target,
		originalInput: input, originalProof: response.NodeID, originalTarget: response.Target,
		responseMode: mode, originalResponseMode: mode, response: response, originalResponse: response}
	captured.self = captured
	return captured, nil
}

func ParseNodeChainPacketSuccessorCandidateInput(input, mode string) (*NodeChainCandidateInput, error) {
	if !NodeChainPrefixMode(mode) {
		return nil, nodeChainError
	}
	captured, err := ParseNodeChainResponseCandidateInput(input, mode)
	if err != nil {
		return nil, err
	}
	var endpoint map[string]any
	if json.Unmarshal([]byte(captured.response.PacketOptions), &endpoint) != nil || !candidateUnboundPacket(endpoint) {
		return nil, nodeChainCandidatePreparationError
	}
	return captured, nil
}

func NodeChainPacketSuccessorCandidateInputSupported(input, mode string) bool {
	_, err := ParseNodeChainPacketSuccessorCandidateInput(input, mode)
	return err == nil
}

func NodeChainHysteria2CandidateInputSupported(input string) bool {
	return NodeChainResponseCandidateInputSupported(input, "hysteria2")
}

func NodeChainResponseCandidateInputSupported(input, mode string) bool {
	_, err := ParseNodeChainResponseCandidateInput(input, mode)
	return err == nil
}

// Build the same private source envelope as NodeChainImportedMemberInput.
// The candidate compiler validates the complete original member before issuing
// an immutable target. This avoids parsing that envelope separately twice.
func NewNodeChainImportedCandidateInput(config, policy string) (string, *NodeChainCandidateInput, error) {
	raw, err := json.Marshal(nodeChainImportedInput{"routervpn-node-chain-imported-member", 1, config, policy})
	if err != nil {
		return "", nil, err
	}
	input := string(raw)
	captured, err := ParseNodeChainCandidateInput(input)
	if err != nil {
		return "", nil, err
	}
	return input, captured, nil
}

// NodeChainCandidateInputSupported is a socket-free eligibility check using
// the same exact original-source compiler as candidate plan construction. It
// exposes no endpoint, credentials or reusable native route capability.
func NodeChainCandidateInputSupported(input string) bool {
	if len(input) == 0 || len(input) > NodeChainInputLimit {
		return false
	}
	_, _, err := nodeChainCandidateTarget(input)
	return err == nil
}

// Original literal SS2022, SOCKS5, HTTP/HTTPS CONNECT and single-remote TCP OpenVPN sources supply a candidate
// TCP endpoint. This measures connection establishment, not the candidate's
// authentication or TLS. UDP-only transports never gain a guessed TCP port.
func nodeChainCandidateTarget(input string) (hopmeasure.CandidateTarget, string, error) {
	bad := errors.New("candidate requires its original literal TCP-capable SS2022 source")
	var header struct {
		Kind string `json:"kind"`
	}
	if json.Unmarshal([]byte(input), &header) != nil {
		return hopmeasure.CandidateTarget{}, "", bad
	}
	if header.Kind == "routervpn-node-chain-openvpn-member" {
		middle, err := parseNodeChainOpenVPNMember(input)
		if err != nil {
			return hopmeasure.CandidateTarget{}, "", err
		}
		closure, err := middle.closure()
		if err != nil {
			return hopmeasure.CandidateTarget{}, "", err
		}
		// The typed source compiler has already proved exactly one original
		// literal remote. A UDP remote grants no TCP destination, even at
		// the same address and port.
		if closure.final["network"] != "tcp" {
			return hopmeasure.CandidateTarget{}, "", errors.New("OpenVPN candidate timing requires one original TCP remote")
		}
		target, err := nodeChainCandidateLiteralTarget(middle.id(), middle.source, closure.final)
		return target, "", err
	}
	if header.Kind == "routervpn-node-chain-socks-member" {
		// The existing typed SOCKS compiler owns version, credentials, literal
		// transport and Off-layer admission. A TCP score never grants a UDP
		// association or proves SOCKS authentication.
		middle, err := parseNodeChainSOCKSMember(input)
		if err != nil {
			return hopmeasure.CandidateTarget{}, "", err
		}
		closure, err := middle.closure()
		if err != nil {
			return hopmeasure.CandidateTarget{}, "", err
		}
		target, err := nodeChainCandidateLiteralTarget(middle.selection.ExitID, middle.source, closure.final)
		return target, "", err
	}
	if header.Kind == "routervpn-node-chain-connect-member" {
		// Keep CONNECT's complete source compiler authoritative for protocol,
		// credentials, verified-TLS configuration, literal address and Off layer.
		// No ordinary NodeProfile or host-provided endpoint grants this scope.
		middle, err := parseNodeChainCONNECTMember(input)
		if err != nil {
			return hopmeasure.CandidateTarget{}, "", err
		}
		closure, err := middle.closure()
		if err != nil {
			return hopmeasure.CandidateTarget{}, "", err
		}
		target, err := nodeChainCandidateLiteralTarget(middle.selection.ExitID, middle.source, closure.final)
		return target, "", err
	}
	var closure *externalPredecessor
	var id, source, proof string
	wantType, wantMethod := "shadowsocks", ""
	var err error
	if header.Kind == "routervpn-node-chain-imported-member" {
		middle, parseErr := parseNodeChainImportedMember(input)
		if parseErr != nil {
			return hopmeasure.CandidateTarget{}, "", parseErr
		}
		closure, err = middle.closure()
		id, source = middle.id(), middle.source
	} else {
		node, parseErr := ParseNodeLaunchInput(input)
		if parseErr != nil || node == nil || node.mode != "shadowsocks" {
			return hopmeasure.CandidateTarget{}, "", bad
		}
		// A paired SS Start Layer uses the same original SS2022 stream owner.
		// Only its validated concrete closure supplies the TCP endpoint. Other
		// modes may add UDP/nested owners and never gain a guessed TCP target.
		switch predecessorText(node.profile, "start_layer") {
		case "", "off":
		case "aes-256-gcm":
			wantMethod = NativeStartLayerMethod
		case "aes-256-gcm+xor-whitening":
			wantType, wantMethod = "routervpn-aes-xor", NativeStartLayerMethod
		default:
			return hopmeasure.CandidateTarget{}, "", bad
		}
		closure, err = nodeMultihopPredecessor(node)
		id, source, proof = predecessorText(node.profile, "id"), node.SourceSHA256(), predecessorText(node.profile, "node_proof_id")
	}
	if err != nil || closure == nil || closure.final["type"] != wantType ||
		(wantMethod != "" && closure.final["method"] != wantMethod) ||
		closure.final["detour"] != nil || closure.final["domain_resolver"] != nil ||
		closure.final["network"] != nil || closure.final["udp_over_tcp"] != nil ||
		!importedSS2022Credentials(predecessorText(closure.final, "method"), predecessorText(closure.final, "password")) {
		return hopmeasure.CandidateTarget{}, "", bad
	}
	target, err := nodeChainCandidateLiteralTarget(id, source, closure.final)
	return target, proof, err
}

// Called only after the candidate's original typed compiler validated its
// complete closure. Never resolve an arbitrary host or infer a default port.
func nodeChainCandidateLiteralTarget(id, source string, final map[string]any) (hopmeasure.CandidateTarget, error) {
	address, err := netip.ParseAddr(predecessorText(final, "server"))
	port, ok := final["server_port"].(float64)
	if err != nil || address.Zone() != "" || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() ||
		!ok || math.IsNaN(port) || math.IsInf(port, 0) || math.Trunc(port) != port || port < 1 || port > 65535 {
		return hopmeasure.CandidateTarget{}, errors.New("candidate requires its captured literal TCP address and port")
	}
	return hopmeasure.CandidateTarget{ID: id, SourceSHA256: source, Address: net.JoinHostPort(address.String(), strconv.Itoa(int(port)))}, nil
}

func (p *NodeChainCandidatePlan) CaptureSHA256() string {
	if p == nil {
		return ""
	}
	return p.capture
}

func (p *NodeChainCandidatePlan) CandidateMode() string {
	if p.validate() != nil {
		return ""
	}
	return p.responseMode
}

// Metadata is safe for the chooser. It contains no private endpoint, source
// input, API token, PSK or reusable native dialing capability.
func (p *NodeChainCandidatePlan) Metadata() string {
	if p.validate() != nil {
		return ""
	}
	if p.appendSource != nil {
		return p.appendMetadata()
	}
	if p.metadataPages == nil {
		return ""
	}
	p.metadataPages.mu.Lock()
	defer p.metadataPages.mu.Unlock()
	if p.metadataPages.full != "" {
		return p.metadataPages.full
	}
	type member struct {
		ID     string `json:"id"`
		Source string `json:"source_sha256"`
	}
	targets := make([]member, len(p.targets))
	for i, target := range p.targets {
		targets[i] = member{target.ID, target.SourceSHA256}
	}
	raw, _ := json.Marshal(struct {
		Schema         int      `json:"schema"`
		Capture        string   `json:"capture_sha256"`
		PrefixPosition int      `json:"prefix_position"`
		PrefixID       string   `json:"prefix_id"`
		Source         string   `json:"source_sha256"`
		Config         string   `json:"config_sha256"`
		Targets        []member `json:"targets"`
		Measurement    string   `json:"measurement,omitempty"`
		CandidateMode  string   `json:"candidate_mode,omitempty"`
	}{1, p.capture, p.prefix.Position, p.prefix.ProfileID, p.chain.SourceSHA256(), p.chain.ConfigSHA256(), targets, p.measurement, p.responseMode})
	p.metadataPages.full = string(raw)
	return p.metadataPages.full
}

func (p *NodeChainCandidatePlan) digest() string {
	if p != nil && p.appendSource != nil {
		return p.appendDigest()
	}
	if p == nil || p.chain == nil {
		return ""
	}
	if p.multipleSeal.matches(p) {
		return p.multipleSeal.seal
	}
	fields := []any{p.chain.SourceSHA256(), p.chain.ConfigSHA256(), p.inventory, p.revision, p.prefix, p.targets, p.capture}
	if p.measurement != "" || p.responses != nil {
		fields = append(fields, p.measurement, p.responses)
	}
	if p.publicResponses != nil {
		fields = append(fields, p.publicResponses)
	}
	if p.connectedFinalResponse {
		fields = append(fields, true)
	}
	if p.preparedNativeResponse {
		fields = append(fields, "closed-prefix")
	}
	if p.responseMode != "" {
		fields = append(fields, p.responseMode)
	}
	if p.multiple != nil {
		fields = append(fields, p.multiple.digest())
	}
	raw, _ := json.Marshal(fields)
	defer clear(raw)
	return externalDigest(raw)
}

func (p *NodeChainCandidatePlan) validate() error {
	if p != nil && p.appendSource != nil {
		return p.validateAppend()
	}
	if p == nil || p.chain == nil || p.appendImportSeals != nil || p.chain.validateCapture() != nil || p.seal == "" || p.seal != p.digest() ||
		p.prefix.Position < 0 || p.prefix.Position >= len(p.chain.proofs) || p.prefix != p.chain.proofs[p.prefix.Position] {
		return errors.New("candidate plan changed its sealed original capture")
	}
	if p.preparedNativeResponse && p.responseMode == "" {
		return nodeChainCandidatePreparationError
	}
	if p.connectedFinalResponse && (p.multiple != nil || p.measurement != hopmeasure.CandidatePrivateResponseMeasurement || !p.chain.connectedFinalResponsePrefix(p.prefix.Position)) {
		return nodeChainCandidatePreparationError
	}
	if p.responseMode != "" && (p.connectedFinalResponse || p.measurement != hopmeasure.CandidatePrivateResponseMeasurement || p.chain.candidateNativeResponseModeAt(p.prefix.Position) != p.responseMode) {
		return nodeChainCandidatePreparationError
	}
	if p.multiple == nil && p.chain.importedNodes != nil && !p.connectedFinalResponse || p.multiple != nil && !p.multiple.currentValidated(p.chain) {
		return nodeChainCandidatePreparationError
	}
	return nil
}

func (p *NodeChainCandidatePlan) NewMeasurementContext(ctx context.Context, owner NodeChainCandidateOwner) (*hopmeasure.CandidateService, error) {
	if ctx == nil {
		return nil, errors.New("candidate measurement requires an original caller")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.validate() != nil || p.appendSource != nil || p.preparedNativeResponse || owner == nil {
		return nil, errors.New("candidate measurement lost its original source owner")
	}
	active, err := owner.MeasurementChainContext(ctx)
	if err != nil || active == nil || active.SourceSHA256() != p.chain.SourceSHA256() || active.ConfigSHA256() != p.chain.ConfigSHA256() ||
		(p.multiple != nil || p.connectedFinalResponse || p.responseMode != "") && active != p.chain {
		return nil, errors.Join(err, hopmeasure.ErrStale)
	}
	if err := active.HealthyContext(ctx); err != nil {
		return nil, err
	}
	if err := externalObservationLock(ctx, &active.runtime.mu); err != nil {
		return nil, err
	}
	identity, reader := active.runtime.identity, active.runtime.engine
	active.runtime.mu.Unlock()
	if p.responseMode != "" {
		if _, ok := reader.(NodeChainCandidatePacketEngine); !ok {
			return nil, errors.New("candidate response has no original Local packet carrier")
		}
	}
	engine := &nodeChainCandidateEngine{plan: p, owner: owner, active: active, identity: identity, reader: reader}
	return p.newService(ctx, engine, p.capture)
}

type nodeChainCandidateEngine struct {
	plan     *NodeChainCandidatePlan
	owner    NodeChainCandidateOwner
	active   *NodeChain
	identity NodeChainIdentity
	reader   NodeChainEngine
	revoked  atomic.Bool
}

func (e *nodeChainCandidateEngine) current(ctx context.Context) (active *NodeChain, err error) {
	if ctx == nil {
		return nil, hopmeasure.ErrStale
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if e.revoked.Load() {
		return nil, hopmeasure.ErrStale
	}
	defer func() {
		// An observed foreign catalog/reader/native owner cannot revive this
		// capture by changing back. A canceled caller alone is not a mutation.
		if err != nil && ctx.Err() == nil {
			e.revoked.Store(true)
		}
	}()
	if e.plan.validate() != nil || e.reader == nil {
		return nil, hopmeasure.ErrStale
	}
	if err := e.owner.CandidateInventoryCurrentContext(ctx, e.plan.capture); err != nil {
		return nil, err
	}
	active, err = e.owner.MeasurementChainContext(ctx)
	if err != nil || active != e.active || active == nil || active.SourceSHA256() != e.plan.chain.SourceSHA256() || active.ConfigSHA256() != e.plan.chain.ConfigSHA256() {
		return nil, errors.Join(err, hopmeasure.ErrStale)
	}
	if err := active.HealthyContext(ctx); err != nil {
		return nil, err
	}
	if err := externalObservationLock(ctx, &active.runtime.mu); err != nil {
		return nil, err
	}
	identity, reader := active.runtime.identity, active.runtime.engine
	active.runtime.mu.Unlock()
	if identity != e.identity || reader != e.reader {
		return nil, hopmeasure.ErrStale
	}
	return active, ctx.Err()
}

func (e *nodeChainCandidateEngine) Identity() string {
	ctx, cancel := context.WithTimeout(context.Background(), hopmeasure.ObservationTimeout)
	defer cancel()
	identity, _ := e.IdentityContext(ctx)
	return identity
}
func (e *nodeChainCandidateEngine) IdentityContext(ctx context.Context) (string, error) {
	if _, err := e.current(ctx); err != nil {
		return "", err
	}
	raw, err := json.Marshal([]any{e.identity, e.plan.capture})
	return string(raw), err
}
func (e *nodeChainCandidateEngine) VerifyMeasurement(ctx context.Context) error {
	_, err := e.current(ctx)
	return err
}
func (e *nodeChainCandidateEngine) BeginMeasurementContext(ctx context.Context) (func(), error) {
	if _, err := e.current(ctx); err != nil {
		return nil, err
	}
	release, err := e.owner.BeginMeasurementContext(ctx)
	if err != nil || release == nil {
		return release, errors.Join(err, errors.New("candidate measurement activity unavailable"))
	}
	if _, err := e.current(ctx); err != nil {
		release()
		return nil, err
	}
	return release, nil
}
func (e *nodeChainCandidateEngine) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	active, err := e.current(ctx)
	if err != nil {
		return nil, err
	}
	allowed := false
	for _, target := range e.plan.targets {
		allowed = allowed || target.Address == address
	}
	if tag != e.plan.prefix.Tag || !allowed {
		return nil, errors.New("candidate dial differs from the captured prefix or original endpoint")
	}
	connection, err := active.dial(ctx, tag, address)
	_, observeErr := e.current(ctx)
	if err != nil || observeErr != nil || ctx.Err() != nil {
		if connection != nil {
			err = errors.Join(err, connection.Close())
		}
		return nil, errors.Join(err, observeErr, ctx.Err())
	}
	return connection, nil
}
