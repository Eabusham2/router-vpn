package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"router-vpn/internal/multihoprelay"
)

const nodeChainAppendPrefixSelectionPath = "/api/multihop/chain/prefix/selection"

func (s *nodeChainExecutionIO) exchangePrefixSelection(ctx context.Context, method string, payload []byte) ([]byte, error) {
	if method == "GET" {
		if len(payload) != 0 {
			return nil, errNodeChainAppendExecution
		}
		return s.exchangeCaptured(ctx, method, nodeChainAppendPrefixSelectionPath, nil, multihoprelay.MaxNodeChainPrefixCapabilitiesBytes)
	}
	if method != "POST" && method != "DELETE" {
		return nil, errNodeChainAppendExecution
	}
	if _, err := multihoprelay.DecodeNodeChainPrefixSelectionRequest(payload); err != nil {
		return nil, err
	}
	return s.exchangeCaptured(ctx, method, nodeChainAppendPrefixSelectionPath, payload, multihoprelay.NodeChainPrefixSelectionMaximumBytes)
}

// Only a complete, joined, otherwise error-free 404 may use legacy read-only
// discovery. In particular, a joined cancellation or ownership failure is not
// an absent capability.
func nodeChainPrefixSelectionMissing(err error) bool {
	if status, ok := err.(controlError); ok {
		return status == (controlError{http.StatusNotFound})
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		return len(children) == 1 && nodeChainPrefixSelectionMissing(children[0])
	}
	return false
}
func (p *NodeChainCandidateAppendExecutionPolicy) selectionRequest(c multihoprelay.NodeChainPrefixSelectionCapability) (multihoprelay.NodeChainPrefixSelectionRequest, error) {
	if p.validate() != nil || c.Validate() != nil || c.Reference.EntryNodeID != p.localMembers[0].NodeID || c.Challenge.ExpiresAt <= time.Now().Unix() {
		return multihoprelay.NodeChainPrefixSelectionRequest{}, errNodeChainAppendExecution
	}
	schema := 1
	if p.localMembers[0].Mode == "shadowsocks" {
		if !p.proxyEntryPeerMatches([]string{c.Challenge.Peer}) {
			return multihoprelay.NodeChainPrefixSelectionRequest{}, errNodeChainAppendExecution
		}
		schema = 2
	}
	nonce, err := randomHex(32)
	if err != nil {
		return multihoprelay.NodeChainPrefixSelectionRequest{}, err
	}
	q := multihoprelay.NodeChainPrefixSelectionRequest{
		Schema: schema, Purpose: multihoprelay.NodeChainPrefixSelectionPurpose,
		EntryNodeID: c.Reference.EntryNodeID, CatalogSHA256: c.Reference.SourceSHA256, CatalogGenerationSHA256: c.GenerationSHA256,
		Peer: c.Challenge.Peer, Epoch: c.Challenge.Epoch, AcquireExpiresAt: c.Challenge.ExpiresAt, Nonce: nonce,
		ExecutionSourceSHA256: p.SourceSHA256(), OriginalSourceSHA256: p.OriginalSourceSHA256(), InventorySHA256: p.inventorySHA,
		AppendPosition: len(p.localMembers), LocalPrefix: append([]multihoprelay.NodeChainPrefixMember(nil), p.localMembers...),
		Candidates: make([]multihoprelay.NodeChainPrefixSelectionCandidate, 0, len(p.candidates)),
	}
	var inventory NodeChainCandidateInventory
	if exactJSON([]byte(p.record.Inventory), &inventory, NodeChainInputLimit) != nil {
		return q, errNodeChainAppendExecution
	}
	for i, original := range p.candidates {
		selected := multihoprelay.NodeChainPrefixSelectionCandidate{
			ProfileID: original.ProfileID, NodeID: original.NodeID, Mode: original.Mode, StartLayer: original.StartLayer, SourceSHA256: original.SourceSHA256,
		}
		if original.Mode != "shadowsocks" {
			if i >= len(p.inputs) {
				return q, errNodeChainAppendExecution
			}
			node, err := ParseNodeLaunchInput(p.inputs[i])
			if err != nil || node == nil || node.source != original.SourceSHA256 || node.mode != original.Mode {
				return q, errNodeChainAppendExecution
			}
			if nodeChainAppendExecutionPacketMode(original.Mode) {
				member, err := nodeChainPrefixPacketMember(node, q.AppendPosition)
				if err != nil {
					return q, err
				}
				selected.TransportSHA256, err = nodeChainPrefixPacketTransport(node)
				if err != nil {
					return q, err
				}
				selected.ClientPublicKey, selected.ServerPublicKey = member.ClientPublicKey, member.ServerPublicKey
			} else if original.Mode == "hysteria2" {
				if i >= len(inventory.IdentitySources) {
					return q, errNodeChainAppendExecution
				}
				member, err := nodeChainPrefixHysteriaMember(node, inventory.IdentitySources[i], q.AppendPosition)
				if err != nil {
					return q, err
				}
				selected.TransportSHA256, selected.CompanionSHA256 = member.TransportSHA256, member.CompanionSHA256
				selected.CompanionClientPublicKey, selected.CompanionServerPublicKey = member.CompanionClientPublicKey, member.CompanionServerPublicKey
			} else {
				return q, errNodeChainAppendExecution
			}
		}
		q.Candidates = append(q.Candidates, selected)
	}
	if !q.MatchesCapability(c) {
		return q, errNodeChainAppendExecution
	}
	return q, nil
}

type nodeChainAppendExecutionSelection struct {
	self                                    *nodeChainAppendExecutionSelection
	runtime                                 *NodeChainCandidateAppendExecutionRuntime
	request                                 multihoprelay.NodeChainPrefixSelectionRequest
	digest                                  string
	stop                                    *nodeChainAppendExecutionRetirement
	mu                                      sync.Mutex
	issued, published, acknowledged, closed bool
	publication                             multihoprelay.NodeChainPrefixSelectionReceipt
}

func (r *NodeChainCandidateAppendExecutionRuntime) initialDiscovery(ctx context.Context) (multihoprelay.NodeChainPrefixDiscovery, multihoprelay.NodeChainPrefixDescriptor, error) {
	fail := func(err error) (multihoprelay.NodeChainPrefixDiscovery, multihoprelay.NodeChainPrefixDescriptor, error) {
		return multihoprelay.NodeChainPrefixDiscovery{}, multihoprelay.NodeChainPrefixDescriptor{}, errors.Join(err, errNodeChainAppendExecution)
	}
	r.mu.Lock()
	control := r.control
	r.mu.Unlock()
	if control == nil {
		return fail(nil)
	}
	raw, err := control.exchangePrefixSelection(ctx, "GET", nil)
	if err != nil {
		if nodeChainPrefixSelectionMissing(err) {
			return r.fetchDiscovery(ctx)
		}
		return fail(err)
	}
	capability, err := multihoprelay.DecodeNodeChainPrefixSelectionDiscovery(raw)
	if err != nil || capability.NodeID != r.preparation.policy.localMembers[0].NodeID {
		return fail(err)
	}
	count := 0
	var static multihoprelay.NodeChainPrefixDescriptor
	for _, descriptor := range capability.StaticPrefixes {
		if r.preparation.policy.matchesDescriptor(descriptor) {
			static = descriptor.Clone()
			count++
		}
	}
	if count > 1 {
		return fail(nil)
	}
	if count == 1 {
		discovery, descriptor, err := r.fetchDiscovery(ctx)
		a, x := static.Digest()
		b, y := descriptor.Digest()
		if err != nil || x != nil || y != nil || a != b {
			return fail(err)
		}
		return discovery, descriptor, nil
	}
	if capability.Catalog == nil {
		return fail(nil)
	}
	q, err := r.preparation.policy.selectionRequest(*capability.Catalog)
	if err != nil {
		return fail(err)
	}
	digest, err := q.Digest()
	if err != nil {
		return fail(err)
	}
	owned := &nodeChainAppendExecutionSelection{runtime: r, request: q.Clone(), digest: digest}
	owned.self = owned
	r.mu.Lock()
	if r.retired || r.prefixSelection != nil || r.lifetime == nil || r.lifetime.Err() != nil {
		r.mu.Unlock()
		return fail(nil)
	}
	r.prefixSelection = owned
	r.mu.Unlock()
	owned.stop, err = r.newSelectionRetirement(owned)
	if err != nil {
		return fail(err)
	}
	body, err := json.Marshal(q)
	if err != nil {
		return fail(err)
	}
	// Retain uncertainty before the original POST can publish anything remotely.
	owned.mu.Lock()
	owned.issued = true
	owned.mu.Unlock()
	raw, err = control.exchangePrefixSelection(ctx, "POST", body)
	if err != nil {
		return fail(err)
	}
	receipt, err := multihoprelay.DecodeNodeChainPrefixSelectionReceipt(raw)
	if err != nil || receipt.Validate(q) != nil || receipt.Phase != "published" || !receipt.Publication {
		return fail(err)
	}
	owned.mu.Lock()
	owned.publication, owned.published = receipt, true
	owned.mu.Unlock()
	return r.fetchDiscovery(ctx)
}
func (s *nodeChainAppendExecutionSelection) validRetirement() error {
	if s == nil || s.self != s || s.runtime == nil || s.runtime.self != s.runtime || s.digest == "" {
		return errNodeChainAppendExecution
	}
	r := s.runtime
	r.mu.Lock()
	retained := r.prefixSelection == s && !r.closed
	r.mu.Unlock()
	s.mu.Lock()
	issued, closed := s.issued, s.closed
	s.mu.Unlock()
	digest, err := s.request.Digest()
	if !retained || !issued || closed || err != nil || digest != s.digest {
		return errNodeChainAppendExecution
	}
	return nil
}
func (s *nodeChainAppendExecutionSelection) receipt() (multihoprelay.NodeChainPrefixSelectionReceipt, bool) {
	if s == nil || s.self != s {
		return multihoprelay.NodeChainPrefixSelectionReceipt{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.publication, s.published && !s.closed
}
func (s *nodeChainAppendExecutionSelection) matches(discovery multihoprelay.NodeChainPrefixDiscovery, descriptor multihoprelay.NodeChainPrefixDescriptor) bool {
	receipt, ok := s.receipt()
	if !ok || s.request.Validate() != nil || receipt.Validate(s.request) != nil || !s.request.MatchesSelectedDescriptor(descriptor) {
		return false
	}
	digest, err := descriptor.Digest()
	return err == nil && receipt.SourceSHA256 == descriptor.SourceSHA256 && receipt.DescriptorSHA256 == digest &&
		discovery.Challenge.Epoch == s.request.Epoch && discovery.Challenge.Peer == s.request.Peer
}
func (r *NodeChainCandidateAppendExecutionRuntime) bindPrefixSelection(q *multihoprelay.NodeChainPrefixRequest, descriptor multihoprelay.NodeChainPrefixDescriptor) error {
	if q == nil {
		return errNodeChainAppendExecution
	}
	r.mu.Lock()
	owned := r.prefixSelection
	r.mu.Unlock()
	if owned == nil {
		if q.SelectionSHA256 != "" {
			return errNodeChainAppendExecution
		}
		return nil
	}
	receipt, ok := owned.receipt()
	digest, err := descriptor.Digest()
	if !ok || receipt.Validate(owned.request) != nil || err != nil || receipt.SourceSHA256 != descriptor.SourceSHA256 || receipt.DescriptorSHA256 != digest {
		return errNodeChainAppendExecution
	}
	q.SelectionSHA256 = owned.digest
	if !owned.request.MatchesLease(*q, descriptor) {
		return errNodeChainAppendExecution
	}
	return nil
}

func (r *NodeChainCandidateAppendExecutionRuntime) newSelectionRetirement(selection *nodeChainAppendExecutionSelection) (*nodeChainAppendExecutionRetirement, error) {
	if selection == nil || selection.self != selection || selection.runtime != r || selection.request.Validate() != nil {
		return nil, errNodeChainAppendExecution
	}
	owned := &nodeChainAppendExecutionRetirement{runtime: r, selection: selection, digest: selection.digest}
	owned.self = owned
	p := r.preparation.original
	node := p.prefixNode(0)
	tag := p.proofs[0].Tag
	var err error
	owned.io, err = newNodeChainExecutionIO(tag, predecessorText(node.profile, "router_api"), predecessorText(node.profile, "api_token"), func(ctx context.Context, actual, address string) (net.Conn, error) {
		return r.dialControl(ctx, actual, address, nil, owned)
	}, func(ctx context.Context) error {
		if err := owned.valid(); err != nil {
			return err
		}
		return r.nativeCurrent(ctx, true)
	})
	return owned, err
}
func (s *nodeChainAppendExecutionSelection) retire(ctx context.Context, io *nodeChainExecutionIO) error {
	if ctx == nil || io == nil || s.validRetirement() != nil {
		return errNodeChainAppendExecution
	}
	body, err := json.Marshal(s.request)
	if err != nil {
		return err
	}
	raw, err := io.exchangePrefixSelection(ctx, "DELETE", body)
	if err != nil {
		return err
	}
	receipt, err := multihoprelay.DecodeNodeChainPrefixSelectionReceipt(raw)
	if err != nil || receipt.Validate(s.request) != nil || receipt.Phase != "retired" {
		return errNodeChainAppendExecution
	}
	original, published := s.receipt()
	if published && (!receipt.Publication || receipt.SourceSHA256 != original.SourceSHA256 || receipt.DescriptorSHA256 != original.DescriptorSHA256) {
		return errNodeChainAppendExecution
	}
	s.mu.Lock()
	s.acknowledged = true
	s.mu.Unlock()
	return nil
}
func (s *nodeChainAppendExecutionSelection) close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if s.self != s || ctx == nil {
		return errNodeChainAppendExecution
	}
	s.mu.Lock()
	issued, acknowledged, closed := s.issued, s.acknowledged, s.closed
	s.mu.Unlock()
	if closed {
		return ctx.Err()
	}
	if issued && !acknowledged {
		if s.stop == nil {
			return errNodeChainAppendExecution
		}
		if err := s.stop.stop(ctx); err != nil {
			return err
		}
	}
	if s.stop != nil {
		if err := s.stop.close(ctx); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}
