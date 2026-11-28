package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"

	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/multihoprelay"
)

const serverNodeChainPrefixCatalogsDirectory = "/etc/router-vpn/node-chain-prefix-catalogs"

type relayPrefixCatalogOwner struct {
	self       *relayPrefixCatalogOwner
	runner     *relayNodeChainExecRunner
	path       string
	file       os.FileInfo
	fileSHA    string
	reference  multihoprelay.NodeChainPrefixCatalogReference
	generation string
	peers      []string
	policy     *mobilemultihop.NodeChainServerPrefixCatalog
	gate       chan struct{}
	closed     atomic.Bool
}

type relaySelectedPrefixSource struct {
	self       *relaySelectedPrefixSource
	catalog    *relayPrefixCatalogOwner
	request    multihoprelay.NodeChainPrefixSelectionRequest
	descriptor multihoprelay.NodeChainPrefixDescriptor
	policy     *mobilemultihop.NodeChainServerPrefixPolicy
	gate       chan struct{}
	closed     atomic.Bool
}

func (r *relayNodeChainExecRunner) capturePrefixCatalog(reference multihoprelay.NodeChainPrefixCatalogReference, node string) (*relayPrefixCatalogOwner, error) {
	if reference.Validate() != nil || reference.EntryNodeID != node {
		return nil, multihoprelay.ErrOwnership
	}
	directory, err := os.Lstat(r.prefixCatalogSources)
	if err != nil || !directory.IsDir() || directory.Mode().Perm() != 0700 {
		return nil, multihoprelay.ErrOwnership
	}
	path := filepath.Join(r.prefixCatalogSources, reference.SourceSHA256+".json")
	raw, file, err := readNodeChainRegistration(path, nil)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	if len(raw) > mobilemultihop.NodeChainInputLimit {
		return nil, multihoprelay.ErrOwnership
	}
	policy, err := mobilemultihop.NewNodeChainServerPrefixCatalog(string(raw))
	if err != nil || policy == nil || policy.Reference() != reference || policy.EntryNodeID() != node {
		return nil, multihoprelay.ErrOwnership
	}
	nonce, err := torIPCNonce()
	if err != nil {
		return nil, err
	}
	generation, err := multihoprelay.NodeChainPrefixSelectionGeneration(reference.SourceSHA256, nonce)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(raw)
	owner := &relayPrefixCatalogOwner{runner: r, path: path, file: file, fileSHA: hex.EncodeToString(hash[:]),
		reference: reference.Clone(), generation: generation, peers: slices.Clone(policy.EntryPeerAddresses()),
		policy: policy, gate: make(chan struct{}, 1)}
	owner.self = owner
	return owner, nil
}

func (r *relayNodeChainExecRunner) PrefixSelectionCatalog() multihoprelay.NodeChainPrefixSelectionCatalog {
	if r == nil || r.prefixCatalog == nil {
		return nil
	}
	return r.prefixCatalog
}

func (c *relayPrefixCatalogOwner) Reference() multihoprelay.NodeChainPrefixCatalogReference {
	if c == nil || c.self != c {
		return multihoprelay.NodeChainPrefixCatalogReference{}
	}
	return c.reference.Clone()
}
func (c *relayPrefixCatalogOwner) GenerationSHA256() string {
	if c == nil || c.self != c {
		return ""
	}
	return c.generation
}
func (c *relayPrefixCatalogOwner) EntryPeerAddresses() []string {
	if c == nil || c.self != c {
		return nil
	}
	return slices.Clone(c.peers)
}
func (c *relayPrefixCatalogOwner) acquire(ctx context.Context) error {
	if ctx == nil || c == nil || c.self != c || c.closed.Load() {
		return multihoprelay.ErrOwnership
	}
	select {
	case c.gate <- struct{}{}:
		if c.closed.Load() || ctx.Err() != nil {
			<-c.gate
			return errors.Join(ctx.Err(), multihoprelay.ErrOwnership)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (c *relayPrefixCatalogOwner) currentLocked(ctx context.Context) error {
	if ctx.Err() != nil || c.closed.Load() || c.policy == nil {
		return errors.Join(ctx.Err(), multihoprelay.ErrOwnership)
	}
	raw, _, err := readNodeChainRegistration(c.path, c.file)
	if err != nil {
		return err
	}
	defer clear(raw)
	hash := sha256.Sum256(raw)
	if hex.EncodeToString(hash[:]) != c.fileSHA || c.policy.Reference() != c.reference || c.closed.Load() {
		return multihoprelay.ErrOwnership
	}
	return ctx.Err()
}
func (c *relayPrefixCatalogOwner) CurrentContext(ctx context.Context) error {
	if err := c.acquire(ctx); err != nil {
		return err
	}
	defer func() { <-c.gate }()
	return c.currentLocked(ctx)
}
func (c *relayPrefixCatalogOwner) SelectContext(ctx context.Context, q multihoprelay.NodeChainPrefixSelectionRequest) (multihoprelay.NodeChainPrefixSelectionSource, error) {
	if err := c.acquire(ctx); err != nil {
		return nil, err
	}
	defer func() { <-c.gate }()
	if err := c.currentLocked(ctx); err != nil {
		return nil, err
	}
	if q.Validate() != nil || q.CatalogSHA256 != c.reference.SourceSHA256 ||
		q.CatalogGenerationSHA256 != c.generation || q.EntryNodeID != c.reference.EntryNodeID ||
		!slices.Contains(c.peers, q.Peer) {
		return nil, multihoprelay.ErrOwnership
	}
	policy, err := c.policy.Select(q.Clone())
	if policy == nil {
		return nil, errors.Join(err, multihoprelay.ErrUnavailable)
	}
	// Keep every actual nonnil result, including one returned with an error
	// or after cancellation, so its caller can join the original data owner.
	descriptor, descriptorErr := policy.Descriptor()
	source := &relaySelectedPrefixSource{catalog: c, request: q.Clone(),
		descriptor: descriptor.Clone(), policy: policy, gate: make(chan struct{}, 1)}
	source.self = source
	if descriptorErr != nil || !q.MatchesSelectedDescriptor(descriptor) {
		err = errors.Join(err, descriptorErr, multihoprelay.ErrOwnership)
	}
	if c.closed.Load() {
		err = errors.Join(err, multihoprelay.ErrOwnership)
	}
	return source, errors.Join(err, ctx.Err())
}
func (c *relayPrefixCatalogOwner) CloseContext(ctx context.Context) error {
	if ctx == nil || c == nil || c.self != c {
		return multihoprelay.ErrOwnership
	}
	c.closed.Store(true)
	select {
	case c.gate <- struct{}{}:
		defer func() { <-c.gate }()
		c.policy = nil
		return ctx.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *relaySelectedPrefixSource) Request() multihoprelay.NodeChainPrefixSelectionRequest {
	if s == nil || s.self != s {
		return multihoprelay.NodeChainPrefixSelectionRequest{}
	}
	return s.request.Clone()
}
func (s *relaySelectedPrefixSource) Descriptor() multihoprelay.NodeChainPrefixDescriptor {
	if s == nil || s.self != s {
		return multihoprelay.NodeChainPrefixDescriptor{}
	}
	return s.descriptor.Clone()
}
func (s *relaySelectedPrefixSource) CatalogSHA256() string {
	if s == nil || s.self != s {
		return ""
	}
	return s.request.CatalogSHA256
}
func (s *relaySelectedPrefixSource) GenerationSHA256() string {
	if s == nil || s.self != s {
		return ""
	}
	return s.request.CatalogGenerationSHA256
}
func (s *relaySelectedPrefixSource) acquire(ctx context.Context) error {
	if ctx == nil || s == nil || s.self != s || s.closed.Load() {
		return multihoprelay.ErrOwnership
	}
	select {
	case s.gate <- struct{}{}:
		if s.closed.Load() || ctx.Err() != nil {
			<-s.gate
			return errors.Join(ctx.Err(), multihoprelay.ErrOwnership)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *relaySelectedPrefixSource) currentLocked(ctx context.Context) error {
	if s.closed.Load() || s.policy == nil || s.catalog == nil || s.catalog.self != s.catalog {
		return multihoprelay.ErrOwnership
	}
	actual, err := s.policy.Descriptor()
	want, wantErr := s.descriptor.Digest()
	got, gotErr := actual.Digest()
	if err != nil || wantErr != nil || gotErr != nil || got != want ||
		!s.request.MatchesSelectedDescriptor(actual) {
		return multihoprelay.ErrOwnership
	}
	if err := s.catalog.CurrentContext(ctx); err != nil {
		return err
	}
	if s.closed.Load() {
		return multihoprelay.ErrOwnership
	}
	return ctx.Err()
}
func (s *relaySelectedPrefixSource) CurrentContext(ctx context.Context) error {
	if err := s.acquire(ctx); err != nil {
		return err
	}
	defer func() { <-s.gate }()
	return s.currentLocked(ctx)
}
func (s *relaySelectedPrefixSource) CloseContext(ctx context.Context) error {
	if ctx == nil || s == nil || s.self != s {
		return multihoprelay.ErrOwnership
	}
	s.closed.Store(true)
	select {
	case s.gate <- struct{}{}:
		defer func() { <-s.gate }()
		s.policy = nil
		return ctx.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (r *relayNodeChainExecRunner) StartSelectedPrefix(ctx context.Context, capture multihoprelay.NodeChainPrefixCapture, selected multihoprelay.NodeChainPrefixSelectionSource) (multihoprelay.NodeChainPrefixProcess, error) {
	if r == nil || ctx == nil || ctx.Err() != nil || capture.Validate() != nil {
		return nil, multihoprelay.ErrOwnership
	}
	source, ok := selected.(*relaySelectedPrefixSource)
	if !ok || source == nil || source.self != source || source.catalog == nil ||
		source.catalog.runner != r || source.catalog != r.prefixCatalog ||
		!source.request.MatchesLease(capture.Request, capture.Source) {
		return nil, multihoprelay.ErrOwnership
	}
	if err := source.acquire(ctx); err != nil {
		return nil, err
	}
	err := source.currentLocked(ctx)
	policy := source.policy
	<-source.gate
	if err != nil || policy == nil {
		return nil, errors.Join(err, multihoprelay.ErrOwnership)
	}
	current := func(currentContext context.Context) bool { return source.CurrentContext(currentContext) == nil }
	return r.startPrefixWithSource(ctx, capture, policy, current)
}
