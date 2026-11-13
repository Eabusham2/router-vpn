package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemtu"
	"sync/atomic"
)

// The Darwin bootstrap supplies native witnesses, never imported profile or
// journal data. The state machine is shared with executable lifecycle tests.
type desktopMacOSParentWitness interface {
	Current(context.Context) error
	Close(context.Context) error
}

type desktopMacOSParent struct {
	controller                      *ownedDesktopController
	input, installLock, processLock *os.File // Borrowed; controller closes after join.
	ownerDone                       <-chan struct{}
	processID                       int
	callerUID                       uint32
	credentials                     [32]byte
	witness                         desktopMacOSParentWitness
	ctx                             context.Context
	cancel                          context.CancelFunc
	joined                          chan struct{}
	gate, retirement                chan struct{}
	session                         *desktopMacOSSession
	originalSession                 *desktopMacOSSession // Immutable retirement authority.
	stopping, closed                bool
}

// One session is allocated by the actual parent bootstrap. It retains native
// dependents across app requests; a decoded receipt cannot construct one.
type desktopMacOSSession struct {
	parent           *desktopMacOSParent
	dependents       map[ownedDesktopNodeParent]struct{}
	external         desktopExternalRetainedRuntime             // Exact active ordinary host; protected by parent.gate.
	nodeChain        *desktopNodeChainPlatformRuntime           // Exact active ordered host; protected by parent.gate.
	candidatePrefix  *desktopNodeCandidatePrefixPlatformRuntime // Separate never-connected purpose; protected by parent.gate.
	stopping, closed bool                                       // Protected by the original parent's gate.
}

// Cleanup retains the original authority after admission is canceled. It does
// not consult a replacement app/controller or a decoded persisted owner. The
// native witness and original open descriptions must still be intact.
func (c *desktopMacOSSessionCapture) cleanupCurrent(ctx context.Context) error {
	if c == nil || c.parent == nil || c.controller == nil || c.session == nil {
		return errors.New("macOS cleanup lost its original capture")
	}
	p := c.parent
	if err := p.enter(ctx); err != nil {
		return err
	}
	defer func() { p.gate <- struct{}{} }()
	original := p.controller
	if p.closed || p.witness == nil || original != c.controller || p.originalSession != c.session || c.session.parent != p ||
		original.input != p.input || original.installLock != p.installLock || original.processLock != p.processLock ||
		original.processID != p.processID || p.processID != os.Getpid() || original.callerUID != p.callerUID ||
		original.ownerDone != p.ownerDone || desktopMacOSCredentials(original) != p.credentials {
		return errors.New("macOS cleanup belongs to another original controller or session")
	}
	return p.witness.Current(ctx)
}

type desktopMacOSSessionCapture struct {
	app        *app
	controller *ownedDesktopController
	parent     *desktopMacOSParent
	session    *desktopMacOSSession
	retired    atomic.Bool
}

func captureDesktopMacOSSession(ctx context.Context, a *app) (*desktopMacOSSessionCapture, error) {
	if a == nil {
		return nil, errors.New("macOS session requires its original application")
	}
	a.mu.Lock()
	controller := a.localController
	a.mu.Unlock()
	if controller == nil {
		return nil, errors.New("macOS application has no authenticated native controller")
	}
	parent, ok := controller.nodeParent.(*desktopMacOSParent)
	if !ok || parent == nil || parent.controller != controller {
		return nil, errors.New("macOS application has another native parent")
	}
	session, err := parent.Session(ctx)
	if err != nil {
		return nil, err
	}
	captured := &desktopMacOSSessionCapture{app: a, controller: controller, parent: parent, session: session}
	return captured, captured.Current(ctx)
}

func (c *desktopMacOSSessionCapture) Current(ctx context.Context) error {
	if c == nil || c.app == nil || c.controller == nil || c.parent == nil || c.session == nil || c.retired.Load() {
		return errors.New("macOS session capture is incomplete")
	}
	if err := mobilemtu.LockContext(ctx, &c.app.mu); err != nil {
		return err
	}
	defer c.app.mu.Unlock()
	if c.retired.Load() || c.app.localController != c.controller || c.controller.nodeParent != c.parent || c.parent.controller != c.controller || c.session.parent != c.parent {
		c.retired.Store(true)
		return errors.New("macOS session capture belongs to a replaced application controller")
	}
	return c.session.Current(ctx)
}

func desktopMacOSCredentials(c *ownedDesktopController) [32]byte {
	return sha256.Sum256([]byte(c.accessToken + "\n" + c.ownerToken))
}

func newDesktopMacOSParent(c *ownedDesktopController, witness desktopMacOSParentWitness) (*desktopMacOSParent, error) {
	if c == nil || c.nodeParent != nil || c.nativeOwner != nil || c.processID != os.Getpid() || c.callerUID == 0 || c.callerUID == ^uint32(0) ||
		!validLocalControllerSecret(c.accessToken) || !validControllerOwnerToken(c.ownerToken) ||
		c.input == nil || c.installLock == nil || c.processLock == nil || c.ownerDone == nil || witness == nil {
		return nil, errors.New("macOS parent requires the original authenticated controller and native witnesses")
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &desktopMacOSParent{controller: c, input: c.input, installLock: c.installLock, processLock: c.processLock,
		ownerDone: c.ownerDone, processID: c.processID, callerUID: c.callerUID, credentials: desktopMacOSCredentials(c),
		witness: witness, ctx: ctx, cancel: cancel, joined: make(chan struct{}), gate: make(chan struct{}, 1), retirement: make(chan struct{}, 1)}
	p.session = &desktopMacOSSession{parent: p, dependents: make(map[ownedDesktopNodeParent]struct{})}
	p.originalSession = p.session
	p.gate <- struct{}{}
	p.retirement <- struct{}{}
	go func() {
		defer close(p.joined)
		select {
		case <-p.ownerDone:
			cancel()
		case <-ctx.Done():
		}
	}()
	return p, nil
}

func (p *desktopMacOSParent) enter(ctx context.Context) error {
	if p == nil || ctx == nil || p.gate == nil {
		return errors.New("macOS parent has no bounded caller")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.gate:
		if err := ctx.Err(); err != nil {
			p.gate <- struct{}{}
			return err
		}
		return nil
	}
}

func (p *desktopMacOSParent) currentLocked(ctx context.Context, published bool) error {
	c := p.controller
	if p.closed || p.stopping || p.ctx.Err() != nil || c == nil || p.witness == nil ||
		c.processID != p.processID || p.processID != os.Getpid() || c.callerUID != p.callerUID || c.nativeOwner != nil ||
		c.input != p.input || c.installLock != p.installLock || c.processLock != p.processLock ||
		c.ownerDone != p.ownerDone || desktopMacOSCredentials(c) != p.credentials || published && c.nodeParent != p ||
		p.session == nil || p.session != p.originalSession || p.session.parent != p || p.session.closed || p.session.stopping {
		return errors.New("macOS parent or session lost its original controller lifetime")
	}
	select {
	case <-p.ownerDone:
		return errors.New("macOS parent lost its original desktop peer")
	default:
	}
	if err := p.witness.Current(ctx); err != nil {
		return err
	}
	select {
	case <-p.ownerDone:
		return errors.New("macOS parent lost its original desktop peer")
	default:
	}
	return p.ctx.Err()
}

func (p *desktopMacOSParent) Current(ctx context.Context) error {
	if err := p.enter(ctx); err != nil {
		return err
	}
	defer func() { p.gate <- struct{}{} }()
	if err := p.currentLocked(ctx, true); err != nil {
		if !common.ObservationContextExpired(ctx, err) {
			p.cancel()
		}
		return err
	}
	return ctx.Err()
}

func (p *desktopMacOSParent) Session(ctx context.Context) (*desktopMacOSSession, error) {
	if err := p.enter(ctx); err != nil {
		return nil, err
	}
	defer func() { p.gate <- struct{}{} }()
	if err := p.currentLocked(ctx, true); err != nil {
		if !common.ObservationContextExpired(ctx, err) {
			p.cancel()
		}
		return nil, err
	}
	return p.session, nil
}

func (s *desktopMacOSSession) Current(ctx context.Context) error {
	if s == nil || s.parent == nil {
		return errors.New("macOS session has no original parent")
	}
	p := s.parent
	if err := p.enter(ctx); err != nil {
		return err
	}
	defer func() { p.gate <- struct{}{} }()
	if p.session != s {
		p.cancel()
		return errors.New("macOS session was replaced")
	}
	if err := p.currentLocked(ctx, true); err != nil {
		if !common.ObservationContextExpired(ctx, err) {
			p.cancel()
		}
		return err
	}
	return ctx.Err()
}

// Retain precedes publication of a dependent. Only a successful checked Close
// removes it; failed cleanup remains attached to the original controller.
func (s *desktopMacOSSession) Retain(ctx context.Context, child ownedDesktopNodeParent) error {
	if s == nil || s.parent == nil || child == nil || child == s || child == s.parent {
		return errors.New("macOS dependent has no distinct native owner")
	}
	p := s.parent
	if err := p.enter(ctx); err != nil {
		return err
	}
	defer func() { p.gate <- struct{}{} }()
	if p.session != s {
		p.cancel()
		return errors.New("macOS dependent belongs to a replaced session")
	}
	if err := p.currentLocked(ctx, true); err != nil {
		if !common.ObservationContextExpired(ctx, err) {
			p.cancel()
		}
		return err
	}
	if _, exists := s.dependents[child]; exists {
		return errors.New("macOS dependent is already retained")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.dependents[child] = struct{}{}
	return nil
}

// The retirement gate serializes close attempts without holding the readback
// gate while joining a dependent (which may itself inspect its old parent).
func (s *desktopMacOSSession) closeDependents(ctx context.Context) error {
	p := s.parent
	if err := p.enter(ctx); err != nil {
		return err
	}
	s.stopping = true
	children := make([]ownedDesktopNodeParent, 0, len(s.dependents))
	for child := range s.dependents {
		children = append(children, child)
	}
	p.gate <- struct{}{}
	for _, child := range children {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := child.Close(ctx); err != nil {
			return err
		}
		if err := p.enter(ctx); err != nil {
			return err
		}
		delete(s.dependents, child)
		p.gate <- struct{}{}
	}
	if err := p.enter(ctx); err != nil {
		return err
	}
	s.closed = true
	p.gate <- struct{}{}
	return nil
}

// Release closes and joins only a dependent already retained by this exact
// session. It also works during cancellation; a failed Close stays retained.
// Dependents never invoke this from their own Close callback.
func (s *desktopMacOSSession) Release(ctx context.Context, child ownedDesktopNodeParent) error {
	if s == nil || s.parent == nil || child == nil || ctx == nil {
		return errors.New("macOS dependent retirement requires its original session")
	}
	p := s.parent
	if p.originalSession != s {
		return errors.New("macOS dependent belongs to another original session")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.retirement:
	}
	defer func() { p.retirement <- struct{}{} }()
	if err := p.enter(ctx); err != nil {
		return err
	}
	_, retained := s.dependents[child]
	p.gate <- struct{}{}
	if !retained {
		return errors.New("macOS dependent was not retained by this session")
	}
	if err := child.Close(ctx); err != nil {
		return err
	}
	if err := p.enter(ctx); err != nil {
		return err
	}
	delete(s.dependents, child)
	p.gate <- struct{}{}
	return nil
}

func (s *desktopMacOSSession) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if s.parent == nil || ctx == nil {
		return errors.New("macOS session retirement has no bounded original owner")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	p := s.parent
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.retirement:
	}
	defer func() { p.retirement <- struct{}{} }()
	return s.closeDependents(ctx)
}

func (p *desktopMacOSParent) Close(ctx context.Context) error {
	if p == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("macOS parent retirement has no bounded caller")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := p.enter(ctx); err != nil {
		return err
	}
	p.stopping = true
	p.cancel()
	p.gate <- struct{}{}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.retirement:
	}
	defer func() { p.retirement <- struct{}{} }()
	if p.closed {
		return nil
	}
	if err := p.originalSession.closeDependents(ctx); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.joined:
	}
	if err := p.witness.Close(ctx); err != nil {
		return err
	}
	if err := p.enter(ctx); err != nil {
		return err
	}
	p.closed = true
	p.gate <- struct{}{}
	return nil
}
