//go:build linux

package linuxprotection

import (
	"context"
	"errors"
	"os"
	"time"

	"router-vpn/internal/linuxprocess"
	"router-vpn/internal/mobiletor"
)

var ErrNodeControlRefused = errors.New("Linux Node original parent refused preparation")
var ErrNodeControlRetired = errors.New("Linux Node original engine retired before admission")

// NodeControl borrows the original authenticated Bootstrap for one captured
// preparation. It neither closes that transport nor owns the native baseline,
// engine, saved profile or journal. Their original caller retains all partial
// owners on every error. Use the engine's bounded protocol lifetime here;
// cancellation of a user's request belongs inside the captured callbacks so
// a refusal and actual source retirement can still be exchanged.
type NodeControl struct {
	gate                         chan struct{}
	bootstrap                    *linuxprocess.Bootstrap
	selection                    NodeSelection
	commandSHA256, selectionHash string
	parent, engine               linuxprocess.Observation
	parentSide                   bool
	next                         uint32
	started, refused, admitted   bool
	closedAck, peerEOF           bool
	network                      string
	created                      *mobiletor.DesktopLinuxNodeCreationRecord
	prepared                     *NodePreparedRecord
	retired                      *NodeRetirementRecord
	uncertain                    error
}

func NewNodeParentControl(ctx context.Context, original *linuxprocess.Bootstrap, selection NodeSelection) (*NodeControl, error) {
	return newNodeControl(ctx, original, selection, true)
}

func NewNodeChildControl(ctx context.Context, original *linuxprocess.Bootstrap, selection NodeSelection) (*NodeControl, error) {
	return newNodeControl(ctx, original, selection, false)
}

func newNodeControl(ctx context.Context, original *linuxprocess.Bootstrap, selection NodeSelection, parentSide bool) (*NodeControl, error) {
	if ctx == nil || ctx.Err() != nil || original == nil || selection.Validate() != nil {
		return nil, errors.New("Linux Node control requires its original live bootstrap and sealed selection")
	}
	command, err := selection.CaptureSHA256()
	if err != nil || original.CheckCapture(ctx, command) != nil {
		return nil, errors.New("Linux Node control changed its authenticated command capture")
	}
	parent, engine, err := original.Observations(ctx)
	if err != nil || parentSide && parent.ProcessID != os.Getpid() || !parentSide && engine.ProcessID != os.Getpid() {
		return nil, errors.Join(err, errors.New("Linux Node control belongs to another native process role"))
	}
	digest, err := selection.ControlSHA256()
	if err != nil {
		return nil, err
	}
	c := &NodeControl{gate: make(chan struct{}, 1), bootstrap: original, selection: selection,
		commandSHA256: command, selectionHash: digest, parent: parent, engine: engine, parentSide: parentSide, next: 1}
	c.gate <- struct{}{}
	return c, nil
}

func (c *NodeControl) enter(ctx context.Context) error {
	if c == nil || ctx == nil || ctx.Err() != nil {
		return errors.New("Linux Node control has no live operation context")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.gate:
		if ctx.Err() != nil {
			c.gate <- struct{}{}
			return ctx.Err()
		}
		return nil
	}
}

func (c *NodeControl) fail(err error) error {
	if c.uncertain == nil {
		c.uncertain = errors.Join(err, errors.New("Linux Node original control retained an unresolved protocol failure"))
	}
	return c.uncertain
}

func (c *NodeControl) current(ctx context.Context) error {
	if c.uncertain != nil {
		return c.uncertain
	}
	if err := c.bootstrap.CheckCapture(ctx, c.commandSHA256); err != nil {
		return c.fail(err)
	}
	parent, engine, err := c.bootstrap.Observations(ctx)
	if err != nil || parent != c.parent || engine != c.engine || ctx.Err() != nil {
		return c.fail(errors.Join(err, ctx.Err(), errors.New("Linux Node control changed its original native participants")))
	}
	return nil
}

func (c *NodeControl) send(ctx context.Context, message NodeControlMessage) error {
	if err := c.current(ctx); err != nil {
		return err
	}
	message.Schema, message.Kind = NodeControlSchema, NodeControlKind
	message.Sequence, message.SelectionSHA256 = c.next, c.selectionHash
	body, err := CanonicalNodeControlMessage(message)
	if err != nil {
		return c.fail(err)
	}
	if err := c.bootstrap.Send(ctx, body); err != nil {
		return c.fail(err)
	}
	c.next++
	return nil
}

func (c *NodeControl) receive(ctx context.Context) (NodeControlMessage, error) {
	if err := c.current(ctx); err != nil {
		return NodeControlMessage{}, err
	}
	body, err := c.bootstrap.Receive(ctx)
	if err != nil {
		return NodeControlMessage{}, c.fail(err)
	}
	message, err := ParseNodeControlMessage(body)
	if err != nil || message.Sequence != c.next || message.SelectionSHA256 != c.selectionHash {
		return NodeControlMessage{}, c.fail(errors.Join(err, errors.New("Linux Node message changed its captured selection or phase order")))
	}
	c.next++
	return message, nil
}

func (c *NodeControl) validPrepared(record NodePreparedRecord) bool {
	return record.Validate() == nil && c.selection.matches(record.Protection.Capture) &&
		record.Protection.Capture.NetworkID == c.network && record.Policy == c.selection.Policy &&
		record.Guardian.Engine == c.engine && c.created != nil && c.created.HomeLAN == c.selection.HomeLAN &&
		c.created.MatchesPrepared(record.Protection)
}

func (c *NodeControl) validRetirement(record NodeRetirementRecord) bool {
	if record.Validate() != nil || (record.Prepared == nil) != (c.prepared == nil) ||
		record.Prepared != nil && *record.Prepared != *c.prepared {
		return false
	}
	if record.Source == nil {
		return c.prepared == nil
	}
	return c.created != nil && c.selection.matches(record.Source.Capture) && record.Source.Capture.NetworkID == c.network &&
		(record.Source.Original == nil || record.Source.Original.Engine == c.engine)
}

func (c *NodeControl) acceptRetirement(record *NodeRetirementRecord) error {
	if record == nil || !c.validRetirement(*record) {
		return c.fail(errors.New("Linux Node retirement lost its actual original prepared source"))
	}
	copy := record.Clone()
	c.retired, c.admitted = &copy, false
	return nil
}

func (c *NodeControl) refuse(ctx context.Context, phase string, cause error) error {
	c.refused = true
	// This is only a negative response to this original captured operation.
	// A cancelled request cannot authorize creation/admission, but must not
	// prevent the child from closing a source it already owns.
	lifetime := ctx
	if ctx.Err() != nil {
		lifetime = context.Background()
	}
	bounded, cancel := context.WithTimeout(lifetime, 2*time.Second)
	defer cancel()
	return errors.Join(cause, ErrNodeControlRefused, c.send(bounded, NodeControlMessage{Action: "refused", Refusal: phase}))
}

// ServePreparation invokes create only after the actual child's complete
// selection matches. create must durably record its prepare intent before
// native creation and its original creation receipt before returning. admit
// must bind that exact native source and commit the original journal/native
// succession before returning. Neither callback can be replaced by decoding
// these comparison records or by a later lookup of a table name or PID.
func (c *NodeControl) ServePreparation(ctx context.Context,
	create func(context.Context, mobiletor.DesktopSocketCapture) (mobiletor.DesktopLinuxNodeCreationRecord, error),
	admit func(context.Context, NodePreparedRecord) error) error {
	if err := c.enter(ctx); err != nil {
		return err
	}
	defer func() { c.gate <- struct{}{} }()
	if !c.parentSide || c.started || c.retired != nil || create == nil || admit == nil {
		return errors.New("Linux Node parent requires one original preparation with both native callbacks")
	}
	c.started = true
	message, err := c.receive(ctx)
	if err != nil {
		return err
	}
	if message.Action == "retired" {
		if err := c.acceptRetirement(message.Retired); err != nil {
			return err
		}
		return ErrNodeControlRetired
	}
	if message.Action != "baseline" {
		return c.fail(errors.New("Linux Node parent received an unrequested initial phase"))
	}
	c.network = message.Network
	capture := mobiletor.DesktopSocketCapture{SessionID: c.selection.SessionID, SourceSHA256: c.selection.SourceSHA256, NetworkID: c.network}
	created, err := create(ctx, capture)
	if err != nil || ctx.Err() != nil {
		return c.refuse(ctx, "baseline", errors.Join(err, ctx.Err()))
	}
	if created.Validate() != nil || created.Capture != capture || created.HomeLAN != c.selection.HomeLAN {
		return c.refuse(ctx, "baseline", errors.New("Linux Node creation callback changed its exact captured receipt"))
	}
	c.created = &created
	if err := c.send(ctx, NodeControlMessage{Action: "created", Created: &created}); err != nil {
		return err
	}
	message, err = c.receive(ctx)
	if err != nil {
		return err
	}
	if message.Action == "retired" {
		if err := c.acceptRetirement(message.Retired); err != nil {
			return err
		}
		return ErrNodeControlRetired
	}
	if message.Action != "prepared" || message.Prepared == nil || !c.validPrepared(*message.Prepared) {
		return c.fail(errors.New("Linux Node preparation substituted its original native engine, network or baseline"))
	}
	prepared := *message.Prepared
	c.prepared = &prepared
	if err := admit(ctx, prepared); err != nil || ctx.Err() != nil {
		return c.refuse(ctx, "admission", errors.Join(err, ctx.Err()))
	}
	receipt, err := NodePreparedSHA256(c.selection, prepared)
	if err != nil {
		return c.fail(err)
	}
	if err := c.send(ctx, NodeControlMessage{Action: "admitted", ReceiptSHA256: receipt}); err != nil {
		return err
	}
	c.admitted = true
	return nil
}

func (c *NodeControl) CreateBaseline(ctx context.Context, capture mobiletor.DesktopSocketCapture) (mobiletor.DesktopLinuxNodeCreationRecord, error) {
	if err := c.enter(ctx); err != nil {
		return mobiletor.DesktopLinuxNodeCreationRecord{}, err
	}
	defer func() { c.gate <- struct{}{} }()
	if c.parentSide || c.started || c.retired != nil || !c.selection.matches(capture) {
		return mobiletor.DesktopLinuxNodeCreationRecord{}, errors.New("Linux Node child lost its original captured network preparation")
	}
	c.started, c.network = true, capture.NetworkID
	if err := c.send(ctx, NodeControlMessage{Action: "baseline", Network: c.network}); err != nil {
		return mobiletor.DesktopLinuxNodeCreationRecord{}, err
	}
	message, err := c.receive(ctx)
	if err != nil {
		return mobiletor.DesktopLinuxNodeCreationRecord{}, err
	}
	if message.Action == "refused" && message.Refusal == "baseline" {
		c.refused = true
		return mobiletor.DesktopLinuxNodeCreationRecord{}, ErrNodeControlRefused
	}
	if message.Action != "created" || message.Created == nil || message.Created.Capture != capture || message.Created.HomeLAN != c.selection.HomeLAN {
		return mobiletor.DesktopLinuxNodeCreationRecord{}, c.fail(errors.New("Linux Node child lost the exact original baseline creation receipt"))
	}
	created := *message.Created
	c.created = &created
	return created, nil
}

func (c *NodeControl) AdmitSource(ctx context.Context, prepared NodePreparedRecord) error {
	if err := c.enter(ctx); err != nil {
		return err
	}
	defer func() { c.gate <- struct{}{} }()
	if c.parentSide || c.refused || c.prepared != nil || c.retired != nil || c.next != 3 || !c.validPrepared(prepared) {
		return errors.New("Linux Node child cannot admit a changed or already consumed native preparation")
	}
	c.prepared = &prepared
	if err := c.send(ctx, NodeControlMessage{Action: "prepared", Prepared: &prepared}); err != nil {
		return err
	}
	message, err := c.receive(ctx)
	if err != nil {
		return err
	}
	if message.Action == "refused" && message.Refusal == "admission" {
		c.refused = true
		return ErrNodeControlRefused
	}
	receipt, err := NodePreparedSHA256(c.selection, prepared)
	if err != nil || message.Action != "admitted" || message.ReceiptSHA256 != receipt {
		return c.fail(errors.Join(err, errors.New("Linux Node child lost its exact original admission receipt")))
	}
	c.admitted = true
	return nil
}

// Current proves only this original native admission. Selected-path DNS,
// Router-node proof and the application's Connected state remain separate.
func (c *NodeControl) Current(ctx context.Context) error {
	if err := c.enter(ctx); err != nil {
		return err
	}
	defer func() { c.gate <- struct{}{} }()
	if !c.admitted || c.retired != nil || c.closedAck || c.peerEOF {
		return errors.New("Linux Node control has no live admitted preparation")
	}
	return c.current(ctx)
}

// ReceiveRetirement retains a received original receipt even if a later
// acknowledgement fails. Returning that historical comparison does not prove
// live protection, child exit, native absence or durable settlement.
func (c *NodeControl) ReceiveRetirement(ctx context.Context) (NodeRetirementRecord, error) {
	if err := c.enter(ctx); err != nil {
		return NodeRetirementRecord{}, err
	}
	defer func() { c.gate <- struct{}{} }()
	if !c.parentSide || !c.started {
		return NodeRetirementRecord{}, errors.New("Linux Node retirement has no original parent preparation")
	}
	if c.retired != nil {
		return c.retired.Clone(), c.uncertain
	}
	message, err := c.receive(ctx)
	if err != nil {
		return NodeRetirementRecord{}, err
	}
	if message.Action != "retired" {
		return NodeRetirementRecord{}, c.fail(errors.New("Linux Node parent received a different retirement phase"))
	}
	if err := c.acceptRetirement(message.Retired); err != nil {
		return NodeRetirementRecord{}, err
	}
	return c.retired.Clone(), nil
}

// AcknowledgeRetirement requires the parent's independent readback through
// its original native baseline. The caller must next close this same borrowed
// Bootstrap, join its actual created engine, and retain the journal/lease
// owners until native retirement and durable settlement finish. This method
// does not delete protection or close the transport on the caller's behalf.
func (c *NodeControl) AcknowledgeRetirement(ctx context.Context, verifyClosed func(context.Context, NodeRetirementRecord) error) error {
	if err := c.enter(ctx); err != nil {
		return err
	}
	defer func() { c.gate <- struct{}{} }()
	if !c.parentSide || c.retired == nil || verifyClosed == nil {
		return errors.New("Linux Node final acknowledgement lacks original source join and native closed readback")
	}
	if c.closedAck {
		return c.uncertain
	}
	if err := c.current(ctx); err != nil {
		return err
	}
	if err := verifyClosed(ctx, c.retired.Clone()); err != nil || ctx.Err() != nil {
		return errors.Join(err, ctx.Err())
	}
	receipt, err := NodeRetirementSHA256(c.selection, *c.retired)
	if err != nil {
		return c.fail(err)
	}
	if err := c.send(ctx, NodeControlMessage{Action: "closed", ReceiptSHA256: receipt}); err != nil {
		return err
	}
	c.closedAck = true
	return nil
}

// Retire consumes no native owner. The caller supplies the exact original
// source's joined record, or nil if no source was returned. After the exact
// closed acknowledgement the child waits for strict original-channel EOF;
// it must stay alive until the parent has finished its ACK send/readback.
// EOF alone is never accepted as a retirement acknowledgement.
func (c *NodeControl) Retire(ctx context.Context, source *mobiletor.DesktopLinuxSourceJoinRecord) error {
	if err := c.enter(ctx); err != nil {
		return err
	}
	defer func() { c.gate <- struct{}{} }()
	if c.parentSide || c.retired != nil || c.closedAck || c.peerEOF {
		return errors.New("Linux Node child retirement is not its unused original terminal phase")
	}
	record := NodeRetirementRecord{Source: source, Prepared: c.prepared}.Clone()
	if !c.validRetirement(record) {
		return errors.New("Linux Node child retirement changed its original joined source")
	}
	receipt, err := NodeRetirementSHA256(c.selection, record)
	if err != nil {
		return err
	}
	c.retired, c.admitted = &record, false
	if err := c.send(ctx, NodeControlMessage{Action: "retired", Retired: &record}); err != nil {
		return err
	}
	message, err := c.receive(ctx)
	if err != nil {
		return err
	}
	if message.Action != "closed" || message.ReceiptSHA256 != receipt {
		return c.fail(errors.New("Linux Node child received no exact original retirement acknowledgement"))
	}
	c.closedAck = true
	// Bootstrap checks the retained channel/process before this read. The
	// sentinel describes receive-side EOF only; the parent still owns Cmd.Wait.
	body, err := c.bootstrap.Receive(ctx)
	if len(body) != 0 || !errors.Is(err, linuxprocess.ErrPeerClosed) || ctx.Err() != nil {
		return c.fail(errors.Join(err, ctx.Err(), errors.New("Linux Node child left its final acknowledgement without original-channel EOF")))
	}
	c.peerEOF = true
	return nil
}
